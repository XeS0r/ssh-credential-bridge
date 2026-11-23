//! The freedesktop Secret Service over D-Bus (GNOME Keyring, KWallet, KeePassXC).
//!
//! Uses the `plain` session algorithm: secrets cross the per-user session bus
//! unencrypted, which only processes of the same user can read. Locked collections are
//! not unlocked from here (that would pop up a prompt in the middle of a git request);
//! they fail with [`VaultError::LockedElsewhere`].

use std::collections::HashMap;
use std::time::Duration;

use credential_bridge_config::VaultKind;
use credential_bridge_proto::secret::Secret;
use zbus::{Connection, ObjectPath, OwnedObjectPath, OwnedVariant, Proxy, Variant};
use zeroize::{Zeroize, Zeroizing};

use super::keepassxc::Entry;
use crate::error::VaultError;

const SERVICE: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SERVICE_INTERFACE: &str = "org.freedesktop.Secret.Service";
const ITEM_INTERFACE: &str = "org.freedesktop.Secret.Item";
const COLLECTION_INTERFACE: &str = "org.freedesktop.Secret.Collection";
const LABEL_PROPERTY: &str = "org.freedesktop.Secret.Item.Label";
const ATTRIBUTES_PROPERTY: &str = "org.freedesktop.Secret.Item.Attributes";

/// Upper bound for one Secret Service operation.
const TIMEOUT: Duration = Duration::from_secs(30);

/// How the Secret Service is named in messages.
const PROGRAM: &str = "secret service";

/// The wire form of a secret: session, parameters, value, content type.
type WireSecret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

/// A failure, before it is attributed to a vault.
#[derive(Debug)]
enum Failure {
    Locked,
    Vault(VaultError),
}

impl Failure {
    fn into_error(self, vault: VaultKind) -> VaultError {
        match self {
            Failure::Locked => VaultError::LockedElsewhere { vault, hint: unlock_hint(vault).to_owned() },
            Failure::Vault(error) => error,
        }
    }
}

impl From<zbus::Error> for Failure {
    fn from(error: zbus::Error) -> Self {
        let name = match &error {
            zbus::Error::MethodError(name, _, _) => name.as_str().to_owned(),
            other => other.to_string(),
        };
        if name.contains("IsLocked") {
            Failure::Locked
        } else if name.contains("ServiceUnknown") || name.contains("NameHasNoOwner") {
            Failure::Vault(failed("no Secret Service on the session bus"))
        } else {
            Failure::Vault(failed(&format!("D-Bus error {name}")))
        }
    }
}

fn failed(detail: &str) -> VaultError {
    VaultError::ToolFailed { program: PROGRAM.to_owned(), detail: detail.to_owned() }
}

fn unlock_hint(vault: VaultKind) -> &'static str {
    match vault {
        VaultKind::KeePassXc => "open and unlock the database in the KeePassXC app",
        _ => "unlock the keyring (it usually opens with your login)",
    }
}

/// Runs `work` with [`TIMEOUT`], mapping failures for `vault`.
async fn bounded<T>(
    vault: VaultKind,
    work: impl Future<Output = Result<T, Failure>>,
) -> Result<T, VaultError> {
    match tokio::time::timeout(TIMEOUT, work).await {
        Ok(result) => result.map_err(|failure| failure.into_error(vault)),
        Err(_) => Err(VaultError::Timeout { program: PROGRAM.to_owned() }),
    }
}

/// An open Secret Service session.
struct Session {
    connection: Connection,
    service: Proxy<'static>,
    path: OwnedObjectPath,
}

impl Session {
    async fn open() -> Result<Self, Failure> {
        let connection =
            Connection::session().await.map_err(|_| Failure::Vault(failed("no D-Bus session bus")))?;
        let service = Proxy::new_owned(connection.clone(), SERVICE, SERVICE_PATH, SERVICE_INTERFACE).await?;
        let (_, path): (OwnedVariant, OwnedObjectPath) =
            service.call("OpenSession", &("plain", Variant::from(""))).await?;
        Ok(Self { connection, service, path })
    }

    async fn close(self) {
        if let Ok(session) =
            Proxy::new(&self.connection, SERVICE, self.path.as_ref(), "org.freedesktop.Secret.Session").await
        {
            let _ = session.call::<_, _, ()>("Close", &()).await;
        }
    }

    /// Unlocked and locked items matching all `attributes`.
    async fn search(
        &self,
        attributes: &HashMap<&str, &str>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), Failure> {
        Ok(self.service.call("SearchItems", &(attributes,)).await?)
    }

    async fn item(&self, path: &OwnedObjectPath) -> Result<Proxy<'static>, Failure> {
        Ok(Proxy::new_owned(self.connection.clone(), SERVICE, path.clone(), ITEM_INTERFACE).await?)
    }

    async fn secret(&self, item: &Proxy<'_>) -> Result<Secret, Failure> {
        let reply = item.call_method("GetSecret", &(&self.path,)).await?;
        let body = reply.body();
        let (_, mut parameters, value, _): WireSecret = body.deserialize_ignore_signature()?;
        parameters.zeroize();
        let value = Zeroizing::new(value);
        let text =
            std::str::from_utf8(&value).map_err(|_| Failure::Vault(failed("the secret is not UTF-8")))?;
        Ok(Secret::new(text.to_owned()))
    }

    fn wire(&self, value: &Secret) -> (ObjectPath<'_>, Vec<u8>, Zeroizing<Vec<u8>>, &'static str) {
        (self.path.as_ref(), Vec::new(), Zeroizing::new(value.expose().as_bytes().to_vec()), "text/plain")
    }

    async fn set_secret(&self, item: &Proxy<'_>, value: &Secret) -> Result<(), Failure> {
        let (path, parameters, bytes, content_type) = self.wire(value);
        item.call::<_, _, ()>("SetSecret", &((path, parameters, &*bytes, content_type),)).await?;
        Ok(())
    }

    /// Creates (or replaces) an item in the default collection.
    async fn create(
        &self,
        label: &str,
        attributes: HashMap<&str, &str>,
        value: &Secret,
    ) -> Result<(), Failure> {
        let collection: OwnedObjectPath = self.service.call("ReadAlias", &("default",)).await?;
        if collection.as_str() == "/" {
            return Err(Failure::Vault(failed("there is no default collection")));
        }
        let collection =
            Proxy::new_owned(self.connection.clone(), SERVICE, collection, COLLECTION_INTERFACE).await?;
        let mut properties: HashMap<&str, Variant<'_>> = HashMap::new();
        properties.insert(LABEL_PROPERTY, Variant::from(label));
        properties.insert(ATTRIBUTES_PROPERTY, Variant::from(attributes));
        let (path, parameters, bytes, content_type) = self.wire(value);
        let (_, prompt): (OwnedObjectPath, OwnedObjectPath) = collection
            .call("CreateItem", &(properties, (path, parameters, &*bytes, content_type), true))
            .await?;
        if prompt.as_str() != "/" {
            return Err(Failure::Locked);
        }
        Ok(())
    }
}

/// Reads the first unlocked item matching `attributes`; `Ok(None)` if none matches.
pub(super) async fn read(attributes: &[(String, String)]) -> Result<Option<Secret>, VaultError> {
    let vault = VaultKind::SecretService;
    bounded(vault, async {
        let session = Session::open().await?;
        let result = async {
            let query: HashMap<&str, &str> =
                attributes.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let (unlocked, locked) = session.search(&query).await?;
            match unlocked.first() {
                Some(path) => Ok(Some(session.secret(&session.item(path).await?).await?)),
                None if !locked.is_empty() => Err(Failure::Locked),
                None => Ok(None),
            }
        }
        .await;
        session.close().await;
        result
    })
    .await
}

/// Stores `value` under `attributes` in the default collection, replacing an item with
/// the same attributes. The label is the reference.
pub(super) async fn write(
    label: &str,
    attributes: &[(String, String)],
    value: &Secret,
) -> Result<(), VaultError> {
    let vault = VaultKind::SecretService;
    bounded(vault, async {
        let session = Session::open().await?;
        let query: HashMap<&str, &str> = attributes.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let result = session.create(label, query, value).await;
        session.close().await;
        result
    })
    .await
}

/// Picks the item of `entry` among KeePassXC items with its title, by their `Path`
/// attribute (`Group/Sub/Title`, root group left out).
fn matches_entry(attributes: &HashMap<String, String>, entry: &Entry<'_>) -> bool {
    let wanted = entry.path();
    attributes.get("Path").is_some_and(|path| path.trim_start_matches('/') == wanted)
}

/// Finds the KeePassXC item of `entry`, with its attributes.
async fn find_entry(
    session: &Session,
    entry: &Entry<'_>,
) -> Result<Option<(Proxy<'static>, HashMap<String, String>)>, Failure> {
    let query = HashMap::from([("Title", entry.item)]);
    let (unlocked, locked) = session.search(&query).await?;
    for path in &unlocked {
        let item = session.item(path).await?;
        let attributes: HashMap<String, String> = item.get_property("Attributes").await?;
        if matches_entry(&attributes, entry) {
            return Ok(Some((item, attributes)));
        }
    }
    if locked.is_empty() { Ok(None) } else { Err(Failure::Locked) }
}

/// Reads a KeePassXC entry: `password` is the item secret, other fields attributes.
pub(super) async fn keepassxc_read(entry: &Entry<'_>) -> Result<Option<Secret>, VaultError> {
    bounded(VaultKind::KeePassXc, async {
        let session = Session::open().await?;
        let result = async {
            let Some((item, attributes)) = find_entry(&session, entry).await? else {
                return Ok(None);
            };
            if entry.attribute() == "Password" {
                return Ok(Some(session.secret(&item).await?));
            }
            Ok(attributes.get(entry.attribute()).map(|value| Secret::new(value.clone())))
        }
        .await;
        session.close().await;
        result
    })
    .await
}

/// Writes a KeePassXC entry. A new entry (password only) lands in the group KeePassXC
/// exposes, whatever group the reference names.
pub(super) async fn keepassxc_write(entry: &Entry<'_>, value: &Secret) -> Result<(), VaultError> {
    bounded(VaultKind::KeePassXc, async {
        let session = Session::open().await?;
        let result = async {
            match find_entry(&session, entry).await? {
                Some((item, _)) if entry.attribute() == "Password" => session.set_secret(&item, value).await,
                Some((item, mut attributes)) => {
                    attributes.insert(entry.attribute().to_owned(), value.expose().to_owned());
                    item.set_property("Attributes", attributes).await.map_err(zbus::Error::from)?;
                    Ok(())
                }
                None if entry.attribute() == "Password" => {
                    session.create(entry.item, HashMap::from([("Title", entry.item)]), value).await
                }
                None => Err(Failure::Vault(VaultError::Unsupported {
                    vault: VaultKind::KeePassXc,
                    reason: "create the entry in KeePassXC first; only passwords create new entries"
                        .to_owned(),
                })),
            }
        }
        .await;
        session.close().await;
        result
    })
    .await
}

/// Whether a Secret Service is running or activatable on the session bus.
pub(super) async fn available() -> (bool, Option<String>) {
    let check = async {
        let connection = Connection::session().await.ok()?;
        let bus =
            Proxy::new(&connection, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus")
                .await
                .ok()?;
        let running: bool = bus.call("NameHasOwner", &(SERVICE,)).await.ok()?;
        if running {
            return Some(true);
        }
        let activatable: Vec<String> = bus.call("ListActivatableNames", &()).await.ok()?;
        Some(activatable.iter().any(|name| name == SERVICE))
    };
    match tokio::time::timeout(Duration::from_secs(5), check).await {
        Ok(Some(true)) => (true, None),
        Ok(Some(false)) => (false, Some("no Secret Service on the session bus".to_owned())),
        Ok(None) | Err(_) => (false, Some("no D-Bus session bus".to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_matching_uses_the_path_attribute() {
        let group = vec!["Dev".to_owned()];
        let entry = Entry { group: &group, item: "app", field: "password" };
        let attributes = |path: &str| HashMap::from([("Path".to_owned(), path.to_owned())]);
        assert!(matches_entry(&attributes("Dev/app"), &entry));
        assert!(matches_entry(&attributes("/Dev/app"), &entry));
        assert!(!matches_entry(&attributes("Other/app"), &entry));
        assert!(!matches_entry(&HashMap::new(), &entry));
    }

    #[test]
    fn wire_shapes_match_the_specification() {
        // The header carries the body signature as text; look for it in the raw message.
        let has = |message: &zbus::Message, needle: &[u8]| {
            message.data().windows(needle.len()).any(|w| w == needle)
        };
        let path = ObjectPath::try_from("/org/freedesktop/secrets/session/s1").unwrap();
        let secret: (ObjectPath<'_>, Vec<u8>, &[u8], &str) = (path, Vec::new(), b"pw", "text/plain");

        // SetSecret's argument and GetSecret's reply: one (oayays) struct, not four values.
        let message = zbus::Message::method_call("/x", "SetSecret").build(&(secret.clone(),)).unwrap();
        assert!(has(&message, b"\x08(oayays)\0"));
        let (_, _, value, content_type): WireSecret = message.body().deserialize_ignore_signature().unwrap();
        assert_eq!((value.as_slice(), content_type.as_str()), (&b"pw"[..], "text/plain"));

        // CreateItem: properties, secret, replace.
        let properties: HashMap<&str, Variant<'_>> = HashMap::from([(LABEL_PROPERTY, Variant::from("l"))]);
        let message =
            zbus::Message::method_call("/x", "CreateItem").build(&(properties, secret, true)).unwrap();
        assert!(has(&message, b"\x0ea{sv}(oayays)b\0"));
    }

    #[test]
    fn dbus_errors_are_classified() {
        let failure = Failure::from(zbus::Error::Failure("org.freedesktop.Secret.Error.IsLocked".to_owned()));
        let error = failure.into_error(VaultKind::KeePassXc);
        assert_eq!(
            error.to_string(),
            "vault keepassxc is locked: open and unlock the database in the KeePassXC app"
        );
        let failure = Failure::from(zbus::Error::Failure("boom".to_owned()));
        assert!(matches!(failure.into_error(VaultKind::SecretService), VaultError::ToolFailed { .. }));
    }
}
