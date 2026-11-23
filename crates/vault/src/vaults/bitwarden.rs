//! Bitwarden through `bw`, with the session key from `ctl vault unlock bitwarden` in
//! `BW_SESSION`. The master password reaches `bw unlock` via `BW_PASSWORD`, item JSON
//! reaches `bw create`/`bw edit` base64-encoded on stdin.

use credential_bridge_config::VaultKind;
use credential_bridge_proto::secret::Secret;
use serde_json::{Value, json};

use super::json::{WipedJson, base64};
use crate::error::VaultError;
use crate::runner::{CommandOutput, CommandRunner, CommandSpec};
use crate::tool::{self, Owner};

const PROGRAM: &str = "bw";
const VAULT: VaultKind = VaultKind::Bitwarden;

/// `bw <args> --nointeraction`, with `BW_SESSION` if given.
fn spec(args: &[&str], session: Option<&Secret>) -> CommandSpec {
    let mut spec = CommandSpec::new(PROGRAM, args.iter().copied().chain(["--nointeraction"]))
        .with_env("BW_NOINTERACTION", Secret::new("true".to_owned()));
    if let Some(session) = session {
        spec = spec.with_env("BW_SESSION", session.clone());
    }
    spec
}

/// Runs `spec`; `Ok(None)` if bw reports that the item does not exist.
async fn run<R: CommandRunner>(
    runner: &R,
    spec: &CommandSpec,
    item: &str,
) -> Result<Option<CommandOutput>, VaultError> {
    let output = tool::run(runner, Owner::Vault(VAULT), spec).await?;
    if output.success() {
        return Ok(Some(output));
    }
    if tool::stderr_mentions(&output, &["not found"]) {
        return Ok(None);
    }
    Err(classify(&output, item))
}

/// The error for a failed `bw` run.
fn classify(output: &CommandOutput, item: &str) -> VaultError {
    if tool::stderr_mentions(output, &["not logged in"]) {
        VaultError::LockedElsewhere {
            vault: VAULT,
            hint: "log in with bw login, then run credential-bridge-ctl vault unlock bitwarden".to_owned(),
        }
    } else if tool::stderr_mentions(output, &["vault is locked", "session key is invalid", "invalid session"])
    {
        VaultError::Locked { vault: VAULT }
    } else if tool::stderr_mentions(output, &["more than one result"]) {
        VaultError::Invalid(format!("bitwarden item {item:?} is ambiguous: use its id"))
    } else {
        tool::failed(PROGRAM, output)
    }
}

/// Reads `field` of `item`: `password`, `username`, `notes`, `totp` (the current code)
/// or a custom field. `Ok(None)` if the item or field does not exist.
pub(super) async fn read<R: CommandRunner>(
    runner: &R,
    session: &Secret,
    item: &str,
    field: &str,
) -> Result<Option<Secret>, VaultError> {
    if field == "totp" {
        let Some(output) = run(runner, &spec(&["get", "totp", item], Some(session)), item).await? else {
            return Ok(None);
        };
        return Ok(Some(Secret::new(output.stdout.expose().trim().to_owned())));
    }
    let Some(found) = get_item(runner, session, item).await? else {
        return Ok(None);
    };
    Ok(field_value(&found, field))
}

/// The item JSON, or `None` if it does not exist.
async fn get_item<R: CommandRunner>(
    runner: &R,
    session: &Secret,
    item: &str,
) -> Result<Option<WipedJson>, VaultError> {
    let Some(output) = run(runner, &spec(&["get", "item", item], Some(session)), item).await? else {
        return Ok(None);
    };
    let parsed = WipedJson::parse(&output.stdout).filter(|json| json.is_object()).ok_or_else(|| {
        VaultError::ToolFailed { program: PROGRAM.to_owned(), detail: "unusable item JSON".to_owned() }
    })?;
    Ok(Some(parsed))
}

/// `field` of an item. `password` and `username` of items that are not logins are
/// custom fields, as [`set_field`] writes them.
fn field_value(item: &Value, field: &str) -> Option<Secret> {
    let login = item.get("login").filter(|login| login.is_object());
    let value = match (field, login) {
        ("password" | "username", Some(login)) => login.get(field),
        ("notes", _) => item.get("notes"),
        _ => item
            .get("fields")
            .and_then(Value::as_array)
            .and_then(|fields| fields.iter().find(|f| f.get("name").and_then(Value::as_str) == Some(field)))
            .and_then(|f| f.get("value")),
    };
    value.and_then(Value::as_str).map(|text| Secret::new(text.to_owned()))
}

/// Sets `field` of an item (see [`read`]); `totp` sets the TOTP seed.
fn set_field(item: &mut Value, field: &str, value: &Secret) {
    let text = Value::String(value.expose().to_owned());
    let login = item.get_mut("login").filter(|login| login.is_object());
    match (field, login) {
        ("password" | "username" | "totp", Some(login)) => {
            login[field] = text;
        }
        ("notes", _) => item["notes"] = text,
        _ => {
            if !item.get("fields").is_some_and(Value::is_array) {
                item["fields"] = json!([]);
            }
            if let Some(fields) = item["fields"].as_array_mut() {
                match fields.iter_mut().find(|f| f.get("name").and_then(Value::as_str) == Some(field)) {
                    Some(existing) => existing["value"] = text,
                    // Type 1: a hidden field.
                    None => fields.push(json!({ "name": field, "value": text, "type": 1 })),
                }
            }
        }
    }
}

/// Writes `field` of `item`, creating a login item if there is none.
pub(super) async fn write<R: CommandRunner>(
    runner: &R,
    session: &Secret,
    item: &str,
    field: &str,
    value: &Secret,
) -> Result<(), VaultError> {
    let (mut json, id) = match get_item(runner, session, item).await? {
        Some(found) => {
            let id = found.get("id").and_then(Value::as_str).map(str::to_owned).ok_or_else(|| {
                VaultError::ToolFailed { program: PROGRAM.to_owned(), detail: "item without id".to_owned() }
            })?;
            (found, Some(id))
        }
        None => {
            let new = json!({
                "type": 1,
                "name": item,
                "notes": null,
                "favorite": false,
                "fields": [],
                "login": { "uris": [], "username": null, "password": null, "totp": null },
                "reprompt": 0,
            });
            (WipedJson(new), None)
        }
    };
    set_field(&mut json, field, value);
    let encoded = base64(json.to_secret().expose().as_bytes());
    let spec = match &id {
        Some(id) => spec(&["edit", "item", id], Some(session)),
        None => spec(&["create", "item"], Some(session)),
    }
    .with_stdin(encoded);
    let output = tool::run(runner, Owner::Vault(VAULT), &spec).await?;
    if output.success() { Ok(()) } else { Err(classify(&output, item)) }
}

/// `bw unlock --raw` with the master password; returns the session key.
pub(super) async fn unlock<R: CommandRunner>(runner: &R, password: Secret) -> Result<Secret, VaultError> {
    let spec =
        spec(&["unlock", "--raw", "--passwordenv", "BW_PASSWORD"], None).with_env("BW_PASSWORD", password);
    let output = tool::run(runner, Owner::Vault(VAULT), &spec).await?;
    drop(spec);
    let key = output.stdout.expose().trim();
    if output.success() && !key.is_empty() {
        return Ok(Secret::new(key.to_owned()));
    }
    if tool::stderr_mentions(&output, &["invalid master password"]) {
        return Err(VaultError::ToolFailed {
            program: PROGRAM.to_owned(),
            detail: "wrong master password".to_owned(),
        });
    }
    Err(classify(&output, ""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vaults::tests::FakeBin;

    fn secret(text: &str) -> Secret {
        Secret::new(text.to_owned())
    }

    #[test]
    fn reads_and_sets_fields() {
        let mut item = json!({
            "login": { "username": "me", "password": "pw" },
            "notes": "n",
            "fields": [{ "name": "token", "value": "t" }],
        });
        assert_eq!(field_value(&item, "username").unwrap().expose(), "me");
        assert_eq!(field_value(&item, "notes").unwrap().expose(), "n");
        assert_eq!(field_value(&item, "token").unwrap().expose(), "t");
        assert!(field_value(&item, "other").is_none());
        set_field(&mut item, "password", &secret("new"));
        set_field(&mut item, "token", &secret("t2"));
        set_field(&mut item, "key", &secret("k"));
        assert_eq!(item["login"]["password"], "new");
        assert_eq!(item["fields"][0]["value"], "t2");
        assert_eq!(item["fields"][1], json!({ "name": "key", "value": "k", "type": 1 }));

        let mut note = json!({ "type": 2, "login": null });
        set_field(&mut note, "password", &secret("p"));
        assert_eq!(note["fields"][0]["name"], "password");
        assert_eq!(field_value(&note, "password").unwrap().expose(), "p");
    }

    #[tokio::test]
    async fn store_edits_or_creates_via_stdin() {
        let bin = FakeBin::new();
        let log = bin.path().join("log");
        bin.script(
            "bw",
            &format!(
                r#"case "$1 $2 $3" in
  "get item app") printf '{{"id":"abc","name":"app","login":{{"password":"old"}}}}' ;;
  "get item new") echo "Not found." >&2; exit 1 ;;
  "edit item abc"|"create item --nointeraction") echo "$1 $2" >> '{log}'; base64 -d >> '{log}'; echo >> '{log}' ;;
  *) echo "unexpected $*" >&2; exit 9 ;;
esac"#,
                log = log.display()
            ),
        );
        let runner = bin.runner();
        let session = secret("s");
        write(&runner, &session, "app", "password", &secret("v1")).await.unwrap();
        write(&runner, &session, "new", "token", &secret("v2")).await.unwrap();
        let log = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines[0], "edit item");
        let edited: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(edited["login"]["password"], "v1");
        assert_eq!(lines[2], "create item");
        let created: Value = serde_json::from_str(lines[3]).unwrap();
        assert_eq!(created["name"], "new");
        assert_eq!(created["fields"][0]["value"], "v2");
        // The value never appears on a command line.
        assert!(!log.contains("unexpected"));
    }

    #[tokio::test]
    async fn not_logged_in_says_so() {
        let bin = FakeBin::new();
        bin.script("bw", "echo 'You are not logged in.' >&2; exit 1");
        let error = unlock(&bin.runner(), secret("pw")).await.unwrap_err();
        assert!(error.to_string().contains("bw login"), "{error}");
        let error = read(&bin.runner(), &secret("s"), "app", "password").await.unwrap_err();
        assert!(matches!(error, VaultError::LockedElsewhere { .. }));
    }
}
