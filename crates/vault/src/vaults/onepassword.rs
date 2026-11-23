//! 1Password through `op`. Reading uses `op read`; the desktop app approves the request,
//! so there is no unlock session here. Writing fetches the item as JSON, changes the
//! field and pipes the item JSON to `op item edit` (or `op item create`) on stdin.

use credential_bridge_config::VaultKind;
use credential_bridge_proto::secret::Secret;
use serde_json::{Value, json};

use super::json::WipedJson;
use crate::error::VaultError;
use crate::runner::{CommandOutput, CommandRunner, CommandSpec};
use crate::tool::{self, Owner};

const PROGRAM: &str = "op";
const VAULT: VaultKind = VaultKind::OnePassword;

/// stderr phrases of `op` for a missing vault, item or field.
const NOT_FOUND: &[&str] =
    &["isn't an item", "isn't a vault", "isn't a field", "could not find", "no item found", "not found"];

/// stderr phrases of `op` for a locked app, a missing sign-in or a refused approval.
const LOCKED: &[&str] = &[
    "not currently signed in",
    "not signed in",
    "authorization prompt dismissed",
    "authorization timeout",
    "session expired",
    "account is locked",
    "connecting to desktop app",
];

/// What to do when 1Password is locked.
const UNLOCK_HINT: &str = "unlock the 1Password app (or run op signin) and approve the request";

/// The parts of an `op://vault/item/[section/]field` URI.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Uri<'a> {
    vault: &'a str,
    item: &'a str,
    section: Option<&'a str>,
    field: &'a str,
}

impl<'a> Uri<'a> {
    fn parse(uri: &'a str) -> Result<Self, VaultError> {
        let invalid = || VaultError::Invalid(format!("{uri} is not op://vault/item/[section/]field"));
        let rest = uri.strip_prefix("op://").ok_or_else(invalid)?;
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.iter().any(|part| part.is_empty()) {
            return Err(invalid());
        }
        match parts[..] {
            [vault, item, field] => Ok(Self { vault, item, section: None, field }),
            [vault, item, section, field] => Ok(Self { vault, item, section: Some(section), field }),
            _ => Err(invalid()),
        }
    }
}

/// The error for a failed `op` run, or `None` if it means "not found".
fn classify(output: &CommandOutput) -> Option<VaultError> {
    if tool::stderr_mentions(output, LOCKED) {
        Some(VaultError::LockedElsewhere { vault: VAULT, hint: UNLOCK_HINT.to_owned() })
    } else if tool::stderr_mentions(output, NOT_FOUND) {
        None
    } else {
        Some(tool::failed(PROGRAM, output))
    }
}

/// Runs `spec`; `Ok(None)` if op reports that something does not exist.
async fn run<R: CommandRunner>(runner: &R, spec: &CommandSpec) -> Result<Option<CommandOutput>, VaultError> {
    let output = tool::run(runner, Owner::Vault(VAULT), spec).await?;
    if output.success() {
        return Ok(Some(output));
    }
    match classify(&output) {
        Some(error) => Err(error),
        None => Ok(None),
    }
}

/// `op read --no-newline <uri>`.
pub(super) async fn read<R: CommandRunner>(runner: &R, uri: &str) -> Result<Option<Secret>, VaultError> {
    let spec = CommandSpec::new(PROGRAM, ["read", "--no-newline", uri]);
    Ok(run(runner, &spec).await?.map(|output| output.stdout))
}

/// Sets the field `uri` names, creating the item or field if needed.
pub(super) async fn write<R: CommandRunner>(runner: &R, uri: &str, value: &Secret) -> Result<(), VaultError> {
    let uri = Uri::parse(uri)?;
    let get = CommandSpec::new(PROGRAM, ["item", "get", uri.item, "--vault", uri.vault, "--format", "json"]);
    let spec = match run(runner, &get).await? {
        Some(output) => {
            let mut item =
                WipedJson::parse(&output.stdout).filter(|item| item.is_object()).ok_or_else(|| {
                    VaultError::ToolFailed {
                        program: PROGRAM.to_owned(),
                        detail: "unusable item JSON".to_owned(),
                    }
                })?;
            let id = item.get("id").and_then(Value::as_str).unwrap_or(uri.item).to_owned();
            set_field(&mut item, &uri, value);
            CommandSpec::new(PROGRAM, ["item", "edit", &id, "--vault", uri.vault, "--format", "json"])
                .with_stdin(item.to_secret())
        }
        None => {
            let category = if uri.field == "password" { "PASSWORD" } else { "SECURE_NOTE" };
            let mut item =
                WipedJson(json!({ "title": uri.item, "category": category, "fields": [], "sections": [] }));
            set_field(&mut item, &uri, value);
            CommandSpec::new(PROGRAM, ["item", "create", "--vault", uri.vault, "--format", "json"])
                .with_stdin(item.to_secret())
        }
    };
    let output = tool::run(runner, Owner::Vault(VAULT), &spec).await?;
    if output.success() {
        Ok(())
    } else {
        Err(classify(&output).unwrap_or_else(|| tool::failed(PROGRAM, &output)))
    }
}

/// Whether the op field `field` is the one `uri` names (by label or id, and section).
fn is_target(field: &Value, uri: &Uri<'_>) -> bool {
    let named = |value: &Value, name: &str| {
        value.get("label").and_then(Value::as_str) == Some(name)
            || value.get("id").and_then(Value::as_str) == Some(name)
    };
    named(field, uri.field)
        && match uri.section {
            None => true,
            Some(section) => field.get("section").is_some_and(|s| named(s, section)),
        }
}

/// Sets the field of `uri` in item JSON, adding the field (and its section) if missing.
fn set_field(item: &mut Value, uri: &Uri<'_>, value: &Secret) {
    let text = Value::String(value.expose().to_owned());
    if !item.get("fields").is_some_and(Value::is_array) {
        item["fields"] = json!([]);
    }
    if let Some(existing) =
        item["fields"].as_array_mut().and_then(|fields| fields.iter_mut().find(|field| is_target(field, uri)))
    {
        existing["value"] = text;
        return;
    }
    let mut field = json!({ "id": uri.field, "label": uri.field, "type": "CONCEALED", "value": text });
    if uri.field == "password" {
        field["purpose"] = json!("PASSWORD");
    }
    if let Some(section) = uri.section {
        if !item.get("sections").is_some_and(Value::is_array) {
            item["sections"] = json!([]);
        }
        let sections = item["sections"].as_array_mut().expect("sections is an array");
        let known = sections.iter().find(|s| {
            s.get("label").and_then(Value::as_str) == Some(section)
                || s.get("id").and_then(Value::as_str) == Some(section)
        });
        let id = match known {
            Some(known) => known.get("id").cloned().unwrap_or_else(|| json!(section)),
            None => {
                sections.push(json!({ "id": section, "label": section }));
                json!(section)
            }
        };
        field["section"] = json!({ "id": id });
    }
    if let Some(fields) = item["fields"].as_array_mut() {
        fields.push(field);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vaults::tests::FakeBin;

    #[test]
    fn parses_uris() {
        let uri = Uri::parse("op://Dev/app/key").unwrap();
        assert_eq!(uri, Uri { vault: "Dev", item: "app", section: None, field: "key" });
        let uri = Uri::parse("op://Dev/app/sec/key").unwrap();
        assert_eq!(uri.section, Some("sec"));
        for bad in ["op://Dev/app", "op://Dev//key", "bw://x/y", "op://a/b/c/d/e"] {
            assert!(Uri::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn sets_existing_and_new_fields() {
        let mut item = json!({
            "id": "x",
            "fields": [
                { "id": "password", "label": "password", "value": "old" },
                { "id": "k1", "label": "key", "value": "a", "section": { "id": "s1", "label": "API" } },
            ],
            "sections": [{ "id": "s1", "label": "API" }],
        });
        let value = Secret::new("new".to_owned());
        set_field(&mut item, &Uri::parse("op://V/x/password").unwrap(), &value);
        assert_eq!(item["fields"][0]["value"], "new");
        set_field(&mut item, &Uri::parse("op://V/x/API/key").unwrap(), &value);
        assert_eq!(item["fields"][1]["value"], "new");
        set_field(&mut item, &Uri::parse("op://V/x/API/other").unwrap(), &value);
        assert_eq!(item["fields"][2]["section"]["id"], "s1");
        set_field(&mut item, &Uri::parse("op://V/x/Fresh/k").unwrap(), &value);
        assert_eq!(item["sections"][1]["label"], "Fresh");
        assert_eq!(item["fields"][3]["section"]["id"], "Fresh");
    }

    #[tokio::test]
    async fn reads_and_classifies_errors() {
        let bin = FakeBin::new();
        bin.script(
            "op",
            r#"case "$3" in
  op://Dev/app/key) printf 's3cret' ;;
  op://Dev/app/missing) echo '[ERROR] could not read secret: "missing" isn'"'"'t a field in the "app" item' >&2; exit 1 ;;
  *) echo '[ERROR] authorization prompt dismissed, please try again' >&2; exit 1 ;;
esac"#,
        );
        let runner = bin.runner();
        assert_eq!(read(&runner, "op://Dev/app/key").await.unwrap().unwrap().expose(), "s3cret");
        assert!(read(&runner, "op://Dev/app/missing").await.unwrap().is_none());
        let error = read(&runner, "op://Dev/other/key").await.unwrap_err();
        assert!(matches!(error, VaultError::LockedElsewhere { vault: VaultKind::OnePassword, .. }));
        assert!(error.to_string().starts_with("vault 1password is locked: "));
    }

    #[tokio::test]
    async fn write_pipes_item_json() {
        let bin = FakeBin::new();
        let log = bin.path().join("log");
        bin.script(
            "op",
            &format!(
                r#"case "$1 $2" in
  "item get") [ "$3" = app ] && printf '{{"id":"id1","fields":[{{"id":"k","label":"key","value":"old"}}]}}' && exit 0
              echo '[ERROR] "new" isn'"'"'t an item in the "Dev" vault' >&2; exit 1 ;;
  "item edit"|"item create") echo "$*" >> '{log}'; cat >> '{log}'; echo >> '{log}' ;;
esac"#,
                log = log.display()
            ),
        );
        let runner = bin.runner();
        let value = Secret::new("v".to_owned());
        write(&runner, "op://Dev/app/key", &value).await.unwrap();
        write(&runner, "op://Dev/new/password", &value).await.unwrap();
        let log = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines[0], "item edit id1 --vault Dev --format json");
        let edited: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(edited["fields"][0]["value"], "v");
        assert_eq!(lines[2], "item create --vault Dev --format json");
        let created: Value = serde_json::from_str(lines[3]).unwrap();
        assert_eq!(
            (created["title"].as_str(), created["category"].as_str()),
            (Some("new"), Some("PASSWORD"))
        );
    }
}
