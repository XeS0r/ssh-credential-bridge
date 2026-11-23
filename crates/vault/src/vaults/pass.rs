//! pass (or gopass when pass is not installed). The secret is the first line of the
//! entry, as pass itself treats it; an entry that starts with a PEM block (`-----BEGIN`)
//! yields the whole block, so private keys stored by `ctl source add github --auth app
//! --create` read back.
//! Decryption runs through gpg-agent and its pinentry.

use credential_bridge_config::VaultKind;
use credential_bridge_proto::secret::Secret;

use crate::error::VaultError;
use crate::runner::{CommandOutput, CommandRunner, CommandSpec};
use crate::tool::{self, Owner};

const VAULT: VaultKind = VaultKind::Pass;

/// stderr phrases for a missing entry.
const NOT_FOUND: &[&str] = &["is not in the password store", "entry not found", "not found"];

/// stderr phrases of gpg failing to decrypt.
const GPG_LOCKED: &[&str] = &["decryption failed", "no secret key", "pinentry", "bad passphrase"];

/// Runs `pass args`, or `gopass gopass_args` if pass is not installed.
async fn run<R: CommandRunner>(
    runner: &R,
    pass_args: &[&str],
    gopass_args: &[&str],
    stdin: Option<&Secret>,
) -> Result<(&'static str, CommandOutput), VaultError> {
    let with_stdin = |spec: CommandSpec| match stdin {
        Some(input) => spec.with_stdin(input.clone()),
        None => spec,
    };
    let pass = with_stdin(CommandSpec::new("pass", pass_args.iter().copied()));
    match tool::run(runner, Owner::Vault(VAULT), &pass).await {
        Err(VaultError::ToolMissing { .. }) => {}
        other => return other.map(|output| ("pass", output)),
    }
    let gopass = with_stdin(CommandSpec::new("gopass", gopass_args.iter().copied()));
    match tool::run(runner, Owner::Vault(VAULT), &gopass).await {
        Err(VaultError::ToolMissing { .. }) => {
            Err(VaultError::ToolMissing { vault: VAULT, program: "pass".to_owned() })
        }
        other => other.map(|output| ("gopass", output)),
    }
}

/// The error for a failed run, or `None` if the entry does not exist.
fn classify(program: &str, output: &CommandOutput) -> Option<VaultError> {
    if tool::stderr_mentions(output, GPG_LOCKED) {
        Some(VaultError::LockedElsewhere {
            vault: VAULT,
            hint:
                "gpg could not decrypt the entry: check that gpg-agent can ask for your passphrase (pinentry)"
                    .to_owned(),
        })
    } else if tool::stderr_mentions(output, NOT_FOUND) {
        None
    } else {
        Some(tool::failed(program, output))
    }
}

/// Reads the secret of entry `path`; `Ok(None)` if it does not exist.
pub(super) async fn read<R: CommandRunner>(runner: &R, path: &str) -> Result<Option<Secret>, VaultError> {
    let (program, output) = run(runner, &["show", path], &["show", "--noparsing", path], None).await?;
    if !output.success() {
        return match classify(program, &output) {
            Some(error) => Err(error),
            None => Ok(None),
        };
    }
    Ok(entry_secret(output.stdout.expose()))
}

/// Replaces entry `path` with `value` (multi-line mode, from stdin).
pub(super) async fn write<R: CommandRunner>(
    runner: &R,
    path: &str,
    value: &Secret,
) -> Result<(), VaultError> {
    let args = ["insert", "--multiline", "--force", path];
    let (program, output) = run(runner, &args, &args, Some(value)).await?;
    if output.success() {
        Ok(())
    } else {
        Err(classify(program, &output).unwrap_or_else(|| tool::failed(program, &output)))
    }
}

/// The secret of an entry: the first line, or the leading PEM block.
fn entry_secret(content: &str) -> Option<Secret> {
    let mut lines = content.lines();
    let first = lines.next()?.trim_end_matches('\r');
    if !first.starts_with("-----BEGIN ") {
        return Some(Secret::new(first.to_owned())).filter(|secret| !secret.is_empty());
    }
    let mut block = String::with_capacity(content.len());
    block.push_str(first);
    block.push('\n');
    for line in lines {
        let line = line.trim_end_matches('\r');
        block.push_str(line);
        block.push('\n');
        if line.starts_with("-----END ") {
            break;
        }
    }
    Some(Secret::new(block))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vaults::tests::FakeBin;

    #[test]
    fn first_line_or_pem_block() {
        assert_eq!(entry_secret("tok\nuser: me\n").unwrap().expose(), "tok");
        assert_eq!(entry_secret("tok\r\n").unwrap().expose(), "tok");
        assert!(entry_secret("").is_none());
        assert!(entry_secret("\nbody").is_none());
        let pem = "-----BEGIN KEY-----\nabc\n-----END KEY-----\nnote: x\n";
        assert_eq!(entry_secret(pem).unwrap().expose(), "-----BEGIN KEY-----\nabc\n-----END KEY-----\n");
    }

    #[tokio::test]
    async fn uses_pass_and_maps_errors() {
        let bin = FakeBin::new();
        let store = bin.path().join("store");
        bin.script(
            "pass",
            &format!(
                r#"case "$1 $2" in
  "show dev/token") printf 'tok\nurl: x\n' ;;
  "show dev/locked") echo 'gpg: decryption failed: No secret key' >&2; exit 2 ;;
  "show "*) echo "Error: $2 is not in the password store." >&2; exit 1 ;;
  "insert --multiline") cat > '{store}' ;;
esac"#,
                store = store.display()
            ),
        );
        let runner = bin.runner();
        assert_eq!(read(&runner, "dev/token").await.unwrap().unwrap().expose(), "tok");
        assert!(read(&runner, "dev/none").await.unwrap().is_none());
        assert!(matches!(read(&runner, "dev/locked").await, Err(VaultError::LockedElsewhere { .. })));
        write(&runner, "dev/new", &Secret::new("line1\nline2".to_owned())).await.unwrap();
        assert_eq!(std::fs::read_to_string(&store).unwrap(), "line1\nline2");
    }

    #[tokio::test]
    async fn falls_back_to_gopass() {
        let bin = FakeBin::new();
        bin.script("gopass", r#"[ "$1 $2 $3" = "show --noparsing dev/token" ] && printf 'gtok\n'"#);
        // Only the fake directory, so no real `pass` is found.
        let runner = crate::runner::SystemRunner::new(vec![(
            "PATH".into(),
            format!("{}:/bin:/usr/bin", bin.path().display()),
        )]);
        if std::path::Path::new("/usr/bin/pass").exists() || std::path::Path::new("/bin/pass").exists() {
            return;
        }
        assert_eq!(read(&runner, "dev/token").await.unwrap().unwrap().expose(), "gtok");
    }
}
