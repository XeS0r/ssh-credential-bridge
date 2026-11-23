//! `cmd:` references: a command line run through `sh -c`; the secret is its stdout with
//! one trailing newline removed. Read-only.

use credential_bridge_config::VaultKind;
use credential_bridge_proto::secret::Secret;

use crate::error::VaultError;
use crate::runner::{CommandRunner, CommandSpec};
use crate::tool::{self, Owner};

/// Runs `command`; its stdout is the secret.
pub(super) async fn read<R: CommandRunner>(runner: &R, command: &str) -> Result<Option<Secret>, VaultError> {
    let spec = CommandSpec::new("sh", ["-c", command]);
    let output = tool::run(runner, Owner::Vault(VaultKind::Command), &spec).await?;
    if !output.success() {
        return Err(tool::failed(&program_name(command), &output));
    }
    let text = output.stdout.expose();
    let trimmed = text.strip_suffix('\n').map(|rest| rest.strip_suffix('\r').unwrap_or(rest)).unwrap_or(text);
    if trimmed.len() == text.len() {
        return Ok(Some(output.stdout));
    }
    Ok(Some(Secret::new(trimmed.to_owned())))
}

/// How the command is named in messages: `cmd <first word>`.
fn program_name(command: &str) -> String {
    format!("cmd {}", command.split_whitespace().next().unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vaults::tests::FakeBin;

    #[tokio::test]
    async fn trims_one_newline_and_reports_failures() {
        let bin = FakeBin::new();
        let runner = bin.runner();
        assert_eq!(read(&runner, "printf 'a\\r\\n'").await.unwrap().unwrap().expose(), "a");
        assert_eq!(read(&runner, "printf a").await.unwrap().unwrap().expose(), "a");
        let error = read(&runner, "false --x").await.unwrap_err();
        assert_eq!(error.to_string(), "cmd false failed: exit status 1");
    }
}
