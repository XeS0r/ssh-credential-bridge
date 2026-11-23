//! Shared helpers for running vault programs and turning their failures into
//! [`VaultError`]s that are safe to show on a server.

use std::io;

use credential_bridge_config::VaultKind;

use crate::error::VaultError;
use crate::runner::{CommandOutput, CommandRunner, CommandSpec};

/// Longest stderr excerpt in an error message, in characters.
const MAX_DETAIL_CHARS: usize = 200;

/// Who a program runs for, which decides the error for a missing program.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Owner {
    /// A vault tool (`op`, `bw`, …): [`VaultError::ToolMissing`].
    Vault(VaultKind),
    /// `gh` or a git credential helper: [`VaultError::ProgramMissing`].
    Program,
}

/// Runs `spec`, mapping spawn errors: missing program, timeout, anything else as
/// [`VaultError::ToolFailed`]. A non-zero exit is returned as output.
pub(crate) async fn run<R: CommandRunner>(
    runner: &R,
    owner: Owner,
    spec: &CommandSpec,
) -> Result<CommandOutput, VaultError> {
    runner.run(spec).await.map_err(|error| spawn_error(owner, &spec.program, &error))
}

/// The [`VaultError`] for an error of [`CommandRunner::run`].
pub(crate) fn spawn_error(owner: Owner, program: &str, error: &io::Error) -> VaultError {
    match (error.kind(), owner) {
        (io::ErrorKind::NotFound, Owner::Vault(vault)) => {
            VaultError::ToolMissing { vault, program: program.to_owned() }
        }
        (io::ErrorKind::NotFound, Owner::Program) => {
            VaultError::ProgramMissing { program: program.to_owned() }
        }
        (io::ErrorKind::TimedOut, _) => VaultError::Timeout { program: program.to_owned() },
        (io::ErrorKind::InvalidData, _) => {
            VaultError::ToolFailed { program: program.to_owned(), detail: "unusable output".to_owned() }
        }
        _ => VaultError::ToolFailed {
            program: program.to_owned(),
            detail: format!("could not run it: {error}"),
        },
    }
}

/// `exit status N` or `killed by a signal`, plus the first non-empty stderr line with
/// control characters removed and cut to [`MAX_DETAIL_CHARS`].
pub(crate) fn failure_detail(output: &CommandOutput) -> String {
    let status = match output.status {
        Some(code) => format!("exit status {code}"),
        None => "killed by a signal".to_owned(),
    };
    match first_stderr_line(output) {
        Some(line) => format!("{status}: {line}"),
        None => status,
    }
}

/// The first non-empty stderr line, sanitized (see [`failure_detail`]).
pub(crate) fn first_stderr_line(output: &CommandOutput) -> Option<String> {
    let line = output.stderr.lines().map(str::trim).find(|line| !line.is_empty())?;
    let clean: String = line.chars().filter(|c| !c.is_control()).take(MAX_DETAIL_CHARS).collect();
    Some(clean)
}

/// [`VaultError::ToolFailed`] for a failed run.
pub(crate) fn failed(program: &str, output: &CommandOutput) -> VaultError {
    VaultError::ToolFailed { program: program.to_owned(), detail: failure_detail(output) }
}

/// Whether stderr contains one of `needles` (lowercase), ignoring case.
pub(crate) fn stderr_mentions(output: &CommandOutput, needles: &[&str]) -> bool {
    let stderr = output.stderr.to_lowercase();
    needles.iter().any(|needle| stderr.contains(needle))
}

/// Whether the program failed without a word on stdout or stderr.
pub(crate) fn failed_silently(output: &CommandOutput) -> bool {
    !output.success() && output.stdout.expose().trim().is_empty() && output.stderr.trim().is_empty()
}

/// Quotes `word` for a POSIX shell if it needs quoting, for commands people paste.
pub(crate) use credential_bridge_proto::text::shell_quote as sh_quote;

#[cfg(test)]
mod tests {
    use credential_bridge_proto::secret::Secret;

    use super::*;

    fn output(status: Option<i32>, stderr: &str) -> CommandOutput {
        CommandOutput { status, stdout: Secret::default(), stderr: stderr.to_owned() }
    }

    #[test]
    fn detail_uses_first_line_without_control_characters() {
        let out = output(Some(2), "\n  bad \x1b[31mthing\n second");
        assert_eq!(failure_detail(&out), "exit status 2: bad [31mthing");
        assert_eq!(failure_detail(&output(None, "")), "killed by a signal");
        let long = "x".repeat(500);
        assert_eq!(first_stderr_line(&output(Some(1), &long)).unwrap().len(), MAX_DETAIL_CHARS);
    }

    #[test]
    fn maps_spawn_errors() {
        let missing = io::Error::from(io::ErrorKind::NotFound);
        assert!(matches!(
            spawn_error(Owner::Vault(VaultKind::Bitwarden), "bw", &missing),
            VaultError::ToolMissing { vault: VaultKind::Bitwarden, .. }
        ));
        assert!(matches!(spawn_error(Owner::Program, "gh", &missing), VaultError::ProgramMissing { .. }));
        let timeout = io::Error::from(io::ErrorKind::TimedOut);
        assert!(matches!(spawn_error(Owner::Program, "gh", &timeout), VaultError::Timeout { .. }));
    }
}
