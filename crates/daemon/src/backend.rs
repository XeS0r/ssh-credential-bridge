//! Runs a local git credential helper ("backend").

use std::io;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use credential_bridge_proto::{Credential, Operation, ParseError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// Errors while running a backend.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("cannot start backend: {0}")]
    Spawn(io::Error),
    #[error("backend did not answer within {0:?}")]
    Timeout(Duration),
    #[error("backend I/O error: {0}")]
    Io(io::Error),
    #[error("backend exited with {status}{detail}")]
    Failed { status: std::process::ExitStatus, detail: String },
    #[error("backend returned invalid output: {0}")]
    Output(ParseError),
}

/// Turns a git `credential.helper` value into a shell command, the same way git does:
///
/// * `!cmd args` runs `cmd args`
/// * `/abs/path args` runs as is
/// * `name args` runs `git credential-name args`
pub fn helper_command(spec: &str) -> String {
    let spec = spec.trim();
    if let Some(command) = spec.strip_prefix('!') {
        command.to_owned()
    } else if spec.split_whitespace().next().is_some_and(|program| Path::new(program).is_absolute()) {
        spec.to_owned()
    } else {
        format!("git credential-{spec}")
    }
}

/// Runs the backend `spec` for `operation` with `credential` on stdin.
///
/// Interactive prompts are disabled, since nobody could answer them. The
/// backend runs in its own process group, which is killed as a whole if it
/// does not finish within `timeout`.
pub async fn run(
    spec: &str,
    operation: Operation,
    credential: &Credential,
    timeout: Duration,
) -> Result<Credential, BackendError> {
    let script = format!("{} \"$@\"", helper_command(spec));
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .arg("credential-bridge-backend")
        .arg(operation.as_str())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GCM_INTERACTIVE", "never")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .map_err(BackendError::Spawn)?;
    let pid = child.id();

    let mut input = Vec::new();
    credential.write_to(&mut input).map_err(BackendError::Io)?;
    input.push(b'\n');
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let mut stdout_pipe = child.stdout.take().expect("stdout is piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr is piped");
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());

    let finished = tokio::time::timeout(timeout, async {
        // Helpers may exit without reading stdin (e.g. for unsupported
        // operations), so a broken pipe here is not an error.
        let write = async {
            let _ = stdin.write_all(&input).await;
            drop(stdin);
        };
        let (_, out, err, status) = tokio::join!(
            write,
            stdout_pipe.read_to_end(&mut stdout),
            stderr_pipe.read_to_end(&mut stderr),
            child.wait()
        );
        out?;
        err?;
        status
    })
    .await;

    let status = match finished {
        Ok(status) => status.map_err(BackendError::Io)?,
        Err(_) => {
            kill_group(pid);
            let _ = child.kill().await;
            return Err(BackendError::Timeout(timeout));
        }
    };

    // Like git, treat a helper that fails silently on `get` as "no credential":
    // `gh auth git-credential`, for example, exits 1 without a word when it is
    // not logged in to the host.
    if !status.success()
        && operation == Operation::Get
        && stdout.iter().all(u8::is_ascii_whitespace)
        && stderr.iter().all(u8::is_ascii_whitespace)
    {
        return Ok(Credential::new());
    }
    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        let first_line = stderr.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or_default();
        let detail = if first_line.is_empty() {
            String::new()
        } else {
            format!(": {}", first_line.chars().take(200).collect::<String>())
        };
        return Err(BackendError::Failed { status, detail });
    }
    Credential::read_from(&mut stdout.as_slice()).map_err(BackendError::Output)
}

/// Kills the backend's process group, including anything it spawned.
fn kill_group(pid: Option<u32>) {
    let pid = pid.and_then(|pid| i32::try_from(pid).ok()).and_then(rustix::process::Pid::from_raw);
    if let Some(pid) = pid {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_command_follows_git_rules() {
        assert_eq!(helper_command("!gh auth git-credential"), "gh auth git-credential");
        assert_eq!(helper_command("/usr/bin/helper --x"), "/usr/bin/helper --x");
        assert_eq!(helper_command("osxkeychain"), "git credential-osxkeychain");
        assert_eq!(helper_command("cache --timeout=60"), "git credential-cache --timeout=60");
    }

    fn request() -> Credential {
        Credential::from_url("https://github.com/org/repo").unwrap()
    }

    #[tokio::test]
    async fn passes_operation_and_input() {
        let spec = r#"!f() { test "$1" = get || exit 3; grep -q '^host=github.com$' || exit 4; printf 'username=u\npassword=p\n'; }; f"#;
        let out = run(spec, Operation::Get, &request(), Duration::from_secs(5)).await.unwrap();
        assert_eq!(out.get("username"), Some("u"));
        assert_eq!(out.get("password"), Some("p"));
    }

    #[tokio::test]
    async fn reports_failures() {
        let err = run("!echo boom >&2; exit 2", Operation::Get, &request(), Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, BackendError::Failed { .. }));
        assert!(err.to_string().contains("boom"));
    }

    #[tokio::test]
    async fn silent_failure_on_get_means_no_credential() {
        let silent = "!f() { exit 1; }; f";
        let out = run(silent, Operation::Get, &request(), Duration::from_secs(5)).await.unwrap();
        assert!(out.is_empty());
        // Not for other operations, and not when the helper says why.
        assert!(run(silent, Operation::Store, &request(), Duration::from_secs(5)).await.is_err());
        let talking = "!f() { echo no >&2; exit 1; }; f";
        assert!(run(talking, Operation::Get, &request(), Duration::from_secs(5)).await.is_err());
    }

    #[tokio::test]
    async fn times_out() {
        let err = run("!f() { sleep 5; }; f", Operation::Get, &request(), Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(matches!(err, BackendError::Timeout(_)));
    }

    #[tokio::test]
    async fn tolerates_helpers_that_ignore_stdin() {
        let out = run("!true", Operation::Erase, &request(), Duration::from_secs(5)).await.unwrap();
        assert!(out.is_empty());
    }
}
