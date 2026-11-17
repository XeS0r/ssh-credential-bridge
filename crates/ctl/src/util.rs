//! Small helpers shared by the commands.

use std::env;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, bail};
use credential_bridge_proto::client::exchange;
use credential_bridge_proto::{Credential, Operation, Request, Status};

pub use credential_bridge_proto::sh_quote;

pub fn is_executable(path: &Path) -> bool {
    path.metadata().map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0).unwrap_or(false)
}

/// Looks `name` up in `$PATH`.
pub fn which(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path).map(|dir| dir.join(name)).find(|candidate| is_executable(candidate))
}

pub fn describe(cmd: &Command) -> String {
    std::iter::once(cmd.get_program())
        .chain(cmd.get_args())
        .map(|arg| sh_quote(&arg.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Runs `cmd` with inherited stdio and fails on a non-zero exit.
pub fn run(cmd: &mut Command) -> anyhow::Result<()> {
    let status = cmd.status().with_context(|| format!("cannot run `{}`", describe(cmd)))?;
    if !status.success() {
        bail!("`{}` failed ({status})", describe(cmd));
    }
    Ok(())
}

/// Polls `done` every `poll` until it holds or `limit` has passed; returns
/// whether it held.
pub fn wait_until(limit: Duration, poll: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + limit;
    loop {
        if done() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(poll);
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code, reason = "used by launchd"))]
/// Runs `action` up to `attempts` times, `delay` apart, until it succeeds;
/// returns the last error otherwise.
pub fn retry<T>(
    attempts: usize,
    delay: Duration,
    mut action: impl FnMut() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let mut last = None;
    for attempt in 0..attempts.max(1) {
        if attempt > 0 {
            std::thread::sleep(delay);
        }
        match action() {
            Ok(value) => return Ok(value),
            Err(err) => last = Some(err),
        }
    }
    Err(last.expect("at least one attempt"))
}

/// Result of pinging a local socket.
#[derive(Debug)]
pub enum SocketState {
    Listening,
    Missing,
    Broken(String),
}

impl std::fmt::Display for SocketState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketState::Listening => f.write_str("listening"),
            SocketState::Missing => f.write_str("not listening"),
            SocketState::Broken(reason) => write!(f, "error: {reason}"),
        }
    }
}

pub fn socket_state(socket: &Path) -> SocketState {
    if !socket.exists() {
        return SocketState::Missing;
    }
    let request = Request::new(Operation::Ping, Credential::new());
    match exchange(socket, &request, Some(Duration::from_secs(3))) {
        Ok(response) if response.status == Status::Ok => SocketState::Listening,
        Ok(response) => SocketState::Broken(response.message.unwrap_or_else(|| response.status.to_string())),
        Err(err) => SocketState::Broken(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_until_success_or_gives_up() {
        let mut calls = 0;
        let result = retry(4, Duration::ZERO, || {
            calls += 1;
            if calls < 3 { anyhow::bail!("Bootstrap failed: 5") } else { Ok(calls) }
        });
        assert_eq!(result.unwrap(), 3);
        let mut calls = 0;
        let result: anyhow::Result<()> = retry(2, Duration::ZERO, || {
            calls += 1;
            anyhow::bail!("attempt {calls}")
        });
        assert_eq!(result.unwrap_err().to_string(), "attempt 2");
    }

    #[test]
    fn waits_until_done_or_limit() {
        let mut n = 0;
        assert!(wait_until(Duration::from_secs(1), Duration::ZERO, || {
            n += 1;
            n == 3
        }));
        assert!(!wait_until(Duration::from_millis(20), Duration::from_millis(5), || false));
    }
}
