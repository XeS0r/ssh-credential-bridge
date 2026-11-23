//! Running external programs, behind a trait so tests can fake them.

use std::future::Future;
use std::io;
use std::process::Stdio;
use std::time::Duration;

use credential_bridge_proto::secret::Secret;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use zeroize::{Zeroize, Zeroizing};

/// Default timeout for vault programs; leaves room for desktop-app approval and PIN
/// prompts. It stays below the daemon's deadline for a vault request (110 s), so the
/// program's own error reaches the user instead of a generic timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(100);

/// Largest stdout [`SystemRunner`] accepts; more fails the run with
/// [`io::ErrorKind::InvalidData`].
pub const MAX_STDOUT: usize = 1024 * 1024;

/// Largest stderr [`SystemRunner`] keeps; the rest is read and dropped.
pub const MAX_STDERR: usize = 64 * 1024;

/// One program invocation. Never goes through a shell, except `cmd:` references, which
/// are run as `sh -c <command>` on purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    /// Program name (looked up in the worker's `PATH`) or absolute path.
    pub program: String,
    /// Arguments.
    pub args: Vec<String>,
    /// Extra environment on top of the worker's allowlisted environment, e.g.
    /// `BW_SESSION`. Values may be secret.
    pub env: Vec<(String, Secret)>,
    /// Written to stdin, then stdin is closed. `None`: stdin is `/dev/null`.
    pub stdin: Option<Secret>,
    /// Kill the program after this long.
    pub timeout: Duration,
}

impl CommandSpec {
    /// `program args…` with no extra environment, no stdin and [`DEFAULT_TIMEOUT`].
    pub fn new(program: impl Into<String>, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            env: Vec::new(),
            stdin: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Adds an environment variable.
    pub fn with_env(mut self, name: impl Into<String>, value: Secret) -> Self {
        self.env.push((name.into(), value));
        self
    }

    /// Sets stdin.
    pub fn with_stdin(mut self, stdin: Secret) -> Self {
        self.stdin = Some(stdin);
        self
    }

    /// Sets the timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// What a finished program produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Exit code; `None` if killed by a signal.
    pub status: Option<i32>,
    /// Stdout (may contain the secret).
    pub stdout: Secret,
    /// Stderr, lossily decoded; for error summaries only, never logged in full.
    pub stderr: String,
}

impl CommandOutput {
    /// Whether the exit code is 0.
    pub fn success(&self) -> bool {
        self.status == Some(0)
    }
}

/// Runs programs.
pub trait CommandRunner: Send + Sync {
    /// Runs `spec` to completion.
    ///
    /// Errors: [`io::ErrorKind::NotFound`] if the program does not exist,
    /// [`io::ErrorKind::TimedOut`] after `spec.timeout` (the program is killed), other
    /// spawn errors as they come. A non-zero exit is not an error.
    fn run(&self, spec: &CommandSpec) -> impl Future<Output = io::Result<CommandOutput>> + Send;
}

/// Runs the programs of `inner` only until `deadline`: a program is not started after it,
/// and a running one is killed when it passes (its timeout is cut to the time left).
#[derive(Debug)]
pub(crate) struct Deadline<'a, R> {
    /// Runs the programs.
    pub inner: &'a R,
    /// When the time is up.
    pub deadline: tokio::time::Instant,
}

impl<R: CommandRunner> CommandRunner for Deadline<'_, R> {
    async fn run(&self, spec: &CommandSpec) -> io::Result<CommandOutput> {
        let left = self.deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{} not started: the deadline has passed", spec.program),
            ));
        }
        if left >= spec.timeout {
            return self.inner.run(spec).await;
        }
        self.inner.run(&spec.clone().with_timeout(left)).await
    }
}

/// Runs programs with `tokio::process`, with the environment cleared except for
/// `allowed_env` (the worker's allowlist) plus the spec's `env`. Stdout must be valid
/// UTF-8.
///
/// Each program runs in its own process group; on timeout the whole group is killed, so
/// `sh -c` pipelines do not linger. Stdout is collected in buffers that are zeroized
/// when they grow or are dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemRunner {
    /// Variables passed to every program (`HOME`, `PATH`, `XDG_RUNTIME_DIR`,
    /// `DBUS_SESSION_BUS_ADDRESS`, display variables).
    pub allowed_env: Vec<(String, String)>,
}

impl SystemRunner {
    /// A runner passing exactly `allowed_env` to its programs.
    pub fn new(allowed_env: Vec<(String, String)>) -> Self {
        Self { allowed_env }
    }

    /// A runner passing on this process's whole (UTF-8) environment. Meant for the vault
    /// worker, whose environment the core already reduced to the allowlist.
    pub fn from_current_env() -> Self {
        let allowed_env = std::env::vars_os()
            .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
            .collect();
        Self { allowed_env }
    }
}

impl CommandRunner for SystemRunner {
    async fn run(&self, spec: &CommandSpec) -> io::Result<CommandOutput> {
        let mut command = tokio::process::Command::new(&spec.program);
        command
            .args(&spec.args)
            .env_clear()
            .envs(self.allowed_env.iter().map(|(name, value)| (name, value)))
            .stdin(if spec.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        for (name, value) in &spec.env {
            command.env(name, value.expose());
        }
        let mut child = command.spawn()?;
        let pid = child.id();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let work = async {
            let feed = async {
                if let (Some(mut pipe), Some(input)) = (stdin, spec.stdin.as_ref()) {
                    match pipe.write_all(input.expose().as_bytes()).await {
                        // The program need not read its input.
                        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {}
                        other => other?,
                    }
                    drop(pipe);
                }
                Ok::<(), io::Error>(())
            };
            let (_, stdout, stderr) =
                tokio::try_join!(feed, read_secret(stdout, MAX_STDOUT), read_lossy(stderr, MAX_STDERR))?;
            let status = child.wait().await?;
            Ok::<_, io::Error>((status, stdout, stderr))
        };
        let outcome = tokio::time::timeout(spec.timeout, work).await;
        let (status, mut stdout, stderr) = match outcome {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                kill_group(pid);
                return Err(error);
            }
            Err(_) => {
                kill_group(pid);
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{} did not finish within {:?}", spec.program, spec.timeout),
                ));
            }
        };
        let stdout = match String::from_utf8(std::mem::take(&mut *stdout)) {
            Ok(text) => Secret::new(text),
            Err(error) => {
                error.into_bytes().zeroize();
                return Err(io::Error::new(io::ErrorKind::InvalidData, "output is not UTF-8"));
            }
        };
        Ok(CommandOutput { status: status.code(), stdout, stderr })
    }
}

/// Kills the process group led by `pid` (the program and everything it started).
fn kill_group(pid: Option<u32>) {
    let pid = pid.and_then(|pid| i32::try_from(pid).ok()).and_then(rustix::process::Pid::from_raw);
    if let Some(pid) = pid {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
}

/// Reads all of `pipe` into a buffer that never leaves an unzeroized copy behind.
/// More than `limit` bytes is [`io::ErrorKind::InvalidData`].
async fn read_secret<P: AsyncRead + Unpin>(pipe: Option<P>, limit: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut buffer = Zeroizing::new(Vec::with_capacity(4096));
    let Some(mut pipe) = pipe else {
        return Ok(buffer);
    };
    let mut chunk = Zeroizing::new([0u8; 4096]);
    loop {
        let read = pipe.read(&mut chunk[..]).await?;
        if read == 0 {
            return Ok(buffer);
        }
        if buffer.len() + read > limit {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "output too large"));
        }
        if buffer.len() + read > buffer.capacity() {
            // Grow by hand: a reallocating `extend` would leave the old buffer behind.
            let mut grown =
                Zeroizing::new(Vec::with_capacity((buffer.capacity() * 2).max(buffer.len() + read)));
            grown.extend_from_slice(&buffer);
            buffer = grown;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

/// Reads `pipe` to the end, keeping the first `limit` bytes, lossily decoded.
async fn read_lossy<P: AsyncRead + Unpin>(pipe: Option<P>, limit: usize) -> io::Result<String> {
    let Some(mut pipe) = pipe else {
        return Ok(String::new());
    };
    let mut kept = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = pipe.read(&mut chunk).await?;
        if read == 0 {
            return Ok(String::from_utf8_lossy(&kept).into_owned());
        }
        let room = limit.saturating_sub(kept.len());
        kept.extend_from_slice(&chunk[..read.min(room)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runner() -> SystemRunner {
        SystemRunner::new(vec![("PATH".into(), std::env::var("PATH").unwrap_or_default())])
    }

    #[tokio::test]
    async fn runs_with_stdin_and_cleared_env() {
        let spec = CommandSpec::new(
            "sh",
            ["-c", "read line; printf '%s|%s|%s' \"$line\" \"$EXTRA\" \"${HOME-unset}\""],
        )
        .with_env("EXTRA", Secret::new("x".into()))
        .with_stdin(Secret::new("hello\n".into()));
        let output = runner().run(&spec).await.unwrap();
        assert!(output.success());
        assert_eq!(output.stdout.expose(), "hello|x|unset");
    }

    #[tokio::test]
    async fn reports_exit_status_and_stderr() {
        let spec = CommandSpec::new("sh", ["-c", "echo oops >&2; exit 3"]);
        let output = runner().run(&spec).await.unwrap();
        assert_eq!(output.status, Some(3));
        assert_eq!(output.stderr.trim(), "oops");
        assert!(!output.success());
    }

    #[tokio::test]
    async fn missing_program_is_not_found() {
        let spec = CommandSpec::new("credential-bridge-no-such-program", Vec::<String>::new());
        let error = runner().run(&spec).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    /// A program is not started after the deadline, and one running at the deadline is
    /// killed then.
    #[tokio::test]
    async fn deadline_bounds_every_program() {
        let marker = tempfile::tempdir().unwrap();
        let started = marker.path().join("started");
        let runner = runner();
        let deadline =
            Deadline { inner: &runner, deadline: tokio::time::Instant::now() + Duration::from_millis(300) };
        let begin = std::time::Instant::now();
        let error = deadline.run(&CommandSpec::new("sleep", ["5"])).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(begin.elapsed() < Duration::from_secs(2), "{:?}", begin.elapsed());

        let touch = CommandSpec::new("touch", [started.display().to_string()]);
        let error = deadline.run(&touch).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(!started.exists(), "a program was started after the deadline");
    }

    #[tokio::test]
    async fn timeout_kills_the_process_group() {
        // The background `sleep` keeps stdout open; only killing the group ends it.
        let spec =
            CommandSpec::new("sh", ["-c", "sleep 30 & sleep 30"]).with_timeout(Duration::from_millis(200));
        let started = std::time::Instant::now();
        let error = runner().run(&spec).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn rejects_oversized_and_non_utf8_output() {
        let spec = CommandSpec::new("sh", ["-c", "head -c 1100000 /dev/zero"]);
        let error = runner().run(&spec).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let spec = CommandSpec::new("sh", ["-c", "printf '\\377'"]);
        let error = runner().run(&spec).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn large_output_survives_buffer_growth() {
        let spec = CommandSpec::new("sh", ["-c", "head -c 100000 /dev/zero | tr '\\0' a"]);
        let output = runner().run(&spec).await.unwrap();
        assert_eq!(output.stdout.len(), 100_000);
        assert!(output.stdout.expose().bytes().all(|b| b == b'a'));
    }
}
