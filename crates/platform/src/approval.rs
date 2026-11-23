//! Approval dialogs for ssh signatures (`confirm = "8h"` in a profile).
//!
//! The core decides when to ask and remembers answers; this module only shows the
//! dialog. Linux uses an askpass helper (`SSH_ASKPASS` with
//! `SSH_ASKPASS_PROMPT=confirm`), macOS `osascript`. Dialogs block; the daemon calls
//! them from a blocking task.

use std::ffi::OsString;
use std::fmt::Debug;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// What the dialog shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// The server, from the bind that selected it (`buildserver`), or `local` for
    /// `agent.sock`.
    pub server: String,
    /// The key: `SHA256:…` fingerprint and comment.
    pub key: String,
    /// The local process from the peer check (`ssh`), if known.
    pub process: Option<String>,
    /// Whether the request comes from a hop: a host behind the server.
    pub hop: bool,
    /// How long an approval will be remembered, shown in the text; `None` if it is not
    /// remembered.
    pub remember: Option<Duration>,
}

/// The user's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalAnswer {
    /// Allow (and remember for [`ApprovalRequest::remember`], if set).
    Allow,
    /// Deny; not remembered.
    Deny,
}

/// The dialog could not be shown or did not finish. The core treats every error as
/// [`ApprovalAnswer::Deny`].
#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    /// No dialog program is available (no askpass helper, no display).
    #[error("no approval dialog available: {0}")]
    Unavailable(String),
    /// The dialog program failed.
    #[error("approval dialog failed: {0}")]
    Failed(String),
    /// No answer within the timeout; the dialog was closed.
    #[error("approval dialog timed out")]
    Timeout,
}

/// Shows approval dialogs.
pub trait ApprovalDialog: Debug + Send + Sync {
    /// Shows `request` and waits up to `timeout` for an answer.
    fn ask(&self, request: &ApprovalRequest, timeout: Duration) -> Result<ApprovalAnswer, ApprovalError>;
}

/// An askpass helper (Linux): run with the prompt as argument and
/// `SSH_ASKPASS_PROMPT=confirm`. As in OpenSSH (`ask_permission` in `readpass.c`), it
/// allows only if the helper exits with status 0 *and* its answer is empty or `yes`
/// (any case): helpers that ignore `SSH_ASKPASS_PROMPT` show a passphrase box, where
/// typing `no` and pressing OK must not allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskpassDialog {
    /// The helper program.
    pub program: PathBuf,
}

impl AskpassDialog {
    /// A dialog that runs `program`.
    pub fn new(program: impl Into<PathBuf>) -> AskpassDialog {
        AskpassDialog { program: program.into() }
    }
}

impl ApprovalDialog for AskpassDialog {
    fn ask(&self, request: &ApprovalRequest, timeout: Duration) -> Result<ApprovalAnswer, ApprovalError> {
        let mut command = Command::new(&self.program);
        command.arg(prompt_text(request)).env("SSH_ASKPASS_PROMPT", "confirm");
        let finished = run_with_timeout(command, timeout)?;
        // The answer may be anything typed into a passphrase box: it is only compared,
        // never logged or put into an error.
        match finished.status.code() {
            Some(0) if askpass_allows(&finished.stdout) => Ok(ApprovalAnswer::Allow),
            // Any other answer, cancel, window closed.
            Some(_) => Ok(ApprovalAnswer::Deny),
            None => Err(ApprovalError::Failed(format!(
                "{} was killed: {}",
                self.program.display(),
                finished.status
            ))),
        }
    }
}

/// Whether an askpass answer (stdout of a helper that exited with status 0) allows, by
/// OpenSSH's rule: the answer up to the first CR or LF is empty or `yes` in any case.
fn askpass_allows(answer: &str) -> bool {
    let line = answer.split(['\r', '\n']).next().unwrap_or_default();
    line.is_empty() || line.eq_ignore_ascii_case("yes")
}

/// `osascript` `display dialog` (macOS).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OsascriptDialog;

/// The AppleScript for [`OsascriptDialog`]; the text arrives as `argv`, so it is never
/// parsed as script.
const OSASCRIPT: &[&str] = &[
    "on run argv",
    "set answer to display dialog (item 1 of argv) with title \"credential-bridge\" \
     buttons {\"Deny\", \"Allow\"} default button \"Deny\" cancel button \"Deny\" \
     with icon caution giving up after (item 2 of argv as integer)",
    "if gave up of answer then return \"timeout\"",
    "return button returned of answer",
    "end run",
];

impl ApprovalDialog for OsascriptDialog {
    fn ask(&self, request: &ApprovalRequest, timeout: Duration) -> Result<ApprovalAnswer, ApprovalError> {
        let seconds = timeout.as_secs().max(1);
        let mut command = Command::new("/usr/bin/osascript");
        for line in OSASCRIPT {
            command.arg("-e").arg(line);
        }
        command.arg(prompt_text(request)).arg(seconds.to_string());
        // `giving up after` closes the dialog; the extra time covers a stuck osascript.
        let finished = run_with_timeout(command, timeout + Duration::from_secs(5))?;
        parse_osascript(&finished)
    }
}

/// Interprets the result of [`OSASCRIPT`]: `Allow` on stdout, exit status 1 with error
/// -128 when the cancel button ("Deny") was pressed.
fn parse_osascript(finished: &Finished) -> Result<ApprovalAnswer, ApprovalError> {
    let stdout = finished.stdout.trim();
    if finished.status.success() {
        return match stdout {
            "Allow" => Ok(ApprovalAnswer::Allow),
            "timeout" => Err(ApprovalError::Timeout),
            _ => Ok(ApprovalAnswer::Deny),
        };
    }
    if finished.stderr.contains("(-128)") {
        return Ok(ApprovalAnswer::Deny);
    }
    let detail = finished.stderr.trim();
    Err(ApprovalError::Failed(format!("osascript failed ({}): {detail}", finished.status)))
}

/// A finished dialog program.
#[derive(Debug)]
struct Finished {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

/// Most output kept from a dialog program.
const MAX_OUTPUT: u64 = 64 * 1024;

/// Runs `command` with stdin closed and waits up to `timeout`; on timeout the program
/// is killed. A program that cannot be started is [`ApprovalError::Unavailable`].
fn run_with_timeout(mut command: Command, timeout: Duration) -> Result<Finished, ApprovalError> {
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
            ApprovalError::Unavailable(format!("{}: {e}", command.get_program().to_string_lossy()))
        }
        _ => ApprovalError::Failed(format!("starting {}: {e}", command.get_program().to_string_lossy())),
    })?;
    let stdout = read_in_background(child.stdout.take());
    let stderr = read_in_background(child.stderr.take());
    let status = wait_with_deadline(&mut child, Instant::now() + timeout)
        .map_err(|e| ApprovalError::Failed(format!("waiting for the dialog: {e}")))?;
    let Some(status) = status else {
        child.kill().ok();
        child.wait().ok();
        return Err(ApprovalError::Timeout);
    };
    Ok(Finished {
        status,
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    })
}

fn read_in_background(pipe: Option<impl Read + Send + 'static>) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut text = Vec::new();
        if let Some(pipe) = pipe {
            // Output beyond the limit is left unread; the pipe closes with the thread.
            pipe.take(MAX_OUTPUT).read_to_end(&mut text).ok();
        }
        String::from_utf8_lossy(&text).into_owned()
    })
}

/// Polls `child` until it exits or `deadline` passes (`Ok(None)`).
fn wait_with_deadline(child: &mut Child, deadline: Instant) -> std::io::Result<Option<ExitStatus>> {
    let mut pause = Duration::from_millis(5);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        std::thread::sleep(pause.min(deadline - now));
        pause = (pause * 2).min(Duration::from_millis(100));
    }
}

/// Askpass helpers looked up in `PATH` when `SSH_ASKPASS` is not set, best first.
pub const KNOWN_ASKPASS_HELPERS: &[&str] = &[
    "ssh-askpass",
    "ksshaskpass",
    "lxqt-openssh-askpass",
    "ssh-askpass-gnome",
    "gnome-ssh-askpass",
    "x11-ssh-askpass",
    "ssh-askpass-fullscreen",
];

/// Fixed install locations of askpass helpers that are not in `PATH`.
const ASKPASS_LOCATIONS: &[&str] = &[
    "/usr/lib/ssh/ssh-askpass",
    "/usr/libexec/openssh/ssh-askpass",
    "/usr/libexec/openssh/gnome-ssh-askpass",
    "/usr/lib/openssh/gnome-ssh-askpass",
    "/usr/libexec/ssh-askpass",
];

/// The askpass helper to use: `ssh_askpass` (the value of `SSH_ASKPASS`) if set and not
/// empty, else the first of [`KNOWN_ASKPASS_HELPERS`] in `path`, else a known install
/// location.
pub fn find_askpass(ssh_askpass: Option<OsString>, path: Option<OsString>) -> Option<PathBuf> {
    if let Some(program) = ssh_askpass.filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(program));
    }
    let dirs: Vec<PathBuf> = path.map(|p| std::env::split_paths(&p).collect()).unwrap_or_default();
    KNOWN_ASKPASS_HELPERS
        .iter()
        .flat_map(|name| dirs.iter().map(move |dir| dir.join(name)))
        .chain(ASKPASS_LOCATIONS.iter().map(PathBuf::from))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// The dialog for this system: macOS [`OsascriptDialog`]; Linux [`AskpassDialog`] with
/// `$SSH_ASKPASS`, else the first known helper found in `PATH`
/// (`ssh-askpass`, `ksshaskpass`, `lxqt-openssh-askpass`, …).
///
/// Errors: [`ApprovalError::Unavailable`] if none is found.
pub fn system_dialog() -> Result<Box<dyn ApprovalDialog>, ApprovalError> {
    if cfg!(target_os = "macos") {
        return Ok(Box::new(OsascriptDialog));
    }
    let has_display =
        ["DISPLAY", "WAYLAND_DISPLAY"].iter().any(|v| std::env::var_os(v).is_some_and(|d| !d.is_empty()));
    if !has_display {
        return Err(ApprovalError::Unavailable(
            "neither DISPLAY nor WAYLAND_DISPLAY is set (import them into the service environment)"
                .to_owned(),
        ));
    }
    find_askpass(std::env::var_os("SSH_ASKPASS"), std::env::var_os("PATH"))
        .map(|program| Box::new(AskpassDialog::new(program)) as Box<dyn ApprovalDialog>)
        .ok_or_else(|| {
            ApprovalError::Unavailable("no askpass helper: set SSH_ASKPASS or install ssh-askpass".to_owned())
        })
}

/// The text shown to the user (one function so all platforms say the same).
pub fn prompt_text(request: &ApprovalRequest) -> String {
    let process = request.process.as_deref().map(one_line).unwrap_or_else(|| "an unknown process".to_owned());
    let via = if request.hop { "a host behind this server (hop)" } else { "the server itself" };
    let remember = match request.remember {
        Some(duration) => format!(
            "If you allow, this is remembered for {} for this server, key, process and origin.",
            format_duration(duration)
        ),
        None => "This answer is not remembered.".to_owned(),
    };
    format!(
        "Allow an ssh signature?\n\nServer: {}\nFrom: {via}\nKey: {}\nRequested by: {process}\n\n{remember}",
        one_line(&request.server),
        one_line(&request.key),
    )
}

/// One line of at most 200 characters without control characters, so that names from
/// servers or agents cannot fake further lines of the dialog.
fn one_line(text: &str) -> String {
    const MAX: usize = 200;
    let mut out: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).take(MAX).collect();
    if text.chars().count() > MAX {
        out.push('…');
    }
    out
}

/// `8h`, `1h30m`, `45s`; zero is `0s`.
fn format_duration(duration: Duration) -> String {
    let total = duration.as_secs();
    if total == 0 {
        return "0s".to_owned();
    }
    let (d, h, m, s) = (total / 86_400, total / 3600 % 24, total / 60 % 60, total % 60);
    [(d, "d"), (h, "h"), (m, "m"), (s, "s")]
        .iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, unit)| format!("{n}{unit}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ApprovalRequest {
        ApprovalRequest {
            server: "buildserver".to_owned(),
            key: "SHA256:abc user@laptop".to_owned(),
            process: Some("ssh".to_owned()),
            hop: false,
            remember: Some(Duration::from_secs(8 * 3600)),
        }
    }

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        write_script(&path, body);
        path
    }

    /// Writes `#!/bin/sh` and `body` to `path` and makes it executable. Written by a child `sh`, so this process never holds the file open for writing: a
    /// test thread that forks meanwhile would inherit such a descriptor until its child
    /// execs, and running the script in that window fails with ETXTBSY ("Text file busy").
    fn write_script(path: &std::path::Path, body: &str) {
        use std::io::Write as _;
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
            .arg(path)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(format!("#!/bin/sh\n{body}\n").as_bytes()).unwrap();
        assert!(child.wait().unwrap().success(), "writing {} failed", path.display());
    }

    #[test]
    fn prompt_names_server_key_process_and_duration() {
        let text = prompt_text(&request());
        assert!(text.contains("Server: buildserver"));
        assert!(text.contains("Key: SHA256:abc user@laptop"));
        assert!(text.contains("Requested by: ssh"));
        assert!(text.contains("for 8h"));
        assert!(text.contains("From: the server itself"));
        let unknown = prompt_text(&ApprovalRequest { process: None, ..request() });
        assert!(unknown.contains("Requested by: an unknown process"));
    }

    #[test]
    fn prompt_shows_hops_and_unremembered_answers() {
        let hop = prompt_text(&ApprovalRequest { hop: true, ..request() });
        assert!(hop.contains("From: a host behind this server (hop)"), "{hop}");
        let once = prompt_text(&ApprovalRequest { remember: None, ..request() });
        assert!(once.contains("This answer is not remembered."), "{once}");
        assert!(!once.contains("remembered for"));
    }

    #[test]
    fn prompt_cannot_be_forged_by_names() {
        let text = prompt_text(&ApprovalRequest { server: "evil\nServer: trusted".to_owned(), ..request() });
        assert_eq!(text.matches("\nServer:").count(), 1);
        let long = prompt_text(&ApprovalRequest { key: "k".repeat(1000), ..request() });
        assert!(long.contains(&format!("{}…", "k".repeat(200))));
    }

    #[test]
    fn formats_durations() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(Duration::from_secs(45)), "45s");
        assert_eq!(format_duration(Duration::from_secs(5400)), "1h30m");
        assert_eq!(format_duration(Duration::from_secs(8 * 3600)), "8h");
        assert_eq!(format_duration(Duration::from_secs(2 * 86_400 + 60)), "2d1m");
    }

    #[test]
    fn askpass_exit_status_decides() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("seen");
        let allow = script(
            dir.path(),
            "allow",
            &format!("printf '%s|%s' \"$SSH_ASKPASS_PROMPT\" \"$1\" > '{}'; exit 0", out.display()),
        );
        let answer = AskpassDialog::new(&allow).ask(&request(), Duration::from_secs(10)).unwrap();
        assert_eq!(answer, ApprovalAnswer::Allow);
        let seen = std::fs::read_to_string(&out).unwrap();
        assert!(seen.starts_with("confirm|Allow an ssh signature?"), "{seen}");

        let deny = script(dir.path(), "deny", "exit 1");
        assert_eq!(
            AskpassDialog::new(deny).ask(&request(), Duration::from_secs(10)).unwrap(),
            ApprovalAnswer::Deny
        );
        // A "yes" with a failing exit status (OpenSSH ignores the answer then).
        let yes_but_failed = script(dir.path(), "yes-but-failed", "echo yes; exit 1");
        assert_eq!(
            AskpassDialog::new(yes_but_failed).ask(&request(), Duration::from_secs(10)).unwrap(),
            ApprovalAnswer::Deny
        );
    }

    #[test]
    fn askpass_answer_decides_like_openssh() {
        let dir = tempfile::tempdir().unwrap();
        let cases: &[(&str, &str, ApprovalAnswer)] = &[
            ("empty", "true", ApprovalAnswer::Allow),
            ("newline", "echo", ApprovalAnswer::Allow),
            ("yes", "printf yes", ApprovalAnswer::Allow),
            ("yes-upper", "printf 'YES\\n'", ApprovalAnswer::Allow),
            ("yes-crlf", "printf 'Yes\\r\\n'", ApprovalAnswer::Allow),
            ("no", "echo no", ApprovalAnswer::Deny),
            ("yes-space", "echo 'yes '", ApprovalAnswer::Deny),
            ("yesno", "echo yesno", ApprovalAnswer::Deny),
            ("secret", "echo 'hunter2-Secret!'", ApprovalAnswer::Deny),
        ];
        for (name, body, expected) in cases {
            let helper = script(dir.path(), name, body);
            let answer = AskpassDialog::new(helper).ask(&request(), Duration::from_secs(10)).unwrap();
            assert_eq!(answer, *expected, "{name}");
        }
    }

    #[test]
    fn askpass_answer_rule() {
        assert!(askpass_allows(""));
        assert!(askpass_allows("\n"));
        assert!(askpass_allows("yes"));
        assert!(askpass_allows("YES\n"));
        assert!(askpass_allows("yEs\nsomething else"));
        assert!(!askpass_allows("no"));
        assert!(!askpass_allows("no\n"));
        assert!(!askpass_allows(" yes"));
        assert!(!askpass_allows("y"));
        assert!(!askpass_allows("correct horse battery staple\n"));
    }

    #[test]
    fn askpass_answer_is_not_in_errors() {
        // A helper that prints a passphrase-like answer and is killed: the error names
        // the program and the signal, never the answer.
        let dir = tempfile::tempdir().unwrap();
        let killed = script(dir.path(), "killed", "echo 'hunter2-Secret!'; kill -9 $$");
        let err = AskpassDialog::new(killed).ask(&request(), Duration::from_secs(10)).unwrap_err();
        assert!(!format!("{err} {err:?}").contains("hunter2"), "{err:?}");
    }

    #[test]
    fn askpass_timeout_kills_the_dialog() {
        let dir = tempfile::tempdir().unwrap();
        let slow = script(dir.path(), "slow", "exec sleep 30");
        let started = Instant::now();
        let err = AskpassDialog::new(slow).ask(&request(), Duration::from_millis(200)).unwrap_err();
        assert!(matches!(err, ApprovalError::Timeout), "{err}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn askpass_killed_or_missing() {
        let dir = tempfile::tempdir().unwrap();
        let killed = script(dir.path(), "killed", "kill -9 $$");
        let err = AskpassDialog::new(killed).ask(&request(), Duration::from_secs(10)).unwrap_err();
        assert!(matches!(err, ApprovalError::Failed(_)), "{err}");
        let err =
            AskpassDialog::new(dir.path().join("none")).ask(&request(), Duration::from_secs(1)).unwrap_err();
        assert!(matches!(err, ApprovalError::Unavailable(_)), "{err}");
    }

    #[test]
    fn finds_askpass_helpers() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            find_askpass(Some("/opt/my-askpass".into()), None),
            Some(PathBuf::from("/opt/my-askpass"))
        );
        let helper = script(dir.path(), "ksshaskpass", "exit 0");
        // Not executable: skipped.
        std::fs::write(dir.path().join("ssh-askpass"), b"").unwrap();
        let path = std::env::join_paths([Path::new("/nonexistent"), dir.path()]).unwrap();
        assert_eq!(find_askpass(Some("".into()), Some(path)), Some(helper));
    }

    fn finished(code: i32, stdout: &str, stderr: &str) -> Finished {
        use std::os::unix::process::ExitStatusExt;
        Finished {
            status: ExitStatus::from_raw(code << 8),
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
        }
    }

    #[test]
    fn parses_osascript_results() {
        assert_eq!(parse_osascript(&finished(0, "Allow\n", "")).unwrap(), ApprovalAnswer::Allow);
        assert_eq!(parse_osascript(&finished(0, "Deny\n", "")).unwrap(), ApprovalAnswer::Deny);
        assert!(matches!(parse_osascript(&finished(0, "timeout\n", "")), Err(ApprovalError::Timeout)));
        let cancel = "0:200: execution error: User canceled. (-128)\n";
        assert_eq!(parse_osascript(&finished(1, "", cancel)).unwrap(), ApprovalAnswer::Deny);
        let broken = "execution error: No user interaction allowed. (-1713)";
        assert!(matches!(parse_osascript(&finished(1, "", broken)), Err(ApprovalError::Failed(_))));
    }

    #[test]
    fn osascript_script_takes_text_as_argument() {
        let script = OSASCRIPT.join("\n");
        assert!(script.contains("item 1 of argv"));
        assert!(!script.contains("buildserver"));
    }
}
