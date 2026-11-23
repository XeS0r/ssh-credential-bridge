//! Reaching servers through the user's own `ssh` (so ssh config, agents and jump hosts
//! apply). Behind a trait so commands can be tested with a fake.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use credential_bridge_proto::text::shell_quote;

/// Output of a remote command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteOutput {
    /// Exit code; `None` if ssh itself failed or the command was killed.
    pub status: Option<i32>,
    /// Stdout.
    pub stdout: String,
    /// Stderr.
    pub stderr: String,
}

impl RemoteOutput {
    /// Whether the command exited with 0.
    pub fn success(&self) -> bool {
        self.status == Some(0)
    }

    /// A short explanation of a failure: the last non-empty line of stderr, or the
    /// exit status.
    pub fn failure_reason(&self) -> String {
        match self.stderr.lines().rev().map(str::trim).find(|line| !line.is_empty()) {
            Some(line) => line.to_owned(),
            None => match self.status {
                Some(code) => format!("exit status {code}"),
                None => "killed by a signal".to_owned(),
            },
        }
    }
}

/// Runs things on servers.
pub trait RemoteShell {
    /// Runs `argv` on `host` (each argument shell-quoted for the remote shell).
    fn run(&self, host: &str, argv: &[&str]) -> io::Result<RemoteOutput>;
    /// Copies a local file to `remote_path` on `host` with mode 0755, atomically
    /// (upload to a temporary name, then rename).
    fn install_file(&self, host: &str, local: &Path, remote_path: &str) -> io::Result<()>;
    /// [`RemoteShell::run`] that also reports the host key ssh accepted for this
    /// connection (from its debug log; a fresh connection, no connection sharing).
    /// `None` if ssh did not say. ssh may ask on the terminal about an unknown host key
    /// and store it in known_hosts.
    fn run_noting_host_key(
        &self,
        host: &str,
        argv: &[&str],
    ) -> io::Result<(RemoteOutput, Option<UsedHostKey>)>;
    /// Runs `credential-bridge-remote query` on `host` with the agent forwarded from
    /// `forward_socket` (`ForwardAgent` set on the command line, whatever the ssh config
    /// says; a fresh connection, no connection sharing), so its agent connection reaches
    /// the daemon. Returns the output and the process id of the local ssh, which the
    /// daemon's audit log names as the peer of that connection.
    fn probe(&self, host: &str, forward_socket: &Path) -> io::Result<ProbeRun>;
    /// The effective client configuration for `host` (`ssh -G` output), for checking
    /// the user's ssh config. Runs locally; nothing connects.
    fn ssh_g(&self, host: &str) -> io::Result<String> {
        check_host(host)?;
        let output = Command::new("ssh").arg("-G").arg("--").arg(host).stdin(Stdio::null()).output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "ssh -G {host} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
    /// The plain host keys of type `key_type` (an `ssh-keyscan -t` name such as
    /// `ed25519`) that `hostname` offers on `port`, as `ssh-keyscan` prints them: one
    /// scan with a 5 second timeout, connecting directly (ssh config, `ProxyJump`
    /// included, does not apply).
    fn keyscan(&self, hostname: &str, port: u16, key_type: &str) -> io::Result<String> {
        check_host(hostname)?;
        let output = Command::new("ssh-keyscan")
            .args(["-T", "5", "-t", key_type, "-p", &port.to_string(), "--", hostname])
            .stdin(Stdio::null())
            .output()?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
    /// What the local `ssh -V` prints (ssh writes it to stderr). Runs locally.
    fn ssh_version(&self) -> io::Result<String> {
        let output = Command::new("ssh").arg("-V").stdin(Stdio::null()).output()?;
        let mut text = String::from_utf8_lossy(&output.stderr).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stdout));
        Ok(text)
    }
}

/// The host key ssh accepted for a connection, as its debug log names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsedHostKey {
    /// The key type, e.g. `ssh-ed25519` (for a host certificate the type of the key in
    /// it).
    pub algorithm: String,
    /// `SHA256:…` of the key (for a host certificate, of the key in it).
    pub fingerprint: String,
    /// Whether the server presented a host certificate.
    pub certificate: bool,
    /// Where ssh found the key, or the CA that signed the certificate, in known_hosts;
    /// `None` if it did not (an unknown or changed key ssh accepted anyway, e.g. with
    /// `StrictHostKeyChecking=no`).
    pub verified: Option<KnownHostsMatch>,
}

/// The known_hosts entry ssh verified a host key with, as its debug log names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHostsMatch {
    /// Whether it is a `@cert-authority` line that signed the host certificate
    /// (`Found CA key in …`), else a host line with the key itself (`Found key in …`).
    pub authority: bool,
    /// The file, as ssh names it.
    pub file: PathBuf,
}

impl UsedHostKey {
    /// `ssh-ed25519 SHA256:…`.
    pub fn describe(&self) -> String {
        format!("{} {}", self.algorithm, self.fingerprint)
    }
}

/// What [`RemoteShell::probe`] returns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeRun {
    /// The output of `credential-bridge-remote query` (and ssh's errors).
    pub output: RemoteOutput,
    /// The process id of the local ssh.
    pub pid: Option<u32>,
}

/// [`RemoteShell`] with the `ssh` program in `PATH`.
///
/// Connections disable agent, X11 and port forwarding: nothing ctl runs on a server
/// needs them, except the probe, which forwards the daemon's forward socket. ssh may
/// still prompt on the terminal (password, unknown host key).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SshShell;

/// Options for every ctl connection.
const SSH_OPTIONS: &[&str] = &["-T", "-a", "-x", "-o", "ClearAllForwardings=yes"];

/// Script that installs stdin as `$1`: temporary file next to it, mode 0755, rename.
/// Kept free of backslashes so the quoting works in fish as well as POSIX shells.
const INSTALL_SCRIPT: &str = r#"set -e
umask 077
mkdir -p "$(dirname "$1")"
t="$1.tmp.$$"
trap 'rm -f "$t"' EXIT
cat > "$t"
chmod 755 "$t"
mv -f "$t" "$1"
trap - EXIT"#;

/// Options for a connection that must make its own key exchange: no connection sharing
/// (a shared connection would neither show the host key nor forward the agent of this
/// command line) and fingerprints in SHA256.
const FRESH_CONNECTION: &[&str] = &["-S", "none", "-o", "FingerprintHash=sha256"];

impl SshShell {
    fn ssh(host: &str, argv: &[&str]) -> io::Result<Command> {
        check_host(host)?;
        let mut command = Command::new("ssh");
        command.args(SSH_OPTIONS).arg("--").arg(host).arg(remote_command(argv));
        Ok(command)
    }
}

/// A private temporary file for ssh's debug log (`ssh -E`), removed when dropped.
fn debug_log() -> io::Result<tempfile::NamedTempFile> {
    tempfile::Builder::new().prefix("credential-bridge-ssh-").suffix(".log").tempfile()
}

/// The output of a finished ssh whose own messages went to `log` (`ssh -E`): ssh's
/// messages other than debug lines are appended to stderr, so failures keep their
/// reason.
fn output_with_log(output: std::process::Output, log: &str) -> RemoteOutput {
    let mut stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    for line in log.lines().filter(|line| !line.starts_with("debug")) {
        stderr.push_str(line);
        stderr.push('\n');
    }
    RemoteOutput {
        status: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr,
    }
}

/// `ForwardAgent=<path>` for the ssh command line: `%` doubled (ssh expands `%` tokens
/// in the path) and the value quoted if it has spaces.
fn forward_agent_option(path: &Path) -> String {
    let path = path.display().to_string().replace('%', "%%");
    if path.contains(char::is_whitespace) {
        format!("ForwardAgent=\"{path}\"")
    } else {
        format!("ForwardAgent={path}")
    }
}

impl RemoteShell for SshShell {
    fn run(&self, host: &str, argv: &[&str]) -> io::Result<RemoteOutput> {
        let output = Self::ssh(host, argv)?.stdin(Stdio::null()).output()?;
        Ok(RemoteOutput {
            status: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn install_file(&self, host: &str, local: &Path, remote_path: &str) -> io::Result<()> {
        let file = File::open(local)?;
        let output = Self::ssh(host, &["sh", "-c", INSTALL_SCRIPT, "sh", remote_path])?
            .stdin(Stdio::from(file))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()?;
        if output.status.success() {
            return Ok(());
        }
        let result = RemoteOutput {
            status: output.status.code(),
            stdout: String::new(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        };
        Err(io::Error::other(format!("uploading to {remote_path} failed: {}", result.failure_reason())))
    }

    fn run_noting_host_key(
        &self,
        host: &str,
        argv: &[&str],
    ) -> io::Result<(RemoteOutput, Option<UsedHostKey>)> {
        check_host(host)?;
        let log = debug_log()?;
        let output = Command::new("ssh")
            .args(SSH_OPTIONS)
            .args(FRESH_CONNECTION)
            .arg("-v")
            .arg("-E")
            .arg(log.path())
            .arg("--")
            .arg(host)
            .arg(remote_command(argv))
            .stdin(Stdio::null())
            .output()?;
        let text = std::fs::read_to_string(log.path()).unwrap_or_default();
        Ok((output_with_log(output, &text), used_host_key(&text)))
    }

    fn probe(&self, host: &str, forward_socket: &Path) -> io::Result<ProbeRun> {
        check_host(host)?;
        let log = debug_log()?;
        let child = Command::new("ssh")
            .args(["-T", "-x", "-o", "ClearAllForwardings=yes"])
            .args(FRESH_CONNECTION)
            .arg("-o")
            .arg(forward_agent_option(forward_socket))
            .arg("-E")
            .arg(log.path())
            .arg("--")
            .arg(host)
            .arg(remote_command(&[REMOTE_BINARY, "query"]))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let pid = Some(child.id());
        let output = child.wait_with_output()?;
        let text = std::fs::read_to_string(log.path()).unwrap_or_default();
        Ok(ProbeRun { output: output_with_log(output, &text), pid })
    }
}

/// The text of a debug log line after its first `:` (`debug1: <text>`). Phrases are
/// matched at its start only: text a server controls (its version, `Remote:` messages,
/// banner lines) never starts there.
fn log_text(line: &str) -> Option<&str> {
    Some(line.trim_start_matches(|c: char| c != ':').strip_prefix(':')?.trim_start())
}

/// The host key in ssh's debug log: `Server host key: <type> <fingerprint>`, or for a
/// host certificate `Server host certificate: <type>-cert-v01@openssh.com
/// <fingerprint>, …` (the fingerprint is that of the key in the certificate), with
/// [`known_hosts_match`].
pub fn used_host_key(log: &str) -> Option<UsedHostKey> {
    log.lines().find_map(|line| {
        let line = log_text(line)?;
        let (rest, certificate) = match line.strip_prefix("Server host key: ") {
            Some(rest) => (rest, false),
            None => (line.strip_prefix("Server host certificate: ")?, true),
        };
        let mut fields = rest.split_whitespace();
        let algorithm = fields.next()?;
        let fingerprint = fields.next()?.trim_end_matches(',');
        let algorithm = algorithm.strip_suffix("-cert-v01@openssh.com").unwrap_or(algorithm);
        fingerprint.starts_with("SHA256:").then(|| UsedHostKey {
            algorithm: algorithm.to_owned(),
            fingerprint: fingerprint.to_owned(),
            certificate,
            verified: known_hosts_match(log),
        })
    })
}

/// Where ssh found the host key in known_hosts, from its debug log: `Found key in
/// <file>:<line>`, or for a host certificate `Found CA key in <file>:<line>` (OpenSSH's
/// `check_host_key`, debug1). ssh logs it only when known_hosts vouches for the key: not
/// for a new key it accepts (asked, `accept-new` or `StrictHostKeyChecking=no`), nor a
/// changed one it accepts anyway, nor a certificate whose CA it does not know (`No
/// matching CA found. Retry with plain key`, after which a plain `Found key` may follow).
pub fn known_hosts_match(log: &str) -> Option<KnownHostsMatch> {
    log.lines().find_map(|line| {
        let text = log_text(line)?;
        let (rest, authority) = match text.strip_prefix("Found key in ") {
            Some(rest) => (rest, false),
            None => (text.strip_prefix("Found CA key in ")?, true),
        };
        let (file, number) = rest.rsplit_once(':')?;
        number.parse::<u64>().ok()?;
        Some(KnownHostsMatch { authority, file: PathBuf::from(file) })
    })
}

/// Refuses host names ssh would read as an option.
fn check_host(host: &str) -> io::Result<()> {
    if host.is_empty() || host.starts_with('-') || host.chars().any(char::is_whitespace) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("invalid ssh host {host:?}")));
    }
    Ok(())
}

/// The command line ssh sends: every argument quoted, joined by spaces.
pub fn remote_command(argv: &[&str]) -> String {
    argv.iter().map(|arg| shell_quote(arg)).collect::<Vec<_>>().join(" ")
}

/// What `ssh -G` says about where a host is, which known_hosts files apply and whether
/// ssh learns new host keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTarget {
    hostname: String,
    port: u16,
    host_key_alias: Option<String>,
    update_host_keys: Option<String>,
    /// `userknownhostsfile` and `globalknownhostsfile` lines: option and value.
    known_hosts: Vec<(String, String)>,
}

/// At most this many `/`-tokens after the first on one known_hosts line are told apart
/// (each may start a file or continue a path with " /" in it).
const MAX_PATH_STARTS: usize = 8;

impl SshTarget {
    /// Parses `ssh -G` output.
    pub fn parse(ssh_g: &str) -> SshTarget {
        let mut target = SshTarget {
            hostname: String::new(),
            port: 22,
            host_key_alias: None,
            update_host_keys: None,
            known_hosts: Vec::new(),
        };
        // ssh -G prints `key value` with one space and the value as it is: paths keep
        // their spaces and tabs, trailing ones included. Only the line end goes.
        for line in ssh_g.split('\n') {
            let Some((key, value)) = line.split_once(' ') else { continue };
            match key {
                "hostname" => target.hostname = value.to_owned(),
                "port" => target.port = value.parse().unwrap_or(22),
                "hostkeyalias" if value != "none" => target.host_key_alias = Some(value.to_owned()),
                "updatehostkeys" => target.update_host_keys = Some(value.to_owned()),
                "userknownhostsfile" | "globalknownhostsfile" => {
                    target.known_hosts.push((key.to_owned(), value.to_owned()));
                }
                _ => {}
            }
        }
        target
    }

    /// The host name ssh connects to.
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// The port ssh connects to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The name ssh looks up in known_hosts: `HostKeyAlias`, else the host name, as
    /// `[host]:port` for a port other than 22; lowercase, as ssh lowercases both.
    pub fn lookup_name(&self) -> String {
        let name = match &self.host_key_alias {
            Some(alias) => alias.clone(),
            None if self.port == 22 => self.hostname.clone(),
            None => format!("[{}]:{}", self.hostname, self.port),
        };
        name.to_ascii_lowercase()
    }

    /// Whether ssh learns the server's new host keys at login (`UpdateHostKeys`): `false`
    /// only if `ssh -G` says it is off, which OpenSSH does on its own when
    /// `UserKnownHostsFile` is set or `VerifyHostKeyDNS` is on.
    pub fn updates_host_keys(&self) -> bool {
        !matches!(self.update_host_keys.as_deref(), Some("false" | "no"))
    }

    /// The known_hosts files ssh reads for this host (`UserKnownHostsFile`, then
    /// `GlobalKnownHostsFile`). Without any in the output: OpenSSH's defaults in `home`.
    ///
    /// `ssh -G` has expanded `~` and `%` tokens and prints each list unquoted, the files
    /// joined by exactly one space (OpenSSH 10.2; other whitespace in a path is printed
    /// as it is). Split at each single space, every file starts with `/`: a token without
    /// one (empty ones included, from two spaces in a row or a trailing space) continues
    /// the path before it. A token with `/` may start a file or continue a path
    /// containing " /"; of the possible readings the one whose files all exist wins,
    /// else the one whose files all have an existing directory, else each such token
    /// starts a file. Errors: a relative path, an unexpanded `%` token, or readings that
    /// cannot be told apart.
    pub fn known_hosts_files(&self, home: &Path) -> Result<Vec<PathBuf>, String> {
        if self.known_hosts.is_empty() {
            return Ok(credential_bridge_config::known_hosts::default_files(home));
        }
        let mut files = Vec::new();
        for (option, value) in &self.known_hosts {
            files.extend(split_paths(option, value)?);
        }
        Ok(files)
    }
}

/// The files of one `ssh -G` known_hosts line; see [`SshTarget::known_hosts_files`].
fn split_paths(option: &str, value: &str) -> Result<Vec<PathBuf>, String> {
    let line = format!("ssh -G prints `{option} {value}`");
    if value.is_empty() || value == "none" {
        return Ok(Vec::new());
    }
    let tokens: Vec<&str> = value.split(' ').collect();
    if let Some(token) = tokens.iter().find(|token| token.contains('%')) {
        return Err(format!(
            "{line}: {token:?} holds a % token ssh did not expand; write the path out in ~/.ssh/config"
        ));
    }
    if !tokens[0].starts_with('/') {
        return Err(format!(
            "{line}: {:?} is a relative path, which ssh reads from the current directory; make it \
             absolute in ~/.ssh/config",
            tokens[0]
        ));
    }
    let starts: Vec<usize> = tokens
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, token)| token.starts_with('/'))
        .map(|(i, _)| i)
        .collect();
    if starts.len() > MAX_PATH_STARTS {
        return Err(format!("{line}: more than {} files on one line", MAX_PATH_STARTS + 1));
    }
    // Bit j of `mask` set: the token at starts[j] starts a file.
    let reading = |mask: usize| -> Vec<PathBuf> {
        let mut paths: Vec<String> = Vec::new();
        for (i, token) in tokens.iter().enumerate() {
            let starts_file =
                i == 0 || starts.iter().position(|&start| start == i).is_some_and(|j| mask & (1 << j) != 0);
            match paths.last_mut() {
                Some(path) if !starts_file => {
                    path.push(' ');
                    path.push_str(token);
                }
                _ => paths.push((*token).to_owned()),
            }
        }
        paths.into_iter().map(PathBuf::from).collect()
    };
    let readings: Vec<Vec<PathBuf>> = (0..1usize << starts.len()).map(reading).collect();
    let tiers: [fn(&Path) -> bool; 2] =
        [|path| path.exists(), |path| path.exists() || path.parent().is_some_and(Path::is_dir)];
    for fits in tiers {
        let fitting: Vec<&Vec<PathBuf>> =
            readings.iter().filter(|reading| reading.iter().all(|path| fits(path))).collect();
        match fitting.as_slice() {
            [] => {}
            [one] => return Ok((*one).clone()),
            several => {
                let listed: Vec<String> = several
                    .iter()
                    .map(|reading| {
                        reading
                            .iter()
                            .map(|path| format!("{:?}", path.display().to_string()))
                            .collect::<Vec<_>>()
                            .join(" + ")
                    })
                    .collect();
                return Err(format!(
                    "{line}, which can be read as different files ({}); rename the path with \" /\" in it",
                    listed.join(" or ")
                ));
            }
        }
    }
    Ok(readings.last().cloned().unwrap_or_default())
}

/// Where `server add` installs the remote binary, relative to the remote home.
pub const REMOTE_BINARY: &str = ".local/bin/credential-bridge-remote";

/// Maps `uname -m` output to the bundled static binary's target triple
/// (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `s390x-unknown-linux-gnu`).
/// `None` for others. Rust ships no musl standard library for s390x, so that binary links
/// glibc statically.
pub fn remote_target(uname_m: &str) -> Option<&'static str> {
    match uname_m.trim() {
        "x86_64" | "amd64" => Some("x86_64-unknown-linux-musl"),
        "aarch64" | "arm64" => Some("aarch64-unknown-linux-musl"),
        "s390x" => Some("s390x-unknown-linux-gnu"),
        _ => None,
    }
}

/// Environment variable naming the directory with the bundled remote binaries.
pub const HELPER_DIR_ENV: &str = "CREDENTIAL_BRIDGE_HELPER_DIR";

/// File name of the bundled remote binary for `target` inside the helper directory.
pub fn bundled_binary_name(target: &str) -> String {
    format!("credential-bridge-remote-{target}")
}

/// Directories searched for bundled remote binaries, in order: `$CREDENTIAL_BRIDGE_HELPER_DIR`,
/// then `<prefix>/share/credential-bridge/helpers` for the prefix of `exe`
/// (`<prefix>/bin/credential-bridge-ctl`).
pub fn helper_dirs(env_dir: Option<&Path>, exe: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(dir) = env_dir.filter(|dir| !dir.as_os_str().is_empty()) {
        dirs.push(dir.to_owned());
    }
    if let Some(prefix) = exe.and_then(Path::parent).and_then(Path::parent) {
        dirs.push(prefix.join("share/credential-bridge/helpers"));
    }
    dirs
}

/// The bundled binary for `target` in the first of `dirs` that has it.
pub fn find_bundled_binary(dirs: &[PathBuf], target: &str) -> Option<PathBuf> {
    let name = bundled_binary_name(target);
    dirs.iter().map(|dir| dir.join(&name)).find(|path| path.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_command_quotes_every_argument() {
        assert_eq!(remote_command(&["echo", "a;b", "c"]), "echo 'a;b' c");
        assert_eq!(
            remote_command(&[".local/bin/credential-bridge-remote", "setup", "--host", "it's"]),
            r".local/bin/credential-bridge-remote setup '--host' 'it'\''s'"
        );
    }

    #[test]
    fn install_script_has_no_backslashes() {
        assert!(!INSTALL_SCRIPT.contains('\\'));
    }

    #[test]
    fn refuses_option_like_hosts() {
        assert!(check_host("-oProxyCommand=x").is_err());
        assert!(check_host("").is_err());
        assert!(check_host("a b").is_err());
        assert!(check_host("buildserver").is_ok());
    }

    #[test]
    fn parses_ssh_g() {
        let target = SshTarget::parse(
            "host buildserver\nhostname build.example.com\nport 2222\n\
             userknownhostsfile ~/.ssh/known_hosts ~/.ssh/known_hosts2\n\
             globalknownhostsfile /etc/ssh/ssh_known_hosts none\nhostkeyalias none\n",
        );
        assert_eq!(target.hostname, "build.example.com");
        assert_eq!(target.port, 2222);
        assert_eq!(target.lookup_name(), "[build.example.com]:2222");
        assert!(target.updates_host_keys());
        let aliased =
            SshTarget::parse("hostname 10.0.0.1\nport 22\nhostkeyalias Build\nupdatehostkeys false\n");
        assert_eq!(aliased.lookup_name(), "build");
        assert!(!aliased.updates_host_keys());
        assert!(SshTarget::parse("updatehostkeys ask\n").updates_host_keys());
        assert_eq!(SshTarget::parse("hostname H\nport 22\n").lookup_name(), "h");
    }

    /// `ssh -G` prints paths unquoted: a token without `/` continues the path before it.
    #[test]
    fn known_hosts_paths_with_spaces() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().display().to_string();
        std::fs::create_dir_all(dir.path().join("a b")).unwrap();
        std::fs::create_dir_all(dir.path().join("u")).unwrap();
        let files = |line: &str| SshTarget::parse(line).known_hosts_files(Path::new("/home/me"));
        assert_eq!(
            files(&format!("userknownhostsfile {root}/a b/kh {root}/u/x\nglobalknownhostsfile none\n"))
                .unwrap(),
            [dir.path().join("a b/kh"), dir.path().join("u/x")]
        );
        // Nothing exists: each `/` token starts a file.
        assert_eq!(
            files("globalknownhostsfile /nonexistent/a /nonexistent/b\n").unwrap(),
            [PathBuf::from("/nonexistent/a"), PathBuf::from("/nonexistent/b")]
        );

        let error = files("userknownhostsfile known_hosts /etc/ssh/x\n").unwrap_err();
        assert!(error.contains("\"known_hosts\" is a relative path"), "{error}");
        assert!(error.starts_with("ssh -G prints `userknownhostsfile known_hosts /etc/ssh/x`"), "{error}");
        let error = files("userknownhostsfile %d/x\n").unwrap_err();
        assert!(error.contains("\"%d/x\" holds a % token"), "{error}");

        // A path with " /" in it: the reading whose files exist wins …
        let odd = dir.path().join(format!("odd {root}/kh"));
        std::fs::create_dir_all(odd.parent().unwrap()).unwrap();
        std::fs::write(&odd, "").unwrap();
        let line = format!("userknownhostsfile {root}/odd {root}/kh\n");
        assert_eq!(files(&line).unwrap(), std::slice::from_ref(&odd));
        // … and if both readings exist, they cannot be told apart.
        std::fs::write(dir.path().join("odd"), "").unwrap();
        std::fs::write(dir.path().join("kh"), "").unwrap();
        let error = files(&line).unwrap_err();
        assert!(error.contains("which can be read as different files"), "{error}");
        assert!(
            error.starts_with(&format!("ssh -G prints `userknownhostsfile {root}/odd {root}/kh`")),
            "{error}"
        );
    }

    /// ssh joins the files with exactly one space and prints other whitespace in a path
    /// as it is: two spaces, a tab and a trailing space stay part of the path.
    #[test]
    fn known_hosts_paths_keep_their_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().display().to_string();
        for name in ["a  b", "t\tab"] {
            std::fs::create_dir_all(dir.path().join(name)).unwrap();
            std::fs::write(dir.path().join(name).join("kh"), "").unwrap();
        }
        std::fs::write(dir.path().join("kh"), "").unwrap();
        std::fs::write(dir.path().join("end "), "").unwrap();
        let files = |line: &str| SshTarget::parse(line).known_hosts_files(Path::new("/home/me")).unwrap();
        assert_eq!(
            files(&format!("userknownhostsfile {root}/a  b/kh {root}/kh\nglobalknownhostsfile none\n")),
            [dir.path().join("a  b/kh"), dir.path().join("kh")]
        );
        assert_eq!(files(&format!("userknownhostsfile {root}/t\tab/kh\n")), [dir.path().join("t\tab/kh")]);
        assert_eq!(
            files(&format!("userknownhostsfile {root}/kh {root}/end \n")),
            [dir.path().join("kh"), dir.path().join("end ")]
        );
        // Without a file of that name the trailing space is kept as well.
        assert_eq!(files("globalknownhostsfile /nonexistent/x \n"), [PathBuf::from("/nonexistent/x ")]);
    }

    #[test]
    fn known_hosts_files_default_to_openssh() {
        let target = SshTarget::parse("hostname h\nport 22\n");
        assert_eq!(
            target.known_hosts_files(Path::new("/home/me")).unwrap(),
            credential_bridge_config::known_hosts::default_files(Path::new("/home/me"))
        );
        // OpenSSH 10 prints them expanded.
        let target = SshTarget::parse(
            "userknownhostsfile /home/me/.ssh/known_hosts\nglobalknownhostsfile /etc/ssh/ssh_known_hosts\n",
        );
        assert_eq!(
            target.known_hosts_files(Path::new("/home/me")).unwrap(),
            [PathBuf::from("/home/me/.ssh/known_hosts"), PathBuf::from("/etc/ssh/ssh_known_hosts")]
        );
    }

    #[test]
    fn reads_the_used_host_key_from_the_debug_log() {
        let log = "debug1: kex: host key algorithm: ssh-ed25519\n\
                   debug1: Server host key: ssh-ed25519 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU\n\
                   Warning: Permanently added 'github.com' (ED25519) to the list of known hosts.\n";
        assert_eq!(
            used_host_key(log),
            Some(UsedHostKey {
                algorithm: "ssh-ed25519".into(),
                fingerprint: "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU".into(),
                certificate: false,
                verified: None,
            })
        );
        let cert = "debug1: Server host certificate: ssh-ed25519-cert-v01@openssh.com SHA256:abc, serial 0 \
                    ID \"box\" CA ssh-ed25519 SHA256:ca valid forever\n";
        let used = used_host_key(cert).unwrap();
        assert_eq!((used.describe().as_str(), used.certificate), ("ssh-ed25519 SHA256:abc", true));
        assert_eq!(used_host_key("debug1: Server host key: ssh-rsa MD5:aa:bb\n"), None);
        assert_eq!(used_host_key("debug1: Connecting to h\n"), None);
    }

    /// ssh's own `Found … in <file>:<line>` lines (as `ssh -v -E` writes them, with CR LF)
    /// count; the same words in text a server controls do not.
    #[test]
    fn reads_where_ssh_found_the_key() {
        let found = |log: &str| known_hosts_match(log);
        let plain = "debug1: Server host key: ssh-ed25519 SHA256:abc\r\n\
                     debug1: load_hostkeys: fopen /home/me/.ssh/known_hosts2: No such file or directory\r\n\
                     debug1: Host 'box' is known and matches the ED25519 host key.\r\n\
                     debug1: Found key in /home/me/my hosts/kh:12\r\n";
        assert_eq!(
            found(plain),
            Some(KnownHostsMatch { authority: false, file: PathBuf::from("/home/me/my hosts/kh") })
        );
        assert_eq!(used_host_key(plain).unwrap().verified, found(plain));
        let ca = "debug1: Server host certificate: ssh-ed25519-cert-v01@openssh.com SHA256:abc, serial 0\n\
                  debug1: Host 'box' is known and matches the ED25519-CERT host certificate.\n\
                  debug1: Found CA key in /etc/ssh/ssh_known_hosts:3\n";
        assert_eq!(
            found(ca),
            Some(KnownHostsMatch { authority: true, file: PathBuf::from("/etc/ssh/ssh_known_hosts") })
        );
        // An unknown CA: ssh retries with the plain key, which may be listed.
        let retry = "debug1: No matching CA found. Retry with plain key\n";
        assert_eq!(found(retry), None);
        assert_eq!(
            found(&format!("{retry}debug1: Found key in /k:1\n")),
            Some(KnownHostsMatch { authority: false, file: PathBuf::from("/k") })
        );
        // Accepted without known_hosts vouching for it.
        assert_eq!(found("Warning: Permanently added 'box' (ED25519) to the list of known hosts.\n"), None);
        // Spoof attempts: server messages, versions, banners, disconnect reasons.
        for spoof in [
            "debug1: Remote: Found key in /home/me/.ssh/known_hosts:1\n",
            "debug1: Remote protocol version 2.0, remote software version Found key in /k:1\n",
            "debug1: kex_exchange_identification: banner line 0: Found key in /k:1\n",
            "Received disconnect from 10.0.0.1 port 22:2: Found CA key in /k:1\n",
            "Found key in /k:1\n",
            "debug1: Found key in /k\n",
            "debug1: Found key in /k:x\n",
        ] {
            assert_eq!(found(spoof), None, "{spoof}");
        }
    }

    #[test]
    fn ssh_messages_from_the_log_keep_failure_reasons() {
        use std::os::unix::process::ExitStatusExt as _;
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(255 << 8),
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        let output = output_with_log(
            output,
            "debug1: Reading configuration data\nme@h: Permission denied (publickey).\n",
        );
        assert_eq!(output.status, Some(255));
        assert_eq!(output.failure_reason(), "me@h: Permission denied (publickey).");
    }

    #[test]
    fn forward_agent_options() {
        assert_eq!(forward_agent_option(Path::new("/run/a.sock")), "ForwardAgent=/run/a.sock");
        assert_eq!(forward_agent_option(Path::new("/my dir/50%.sock")), "ForwardAgent=\"/my dir/50%%.sock\"");
    }

    #[test]
    fn maps_architectures() {
        assert_eq!(remote_target("x86_64\n"), Some("x86_64-unknown-linux-musl"));
        assert_eq!(remote_target("arm64"), Some("aarch64-unknown-linux-musl"));
        assert_eq!(remote_target("s390x"), Some("s390x-unknown-linux-gnu"));
        assert_eq!(remote_target("riscv64"), None);
    }

    #[test]
    fn finds_bundled_binaries() {
        let dir = tempfile::tempdir().unwrap();
        let helpers = dir.path().join("share/credential-bridge/helpers");
        std::fs::create_dir_all(&helpers).unwrap();
        std::fs::write(helpers.join("credential-bridge-remote-x86_64-unknown-linux-musl"), b"bin").unwrap();
        let exe = dir.path().join("bin/credential-bridge-ctl");
        let dirs = helper_dirs(Some(Path::new("/nonexistent")), Some(&exe));
        assert_eq!(dirs.len(), 2);
        assert_eq!(
            find_bundled_binary(&dirs, "x86_64-unknown-linux-musl"),
            Some(helpers.join("credential-bridge-remote-x86_64-unknown-linux-musl"))
        );
        assert_eq!(find_bundled_binary(&dirs, "s390x-unknown-linux-gnu"), None);
        assert_eq!(helper_dirs(Some(Path::new("")), None), Vec::<PathBuf>::new());
    }

    #[test]
    fn output_failure_reason() {
        let output = RemoteOutput {
            status: Some(255),
            stdout: String::new(),
            stderr: "a\nPermission denied\n\n".into(),
        };
        assert_eq!(output.failure_reason(), "Permission denied");
        assert!(!output.success());
        let output = RemoteOutput { status: Some(3), ..RemoteOutput::default() };
        assert_eq!(output.failure_reason(), "exit status 3");
    }
}
