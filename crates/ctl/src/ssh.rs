//! Running commands on a remote through the system `ssh`.
//!
//! All connections use `ClearAllForwardings=yes`: the user's ssh config
//! forwards the bridge socket, and that must not interfere with (or fail
//! because of) installation, e.g. while the remote socket directory does not
//! exist yet.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{Context, bail};

use crate::util::{describe, sh_quote};

const PROBE_MARKER: &str = "credential-bridge-probe";

/// Facts about the remote, gathered by [`Ssh::probe`].
#[derive(Debug, Clone)]
pub struct RemoteInfo {
    /// `linux`, `darwin`, …
    pub os: String,
    /// `x86_64`, `aarch64`, …
    pub arch: String,
    pub home: String,
    /// `2.56.0`, if git is installed.
    pub git_version: Option<String>,
}

impl RemoteInfo {
    /// `<arch>-<os>`, e.g. `x86_64-linux`, as used in helper binary names.
    pub fn platform(&self) -> String {
        format!("{}-{}", self.arch, self.os)
    }
}

#[derive(Debug)]
pub struct Ssh {
    target: String,
}

impl Ssh {
    pub fn new(target: &str) -> Self {
        Self { target: target.to_owned() }
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new("ssh");
        cmd.args(["-T", "-o", "ClearAllForwardings=yes", "--", &self.target]);
        cmd
    }

    /// Echoes a command with `-v`.
    fn trace(cmd: &Command) {
        if crate::ui::verbose() {
            eprintln!("{}", crate::ui::dim(&format!("$ {}", describe(cmd).replace('\n', "\n  "))));
        }
    }

    /// Runs a POSIX shell script on the remote (`sh -s`, script on stdin) and
    /// returns its stdout.
    pub fn run_script(&self, script: &str) -> anyhow::Result<String> {
        let mut cmd = self.command();
        cmd.args(["sh", "-s"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit());
        Self::trace(&cmd);
        let mut child = cmd.spawn().with_context(|| format!("cannot run `{}`", describe(&cmd)))?;
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(script.as_bytes())
            .context("cannot send the script to ssh")?;
        let output = child.wait_with_output()?;
        self.check(output.status)?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Turns a failed exit status into an error; ssh itself exits with 255.
    fn check(&self, status: ExitStatus) -> anyhow::Result<()> {
        match status.code() {
            _ if status.success() => Ok(()),
            Some(SSH_FAILED) => bail!(
                "cannot reach {} via ssh (see ssh's message above); check that `ssh {}` works",
                self.target,
                self.target
            ),
            _ => bail!("the command on {} failed ({status})", self.target),
        }
    }

    /// Runs `sh -c <script>` on the remote with `input` as stdin and returns
    /// its stdout; stderr goes to the terminal.
    pub fn run_with_input(&self, script: &str, input: &Path) -> anyhow::Result<String> {
        let file = File::open(input).with_context(|| format!("cannot open {}", input.display()))?;
        let mut cmd = self.command();
        cmd.args(["sh", "-c", &sh_quote(script)]).stdin(file).stdout(Stdio::piped()).stderr(Stdio::inherit());
        Self::trace(&cmd);
        let output = cmd.output().with_context(|| format!("cannot run `{}`", describe(&cmd)))?;
        self.check(output.status)?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Runs `sh -c <script>` without forwardings; returns whether it
    /// succeeded and its stdout and stderr together. Fails only if ssh does.
    pub fn run_without_forwarding(&self, script: &str) -> anyhow::Result<(bool, String)> {
        let mut cmd = self.command();
        cmd.args(["sh", "-c", &sh_quote(script)]);
        self.capture(cmd)
    }

    /// Like [`Ssh::run_without_forwarding`], but with the forwardings of the
    /// user's ssh config (unlike every other method).
    pub fn run_forwarded(&self, script: &str) -> anyhow::Result<(bool, String)> {
        let mut cmd = Command::new("ssh");
        cmd.args(["-T", "-o", "ExitOnForwardFailure=yes", "--", &self.target, "sh", "-c", &sh_quote(script)]);
        self.capture(cmd)
    }

    fn capture(&self, mut cmd: Command) -> anyhow::Result<(bool, String)> {
        let output =
            cmd.stdin(Stdio::null()).output().with_context(|| format!("cannot run `{}`", describe(&cmd)))?;
        let text =
            format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        if output.status.code() == Some(SSH_FAILED) {
            bail!("cannot reach {} via ssh: {}", self.target, text.trim());
        }
        Ok((output.status.success(), text))
    }

    /// The `RemoteForward`s the user's ssh config applies to this target,
    /// as `<listen> <connect>` lines, via `ssh -G`.
    pub fn configured_forwards(&self) -> anyhow::Result<Vec<String>> {
        let mut cmd = Command::new("ssh");
        cmd.args(["-G", "--", &self.target]).stdin(Stdio::null());
        let output = cmd.output().with_context(|| format!("cannot run `{}`", describe(&cmd)))?;
        if !output.status.success() {
            bail!("`{}` failed: {}", describe(&cmd), String::from_utf8_lossy(&output.stderr).trim());
        }
        Ok(parse_remote_forwards(&String::from_utf8_lossy(&output.stdout)))
    }

    /// Detects OS, architecture, home directory and git on the remote.
    pub fn probe(&self) -> anyhow::Result<RemoteInfo> {
        let script = format!(
            "echo {PROBE_MARKER}\nuname -s\nuname -m\nprintf '%s\\n' \"$HOME\"\n\
             if command -v git >/dev/null 2>&1; then echo \"git=$(git --version)\"; else echo git=; fi\n"
        );
        let output = self.run_script(&script)?;
        // Ignore anything shell startup files print before our marker.
        let mut lines = output.lines().skip_while(|line| line.trim() != PROBE_MARKER).skip(1).map(str::trim);
        let (Some(os), Some(arch), Some(home), Some(git)) =
            (lines.next(), lines.next(), lines.next(), lines.next())
        else {
            bail!("unexpected answer while probing {}:\n{output}", self.target);
        };
        if !home.starts_with('/') {
            bail!("remote $HOME is not an absolute path: {home:?}");
        }
        Ok(RemoteInfo {
            os: normalize_os(os),
            arch: normalize_arch(arch),
            home: home.to_owned(),
            git_version: git
                .strip_prefix("git=")
                .and_then(|v| v.split_whitespace().nth(2))
                .map(str::to_owned),
        })
    }
}

/// Exit status of `ssh` itself failing (connection, authentication, …).
const SSH_FAILED: i32 = 255;

/// The `remoteforward …` values of `ssh -G` output, as printed: `<listen>
/// <connect>`. ssh does not quote paths there, so a path with a space cannot
/// be split off here; [`crate::remote`] matches them against the known
/// local socket instead.
fn parse_remote_forwards(dump: &str) -> Vec<String> {
    dump.lines()
        .filter_map(|line| line.strip_prefix("remoteforward "))
        .map(|rest| rest.trim().to_owned())
        .collect()
}

fn normalize_os(uname_s: &str) -> String {
    uname_s.to_ascii_lowercase()
}

fn normalize_arch(uname_m: &str) -> String {
    match uname_m {
        "amd64" | "x86_64" => "x86_64".to_owned(),
        "arm64" | "aarch64" => "aarch64".to_owned(),
        other => other.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_platforms() {
        assert_eq!(normalize_os("Linux"), "linux");
        assert_eq!(normalize_os("Darwin"), "darwin");
        assert_eq!(normalize_arch("amd64"), "x86_64");
        assert_eq!(normalize_arch("arm64"), "aarch64");
        assert_eq!(normalize_arch("riscv64"), "riscv64");
    }

    #[test]
    fn parses_remote_forwards() {
        let dump = "user me\nremoteforward /home/me/b.sock /home/l/s/x.sock\n\
                    remoteforward /home/eve space/b.sock /home/l/s/y.sock\nclearallforwardings no\n";
        assert_eq!(
            parse_remote_forwards(dump),
            ["/home/me/b.sock /home/l/s/x.sock", "/home/eve space/b.sock /home/l/s/y.sock"]
        );
    }
}
