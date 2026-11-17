//! `service …` commands: the credential-bridged user service.

#[cfg(target_os = "macos")]
mod launchd;
#[cfg(target_os = "linux")]
mod systemd;

use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use credential_bridge_core::paths::{self, DAEMON_BINARY};

use crate::ui::{self, Level};
use crate::util::{SocketState, is_executable, socket_state, wait_until, which};
use crate::{Ctx, ServiceCommand};

/// How the daemon is started.
#[derive(Debug, Clone)]
pub struct DaemonSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Environment for the daemon: `PATH`, so backends like `gh` are found as
    /// in the user's shell, and the XDG directories ctl resolved its own paths
    /// with, so both look at the same config and sockets.
    pub env: Vec<(String, String)>,
}

/// What an installed service definition runs.
#[derive(Debug, Clone, PartialEq)]
pub struct InstalledSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

/// Runtime facts about the service.
#[derive(Debug, Default)]
pub struct ServiceInfo {
    pub pid: Option<u32>,
    /// Start time as the service manager prints it.
    pub since: Option<String>,
}

/// A platform's user-level service manager.
pub trait ServiceManager {
    /// File describing the service (unit file / launchd plist).
    fn definition_path(&self) -> &Path;
    fn install(&self, daemon: &DaemonSpec, start: bool) -> anyhow::Result<()>;
    fn uninstall(&self) -> anyhow::Result<()>;
    fn start(&self) -> anyhow::Result<()>;
    fn stop(&self) -> anyhow::Result<()>;
    fn restart(&self) -> anyhow::Result<()>;
    fn reload(&self) -> anyhow::Result<()>;
    /// Prints the manager's status output.
    fn status(&self) -> anyhow::Result<()>;
    fn logs(&self, follow: bool, lines: usize) -> anyhow::Result<()>;
    fn is_active(&self) -> bool;
    /// Daemon program named in an installed service definition.
    fn installed_program(&self) -> Option<PathBuf>;
    /// PID and start time of the running daemon, as far as known.
    fn info(&self) -> ServiceInfo;
    /// Program, arguments and environment of the installed definition.
    fn installed_spec(&self) -> Option<InstalledSpec>;

    fn is_installed(&self) -> bool {
        self.definition_path().exists()
    }
}

pub fn manager() -> anyhow::Result<Box<dyn ServiceManager>> {
    #[cfg(target_os = "linux")]
    return Ok(Box::new(systemd::Systemd::new()?));
    #[cfg(target_os = "macos")]
    return Ok(Box::new(launchd::Launchd::new()?));
    #[allow(unreachable_code)]
    {
        bail!("service management is not supported on this platform; run `credential-bridged run` yourself")
    }
}

pub fn run(ctx: &Ctx, cmd: ServiceCommand) -> anyhow::Result<()> {
    let manager = manager()?;
    let require_installed = || -> anyhow::Result<()> {
        if !manager.is_installed() {
            bail!("the service is not installed; run `credential-bridge-ctl service install`");
        }
        Ok(())
    };
    match cmd {
        ServiceCommand::Install { daemon_path, no_start } => {
            let previous = manager.installed_spec();
            let spec = daemon_spec(ctx, daemon_path, previous.as_ref())?;
            manager.install(&spec, !no_start)?;
            println!("installed {}", manager.definition_path().display());
            println!("daemon: {}", spec.program.display());
            if is_store_path(&spec.program) {
                eprintln!(
                    "warning: the daemon is a Nix store path, which an update or garbage collection \
                     removes; install with `just install` (or `nix run .#install`) and pass \
                     `--daemon-path ~/.local/bin/{DAEMON_BINARY}`"
                );
            }
            if !no_start {
                println!("started; see `credential-bridge-ctl service status`");
            }
        }
        ServiceCommand::Uninstall => {
            require_installed()?;
            manager.uninstall()?;
            println!("removed {}", manager.definition_path().display());
        }
        ServiceCommand::Start => {
            require_installed()?;
            manager.start()?;
        }
        ServiceCommand::Stop => {
            require_installed()?;
            manager.stop()?;
        }
        ServiceCommand::Restart => {
            require_installed()?;
            manager.restart()?;
        }
        ServiceCommand::Reload => {
            require_installed()?;
            manager.reload()?;
        }
        ServiceCommand::Status { raw: true } => {
            require_installed()?;
            manager.status()?;
        }
        ServiceCommand::Status { raw: false } => print_status(ctx, manager.as_ref()),
        ServiceCommand::Logs { follow, lines } => manager.logs(follow, lines)?,
    }
    Ok(())
}

/// `service status`: the essentials instead of the service manager's output.
fn print_status(ctx: &Ctx, manager: &dyn ServiceManager) {
    if !manager.is_installed() {
        println!("{} {}", Level::Fail.symbol(), ui::bold("not installed"));
        println!("{}", ui::fix(2, "credential-bridge-ctl service install"));
        return;
    }
    let program = manager.installed_program();
    if manager.is_active() {
        let info = manager.info();
        let mut facts = Vec::new();
        if let Some(since) = info.since.as_deref() {
            facts.push(format!("since {}", short_since(since, &today())));
        }
        if let Some(pid) = info.pid {
            facts.push(format!("pid {pid}"));
        }
        if let Some(version) = program.as_deref().and_then(daemon_version) {
            facts.push(format!("version {version}"));
        }
        println!("{} {}  {}", Level::Ok.dot(), ui::bold("running"), ui::dim(&facts.join(" · ")));
    } else {
        println!("{} {}", Level::Fail.dot(), ui::bold("stopped"));
        println!("{}", ui::fix(2, "credential-bridge-ctl service start"));
    }
    if let Some(program) = &program {
        let note = if is_store_path(program) {
            format!("  {}", ui::yellow("⚠ Nix store path"))
        } else {
            String::new()
        };
        println!("  daemon   {}{note}", ui::home_tilde(program));
    }
    println!("  config   {}", ui::home_tilde(&ctx.config_path));
    if let Ok(config) = ctx.load() {
        let sockets: Vec<String> = config
            .remotes
            .iter()
            .map(|remote| {
                let level = match config.socket_path(&remote.name).map(|s| socket_state(&s)) {
                    Ok(SocketState::Listening) => Level::Ok,
                    _ => Level::Fail,
                };
                format!("{} {}", level.dot(), remote.name)
            })
            .collect();
        if sockets.is_empty() {
            println!("  sockets  {}", ui::dim("no remotes configured"));
        } else {
            println!("  sockets  {}", sockets.join("  "));
        }
    }
    if ui::verbose() {
        println!("  {}", ui::dim(&format!("unit: {}", manager.definition_path().display())));
    }
}

/// `credential-bridged 0.1.0` -> `0.1.0`.
fn daemon_version(program: &Path) -> Option<String> {
    let out = std::process::Command::new(program).arg("--version").output().ok()?;
    String::from_utf8_lossy(&out.stdout).split_whitespace().nth(1).map(str::to_owned)
}

/// Today's date as `YYYY-MM-DD` in local time.
fn today() -> String {
    std::process::Command::new("date")
        .arg("+%F")
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .unwrap_or_default()
}

/// `Wed 2026-11-18 08:33:07 CET` -> `08:33` today, `2026-11-17 08:33` otherwise.
fn short_since(timestamp: &str, today: &str) -> String {
    let mut parts = timestamp.split_whitespace();
    let (Some(_weekday), Some(date), Some(time)) = (parts.next(), parts.next(), parts.next()) else {
        return timestamp.to_owned();
    };
    let hm = time.get(..5).unwrap_or(time);
    if date == today { hm.to_owned() } else { format!("{date} {hm}") }
}

/// Runs a log command and prints every line through `format`.
fn print_log_lines(mut cmd: std::process::Command, format: fn(&str) -> String) -> anyhow::Result<()> {
    use std::io::BufRead;
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("cannot run `{}`", crate::util::describe(&cmd)))?;
    let stdout = child.stdout.take().expect("stdout is piped");
    for line in std::io::BufReader::new(stdout).lines() {
        println!("{}", format(&line?));
    }
    child.wait()?;
    Ok(())
}

/// `2026-11-18T11:26:56+01:00 credential-bridged[6155]: msg` -> `11:26:56  msg`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code, reason = "used by systemd"))]
fn format_journal_line(line: &str) -> String {
    if line.starts_with("-- ") {
        return ui::dim(line);
    }
    let (Some(time), Some((ident, message))) = (clock(line), line.split_once("]: ")) else {
        return line.to_owned();
    };
    if ident.contains(" systemd[") {
        return format!("{}  {}", ui::dim(time), ui::dim(message));
    }
    format!("{}  {}", ui::dim(time), colorize_log(message))
}

/// The daemon's own log file: `2026-11-18T15:09:05.218676Z msg` (UTC).
#[cfg_attr(not(target_os = "macos"), allow(dead_code, reason = "used by launchd"))]
fn format_file_line(line: &str) -> String {
    match (clock(line), line.split_once(' ')) {
        (Some(time), Some((_, message))) => format!("{}  {}", ui::dim(time), colorize_log(message)),
        _ => line.to_owned(),
    }
}

/// `HH:MM:SS` of a line that starts with an ISO 8601 timestamp.
fn clock(line: &str) -> Option<&str> {
    (line.as_bytes().get(10) == Some(&b'T')).then(|| line.get(11..19)).flatten()
}

/// Colors the outcome column of request lines and error/warning lines.
fn colorize_log(message: &str) -> String {
    if let Some(rest) = message.strip_prefix("error: ") {
        return format!("{} {rest}", ui::red("error:"));
    }
    if let Some(rest) = message.strip_prefix("warning: ") {
        return format!("{} {rest}", ui::yellow("warning:"));
    }
    let mut out = message.to_owned();
    for (token, paint) in [
        ("✓ allowed", ui::green as fn(&str) -> String),
        ("✗ denied", ui::yellow),
        ("∅ none", ui::yellow),
        ("! error", ui::red),
    ] {
        if out.contains(token) {
            out = out.replacen(token, &paint(token), 1);
            break;
        }
    }
    out
}

/// After a configuration change: reload a running daemon, or say how to start one.
pub fn reload_if_active(ctx: &Ctx) {
    let Ok(manager) = manager() else { return };
    if manager.is_active() {
        if let Err(err) = manager.reload() {
            eprintln!("warning: cannot reload credential-bridged: {err:#}");
            return;
        }
        // Wait until the daemon has applied the configuration now on disk
        // (it records that locally), so that a following `remote install` or
        // `check` sees the new state; unchanged sockets answer all along.
        let expected = match std::fs::read_to_string(&ctx.config_path) {
            Ok(text) => credential_bridge_proto::fingerprint(&text),
            Err(_) => credential_bridge_proto::fingerprint(""),
        };
        let loaded = paths::loaded_config_file().ok();
        let applied = || {
            loaded
                .as_ref()
                .and_then(|path| std::fs::read_to_string(path).ok())
                .is_some_and(|text| text.trim() == expected)
        };
        if wait_until(Duration::from_secs(3), Duration::from_millis(50), applied) {
            println!("reloaded credential-bridged");
        } else {
            eprintln!(
                "warning: sent the reload, but credential-bridged has not applied the new \
                 configuration yet; see `credential-bridge-ctl service logs`"
            );
        }
    } else if manager.is_installed() {
        println!(
            "note: credential-bridged is not running; start it with `credential-bridge-ctl service start`"
        );
    } else {
        println!("note: the service is not installed yet; run `credential-bridge-ctl service install`");
    }
}

fn daemon_spec(
    ctx: &Ctx,
    explicit: Option<PathBuf>,
    previous: Option<&InstalledSpec>,
) -> anyhow::Result<DaemonSpec> {
    let program = resolve_daemon_path(explicit)?;
    let config = if ctx.explicit_config {
        Some(std::path::absolute(&ctx.config_path)?.to_string_lossy().into_owned())
    } else {
        None
    };
    let (args, env, kept) = merge_spec(config, service_env(|name| env::var(name).ok()), previous);
    for note in kept {
        println!("keeping {note} from the installed service");
    }
    Ok(DaemonSpec { program, args, env })
}

/// Arguments and environment for a (re)installed service. What was given
/// now wins; `--config` and the XDG directories of the installed service
/// are kept otherwise, so an update (`just install`, `install.sh`) does not
/// silently point the daemon at other files. Also returns what was kept.
fn merge_spec(
    config: Option<String>,
    mut env: Vec<(String, String)>,
    previous: Option<&InstalledSpec>,
) -> (Vec<String>, Vec<(String, String)>, Vec<String>) {
    let mut kept = Vec::new();
    let previous_config = previous
        .and_then(|p| p.args.iter().position(|a| a == "--config").and_then(|i| p.args.get(i + 1)).cloned());
    let config = config.or_else(|| previous_config.inspect(|path| kept.push(format!("--config {path}"))));
    let mut args = vec!["run".to_owned()];
    if let Some(config) = config {
        args.push("--config".to_owned());
        args.push(config);
    }
    for (name, value) in previous.map(|p| p.env.as_slice()).unwrap_or_default() {
        if SHARED_VARS.contains(&name.as_str()) && !env.iter().any(|(n, _)| n == name) {
            kept.push(format!("{name}={value}"));
            env.push((name.clone(), value.clone()));
        }
    }
    (args, env, kept)
}

/// Variables the daemon needs to see as ctl does (see [`DaemonSpec::env`]).
const SHARED_VARS: &[&str] = &["XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME"];

fn service_env(get: impl Fn(&str) -> Option<String>) -> Vec<(String, String)> {
    let path = get("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".to_owned());
    std::iter::once(("PATH".to_owned(), path))
        .chain(
            SHARED_VARS
                .iter()
                .filter_map(|&name| get(name).filter(|v| v.starts_with('/')).map(|v| (name.to_owned(), v))),
        )
        .collect()
}

fn resolve_daemon_path(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(path) = explicit {
        let path = std::path::absolute(&path)?;
        if !is_executable(&path) {
            bail!("{} is not an executable file", path.display());
        }
        return Ok(path);
    }
    // The path this program was started as, *not* `current_exe()`: that one
    // resolves symlinks, so for `~/.local/bin/credential-bridge-ctl -> …` it
    // would name a Nix store path, which goes stale on the next update.
    let invoked = invoked_path(env::args_os().next().map(PathBuf::from), which);
    let sibling = |exe: PathBuf| {
        exe.parent().map(|dir| dir.join(DAEMON_BINARY)).filter(|candidate| is_executable(candidate))
    };
    invoked
        .and_then(sibling)
        .or_else(|| which(DAEMON_BINARY))
        .or_else(|| env::current_exe().ok().and_then(sibling))
        .with_context(|| format!("cannot find {DAEMON_BINARY}; pass --daemon-path"))
}

/// Absolute, symlink-preserving path of `argv0`: as given if it contains a
/// slash, otherwise looked up in `$PATH` the way the shell found it.
pub fn invoked_path(argv0: Option<PathBuf>, lookup: impl Fn(&str) -> Option<PathBuf>) -> Option<PathBuf> {
    let argv0 = argv0?;
    if argv0.components().count() > 1 { std::path::absolute(&argv0).ok() } else { lookup(argv0.to_str()?) }
}

/// Whether the service runs a daemon from the Nix store, which a later
/// update or garbage collection removes.
pub fn is_store_path(program: &Path) -> bool {
    program.starts_with("/nix/store")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reinstalling_keeps_config_and_xdg_unless_given_again() {
        let previous = InstalledSpec {
            program: "/old/credential-bridged".into(),
            args: vec!["run".into(), "--config".into(), "/home/me/cb.toml".into()],
            env: vec![("PATH".into(), "/old/bin".into()), ("XDG_STATE_HOME".into(), "/home/me/xs".into())],
        };
        let now = vec![("PATH".to_owned(), "/new/bin".to_owned())];
        let (args, env, kept) = merge_spec(None, now.clone(), Some(&previous));
        assert_eq!(args, ["run", "--config", "/home/me/cb.toml"]);
        assert_eq!(
            env,
            [
                ("PATH".to_owned(), "/new/bin".to_owned()),
                ("XDG_STATE_HOME".to_owned(), "/home/me/xs".to_owned())
            ]
        );
        assert_eq!(kept.len(), 2);

        // Given again: the new values win.
        let now = vec![
            ("PATH".to_owned(), "/new/bin".to_owned()),
            ("XDG_STATE_HOME".to_owned(), "/other".to_owned()),
        ];
        let (args, env, _) = merge_spec(Some("/x.toml".into()), now.clone(), Some(&previous));
        assert_eq!(args, ["run", "--config", "/x.toml"]);
        assert_eq!(env, now);

        // Nothing installed yet.
        assert_eq!(merge_spec(None, vec![], None).0, ["run"]);
    }

    #[test]
    fn service_sees_the_xdg_directories_ctl_uses() {
        let shell = |name: &str| match name {
            "PATH" => Some("/home/me/bin:/usr/bin".to_owned()),
            "XDG_STATE_HOME" => Some("/home/me/state".to_owned()),
            "XDG_CONFIG_HOME" => Some("relative/is/ignored".to_owned()),
            _ => None,
        };
        assert_eq!(
            service_env(shell),
            [
                ("PATH".to_owned(), "/home/me/bin:/usr/bin".to_owned()),
                ("XDG_STATE_HOME".to_owned(), "/home/me/state".to_owned())
            ]
        );
    }

    #[test]
    fn formats_logs() {
        assert_eq!(short_since("Wed 2026-11-18 08:33:07 CET", "2026-11-18"), "08:33");
        assert_eq!(short_since("Tue 2026-11-17 08:33:07 CET", "2026-11-18"), "2026-11-17 08:33");
        assert_eq!(
            format_journal_line(
                "2026-11-18T11:26:56+01:00 credential-bridged[6155]: testbox  get    ✓ allowed  github.com/x"
            ),
            "11:26:56  testbox  get    ✓ allowed  github.com/x"
        );
        assert_eq!(
            format_journal_line(
                "2026-11-18T08:33:07+01:00 systemd[5045]: Started credential-bridged.service."
            ),
            "08:33:07  Started credential-bridged.service."
        );
        assert_eq!(format_journal_line("-- Boot 05c8 --"), "-- Boot 05c8 --");
        assert_eq!(format_file_line("2026-11-18T15:09:05.218676Z warning: x"), "15:09:05  warning: x");
    }

    #[test]
    fn invoked_path_keeps_symlinks() {
        let lookup = |name: &str| Some(PathBuf::from("/home/me/.local/bin").join(name));
        assert_eq!(
            invoked_path(Some("credential-bridge-ctl".into()), lookup),
            Some(PathBuf::from("/home/me/.local/bin/credential-bridge-ctl"))
        );
        assert_eq!(
            invoked_path(Some("/opt/cb/bin/credential-bridge-ctl".into()), lookup),
            Some(PathBuf::from("/opt/cb/bin/credential-bridge-ctl"))
        );
        assert!(invoked_path(Some("./ctl".into()), lookup).unwrap().is_absolute());
        assert_eq!(invoked_path(None, lookup), None);
        assert!(is_store_path(Path::new("/nix/store/abc-cb/bin/credential-bridged")));
        assert!(!is_store_path(Path::new("/home/me/.local/bin/credential-bridged")));
    }
}
