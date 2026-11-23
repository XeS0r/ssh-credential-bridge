//! `check`: everything that is configured on this machine, nothing else; with server
//! names or `--all` also those servers.

use std::os::unix::fs::FileTypeExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use credential_bridge_config::host_keys::HostKeyWarning;
use credential_bridge_config::{
    Config, ConfigError, Confirm, KeySelection, Server, ServerKeys, Signing, SocketSpec, SourceKind,
};
use credential_bridge_platform::socket::is_listening;
use credential_bridge_proto::ipc::control::{DaemonStatus, Request, Response, UpstreamStatus};

use super::change::{RESTART_HINT, moved_paths_line, moved_vault_line};
use super::probe;
use super::server::{expected_remote_version, setup_argv, signing_key, ssh_client_line};
use super::vault::{Live, check_lines};
use super::{CONTROL_TIMEOUT, Context, VERSION, connect, daemon_config, in_path, printable};
use crate::audit;
use crate::cli::CheckArgs;
use crate::control::ControlError;
use crate::remote::{REMOTE_BINARY, RemoteShell, SshShell};
use crate::report::{Line, Report};
use crate::ssh_config::EffectiveSshConfig;

/// Time a socket gets to accept a connection.
const SOCKET_TIMEOUT: Duration = Duration::from_millis(500);

/// How much of the end of the audit log `check` reads for recent requests from
/// unregistered hosts and unrecognised connections.
const AUDIT_TAIL: u64 = 256 * 1024;

/// At most this many hosts or connection kinds are listed.
const MAX_LISTED: usize = 5;

/// The hint for an unregistered host.
const SERVER_ADD_HINT: &str = "credential-bridge-ctl server add NAME --profile PROFILE";

/// The hint for a host key of several servers.
const AMBIGUOUS_HINT: &str = "keep the key under one server: remove the other entry, or fix known_hosts";

/// `check`: only what is configured on this machine: configuration problems
/// (`Config::validate`), the effective `profile.unregistered`, daemon reachable and same
/// version, sockets, upstreams, vaults, the local ssh client's version (with servers)
/// and ssh config entries, gpg-agent extra socket, whether every server has host keys
/// of its own (known_hosts entries present, no key under two servers), and recent
/// requests from unregistered hosts and unrecognised connections (from the audit log).
/// Nothing connects to a server. With server names (or `--all`, every server) also each
/// of those servers: the probe through the daemon (as `server add` runs it), its remote
/// binary, git config and gpg.conf. Exit code 1 if any line failed.
pub fn check(ctx: &Context, args: &CheckArgs) -> anyhow::Result<ExitCode> {
    let mut report = Report::printing();
    check_with(ctx, args, &SshShell, &mut report);
    Ok(if report.failed() { ExitCode::FAILURE } else { ExitCode::SUCCESS })
}

/// [`check`] with an explicit shell and report.
pub fn check_with(ctx: &Context, args: &CheckArgs, shell: &dyn RemoteShell, report: &mut Report) {
    let config = check_config(ctx, report);
    let status = check_daemon(ctx, config.as_ref(), report);
    if let Some(line) = super::service::leftover_v01_line(ctx) {
        report.push(line);
    }
    let Some(config) = config else {
        for name in &args.servers {
            report.push(Line::fail(format!("server {name}"), "not checked: fix the configuration first"));
        }
        return;
    };
    report.push(unregistered_line(&config));
    check_upstreams(&config, status.as_ref(), report);
    check_vaults(&config, status.as_ref(), report);
    check_gpg(&config, report);
    check_ssh_config(ctx, &config, shell, report);
    check_host_keys(&config, report);
    // The log the daemon writes; the configured one only while it is not running.
    let audit_log = status
        .as_ref()
        .map_or_else(|| config.daemon.audit_log.clone(), |status| PathBuf::from(&status.paths.audit_log));
    check_strangers(&audit_log, report);
    let servers: Vec<&str> = if args.all {
        config.servers.keys().map(String::as_str).collect()
    } else {
        args.servers.iter().map(String::as_str).collect()
    };
    for name in servers {
        match config.servers.get(name) {
            Some(server) => check_remote(&config, server, shell, report),
            None => report.push(
                Line::fail(
                    format!("server {name}"),
                    format!("no [server.{name}] in {}", ctx.config_path.display()),
                )
                .with_hint(format!("credential-bridge-ctl server add {name} --profile PROFILE")),
            ),
        }
    }
}

pub(crate) fn check_config(ctx: &Context, report: &mut Report) -> Option<Config> {
    let path = ctx.config_path.display();
    match Config::load(&ctx.config_path, &ctx.paths) {
        Ok(config) => {
            if ctx.config_path.exists() {
                report.push(Line::ok("config", path.to_string()));
            } else {
                report.push(Line::ok("config", format!("{path} does not exist: nothing configured")));
            }
            let problems = config.validate();
            for problem in &problems {
                report.push(Line::fail("config", problem.to_string()));
            }
            for warning in config.warnings() {
                report.push(Line::warn("config", warning.to_string()));
            }
            problems.is_empty().then_some(config)
        }
        Err(ConfigError::Invalid { problems, .. }) => {
            for problem in problems {
                report.push(Line::fail("config", problem.to_string()));
            }
            None
        }
        Err(error) => {
            report.push(Line::fail("config", error.to_string()));
            None
        }
    }
}

/// Daemon liveness, version and the agent sockets. Returns its status if it answered.
fn check_daemon(ctx: &Context, config: Option<&Config>, report: &mut Report) -> Option<DaemonStatus> {
    let daemon = daemon_config(ctx, config);
    let status =
        connect(&daemon, CONTROL_TIMEOUT).and_then(|mut client| match client.request(&Request::Status)? {
            Response::Status(status) => Ok(status),
            _ => Err(ControlError::Unexpected),
        });
    let status = match status {
        Ok(status) => status,
        Err(ControlError::NotRunning(_)) => {
            report.push(Line::fail("daemon", "not running").with_hint("credential-bridge-ctl daemon start"));
            return None;
        }
        Err(error) => {
            report.push(Line::fail("daemon", error.to_string()));
            return None;
        }
    };
    if status.version == VERSION {
        report.push(Line::ok("daemon", format!("running, version {} (pid {})", status.version, status.pid)));
    } else {
        report.push(
            Line::warn(
                "daemon",
                format!("version {} runs, this ctl is {VERSION}", printable(&status.version)),
            )
            .with_hint(RESTART_HINT),
        );
    }
    if Path::new(&status.config) != ctx.config_path {
        report.push(Line::warn(
            "daemon",
            format!("uses {}, not {}", printable(&status.config), ctx.config_path.display()),
        ));
    }
    if status.locked {
        report.push(Line::warn("daemon", "the proxy is locked (ssh-add -x)").with_hint("ssh-add -X"));
    }
    // The paths the daemon uses: those of [daemon] when it started.
    let used = &status.paths;
    let (socket, forward) = (PathBuf::from(&used.socket), PathBuf::from(&used.forward_socket));
    if let Some(line) = moved_paths_line(used, &daemon) {
        report.push(line);
    }
    if let Some(line) = config.and_then(|config| moved_vault_line(used, &config.vault.keepassxc)) {
        report.push(line);
    }
    if is_listening(&socket, SOCKET_TIMEOUT) {
        report.push(Line::ok("agent socket", socket.display().to_string()));
    } else {
        report.push(Line::fail("agent socket", format!("{} does not accept connections", socket.display())));
    }
    // Not connected to: every connection there is a server's, checked and logged as one
    // (ctl itself is not dumpable, so the daemon cannot read its executable and would
    // log a client it cannot verify). The daemon answered, so it listens there; ssh
    // needs the socket file.
    let forward = &forward;
    match std::fs::symlink_metadata(forward) {
        Ok(meta) if meta.file_type().is_socket() => {
            report.push(Line::ok("forward socket", forward.display().to_string()));
        }
        Ok(_) => report.push(Line::fail("forward socket", format!("{} is not a socket", forward.display()))),
        Err(error) => report.push(Line::fail("forward socket", format!("{}: {error}", forward.display()))),
    }
    for worker in &status.workers {
        if !worker.degraded.is_empty() {
            report.push(Line::warn(
                format!("worker {}", worker.kind),
                format!(
                    "runs without {}",
                    worker.degraded.iter().map(|s| printable(s)).collect::<Vec<_>>().join(", ")
                ),
            ));
        }
    }
    Some(status)
}

/// The effective `profile.unregistered` (built in, with the fields the configuration
/// sets); a warning if it shows all keys or signs without a dialog.
pub(crate) fn unregistered_line(config: &Config) -> Line {
    let profile = &config.unregistered;
    let (keys, confirm) = match &profile.ssh {
        None => ("no keys".to_owned(), None),
        Some(ssh) => {
            let keys = match &ssh.keys {
                KeySelection::All => "all keys".to_owned(),
                KeySelection::Upstreams(names) if names.is_empty() => "no keys".to_owned(),
                KeySelection::Upstreams(names) => format!("keys of {}", names.join(", ")),
            };
            (keys, Some(ssh.confirm))
        }
    };
    let mut detail = keys.clone();
    if let Some(confirm) = confirm.filter(|_| keys != "no keys") {
        detail.push_str(&format!(", confirm = \"{}\"", confirm.describe()));
    }
    if profile.hops.ssh {
        detail.push_str(", hops.ssh");
    }
    detail.push_str(", no tokens, no gpg");
    let mut loose = Vec::new();
    if matches!(&profile.ssh, Some(ssh) if ssh.keys == KeySelection::All) {
        loose.push("keys = \"all\" shows every key to any server you have not added");
    }
    if matches!(&profile.ssh, Some(ssh) if ssh.confirm == Confirm::Never) && keys != "no keys" {
        loose.push("confirm = \"never\" lets any server you have not added sign without asking");
    }
    if loose.is_empty() {
        Line::ok("unregistered", detail)
    } else {
        Line::warn("unregistered", format!("{detail}: {}", loose.join("; ")))
            .with_hint("loosen [profile.unregistered] only on purpose, or add the servers you use")
    }
}

/// What the audit log says about one unregistered host or one kind of unrecognised
/// connection.
#[derive(Debug, Default, PartialEq, Eq)]
struct Stranger {
    /// The audit label: `unregistered host SHA256:…` or `unrecognised host (…)`.
    label: String,
    /// Time of the last event.
    last: String,
    /// Events seen (connections and refused requests).
    events: usize,
    /// The reason of the last refusal.
    reason: Option<String>,
}

/// The start of the label of a host key that belongs to several servers.
const AMBIGUOUS: &str = "host key ";

/// Unregistered hosts and unrecognised connections in audit log lines, the most recent
/// first. An unregistered host shows up as a `server` event without server name and in
/// every later event's label; an unrecognised connection only in labels. A host whose
/// key belongs to several servers (`ambiguous` in its `server` event) is labelled
/// `host key SHA256:… belongs to several servers: a, b`, its later events included.
fn strangers(lines: &str) -> Vec<Stranger> {
    let mut found: Vec<Stranger> = Vec::new();
    // `unregistered host SHA256:…` → the label of an ambiguous key.
    let mut ambiguous: Vec<(String, String)> = Vec::new();
    for event in audit::events(lines) {
        let text = |key: &str| audit::text(&event, key);
        let label = match (text("event"), text("server")) {
            (Some("server"), None) => match text("host_key") {
                Some(host_key) => {
                    let unregistered = format!("unregistered host {host_key}");
                    let servers: Vec<&str> = event
                        .get("ambiguous")
                        .and_then(serde_json::Value::as_array)
                        .map(|names| names.iter().filter_map(serde_json::Value::as_str).collect())
                        .unwrap_or_default();
                    ambiguous.retain(|(label, _)| *label != unregistered);
                    if servers.is_empty() {
                        unregistered
                    } else {
                        let label = format!(
                            "{AMBIGUOUS}{host_key} belongs to several servers: {}",
                            servers.join(", ")
                        );
                        ambiguous.push((unregistered, label.clone()));
                        label
                    }
                }
                None => continue,
            },
            (Some("sign" | "git" | "gpg" | "refused"), Some(label))
                if label.starts_with("unregistered host ") || label.starts_with("unrecognised host (") =>
            {
                ambiguous
                    .iter()
                    .find(|(unregistered, _)| unregistered == label)
                    .map_or_else(|| label.to_owned(), |(_, ambiguous)| ambiguous.clone())
            }
            _ => continue,
        };
        let index = match found.iter().position(|stranger| stranger.label == label) {
            Some(index) => index,
            None => {
                found.push(Stranger { label, ..Stranger::default() });
                found.len() - 1
            }
        };
        let stranger = &mut found[index];
        stranger.events += 1;
        stranger.last = text("time").unwrap_or_default().to_owned();
        if let Some(reason) = text("reason") {
            stranger.reason = Some(reason.to_owned());
        }
    }
    // RFC 3339 times in UTC sort as text.
    found.sort_by(|a, b| b.last.cmp(&a.last));
    found
}

/// Whether every server has host keys of its own, read like the daemon reads them: a
/// server with `known_host` whose known_hosts files list no key for it, and a key that
/// belongs to more than one server, get nothing (treated as unregistered). A known_hosts
/// file that cannot be read is a warning of its own: ssh skips it as well, and the
/// servers it leaves without keys fail.
fn check_host_keys(config: &Config, report: &mut Report) {
    if config.servers.is_empty() {
        return;
    }
    let read = probe::HostKeys::read(config);
    let mut problems = false;
    for warning in &read.warnings {
        let line = match warning {
            HostKeyWarning::Unreadable { path, error } => {
                Line::warn("known_hosts file", probe::unreadable_text(path, error))
            }
            HostKeyWarning::NoKeys { server, unreadable, any_read } => {
                problems = true;
                let lookup = match config.servers.get(server).map(|server| &server.keys) {
                    Some(ServerKeys::KnownHost(known)) => printable(&known.name),
                    _ => server.clone(),
                };
                let line = Line::fail(
                    "host keys",
                    format!(
                        "known_hosts lists no key for {lookup} (server {server}): it is treated as unregistered"
                    ),
                );
                if !any_read && !unreadable.is_empty() {
                    let files: Vec<String> =
                        unreadable.iter().map(|path| path.display().to_string()).collect();
                    line.with_hint(format!(
                        "none of its known_hosts files can be read; make {} readable",
                        files.join(", ")
                    ))
                } else {
                    line.with_hint(format!("connect once with ssh {server} and confirm the host key"))
                }
            }
            HostKeyWarning::Ambiguous { key, servers } => {
                problems = true;
                Line::fail(
                    "host keys",
                    format!(
                        "{} belongs to servers {}: each of them is treated as unregistered",
                        super::server::fingerprint(key),
                        servers.join(" and ")
                    ),
                )
                .with_hint(AMBIGUOUS_HINT)
            }
        };
        report.push(line);
    }
    if !problems {
        report.push(Line::ok(
            "host keys",
            format!("{} server(s), each with keys of its own", config.servers.len()),
        ));
    }
}

/// Recent requests from unregistered hosts and unrecognised connections, from the end of
/// the audit log `audit_log`: one warning per host or kind of connection, with the hint
/// to register the server (or, for a key of several servers, to keep it under one).
/// Nothing if the log is missing or has none.
fn check_strangers(audit_log: &Path, report: &mut Report) {
    let Ok(tail) = audit::tail(audit_log, AUDIT_TAIL) else { return };
    let found = strangers(&tail);
    for stranger in found.iter().take(MAX_LISTED) {
        let mut detail = format!("{}: {} event(s), last {}", stranger.label, stranger.events, stranger.last);
        if let Some(reason) = &stranger.reason {
            detail.push_str(&format!(" ({reason})"));
        }
        let line = Line::warn("recent request", printable(&detail));
        report.push(if stranger.label.starts_with("unregistered host ") {
            line.with_hint(SERVER_ADD_HINT)
        } else if stranger.label.starts_with(AMBIGUOUS) {
            line.with_hint(AMBIGUOUS_HINT)
        } else {
            line.with_hint("not recognised, so nothing was given; see credential-bridge-ctl log")
        });
    }
    if found.len() > MAX_LISTED {
        report.push(Line::warn(
            "recent request",
            format!("{} more hosts or connections: credential-bridge-ctl log", found.len() - MAX_LISTED),
        ));
    }
}

/// Detail line for an upstream the daemon could not reach: the socket and the reason
/// (`timeout` if it did not answer in time).
fn unreachable_detail(up: &UpstreamStatus) -> String {
    match &up.error {
        Some(error) => format!("{} is not reachable: {}", printable(&up.socket), printable(error)),
        None => format!("{} is not reachable", printable(&up.socket)),
    }
}

fn check_upstreams(config: &Config, status: Option<&DaemonStatus>, report: &mut Report) {
    let Some(agent) = &config.agent else { return };
    for upstream in &agent.upstreams {
        let label = format!("upstream {}", upstream.name);
        let from_daemon = status.and_then(|status| status.upstreams.iter().find(|u| u.name == upstream.name));
        match from_daemon {
            Some(up) if up.reachable => {
                report.push(Line::ok(
                    label,
                    format!("{} key(s) at {}", up.keys.unwrap_or(0), printable(&up.socket)),
                ));
            }
            Some(up) => report.push(Line::fail(label, unreachable_detail(up))),
            // Without the daemon only plain paths can be checked here.
            None => match &upstream.socket {
                SocketSpec::Path(path) if is_listening(path, SOCKET_TIMEOUT) => {
                    report.push(Line::ok(label, path.display().to_string()));
                }
                SocketSpec::Path(path) => {
                    report.push(Line::fail(label, format!("{} does not accept connections", path.display())));
                }
                SocketSpec::Gpgconf(name) => match gpgconf_dir(name) {
                    Some(path) if is_listening(&path, SOCKET_TIMEOUT) => {
                        report.push(Line::ok(label, path.display().to_string()));
                    }
                    Some(path) => report.push(
                        Line::fail(label, format!("{} does not accept connections", path.display()))
                            .with_hint("gpgconf --launch gpg-agent"),
                    ),
                    None => report.push(Line::fail(label, format!("gpgconf --list-dirs {name} failed"))),
                },
            },
        }
    }
}

/// `gh` for `auth = "gh"` sources, then the vault lines of `vault list`.
fn check_vaults(config: &Config, status: Option<&DaemonStatus>, report: &mut Report) {
    let gh = config.sources.values().any(|source| matches!(source.kind, SourceKind::GithubGh { .. }));
    if gh {
        if in_path("gh") {
            report.push(Line::ok("tool gh", "installed"));
        } else {
            report.push(Line::fail("tool gh", "not installed (a source uses auth = \"gh\")"));
        }
    }
    let live = status.map_or(Live::NotRunning, |status| Live::Running(status.vaults.clone()));
    for line in check_lines(config, &live) {
        report.push(line);
    }
}

/// `gpgconf --list-dirs <name>`.
pub(crate) fn gpgconf_dir(name: &str) -> Option<PathBuf> {
    let output = std::process::Command::new("gpgconf")
        .args(["--list-dirs", name])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (output.status.success() && path.starts_with('/')).then(|| PathBuf::from(path))
}

/// Whether any profile allows gpg.
fn gpg_used(config: &Config) -> bool {
    config.profiles.values().any(|profile| profile.gpg.sign || profile.gpg.decrypt)
}

fn check_gpg(config: &Config, report: &mut Report) {
    let Some(gpg) = config.gpg.as_ref().filter(|_| gpg_used(config)) else { return };
    let path = match &gpg.socket {
        SocketSpec::Path(path) => Some(path.clone()),
        SocketSpec::Gpgconf(name) => gpgconf_dir(name),
    };
    match path {
        Some(path) if is_listening(&path, SOCKET_TIMEOUT) => {
            report.push(Line::ok("gpg-agent", path.display().to_string()));
        }
        Some(path) => report.push(
            Line::fail("gpg-agent", format!("{} does not accept connections", path.display()))
                .with_hint("gpgconf --launch gpg-agent"),
        ),
        None => {
            report.push(Line::fail("gpg-agent", "gpgconf does not report the socket (is GnuPG installed?)"))
        }
    }
}

fn check_ssh_config(ctx: &Context, config: &Config, shell: &dyn RemoteShell, report: &mut Report) {
    let home = &ctx.paths.home;
    if !config.servers.is_empty() {
        // Servers are recognised only behind OpenSSH 8.9 or later.
        report.push(ssh_client_line(shell));
    }
    if config.agent.is_some() {
        // Any host will do; ssh -G does not connect.
        let probe = config.servers.keys().next().map_or("credential-bridge-check.invalid", String::as_str);
        match shell.ssh_g(probe) {
            Ok(output)
                if EffectiveSshConfig::parse(&output).identity_agent_is(&config.daemon.socket, home) =>
            {
                report.push(Line::ok("ssh config", "IdentityAgent is the proxy"));
            }
            Ok(_) => report.push(
                Line::warn("ssh config", "IdentityAgent is not the proxy: own logins bypass it")
                    .with_hint("credential-bridge-ctl server ssh-config"),
            ),
            Err(error) => report.push(Line::warn("ssh config", error.to_string())),
        }
    }
    for name in config.servers.keys() {
        let hint = format!("credential-bridge-ctl server ssh-config {name}");
        match shell.ssh_g(name) {
            Ok(output)
                if EffectiveSshConfig::parse(&output).forwards_to(&config.daemon.forward_socket, home) =>
            {
                report.push(Line::ok("ssh config", format!("ForwardAgent to the proxy for {name}")));
            }
            Ok(_) => report.push(
                Line::warn("ssh config", format!("no ForwardAgent to the proxy for {name}")).with_hint(hint),
            ),
            Err(error) => report.push(Line::warn("ssh config", error.to_string()).with_hint(hint)),
        }
    }
}

/// The remote binary, its git config, (for gpg profiles) gpg.conf, and the probe
/// through the daemon on one server.
fn check_remote(config: &Config, server: &Server, shell: &dyn RemoteShell, report: &mut Report) {
    let name = &server.name;
    let label = format!("server {name}");
    let update = format!("credential-bridge-ctl server add {name} --profile {}", server.profile);
    let version = match shell.run(name, &[REMOTE_BINARY, "--version"]) {
        Ok(output) => output,
        Err(error) => {
            report.push(Line::fail(label, error.to_string()));
            return;
        }
    };
    if version.status == Some(255) {
        report.push(Line::fail(label, format!("unreachable: {}", printable(&version.failure_reason()))));
        return;
    }
    if !version.success() {
        report.push(Line::fail(label, "credential-bridge-remote is not installed").with_hint(update));
        return;
    }
    let installed = version.stdout.trim();
    if installed != expected_remote_version() {
        report.push(
            Line::warn(label.clone(), format!("out of date: {} (ctl is {VERSION})", printable(installed)))
                .with_hint(update.clone()),
        );
    } else {
        report.push(Line::ok(label.clone(), printable(installed)));
    }

    let hosts = config.git_hosts_for(server);
    let signing =
        config.profile_for(Some(server)).is_some_and(|profile| profile.signing == Some(Signing::Ssh));
    let key = if signing { signing_key(config, name).ok() } else { None };
    if !hosts.is_empty() || key.is_some() {
        let argv = setup_argv(&hosts, key.as_deref(), true);
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        match shell.run(name, &argv) {
            Ok(output) if output.success() && output.stdout.trim().is_empty() => {
                report.push(Line::ok(label.clone(), "git config up to date"));
            }
            Ok(output) if output.success() => {
                let line = Line::warn(label.clone(), "git config out of date");
                report.push(if server.git_config {
                    line.with_hint(update.clone())
                } else {
                    let lines: Vec<String> = output.stdout.lines().map(printable).collect();
                    line.with_hint(format!("run on the server:\n{}", lines.join("\n")))
                });
            }
            Ok(output) => report.push(Line::fail(label.clone(), printable(&output.failure_reason()))),
            Err(error) => report.push(Line::fail(label.clone(), error.to_string())),
        }
    }

    let gpg = config.profile_for(Some(server)).is_some_and(|profile| profile.gpg.sign || profile.gpg.decrypt);
    if gpg {
        // Counts matching lines only; nothing of gpg.conf is printed.
        let script = r#"grep -c '^[[:space:]]*agent-program.*credential-bridge-remote' "${GNUPGHOME:-$HOME/.gnupg}/gpg.conf""#;
        match shell.run(name, &["sh", "-c", script]) {
            Ok(output) if output.success() && output.stdout.trim() != "0" => {
                report.push(Line::ok(label.clone(), "gpg.conf uses the gpg shim"));
            }
            Ok(_) => report.push(
                Line::warn(label.clone(), "gpg.conf has no agent-program for the gpg shim")
                    .with_hint(format!("credential-bridge-ctl gpg setup {name}")),
            ),
            Err(error) => report.push(Line::fail(label.clone(), error.to_string())),
        }
    }

    let probe = probe::probe(config, server, shell);
    report.push(Line { label, ..probe });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_support::{FakeShell, context, test_key, write_config};
    use crate::report::Status;

    fn config_text() -> String {
        format!(
            r#"version = 2
[agent]
[[agent.upstream]]
name = "fido"
socket = "/nonexistent/agent.sock"

[source.github]
type = "github"
auth = "gh"

[source.ci]
type = "github"
auth = "pat"
token = "bw://ci/token"

[profile.build]
ssh = {{ keys = "all" }}
[[profile.build.git]]
url = "https://github.com/*"
source = "ci"

[server.buildserver]
host_keys = ["{}"]
profile = "build"
"#,
            test_key(1)
        )
    }

    fn statuses(report: &Report) -> Vec<(String, Status)> {
        report.lines.iter().map(|line| (line.label.clone(), line.status)).collect()
    }

    #[test]
    fn reports_only_what_is_configured() {
        let (_dir, ctx) = context();
        write_config(&ctx, &config_text());
        let shell = FakeShell { ssh_g: "forwardagent yes\n".into(), ..FakeShell::default() };
        let mut report = Report::default();
        check_with(&ctx, &CheckArgs { servers: vec![], all: false }, &shell, &mut report);
        let labels = statuses(&report);
        assert_eq!(labels[0], ("config".to_owned(), Status::Ok));
        assert_eq!(labels[1], ("daemon".to_owned(), Status::Fail));
        assert!(labels.contains(&("upstream fido".to_owned(), Status::Fail)));
        assert!(labels.iter().any(|(label, _)| label == "vault bitwarden"));
        assert!(labels.iter().any(|(label, _)| label == "tool gh"));
        // No gpg profile: no gpg line. No server names: no server lines.
        assert!(!labels.iter().any(|(label, _)| label == "gpg-agent" || label.starts_with("server ")));
        assert!(
            report.lines.iter().any(|line| line.detail == "no ForwardAgent to the proxy for buildserver")
        );
        assert!(report.lines.iter().any(|line| line.detail.starts_with("IdentityAgent is not the proxy")));
        assert!(labels.contains(&("ssh client".to_owned(), Status::Ok)));
        assert!(report.failed());
        assert!(shell.commands().is_empty());

        // An ssh client before OpenSSH 8.9: a warning, not a failure.
        let old = FakeShell { ssh_version: Some("OpenSSH_8.8p1, OpenSSL 1.1.1l\n".into()), ..shell };
        let mut report = Report::default();
        check_with(&ctx, &CheckArgs { servers: vec![], all: false }, &old, &mut report);
        let line = report.lines.iter().find(|line| line.label == "ssh client").unwrap();
        assert_eq!(line.status, Status::Warn);
        assert!(line.detail.starts_with("OpenSSH 8.8 sends no session-bind"), "{}", line.detail);
    }

    #[test]
    fn unreachable_upstreams_name_the_reason() {
        let mut up = UpstreamStatus {
            name: "fido".into(),
            socket: "/run/fido.sock".into(),
            reachable: false,
            keys: None,
            error: Some("timeout".into()),
        };
        assert_eq!(unreachable_detail(&up), "/run/fido.sock is not reachable: timeout");
        up.error = Some("cannot connect: refused\x1b[2J".into());
        let detail = unreachable_detail(&up);
        assert!(detail.starts_with("/run/fido.sock is not reachable: cannot connect: refused"), "{detail}");
        assert!(!detail.contains('\x1b'), "{detail}");
        up.error = None;
        assert_eq!(unreachable_detail(&up), "/run/fido.sock is not reachable");
    }

    #[test]
    fn invalid_configuration_fails() {
        let (_dir, ctx) = context();
        write_config(&ctx, "version = 2\n[server.a]\nhost_keys = []\nprofile = \"nope\"\n");
        let mut report = Report::default();
        check_with(&ctx, &CheckArgs { servers: vec![], all: true }, &FakeShell::default(), &mut report);
        assert!(report.failed());
        assert!(report.lines.iter().any(|line| line.label == "config" && line.status == Status::Fail));

        // A unit 0.1 left behind is warned about, also with a configuration that fails.
        let unit = ctx.paths.home.join(".config/systemd/user/credential-bridged.service");
        std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
        std::fs::write(&unit, "").unwrap();
        let mut report = Report::default();
        check_with(&ctx, &CheckArgs { servers: vec![], all: false }, &FakeShell::default(), &mut report);
        let line = report.lines.iter().find(|line| line.label == "0.1 service").unwrap();
        assert_eq!(line.status, Status::Warn);
        assert!(line.detail.ends_with(&unit.display().to_string()), "{}", line.detail);
    }

    /// An upstream that is the proxy's own socket fails the check, as it fails loading.
    #[test]
    fn upstream_that_is_the_proxy_fails() {
        let (_dir, ctx) = context();
        let own = ctx.paths.forward_socket.display().to_string();
        write_config(&ctx, &format!("version = 2\n[[agent.upstream]]\nname = \"me\"\nsocket = \"{own}\"\n"));
        let mut report = Report::default();
        check_config(&ctx, &mut report);
        assert!(report.failed());
        assert!(
            report.text.contains(&format!(
                "agent.upstream[0].socket: {own} is the proxy's own socket (daemon.forward_socket = {own})"
            )),
            "{}",
            report.text
        );
    }

    #[test]
    fn missing_configuration_checks_the_daemon_and_the_built_in_profile() {
        let (_dir, ctx) = context();
        let mut report = Report::default();
        check_with(&ctx, &CheckArgs { servers: vec![], all: true }, &FakeShell::default(), &mut report);
        assert_eq!(
            statuses(&report),
            vec![
                ("config".to_owned(), Status::Ok),
                ("daemon".to_owned(), Status::Fail),
                // The built-in profile.unregistered is always in force.
                ("unregistered".to_owned(), Status::Ok)
            ]
        );
    }

    #[test]
    fn remote_checks_version_and_git_config() {
        let (_dir, ctx) = context();
        write_config(&ctx, &config_text());
        let shell = FakeShell::default()
            .answer(&format!("{REMOTE_BINARY} --version"), 0, "credential-bridge-remote 0.0.1\n")
            .answer(
                &format!("{REMOTE_BINARY} setup"),
                0,
                "git config --global --add credential.https://github.com.helper x\n",
            );
        let mut report = Report::default();
        check_with(&ctx, &CheckArgs { servers: vec![], all: true }, &shell, &mut report);
        let server: Vec<&Line> =
            report.lines.iter().filter(|line| line.label == "server buildserver").collect();
        assert_eq!(server.len(), 3);
        // The probe needs the daemon.
        assert_eq!(
            (server[2].status, server[2].detail.as_str()),
            (Status::Warn, "skipped: the daemon is not running")
        );
        assert_eq!(server[0].status, Status::Warn);
        assert!(server[0].detail.starts_with("out of date: credential-bridge-remote 0.0.1"));
        assert_eq!(server[1].detail, "git config out of date");
        assert_eq!(
            server[1].hint.as_deref(),
            Some("credential-bridge-ctl server add buildserver --profile build")
        );
        assert!(shell.commands()[1].ends_with("setup --host github.com --http-path github.com --print"));
    }

    /// `check` alone stays on this machine; `check NAME…` adds only those servers,
    /// `check --all` every server.
    #[test]
    fn scope_of_server_checks() {
        let (_dir, ctx) = context();
        let text = format!(
            "{}\n[server.devbox]\nhost_keys = [\"{}\"]\nprofile = \"build\"\n",
            config_text(),
            test_key(2)
        );
        write_config(&ctx, &text);
        let shell = || {
            FakeShell::default()
                .answer(&format!("{REMOTE_BINARY} --version"), 0, &format!("{}\n", expected_remote_version()))
                .answer(&format!("{REMOTE_BINARY} setup"), 0, "")
        };
        let hosts = |shell: &FakeShell| {
            let mut hosts: Vec<String> = shell.calls.borrow().iter().map(|(host, _)| host.clone()).collect();
            hosts.dedup();
            hosts
        };
        let run = |servers: &[&str], all: bool, shell: &FakeShell| {
            let mut report = Report::default();
            let args = CheckArgs { servers: servers.iter().map(|name| (*name).to_owned()).collect(), all };
            check_with(&ctx, &args, shell, &mut report);
            report
        };

        let local = shell();
        let report = run(&[], false, &local);
        assert!(local.calls.borrow().is_empty(), "{:?}", local.calls.borrow());
        assert!(!report.lines.iter().any(|line| line.label.starts_with("server ")), "{}", report.text);

        let one = shell();
        let report = run(&["devbox"], false, &one);
        assert_eq!(hosts(&one), ["devbox"]);
        let devbox: Vec<&Line> = report.lines.iter().filter(|line| line.label == "server devbox").collect();
        assert_eq!(devbox.last().unwrap().detail, "skipped: the daemon is not running");
        assert!(!report.lines.iter().any(|line| line.label == "server buildserver"));

        let all = shell();
        run(&[], true, &all);
        assert_eq!(hosts(&all), ["buildserver", "devbox"]);

        let unknown = shell();
        let report = run(&["nope"], false, &unknown);
        let line = report.lines.iter().find(|line| line.label == "server nope").unwrap();
        assert_eq!(line.status, Status::Fail);
        assert!(line.detail.starts_with("no [server.nope] in "), "{}", line.detail);
        assert!(unknown.calls.borrow().is_empty());
    }

    /// A followed server without a known_hosts entry and a key of two servers both fail;
    /// the daemon would treat those hosts as unregistered.
    #[test]
    fn host_keys_must_belong_to_one_server() {
        let (dir, ctx) = context();
        let known_hosts = dir.path().join("known_hosts");
        std::fs::write(&known_hosts, format!("shared {}\n", test_key(1))).unwrap();
        let file = format!("known_hosts_files = [\"{}\"]\n", known_hosts.display());
        let text = format!(
            "{}\n[server.shared]\nknown_host = \"shared\"\n{file}profile = \"build\"\n\
             [server.missing]\nknown_host = \"missing\"\n{file}profile = \"build\"\n",
            config_text()
        );
        write_config(&ctx, &text);
        let mut report = Report::default();
        check_with(&ctx, &CheckArgs { servers: vec![], all: false }, &FakeShell::default(), &mut report);
        let lines: Vec<&Line> = report.lines.iter().filter(|line| line.label == "host keys").collect();
        assert_eq!(lines.len(), 2, "{}", report.text);
        assert!(lines.iter().all(|line| line.status == Status::Fail));
        assert!(
            lines[0].detail.starts_with("known_hosts lists no key for missing (server missing)"),
            "{}",
            lines[0].detail
        );
        assert!(
            lines[1].detail.ends_with(
                "belongs to servers buildserver and shared: each of them is treated as unregistered"
            ),
            "{}",
            lines[1].detail
        );

        write_config(&ctx, &config_text());
        let mut report = Report::default();
        check_with(&ctx, &CheckArgs { servers: vec![], all: false }, &FakeShell::default(), &mut report);
        let line = report.lines.iter().find(|line| line.label == "host keys").unwrap();
        assert_eq!(
            (line.status, line.detail.as_str()),
            (Status::Ok, "1 server(s), each with keys of its own")
        );
    }

    /// An unreadable known_hosts file is a warning of its own; a server it leaves
    /// without any readable file fails without the "connect once" hint, which would not
    /// help.
    #[test]
    fn unreadable_known_hosts_files_are_warned_about() {
        let (dir, ctx) = context();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        let empty = dir.path().join("empty");
        std::fs::write(&empty, "").unwrap();
        let text = format!(
            "{}\n[server.locked]\nknown_host = \"locked\"\nknown_hosts_files = [\"{locked}\"]\nprofile = \"build\"\n\
             [server.partly]\nknown_host = \"partly\"\nknown_hosts_files = [\"{locked}\", \"{empty}\"]\n\
             profile = \"build\"\n",
            config_text(),
            locked = locked.display(),
            empty = empty.display()
        );
        write_config(&ctx, &text);
        let mut report = Report::default();
        check_with(&ctx, &CheckArgs { servers: vec![], all: false }, &FakeShell::default(), &mut report);
        let file = report.lines.iter().find(|line| line.label == "known_hosts file").unwrap();
        assert_eq!(file.status, Status::Warn);
        assert_eq!(
            file.detail,
            format!(
                "cannot read {}: not a regular file; skipped (ssh and the daemon skip it too)",
                locked.display()
            )
        );
        assert_eq!(report.lines.iter().filter(|line| line.label == "known_hosts file").count(), 1);
        let lines: Vec<&Line> = report.lines.iter().filter(|line| line.label == "host keys").collect();
        assert_eq!(lines.len(), 2, "{}", report.text);
        assert!(lines[0].detail.starts_with("known_hosts lists no key for locked (server locked)"));
        assert_eq!(
            lines[0].hint.as_deref(),
            Some(
                format!("none of its known_hosts files can be read; make {} readable", locked.display())
                    .as_str()
            )
        );
        assert!(lines[1].detail.starts_with("known_hosts lists no key for partly (server partly)"));
        assert_eq!(lines[1].hint.as_deref(), Some("connect once with ssh partly and confirm the host key"));
    }

    #[test]
    fn remote_not_installed() {
        let (_dir, ctx) = context();
        write_config(&ctx, &config_text());
        let shell = FakeShell::default();
        let mut report = Report::default();
        check_with(&ctx, &CheckArgs { servers: vec![], all: true }, &shell, &mut report);
        let line = report.lines.iter().find(|line| line.label == "server buildserver").unwrap();
        assert_eq!(line.status, Status::Fail);
        assert_eq!(line.detail, "credential-bridge-remote is not installed");
    }

    #[test]
    fn unregistered_profile_is_shown_and_loosening_warned() {
        let config = Config::default();
        let line = unregistered_line(&config);
        assert_eq!((line.status, line.detail.as_str()), (Status::Ok, "no keys, no tokens, no gpg"));

        let (_dir, ctx) = context();
        let base = "version = 2\n[agent]\n[[agent.upstream]]\nname = \"fido\"\nsocket = \"/run/f.sock\"\n";
        let parse = |extra: &str| Config::parse(&format!("{base}{extra}"), &ctx.paths).unwrap();
        let line = unregistered_line(&parse(
            "[profile.unregistered]\nssh = { keys = [\"fido\"], confirm = \"8h\" }\n",
        ));
        assert_eq!(line.status, Status::Ok);
        assert_eq!(line.detail, "keys of fido, confirm = \"8h\", no tokens, no gpg");
        let line = unregistered_line(&parse("[profile.unregistered]\nssh = { keys = [\"fido\"] }\n"));
        assert_eq!(line.detail, "keys of fido, confirm = \"always\", no tokens, no gpg");
        let line = unregistered_line(&parse(
            "[profile.unregistered]\nssh = { keys = \"all\", confirm = \"never\" }\n",
        ));
        assert_eq!(line.status, Status::Warn);
        assert!(line.detail.contains("keys = \"all\" shows every key"), "{}", line.detail);
        assert!(line.detail.contains("confirm = \"never\" lets"), "{}", line.detail);
    }

    #[test]
    fn strangers_come_from_the_audit_log() {
        let log = [
            r#"{"event":"server","server":"buildserver","host_key":"SHA256:pinned","profile":"build","time":"2026-11-21T10:00:00Z"}"#,
            r#"{"event":"refused","server":"buildserver","reason":"proxy is locked","time":"2026-11-21T10:00:01Z"}"#,
            r#"{"event":"server","server":null,"host_key":"SHA256:other","profile":"unregistered","time":"2026-11-21T10:01:00Z"}"#,
            r#"{"event":"refused","server":"unregistered host SHA256:other","reason":"the host is not registered","time":"2026-11-21T10:01:01Z"}"#,
            r#"{"event":"refused","server":"unrecognised host (no session-bind)","reason":"no session-bind","time":"2026-11-21T10:02:00Z"}"#,
            r#"{"event":"sign","server":"local","key":"SHA256:k","outcome":"ok","time":"2026-11-21T10:03:00Z"}"#,
            "not json",
        ]
        .join("\n");
        let found = strangers(&log);
        assert_eq!(
            found,
            vec![
                Stranger {
                    label: "unrecognised host (no session-bind)".into(),
                    last: "2026-11-21T10:02:00Z".into(),
                    events: 1,
                    reason: Some("no session-bind".into()),
                },
                Stranger {
                    label: "unregistered host SHA256:other".into(),
                    last: "2026-11-21T10:01:01Z".into(),
                    events: 2,
                    reason: Some("the host is not registered".into()),
                },
            ]
        );

        let (_dir, ctx) = context();
        let config = Config::empty(&ctx.paths);
        std::fs::create_dir_all(config.daemon.audit_log.parent().unwrap()).unwrap();
        std::fs::write(&config.daemon.audit_log, &log).unwrap();
        let mut report = Report::default();
        check_strangers(&config.daemon.audit_log, &mut report);
        assert_eq!(report.lines.len(), 2);
        let unregistered = &report.lines[1];
        assert_eq!(unregistered.status, Status::Warn);
        assert!(
            unregistered.detail.starts_with("unregistered host SHA256:other: 2 event(s)"),
            "{}",
            unregistered.detail
        );
        assert_eq!(unregistered.hint.as_deref(), Some(SERVER_ADD_HINT));
        assert!(!report.failed(), "a warning, not a failure");

        let mut report = Report::default();
        check_strangers(&ctx.paths.home.join("missing.log"), &mut report);
        assert!(report.lines.is_empty());
    }

    /// A host key of several servers is named as such, with its later refusals, and
    /// gets the hint to keep the key under one server, not to add a server.
    #[test]
    fn ambiguous_hosts_are_not_unregistered_ones() {
        let log = [
            r#"{"event":"server","server":null,"host_key":"SHA256:both","profile":"unregistered","ambiguous":["a","b"],"time":"2026-11-21T10:00:00Z"}"#,
            r#"{"event":"refused","server":"unregistered host SHA256:both","reason":"the host is not registered","time":"2026-11-21T10:00:01Z"}"#,
            r#"{"event":"server","server":null,"host_key":"SHA256:new","profile":"unregistered","time":"2026-11-21T10:01:00Z"}"#,
        ]
        .join("\n");
        let found = strangers(&log);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[1].label, "host key SHA256:both belongs to several servers: a, b");
        assert_eq!(found[1].events, 2);
        assert_eq!(found[0].label, "unregistered host SHA256:new");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, &log).unwrap();
        let mut report = Report::default();
        check_strangers(&path, &mut report);
        let ambiguous = &report.lines[1];
        assert!(
            ambiguous.detail.starts_with("host key SHA256:both belongs to several servers: a, b: 2 event(s)"),
            "{}",
            ambiguous.detail
        );
        assert_eq!(ambiguous.hint.as_deref(), Some(AMBIGUOUS_HINT));
        assert_eq!(report.lines[0].hint.as_deref(), Some(SERVER_ADD_HINT));
    }

    /// Two servers following the same name in the same files: a warning, not a failure.
    #[test]
    fn configuration_warnings_are_shown() {
        let (_dir, ctx) = context();
        write_config(
            &ctx,
            "version = 2\n[profile.p]\n[server.a]\nknown_host = \"box\"\nprofile = \"p\"\n\
             [server.b]\nknown_host = \"box\"\nprofile = \"p\"\n",
        );
        let mut report = Report::default();
        assert!(check_config(&ctx, &mut report).is_some());
        let line = report.lines.iter().find(|line| line.status == Status::Warn).unwrap();
        assert!(
            line.detail.starts_with("server.b.known_host: server \"a\" follows \"box\""),
            "{}",
            line.detail
        );
        assert!(!report.failed());
    }

    /// With the daemon running, check reads the audit log it writes and names paths of
    /// `[daemon]` and `[vault]` that take effect only on a restart.
    #[test]
    fn uses_the_paths_of_the_running_daemon() {
        let (dir, ctx) = context();
        write_config(&ctx, "version = 2\n");
        let config = Config::empty(&ctx.paths);
        let elsewhere = dir.path().join("elsewhere.log");
        std::fs::write(
            &elsewhere,
            r#"{"event":"server","server":null,"host_key":"SHA256:new","profile":"unregistered","time":"t"}"#,
        )
        .unwrap();
        let status = DaemonStatus {
            version: VERSION.into(),
            pid: 1,
            config: ctx.config_path.display().to_string(),
            paths: credential_bridge_proto::ipc::control::DaemonPaths {
                socket: config.daemon.socket.display().to_string(),
                forward_socket: config.daemon.forward_socket.display().to_string(),
                control_socket: config.daemon.control_socket.display().to_string(),
                audit_log: elsewhere.display().to_string(),
                keepassxc_database: Some("/old/db.kdbx".into()),
                keepassxc_key_file: None,
            },
            locked: false,
            upstreams: vec![],
            workers: vec![],
            vaults: vec![],
        };
        crate::commands::test_support::fake_daemon(&config.daemon.control_socket, Response::Status(status));
        let mut report = Report::default();
        check_with(&ctx, &CheckArgs { servers: vec![], all: false }, &FakeShell::default(), &mut report);
        let vault =
            report.lines.iter().find(|line| line.detail.starts_with("uses [vault.keepassxc]")).unwrap();
        assert_eq!(
            (vault.status, vault.detail.as_str()),
            (Status::Warn, "uses [vault.keepassxc] database /old/db.kdbx (configured: none)")
        );
        let moved = report.lines.iter().find(|line| line.detail.starts_with("uses audit_log ")).unwrap();
        assert_eq!(moved.status, Status::Warn);
        assert!(
            moved.detail.ends_with(&format!("(configured: {})", config.daemon.audit_log.display())),
            "{}",
            moved.detail
        );
        assert!(
            report.lines.iter().any(|line| line.detail.starts_with("unregistered host SHA256:new")),
            "{}",
            report.text
        );
    }
}
