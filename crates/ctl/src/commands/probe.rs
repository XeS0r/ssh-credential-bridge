//! The probe of `server add` and `check NAME`: one real connection through the daemon,
//! judged by the daemon's audit log.
//!
//! ctl runs `ssh -o ForwardAgent=<forward socket> NAME credential-bridge-remote query`
//! (whatever the user's ssh config says about forwarding). The remote binary's agent
//! connection reaches the daemon through the forwarded channel; the daemon writes a
//! `connect` event naming the local ssh's process id, then `client` (whether that ssh is
//! a verified OpenSSH 8.9 or later) and `server` (what the host key selected) with the
//! same connection number. The verdict comes from those events only: towards an
//! unregistered host the bridge is hidden on purpose, so the output of `query` cannot
//! tell an unregistered host from a server without the bridge.

use std::path::Path;
use std::time::{Duration, Instant};

use credential_bridge_config::host_keys::{HostKeyMap, HostKeyWarning};
use credential_bridge_config::known_hosts::KnownHosts;
use credential_bridge_config::{Config, Server, ServerKeys};
use credential_bridge_platform::ssh_client::SESSION_BIND_SINCE;
use credential_bridge_proto::ipc::control::DaemonPaths;

use super::{daemon_paths, printable};
use crate::audit::{self, Event, Mark};
use crate::control::ControlError;
use crate::remote::{ProbeRun, RemoteShell};
use crate::report::Line;

/// The report label.
const LABEL: &str = "probe";

/// How long the probe waits for the daemon's events once ssh has finished (the daemon
/// writes the audit log on a thread of its own).
const AUDIT_WAIT: Duration = Duration::from_secs(3);

/// Probes `server` if the daemon runs: `⚠ probe skipped` if it does not. The probe
/// forwards the daemon's forward socket and reads the audit log it writes, as the daemon
/// reports them (a changed `[daemon]` takes effect only when it restarts).
pub(crate) fn probe(config: &Config, server: &Server, shell: &dyn RemoteShell) -> Line {
    match daemon_paths(&config.daemon) {
        Ok(paths) => probe_running(config, server, shell, &paths, AUDIT_WAIT),
        Err(ControlError::NotRunning(_)) => Line::warn(LABEL, "skipped: the daemon is not running")
            .with_hint(format!(
                "credential-bridge-ctl daemon start, then credential-bridge-ctl check {}",
                server.name
            )),
        Err(error) => Line::warn(LABEL, format!("skipped: {error}")),
    }
}

/// The probe against a running daemon that uses `paths`, waiting up to `wait` for its
/// events.
pub(crate) fn probe_running(
    config: &Config,
    server: &Server,
    shell: &dyn RemoteShell,
    paths: &DaemonPaths,
    wait: Duration,
) -> Line {
    let log = Path::new(&paths.audit_log);
    let mark = Mark::of(log);
    let run = match shell.probe(&server.name, Path::new(&paths.forward_socket)) {
        Ok(run) => run,
        Err(error) => return Line::fail(LABEL, format!("cannot run ssh {}: {error}", server.name)),
    };
    let deadline = Instant::now() + wait;
    loop {
        let events = mark.since(log).map(|text| audit::events(&text)).unwrap_or_default();
        let seen = Seen::find(&events, run.pid);
        if seen.complete() || Instant::now() >= deadline {
            return verdict(config, server, &seen, &run);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// What the audit log says about the probe's connections.
#[derive(Debug, Default, PartialEq, Eq)]
struct Seen {
    /// Whether a connection from the probe's ssh reached the forward socket.
    connected: bool,
    /// The `client` event: verified, and the description.
    client: Option<(bool, String)>,
    /// The `server` event.
    server: Option<Event>,
}

impl Seen {
    /// The events of the first connection on the forward socket whose peer is `pid`
    /// and that got a verdict (a `server` event, or a client that is not verified);
    /// else of the first such connection.
    fn find(events: &[Event], pid: Option<u32>) -> Seen {
        let Some(pid) = pid else { return Seen::default() };
        let prefix = format!("{pid} ");
        let connections: Vec<&serde_json::Value> = events
            .iter()
            .filter(|event| audit::text(event, "event") == Some("connect"))
            .filter(|event| audit::text(event, "socket") == Some("forward"))
            .filter(|event| audit::text(event, "peer").is_some_and(|peer| peer.starts_with(&prefix)))
            .filter_map(|event| event.get("connection"))
            .collect();
        let of = |number: &serde_json::Value| {
            let mut seen = Seen { connected: true, ..Seen::default() };
            for event in events.iter().filter(|event| event.get("connection") == Some(number)) {
                match audit::text(event, "event") {
                    Some("client") => {
                        let verified = event.get("server_recognition").and_then(serde_json::Value::as_bool);
                        let client = audit::text(event, "client").unwrap_or_default().to_owned();
                        seen.client = Some((verified.unwrap_or(false), client));
                    }
                    Some("server") => seen.server = Some(event.clone()),
                    _ => {}
                }
            }
            seen
        };
        let mut all = connections.into_iter().map(of);
        let Some(first) = all.next() else { return Seen::default() };
        if first.complete() {
            return first;
        }
        all.find(Seen::complete).unwrap_or(first)
    }

    /// Whether the daemon has decided about the connection.
    fn complete(&self) -> bool {
        self.server.is_some() || matches!(self.client, Some((false, _)))
    }
}

/// The report line for what was seen.
fn verdict(config: &Config, server: &Server, seen: &Seen, run: &ProbeRun) -> Line {
    let name = &server.name;
    let again = format!("credential-bridge-ctl server add {name} --profile {}", server.profile);
    if let Some((false, client)) = &seen.client {
        return Line::fail(
            LABEL,
            format!("the local ssh client is {}: no server is recognised behind it", printable(client)),
        )
        .with_hint(format!("OpenSSH {SESSION_BIND_SINCE} or later is needed to recognise servers"));
    }
    let Some(event) = &seen.server else {
        if seen.connected {
            return Line::fail(
                LABEL,
                "the daemon did not recognise the probe's connection (no valid session-bind first)",
            )
            .with_hint("credential-bridge-ctl log shows the connection");
        }
        let reason = if run.output.success() {
            "ssh ran, but no forwarded agent connection reached the daemon".to_owned()
        } else {
            format!(
                "no forwarded agent connection reached the daemon (ssh {name}: {})",
                printable(&run.output.failure_reason())
            )
        };
        return Line::fail(LABEL, reason)
            .with_hint(format!("agent forwarding must be allowed on {name} (sshd AllowAgentForwarding)"));
    };
    let host_key = audit::text(event, "host_key").unwrap_or("?");
    match audit::text(event, "server") {
        Some(found) if found == name => {
            let profile = audit::text(event, "profile").unwrap_or("none");
            Line::ok(LABEL, format!("the daemon recognises {name} (profile {})", printable(profile)))
        }
        Some(other) => Line::fail(
            LABEL,
            format!("the daemon took the host key {host_key} for server {}, not {name}", printable(other)),
        )
        .with_hint("one host key, one server: remove the other entry or fix its known_host"),
        None => {
            let ambiguous: Vec<&str> = event
                .get("ambiguous")
                .and_then(serde_json::Value::as_array)
                .map(|names| names.iter().filter_map(serde_json::Value::as_str).collect())
                .unwrap_or_default();
            if !ambiguous.is_empty() {
                return Line::fail(
                    LABEL,
                    format!(
                        "host key {host_key} belongs to servers {}, so the daemon treats {name} as unregistered",
                        printable(&ambiguous.join(" and "))
                    ),
                )
                .with_hint("keep the key under one server: remove the other entry, or fix known_hosts");
            }
            let (keys, hint) = match &server.keys {
                ServerKeys::KnownHost(known) => (
                    followed_text(config, server, &known.name),
                    format!(
                        "ssh must store the server's key under {} in known_hosts (ssh {name}, confirm the host \
                         key), or run {again}",
                        known.name
                    ),
                ),
                ServerKeys::Pinned(keys) => (
                    format!("pinned: {}", describe(keys)),
                    format!("the server's host key changed? check it, then run {again}"),
                ),
            };
            Line::fail(
                LABEL,
                format!("the daemon treats {name} as unregistered: host key {host_key} is not among its keys ({keys})"),
            )
            .with_hint(hint)
        }
    }
}

/// `known_hosts NAME: <keys>`, read like the daemon reads them, with the server's files
/// that cannot be read.
fn followed_text(config: &Config, server: &Server, lookup: &str) -> String {
    let read = HostKeys::read(config);
    let mut text = format!("known_hosts {lookup}: {}", describe(read.map.followed(&server.name)));
    for (path, error) in read.unreadable(config, &server.name) {
        text.push_str(&format!("; cannot read {}: {error}", path.display()));
    }
    text
}

/// The daemon's host key map, built from the known_hosts files as they are now, and what
/// is wrong with it.
pub(crate) struct HostKeys {
    /// The map.
    pub map: HostKeyMap,
    /// Unreadable files, followed servers without keys, keys of several servers.
    pub warnings: Vec<HostKeyWarning>,
}

impl HostKeys {
    /// Reads the files of `config` like the daemon reads them.
    pub fn read(config: &Config) -> HostKeys {
        let (map, warnings) = HostKeyMap::build_reporting(config, KnownHosts::read);
        HostKeys { map, warnings }
    }

    /// The known_hosts files of server `name` (in `config`) that cannot be read, with
    /// why.
    pub fn unreadable<'a>(&'a self, config: &Config, name: &str) -> Vec<(&'a Path, &'a str)> {
        self.warnings
            .iter()
            .filter(|warning| warning.concerns(config, name))
            .filter_map(|warning| match warning {
                HostKeyWarning::Unreadable { path, error } => Some((path.as_path(), error.as_str())),
                _ => None,
            })
            .collect()
    }
}

/// How ctl reports a known_hosts file it cannot read.
pub(crate) fn unreadable_text(path: &Path, error: &str) -> String {
    format!("cannot read {}: {error}; skipped (ssh and the daemon skip it too)", path.display())
}

/// `ssh-ed25519 SHA256:…, ssh-rsa SHA256:…`, or `none`.
fn describe(keys: &[ssh_key::PublicKey]) -> String {
    if keys.is_empty() {
        return "none".to_owned();
    }
    keys.iter().map(super::server::fingerprint).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::commands::test_support::{FakeShell, context, test_key, write_config};
    use crate::commands::{Context, load_config};
    use crate::report::Status;

    /// A configuration with `box` following known_hosts and `pinned` with a pinned key.
    fn setup() -> (tempfile::TempDir, Context, Config) {
        let (dir, ctx) = context();
        let known_hosts = dir.path().join("known_hosts");
        std::fs::write(&known_hosts, format!("box {}\n", test_key(1))).unwrap();
        write_config(
            &ctx,
            &format!(
                "version = 2\n[profile.dev]\n[server.box]\nknown_host = \"box\"\nknown_hosts_files = [\"{}\"]\n\
                 profile = \"dev\"\n[server.pinned]\nhost_keys = [\"{}\"]\nprofile = \"dev\"\n",
                known_hosts.display(),
                test_key(2)
            ),
        );
        let config = load_config(&ctx).unwrap();
        std::fs::create_dir_all(config.daemon.audit_log.parent().unwrap()).unwrap();
        std::fs::write(
            &config.daemon.audit_log,
            "{\"event\":\"connect\",\"connection\":1,\"socket\":\"forward\",\"peer\":\"4242 ssh\"}\n",
        )
        .unwrap();
        (dir, ctx, config)
    }

    /// A shell whose probe makes "the daemon" append `events` (with the connection's
    /// peer `4242 ssh`).
    fn shell(config: &Config, events: &[&str]) -> FakeShell {
        let mut lines = vec![
            r#"{"event":"connect","connection":9,"socket":"forward","peer":"4242 ssh","time":"t"}"#
                .to_owned(),
        ];
        lines.extend(events.iter().map(|event| event.replace("{n}", "9")));
        FakeShell {
            probe_events: RefCell::new(Some((config.daemon.audit_log.clone(), lines))),
            probe_pid: Some(4242),
            ..FakeShell::default()
        }
    }

    /// The paths of a daemon that uses the configured ones.
    fn paths(config: &Config) -> DaemonPaths {
        DaemonPaths {
            forward_socket: config.daemon.forward_socket.display().to_string(),
            audit_log: config.daemon.audit_log.display().to_string(),
            ..DaemonPaths::default()
        }
    }

    fn probe_line(config: &Config, server: &str, events: &[&str]) -> Line {
        let shell = shell(config, events);
        let line = probe_running(
            config,
            &config.servers[server],
            &shell,
            &paths(config),
            Duration::from_millis(200),
        );
        assert_eq!(shell.commands(), [format!("probe {}", config.daemon.forward_socket.display())]);
        line
    }

    const VERIFIED: &str =
        r#"{"event":"client","connection":{n},"client":"OpenSSH 10.2","server_recognition":true}"#;

    #[test]
    fn recognised() {
        let (_dir, _ctx, config) = setup();
        let server = r#"{"event":"server","connection":{n},"server":"box","host_key":"SHA256:x","profile":"dev","source":"known_hosts"}"#;
        let line = probe_line(&config, "box", &[VERIFIED, server]);
        assert_eq!(
            (line.status, line.detail.as_str()),
            (Status::Ok, "the daemon recognises box (profile dev)")
        );
    }

    #[test]
    fn unregistered_names_the_host_key_and_the_known_keys() {
        let (_dir, _ctx, config) = setup();
        let event = r#"{"event":"server","connection":{n},"server":null,"host_key":"SHA256:used","profile":"unregistered"}"#;
        let line = probe_line(&config, "box", &[VERIFIED, event]);
        assert_eq!(line.status, Status::Fail);
        assert!(line.detail.starts_with("the daemon treats box as unregistered: host key SHA256:used is not among its keys (known_hosts box: ssh-ed25519 SHA256:"), "{}", line.detail);
        assert!(line.hint.as_deref().unwrap().contains("under box in known_hosts"), "{line:?}");

        let line = probe_line(&config, "pinned", &[VERIFIED, event]);
        assert!(line.detail.contains("(pinned: ssh-ed25519 SHA256:"), "{}", line.detail);
        assert!(line.hint.as_deref().unwrap().contains("server add pinned --profile dev"), "{line:?}");
    }

    /// A known_hosts file that cannot be read is named with the keys the daemon has.
    #[test]
    fn unregistered_names_unreadable_files() {
        let (dir, ctx, _config) = setup();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        write_config(
            &ctx,
            &format!(
                "version = 2\n[profile.dev]\n[server.box]\nknown_host = \"box\"\nknown_hosts_files = [\"{}\"]\n\
                 profile = \"dev\"\n",
                locked.display()
            ),
        );
        let config = load_config(&ctx).unwrap();
        let event = r#"{"event":"server","connection":{n},"server":null,"host_key":"SHA256:used","profile":"unregistered"}"#;
        let line = probe_line(&config, "box", &[VERIFIED, event]);
        assert!(
            line.detail.ends_with(&format!(
                "(known_hosts box: none; cannot read {}: not a regular file)",
                locked.display()
            )),
            "{}",
            line.detail
        );
    }

    #[test]
    fn ambiguous_and_other_servers() {
        let (_dir, _ctx, config) = setup();
        let event = r#"{"event":"server","connection":{n},"server":null,"host_key":"SHA256:k","profile":"unregistered","ambiguous":["box","pinned"]}"#;
        let line = probe_line(&config, "box", &[VERIFIED, event]);
        assert_eq!(line.status, Status::Fail);
        assert!(line.detail.contains("belongs to servers box and pinned"), "{}", line.detail);
        let event =
            r#"{"event":"server","connection":{n},"server":"pinned","host_key":"SHA256:k","profile":"dev"}"#;
        let line = probe_line(&config, "box", &[VERIFIED, event]);
        assert!(line.detail.contains("for server pinned, not box"), "{}", line.detail);
    }

    #[test]
    fn unverified_client() {
        let (_dir, _ctx, config) = setup();
        let event = r#"{"event":"client","connection":{n},"client":"not verified as OpenSSH 8.9 or later: OpenSSH 8.8 sends no session-bind","server_recognition":false}"#;
        let line = probe_line(&config, "box", &[event]);
        assert_eq!(line.status, Status::Fail);
        assert!(line.detail.contains("OpenSSH 8.8 sends no session-bind"), "{}", line.detail);
        assert_eq!(line.hint.as_deref(), Some("OpenSSH 8.9 or later is needed to recognise servers"));
    }

    #[test]
    fn no_connection_and_events_of_others() {
        let (_dir, _ctx, config) = setup();
        // Another ssh's connection does not count; the old line before the mark neither.
        let mut shell = shell(&config, &[]);
        shell.probe_pid = Some(1);
        shell.probe_output = crate::remote::RemoteOutput {
            status: Some(255),
            stdout: String::new(),
            stderr: "Connection refused\n".into(),
        };
        let line = probe_running(
            &config,
            &config.servers["box"],
            &shell,
            &paths(&config),
            Duration::from_millis(100),
        );
        assert_eq!(line.status, Status::Fail);
        assert_eq!(
            line.detail,
            "no forwarded agent connection reached the daemon (ssh box: Connection refused)"
        );
    }

    /// The probe forwards the socket and reads the audit log the running daemon names,
    /// not the configured ones (`[daemon]` changed without a restart).
    #[test]
    fn follows_the_paths_of_the_running_daemon() {
        let (dir, _ctx, config) = setup();
        let elsewhere = dir.path().join("elsewhere.log");
        std::fs::write(&elsewhere, "").unwrap();
        let paths = DaemonPaths {
            forward_socket: "/run/forward.sock".into(),
            audit_log: elsewhere.display().to_string(),
            ..DaemonPaths::default()
        };
        let pong = credential_bridge_proto::ipc::control::Response::Pong {
            version: crate::commands::VERSION.into(),
            paths,
        };
        crate::commands::test_support::fake_daemon(&config.daemon.control_socket, pong);
        let server =
            r#"{"event":"server","connection":{n},"server":"box","host_key":"SHA256:x","profile":"dev"}"#;
        let shell = shell(&config, &[VERIFIED, server]);
        shell.probe_events.borrow_mut().as_mut().unwrap().0 = elsewhere;
        let line = probe(&config, &config.servers["box"], &shell);
        assert_eq!(
            (line.status, line.detail.as_str()),
            (Status::Ok, "the daemon recognises box (profile dev)")
        );
        assert_eq!(shell.commands(), ["probe /run/forward.sock"]);
    }

    #[test]
    fn daemon_down_skips() {
        let (_dir, _ctx, config) = setup();
        let shell = FakeShell::default();
        let line = probe(&config, &config.servers["box"], &shell);
        assert_eq!((line.status, line.detail.as_str()), (Status::Warn, "skipped: the daemon is not running"));
        assert!(shell.commands().is_empty());
    }

    #[test]
    fn picks_the_connection_with_a_verdict() {
        let connect = |n: u64, pid: u32| {
            audit::events(&format!(
                r#"{{"event":"connect","connection":{n},"socket":"forward","peer":"{pid} ssh"}}"#
            ))
        };
        let mut events = connect(1, 7);
        events.extend(connect(2, 8));
        events.extend(connect(3, 7));
        events.extend(audit::events(
            r#"{"event":"server","connection":3,"server":"box","host_key":"SHA256:k"}"#,
        ));
        let seen = Seen::find(&events, Some(7));
        assert!(seen.complete() && seen.connected);
        assert_eq!(seen.server.as_ref().and_then(|event| audit::text(event, "server")), Some("box"));
        assert!(!Seen::find(&events, Some(8)).complete());
        assert!(Seen::find(&events, Some(8)).connected);
        assert_eq!(Seen::find(&events, Some(9)), Seen::default());
        assert_eq!(Seen::find(&events, None), Seen::default());
    }
}
