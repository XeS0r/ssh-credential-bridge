//! `agent add|list|set|remove`: the upstream agents behind the proxy.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::bail;
use credential_bridge_config::{Config, SocketSpec};
use credential_bridge_proto::agent::AgentClient;
use credential_bridge_proto::ipc::control::{DaemonStatus, Request, Response};

use super::change::{apply, socket_value, tilde};
use super::{CONTROL_TIMEOUT, Context, connect, load_config, printable};
use crate::cli::{AgentAddArgs, AgentCommand, AgentSetArgs, NameWriteArgs};
use crate::control::ControlError;
use crate::report::{Line, Report};

/// How long `agent list` waits for an agent when it asks the socket itself.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(2);

/// Runs an `agent` subcommand.
pub fn agent(ctx: &Context, command: &AgentCommand, report: &mut Report) -> anyhow::Result<()> {
    match command {
        AgentCommand::Add(args) => agent_add(ctx, args, report),
        AgentCommand::List => agent_list(ctx, report),
        AgentCommand::Set(args) => agent_set(ctx, args, report),
        AgentCommand::Remove(args) => agent_remove(ctx, args, report),
    }
}

/// `agent add NAME SOCKET [--add-to]`.
fn agent_add(ctx: &Context, args: &AgentAddArgs, report: &mut Report) -> anyhow::Result<()> {
    let socket = socket_value(&args.socket)?;
    let summary = format!("[[agent.upstream]] {} added", args.name);
    apply(ctx, args.write.dry_run, report, &summary, |doc| {
        doc.add_upstream(&args.name, &socket)?;
        if args.add_to {
            doc.set_add_to(Some(&args.name))?;
        }
        Ok(())
    })?;
    Ok(())
}

/// `agent set [NAME --socket S] [--add-to NAME | --no-add-to]`.
fn agent_set(ctx: &Context, args: &AgentSetArgs, report: &mut Report) -> anyhow::Result<()> {
    if args.socket.is_none() && args.add_to.is_none() && !args.no_add_to {
        bail!("nothing to set: give NAME --socket SOCKET, --add-to NAME or --no-add-to");
    }
    let socket = args.socket.as_deref().map(socket_value).transpose()?;
    let mut changes = Vec::new();
    if let (Some(name), Some(_)) = (&args.name, &socket) {
        changes.push(format!("socket of {name}"));
    }
    if let Some(add_to) = &args.add_to {
        changes.push(format!("add_to = {add_to}"));
    }
    if args.no_add_to {
        changes.push("add_to removed".to_owned());
    }
    apply(ctx, args.write.dry_run, report, &format!("[agent] {}", changes.join(", ")), |doc| {
        if let (Some(name), Some(socket)) = (&args.name, &socket) {
            doc.set_upstream_socket(name, socket)?;
        }
        if let Some(add_to) = &args.add_to {
            doc.set_add_to(Some(add_to))?;
        }
        if args.no_add_to {
            doc.set_add_to(None)?;
        }
        Ok(())
    })?;
    Ok(())
}

/// `agent remove NAME`.
fn agent_remove(ctx: &Context, args: &NameWriteArgs, report: &mut Report) -> anyhow::Result<()> {
    let summary = format!("[[agent.upstream]] {} removed", args.name);
    apply(ctx, args.write.dry_run, report, &summary, |doc| doc.remove_upstream(&args.name))?;
    Ok(())
}

/// One row of `agent list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentRow {
    /// The upstream name.
    pub name: String,
    /// The socket as configured (`~/…`, `gpgconf:…`).
    pub socket: String,
    /// Keys listed, if it answered.
    pub keys: Option<usize>,
    /// `ok`, or why it does not answer.
    pub status: String,
    /// Whether it is `agent.add_to`.
    pub add_to: bool,
}

/// `agent list`: every upstream with its socket, key count and status, from the daemon
/// if it runs, else by asking each socket directly.
fn agent_list(ctx: &Context, report: &mut Report) -> anyhow::Result<()> {
    let config = load_config(ctx)?;
    let status = daemon_status(&config);
    let rows = agent_rows(ctx, &config, status.as_ref());
    report.show(&agent_table(&rows));
    if config.agent.is_some() {
        match status {
            Ok(_) => {}
            Err(ControlError::NotRunning(_)) => report.push(
                Line::warn("daemon", "not running; asked the agent sockets directly")
                    .with_hint("credential-bridge-ctl daemon start"),
            ),
            Err(error) => report
                .push(Line::warn("daemon", format!("no status ({error}); asked the agent sockets directly"))),
        }
    }
    Ok(())
}

/// The daemon's status, with the upstreams it reaches.
fn daemon_status(config: &Config) -> Result<DaemonStatus, ControlError> {
    let mut client = connect(&config.daemon, CONTROL_TIMEOUT)?;
    match client.request(&Request::Status)? {
        Response::Status(status) => Ok(status),
        _ => Err(ControlError::Unexpected),
    }
}

/// The rows of `agent list`; upstreams the daemon did not report are asked directly.
pub(crate) fn agent_rows(
    ctx: &Context,
    config: &Config,
    status: Result<&DaemonStatus, &ControlError>,
) -> Vec<AgentRow> {
    let Some(agent) = &config.agent else { return Vec::new() };
    agent
        .upstreams
        .iter()
        .map(|upstream| {
            let socket = match &upstream.socket {
                SocketSpec::Path(path) => tilde(&ctx.paths, path),
                SocketSpec::Gpgconf(name) => format!("gpgconf:{name}"),
            };
            let from_daemon =
                status.ok().and_then(|status| status.upstreams.iter().find(|up| up.name == upstream.name));
            let (keys, status) = match from_daemon {
                Some(up) if up.reachable => (up.keys, "ok".to_owned()),
                Some(up) => (None, printable(up.error.as_deref().unwrap_or("not reachable"))),
                None => match resolve(&upstream.socket) {
                    Ok(path) => count_keys(&path),
                    Err(why) => (None, why),
                },
            };
            AgentRow {
                name: upstream.name.clone(),
                socket,
                keys,
                status,
                add_to: agent.add_to.as_deref() == Some(upstream.name.as_str()),
            }
        })
        .collect()
}

/// The path of a socket; `gpgconf:` names are asked from gpgconf.
fn resolve(socket: &SocketSpec) -> Result<std::path::PathBuf, String> {
    match socket {
        SocketSpec::Path(path) => Ok(path.clone()),
        SocketSpec::Gpgconf(name) => {
            super::check::gpgconf_dir(name).ok_or_else(|| format!("gpgconf --list-dirs {name} failed"))
        }
    }
}

/// Asks an agent socket for its keys.
fn count_keys(path: &Path) -> (Option<usize>, String) {
    let stream = match UnixStream::connect(path) {
        Ok(stream) => stream,
        Err(error) => return (None, format!("cannot connect: {error}")),
    };
    let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
    let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));
    match AgentClient::new(stream).identities() {
        Ok(identities) => (Some(identities.len()), "ok".to_owned()),
        Err(error) => (None, format!("no answer: {error}")),
    }
}

/// The table `agent list` prints.
pub(crate) fn agent_table(rows: &[AgentRow]) -> String {
    if rows.is_empty() {
        return "no upstream agents: the proxy only hands out tokens; add one with\n  \
                credential-bridge-ctl agent add NAME SOCKET\n"
            .to_owned();
    }
    let names: Vec<String> = rows
        .iter()
        .map(|row| if row.add_to { format!("{} (add_to)", row.name) } else { row.name.clone() })
        .collect();
    let name_width = names.iter().map(String::len).max().unwrap_or(0).max(8);
    let socket_width = rows.iter().map(|row| row.socket.chars().count()).max().unwrap_or(0).max(6);
    let mut out = format!("{:<name_width$}  {:<socket_width$}  KEYS  STATUS\n", "UPSTREAM", "SOCKET");
    for (row, name) in rows.iter().zip(&names) {
        let keys = row.keys.map_or("-".to_owned(), |keys| keys.to_string());
        out.push_str(&format!(
            "{name:<name_width$}  {:<socket_width$}  {keys:<4}  {}\n",
            row.socket, row.status
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::WriteArgs;
    use crate::commands::test_support::{context, write_config};

    const TEXT: &str = "version = 2\n\n# my agents\n[agent]\nadd_to = \"main\"   # ssh-add\n\n\
                        [[agent.upstream]]\nname = \"main\"\nsocket = \"~/agents/main.sock\"\n\n\
                        [profile.dev]\nssh = { keys = [\"main\"] }\n";

    fn run(ctx: &Context, command: AgentCommand) -> anyhow::Result<Report> {
        let mut report = Report::default();
        agent(ctx, &command, &mut report).map(|()| report)
    }

    fn add(name: &str, socket: &str, add_to: bool, dry_run: bool) -> AgentCommand {
        AgentCommand::Add(AgentAddArgs {
            name: name.into(),
            socket: socket.into(),
            add_to,
            write: WriteArgs { dry_run },
        })
    }

    #[test]
    fn add_set_remove_keep_comments() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        run(&ctx, add("sk", "/run/sk.sock", true, false)).unwrap();
        let text = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(text.contains("# my agents\n[agent]\nadd_to = \"sk\"   # ssh-add\n"), "{text}");
        assert!(text.contains("[[agent.upstream]]\nname = \"sk\"\nsocket = \"/run/sk.sock\"\n"), "{text}");

        let set = AgentSetArgs {
            name: Some("sk".into()),
            socket: Some("gpgconf:agent-ssh-socket".into()),
            add_to: Some("main".into()),
            no_add_to: false,
            write: WriteArgs::default(),
        };
        run(&ctx, AgentCommand::Set(set)).unwrap();
        let text = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(text.contains("socket = \"gpgconf:agent-ssh-socket\""), "{text}");
        assert!(text.contains("add_to = \"main\"   # ssh-add"), "{text}");

        let remove = |name: &str| {
            AgentCommand::Remove(NameWriteArgs { name: name.into(), write: WriteArgs::default() })
        };
        run(&ctx, remove("sk")).unwrap();
        // main is add_to and shown by profile dev: refused, with the fixes.
        let message = format!("{:#}", run(&ctx, remove("main")).unwrap_err());
        assert!(message.contains("agent.add_to, profile.dev.ssh.keys"), "{message}");
        assert!(message.contains("credential-bridge-ctl profile set dev ssh.keys=none"), "{message}");
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), TEXT);
    }

    #[test]
    fn dry_run_and_errors_write_nothing() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let report = run(&ctx, add("sk", "/run/sk.sock", false, true)).unwrap();
        assert!(report.text.contains("+[[agent.upstream]]\n+name = \"sk\"\n"), "{}", report.text);
        assert!(
            run(&ctx, add("main", "/x", false, false)).unwrap_err().to_string().contains("already exists")
        );
        // A relative socket path is made absolute; a bad gpgconf name fails validation.
        let message = format!("{:#}", run(&ctx, add("g", "gpgconf:Nope", false, false)).unwrap_err());
        assert!(message.contains("not a gpgconf socket name"), "{message}");
        assert!(
            run(
                &ctx,
                AgentCommand::Set(AgentSetArgs {
                    name: None,
                    socket: None,
                    add_to: None,
                    no_add_to: false,
                    write: WriteArgs::default()
                })
            )
            .is_err()
        );
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), TEXT);
    }

    #[test]
    fn list_asks_the_sockets_without_daemon() {
        let (dir, ctx) = context();
        let socket = dir.path().join("agent.sock");
        let _agent = empty_agent(&socket);
        write_config(
            &ctx,
            &format!(
                "version = 2\n[agent]\nadd_to = \"live\"\n[[agent.upstream]]\nname = \"live\"\nsocket = \"{}\"\n\
                 [[agent.upstream]]\nname = \"gone\"\nsocket = \"~/gone.sock\"\n",
                socket.display()
            ),
        );
        let report = run(&ctx, AgentCommand::List).unwrap();
        let text = &report.text;
        assert!(text.contains("live (add_to)  ~/agent.sock"), "{text}");
        assert!(text.lines().nth(1).unwrap().ends_with("0     ok"), "{text}");
        assert!(text.contains("gone           ~/gone.sock   -     cannot connect"), "{text}");
        assert!(
            text.contains("⚠ daemon               not running; asked the agent sockets directly"),
            "{text}"
        );
    }

    /// A minimal agent on `path` that answers every request with an empty key list.
    fn empty_agent(path: &Path) -> std::thread::JoinHandle<()> {
        use std::io::{Read as _, Write as _};
        let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut len = [0u8; 4];
                if stream.read_exact(&mut len).is_err() {
                    continue;
                }
                let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
                let _ = stream.read_exact(&mut body);
                // SSH_AGENT_IDENTITIES_ANSWER (12) with zero keys.
                let _ = stream.write_all(&[0, 0, 0, 5, 12, 0, 0, 0, 0]);
            }
        })
    }

    #[test]
    fn table_marks_add_to() {
        let rows = vec![AgentRow {
            name: "a".into(),
            socket: "~/a.sock".into(),
            keys: Some(2),
            status: "ok".into(),
            add_to: true,
        }];
        assert_eq!(
            agent_table(&rows),
            "UPSTREAM    SOCKET    KEYS  STATUS\na (add_to)  ~/a.sock  2     ok\n"
        );
        assert!(agent_table(&[]).contains("agent add NAME SOCKET"));
    }
}
