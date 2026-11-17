//! `remote …` and `test` commands.

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, bail};
use credential_bridge_core::config::{Config, RemoteConfig, validate_name};
use credential_bridge_core::paths::{self, HELPER_BINARY};
use credential_bridge_core::policy::UrlPattern;
use credential_bridge_proto::client::exchange;
use credential_bridge_proto::{Credential, Operation, Request, Status};

use crate::ssh::Ssh;
use crate::ui::{self, Level};
use crate::util::{sh_quote, socket_state};
use crate::{AddArgs, Ctx, EditArgs, InstallArgs, RemoteCommand, TestArgs, service};

/// Environment variable naming a directory with prebuilt helpers
/// (`git-credential-bridge-<arch>-<os>`); set by the Nix package.
const HELPER_DIR_ENV: &str = "CREDENTIAL_BRIDGE_HELPER_DIR";

pub fn run(ctx: &Ctx, cmd: RemoteCommand) -> anyhow::Result<()> {
    match cmd {
        RemoteCommand::Add(args) => add(ctx, args),
        RemoteCommand::Remove { name } => remove(ctx, &name),
        RemoteCommand::List => list(ctx),
        RemoteCommand::Show { name } => show(ctx, &name),
        RemoteCommand::SshConfig { name } => {
            let config = ctx.load()?;
            let remote = find(&config, &name)?;
            print_ssh_config(&config, remote)
        }
        RemoteCommand::Edit(args) => edit(ctx, args),
        RemoteCommand::Install(args) => install(ctx, &args),
        RemoteCommand::Check { name } => check(ctx, &name),
        RemoteCommand::Uninstall { name, dry_run } => uninstall(ctx, &name, dry_run),
    }
}

fn find<'a>(config: &'a Config, name: &str) -> anyhow::Result<&'a RemoteConfig> {
    config
        .remote(name)
        .with_context(|| format!("no remote named '{name}' (see `credential-bridge-ctl remote list`)"))
}

fn add(ctx: &Ctx, args: AddArgs) -> anyhow::Result<()> {
    validate_name(&args.name)?;
    for pattern in &args.allow {
        pattern.parse::<UrlPattern>()?;
    }
    let operations = if args.operations.is_empty() { vec!["get".to_owned()] } else { args.operations };
    let remote = RemoteConfig {
        name: args.name,
        ssh_host: args.ssh_host,
        remote_socket: args.remote_socket,
        allow: args.allow,
        operations,
        backend: args.backend,
    };
    let mut doc = ctx.document()?;
    doc.add_remote(&remote)?;
    doc.save()?;
    println!("added remote '{}' to {}", remote.name, doc.path().display());
    service::reload_if_active(ctx);
    println!();
    println!("next steps:");
    println!(
        "  credential-bridge-ctl remote install {}     # helper + git config on the remote",
        remote.name
    );
    println!("  credential-bridge-ctl remote ssh-config {}  # lines for ~/.ssh/config", remote.name);
    Ok(())
}

fn remove(ctx: &Ctx, name: &str) -> anyhow::Result<()> {
    let mut doc = ctx.document()?;
    if !doc.remove_remote(name)? {
        bail!("no remote named '{name}'");
    }
    doc.save()?;
    println!("removed remote '{name}' from {}", doc.path().display());
    println!("note: the helper stays on the remote; `remote uninstall` removes it (run it before `remove`)");
    println!("note: remove the RemoteForward line for this remote from ~/.ssh/config");
    service::reload_if_active(ctx);
    Ok(())
}

fn edit(ctx: &Ctx, args: EditArgs) -> anyhow::Result<()> {
    let config = ctx.load()?;
    let before = find(&config, &args.name)?.clone();

    let mut allow = before.allow.clone();
    for pattern in &args.add_allow {
        pattern.parse::<UrlPattern>()?;
        if !allow.contains(pattern) {
            allow.push(pattern.clone());
        }
    }
    for pattern in &args.remove_allow {
        if !allow.contains(pattern) {
            bail!("'{pattern}' is not in the allow list of '{}': {}", args.name, before.allow.join(", "));
        }
        allow.retain(|p| p != pattern);
    }
    if allow.is_empty() {
        bail!("the allow list of '{}' must not become empty", args.name);
    }

    let mut doc = ctx.document()?;
    let name = &args.name;
    if allow != before.allow {
        doc.set_remote_list(name, "allow", &allow)?;
    }
    if !args.operations.is_empty() {
        doc.set_remote_list(name, "operations", &args.operations)?;
    }
    if let Some(host) = &args.ssh_host {
        doc.set_remote_value(name, "ssh_host", host)?;
        // The recorded socket path lives in the old host's home; the new
        // one is only known after `remote install` has probed it.
        if host != before.ssh_target() {
            doc.remove_remote_value(name, "remote_socket")?;
        }
    }
    if let Some(backend) = &args.backend {
        doc.set_remote_value(name, "backend", backend)?;
    }
    if args.default_backend {
        doc.remove_remote_value(name, "backend")?;
    }
    doc.save()?;

    let config = ctx.load()?;
    let after = find(&config, name)?;
    println!("updated remote '{name}' in {}", doc.path().display());
    print_remote(&config, after)?;
    service::reload_if_active(ctx);

    if after.remote_socket.is_some() && origins(after)? != origins(&before)? {
        println!();
        println!("note: the remote's git configuration covers other hosts now; update it with:");
        println!("  credential-bridge-ctl remote install {name}");
    }
    if after.ssh_target() != before.ssh_target() {
        println!("note: the ssh destination changed; set it up there with:");
        println!("  credential-bridge-ctl remote install {name}");
        println!("  credential-bridge-ctl remote ssh-config {name}   # the RemoteForward for the new host");
    }
    Ok(())
}

fn list(ctx: &Ctx) -> anyhow::Result<()> {
    let config = ctx.load()?;
    if config.remotes.is_empty() {
        println!("no remotes configured");
        println!("{}", ui::fix(2, "credential-bridge-ctl remote add NAME --allow https://github.com/ORG/*"));
        return Ok(());
    }
    let name_width = config.remotes.iter().map(|r| r.name.chars().count()).max().unwrap_or(0);
    let dest_width = config.remotes.iter().map(|r| r.ssh_target().chars().count() + 2).max().unwrap_or(0);
    for remote in &config.remotes {
        let listening = matches!(
            config.socket_path(&remote.name).map(|s| socket_state(&s)),
            Ok(crate::util::SocketState::Listening)
        );
        let forward = forward_status(&config, remote).is_ok_and(|s| s == ForwardStatus::Configured);
        let installed = remote.remote_socket.is_some();
        let ready = listening && forward && installed;
        let level = if ready {
            Level::Ok
        } else if listening {
            Level::Warn
        } else {
            Level::Fail
        };
        let allow: Vec<&str> = remote.allow.iter().map(|a| ui::short_url(a)).collect();
        let state = if ready {
            String::new()
        } else {
            format!("   {} {}", ui::red("not ready"), ui::dim("(doctor)"))
        };
        println!(
            "{} {}  {}  {}{state}",
            level.dot(),
            ui::pad(&remote.name, name_width),
            ui::dim(&ui::pad(&format!("→ {}", remote.ssh_target()), dest_width)),
            allow.join(", ")
        );
    }
    Ok(())
}

fn show(ctx: &Ctx, name: &str) -> anyhow::Result<()> {
    let config = ctx.load()?;
    print_remote(&config, find(&config, name)?)
}

fn print_remote(config: &Config, remote: &RemoteConfig) -> anyhow::Result<()> {
    let name = &remote.name;
    let socket = config.socket_path(name)?;
    println!("remote {name}");
    println!("  ssh destination: {}", remote.ssh_target());
    println!("  allow:           {}", remote.allow.join(", "));
    println!("  operations:      {}", remote.operations.join(", "));
    println!("  backend:         {}", remote.backend.as_deref().unwrap_or(&config.backend));
    println!("  local socket:    {} ({})", socket.display(), socket_state(&socket));
    match &remote.remote_socket {
        Some(path) => println!("  remote socket:   {path}"),
        None => println!("  remote socket:   unknown (run `credential-bridge-ctl remote install {name}`)"),
    }
    Ok(())
}

/// Quotes a path for ssh_config if needed.
fn ssh_config_quote(path: &str) -> String {
    if path.contains(char::is_whitespace) { format!("\"{path}\"") } else { path.to_owned() }
}

fn print_ssh_config(config: &Config, remote: &RemoteConfig) -> anyhow::Result<()> {
    let local = config.socket_path(&remote.name)?;
    let remote_socket = match &remote.remote_socket {
        Some(path) => path.clone(),
        None => {
            eprintln!(
                "note: the socket path on the remote is not known yet; run \
                 `credential-bridge-ctl remote install {}` first, or replace <REMOTE_HOME> below",
                remote.name
            );
            paths::default_remote_socket("<REMOTE_HOME>")
        }
    };
    let host = remote.ssh_target().rsplit('@').next().unwrap_or(remote.ssh_target());
    println!("# credential-bridge: forward the socket of remote '{}'", remote.name);
    println!("Host {host}");
    println!(
        "    RemoteForward {} {}",
        ssh_config_quote(&remote_socket),
        ssh_config_quote(&local.to_string_lossy())
    );
    eprintln!(
        "note: if this Host already has an entry in ~/.ssh/config, add only the RemoteForward line to it"
    );
    eprintln!(
        "note: the remote's sshd should set `StreamLocalBindUnlink yes`; otherwise a stale socket \
         left by an earlier connection blocks the forwarding"
    );
    Ok(())
}

/// Directories that may hold prebuilt helpers (`git-credential-bridge-<platform>`),
/// in this order:
///
/// 1. `$CREDENTIAL_BRIDGE_HELPER_DIR` (set by the Nix package's wrapper)
/// 2. `<prefix>/share/credential-bridge/helpers` next to this program's `bin/`,
///    as the path it was started by and with symlinks resolved (release
///    packages, `install.sh`, distribution packages)
/// 3. `$XDG_DATA_HOME/credential-bridge/helpers` (helpers put there by hand)
pub fn helper_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = env::var_os(HELPER_DIR_ENV).map(PathBuf::from).into_iter().collect();
    let invoked = service::invoked_path(env::args_os().next().map(PathBuf::from), crate::util::which);
    for exe in [invoked, env::current_exe().ok()].into_iter().flatten() {
        if let Some(prefix) = exe.parent().and_then(Path::parent) {
            dirs.push(prefix.join("share/credential-bridge/helpers"));
        }
    }
    if let Ok(data) = paths::data_home() {
        dirs.push(data.join("credential-bridge/helpers"));
    }
    dirs.dedup();
    dirs
}

/// Platforms with a helper in [`helper_dirs`], e.g. `["aarch64-linux", "x86_64-linux"]`.
pub fn available_helpers() -> Vec<String> {
    let prefix = format!("{HELPER_BINARY}-");
    let mut platforms: Vec<String> = helper_dirs()
        .iter()
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.strip_prefix(&prefix).map(str::to_owned))
        .collect();
    platforms.sort();
    platforms.dedup();
    platforms
}

/// Finds the helper binary to upload for `platform` (e.g. `x86_64-linux`).
fn find_helper_binary(platform: &str) -> anyhow::Result<PathBuf> {
    let file = format!("{HELPER_BINARY}-{platform}");
    if let Some(found) = helper_dirs().into_iter().map(|dir| dir.join(&file)).find(|c| c.is_file()) {
        return Ok(found);
    }
    let available = available_helpers();
    bail!(
        "no {HELPER_BINARY} for {platform} found{}.\n\
         Use a release package that includes it, put `{file}` into \
         ~/.local/share/credential-bridge/helpers/, or pass `--binary PATH`.",
        if available.is_empty() { String::new() } else { format!(" (available: {})", available.join(", ")) }
    )
}

/// git config `credential.<origin>` sections for the allow list; `true` if
/// any pattern of that origin needs the request path. Same rule as the
/// helper's `setup`, from the shared crate.
fn origins(remote: &RemoteConfig) -> anyhow::Result<BTreeMap<String, bool>> {
    Ok(credential_bridge_proto::git_sections(&remote.patterns()?))
}

/// Uploads the helper from stdin and lets it register itself with git
/// (`git-credential-bridge setup`), all in one ssh connection.
fn install_script(helper: &str, remote_socket: &str, allow: &[String], git_config: bool) -> String {
    let dir = Path::new(helper).parent().map_or("/".into(), |p| p.to_string_lossy().into_owned());
    let tmp = format!("{helper}.tmp");
    let mut setup = format!("{} setup --socket {}", sh_quote(helper), sh_quote(remote_socket));
    if !git_config {
        setup += " --no-git-config";
    }
    for pattern in allow {
        setup += &format!(" {}", sh_quote(pattern));
    }
    format!(
        "set -eu\nmkdir -p {dir}\ncat > {tmp}\nchmod 755 {tmp}\nmv -f {tmp} {dst}\n{setup}\n",
        dir = sh_quote(&dir),
        tmp = sh_quote(&tmp),
        dst = sh_quote(helper),
    )
}

/// Lets the helper remove its git configuration and itself
/// (`git-credential-bridge uninstall --remove-binary`).
fn uninstall_script() -> String {
    format!(
        "set -eu\nh=\"$HOME\"/{0}\nif [ -x \"$h\" ]; then \"$h\" uninstall --remove-binary; \
         else echo \"nothing to remove: $h does not exist\"; fi\n",
        paths::REMOTE_HELPER_RELATIVE
    )
}

/// One line of a step list: `✓ connect        detail`.
fn step_line(level: Level, name: &str, detail: &str) -> String {
    format!("{} {}  {}", level.symbol(), ui::pad(name, 13), ui::dim(detail))
}

fn install(ctx: &Ctx, args: &InstallArgs) -> anyhow::Result<()> {
    let config = ctx.load()?;
    let remote = find(&config, &args.name)?;
    let hosts: Vec<String> = origins(remote)?.keys().map(|o| ui::short_url(o).to_owned()).collect();
    let ssh = Ssh::new(remote.ssh_target());

    let info = ssh.probe()?;
    let git = info.git_version.as_deref().map_or_else(|| "no git".to_owned(), |v| format!("git {v}"));
    println!(
        "{}",
        step_line(Level::Ok, "connect", &format!("{} · {} · {git}", ssh.target(), info.platform()))
    );

    let binary = match &args.binary {
        Some(path) => path.clone(),
        None => find_helper_binary(&info.platform())?,
    };
    if !binary.is_file() {
        bail!("{} is not a file", binary.display());
    }

    let helper = paths::default_remote_helper(&info.home);
    let remote_socket =
        remote.remote_socket.clone().unwrap_or_else(|| paths::default_remote_socket(&info.home));
    let git_config = !args.no_git_config && info.git_version.is_some();
    let script = install_script(&helper, &remote_socket, &remote.allow, git_config);

    if args.dry_run {
        println!();
        println!("# run on {} with {} on stdin:", ssh.target(), binary.display());
        print!("{script}");
        if remote.remote_socket.is_none() {
            println!();
            println!("# then record remote_socket = {remote_socket:?} in {}", ctx.config_path.display());
        }
        return Ok(());
    }

    let output = ssh.run_with_input(&script, &binary)?;
    let size = std::fs::metadata(&binary)
        .map(|m| format!(" · {:.1} MB", m.len() as f64 / 1_000_000.0))
        .unwrap_or_default();
    let remote_home = Some(info.home.as_str());
    println!(
        "{}",
        step_line(Level::Ok, "upload helper", &format!("{}{size}", ui::tilde(&helper, remote_home)))
    );
    if git_config {
        println!("{}", step_line(Level::Ok, "configure git", &hosts.join(", ")));
    } else if args.no_git_config {
        println!("{}", step_line(Level::Ok, "configure git", "skipped (--no-git-config)"));
    } else {
        println!("{}", step_line(Level::Warn, "configure git", "skipped: git not found on the remote"));
    }
    if ui::verbose() {
        for line in output.lines() {
            println!("  {}", ui::dim(line));
        }
    }

    if remote.remote_socket.is_none() {
        let mut doc = ctx.document()?;
        doc.set_remote_value(&remote.name, "remote_socket", &remote_socket)?;
        doc.save()?;
        if ui::verbose() {
            println!(
                "  {}",
                ui::dim(&format!("recorded remote_socket in {}", ui::home_tilde(&ctx.config_path)))
            );
        }
    }

    let config = ctx.load()?;
    let remote = find(&config, &args.name)?;
    let status = forward_status(&config, remote)?;
    let check = format!("credential-bridge-ctl remote check {}", remote.name);
    if status == ForwardStatus::Configured {
        println!("{}", step_line(Level::Ok, "ssh config", "RemoteForward present"));
        println!();
        println!("{} Check it: {}", ui::green(&ui::bold("Installed.")), ui::cyan(&check));
    } else {
        println!("{}", step_line(Level::Warn, "ssh config", &status.to_string()));
        println!();
        status.explain(remote);
        print_ssh_config(&config, remote)?;
        println!();
        println!("{} Then reconnect and check it: {}", ui::green(&ui::bold("Installed.")), ui::cyan(&check));
    }
    Ok(())
}

/// Whether the user's ssh config forwards a remote's socket.
#[derive(Debug, PartialEq)]
pub enum ForwardStatus {
    Configured,
    /// No RemoteForward to our local socket.
    Missing,
    /// Forwards our local socket, but to another path on the remote.
    WrongRemotePath(String),
    /// `ssh -G` failed.
    Unknown(String),
}

impl std::fmt::Display for ForwardStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardStatus::Configured => f.write_str("forwards the socket"),
            ForwardStatus::Missing => f.write_str("has no RemoteForward for the socket"),
            ForwardStatus::WrongRemotePath(path) => write!(f, "forwards the socket to {path} on the remote"),
            ForwardStatus::Unknown(err) => write!(f, "cannot be checked: {err}"),
        }
    }
}

impl ForwardStatus {
    pub fn explain(&self, remote: &RemoteConfig) {
        match self {
            ForwardStatus::Configured => {}
            ForwardStatus::Missing => {
                println!("ssh config: no RemoteForward for '{}' yet; add this to ~/.ssh/config:", remote.name)
            }
            ForwardStatus::WrongRemotePath(path) => println!(
                "ssh config: the RemoteForward for '{}' points to {path} on the remote; replace it with:",
                remote.name
            ),
            ForwardStatus::Unknown(err) => {
                println!("ssh config: cannot check ({err}); make sure ~/.ssh/config contains:")
            }
        }
    }
}

/// Checks the RemoteForward of `remote` with `ssh -G`. Without a recorded
/// remote socket (not installed yet) only the local end is compared.
pub fn forward_status(config: &Config, remote: &RemoteConfig) -> anyhow::Result<ForwardStatus> {
    let local = config.socket_path(&remote.name)?;
    let forwards = match Ssh::new(remote.ssh_target()).configured_forwards() {
        Ok(forwards) => forwards,
        Err(err) => return Ok(ForwardStatus::Unknown(format!("{err:#}"))),
    };
    Ok(match_forward(&forwards, &local.to_string_lossy(), remote.remote_socket.as_deref()))
}

fn match_forward(forwards: &[String], local: &str, remote_socket: Option<&str>) -> ForwardStatus {
    // `<listen> <connect>`: find the line that ends with our local socket;
    // whatever comes before it is the path on the remote, spaces included.
    let unquote = |s: &str| s.trim().trim_matches('"').to_owned();
    let listen = forwards.iter().find_map(|line| {
        let line = line.trim();
        line.strip_suffix(local)
            .or_else(|| line.strip_suffix(&format!("\"{local}\"")))
            .filter(|rest| rest.ends_with(char::is_whitespace))
            .map(unquote)
    });
    let Some(listen) = listen else {
        return ForwardStatus::Missing;
    };
    match remote_socket {
        Some(expected) if listen != expected => ForwardStatus::WrongRemotePath(listen),
        _ => ForwardStatus::Configured,
    }
}

/// A station of the chain `remote check` walks.
#[derive(Debug, Clone, PartialEq)]
enum Station {
    Ok,
    Broken { problem: String, fix: String },
    Unchecked,
}

const STATIONS: [&str; 5] = ["daemon", "ssh config", "ssh", "helper", "git"];

/// `daemon ━ ssh config ━ ssh ━ helper ━ git    ready`, with the broken
/// station in red and unchecked ones dimmed.
fn render_chain(stations: &[Station; 5]) -> String {
    let mut out = String::new();
    for (i, (name, station)) in STATIONS.iter().zip(stations).enumerate() {
        if i > 0 {
            let link = if *station == Station::Unchecked {
                ui::dim(" ┄ ")
            } else {
                format!(" {} ", ui::green("━"))
            };
            out += &link;
        }
        out += &match station {
            Station::Ok => (*name).to_owned(),
            Station::Broken { .. } => ui::red(&ui::bold(name)),
            Station::Unchecked => ui::dim(name),
        };
    }
    let ready = stations.iter().all(|s| *s == Station::Ok);
    out + "    " + &if ready { ui::green(&ui::bold("ready")) } else { ui::red(&ui::bold("broken")) }
}

/// `remote check`: the whole chain, from the remote's point of view.
fn check(ctx: &Ctx, name: &str) -> anyhow::Result<()> {
    let config = ctx.load()?;
    let remote = find(&config, name)?;
    let mut stations = [Station::Ok, Station::Ok, Station::Ok, Station::Ok, Station::Ok];
    let mut detail = Vec::new();
    let install = format!("credential-bridge-ctl remote install {name}");
    let broken = |problem: String, fix: String| Station::Broken { problem, fix };

    let run = (|| -> anyhow::Result<()> {
        let local = config.socket_path(name)?;
        if !matches!(socket_state(&local), crate::util::SocketState::Listening) {
            stations[0] = broken(
                "the local daemon does not serve this remote".into(),
                "credential-bridge-ctl service reload".into(),
            );
            return Ok(());
        }
        let status = forward_status(&config, remote)?;
        if status != ForwardStatus::Configured {
            stations[1] = broken(
                format!("ssh config {status}"),
                format!("credential-bridge-ctl remote ssh-config {name}"),
            );
            return Ok(());
        }
        let Some(remote_socket) = &remote.remote_socket else {
            stations[2] = Station::Unchecked;
            stations[3] = broken("not installed on the remote".into(), install.clone());
            return Ok(());
        };
        // An open session may already forward the socket; connecting with our
        // own forwarding would take it over (StreamLocalBindUnlink) and remove
        // it when we disconnect, so try without forwarding first.
        let ssh = Ssh::new(remote.ssh_target());
        let script = check_script(remote_socket);
        let first = match ssh.run_without_forwarding(&script) {
            Ok(result) => result,
            Err(err) => {
                stations[2] = broken(format!("{err:#}"), format!("ssh {}", remote.ssh_target()));
                return Ok(());
            }
        };
        let first_report = CheckReport::parse(&first.1);
        let (reached, output, via) = match after_first_run(first.0, &first_report) {
            NextStep::Reached => (true, first.1, "an open ssh session"),
            // A forwarding cannot fix a missing helper or git config, and it
            // would take over (and on disconnect remove) the socket of a
            // session that is open right now.
            NextStep::Report => (false, first.1, "a connection without forwarding"),
            NextStep::Forward => match ssh.run_forwarded(&script) {
                Ok((ok, output)) => (ok, output, "a new ssh connection"),
                // sshd could not bind the socket path: usually a stale socket
                // from an earlier connection without StreamLocalBindUnlink.
                Err(err) if format!("{err:#}").contains("forwarding failed") => {
                    stations[2] = broken(
                        format!("sshd cannot create {remote_socket} on the remote (stale socket?)"),
                        format!(
                            "set `StreamLocalBindUnlink yes` in the remote's sshd_config, or: ssh {} rm {}",
                            remote.ssh_target(),
                            sh_quote(remote_socket)
                        ),
                    );
                    return Ok(());
                }
                Err(err) => return Err(err),
            },
        };
        detail.push(format!("via {via}"));
        let report = CheckReport::parse(&output);
        if !report.helper {
            stations[3] = broken("the helper is missing on the remote".into(), install.clone());
            stations[4] = Station::Unchecked;
            return Ok(());
        }
        if report.git_entries == 0 {
            stations[4] = broken("git on the remote does not use the helper".into(), install.clone());
            return Ok(());
        }
        if !reached {
            stations[2] = broken(
                format!("the forwarded socket does not reach the daemon: {}", report.ping.trim()),
                "set `StreamLocalBindUnlink yes` in the remote's sshd_config, then reconnect".into(),
            );
        }
        Ok(())
    })();
    run?;

    // Everything after the first broken station is unchecked.
    if let Some(first) = stations.iter().position(|s| matches!(s, Station::Broken { .. })) {
        for station in stations.iter_mut().skip(first + 1) {
            if *station == Station::Ok {
                *station = Station::Unchecked;
            }
        }
    }
    println!("{}", render_chain(&stations));
    if ui::verbose() && !detail.is_empty() {
        println!("  {}", ui::dim(&detail.join(" · ")));
    }
    for station in &stations {
        if let Station::Broken { problem, fix } = station {
            println!("  {} {problem}", Level::Fail.symbol());
            println!("{}", ui::fix(4, fix));
            bail!("{name} is not ready");
        }
    }
    Ok(())
}

/// Runs on the remote for `remote check`: helper present, git entries, ping.
fn check_script(remote_socket: &str) -> String {
    format!(
        "h=\"$HOME\"/{helper}; if [ -x \"$h\" ]; then echo helper=yes; else echo helper=no; exit 3; fi; \
         echo \"git-entries=$(git config --global --get-regexp '^credential\\..*\\.helper$' 2>/dev/null | grep -c {name})\"; \
         \"$h\" --socket {socket} ping",
        helper = paths::REMOTE_HELPER_RELATIVE,
        name = HELPER_BINARY,
        socket = sh_quote(remote_socket),
    )
}

/// What `check` does after its first run, which has no forwarding.
#[derive(Debug, PartialEq)]
enum NextStep {
    /// An open session forwards the socket and the daemon answered.
    Reached,
    /// Helper or git config is missing; report that without forwarding.
    Report,
    /// Everything is installed but nothing forwards the socket: try with ours.
    Forward,
}

fn after_first_run(ok: bool, report: &CheckReport) -> NextStep {
    if ok {
        NextStep::Reached
    } else if !report.helper || report.git_entries == 0 {
        NextStep::Report
    } else {
        NextStep::Forward
    }
}

#[derive(Debug, Default, PartialEq)]
struct CheckReport {
    helper: bool,
    git_entries: usize,
    /// Output of `ping` (and anything else).
    ping: String,
}

impl CheckReport {
    fn parse(output: &str) -> Self {
        let mut report = CheckReport::default();
        for line in output.lines() {
            if let Some(v) = line.strip_prefix("helper=") {
                report.helper = v.trim() == "yes";
            } else if let Some(v) = line.strip_prefix("git-entries=") {
                report.git_entries = v.trim().parse().unwrap_or(0);
            } else {
                report.ping += line;
                report.ping.push('\n');
            }
        }
        report
    }
}

fn uninstall(ctx: &Ctx, name: &str, dry_run: bool) -> anyhow::Result<()> {
    let config = ctx.load()?;
    let remote = find(&config, name)?;
    let ssh = Ssh::new(remote.ssh_target());
    let script = uninstall_script();
    if dry_run {
        println!("# run on {}:", ssh.target());
        print!("{script}");
        return Ok(());
    }
    let output = ssh.run_script(&script)?;
    if output.contains("nothing to remove") {
        println!("{} nothing to remove on {}", Level::Ok.symbol(), ssh.target());
    } else {
        let hosts = output
            .lines()
            .find_map(|l| l.strip_prefix("removed the git configuration for "))
            .unwrap_or("its hosts");
        println!(
            "{} removed the helper from {}  {}",
            Level::Ok.symbol(),
            ssh.target(),
            ui::dim(&format!("git config for {hosts}"))
        );
    }
    if ui::verbose() {
        output.lines().for_each(|line| println!("  {}", ui::dim(line)));
    }
    println!(
        "{}",
        ui::dim(&format!(
            "the remote stays configured locally; `credential-bridge-ctl remote remove {name}` drops it"
        ))
    );
    Ok(())
}

pub fn test(ctx: &Ctx, args: &TestArgs) -> anyhow::Result<ExitCode> {
    let config = ctx.load()?;
    find(&config, &args.remote)?;
    let socket = config.socket_path(&args.remote)?;
    let operation: Operation = args.operation.parse()?;
    let credential = Credential::from_url(&args.url)?;
    println!("socket:  {}", socket.display());
    println!("request: {operation} {}", credential.redacted());
    let response = exchange(&socket, &Request::new(operation, credential), Some(Duration::from_secs(60)))
        .context("is the service running? (`credential-bridge-ctl service status`)")?;
    let message = response.message.as_deref().map(|m| format!(" ({m})")).unwrap_or_default();
    match response.status {
        Status::Ok if response.credential.is_empty() && operation == Operation::Get => {
            println!("result:  ok{message}, but the backend has no credential for this URL");
        }
        Status::Ok => println!("result:  ok{message} {}", response.credential.redacted()),
        Status::Denied => println!("result:  denied{message}"),
        Status::Error => println!("result:  error{message}"),
    }
    Ok(if response.status == Status::Ok { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(allow: &[&str]) -> RemoteConfig {
        RemoteConfig {
            name: "r".into(),
            ssh_host: None,
            remote_socket: None,
            allow: allow.iter().map(|s| s.to_string()).collect(),
            operations: vec!["get".into()],
            backend: None,
        }
    }

    #[test]
    fn renders_the_chain() {
        let ok = [Station::Ok, Station::Ok, Station::Ok, Station::Ok, Station::Ok];
        assert_eq!(render_chain(&ok), "daemon ━ ssh config ━ ssh ━ helper ━ git    ready");
        let broken = Station::Broken { problem: "x".into(), fix: "y".into() };
        let chain = [Station::Ok, broken, Station::Unchecked, Station::Unchecked, Station::Unchecked];
        assert_eq!(render_chain(&chain), "daemon ━ ssh config ┄ ssh ┄ helper ┄ git    broken");
    }

    #[test]
    fn check_forwards_only_when_that_can_help() {
        let installed = CheckReport { helper: true, git_entries: 1, ping: String::new() };
        assert_eq!(after_first_run(true, &installed), NextStep::Reached);
        assert_eq!(after_first_run(false, &installed), NextStep::Forward);
        let no_helper = CheckReport { helper: false, git_entries: 0, ping: String::new() };
        assert_eq!(
            after_first_run(false, &no_helper),
            NextStep::Report,
            "must not take an open session's socket"
        );
        let no_git = CheckReport { helper: true, git_entries: 0, ping: String::new() };
        assert_eq!(after_first_run(false, &no_git), NextStep::Report);
    }

    #[test]
    fn parses_check_output() {
        let report = CheckReport::parse("helper=yes\ngit-entries=2\nok: reachable\n");
        assert_eq!(report, CheckReport { helper: true, git_entries: 2, ping: "ok: reachable\n".into() });
        assert!(!CheckReport::parse("helper=no\n").helper);
    }

    #[test]
    fn matches_forwards() {
        let forwards = [
            "/home/r/b.sock /home/l/s/x.sock".to_owned(),
            "/home/eve space/b.sock /home/l/s/y.sock".to_owned(),
        ];
        assert_eq!(
            match_forward(&forwards, "/home/l/s/x.sock", Some("/home/r/b.sock")),
            ForwardStatus::Configured
        );
        assert_eq!(match_forward(&forwards, "/home/l/s/x.sock", None), ForwardStatus::Configured);
        assert_eq!(
            match_forward(&forwards, "/home/l/s/x.sock", Some("/other.sock")),
            ForwardStatus::WrongRemotePath("/home/r/b.sock".into())
        );
        assert_eq!(match_forward(&forwards, "/home/l/s/z.sock", None), ForwardStatus::Missing);
        assert_eq!(
            match_forward(&forwards, "/home/l/s/y.sock", Some("/home/eve space/b.sock")),
            ForwardStatus::Configured,
            "a remote home with a space"
        );
        assert_eq!(
            match_forward(&["/a/b.sock /x/s/x.sock".to_owned()], "s/x.sock", None),
            ForwardStatus::Missing
        );
    }

    #[test]
    fn origins_merge_patterns() {
        let o =
            origins(&remote(&["https://github.com", "https://github.com/org/*", "https://git.example.com"]))
                .unwrap();
        assert_eq!(
            o.into_iter().collect::<Vec<_>>(),
            [("https://git.example.com".to_owned(), false), ("https://github.com".to_owned(), true)]
        );
    }

    #[test]
    fn install_script_uploads_and_sets_up() {
        let allow = ["https://github.com/org/*".to_owned(), "https://x.example".to_owned()];
        let script = install_script("/home/me/.local/bin/h", "/home/me/s/bridge.sock", &allow, true);
        assert_eq!(
            script,
            "set -eu\nmkdir -p /home/me/.local/bin\ncat > /home/me/.local/bin/h.tmp\n\
             chmod 755 /home/me/.local/bin/h.tmp\nmv -f /home/me/.local/bin/h.tmp /home/me/.local/bin/h\n\
             /home/me/.local/bin/h setup --socket /home/me/s/bridge.sock 'https://github.com/org/*' https://x.example\n"
        );
        let script = install_script("/h", "/s.sock", &allow, false);
        assert!(script.contains("setup --socket /s.sock --no-git-config "));
    }

    #[test]
    fn uninstall_script_lets_the_helper_clean_up() {
        let script = uninstall_script();
        assert!(script.contains("h=\"$HOME\"/.local/bin/git-credential-bridge\n"));
        assert!(script.contains("\"$h\" uninstall --remove-binary"));
    }
}
