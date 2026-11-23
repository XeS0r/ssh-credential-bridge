//! `init`: a first configuration from what is found on this machine.
//!
//! It looks for agents (`SSH_AUTH_SOCK`, the 1Password agent, gpg-agent's ssh socket;
//! never the proxy's own sockets) and a logged-in `gh`, shows the proposal and, on a
//! terminal, asks for each item whether to accept, change or skip it. With `--yes` or
//! without a terminal the proposal is written as it is. The result always validates;
//! an existing configuration is replaced only with `--force`, after a backup.

use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use credential_bridge_config::Config;
use credential_bridge_config::edit::{ConfigDocument, NewSource};
use credential_bridge_config::paths::{Paths, TargetOs};

use super::change::{Change, apply_doc, edit_error, tilde};
use super::{Context, ask_terminal, in_path};
use crate::cli::InitArgs;
use crate::report::{Line, Report};

/// The 1Password agent socket on Linux, below the home directory.
const ONEPASSWORD_LINUX: &str = ".1password/agent.sock";

/// The 1Password agent socket on macOS, below the home directory.
const ONEPASSWORD_MACOS: &str = "Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock";

/// What `init` looks at, so tests can replace the machine.
pub(crate) trait Environment {
    /// An environment variable (`SSH_AUTH_SOCK`).
    fn var(&self, name: &str) -> Option<String>;
    /// Whether `path` is a unix socket.
    fn is_socket(&self, path: &Path) -> bool;
    /// `gpgconf --list-dirs <name>`, if gpgconf exists and answers.
    fn gpgconf(&self, name: &str) -> Option<PathBuf>;
    /// Whether `gh auth status` succeeds (gh exists and is logged in).
    fn gh_logged_in(&self) -> bool;
    /// The system whose paths apply.
    fn os(&self) -> TargetOs;
}

/// This machine.
struct Machine;

impl Environment for Machine {
    fn var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|value| !value.is_empty())
    }

    fn is_socket(&self, path: &Path) -> bool {
        use std::os::unix::fs::FileTypeExt as _;
        std::fs::metadata(path).is_ok_and(|meta| meta.file_type().is_socket())
    }

    fn gpgconf(&self, name: &str) -> Option<PathBuf> {
        if !in_path("gpgconf") {
            return None;
        }
        super::check::gpgconf_dir(name)
    }

    fn gh_logged_in(&self) -> bool {
        in_path("gh")
            && std::process::Command::new("gh")
                .args(["auth", "status", "--hostname", "github.com"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
    }

    fn os(&self) -> TargetOs {
        TargetOs::current()
    }
}

/// How `init` asks; replaced in tests.
pub(crate) trait Ask {
    /// Shows `question` and returns the trimmed answer.
    fn ask(&mut self, question: &str) -> std::io::Result<String>;
}

/// Asks on stdin/stdout.
struct Terminal;

impl Ask for Terminal {
    fn ask(&mut self, question: &str) -> std::io::Result<String> {
        ask_terminal(question)
    }
}

/// One agent `init` proposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FoundAgent {
    /// The upstream name.
    pub name: String,
    /// The socket as written: `~/…`, an absolute path or `gpgconf:…`.
    pub socket: String,
    /// The socket path, for de-duplication.
    pub path: PathBuf,
    /// Where it was found.
    pub why: String,
    /// Something to look at, e.g. a socket that changes with every agent start.
    pub warning: Option<String>,
}

/// What `init` proposes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Proposal {
    /// Upstream agents, in the order they will be written.
    pub agents: Vec<FoundAgent>,
    /// `agent.add_to`.
    pub add_to: Option<String>,
    /// A `[source.github]` with `auth = "gh"`.
    pub github: bool,
}

/// Whether two socket paths are the same file.
fn same(a: &Path, b: &Path) -> bool {
    a == b || matches!((std::fs::canonicalize(a), std::fs::canonicalize(b)), (Ok(x), Ok(y)) if x == y)
}

/// `/tmp/ssh-XXXXXX/agent.<pid>`: the socket of one `ssh-agent` run without `-a`, or a
/// forwarded agent of an ssh session.
fn temporary(path: &Path) -> bool {
    let file = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    let dir = path.parent().and_then(Path::file_name).map(|name| name.to_string_lossy().into_owned());
    file.starts_with("agent.") && dir.is_some_and(|dir| dir.starts_with("ssh-"))
}

/// Looks at `env` and proposes agents, `add_to` and a GitHub source. Sockets that are
/// the proxy's own (`own`: the configured and the default `daemon.socket` and
/// `daemon.forward_socket`) are never proposed as upstreams.
pub(crate) fn detect(env: &dyn Environment, paths: &Paths, own: &[PathBuf]) -> Proposal {
    let mut proposal = Proposal::default();
    let onepassword = paths.home.join(match env.os() {
        TargetOs::Linux => ONEPASSWORD_LINUX,
        TargetOs::MacOs => ONEPASSWORD_MACOS,
    });
    let gpg = env.gpgconf("agent-ssh-socket").filter(|path| env.is_socket(path));
    let mut add = |agent: FoundAgent| {
        if own.iter().any(|own| same(own, &agent.path)) {
            return;
        }
        if !proposal.agents.iter().any(|known| same(&known.path, &agent.path) || known.name == agent.name) {
            proposal.agents.push(agent);
        }
    };
    let gpg_agent = |path: &Path, why: &str| FoundAgent {
        name: "gpg-agent".into(),
        socket: "gpgconf:agent-ssh-socket".into(),
        path: path.to_owned(),
        why: why.into(),
        warning: None,
    };
    let onepassword_agent = |why: &str| FoundAgent {
        name: "1password".into(),
        socket: tilde(paths, &onepassword),
        path: onepassword.clone(),
        why: why.into(),
        warning: None,
    };

    if let Some(auth_sock) = env.var("SSH_AUTH_SOCK").map(PathBuf::from)
        && env.is_socket(&auth_sock)
    {
        if same(&auth_sock, &onepassword) {
            add(onepassword_agent("SSH_AUTH_SOCK"));
        } else if gpg.as_deref().is_some_and(|gpg| same(gpg, &auth_sock)) {
            add(gpg_agent(&auth_sock, "SSH_AUTH_SOCK"));
        } else {
            let warning = temporary(&auth_sock).then(|| {
                "looks like the socket of one ssh-agent run, which changes when the agent restarts; \
                 start ssh-agent with -a PATH (or use your desktop's agent socket) and change it"
                    .to_owned()
            });
            add(FoundAgent {
                name: "ssh-agent".into(),
                socket: tilde(paths, &auth_sock),
                path: auth_sock,
                why: "SSH_AUTH_SOCK".into(),
                warning,
            });
        }
    }
    if env.is_socket(&onepassword) {
        add(onepassword_agent("1Password"));
    }
    if let Some(gpg) = &gpg {
        add(gpg_agent(gpg, "gpgconf --list-dirs agent-ssh-socket"));
    }
    // 1Password does not take keys from ssh-add.
    proposal.add_to = preferred_add_to(&proposal.agents);
    proposal.github = env.gh_logged_in();
    proposal
}

/// The agent `ssh-add` through the proxy should go to: an ssh-agent, else gpg-agent.
fn preferred_add_to(agents: &[FoundAgent]) -> Option<String> {
    ["ssh-agent", "gpg-agent"]
        .into_iter()
        .find(|name| agents.iter().any(|agent| agent.name == *name))
        .map(str::to_owned)
}

/// The report lines that describe `proposal`.
fn proposal_lines(proposal: &Proposal) -> Vec<Line> {
    let mut lines = Vec::new();
    if proposal.agents.is_empty() {
        lines.push(
            Line::warn("agents", "none found: the proxy will only hand out tokens")
                .with_hint("credential-bridge-ctl agent add NAME SOCKET"),
        );
    }
    for agent in &proposal.agents {
        let line = Line::ok(format!("agent {}", agent.name), format!("{} ({})", agent.socket, agent.why));
        lines.push(match &agent.warning {
            Some(warning) => Line { status: crate::report::Status::Warn, ..line }.with_hint(warning.clone()),
            None => line,
        });
    }
    if let Some(add_to) = &proposal.add_to {
        lines.push(Line::ok("add_to", format!("{add_to} (ssh-add through the proxy goes here)")));
    }
    if proposal.github {
        lines.push(Line::ok("source github", "gh is logged in to github.com"));
    }
    lines
}

/// Asks whether to accept, change (if `change`) or skip `what`: `'a'`, `'c'` or `'s'`.
fn choose(ask: &mut dyn Ask, report: &mut Report, what: &str, change: bool) -> anyhow::Result<char> {
    let question = if change {
        format!("{what}: (a)ccept, (c)hange, (s)kip? [a] ")
    } else {
        format!("{what}: (a)ccept, (s)kip? [a] ")
    };
    loop {
        match ask.ask(&question)?.to_ascii_lowercase().as_str() {
            "" | "a" => return Ok('a'),
            "c" if change => return Ok('c'),
            "s" => return Ok('s'),
            _ => report.show(if change { "please answer a, c or s\n" } else { "please answer a or s\n" }),
        }
    }
}

/// Asks about each item of `proposal` and returns what to write.
fn review(mut proposal: Proposal, ask: &mut dyn Ask, report: &mut Report) -> anyhow::Result<Proposal> {
    let mut agents = Vec::new();
    for mut agent in std::mem::take(&mut proposal.agents) {
        match choose(ask, report, &format!("agent {} at {}", agent.name, agent.socket), true)? {
            'a' => agents.push(agent),
            'c' => {
                let name = ask.ask(&format!("  name [{}]: ", agent.name))?;
                let socket = ask.ask(&format!("  socket [{}]: ", agent.socket))?;
                if !name.is_empty() {
                    agent.name = name;
                }
                if !socket.is_empty() {
                    agent.socket = super::change::socket_value(&socket)?;
                }
                agents.push(agent);
            }
            _ => {}
        }
    }
    proposal.agents = agents;
    let add_to = proposal
        .add_to
        .take()
        .filter(|name| proposal.agents.iter().any(|agent| agent.name == *name))
        .or_else(|| preferred_add_to(&proposal.agents))
        .or_else(|| proposal.agents.first().map(|agent| agent.name.clone()));
    if let Some(add_to) = add_to {
        match choose(ask, report, &format!("add_to = {add_to} (where ssh-add through the proxy goes)"), true)?
        {
            'a' => proposal.add_to = Some(add_to),
            'c' => {
                let names: Vec<&str> = proposal.agents.iter().map(|agent| agent.name.as_str()).collect();
                let name = ask.ask(&format!("  add_to ({}): ", names.join(", ")))?;
                if !names.contains(&name.as_str()) {
                    bail!("{name:?} is not one of the agents ({})", names.join(", "));
                }
                proposal.add_to = Some(name);
            }
            _ => {}
        }
    }
    if proposal.github {
        proposal.github = choose(ask, report, "source github (gh, github.com)", false)? == 'a';
    }
    Ok(proposal)
}

/// The comment `init` ends the file with.
fn next_steps(proposal: &Proposal) -> String {
    let source = if proposal.github {
        "#   credential-bridge-ctl profile rule add dev 'https://github.com/my-org/*' --source github\n"
    } else {
        "#   credential-bridge-ctl source add github github\n\
         #   credential-bridge-ctl profile rule add dev 'https://github.com/my-org/*' --source github\n"
    };
    format!(
        "\n# Next: a profile says what a server may use; then add the server, e.g.\n\
         #   credential-bridge-ctl profile add dev ssh.keys=all\n{source}\
         #   credential-bridge-ctl server add buildserver --profile dev\n\
         # Servers without a [server.*] entry get the built-in profile.unregistered:\n\
         # no keys, no tokens, no gpg.\n"
    )
}

/// The configuration text for `proposal`.
fn render(path: &Path, proposal: &Proposal) -> anyhow::Result<String> {
    let header = format!(
        "# credential-bridge configuration, written by credential-bridge-ctl init.\n\
         # Change it with credential-bridge-ctl (agent, source, profile, server …) or by hand;\n\
         # credential-bridge-ctl config check validates it.\n\
         version = {}\n",
        credential_bridge_config::CONFIG_VERSION
    );
    let mut doc = ConfigDocument::replacing(path, None, &header).map_err(edit_error)?;
    for agent in &proposal.agents {
        doc.add_upstream(&agent.name, &agent.socket).map_err(edit_error)?;
    }
    if let Some(add_to) = &proposal.add_to {
        doc.set_add_to(Some(add_to)).map_err(edit_error)?;
    }
    if proposal.github {
        doc.add_source("github", &NewSource::GithubGh { host: None }).map_err(edit_error)?;
    }
    Ok(format!("{}{}", doc.to_text(), next_steps(proposal)))
}

/// `init`.
pub fn init(ctx: &Context, args: &InitArgs, report: &mut Report) -> anyhow::Result<()> {
    let interactive = !args.yes && std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    init_with(ctx, args, &Machine, interactive.then_some(&mut Terminal as &mut dyn Ask), report)
}

/// [`init`] with an explicit machine and, for interactive use, a way to ask.
///
/// The existing file (with `--force`) is read once: its daemon sockets are left out of
/// the proposal, the backup is made from that text, and the new text replaces it only
/// after it validated.
pub(crate) fn init_with(
    ctx: &Context,
    args: &InitArgs,
    env: &dyn Environment,
    ask: Option<&mut dyn Ask>,
    report: &mut Report,
) -> anyhow::Result<()> {
    let path = &ctx.config_path;
    let exists = std::fs::symlink_metadata(path).is_ok();
    if exists && !args.force {
        bail!(
            "{} exists; init does not overwrite it. Change it with credential-bridge-ctl agent|source|profile|server, \
             or start over with --force (the old file is kept as a backup)",
            path.display()
        );
    }
    let original = match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).with_context(|| format!("cannot read {}", path.display())),
    };
    let proposal = detect(env, &ctx.paths, &own_sockets(&ctx.paths, original.as_deref()));
    report.show(&format!("Proposal for {}:\n", path.display()));
    for line in proposal_lines(&proposal) {
        report.push(line);
    }
    let proposal = match ask {
        Some(ask) => match review(proposal, ask, report) {
            Ok(proposal) => proposal,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::UnexpectedEof) =>
            {
                bail!("aborted (no answer); nothing was written");
            }
            Err(error) => return Err(error),
        },
        None => proposal,
    };
    let text = render(path, &proposal)?;
    let doc = ConfigDocument::replacing(path, original, &text).map_err(edit_error)?;
    let change = Change {
        dry_run: args.dry_run,
        before_save: Some(Box::new(|doc: &ConfigDocument, report: &mut Report| {
            if let Some(original) = doc.original_text() {
                let backup = backup(path, original.as_bytes())?;
                report.push(Line::ok("backup", backup.display().to_string()));
            }
            Ok(())
        })),
        ..Change::default()
    };
    apply_doc(ctx, doc, change, report, |_| Ok("written".to_owned()))?;
    if !args.dry_run {
        report.show(
            "\nNext:\n  credential-bridge-ctl daemon install         # start the daemon\n  \
             credential-bridge-ctl profile add dev ssh.keys=all\n  \
             credential-bridge-ctl server add buildserver --profile dev\n",
        );
    }
    Ok(())
}

/// The proxy's own agent sockets: the defaults, and those `original` (the existing
/// file) configures, if it loads.
fn own_sockets(paths: &Paths, original: Option<&str>) -> Vec<PathBuf> {
    let mut own = vec![paths.agent_socket.clone(), paths.forward_socket.clone()];
    if let Some(config) = original.and_then(|text| Config::parse(text, paths).ok()) {
        own.extend([config.daemon.socket, config.daemon.forward_socket]);
    }
    own
}

/// Writes `contents` (the configuration as it was read) to a new
/// `<path>.bak-<UTC time>` next to it, with `-<n>` added if that name exists; never
/// replaces a file.
fn backup(path: &Path, contents: &[u8]) -> anyhow::Result<PathBuf> {
    let stamp = timestamp(super::now_secs());
    for attempt in 0..1000 {
        let mut name = path.as_os_str().to_owned();
        name.push(format!(".bak-{stamp}"));
        if attempt > 0 {
            name.push(format!("-{attempt}"));
        }
        let backup = PathBuf::from(name);
        match credential_bridge_config::file::write_private(&backup, contents) {
            Ok(()) => return Ok(backup),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| format!("cannot create the backup {}", backup.display()));
            }
        }
    }
    bail!("cannot create a backup of {}: too many backups from this second", path.display())
}

/// `20261122T093000Z` for seconds since the epoch.
fn timestamp(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rest = secs % 86_400;
    // Days to civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z", rest / 3600, rest % 3600 / 60, rest % 60)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};

    use super::*;
    use crate::commands::load_config;
    use crate::commands::test_support::{context, write_config};

    /// A machine described by its fields.
    #[derive(Default)]
    struct Fake {
        vars: BTreeMap<String, String>,
        sockets: Vec<PathBuf>,
        gpgconf: Option<PathBuf>,
        gh: bool,
        os: Option<TargetOs>,
    }

    impl Environment for Fake {
        fn var(&self, name: &str) -> Option<String> {
            self.vars.get(name).cloned()
        }
        fn is_socket(&self, path: &Path) -> bool {
            self.sockets.iter().any(|socket| socket == path)
        }
        fn gpgconf(&self, name: &str) -> Option<PathBuf> {
            assert_eq!(name, "agent-ssh-socket");
            self.gpgconf.clone()
        }
        fn gh_logged_in(&self) -> bool {
            self.gh
        }
        fn os(&self) -> TargetOs {
            self.os.unwrap_or(TargetOs::Linux)
        }
    }

    /// Answers from a list, and remembers the questions.
    struct Answers(VecDeque<&'static str>, Vec<String>);

    impl Ask for Answers {
        fn ask(&mut self, question: &str) -> std::io::Result<String> {
            self.1.push(question.to_owned());
            Ok(self.0.pop_front().expect("an answer for every question").to_owned())
        }
    }

    /// Everything: a plain ssh-agent, 1Password, gpg-agent and gh.
    fn full(ctx: &Context) -> Fake {
        let home = &ctx.paths.home;
        let auth = home.join("agents/ssh.sock");
        let gpg = PathBuf::from("/run/user/1000/gnupg/S.gpg-agent.ssh");
        Fake {
            vars: [("SSH_AUTH_SOCK".to_owned(), auth.display().to_string())].into(),
            sockets: vec![auth, home.join(ONEPASSWORD_LINUX), gpg.clone()],
            gpgconf: Some(gpg),
            gh: true,
            os: None,
        }
    }

    /// The default daemon sockets.
    fn own(ctx: &Context) -> Vec<PathBuf> {
        own_sockets(&ctx.paths, None)
    }

    fn backups(ctx: &Context) -> Vec<PathBuf> {
        let mut backups: Vec<PathBuf> = std::fs::read_dir(ctx.config_path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.to_string_lossy().contains(".bak-"))
            .collect();
        backups.sort();
        backups
    }

    fn args(yes: bool, force: bool, dry_run: bool) -> InitArgs {
        InitArgs { yes, force, dry_run }
    }

    #[test]
    fn detects_agents_and_gh() {
        let (_dir, ctx) = context();
        let proposal = detect(&full(&ctx), &ctx.paths, &own(&ctx));
        let found: Vec<(&str, &str)> =
            proposal.agents.iter().map(|agent| (agent.name.as_str(), agent.socket.as_str())).collect();
        assert_eq!(
            found,
            [
                ("ssh-agent", "~/agents/ssh.sock"),
                ("1password", "~/.1password/agent.sock"),
                ("gpg-agent", "gpgconf:agent-ssh-socket")
            ]
        );
        assert_eq!(proposal.add_to.as_deref(), Some("ssh-agent"));
        assert!(proposal.github);
    }

    #[test]
    fn skips_the_proxy_and_names_known_sockets() {
        let (_dir, ctx) = context();
        let mut env = full(&ctx);
        // SSH_AUTH_SOCK is the proxy itself: not an upstream.
        env.vars.insert("SSH_AUTH_SOCK".into(), ctx.paths.agent_socket.display().to_string());
        env.sockets.push(ctx.paths.agent_socket.clone());
        let proposal = detect(&env, &ctx.paths, &own(&ctx));
        assert!(proposal.agents.iter().all(|agent| agent.name != "ssh-agent"), "{proposal:?}");
        assert_eq!(proposal.add_to.as_deref(), Some("gpg-agent"));

        // SSH_AUTH_SOCK is 1Password's socket: named 1password, listed once, not add_to.
        let one = ctx.paths.home.join(ONEPASSWORD_LINUX);
        let env = Fake {
            vars: [("SSH_AUTH_SOCK".to_owned(), one.display().to_string())].into(),
            sockets: vec![one],
            ..Fake::default()
        };
        let proposal = detect(&env, &ctx.paths, &own(&ctx));
        assert_eq!(proposal.agents.len(), 1);
        assert_eq!(proposal.agents[0].name, "1password");
        assert_eq!(proposal.agents[0].why, "SSH_AUTH_SOCK");
        assert_eq!(proposal.add_to, None);
        assert!(!proposal.github);

        // A socket of one ssh-agent run gets a warning; a missing socket is ignored.
        let env = Fake {
            vars: [("SSH_AUTH_SOCK".to_owned(), "/tmp/ssh-AbC123/agent.4711".to_owned())].into(),
            sockets: vec!["/tmp/ssh-AbC123/agent.4711".into()],
            ..Fake::default()
        };
        assert!(
            detect(&env, &ctx.paths, &own(&ctx)).agents[0].warning.as_deref().unwrap().contains("-a PATH")
        );
        let env = Fake { vars: [("SSH_AUTH_SOCK".to_owned(), "/gone".to_owned())].into(), ..Fake::default() };
        assert!(detect(&env, &ctx.paths, &own(&ctx)).agents.is_empty());

        // macOS: 1Password's socket in the group container.
        let mac = ctx.paths.home.join(ONEPASSWORD_MACOS);
        let env = Fake { sockets: vec![mac], os: Some(TargetOs::MacOs), ..Fake::default() };
        assert_eq!(
            detect(&env, &ctx.paths, &own(&ctx)).agents[0].socket,
            "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
        );
    }

    #[test]
    fn non_interactive_init_writes_a_valid_configuration() {
        let (_dir, ctx) = context();
        let mut report = Report::default();
        init_with(&ctx, &args(true, false, false), &full(&ctx), None, &mut report).unwrap();
        let text = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(text.contains("version = 2\n\n[agent]\nadd_to = \"ssh-agent\"\n"), "{text}");
        assert!(
            text.contains(
                "[[agent.upstream]]\nname = \"gpg-agent\"\nsocket = \"gpgconf:agent-ssh-socket\"\n"
            )
        );
        assert!(text.contains("[source.github]\ntype = \"github\"\nauth = \"gh\"\n"), "{text}");
        assert!(text.contains("#   credential-bridge-ctl server add buildserver --profile dev\n"), "{text}");
        let config = load_config(&ctx).unwrap();
        assert_eq!(config.agent.unwrap().upstreams.len(), 3);
        assert!(report.text.contains("✓ agent 1password"), "{}", report.text);
        assert!(report.text.contains("✓ config               written in"), "{}", report.text);
    }

    #[test]
    fn nothing_found_still_validates() {
        let (_dir, ctx) = context();
        let mut report = Report::default();
        init_with(&ctx, &args(true, false, false), &Fake::default(), None, &mut report).unwrap();
        assert!(report.text.contains("⚠ agents"), "{}", report.text);
        let text = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(text.contains("version = 2\n") && text.contains("source add github github"), "{text}");
        load_config(&ctx).unwrap();
    }

    #[test]
    fn existing_configuration_needs_force_and_is_backed_up() {
        let (_dir, ctx) = context();
        write_config(&ctx, "# precious\nversion = 2\n");
        let error = init_with(&ctx, &args(true, false, false), &full(&ctx), None, &mut Report::default())
            .unwrap_err();
        assert!(error.to_string().contains("--force"), "{error}");
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), "# precious\nversion = 2\n");

        // A dry run with --force shows the replacement and makes no backup.
        let mut report = Report::default();
        init_with(&ctx, &args(true, true, true), &full(&ctx), None, &mut report).unwrap();
        assert!(report.text.contains("-# precious\n"), "{}", report.text);
        let dir = ctx.config_path.parent().unwrap();
        assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1);

        init_with(&ctx, &args(true, true, false), &full(&ctx), None, &mut Report::default()).unwrap();
        let first = backups(&ctx);
        assert_eq!(first.len(), 1);
        assert_eq!(std::fs::read_to_string(&first[0]).unwrap(), "# precious\nversion = 2\n");
        assert!(std::fs::read_to_string(&ctx.config_path).unwrap().contains("[agent]"));
        let written = std::fs::read_to_string(&ctx.config_path).unwrap();

        // Again within the same second: a second backup with its own name; none is
        // replaced.
        init_with(&ctx, &args(true, true, false), &Fake::default(), None, &mut Report::default()).unwrap();
        let both = backups(&ctx);
        assert_eq!(both.len(), 2, "{both:?}");
        assert_eq!(std::fs::read_to_string(&first[0]).unwrap(), "# precious\nversion = 2\n");
        let second = both.iter().find(|path| **path != first[0]).unwrap();
        assert_eq!(std::fs::read_to_string(second).unwrap(), written);
    }

    /// The new text is validated before anything is written: an invalid result makes
    /// no backup and leaves the file alone.
    #[test]
    fn invalid_results_make_no_backup() {
        let (_dir, ctx) = context();
        write_config(&ctx, "# precious\nversion = 2\n");
        // Rename the ssh-agent to an invalid name, accept the rest.
        let mut answers = Answers(VecDeque::from(["c", "a b", "", "a", "a", "a", "a"]), Vec::new());
        let error = init_with(
            &ctx,
            &args(false, true, false),
            &full(&ctx),
            Some(&mut answers),
            &mut Report::default(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("invalid upstream name"), "{error:#}");
        assert!(backups(&ctx).is_empty());
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), "# precious\nversion = 2\n");
    }

    /// No answer (end of input) aborts and writes nothing.
    #[test]
    fn end_of_input_aborts() {
        struct Eof;
        impl Ask for Eof {
            fn ask(&mut self, _: &str) -> std::io::Result<String> {
                Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no answer"))
            }
        }
        let (_dir, ctx) = context();
        let error =
            init_with(&ctx, &args(false, false, false), &full(&ctx), Some(&mut Eof), &mut Report::default())
                .unwrap_err();
        assert_eq!(error.to_string(), "aborted (no answer); nothing was written");
        assert!(!ctx.config_path.exists());
    }

    /// With --force, the proxy's sockets of the existing file are not proposed as
    /// upstreams, even when SSH_AUTH_SOCK (or another place) points to them.
    #[test]
    fn force_skips_the_configured_proxy_sockets() {
        let (_dir, ctx) = context();
        let custom = ctx.paths.home.join("run/proxy.sock");
        let forward = ctx.paths.home.join("run/forward.sock");
        write_config(
            &ctx,
            &format!(
                "version = 2\n[daemon]\nsocket = \"{}\"\nforward_socket = \"{}\"\n",
                custom.display(),
                forward.display()
            ),
        );
        let mut env = full(&ctx);
        env.vars.insert("SSH_AUTH_SOCK".into(), custom.display().to_string());
        env.sockets.push(custom.clone());
        let mut report = Report::default();
        init_with(&ctx, &args(true, true, false), &env, None, &mut report).unwrap();
        let text = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(!text.contains("proxy.sock") && !text.contains("name = \"ssh-agent\""), "{text}");
        assert!(text.contains("add_to = \"gpg-agent\""), "{text}");

        // The detection itself, also through a link to the socket.
        let link = ctx.paths.home.join("link.sock");
        std::fs::create_dir_all(custom.parent().unwrap()).unwrap();
        std::fs::write(&custom, "").unwrap();
        std::os::unix::fs::symlink(&custom, &link).unwrap();
        let env = Fake {
            vars: [("SSH_AUTH_SOCK".to_owned(), link.display().to_string())].into(),
            sockets: vec![link],
            ..Fake::default()
        };
        assert!(detect(&env, &ctx.paths, std::slice::from_ref(&custom)).agents.is_empty());
        let original = format!("version = 2\n[daemon]\nforward_socket = \"{}\"\n", forward.display());
        let own = own_sockets(&ctx.paths, Some(&original));
        assert!(own.contains(&forward) && own.contains(&ctx.paths.agent_socket), "{own:?}");
    }

    #[test]
    fn dry_run_writes_nothing() {
        let (_dir, ctx) = context();
        let mut report = Report::default();
        init_with(&ctx, &args(true, false, true), &full(&ctx), None, &mut report).unwrap();
        assert!(report.text.contains("--- /dev/null\n"), "{}", report.text);
        assert!(!ctx.config_path.exists());
    }

    #[test]
    fn interactive_review() {
        let (_dir, ctx) = context();
        // ssh-agent: change the name; 1password: skip; gpg-agent: accept;
        // add_to (main, the renamed ssh-agent is no longer "ssh-agent"): change to main;
        // github: skip.
        let mut answers = Answers(VecDeque::from(["c", "main", "", "s", "", "c", "main", "s"]), Vec::new());
        let mut report = Report::default();
        init_with(&ctx, &args(false, false, false), &full(&ctx), Some(&mut answers), &mut report).unwrap();
        assert!(answers.0.is_empty());
        assert!(
            answers.1[0].starts_with("agent ssh-agent at ~/agents/ssh.sock: (a)ccept, (c)hange, (s)kip?")
        );
        assert!(answers.1[5].starts_with("add_to = gpg-agent"), "{:?}", answers.1);
        let text = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(text.contains("add_to = \"main\""), "{text}");
        assert!(text.contains("name = \"main\"\nsocket = \"~/agents/ssh.sock\""), "{text}");
        assert!(!text.contains("1password") && !text.contains("[source.github]"), "{text}");
        load_config(&ctx).unwrap();
    }

    /// What ctl adds after init lands above the closing hint, which stays last.
    #[test]
    fn later_commands_keep_the_hint_last() {
        let (_dir, ctx) = context();
        init_with(&ctx, &args(true, false, false), &Fake::default(), None, &mut Report::default()).unwrap();
        let mut doc = ConfigDocument::open(&ctx.config_path).unwrap();
        doc.add_upstream("main", "~/agents/main.sock").unwrap();
        doc.add_profile("work").unwrap();
        doc.save(&ctx.paths).unwrap();
        let text = std::fs::read_to_string(&ctx.config_path).unwrap();
        let hint = text.find("# Next: a profile").unwrap();
        assert!(text.find("[profile.work]").unwrap() < hint, "{text}");
        assert!(text.find("[[agent.upstream]]").unwrap() < hint, "{text}");
        assert!(text.ends_with("# no keys, no tokens, no gpg.\n"), "{text}");
    }

    #[test]
    fn timestamps() {
        assert_eq!(timestamp(0), "19700101T000000Z");
        assert_eq!(timestamp(1_795_340_096), "20261122T093456Z");
    }
}
