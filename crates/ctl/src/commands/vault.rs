//! `vault list|show|setup|forget`: the vaults the sources use, their settings and their
//! state. `vault unlock|lock` are in [`super::daemon`]; `check` shows the vault lines of
//! [`state`] as well.

use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use credential_bridge_config::edit::{EditError, KeepassxcKey};
use credential_bridge_config::paths::TargetOs;
use credential_bridge_config::{Config, KeepassxcConfig, VaultKind};
use credential_bridge_proto::ipc::control::{Request, Response};
use credential_bridge_proto::ipc::vault::VaultStatus;

use super::change::{RESTART_HINT, apply, path_value, tilde, uses_keepassxc};
use super::{
    CONTROL_TIMEOUT, Context, ask_terminal, connect, daemon_config, daemon_paths, in_path, load_config,
    printable,
};
use crate::cli::{UnlockArgs, VaultCommand, VaultForgetArgs, VaultNameArg, VaultSetupArgs};
use crate::control::ControlError;
use crate::report::{Line, Report, Status};

/// The vaults `vault setup|forget|show` take, for messages.
const VAULT_NAMES: &str = "1password, bitwarden, keepassxc, keychain, secret-service, pass, cmd";

/// Directories (below the home directory) where `vault setup keepassxc` looks for a
/// `.kdbx` file to offer; only their own entries, not their subdirectories.
const DATABASE_DIRS: &[&str] = &["", "Documents", "Dropbox", "Nextcloud", "Sync"];

/// Runs a `vault` subcommand.
pub fn vault(ctx: &Context, command: &VaultCommand, report: &mut Report) -> anyhow::Result<()> {
    match command {
        VaultCommand::List => {
            let config = load_config(ctx)?;
            let live = live(ctx, &config);
            report.show(&list_text(ctx, &config, &live, TargetOs::current()));
            Ok(())
        }
        VaultCommand::Show(VaultNameArg { vault }) => {
            let vault = vault_kind(vault)?;
            let config = load_config(ctx)?;
            let live = live(ctx, &config);
            report.show(&show_text(ctx, &config, vault, &live, TargetOs::current()));
            Ok(())
        }
        VaultCommand::Setup(args) => {
            let interactive = !args.yes && std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
            setup(ctx, args, interactive.then_some(&mut Terminal as &mut dyn SetupIo), report)
        }
        VaultCommand::Forget(args) => forget(ctx, args, TargetOs::current(), report),
        VaultCommand::Unlock(args) => super::daemon::unlock(ctx, args),
        VaultCommand::Lock(args) => super::daemon::lock(ctx, args),
    }
}

/// A vault by its name on the command line (`op` and `bw` also do).
fn vault_kind(name: &str) -> anyhow::Result<VaultKind> {
    let vault: VaultKind =
        name.parse().map_err(|_| anyhow::anyhow!("unknown vault {name:?}; vaults: {VAULT_NAMES}"))?;
    if vault == VaultKind::HashiVault {
        bail!("vault (HashiCorp Vault) is not supported yet");
    }
    Ok(vault)
}

// ── what the configuration says ────────────────────────────────────────────────────

/// One vault the configuration uses or sets up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VaultUse {
    /// The vault.
    pub vault: VaultKind,
    /// `(source, reference)` for each secret reference into it.
    pub references: Vec<(String, String)>,
}

/// The vaults the sources reference, and `keepassxc` if `[vault.keepassxc]` sets it up
/// without a reference, in [`VaultKind::ALL`] order.
pub(crate) fn vaults_in(config: &Config) -> Vec<VaultUse> {
    VaultKind::ALL
        .into_iter()
        .filter_map(|vault| {
            let references = references_to(config, vault);
            let configured = vault == VaultKind::KeePassXc && keepassxc_cli_used(config);
            (configured || !references.is_empty()).then_some(VaultUse { vault, references })
        })
        .collect()
}

/// `(source, reference)` for each secret reference into `vault`.
fn references_to(config: &Config, vault: VaultKind) -> Vec<(String, String)> {
    config
        .sources
        .values()
        .flat_map(|source| {
            source
                .kind
                .secret_refs()
                .into_iter()
                .filter(|reference| reference.vault() == vault)
                .map(|reference| (source.name.clone(), reference.to_string()))
        })
        .collect()
}

/// The 1Password hint for its sources with `cache = false`: the bridge keeps no token of
/// theirs, so every git request reads the reference and asks for approval in the app.
/// `None` for other vaults or without such a source.
fn uncached_hint(config: &Config, vault: VaultKind) -> Option<String> {
    if vault != VaultKind::OnePassword {
        return None;
    }
    let names: Vec<&str> = config
        .sources
        .values()
        .filter(|source| !source.cache)
        .filter(|source| source.kind.secret_refs().iter().any(|reference| reference.vault() == vault))
        .map(|source| source.name.as_str())
        .collect();
    let (noun, verb) = if names.len() == 1 { ("source", "has") } else { ("sources", "have") };
    (!names.is_empty()).then(|| {
        format!(
            "{noun} {} {verb} cache = false: each git request asks for approval in the 1Password app",
            names.join(", ")
        )
    })
}

/// The names of the sources in `references`, each once.
fn source_names(references: &[(String, String)]) -> Vec<&str> {
    let mut names: Vec<&str> = references.iter().map(|(source, _)| source.as_str()).collect();
    names.dedup();
    names
}

/// The tools a vault needs locally, any of which will do. Empty: nothing to check.
pub(crate) fn vault_tools(config: &Config, vault: VaultKind) -> &'static [&'static str] {
    match vault {
        VaultKind::OnePassword => &["op"],
        VaultKind::Bitwarden => &["bw"],
        VaultKind::KeePassXc if keepassxc_cli_used(config) => &["keepassxc-cli"],
        VaultKind::Pass => &["pass", "gopass"],
        VaultKind::Command => &["sh"],
        VaultKind::HashiVault => &["vault"],
        VaultKind::KeePassXc | VaultKind::Keychain | VaultKind::SecretService => &[],
    }
}

/// Whether `ctl vault unlock` is how this vault gets unlocked with this configuration.
pub(crate) fn needs_unlock_command(config: &Config, vault: VaultKind) -> bool {
    match vault {
        VaultKind::KeePassXc => keepassxc_cli_used(config),
        other => other.has_unlock_session(),
    }
}

/// Whether KeePassXC is reached through `keepassxc-cli` (a database is configured)
/// rather than the app's Secret Service.
pub(crate) fn keepassxc_cli_used(config: &Config) -> bool {
    config.vault.keepassxc.database.is_some()
}

/// The settings of `vault` in the configuration, `-` if it has none.
fn settings_text(ctx: &Context, config: &Config, vault: VaultKind) -> String {
    if vault != VaultKind::KeePassXc {
        return "-".to_owned();
    }
    let keepassxc = &config.vault.keepassxc;
    match (&keepassxc.database, &keepassxc.key_file) {
        (Some(database), Some(key_file)) => {
            format!("database {}, key file {}", tilde(&ctx.paths, database), tilde(&ctx.paths, key_file))
        }
        (Some(database), None) => format!("database {}", tilde(&ctx.paths, database)),
        (None, _) => "-".to_owned(),
    }
}

/// How the bridge reaches `vault` and how it gets unlocked.
fn access_text(config: &Config, vault: VaultKind) -> (&'static str, &'static str) {
    match vault {
        VaultKind::OnePassword => ("op, the 1Password CLI", "each read is approved in the 1Password app"),
        VaultKind::Bitwarden => (
            "bw, the Bitwarden CLI (log in once with bw login)",
            "credential-bridge-ctl vault unlock bitwarden opens a session (8h by default)",
        ),
        VaultKind::KeePassXc if keepassxc_cli_used(config) => (
            "keepassxc-cli on the database file",
            "credential-bridge-ctl vault unlock keepassxc opens a session (8h by default)",
        ),
        VaultKind::KeePassXc => {
            ("the KeePassXC app's Secret Service (Linux)", "open the database in the KeePassXC app")
        }
        VaultKind::Keychain => ("the macOS Keychain", "with your login"),
        VaultKind::SecretService => {
            ("the Secret Service over D-Bus (GNOME Keyring, KWallet, KeePassXC)", "with your login")
        }
        VaultKind::Pass => ("pass or gopass", "gpg-agent asks with its pinentry"),
        VaultKind::Command => ("sh -c with the command", "up to the script"),
        VaultKind::HashiVault => ("not supported yet", "-"),
    }
}

// ── what the daemon says ───────────────────────────────────────────────────────────

/// The vault state from the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Live {
    /// The daemon answered; the vaults its vault worker reported.
    Running(Vec<VaultStatus>),
    /// No daemon is running.
    NotRunning,
    /// The daemon could not be asked.
    Failed(String),
}

/// Asks the daemon for the vault state (control request `Status`).
pub(crate) fn live(ctx: &Context, config: &Config) -> Live {
    let daemon = daemon_config(ctx, Some(config));
    let status =
        connect(&daemon, CONTROL_TIMEOUT).and_then(|mut client| match client.request(&Request::Status)? {
            Response::Status(status) => Ok(status),
            _ => Err(ControlError::Unexpected),
        });
    match status {
        Ok(status) => Live::Running(status.vaults),
        Err(ControlError::NotRunning(_)) => Live::NotRunning,
        Err(error) => Live::Failed(error.to_string()),
    }
}

/// The state of one vault: availability of its tool and how it is unlocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct State {
    /// The outcome.
    pub status: Status,
    /// e.g. `locked`, `unlocked, expires in 7h59m`, `bw not installed`.
    pub text: String,
    /// What to do next: a ctl command without `credential-bridge-ctl`, e.g.
    /// `vault unlock bitwarden`.
    pub next: Option<String>,
}

impl State {
    fn new(status: Status, text: impl Into<String>, next: Option<String>) -> State {
        State { status, text: text.into(), next }
    }

    /// The `check` line for `vault`.
    pub(crate) fn line(&self, label: String) -> Line {
        let line = Line::new(self.status, label, self.text.clone());
        match &self.next {
            Some(next) => line.with_hint(format!("credential-bridge-ctl {next}")),
            None => line,
        }
    }

    /// The state column of `vault list`: `⚠ locked → vault unlock bitwarden`.
    fn cell(&self) -> String {
        match &self.next {
            Some(next) => format!("{} {} → {next}", self.status.symbol(), self.text),
            None => format!("{} {}", self.status.symbol(), self.text),
        }
    }
}

/// The state of `vault` from `live`; without a daemon only whether its tool is installed.
pub(crate) fn state(config: &Config, vault: VaultKind, live: &Live) -> State {
    let reported = match live {
        Live::Running(vaults) => vaults.iter().find(|status| status.vault == vault.name()),
        Live::NotRunning | Live::Failed(_) => None,
    };
    let Some(status) = reported else {
        let tools = vault_tools(config, vault);
        if !tools.is_empty() && !tools.iter().any(|tool| in_path(tool)) {
            return State::new(Status::Fail, format!("{} not installed", tools.join(" or ")), None);
        }
        let why = match live {
            Live::Running(_) => "unknown: the daemon reports vaults once a source uses one".to_owned(),
            Live::NotRunning => "unknown (daemon not running)".to_owned(),
            Live::Failed(error) => format!("unknown ({})", printable(error)),
        };
        return State::new(Status::Warn, why, None);
    };
    let note = status.note.as_deref().map(printable);
    if !status.available {
        let next = (vault == VaultKind::KeePassXc && keepassxc_cli_used(config))
            .then(|| "vault setup keepassxc".to_owned());
        return State::new(Status::Fail, note.unwrap_or_else(|| "not available".to_owned()), next);
    }
    if let Some(until) = status.unlocked_until {
        return State::new(Status::Ok, format!("unlocked, expires {}", super::relative_time(until)), None);
    }
    if needs_unlock_command(config, vault) {
        return State::new(Status::Warn, "locked", Some(format!("vault unlock {}", vault.name())));
    }
    let text = match vault {
        VaultKind::OnePassword => "app approval".to_owned(),
        VaultKind::Pass => match note {
            Some(note) => format!("gpg-agent, {note}"),
            None => "gpg-agent".to_owned(),
        },
        VaultKind::Keychain | VaultKind::SecretService => "with login".to_owned(),
        VaultKind::KeePassXc => "with the KeePassXC app".to_owned(),
        VaultKind::Command => "up to the script".to_owned(),
        VaultKind::Bitwarden | VaultKind::HashiVault => note.unwrap_or_else(|| "available".to_owned()),
    };
    State::new(Status::Ok, text, None)
}

/// The `check` lines of the vaults: the same as `vault list`, as report lines.
pub(crate) fn check_lines(config: &Config, live: &Live) -> Vec<Line> {
    vaults_in(config)
        .into_iter()
        .map(|used| {
            let mut line = state(config, used.vault, live).line(format!("vault {}", used.vault));
            if used.references.is_empty() {
                line.detail.push_str("; no source uses it");
            }
            line
        })
        .collect()
}

// ── vault list, vault show ─────────────────────────────────────────────────────────

/// The table `vault list` prints.
fn list_text(ctx: &Context, config: &Config, live: &Live, os: TargetOs) -> String {
    let used = vaults_in(config);
    let mut out = String::new();
    if used.is_empty() {
        out.push_str(
            "no vault in use: sources take secrets by reference, e.g.\n  \
             credential-bridge-ctl source add github work --auth pat --token op://Dev/github/token\n",
        );
    } else {
        let rows: Vec<[String; 4]> = used
            .iter()
            .map(|used| {
                let sources = source_names(&used.references);
                [
                    used.vault.name().to_owned(),
                    if sources.is_empty() { "no source".to_owned() } else { sources.join(", ") },
                    settings_text(ctx, config, used.vault),
                    state(config, used.vault, live).cell(),
                ]
            })
            .collect();
        let header = ["VAULT", "USED BY", "SETTINGS", "STATE"];
        let widths: Vec<usize> = (0..3)
            .map(|column| {
                rows.iter()
                    .map(|row| row[column].chars().count())
                    .max()
                    .unwrap_or(0)
                    .max(header[column].len())
            })
            .collect();
        let line = |cells: [&str; 4]| {
            format!(
                "{:<w0$}  {:<w1$}  {:<w2$}  {}\n",
                cells[0],
                cells[1],
                cells[2],
                cells[3],
                w0 = widths[0],
                w1 = widths[1],
                w2 = widths[2]
            )
        };
        out.push_str(&line(header));
        for row in &rows {
            out.push_str(&line([&row[0], &row[1], &row[2], &row[3]]));
        }
    }
    if let Some(hint) = uncached_hint(config, VaultKind::OnePassword) {
        out.push_str(&format!("\n1password: {hint}\n"));
    }
    if *live == Live::NotRunning {
        out.push_str(
            "\nthe daemon is not running: tool and unlock state unknown → credential-bridge-ctl \
             daemon start\n",
        );
    }
    let unused: Vec<&str> = VaultKind::ALL
        .into_iter()
        .filter(|vault| !used.iter().any(|used| used.vault == *vault))
        .filter(|vault| match vault {
            VaultKind::HashiVault => false,
            VaultKind::Keychain => os == TargetOs::MacOs,
            VaultKind::SecretService => os == TargetOs::Linux,
            _ => true,
        })
        .map(VaultKind::name)
        .collect();
    if !unused.is_empty() {
        out.push_str(&format!(
            "\nnot in use: {}; credential-bridge-ctl vault show NAME tells how to use one\n",
            unused.join(", ")
        ));
    }
    out
}

/// What `vault show` prints.
fn show_text(ctx: &Context, config: &Config, vault: VaultKind, live: &Live, os: TargetOs) -> String {
    let references = references_to(config, vault);
    let mut out = format!("vault      {vault}\n");
    if references.is_empty() {
        out.push_str("used by    no source\n");
    }
    for (index, (source, reference)) in references.iter().enumerate() {
        let key = if index == 0 { "used by" } else { "" };
        out.push_str(&format!("{key:<10} {source}: {reference}\n"));
    }
    let settings = match (vault, keepassxc_cli_used(config)) {
        (VaultKind::KeePassXc, true) => format!("{} ([vault.keepassxc])", settings_text(ctx, config, vault)),
        (VaultKind::KeePassXc, false) => "none ([vault.keepassxc] is not set)".to_owned(),
        _ => "none needed".to_owned(),
    };
    out.push_str(&format!("settings   {settings}\n"));
    let (access, unlock) = access_text(config, vault);
    out.push_str(&format!("access     {access}\nunlock     {unlock}\n"));
    if let Live::Running(vaults) = live
        && let Some(note) =
            vaults.iter().find(|status| status.vault == vault.name()).and_then(|s| s.note.as_deref())
    {
        out.push_str(&format!("tool       {}\n", printable(note)));
    }
    let state = state(config, vault, live);
    out.push_str(&format!("state      {} {}\n", state.status.symbol(), state.text));
    if let Some(next) = &state.next {
        out.push_str(&format!("           → credential-bridge-ctl {next}\n"));
    }
    for hint in hints(config, vault, &references, os) {
        out.push_str(&format!("hint       {hint}\n"));
    }
    out
}

/// Advice for `vault show`.
fn hints(config: &Config, vault: VaultKind, references: &[(String, String)], os: TargetOs) -> Vec<String> {
    let mut hints = Vec::new();
    match vault {
        VaultKind::KeePassXc if !keepassxc_cli_used(config) => {
            if os == TargetOs::MacOs {
                hints.push(
                    "on macOS keepassxc:// needs the database file: credential-bridge-ctl vault setup keepassxc"
                        .to_owned(),
                );
            } else {
                hints.push(
                    "to use keepassxc-cli on one database file instead of the app: credential-bridge-ctl \
                     vault setup keepassxc"
                        .to_owned(),
                );
            }
        }
        VaultKind::KeePassXc => hints.push(
            "changes to [vault.keepassxc] take effect when the daemon restarts; credential-bridge-ctl \
             vault forget keepassxc removes them"
                .to_owned(),
        ),
        VaultKind::Keychain if os != TargetOs::MacOs => {
            hints.push("the Keychain exists only on macOS".to_owned())
        }
        VaultKind::SecretService if os != TargetOs::Linux => {
            hints.push("the Secret Service exists only on Linux".to_owned());
        }
        _ => {}
    }
    hints.extend(uncached_hint(config, vault));
    if references.is_empty() {
        hints.push(format!(
            "use it with a reference in source add, e.g. --token {}",
            example_reference(vault)
        ));
    } else {
        hints.push("test a source with: credential-bridge-ctl source test NAME".to_owned());
    }
    hints
}

/// An example reference into `vault`.
fn example_reference(vault: VaultKind) -> &'static str {
    match vault {
        VaultKind::OnePassword => "op://Dev/github-pat/credential",
        VaultKind::Bitwarden => "bw://gitlab-team/token",
        VaultKind::KeePassXc => "keepassxc://Dev/forgejo/password",
        VaultKind::Keychain => "keychain://github.example.com/ci-bot",
        VaultKind::SecretService => "secret-service://service=gitea",
        VaultKind::Pass => "pass://dev/codeberg-token",
        VaultKind::Command => "'cmd:my-token-script --org my-org'",
        VaultKind::HashiVault => "vault://kv/ci/github#token",
    }
}

// ── vault setup ────────────────────────────────────────────────────────────────────

/// How `vault setup` asks and acts beyond the configuration file; replaced in tests.
pub(crate) trait SetupIo {
    /// Shows `question` and returns the trimmed answer; end of input is an error of kind
    /// [`std::io::ErrorKind::UnexpectedEof`].
    fn ask(&mut self, question: &str) -> std::io::Result<String>;
    /// Restarts the daemon service so it reads `[vault]` again.
    fn restart_daemon(&mut self, ctx: &Context) -> anyhow::Result<()>;
    /// `vault unlock keepassxc`.
    fn unlock(&mut self, ctx: &Context) -> anyhow::Result<()>;
}

/// The terminal and the real service.
struct Terminal;

impl SetupIo for Terminal {
    fn ask(&mut self, question: &str) -> std::io::Result<String> {
        ask_terminal(question)
    }

    fn restart_daemon(&mut self, ctx: &Context) -> anyhow::Result<()> {
        super::service::restart(ctx)
    }

    fn unlock(&mut self, ctx: &Context) -> anyhow::Result<()> {
        let args =
            UnlockArgs { vault: VaultKind::KeePassXc.name().to_owned(), ttl: None, password_stdin: false };
        super::daemon::unlock(ctx, &args)
    }
}

/// `vault setup NAME`: KeePassXC asks for (or takes) its database and key file, writes
/// `[vault.keepassxc]` and offers to restart the daemon and unlock; every other vault
/// needs no setup and says why, with its state. `io` is `None` without a terminal or
/// with `--yes`.
pub(crate) fn setup(
    ctx: &Context,
    args: &VaultSetupArgs,
    io: Option<&mut dyn SetupIo>,
    report: &mut Report,
) -> anyhow::Result<()> {
    let vault = vault_kind(&args.vault)?;
    if vault != VaultKind::KeePassXc {
        for (used, flag) in [
            (args.database.is_some(), "--database"),
            (args.key_file.is_some(), "--key-file"),
            (args.no_key_file, "--no-key-file"),
        ] {
            if used {
                bail!("{flag} is only for keepassxc");
            }
        }
        let config = load_config(ctx)?;
        let live = live(ctx, &config);
        no_setup(&config, vault, &live, report);
        return Ok(());
    }
    match setup_keepassxc(ctx, args, io, report) {
        Err(error) if is_eof(&error) => bail!("aborted (no answer); nothing more was done"),
        other => other,
    }
}

/// Whether `error` is the end of input of a question.
fn is_eof(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::UnexpectedEof)
}

/// The report of `vault setup` for a vault without settings.
fn no_setup(config: &Config, vault: VaultKind, live: &Live, report: &mut Report) {
    let why = match vault {
        VaultKind::OnePassword => "op reads each reference; the 1Password app approves it",
        VaultKind::Bitwarden => "bw reads each reference once you are logged in (bw login)",
        VaultKind::Keychain => "references name the Keychain item; your login unlocks it",
        VaultKind::SecretService => "references name the item's attributes; your login unlocks the keyring",
        VaultKind::Pass => "pass or gopass reads each entry; gpg-agent unlocks the store",
        VaultKind::Command => "the command does what it needs; unlocking is up to the script",
        VaultKind::KeePassXc | VaultKind::HashiVault => unreachable!("handled by the caller"),
    };
    let tools = vault_tools(config, vault);
    let tool = match live {
        Live::Running(vaults) => vaults.iter().find(|status| status.vault == vault.name()).map(|status| {
            let name = tools.first().copied().unwrap_or(vault.name());
            if status.available { format!("{name} ✓") } else { format!("{name} ✗") }
        }),
        Live::NotRunning | Live::Failed(_) => None,
    };
    let mut detail = format!("needs no setup: {why}");
    if let Some(tool) = tool {
        detail = format!("{detail}; {tool}");
    }
    let mut line = Line::ok(vault.name(), detail);
    if vault.has_unlock_session() {
        line = line.with_hint(format!("unlock with credential-bridge-ctl vault unlock {}", vault.name()));
    }
    report.push(line);
    report.push(state(config, vault, live).line("state".to_owned()));
}

/// A file `vault setup keepassxc` writes: as written into the configuration, and where it is.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChosenFile {
    /// `~/…` or absolute, as written.
    text: String,
    /// The path with `~/` expanded.
    path: PathBuf,
}

/// Checks `text` given for `what` (`database`, `key file`): it must name an existing
/// regular file.
fn chosen_file(ctx: &Context, what: &str, text: &str) -> anyhow::Result<ChosenFile> {
    let text = path_value(text)?;
    let path = ctx.paths.expand_home(Path::new(&text));
    let meta = std::fs::metadata(&path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => anyhow::anyhow!("the {what} {text} does not exist"),
        _ => anyhow::anyhow!("cannot read the {what} {text}: {error}"),
    })?;
    if !meta.is_file() {
        bail!("the {what} {text} is not a regular file");
    }
    Ok(ChosenFile { text, path })
}

/// The `.kdbx` files directly in [`DATABASE_DIRS`] below `home`.
fn find_databases(home: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for dir in DATABASE_DIRS {
        let Ok(entries) = std::fs::read_dir(home.join(dir)) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|extension| extension == "kdbx") && path.is_file() {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// A question of [`ask_file`].
struct FileQuestion<'a> {
    /// The label of warnings (`database`, `key file`).
    what: &'a str,
    /// The question.
    question: &'a str,
    /// What an empty answer takes.
    default: Option<&'a str>,
    /// Whether `-` (or, without default, an empty answer) means none.
    optional: bool,
    /// Files to choose from by number (1, 2, …), listed before the first question.
    choices: &'a [String],
}

/// Asks for a file until the answer names one; empty takes `default`, `-` (if
/// `optional`) means none, a number one of `choices`.
fn ask_file(
    ctx: &Context,
    io: &mut dyn SetupIo,
    report: &mut Report,
    ask: &FileQuestion<'_>,
) -> anyhow::Result<Option<ChosenFile>> {
    let FileQuestion { what, default, optional, choices, .. } = *ask;
    let question = if choices.is_empty() {
        ask.question.to_owned()
    } else {
        let listed: String =
            choices.iter().enumerate().map(|(index, file)| format!("  {}) {file}\n", index + 1)).collect();
        report.show(&format!("Found {} {what} files:\n{listed}", choices.len()));
        format!("{} (number or path)", ask.question)
    };
    loop {
        let prompt = match (default, optional) {
            (Some(default), true) => format!("{question} [{default}; - for none]: "),
            (Some(default), false) => format!("{question} [{default}]: "),
            (None, true) => format!("{question} [none]: "),
            (None, false) => format!("{question}: "),
        };
        let answer = io.ask(&prompt)?;
        let chosen = answer.parse::<usize>().ok().and_then(|number| choices.get(number.checked_sub(1)?));
        let text = match (answer.as_str(), default) {
            _ if chosen.is_some() => chosen.cloned().unwrap_or_default(),
            ("-", _) if optional => return Ok(None),
            ("", Some(default)) => default.to_owned(),
            ("", None) if optional => return Ok(None),
            ("", None) => {
                report.push(Line::warn(what, "a file is needed; Ctrl-D aborts"));
                continue;
            }
            (answer, _) => answer.to_owned(),
        };
        match chosen_file(ctx, what, &text) {
            Ok(file) => return Ok(Some(file)),
            Err(error) => report.push(Line::warn(what, format!("{error:#}; try again (Ctrl-D aborts)"))),
        }
    }
}

/// Asks a yes/no question; empty is yes.
fn confirm(io: &mut dyn SetupIo, question: &str) -> std::io::Result<bool> {
    loop {
        match io.ask(&format!("{question} [Y/n] "))?.to_lowercase().as_str() {
            "" | "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => {}
        }
    }
}

/// `vault setup keepassxc`.
fn setup_keepassxc(
    ctx: &Context,
    args: &VaultSetupArgs,
    mut io: Option<&mut dyn SetupIo>,
    report: &mut Report,
) -> anyhow::Result<()> {
    let config = load_config(ctx)?;
    let current = config.vault.keepassxc.clone();
    let current_database = current.database.as_deref().map(|path| tilde(&ctx.paths, path));
    let current_key_file = current.key_file.as_deref().map(|path| tilde(&ctx.paths, path));
    if io.is_some() && current.database.is_none() && TargetOs::current() == TargetOs::Linux {
        report.push(Line::ok(
            "keepassxc",
            "without a database file keepassxc:// uses the KeePassXC app; with one, keepassxc-cli opens that file",
        ));
    }

    let database = match (&args.database, io.as_deref_mut()) {
        (Some(database), _) => chosen_file(ctx, "database", database)?,
        (None, Some(io)) => {
            let found: Vec<String> =
                find_databases(&ctx.paths.home).iter().map(|path| tilde(&ctx.paths, path)).collect();
            let (default, choices) = match (&current_database, found.as_slice()) {
                (Some(current), _) => (Some(current.clone()), &[][..]),
                (None, [only]) => (Some(only.clone()), &[][..]),
                (None, several) => (None, several),
            };
            let ask = FileQuestion {
                what: "database",
                question: "KeePassXC database (.kdbx)",
                default: default.as_deref(),
                optional: false,
                choices,
            };
            ask_file(ctx, io, report, &ask)?.context("a database is needed")?
        }
        (None, None) => match &current_database {
            Some(database) => chosen_file(ctx, "database", database)?,
            None => bail!(
                "vault setup keepassxc needs --database PATH (the .kdbx file) when it cannot ask \
                 (no terminal, or --yes)"
            ),
        },
    };
    let key_file = match (&args.key_file, args.no_key_file, io.as_deref_mut()) {
        (Some(key_file), _, _) => Some(chosen_file(ctx, "key file", key_file)?),
        (None, true, _) => None,
        (None, false, Some(io)) => {
            let ask = FileQuestion {
                what: "key file",
                question: "Key file, if the database uses one",
                default: current_key_file.as_deref(),
                optional: true,
                choices: &[],
            };
            ask_file(ctx, io, report, &ask)?
        }
        (None, false, None) => {
            current_key_file.as_deref().map(|key_file| chosen_file(ctx, "key file", key_file)).transpose()?
        }
    };

    // Only what changed is written, so a path stays as it was written.
    let mut edits: Vec<(KeepassxcKey, Option<String>)> = Vec::new();
    if current.database.as_deref() != Some(database.path.as_path()) {
        edits.push((KeepassxcKey::Database, Some(database.text.clone())));
    }
    if current.key_file != key_file.as_ref().map(|file| file.path.clone()) {
        edits.push((KeepassxcKey::KeyFile, key_file.as_ref().map(|file| file.text.clone())));
    }
    let summary = edits
        .iter()
        .map(|(key, value)| match value {
            Some(value) => format!("{} = {value}", key.name()),
            None => format!("{} removed", key.name()),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let summary = format!("[vault.keepassxc] {summary}");
    let applied = apply(ctx, args.write.dry_run, report, &summary, |doc| {
        edits.iter().try_for_each(|(key, value)| doc.set_keepassxc(*key, value.as_deref()))
    })?;
    if args.write.dry_run {
        return Ok(());
    }
    let wanted =
        KeepassxcConfig { database: Some(database.path.clone()), key_file: key_file.map(|file| file.path) };
    let unlock_hint = "credential-bridge-ctl vault unlock keepassxc";
    // The files the running daemon started with: a restart is due whenever they are not
    // those of the file, also when an earlier setup changed it without a restart.
    let daemon = daemon_config(ctx, Some(&config));
    let used = daemon_paths(&daemon);
    let stale = match &used {
        Ok(used) => !uses_keepassxc(used, &wanted),
        Err(_) => applied.is_some(),
    };
    let Some(io) = io else {
        if stale {
            report.push(Line::ok("next", "after the restart, unlock the database").with_hint(unlock_hint));
        }
        return Ok(());
    };
    match &used {
        Ok(_) => {}
        Err(ControlError::NotRunning(_)) => {
            report.push(
                Line::warn("daemon", "not running; it reads [vault.keepassxc] when it starts")
                    .with_hint(format!("credential-bridge-ctl daemon start, then {unlock_hint}")),
            );
            return Ok(());
        }
        Err(error) => {
            report.push(
                Line::warn("daemon", error.to_string())
                    .with_hint(format!("{RESTART_HINT}\nthen {unlock_hint}")),
            );
            return Ok(());
        }
    }
    if stale {
        if !confirm(io, "Restart the daemon now so it uses the database?")? {
            report.push(
                Line::warn("daemon", "still uses the old [vault] settings")
                    .with_hint(format!("{RESTART_HINT}\nthen {unlock_hint}")),
            );
            return Ok(());
        }
        match io.restart_daemon(ctx) {
            Ok(()) => report.push(Line::ok("daemon", "restarted; it uses the database now")),
            Err(error) => {
                report
                    .push(Line::warn("daemon", format!("restart failed: {error:#}")).with_hint(RESTART_HINT));
                return Ok(());
            }
        }
    }
    if !confirm(io, "Unlock keepassxc now?")? {
        report.push(Line::ok("unlock", "later").with_hint(unlock_hint));
        return Ok(());
    }
    if let Err(error) = io.unlock(ctx) {
        report.push(Line::warn("unlock", format!("{error:#}")).with_hint(unlock_hint));
    }
    Ok(())
}

// ── vault forget ───────────────────────────────────────────────────────────────────

/// `vault forget NAME`: removes `[vault.NAME]` and ends the vault's unlock session; the
/// vault itself is untouched. Warns about sources that still reference it.
pub(crate) fn forget(
    ctx: &Context,
    args: &VaultForgetArgs,
    os: TargetOs,
    report: &mut Report,
) -> anyhow::Result<()> {
    let vault = vault_kind(&args.vault)?;
    if vault != VaultKind::KeePassXc {
        let lock = if vault.has_unlock_session() {
            format!("; to end its unlock session: credential-bridge-ctl vault lock {vault}")
        } else {
            String::new()
        };
        bail!("{vault} has no settings in the configuration, so there is nothing to forget{lock}");
    }
    let before = load_config(ctx).ok();
    let database = before.as_ref().and_then(|config| config.vault.keepassxc.database.clone());
    let applied = apply(ctx, args.write.dry_run, report, "[vault.keepassxc] removed", |doc| {
        if doc.remove_keepassxc() {
            Ok(())
        } else {
            Err(EditError::NotFound {
                table: "[vault.keepassxc] in the configuration: nothing to forget".to_owned(),
            })
        }
    })?;
    if !args.write.dry_run && applied.is_some() {
        let daemon = daemon_config(ctx, before.as_ref());
        let request = Request::Lock { vault: Some(vault.name().to_owned()) };
        match connect(&daemon, CONTROL_TIMEOUT).and_then(|mut client| client.request(&request)) {
            Ok(Response::Locked) => report.push(Line::ok("session", "keepassxc locked")),
            Ok(_) => report.push(Line::warn("session", "unexpected answer from the daemon")),
            Err(ControlError::NotRunning(_)) => {
                report.push(Line::ok("session", "none open (daemon not running)"))
            }
            Err(error) => report.push(
                Line::warn("session", format!("could not end it: {error}"))
                    .with_hint("credential-bridge-ctl vault lock keepassxc"),
            ),
        }
        let file = database.map_or_else(String::new, |path| format!(" ({})", tilde(&ctx.paths, &path)));
        report.push(Line::ok("keepassxc", format!("forgotten; the database itself is untouched{file}")));
    }
    let users: Vec<(String, String)> =
        before.as_ref().map(|config| references_to(config, vault)).unwrap_or_default();
    if !users.is_empty() {
        let names = source_names(&users).join(", ");
        let detail = match os {
            TargetOs::Linux => format!(
                "source {names} still uses keepassxc:// references; without a database they go to the KeePassXC app"
            ),
            TargetOs::MacOs => {
                format!("source {names} still uses keepassxc:// references, which need a database")
            }
        };
        report.push(Line::warn("sources", detail).with_hint("credential-bridge-ctl vault setup keepassxc"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use credential_bridge_proto::ipc::control::{DaemonPaths, DaemonStatus};

    use super::*;
    use crate::cli::WriteArgs;
    use crate::commands::test_support::{context, fake_daemon, recording_daemon, write_config};

    /// A source per vault kind that needs no tool lookup (`cmd`), one into Bitwarden, one
    /// into KeePassXC.
    const SOURCES: &str = "version = 2\n\n[source.ci]\ntype = \"gitlab\"\nhost = \"gitlab.example.com\"\n\
                           token = \"bw://ci/token\"\n\n[source.home]\ntype = \"forgejo\"\nhost = \"git.example.org\"\n\
                           token = \"keepassxc://Dev/forgejo/password\"\n\n[source.ops]\ntype = \"gitlab\"\n\
                           host = \"gitlab.ops.example\"\ntoken = \"cmd:my-token-script\"\n\n[source.work]\n\
                           type = \"github\"\nauth = \"pat\"\ntoken = \"op://Dev/github/token\"\n";

    fn status(vault: &str, available: bool, unlocked_until: Option<u64>, note: Option<&str>) -> VaultStatus {
        VaultStatus { vault: vault.into(), available, unlocked_until, note: note.map(str::to_owned) }
    }

    fn daemon_status(ctx: &Context, vaults: Vec<VaultStatus>) -> Response {
        Response::Status(DaemonStatus {
            version: super::super::VERSION.into(),
            pid: 1,
            config: ctx.config_path.display().to_string(),
            paths: Default::default(),
            locked: false,
            upstreams: vec![],
            workers: vec![],
            vaults,
        })
    }

    fn run(ctx: &Context, command: VaultCommand) -> anyhow::Result<Report> {
        let mut report = Report::default();
        vault(ctx, &command, &mut report).map(|()| report)
    }

    fn text(ctx: &Context) -> String {
        std::fs::read_to_string(&ctx.config_path).unwrap()
    }

    #[test]
    fn list_without_daemon_shows_the_configuration_and_unknown_state() {
        let (dir, ctx) = context();
        let database = dir.path().join("db.kdbx");
        write_config(
            &ctx,
            &format!(
                "version = 2\n[source.ops]\ntype = \"gitlab\"\nhost = \"gl.example\"\ntoken = \"cmd:my-token-script\"\n\
                 [vault.keepassxc]\ndatabase = \"{}\"\n",
                database.display()
            ),
        );
        let list = run(&ctx, VaultCommand::List).unwrap().text;
        let lines: Vec<&str> = list.lines().collect();
        assert!(lines[0].starts_with("VAULT      USED BY    SETTINGS"), "{list}");
        assert!(lines[1].starts_with("keepassxc  no source  database ~/db.kdbx"), "{list}");
        assert!(lines[2].starts_with("cmd        ops        -"), "{list}");
        assert!(lines[2].ends_with("⚠ unknown (daemon not running)"), "{list}");
        assert!(list.contains("the daemon is not running: tool and unlock state unknown"), "{list}");
        assert!(list.contains("not in use: 1password, bitwarden"), "{list}");

        // `check` shows the same vaults, the unused one marked.
        let config = load_config(&ctx).unwrap();
        let checked = check_lines(&config, &Live::NotRunning);
        assert_eq!(checked.len(), 2);
        assert_eq!(checked[0].label, "vault keepassxc");
        assert!(checked[0].detail.ends_with("; no source uses it"), "{}", checked[0].detail);
        assert_eq!(checked[1].label, "vault cmd");
        assert_eq!(checked[1].detail, "unknown (daemon not running)");
    }

    #[test]
    fn list_with_daemon_shows_live_state_and_next_steps() {
        let (_dir, ctx) = context();
        write_config(&ctx, SOURCES);
        let soon = super::super::now_secs() + 3600;
        fake_daemon(
            &ctx.paths.control_socket,
            daemon_status(
                &ctx,
                vec![
                    status("1password", true, None, None),
                    status("bitwarden", true, None, None),
                    status("keepassxc", true, None, None),
                    status("cmd", true, None, None),
                    status("pass", false, None, Some("pass not found in PATH")),
                ],
            ),
        );
        let list = run(&ctx, VaultCommand::List).unwrap().text;
        let row = |vault: &str| {
            list.lines().find(|line| line.starts_with(&format!("{vault} "))).unwrap().to_owned()
        };
        assert!(row("1password").contains("work") && row("1password").ends_with("✓ app approval"), "{list}");
        assert!(row("bitwarden").ends_with("⚠ locked → vault unlock bitwarden"), "{list}");
        assert!(row("keepassxc").ends_with("✓ with the KeePassXC app"), "{list}");
        assert!(row("cmd").ends_with("✓ up to the script"), "{list}");
        assert!(!list.contains("daemon is not running"), "{list}");
        assert!(!list.contains("cache = false"), "{list}");

        let (_dir, ctx) = context();
        write_config(&ctx, SOURCES);
        fake_daemon(
            &ctx.paths.control_socket,
            daemon_status(&ctx, vec![status("bitwarden", true, Some(soon), None)]),
        );
        let list = run(&ctx, VaultCommand::List).unwrap().text;
        assert!(list.contains("✓ unlocked, expires in 1h"), "{list}");
    }

    /// 1Password sources with `cache = false` ask for approval on every git request.
    #[test]
    fn uncached_1password_sources_are_pointed_out() {
        let (_dir, ctx) = context();
        let text = SOURCES
            .replace(
                "token = \"op://Dev/github/token\"\n",
                "token = \"op://Dev/github/token\"\ncache = false\n",
            )
            .replace("token = \"bw://ci/token\"\n", "token = \"bw://ci/token\"\ncache = false\n");
        write_config(&ctx, &text);
        let hint = "source work has cache = false: each git request asks for approval in the 1Password app";
        let list = run(&ctx, VaultCommand::List).unwrap().text;
        assert!(list.contains(&format!("\n1password: {hint}\n")), "{list}");
        let show =
            |vault: &str| run(&ctx, VaultCommand::Show(VaultNameArg { vault: vault.into() })).unwrap().text;
        assert!(show("1password").contains(&format!("hint       {hint}\n")), "{}", show("1password"));
        assert!(!show("bitwarden").contains("cache = false"), "only 1Password asks per read");

        let mut config = load_config(&ctx).unwrap();
        let mut second = config.sources["work"].clone();
        second.name = "prod".into();
        config.sources.insert("prod".into(), second);
        assert_eq!(
            uncached_hint(&config, VaultKind::OnePassword).unwrap(),
            "sources prod, work have cache = false: each git request asks for approval in the 1Password app"
        );
    }

    #[test]
    fn list_without_vaults_says_how_to_use_one() {
        let (_dir, ctx) = context();
        let list = run(&ctx, VaultCommand::List).unwrap().text;
        assert!(list.starts_with("no vault in use: sources take secrets by reference"), "{list}");
    }

    #[test]
    fn show_explains_one_vault() {
        let (dir, ctx) = context();
        write_config(&ctx, &format!("{SOURCES}\n[vault.keepassxc]\ndatabase = \"~/db.kdbx\"\n"));
        let database = dir.path().join("db.kdbx").display().to_string();
        fake_daemon(
            &ctx.paths.control_socket,
            daemon_status(
                &ctx,
                vec![status("keepassxc", true, None, Some(&format!("keepassxc-cli on {database}")))],
            ),
        );
        let show = run(&ctx, VaultCommand::Show(VaultNameArg { vault: "keepassxc".into() })).unwrap().text;
        assert!(show.contains("used by    home: keepassxc://Dev/forgejo/password\n"), "{show}");
        assert!(show.contains("settings   database ~/db.kdbx ([vault.keepassxc])\n"), "{show}");
        assert!(show.contains("access     keepassxc-cli on the database file\n"), "{show}");
        assert!(show.contains(&format!("tool       keepassxc-cli on {database}\n")), "{show}");
        assert!(
            show.contains("state      ⚠ locked\n           → credential-bridge-ctl vault unlock keepassxc\n")
        );
        assert!(
            show.contains("hint       test a source with: credential-bridge-ctl source test NAME"),
            "{show}"
        );

        // An unused vault, and KeePassXC without a database on macOS.
        let config = load_config(&ctx).unwrap();
        let show = show_text(&ctx, &config, VaultKind::Pass, &Live::NotRunning, TargetOs::Linux);
        assert!(show.contains("used by    no source\n"), "{show}");
        assert!(show.contains("unlock     gpg-agent asks with its pinentry\n"), "{show}");
        assert!(show.contains("e.g. --token pass://dev/codeberg-token"), "{show}");
        let empty = Config::empty(&ctx.paths);
        let show = show_text(&ctx, &empty, VaultKind::KeePassXc, &Live::NotRunning, TargetOs::MacOs);
        assert!(show.contains("hint       on macOS keepassxc:// needs the database file"), "{show}");
        assert!(run(&ctx, VaultCommand::Show(VaultNameArg { vault: "lastpass".into() })).is_err());
    }

    /// Scripted answers through [`super::super::ask_on`], and what was restarted or
    /// unlocked.
    struct FakeIo {
        input: Cursor<Vec<u8>>,
        asked: Vec<u8>,
        restarts: usize,
        unlocks: usize,
    }

    impl FakeIo {
        fn new(answers: &str) -> FakeIo {
            FakeIo {
                input: Cursor::new(answers.as_bytes().to_vec()),
                asked: Vec::new(),
                restarts: 0,
                unlocks: 0,
            }
        }

        fn asked(&self) -> String {
            String::from_utf8_lossy(&self.asked).into_owned()
        }
    }

    impl SetupIo for FakeIo {
        fn ask(&mut self, question: &str) -> std::io::Result<String> {
            super::super::ask_on(question, &mut self.input, &mut self.asked)
        }

        fn restart_daemon(&mut self, _ctx: &Context) -> anyhow::Result<()> {
            self.restarts += 1;
            Ok(())
        }

        fn unlock(&mut self, _ctx: &Context) -> anyhow::Result<()> {
            self.unlocks += 1;
            Ok(())
        }
    }

    fn setup_args(vault: &str) -> VaultSetupArgs {
        VaultSetupArgs {
            vault: vault.into(),
            database: None,
            key_file: None,
            no_key_file: false,
            yes: false,
            write: WriteArgs::default(),
        }
    }

    fn run_setup(
        ctx: &Context,
        args: &VaultSetupArgs,
        io: Option<&mut dyn SetupIo>,
    ) -> anyhow::Result<Report> {
        let mut report = Report::default();
        setup(ctx, args, io, &mut report).map(|()| report)
    }

    /// Wrong answers are asked again; the result is written; without a daemon nothing
    /// is restarted or unlocked.
    #[test]
    fn setup_keepassxc_asks_until_the_file_exists() {
        let (dir, ctx) = context();
        write_config(&ctx, SOURCES);
        let database = dir.path().join("vault").join("work.kdbx");
        std::fs::create_dir_all(database.parent().unwrap()).unwrap();
        std::fs::write(&database, "kdbx").unwrap();
        let answers = format!(
            "{missing}\n{folder}\n\n{database}\n\n",
            missing = dir.path().join("missing.kdbx").display(),
            folder = dir.path().join("vault").display(),
            database = database.display()
        );
        let mut io = FakeIo::new(&answers);
        let report = run_setup(&ctx, &setup_args("keepassxc"), Some(&mut io)).unwrap();
        assert!(report.text.contains("missing.kdbx does not exist; try again"), "{}", report.text);
        assert!(report.text.contains("is not a regular file; try again"), "{}", report.text);
        assert!(report.text.contains("a file is needed"), "{}", report.text);
        assert!(io.asked().contains("KeePassXC database (.kdbx): "), "{}", io.asked());
        assert!(io.asked().contains("Key file, if the database uses one [none]: "), "{}", io.asked());
        assert!(
            text(&ctx).ends_with(&format!("[vault.keepassxc]\ndatabase = \"{}\"\n", database.display())),
            "{}",
            text(&ctx)
        );
        assert!(
            report.text.contains("vault settings take effect when the daemon restarts"),
            "{}",
            report.text
        );
        assert!(
            report.text.contains("not running; it reads [vault.keepassxc] when it starts"),
            "{}",
            report.text
        );
        assert_eq!((io.restarts, io.unlocks), (0, 0));
    }

    #[test]
    fn setup_keepassxc_aborts_at_end_of_input() {
        let (_dir, ctx) = context();
        write_config(&ctx, SOURCES);
        let mut io = FakeIo::new("");
        let error = run_setup(&ctx, &setup_args("keepassxc"), Some(&mut io)).unwrap_err();
        assert!(error.to_string().starts_with("aborted (no answer)"), "{error}");
        assert_eq!(text(&ctx), SOURCES);
    }

    /// The one `.kdbx` in the home directory is offered; with the daemon running, setup
    /// restarts it and unlocks.
    #[test]
    fn setup_keepassxc_offers_the_database_found_and_restarts_and_unlocks() {
        let (dir, ctx) = context();
        write_config(&ctx, SOURCES);
        std::fs::write(dir.path().join("db.kdbx"), "kdbx").unwrap();
        let uses = pong_daemon(&ctx);
        let mut io = FakeIo::new("\n\ny\n\n");
        let report = run_setup(&ctx, &setup_args("keepassxc"), Some(&mut io)).unwrap();
        assert!(io.asked().contains("KeePassXC database (.kdbx) [~/db.kdbx]: "), "{}", io.asked());
        assert!(io.asked().contains("Restart the daemon now so it uses the database? [Y/n] "));
        assert!(io.asked().contains("Unlock keepassxc now? [Y/n] "));
        assert!(text(&ctx).ends_with("[vault.keepassxc]\ndatabase = \"~/db.kdbx\"\n"), "{}", text(&ctx));
        assert!(report.text.contains("restarted; it uses the database now"), "{}", report.text);
        assert_eq!((io.restarts, io.unlocks), (1, 1));
        uses.lock().unwrap().keepassxc_database = Some(dir.path().join("db.kdbx").display().to_string());

        // Again: nothing changes and the daemon uses the file, so no restart; declining the
        // unlock leaves the hint.
        let mut io = FakeIo::new("\n\nn\n");
        let report = run_setup(&ctx, &setup_args("keepassxc"), Some(&mut io)).unwrap();
        assert!(report.text.contains("unchanged"), "{}", report.text);
        assert!(!io.asked().contains("Restart"), "{}", io.asked());
        assert!(report.text.contains("→ credential-bridge-ctl vault unlock keepassxc"), "{}", report.text);
        assert_eq!((io.restarts, io.unlocks), (0, 0));

        // The daemon still uses other files (the restart was declined before): offered
        // again, although the file does not change.
        uses.lock().unwrap().keepassxc_database = None;
        let mut io = FakeIo::new("\n\ny\nn\n");
        let report = run_setup(&ctx, &setup_args("keepassxc"), Some(&mut io)).unwrap();
        assert!(report.text.contains("unchanged"), "{}", report.text);
        assert!(
            io.asked().contains("Restart the daemon now so it uses the database? [Y/n] "),
            "{}",
            io.asked()
        );
        assert_eq!((io.restarts, io.unlocks), (1, 0));
        // Without questions: the restart is named as the next step.
        let mut args = setup_args("keepassxc");
        args.no_key_file = true;
        let report = run_setup(&ctx, &args, None).unwrap();
        assert!(report.text.contains("after the restart, unlock the database"), "{}", report.text);
    }

    /// A daemon that answers Ping with the paths in the returned cell, anything else with
    /// `Reloaded`.
    fn pong_daemon(ctx: &Context) -> std::sync::Arc<std::sync::Mutex<DaemonPaths>> {
        let socket = ctx.paths.control_socket.clone();
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let uses = std::sync::Arc::new(std::sync::Mutex::new(DaemonPaths::default()));
        let paths = std::sync::Arc::clone(&uses);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let answer = match credential_bridge_proto::ipc::read_frame(&mut stream) {
                    Ok(Some(Request::Ping)) => Response::Pong {
                        version: super::super::VERSION.into(),
                        paths: paths.lock().unwrap().clone(),
                    },
                    Ok(Some(_)) => Response::Reloaded,
                    _ => continue,
                };
                let _ = credential_bridge_proto::ipc::write_frame(&mut stream, &answer);
            }
        });
        uses
    }

    /// Several `.kdbx` found: they are listed numbered, and a number or a path answers.
    #[test]
    fn setup_keepassxc_lists_several_databases() {
        let (dir, ctx) = context();
        write_config(&ctx, SOURCES);
        std::fs::create_dir_all(dir.path().join("Documents")).unwrap();
        std::fs::write(dir.path().join("Documents/b.kdbx"), "kdbx").unwrap();
        std::fs::write(dir.path().join("a.kdbx"), "kdbx").unwrap();
        // 3 is no choice (and no file), 2 is.
        let mut io = FakeIo::new("3\n2\n\n");
        let report = run_setup(&ctx, &setup_args("keepassxc"), Some(&mut io)).unwrap();
        assert!(
            report.text.contains("Found 2 database files:\n  1) ~/Documents/b.kdbx\n  2) ~/a.kdbx\n"),
            "{}",
            report.text
        );
        assert_eq!(report.text.matches("Found 2 database files").count(), 1, "{}", report.text);
        assert_eq!(
            io.asked().matches("KeePassXC database (.kdbx) (number or path): ").count(),
            2,
            "{}",
            io.asked()
        );
        assert!(report.text.contains("3 does not exist; try again"), "{}", report.text);
        assert!(text(&ctx).ends_with("[vault.keepassxc]\ndatabase = \"~/a.kdbx\"\n"), "{}", text(&ctx));
        assert!(
            report.text.contains("✓ config               [vault.keepassxc] database = ~/a.kdbx in "),
            "{}",
            report.text
        );

        // A path answers as well.
        let mut io = FakeIo::new(&format!("{}\n\n", dir.path().join("Documents/b.kdbx").display()));
        let report = run_setup(&ctx, &setup_args("keepassxc"), Some(&mut io)).unwrap();
        assert!(!report.text.contains("Found 2"), "the configured database is the default: {}", report.text);
        assert!(text(&ctx).contains("Documents/b.kdbx"), "{}", text(&ctx));
    }

    #[test]
    fn setup_keepassxc_without_questions() {
        let (dir, ctx) = context();
        write_config(&ctx, SOURCES);
        let message = format!("{:#}", run_setup(&ctx, &setup_args("keepassxc"), None).unwrap_err());
        assert!(message.contains("needs --database PATH"), "{message}");
        let mut args = setup_args("keepassxc");
        args.database = Some("~/db.kdbx".into());
        let message = format!("{:#}", run_setup(&ctx, &args, None).unwrap_err());
        assert!(message.contains("the database ~/db.kdbx does not exist"), "{message}");
        std::fs::write(dir.path().join("db.kdbx"), "kdbx").unwrap();
        std::fs::write(dir.path().join("db.keyx"), "key").unwrap();
        args.key_file = Some("~/db.keyx".into());

        args.write.dry_run = true;
        let report = run_setup(&ctx, &args, None).unwrap();
        assert!(
            report
                .text
                .contains("+[vault.keepassxc]\n+database = \"~/db.kdbx\"\n+key_file = \"~/db.keyx\"\n"),
            "{}",
            report.text
        );
        assert_eq!(text(&ctx), SOURCES);

        args.write.dry_run = false;
        let report = run_setup(&ctx, &args, None).unwrap();
        assert!(
            text(&ctx).ends_with("[vault.keepassxc]\ndatabase = \"~/db.kdbx\"\nkey_file = \"~/db.keyx\"\n")
        );
        assert!(report.text.contains("after the restart, unlock the database"), "{}", report.text);
        assert!(
            report.text.contains("[vault.keepassxc] database = ~/db.kdbx, key_file = ~/db.keyx in "),
            "{}",
            report.text
        );

        // --no-key-file removes the key file; the database stays as written.
        let args = VaultSetupArgs { key_file: None, no_key_file: true, database: None, ..args };
        let report = run_setup(&ctx, &args, None).unwrap();
        assert!(
            report.text.contains("✓ config               [vault.keepassxc] key_file removed in "),
            "{}",
            report.text
        );
        assert!(text(&ctx).ends_with("[vault.keepassxc]\ndatabase = \"~/db.kdbx\"\n"), "{}", text(&ctx));
    }

    #[test]
    fn setup_of_a_vault_without_settings_writes_nothing() {
        let (_dir, ctx) = context();
        write_config(&ctx, SOURCES);
        fake_daemon(
            &ctx.paths.control_socket,
            daemon_status(&ctx, vec![status("bitwarden", true, None, None)]),
        );
        let mut io = FakeIo::new("");
        let report = run_setup(&ctx, &setup_args("bw"), Some(&mut io)).unwrap();
        assert!(
            report.text.contains("✓ bitwarden            needs no setup: bw reads each reference"),
            "{}",
            report.text
        );
        assert!(report.text.contains("; bw ✓"), "{}", report.text);
        assert!(
            report.text.contains("unlock with credential-bridge-ctl vault unlock bitwarden"),
            "{}",
            report.text
        );
        assert!(report.text.contains("⚠ state                locked"), "{}", report.text);
        assert!(io.asked().is_empty());
        assert_eq!(text(&ctx), SOURCES);
        let mut args = setup_args("1password");
        args.database = Some("~/db.kdbx".into());
        assert!(run_setup(&ctx, &args, None).unwrap_err().to_string().contains("only for keepassxc"));
        assert!(
            run_setup(&ctx, &setup_args("vault"), None).unwrap_err().to_string().contains("not supported")
        );
    }

    #[test]
    fn forget_removes_the_settings_and_ends_the_session() {
        let (_dir, ctx) = context();
        let with = format!("{SOURCES}\n[vault.keepassxc]\ndatabase = \"~/db.kdbx\"\n");
        write_config(&ctx, &with);
        let requests = recording_daemon(&ctx.paths.control_socket, Response::Locked);
        let mut report = Report::default();
        let dry = VaultForgetArgs { vault: "keepassxc".into(), write: WriteArgs { dry_run: true } };
        forget(&ctx, &dry, TargetOs::Linux, &mut report).unwrap();
        assert!(report.text.contains("-[vault.keepassxc]\n-database = \"~/db.kdbx\"\n"), "{}", report.text);
        assert_eq!(text(&ctx), with);
        assert!(requests.lock().unwrap().is_empty(), "a dry run sends no Lock");

        let mut report = Report::default();
        let args = VaultForgetArgs { vault: "keepassxc".into(), write: WriteArgs::default() };
        forget(&ctx, &args, TargetOs::Linux, &mut report).unwrap();
        assert_eq!(text(&ctx), SOURCES);
        assert_eq!(*requests.lock().unwrap(), vec![Request::Lock { vault: Some("keepassxc".into()) }]);
        assert!(report.text.contains("✓ session              keepassxc locked"), "{}", report.text);
        assert!(
            report.text.contains("forgotten; the database itself is untouched (~/db.kdbx)"),
            "{}",
            report.text
        );
        assert!(
            report.text.contains("source home still uses keepassxc:// references; without a database they go to the KeePassXC app"),
            "{}",
            report.text
        );
        assert!(report.text.contains("→ credential-bridge-ctl vault setup keepassxc"), "{}", report.text);

        let message =
            format!("{:#}", forget(&ctx, &args, TargetOs::Linux, &mut Report::default()).unwrap_err());
        assert!(message.contains("nothing to forget"), "{message}");
        let bitwarden = VaultForgetArgs { vault: "bitwarden".into(), write: WriteArgs::default() };
        let message =
            forget(&ctx, &bitwarden, TargetOs::Linux, &mut Report::default()).unwrap_err().to_string();
        assert!(message.contains(
            "nothing to forget; to end its unlock session: credential-bridge-ctl vault lock bitwarden"
        ));
    }

    #[test]
    fn vault_tool_names() {
        let config = Config::default();
        assert_eq!(vault_tools(&config, VaultKind::Pass), &["pass", "gopass"]);
        assert!(vault_tools(&config, VaultKind::SecretService).is_empty());
        assert!(needs_unlock_command(&config, VaultKind::Bitwarden));
        assert!(!needs_unlock_command(&config, VaultKind::OnePassword));
    }

    /// KeePassXC needs `keepassxc-cli` and `ctl vault unlock` exactly when a database is
    /// configured; without one (Linux) the running app is used.
    #[test]
    fn keepassxc_tool_and_unlock_follow_the_database() {
        let without = Config::default();
        assert!(vault_tools(&without, VaultKind::KeePassXc).is_empty());
        assert!(!needs_unlock_command(&without, VaultKind::KeePassXc));
        let mut with = Config::default();
        with.vault.keepassxc.database = Some("/home/u/db.kdbx".into());
        assert_eq!(vault_tools(&with, VaultKind::KeePassXc), &["keepassxc-cli"]);
        assert!(needs_unlock_command(&with, VaultKind::KeePassXc));
    }
}
