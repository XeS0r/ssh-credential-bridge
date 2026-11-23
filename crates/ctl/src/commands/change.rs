//! The one way ctl changes the configuration file.
//!
//! Every changing command runs its edit through [`apply`]: open the file with
//! [`ConfigDocument`] (comments and layout stay), apply the typed edit, validate the
//! result exactly as the daemon would load it, and only then save it atomically and ask
//! a running daemon to reload. With `--dry-run` the change is shown as a unified diff
//! and nothing is written.

use std::path::Path;

use anyhow::bail;
use credential_bridge_config::edit::{ConfigDocument, EditError};
use credential_bridge_config::paths::Paths;
use credential_bridge_config::{Config, DaemonConfig, KeepassxcConfig, SecretRef, Server, Signing};

use credential_bridge_proto::ipc::control::DaemonPaths;

use super::{Context, config_error, printable, reload_daemon};
use crate::control::ControlError;
use crate::report::{Line, Report};

/// The hint for settings the daemon reads only when it starts (`[daemon]`, `[vault]`)
/// and for a daemon of another version. A restart drops unlock sessions and approvals.
pub(crate) const RESTART_HINT: &str =
    "credential-bridge-ctl daemon stop && credential-bridge-ctl daemon start";

/// The hint when the running daemon has not loaded the configuration file as it is.
pub(crate) const RELOAD_HINT: &str = "credential-bridge-ctl daemon reload";

/// The result of a change that did something (or, with `--dry-run`, would do).
#[derive(Debug)]
pub(crate) struct Applied {
    /// The configuration after the change (validated).
    pub config: Config,
}

/// How [`apply_doc`] applies a change; `Change::default()` writes and has no extras.
#[derive(Default)]
pub(crate) struct Change<'a> {
    /// Show the diff and write nothing.
    pub dry_run: bool,
    /// A server the caller sets up right after the change (`server add`): it gets no
    /// hint that its git setup is out of date.
    pub sets_up: Option<&'a str>,
    /// Runs after the result validated, right before it is saved (`init` keeps a
    /// backup). Gets the document, whose original text is the file as it was read.
    pub before_save: Option<BeforeSave<'a>>,
}

/// See [`Change::before_save`].
pub(crate) type BeforeSave<'a> = Box<dyn FnOnce(&ConfigDocument, &mut Report) -> anyhow::Result<()> + 'a>;

impl Change<'_> {
    /// A plain change, written unless `dry_run`.
    pub(crate) fn new(dry_run: bool) -> Change<'static> {
        Change { dry_run, ..Change::default() }
    }
}

/// Applies `edit` to the configuration file. Returns `None` if the file already says
/// what the edit would write.
///
/// Errors (nothing is written): the file cannot be read or parsed, the edit refuses
/// (unknown name, a reference still in use, an invalid value), the result does not
/// validate, or saving fails. `summary` describes the change in the `config` report
/// line, e.g. `[source.github] added`.
pub(crate) fn apply(
    ctx: &Context,
    dry_run: bool,
    report: &mut Report,
    summary: &str,
    edit: impl FnOnce(&mut ConfigDocument) -> Result<(), EditError>,
) -> anyhow::Result<Option<Applied>> {
    apply_described(ctx, dry_run, report, |doc| edit(doc).map(|()| summary.to_owned()))
}

/// [`apply`] for an edit that describes itself: it returns the summary, so it can say
/// what it found (`[gpg] added` or `changed`).
pub(crate) fn apply_described(
    ctx: &Context,
    dry_run: bool,
    report: &mut Report,
    edit: impl FnOnce(&mut ConfigDocument) -> Result<String, EditError>,
) -> anyhow::Result<Option<Applied>> {
    let doc = ConfigDocument::open(&ctx.config_path).map_err(edit_error)?;
    apply_doc(ctx, doc, Change::new(dry_run), report, edit)
}

/// Applies `edit` to `doc`, a document opened from the configuration file: the one
/// path every change takes.
///
/// The file was read once, when `doc` was opened; the configuration before the change
/// comes from that text, and the result is validated once and saved as validated. After
/// saving, a running daemon is told to reload, unless only `[daemon]` or `[vault]`
/// changed (those take effect when it restarts). Servers whose remote git setup (git
/// hosts, signing) the change makes out of date get a hint, never on a dry run.
pub(crate) fn apply_doc(
    ctx: &Context,
    mut doc: ConfigDocument,
    change: Change<'_>,
    report: &mut Report,
    edit: impl FnOnce(&mut ConfigDocument) -> Result<String, EditError>,
) -> anyhow::Result<Option<Applied>> {
    // An unreadable or invalid file before the change: nothing to compare with.
    let old = doc.original_config(&ctx.paths).ok();
    let summary = edit(&mut doc).map_err(edit_error)?;
    let baseline = doc
        .original_text()
        .map_or_else(|| format!("version = {}\n", credential_bridge_config::CONFIG_VERSION), str::to_owned);
    if doc.to_text() == baseline {
        report.push(Line::ok("config", format!("unchanged: {} already says so", ctx.config_path.display())));
        return Ok(None);
    }
    let validated = doc.validate(&ctx.paths);
    if change.dry_run {
        report.show(&diff_text(&doc));
        let config = validated.map_err(edit_error)?.config().clone();
        report.push(Line::ok("dry run", "the result validates; nothing was written"));
        warning_lines(&config, report);
        return Ok(Some(Applied { config }));
    }
    let validated = validated.map_err(edit_error)?;
    if let Some(before_save) = change.before_save {
        before_save(&doc, report)?;
    }
    let config = validated.save().map_err(edit_error)?;
    report.push(Line::ok("config", format!("{summary} in {}", ctx.config_path.display())));
    warning_lines(&config, report);
    let old_daemon =
        old.as_ref().map_or_else(|| DaemonConfig::from_paths(&ctx.paths), |old| old.daemon.clone());
    if old.as_ref().is_none_or(|old| needs_reload(old, &config)) {
        report.push(reload_line(&old_daemon));
    }
    if let Some(old) = &old {
        if let Some(line) = restart_line(old, &config) {
            report.push(line);
        }
        if let Some(line) = stale_git_setup_line(old, &config, change.sets_up) {
            report.push(line);
        }
    }
    Ok(Some(Applied { config }))
}

/// What loads but is most likely a mistake ([`Config::warnings`]), as warnings.
fn warning_lines(config: &Config, report: &mut Report) {
    for warning in config.warnings() {
        report.push(Line::warn("config", warning.to_string()));
    }
}

/// Whether the daemon has to reload to apply the change from `old` to `new`: anything
/// but `[daemon]` and `[vault]` changed, which the daemon reads only when it starts.
fn needs_reload(old: &Config, new: &Config) -> bool {
    let Config { daemon: _, vault: _, agent, gpg, sources, profiles, unregistered, servers } = new;
    *agent != old.agent
        || *gpg != old.gpg
        || *sources != old.sources
        || *profiles != old.profiles
        || *unregistered != old.unregistered
        || *servers != old.servers
}

/// The warning when `[daemon]` or `[vault]` changed: they take effect on a restart.
fn restart_line(old: &Config, new: &Config) -> Option<Line> {
    let what = match (old.daemon != new.daemon, old.vault != new.vault) {
        (false, false) => return None,
        (true, false) => "socket and audit log paths take effect when the daemon restarts",
        (false, true) => "vault settings take effect when the daemon restarts",
        (true, true) => "[daemon] and [vault] settings take effect when the daemon restarts",
    };
    let mut hint = RESTART_HINT.to_owned();
    if old.daemon.socket != new.daemon.socket || old.daemon.forward_socket != new.daemon.forward_socket {
        hint.push_str("; then update IdentityAgent/ForwardAgent: credential-bridge-ctl server ssh-config");
    }
    Some(Line::warn("daemon", what).with_hint(hint))
}

/// What a server's remote git setup (`credential-bridge-remote setup`) is made from:
/// its git hosts and whether it signs with ssh.
fn git_setup(config: &Config, server: &Server) -> (Vec<(String, bool)>, Option<Signing>) {
    let signing = config.profile_for(Some(server)).and_then(|profile| profile.signing);
    (config.git_hosts_for(server), signing)
}

/// The hint for servers (in both `old` and `new`, except `sets_up`) whose git setup
/// the change from `old` to `new` makes out of date.
fn stale_git_setup_line(old: &Config, new: &Config, sets_up: Option<&str>) -> Option<Line> {
    let stale: Vec<&Server> = new
        .servers
        .values()
        .filter(|server| Some(server.name.as_str()) != sets_up)
        .filter(|server| {
            old.servers
                .get(&server.name)
                .is_some_and(|before| git_setup(old, before) != git_setup(new, server))
        })
        .collect();
    if stale.is_empty() {
        return None;
    }
    let names: Vec<&str> = stale.iter().map(|server| server.name.as_str()).collect();
    let commands: Vec<String> = stale
        .iter()
        .map(|server| {
            format!("credential-bridge-ctl server add {} --profile {}", server.name, server.profile)
        })
        .collect();
    Some(
        Line::warn("git config", format!("set up for the old configuration on {}", names.join(", ")))
            .with_hint(commands.join("\n")),
    )
}

/// The diff `--dry-run` prints: the file as it is against the file as it would be.
pub(crate) fn diff_text(doc: &ConfigDocument) -> String {
    let path = doc.path().display().to_string();
    let old_name = if doc.original_text().is_some() { path.clone() } else { "/dev/null".to_owned() };
    crate::diff::unified(
        doc.original_text().unwrap_or(""),
        &doc.to_text(),
        &old_name,
        &format!("{path} (new)"),
    )
}

/// Reloads the daemon and describes the result.
pub(crate) fn reload_line(daemon: &DaemonConfig) -> Line {
    match reload_daemon(daemon) {
        Ok(true) => Line::ok("daemon", "reloaded the configuration"),
        Ok(false) => Line::warn("daemon", "not running; it reads the configuration when it starts")
            .with_hint("credential-bridge-ctl daemon start"),
        Err(error) => reload_failed_line(&error),
    }
}

/// The warning when a running daemon did not reload after a change.
pub(crate) fn reload_failed_line(error: &ControlError) -> Line {
    Line::warn("daemon", format!("reload failed: {error}")).with_hint(RELOAD_HINT)
}

/// The warning when the running daemon uses other sockets or another audit log than
/// `[daemon]` names (`used` is what it reports): they change only on a restart.
pub(crate) fn moved_paths_line(used: &DaemonPaths, configured: &DaemonConfig) -> Option<Line> {
    let moved: Vec<String> = [
        ("socket", &used.socket, &configured.socket),
        ("forward_socket", &used.forward_socket, &configured.forward_socket),
        ("audit_log", &used.audit_log, &configured.audit_log),
    ]
    .into_iter()
    .filter(|(_, used, configured)| Path::new(used) != configured.as_path())
    .map(|(key, used, configured)| format!("{key} {used} (configured: {})", configured.display()))
    .collect();
    if moved.is_empty() {
        return None;
    }
    Some(
        Line::warn("daemon", format!("uses {}", printable(&moved.join(", "))))
            .with_hint(format!("[daemon] changes take effect on a restart: {RESTART_HINT}")),
    )
}

/// Whether the running daemon uses the KeePassXC files of `configured` (`used` is what
/// it reports; it reads `[vault]` when it starts).
pub(crate) fn uses_keepassxc(used: &DaemonPaths, configured: &KeepassxcConfig) -> bool {
    let text = |path: &Option<std::path::PathBuf>| path.as_ref().map(|path| path.display().to_string());
    used.keepassxc_database == text(&configured.database)
        && used.keepassxc_key_file == text(&configured.key_file)
}

/// The warning when the running daemon uses other `[vault.keepassxc]` files than the
/// configuration names: they change only on a restart.
pub(crate) fn moved_vault_line(used: &DaemonPaths, configured: &KeepassxcConfig) -> Option<Line> {
    if uses_keepassxc(used, configured) {
        return None;
    }
    let text = |path: &Option<String>| path.clone().unwrap_or_else(|| "none".to_owned());
    let configured_text = |path: &Option<std::path::PathBuf>| {
        path.as_ref().map_or_else(|| "none".to_owned(), |path| path.display().to_string())
    };
    let moved: Vec<String> = [
        ("database", &used.keepassxc_database, &configured.database),
        ("key_file", &used.keepassxc_key_file, &configured.key_file),
    ]
    .into_iter()
    .filter(|(_, used, configured)| used.as_deref().map(Path::new) != configured.as_deref())
    .map(|(key, used, configured)| {
        format!("{key} {} (configured: {})", text(used), configured_text(configured))
    })
    .collect();
    Some(
        Line::warn("daemon", format!("uses [vault.keepassxc] {}", printable(&moved.join(", "))))
            .with_hint(format!("[vault] changes take effect on a restart: {RESTART_HINT}")),
    )
}

/// Errors of editing as messages: every configuration problem on its own line, and for a
/// refused removal who still uses the item and the commands that fix it.
pub(crate) fn edit_error(error: EditError) -> anyhow::Error {
    match error {
        EditError::Invalid(error) => config_error(error).context(WouldBeInvalid),
        EditError::InUse { item, users, fixes } => anyhow::anyhow!(
            "{item} is still used by {}; nothing was changed. First run:\n{}",
            users.join(", "),
            fixes.iter().map(|fix| format!("  {fix}")).collect::<Vec<_>>().join("\n")
        ),
        other => other.into(),
    }
}

/// The context of an error whose cause is that the result does not validate (as opposed
/// to reading or writing failing); `config edit` looks for it with `downcast_ref`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WouldBeInvalid;

impl std::fmt::Display for WouldBeInvalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the configuration would become invalid")
    }
}

/// Whether `error` (from [`apply_doc`]) means the text is wrong, so editing it again can
/// fix it: it does not parse, or it does not validate.
pub(crate) fn is_invalid_text(error: &anyhow::Error) -> bool {
    error.downcast_ref::<WouldBeInvalid>().is_some()
        || matches!(error.downcast_ref::<EditError>(), Some(EditError::Syntax { .. }))
}

/// Parses a secret reference given for `flag`. The value is never repeated in the
/// error, because a mistaken value may be the secret itself.
pub(crate) fn secret_ref(flag: &str, value: &str) -> anyhow::Result<SecretRef> {
    match value.parse::<SecretRef>() {
        Ok(reference) => Ok(reference),
        Err(error) => bail!(
            "{flag} takes a reference to where the secret is stored, not the secret: {} \
             (the value given is not shown)",
            error.reason
        ),
    }
}

/// A socket for the configuration: `gpgconf:<name>`, `~/…` and absolute paths as given,
/// a relative path made absolute.
pub(crate) fn socket_value(text: &str) -> anyhow::Result<String> {
    if text.starts_with("gpgconf:") || text.starts_with("~/") || text.starts_with('/') {
        return Ok(text.to_owned());
    }
    path_value(text)
}

/// A file path for the configuration: `~/…` and absolute paths as given, a relative path
/// made absolute against the current directory.
pub(crate) fn path_value(text: &str) -> anyhow::Result<String> {
    if text.is_empty() {
        bail!("the path is empty");
    }
    if text.starts_with("~/") || text.starts_with('/') {
        return Ok(text.to_owned());
    }
    let absolute = std::path::absolute(Path::new(text))?;
    absolute.to_str().map(str::to_owned).ok_or_else(|| anyhow::anyhow!("{text:?} is not valid UTF-8"))
}

/// Shows a path with the home directory as `~`.
pub(crate) fn tilde(paths: &Paths, path: &Path) -> String {
    match path.strip_prefix(&paths.home) {
        Ok(rest) if !rest.as_os_str().is_empty() => format!("~/{}", rest.display()),
        _ => path.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use credential_bridge_config::edit::HostKeysEntry;

    use crate::commands::test_support::{context, write_config};
    use crate::report::Status;

    const TEXT: &str = "# mine\nversion = 2\n\n[profile.dev]   # dev boxes\nssh = { keys = \"all\" }\n";

    fn add_profile(doc: &mut ConfigDocument) -> Result<(), EditError> {
        doc.add_profile("ci")
    }

    #[test]
    fn writes_validated_changes_and_keeps_comments() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let mut report = Report::default();
        let applied = apply(&ctx, false, &mut report, "[profile.ci] added", add_profile).unwrap().unwrap();
        assert!(applied.config.profiles.contains_key("ci"));
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), format!("{TEXT}\n[profile.ci]\n"));
        assert!(report.text.contains("✓ config               [profile.ci] added in"), "{}", report.text);
        assert!(report.text.contains("⚠ daemon               not running"), "{}", report.text);
    }

    #[test]
    fn dry_run_prints_a_diff_and_writes_nothing() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let mut report = Report::default();
        let applied = apply(&ctx, true, &mut report, "x", add_profile).unwrap().unwrap();
        assert!(applied.config.profiles.contains_key("ci"));
        let path = ctx.config_path.display();
        assert!(
            report.text.starts_with(&format!(
                "--- {path}\n+++ {path} (new)\n@@ -3,3 +3,5 @@\n \n [profile.dev]   # dev boxes\n \
                 ssh = {{ keys = \"all\" }}\n+\n+[profile.ci]\n"
            )),
            "{}",
            report.text
        );
        assert!(report.text.contains("✓ dry run"));
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), TEXT);

        // Without a file the diff starts from /dev/null, and no file appears.
        std::fs::remove_file(&ctx.config_path).unwrap();
        let mut report = Report::default();
        apply(&ctx, true, &mut report, "x", add_profile).unwrap();
        assert!(report.text.starts_with("--- /dev/null\n"), "{}", report.text);
        assert!(report.text.contains("+version = 2\n+\n+[profile.ci]\n"), "{}", report.text);
        assert!(!ctx.config_path.exists());
    }

    #[test]
    fn invalid_results_and_refusals_leave_the_file_alone() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let mut report = Report::default();
        let error = apply(&ctx, false, &mut report, "x", |doc| {
            doc.set_server(
                "box",
                &HostKeysEntry::Pinned(&[crate::commands::test_support::test_key(1)]),
                "nope",
                true,
            )
        })
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("would become invalid") && message.contains("nope"), "{message}");
        let error = apply(&ctx, true, &mut report, "x", |doc| doc.remove_profile("nope")).unwrap_err();
        assert_eq!(error.to_string(), "no profile.nope");
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), TEXT);
    }

    #[test]
    fn unchanged_files_are_not_written() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let mut report = Report::default();
        assert!(apply(&ctx, false, &mut report, "x", |_| Ok(())).unwrap().is_none());
        assert!(report.text.contains("unchanged"));
    }

    /// A reload that failed after a change points to `daemon reload`, not to a restart.
    #[test]
    fn failed_reloads_hint_at_daemon_reload() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let busy = credential_bridge_proto::ipc::WorkerError::new(
            credential_bridge_proto::ipc::WorkerErrorKind::Internal,
            "the configuration changed while it was read",
        );
        crate::commands::test_support::fake_daemon(
            &ctx.paths.control_socket,
            credential_bridge_proto::ipc::control::Response::Error(busy),
        );
        let mut report = Report::default();
        apply(&ctx, false, &mut report, "x", |doc| doc.add_profile("ci")).unwrap();
        assert!(
            report.text.contains(
                "⚠ daemon               reload failed: the configuration changed while it was read\n  \
                 \x20                    → credential-bridge-ctl daemon reload\n"
            ),
            "{}",
            report.text
        );
    }

    /// `[daemon]` and `[vault]` take effect on a restart: no reload for them alone.
    #[test]
    fn daemon_and_vault_changes_do_not_reload() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let mut report = Report::default();
        apply(&ctx, false, &mut report, "x", |doc| {
            doc.set_daemon(credential_bridge_config::edit::DaemonKey::AuditLog, Some("/a.log"))?;
            doc.set_keepassxc(credential_bridge_config::edit::KeepassxcKey::Database, Some("/db.kdbx"))
        })
        .unwrap();
        assert!(!report.text.contains("not running"), "{}", report.text);
        assert!(
            report.text.contains("⚠ daemon               [daemon] and [vault] settings take effect"),
            "{}",
            report.text
        );

        let mut report = Report::default();
        apply(&ctx, false, &mut report, "x", |doc| {
            doc.set_daemon(credential_bridge_config::edit::DaemonKey::Socket, Some("/run/a.sock"))?;
            doc.add_profile("ci")
        })
        .unwrap();
        assert!(report.text.contains("⚠ daemon               not running"), "{}", report.text);
        assert!(report.text.contains("socket and audit log paths take effect"), "{}", report.text);
        assert!(report.text.contains("credential-bridge-ctl server ssh-config"), "{}", report.text);
    }

    const GIT: &str = "version = 2\n\n[source.github]\ntype = \"github\"\nauth = \"gh\"\n\n\
                       [profile.build]\nssh = { keys = \"all\" }\n\n\
                       [[profile.build.git]]\nurl = \"https://github.com/*\"\nsource = \"github\"\n\n\
                       [profile.dev]\n";

    /// Replaces the file's text through `apply`, as `config edit` does.
    fn edit_text(ctx: &Context, dry_run: bool, text: &str) -> Report {
        let mut report = Report::default();
        apply(ctx, dry_run, &mut report, "edited", |doc| {
            *doc = ConfigDocument::replacing(doc.path(), doc.original_text().map(str::to_owned), text)?;
            Ok(())
        })
        .unwrap();
        report
    }

    /// A change whose result loads but is most likely a mistake is written, with the
    /// warnings of the result.
    #[test]
    fn warnings_of_the_result_are_shown() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let twice = format!(
            "{TEXT}[server.a]\nknown_host = \"box\"\nprofile = \"dev\"\n[server.b]\nknown_host = \"box\"\nprofile = \"dev\"\n"
        );
        for dry_run in [true, false] {
            let report = edit_text(&ctx, dry_run, &twice);
            let warning =
                report.lines.iter().find(|line| line.label == "config" && line.status == Status::Warn);
            assert!(
                warning.unwrap().detail.contains("follows \"box\" in the same known_hosts files"),
                "{}",
                report.text
            );
        }
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), twice);
    }

    fn git_hint(report: &Report) -> Option<String> {
        report.lines.iter().find(|line| line.label == "git config").map(ToString::to_string)
    }

    /// One comparison of what each server's git setup is made of, before and after:
    /// a hint exactly when that changed, never on a dry run.
    #[test]
    fn stale_git_setups_are_named_once() {
        let (_dir, ctx) = context();
        let servers = format!(
            "\n[server.box]\nhost_keys = [\"{}\"]\nprofile = \"build\"\n\n\
             [server.other]\nhost_keys = [\"{}\"]\nprofile = \"dev\"\n",
            crate::commands::test_support::test_key(1),
            crate::commands::test_support::test_key(2)
        );
        let base = format!("{GIT}{servers}");
        write_config(&ctx, &base);
        let with = |extra: &str| base.replace("[profile.dev]\n", &format!("{extra}[profile.dev]\n"));

        // Another rule for a host the server already has: nothing to set up.
        let same_host =
            with("\n[[profile.build.git]]\nurl = \"https://github.com/*/*\"\nsource = \"github\"\n\n");
        assert_eq!(git_hint(&edit_text(&ctx, false, &same_host)), None);
        // Unrelated changes neither.
        assert_eq!(git_hint(&edit_text(&ctx, false, &format!("{same_host}\n[profile.ci]\n"))), None);

        // A rule for a new host; on a dry run nothing is said.
        let new_host = with(
            "\n[source.lab]\ntype = \"gitlab\"\nhost = \"gitlab.com\"\nauth = \"token\"\ntoken = \"pass://lab\"\n\n\
             [[profile.build.git]]\nurl = \"https://gitlab.com/*\"\nsource = \"lab\"\n\n",
        );
        write_config(&ctx, &base);
        assert_eq!(git_hint(&edit_text(&ctx, true, &new_host)), None);
        let hint = git_hint(&edit_text(&ctx, false, &new_host)).unwrap();
        assert!(hint.contains("set up for the old configuration on box\n"), "{hint}");
        assert!(hint.contains("→ credential-bridge-ctl server add box --profile build"), "{hint}");
        assert!(!hint.contains("other"), "{hint}");

        // Removing the rule again.
        assert!(git_hint(&edit_text(&ctx, false, &base)).is_some());

        // Signing, for both servers.
        let signing = base
            .replace("ssh = { keys = \"all\" }\n", "ssh = { keys = \"all\" }\nsigning = \"ssh\"\n")
            .replace("[profile.dev]\n", "[profile.dev]\nssh = { keys = \"all\" }\nsigning = \"ssh\"\n");
        let hint = git_hint(&edit_text(&ctx, false, &signing)).unwrap();
        assert!(hint.contains("on box, other\n"), "{hint}");

        // The kind of a source: an App needs the path of each repository, a host-only
        // rule of a gh source does not.
        let base = base.replace("url = \"https://github.com/*\"", "url = \"https://github.com\"");
        write_config(&ctx, &base);
        let app = base
            .replace(
                "auth = \"gh\"\n",
                "auth = \"app\"\napp_id = 1\nprivate_key = \"op://a/b/c\"\nmax_permissions = { contents = \"read\" }\n",
            )
            .replace("source = \"github\"\n", "source = \"github\"\npermissions = { contents = \"read\" }\n");
        assert!(git_hint(&edit_text(&ctx, false, &app)).unwrap().contains("on box\n"));
    }

    #[test]
    fn secret_references_never_echo_the_value() {
        assert!(secret_ref("--token", "op://Vault/Item/field").is_ok());
        for value in ["ghp_0123456789abcdefSECRET", "op://only-two/parts", ""] {
            let message = secret_ref("--token", value).unwrap_err().to_string();
            assert!(message.starts_with("--token takes a reference"), "{message}");
            assert!(value.is_empty() || !message.contains(value), "{message}");
        }
    }

    #[test]
    fn socket_and_path_values() {
        assert_eq!(socket_value("gpgconf:agent-ssh-socket").unwrap(), "gpgconf:agent-ssh-socket");
        assert_eq!(socket_value("~/a.sock").unwrap(), "~/a.sock");
        assert_eq!(socket_value("/a.sock").unwrap(), "/a.sock");
        let relative = socket_value("a.sock").unwrap();
        assert!(relative.starts_with('/') && relative.ends_with("/a.sock"), "{relative}");
        assert!(path_value("").is_err());
    }
}
