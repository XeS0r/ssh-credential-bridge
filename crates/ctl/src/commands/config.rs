//! `config show|path|check|edit`: the whole file.

use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, bail};
use credential_bridge_config::edit::ConfigDocument;
use credential_bridge_config::edit::EditError;
use credential_bridge_config::{Config, KeySelection, Profile, ServerKeys, SocketSpec, Source, SourceKind};

use super::change::{Change, apply_doc, edit_error, is_invalid_text};
use super::check::check_config;
use super::{Context, ask_terminal, config_error};
use crate::cli::ConfigCommand;
use crate::report::Report;

/// The mark of values that are not written in the file.
const BUILT_IN: &str = "# built in";

/// Runs a `config` subcommand. `check` fails with exit code 1 if the configuration is
/// invalid.
pub fn config(ctx: &Context, command: &ConfigCommand, report: &mut Report) -> anyhow::Result<ExitCode> {
    match command {
        ConfigCommand::Show => {
            // One read: the values and the marks of what the file writes come from it.
            let doc = ConfigDocument::open(&ctx.config_path).map_err(edit_error)?;
            let config = doc.original_config(&ctx.paths).map_err(|error| match error {
                EditError::Invalid(error) => config_error(error),
                other => edit_error(other),
            })?;
            report.show(&show_text(ctx, &config, &doc));
        }
        ConfigCommand::Path => report.show(&format!("{}\n", ctx.config_path.display())),
        ConfigCommand::Check => {
            check_config(ctx, report);
            if report.failed() {
                return Ok(ExitCode::FAILURE);
            }
        }
        ConfigCommand::Edit => {
            if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
                bail!(
                    "config edit needs a terminal; edit {} directly and run credential-bridge-ctl config check",
                    ctx.config_path.display()
                );
            }
            config_edit(ctx, &editor(), &mut ask_terminal, report)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ── config show ────────────────────────────────────────────────────────────────────

/// Quotes `text` as a TOML basic string.
fn quoted(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A TOML table name part: bare if possible.
fn key(name: &str) -> String {
    if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        name.to_owned()
    } else {
        quoted(name)
    }
}

/// `["a", "b"]`.
fn list(items: &[String]) -> String {
    format!("[{}]", items.iter().map(|item| quoted(item)).collect::<Vec<_>>().join(", "))
}

fn socket(spec: &SocketSpec) -> String {
    match spec {
        SocketSpec::Path(path) => quoted(&path.display().to_string()),
        SocketSpec::Gpgconf(name) => quoted(&format!("gpgconf:{name}")),
    }
}

/// Collects `key = value` lines and marks those the file does not write.
struct Writer<'a> {
    doc: &'a ConfigDocument,
    out: String,
}

impl Writer<'_> {
    fn line(&mut self, path: &[&str], key: &str, value: String) {
        let mut full: Vec<&str> = path.to_vec();
        full.extend(key.split('.'));
        let mut line = format!("{key} = {value}");
        if !self.doc.contains(&full) {
            line = format!("{line:<40}  {BUILT_IN}");
        }
        self.out.push_str(line.trim_end());
        self.out.push('\n');
    }

    fn text(&mut self, text: &str) {
        self.out.push_str(text);
    }
}

/// The effective configuration as TOML that loads to the same [`Config`]: every value,
/// with defaults the file does not write marked `# built in`.
fn show_text(ctx: &Context, config: &Config, doc: &ConfigDocument) -> String {
    let mut w = Writer { doc, out: String::new() };
    let exists = doc.original_text().is_some();
    w.text(&format!(
        "# Effective configuration of {}{}\n# Values marked \"{BUILT_IN}\" are defaults the file does not write.\n\n",
        ctx.config_path.display(),
        if exists { "" } else { " (the file does not exist)" }
    ));
    w.text(&format!("version = {}\n\n[daemon]\n", credential_bridge_config::CONFIG_VERSION));
    let daemon = &config.daemon;
    w.line(&["daemon"], "socket", quoted(&daemon.socket.display().to_string()));
    w.line(&["daemon"], "forward_socket", quoted(&daemon.forward_socket.display().to_string()));
    w.line(&["daemon"], "control_socket", quoted(&daemon.control_socket.display().to_string()));
    w.line(&["daemon"], "audit_log", quoted(&daemon.audit_log.display().to_string()));

    match &config.agent {
        None => w.text("\n# No [agent]: the proxy shows no keys and only hands out tokens.\n"),
        Some(agent) => {
            w.text("\n[agent]\n");
            match &agent.add_to {
                Some(add_to) => w.line(&["agent"], "add_to", quoted(add_to)),
                None => w.text("# no add_to: ssh-add through the proxy fails\n"),
            }
            for upstream in &agent.upstreams {
                w.text(&format!(
                    "\n[[agent.upstream]]\nname = {}\nsocket = {}\n",
                    quoted(&upstream.name),
                    socket(&upstream.socket)
                ));
            }
        }
    }

    match &config.gpg {
        None => w.text("\n# No [gpg]: no profile may allow gpg.\n"),
        Some(gpg) => {
            w.text("\n[gpg]\n");
            w.line(&["gpg"], "socket", socket(&gpg.socket));
        }
    }

    let keepassxc = &config.vault.keepassxc;
    if keepassxc.database.is_some() || keepassxc.key_file.is_some() {
        w.text("\n[vault.keepassxc]\n");
        for (name, value) in [("database", &keepassxc.database), ("key_file", &keepassxc.key_file)] {
            if let Some(path) = value {
                w.line(&["vault", "keepassxc"], name, quoted(&path.display().to_string()));
            }
        }
    }

    for source in config.sources.values() {
        source_section(&mut w, source);
    }
    for profile in config.profiles.values() {
        profile_section(&mut w, config, profile);
    }
    w.text("\n# Built in for hosts without a [server.*] entry; never git rules, gpg or signing.\n");
    profile_section(&mut w, config, &config.unregistered);

    for server in config.servers.values() {
        let path = ["server", server.name.as_str()];
        w.text(&format!("\n[server.{}]\n", key(&server.name)));
        match &server.keys {
            ServerKeys::KnownHost(known) => {
                w.line(&path, "known_host", quoted(&known.name));
                let files: Vec<String> = known.files.iter().map(|file| file.display().to_string()).collect();
                w.line(&path, "known_hosts_files", list(&files));
            }
            ServerKeys::Pinned(keys) => {
                let keys: Vec<String> = keys.iter().filter_map(|key| key.to_openssh().ok()).collect();
                w.line(&path, "host_keys", list(&keys));
            }
        }
        w.line(&path, "profile", quoted(&server.profile));
        w.line(&path, "git_config", server.git_config.to_string());
    }
    w.out
}

fn source_section(w: &mut Writer<'_>, source: &Source) {
    let path = ["source", source.name.as_str()];
    w.text(&format!("\n[source.{}]\n", key(&source.name)));
    let (kind, auth) = match &source.kind {
        SourceKind::GithubGh { .. } => ("github", Some("gh")),
        SourceKind::GithubPat { .. } => ("github", Some("pat")),
        SourceKind::GithubApp { .. } => ("github", Some("app")),
        SourceKind::GitlabToken { .. } => ("gitlab", Some("token")),
        SourceKind::ForgejoToken { .. } => ("forgejo", Some("token")),
        SourceKind::Helper { .. } => ("helper", None),
    };
    // `type = "gitea"` is shown as written.
    let kind = w.doc.string_at(&["source", &source.name, "type"]).unwrap_or(kind).to_owned();
    w.line(&path, "type", quoted(&kind));
    if let Some(auth) = auth {
        w.line(&path, "auth", quoted(auth));
    }
    if let Some(host) = source.kind.host() {
        w.line(&path, "host", quoted(host));
    }
    match &source.kind {
        SourceKind::GithubPat { token, .. }
        | SourceKind::GitlabToken { token, .. }
        | SourceKind::ForgejoToken { token, .. } => w.line(&path, "token", quoted(&token.to_string())),
        SourceKind::GithubApp { api_url, app_id, private_key, max_permissions, .. } => {
            w.line(&path, "api_url", quoted(api_url));
            w.line(&path, "app_id", app_id.to_string());
            w.line(&path, "private_key", quoted(&private_key.to_string()));
            w.line(&path, "max_permissions", permissions(max_permissions));
        }
        SourceKind::Helper { helper } => w.line(&path, "helper", quoted(helper)),
        SourceKind::GithubGh { .. } => {}
    }
    if source.kind.cached_by_bridge() {
        w.line(&path, "cache", source.cache.to_string());
    }
}

/// `{ contents = "write" }`.
fn permissions(permissions: &credential_bridge_proto::ipc::git::Permissions) -> String {
    if permissions.is_empty() {
        return "{}".to_owned();
    }
    let items: Vec<String> = permissions
        .iter()
        .map(|(name, access)| format!("{} = {}", key(name), quoted(access.as_str())))
        .collect();
    format!("{{ {} }}", items.join(", "))
}

fn profile_section(w: &mut Writer<'_>, config: &Config, profile: &Profile) {
    let name = profile.name.as_str();
    let path = ["profile", name];
    w.text(&format!("\n[profile.{}]\n", key(name)));
    match &profile.ssh {
        None => w.text("# no ssh: the server sees no keys\n"),
        Some(ssh) => {
            let keys = match &ssh.keys {
                KeySelection::All => quoted("all"),
                KeySelection::Upstreams(names) => list(names),
            };
            w.line(&path, "ssh.keys", keys);
            w.line(&path, "ssh.confirm", quoted(&ssh.confirm.describe()));
        }
    }
    let mut gpg = Vec::new();
    if profile.gpg.sign {
        gpg.push("sign".to_owned());
    }
    if profile.gpg.decrypt {
        gpg.push("decrypt".to_owned());
    }
    w.line(&path, "gpg", list(&gpg));
    w.line(&path, "hops.ssh", profile.hops.ssh.to_string());
    w.line(&path, "hops.git", profile.hops.git.to_string());
    w.line(&path, "hops.gpg", profile.hops.gpg.to_string());
    if profile.signing.is_some() {
        w.line(&path, "signing", quoted("ssh"));
    }
    for (index, rule) in profile.git.iter().enumerate() {
        w.text(&format!("\n[[profile.{}.git]]\n", key(name)));
        w.text(&format!("url = {}\nsource = {}\n", quoted(rule.url.as_str()), quoted(&rule.source)));
        let is_app = config
            .sources
            .get(&rule.source)
            .is_some_and(|source| matches!(source.kind, SourceKind::GithubApp { .. }));
        if is_app {
            w.text(&format!("permissions = {}\n", permissions(&rule.permissions)));
            let per = rule.per.as_str();
            let written = w.doc.rule_contains(name, index, "per");
            let line = format!("per = {}", quoted(per));
            if written {
                w.text(&format!("{line}\n"));
            } else {
                w.text(&format!("{line:<40}  {BUILT_IN}\n"));
            }
        }
    }
}

// ── config edit ────────────────────────────────────────────────────────────────────

/// `$VISUAL`, else `$EDITOR`, else `vi`.
fn editor() -> String {
    ["VISUAL", "EDITOR"]
        .into_iter()
        .filter_map(|name| std::env::var(name).ok())
        .find(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "vi".to_owned())
}

/// The temporary copy `config edit` opens; removed when dropped unless kept.
struct TempCopy {
    path: PathBuf,
    keep: bool,
}

impl Drop for TempCopy {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Writes a new private file next to the configuration.
fn temp_copy(config_path: &Path, text: &str) -> anyhow::Result<TempCopy> {
    let dir = match config_path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_owned(),
        _ => PathBuf::from("."),
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let name = config_path.file_name().map_or("config.toml".into(), |name| name.to_string_lossy());
    let path = dir.join(format!(".{name}.edit-{}.toml", std::process::id()));
    // A stale copy of an earlier run with the same process ID.
    let _ = std::fs::remove_file(&path);
    credential_bridge_config::file::write_private(&path, text.as_bytes())
        .with_context(|| format!("cannot create {}", path.display()))?;
    Ok(TempCopy { path, keep: false })
}

/// `config edit` with an explicit editor command (run through `sh -c`, so it may carry
/// arguments) and a way to ask: opens a copy of the file, and saves it when it
/// validates. On an invalid result it asks whether to edit again or abort, as
/// `crontab -e` does; no answer (end of input) aborts. Nothing is written unless the
/// result validates.
///
/// The copy is removed after a successful save or when nothing changed. Otherwise
/// (abort, a failing editor, a save that fails) it is kept and its path is named, so
/// the edits are not lost.
pub(crate) fn config_edit(
    ctx: &Context,
    editor: &str,
    ask: &mut dyn FnMut(&str) -> std::io::Result<String>,
    report: &mut Report,
) -> anyhow::Result<()> {
    let original = match std::fs::read_to_string(&ctx.config_path) {
        Ok(text) => Some(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("cannot read {}", ctx.config_path.display()));
        }
    };
    let start = original
        .clone()
        .unwrap_or_else(|| format!("version = {}\n", credential_bridge_config::CONFIG_VERSION));
    let mut copy = temp_copy(&ctx.config_path, &start)?;
    let config_path = ctx.config_path.display().to_string();
    loop {
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("{editor} \"$1\""))
            .arg("sh")
            .arg(&copy.path)
            .status()
            .with_context(|| format!("cannot start the editor {editor:?}"));
        let text = std::fs::read_to_string(&copy.path)
            .with_context(|| format!("cannot read {}", copy.path.display()))?;
        let changed = text != start;
        match status {
            Ok(status) if status.success() => {}
            Ok(status) => {
                copy.keep = changed;
                bail!(
                    "the editor {editor:?} failed ({status}); {config_path} was not changed{}",
                    kept(&copy)
                );
            }
            Err(error) => {
                copy.keep = changed;
                return Err(error.context(format!("{config_path} was not changed{}", kept(&copy))));
            }
        }
        if !changed {
            report.push(crate::report::Line::ok("config", "no changes"));
            return Ok(());
        }
        let now = std::fs::read_to_string(&ctx.config_path).ok();
        if now != original {
            copy.keep = true;
            bail!(
                "{config_path} was changed by something else while you edited it; nothing was written{}",
                kept(&copy)
            );
        }
        let result = ConfigDocument::replacing(&ctx.config_path, original.clone(), &text)
            .map_err(edit_error)
            .and_then(|doc| apply_doc(ctx, doc, Change::default(), report, |_| Ok("edited".to_owned())));
        let error = match result {
            Ok(_) => return Ok(()),
            Err(error) => error,
        };
        if !is_invalid_text(&error) {
            // Reading or writing failed: editing again would not help.
            copy.keep = true;
            return Err(error.context(format!("{config_path} was not changed{}", kept(&copy))));
        }
        report.show(&format!("{error:#}\n"));
        loop {
            match ask("(e)dit again or (a)bort? [e] ").as_deref() {
                Ok("" | "e" | "E") => break,
                // `a`, or no answer at all (end of input, Ctrl-D).
                Ok("a" | "A") | Err(_) => {
                    copy.keep = true;
                    bail!("aborted; {config_path} was not changed{}", kept(&copy));
                }
                Ok(_) => {}
            }
        }
    }
}

/// `; your version is in <copy>` for a copy that is kept, else nothing.
fn kept(copy: &TempCopy) -> String {
    if copy.keep { format!("; your version is in {}", copy.path.display()) } else { String::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::load_config;
    use crate::commands::test_support::{context, test_key, write_config};

    const FULL: &str = r#"# mine
version = 2

[agent]
add_to = "fido"

[[agent.upstream]]
name   = "fido"
socket = "~/.ssh/agent.sock"

[[agent.upstream]]
name   = "yubikey"
socket = "gpgconf:agent-ssh-socket"

[gpg]

[vault.keepassxc]
database = "~/db.kdbx"

[source.github]
type = "github"
auth = "gh"

[source.app]
type = "github"
auth = "app"
app_id = 7
private_key = "op://Dev/app/key"
max_permissions = { contents = "write" }

[source.forge]
type = "gitea"
host = "git.example.com"
token = "pass://forge/token"
cache = false

[profile.build]
ssh  = { keys = ["yubikey"] }
gpg  = ["sign"]

[[profile.build.git]]
url = "https://github.com/acme/*"
source = "app"
permissions = { contents = "read" }
per = "owner"

[[profile.build.git]]
url = "https://github.com/other/app"
source = "app"
permissions = { contents = "read" }

[[profile.build.git]]
url = "https://git.example.com/*"
source = "forge"

[profile.dev]
ssh = { keys = "all", confirm = "8h" }
signing = "ssh"

[profile.unregistered]
ssh = { keys = ["fido"] }
"#;

    #[test]
    fn show_marks_built_in_values_and_loads_back() {
        let (_dir, ctx) = context();
        write_config(
            &ctx,
            &format!(
                "{FULL}\n[server.box]\nhost_keys = [\"{}\"]\nprofile = \"dev\"\n\
                 [server.follows]\nknown_host = \"[follows.example]:2222\"\nprofile = \"dev\"\n\
                 [server.work]\nknown_host = \"work\"\nknown_hosts_files = [\"~/.ssh/work\"]\nprofile = \"dev\"\n",
                test_key(1)
            ),
        );
        let mut report = Report::default();
        let _ = config(&ctx, &ConfigCommand::Show, &mut report).unwrap();
        let text = report.text;
        let marked = |line: &str| text.lines().any(|l| l.starts_with(line) && l.ends_with(BUILT_IN));
        let plain = |line: &str| text.lines().any(|l| l == line);
        assert!(marked("socket = \""), "{text}");
        assert!(marked("socket = \"gpgconf:agent-extra-socket\""), "{text}");
        assert!(plain("add_to = \"fido\""), "{text}");
        assert!(marked("api_url = \"https://api.github.com\""), "{text}");
        assert!(plain("type = \"gitea\""), "{text}");
        assert!(marked("auth = \"token\""), "{text}");
        assert!(marked("cache = true") && plain("cache = false"), "{text}");
        let gh = text.split("[source.github]\n").nth(1).unwrap().split("\n\n").next().unwrap();
        assert!(gh.starts_with("type = \"github\"\nauth = \"gh\"") && !gh.contains("cache"), "{text}");
        assert!(marked("ssh.confirm = \"never\""), "{text}");
        assert!(plain("ssh.confirm = \"8h\""), "{text}");
        assert!(marked("per = \"repo\"") && plain("per = \"owner\""), "{text}");
        assert!(marked("hops.ssh = true"), "{text}");
        assert!(
            text.contains("[profile.unregistered]\nssh.keys = [\"fido\"]\nssh.confirm = \"always\""),
            "{text}"
        );
        assert!(marked("git_config = true"), "{text}");
        assert!(plain(&format!("host_keys = [\"{}\"]", test_key(1))), "{text}");
        assert!(plain("known_host = \"[follows.example]:2222\""), "{text}");
        let home = ctx.paths.home.display();
        assert!(marked(&format!("known_hosts_files = [\"{home}/.ssh/known_hosts\", ")), "{text}");
        assert!(plain(&format!("known_hosts_files = [\"{home}/.ssh/work\"]")), "{text}");
        // The output is a configuration that loads to the same thing.
        let shown = Config::parse(&text, &ctx.paths).unwrap_or_else(|error| panic!("{error}\n{text}"));
        assert_eq!(shown, load_config(&ctx).unwrap());
    }

    #[test]
    fn show_without_a_file_shows_the_defaults() {
        let (_dir, ctx) = context();
        let mut report = Report::default();
        let _ = config(&ctx, &ConfigCommand::Show, &mut report).unwrap();
        assert!(report.text.contains("(the file does not exist)"));
        assert!(report.text.contains("# No [agent]"));
        assert!(report.text.contains("[profile.unregistered]\nssh.keys = []"), "{}", report.text);
        assert_eq!(Config::parse(&report.text, &ctx.paths).unwrap(), Config::empty(&ctx.paths));
    }

    #[test]
    fn path_and_check() {
        let (_dir, ctx) = context();
        let mut report = Report::default();
        let _ = config(&ctx, &ConfigCommand::Path, &mut report).unwrap();
        assert_eq!(report.text, format!("{}\n", ctx.config_path.display()));
        write_config(&ctx, "version = 2\n[server.a]\nhost_keys = []\nprofile = \"nope\"\n");
        let mut report = Report::default();
        assert_eq!(config(&ctx, &ConfigCommand::Check, &mut report).unwrap(), ExitCode::FAILURE);
        assert!(report.text.contains("✗ config"), "{}", report.text);
        write_config(&ctx, FULL);
        let mut report = Report::default();
        assert_eq!(config(&ctx, &ConfigCommand::Check, &mut report).unwrap(), ExitCode::SUCCESS);
    }

    type AskFn<'a> = dyn FnMut(&str) -> std::io::Result<String> + 'a;

    /// An editor script that replaces the file with the next of `texts` on each run.
    fn fake_editor(dir: &Path, texts: &[&str]) -> String {
        let mut script = String::from(
            "#!/bin/sh\nn=$(cat \"$0.count\" 2>/dev/null || echo 0)\necho $((n + 1)) > \"$0.count\"\n",
        );
        for (index, text) in texts.iter().enumerate() {
            script.push_str(&format!("[ \"$n\" = {index} ] && cat > \"$1\" <<'EOF'\n{text}EOF\n"));
        }
        script.push_str("exit 0\n");
        let path = dir.join("editor.sh");
        std::fs::write(&path, script).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.display().to_string()
    }

    fn leftovers(ctx: &Context) -> Vec<String> {
        std::fs::read_dir(ctx.config_path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".edit-"))
            .collect()
    }

    #[test]
    fn edit_saves_a_valid_result() {
        let (dir, ctx) = context();
        write_config(&ctx, "# mine\nversion = 2\n");
        let editor = fake_editor(dir.path(), &["# mine\nversion = 2\n\n[profile.dev]\n"]);
        let mut report = Report::default();
        config_edit(&ctx, &editor, &mut |_| panic!("no question expected"), &mut report).unwrap();
        assert_eq!(
            std::fs::read_to_string(&ctx.config_path).unwrap(),
            "# mine\nversion = 2\n\n[profile.dev]\n"
        );
        assert!(report.text.contains("✓ config               edited in"), "{}", report.text);
        assert!(leftovers(&ctx).is_empty());
    }

    #[test]
    fn edit_asks_again_on_errors_and_can_abort() {
        let (dir, ctx) = context();
        write_config(&ctx, "version = 2\n");
        let bad = "version = 2\n[server.x]\nhost_keys = []\nprofile = \"nope\"\n";
        let editor = fake_editor(dir.path(), &[bad, "version = 2\n[profile.ok]\n"]);
        let mut questions = 0;
        let mut report = Report::default();
        config_edit(
            &ctx,
            &editor,
            &mut |_| {
                questions += 1;
                Ok("e".into())
            },
            &mut report,
        )
        .unwrap();
        assert_eq!(questions, 1);
        assert!(report.text.contains("would become invalid"), "{}", report.text);
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), "version = 2\n[profile.ok]\n");

        // Abort, and end of input (Ctrl-D) as an answer, keep the edited copy.
        let eof = || Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no answer"));
        let answers: [&mut AskFn<'_>; 2] = [&mut |_| Ok("a".into()), &mut |_| eof()];
        for ask in answers {
            let editor = fake_editor(dir.path(), &[bad]);
            std::fs::remove_file(format!("{editor}.count")).ok();
            let error = config_edit(&ctx, &editor, ask, &mut Report::default()).unwrap_err();
            assert!(error.to_string().starts_with("aborted"), "{error}");
            assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), "version = 2\n[profile.ok]\n");
            let kept = leftovers(&ctx);
            assert_eq!(kept.len(), 1, "{kept:?}");
            let copy = ctx.config_path.parent().unwrap().join(&kept[0]);
            assert!(
                error.to_string().ends_with(&format!("your version is in {}", copy.display())),
                "{error}"
            );
            assert_eq!(std::fs::read_to_string(&copy).unwrap(), bad);
            std::fs::remove_file(&copy).unwrap();
        }
    }

    /// A save that fails for another reason than the text keeps the edits.
    #[cfg(unix)]
    #[test]
    fn edit_keeps_the_copy_when_saving_fails() {
        use std::os::unix::fs::PermissionsExt as _;

        let (dir, ctx) = context();
        write_config(&ctx, "version = 2\n");
        std::fs::set_permissions(&ctx.config_path, std::fs::Permissions::from_mode(0o444)).unwrap();
        // As root, permissions do not stop writing: nothing to test.
        if std::fs::OpenOptions::new().write(true).open(&ctx.config_path).is_ok() {
            return;
        }
        let editor = fake_editor(dir.path(), &["version = 2\n[profile.ok]\n"]);
        let error =
            config_edit(&ctx, &editor, &mut |_| panic!("no question expected"), &mut Report::default())
                .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("is not writable") && message.contains("your version is in"), "{message}");
        let kept = leftovers(&ctx);
        assert_eq!(kept.len(), 1, "{kept:?}");
        let copy = ctx.config_path.parent().unwrap().join(&kept[0]);
        assert_eq!(std::fs::read_to_string(&copy).unwrap(), "version = 2\n[profile.ok]\n");
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), "version = 2\n");

        // A failing editor keeps changed text too, and drops an unchanged copy.
        std::fs::remove_file(&copy).unwrap();
        let editor = fake_editor(dir.path(), &["version = 2\n[profile.x]\n"]);
        std::fs::remove_file(format!("{editor}.count")).ok();
        let failing = format!("{editor} \"$1\"; false");
        let error = config_edit(&ctx, &failing, &mut |_| panic!(), &mut Report::default()).unwrap_err();
        assert!(error.to_string().contains("your version is in"), "{error}");
        let kept = leftovers(&ctx);
        assert_eq!(kept.len(), 1, "{kept:?}");
        std::fs::remove_file(ctx.config_path.parent().unwrap().join(&kept[0])).unwrap();
    }

    #[test]
    fn edit_without_changes_or_with_a_failing_editor_writes_nothing() {
        let (_dir, ctx) = context();
        let mut report = Report::default();
        config_edit(&ctx, "true", &mut |_| panic!(), &mut report).unwrap();
        assert!(report.text.contains("no changes"));
        assert!(!ctx.config_path.exists());
        assert!(
            config_edit(&ctx, "false", &mut |_| panic!(), &mut report)
                .unwrap_err()
                .to_string()
                .contains("failed")
        );
        assert!(leftovers(&ctx).is_empty());
    }
}
