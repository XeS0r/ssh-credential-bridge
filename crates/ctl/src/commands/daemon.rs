//! Commands that talk to the daemon: `daemon alive`, `daemon reload`, `server keys`,
//! `server token`, `vault unlock`, `vault lock`.

use std::io::{BufRead as _, Read as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context as _, bail};
use credential_bridge_config::paths::Paths;
use credential_bridge_config::{GitTarget, VaultKind};
use credential_bridge_platform::socket::is_listening;
use credential_bridge_proto::ipc::control::{KeyInfo, Request, Response, TokenTestResult};
use credential_bridge_proto::secret::Secret;
use zeroize::Zeroizing;

use super::change::{moved_paths_line, moved_vault_line};
use super::{
    Context, SLOW_CONTROL_TIMEOUT, connect, daemon_config, daemon_paths, load_config, printable,
    relative_time, reload_daemon,
};
use crate::cli::{KeysArgs, ServerTokenArgs, UnlockArgs, VaultLockArgs};
use crate::control::ControlError;
use crate::report::{Line, Report};

/// How long `daemon alive` waits for the socket.
const ALIVE_TIMEOUT: Duration = Duration::from_millis(200);

/// `daemon alive`: [`credential_bridge_platform::socket::is_listening`] on the agent
/// socket with a 200 ms timeout. No output. The socket is `[daemon] socket` read on its
/// own ([`credential_bridge_config::daemon_settings`]), so a mistake elsewhere in the
/// configuration does not make `daemon alive` check the wrong socket.
pub fn alive(config: Option<PathBuf>) -> ExitCode {
    let Ok(paths) = Paths::discover() else { return ExitCode::FAILURE };
    let path = config.unwrap_or_else(|| paths.config_file.clone());
    alive_at(&path, &paths)
}

/// [`alive`] for the configuration file `path`.
fn alive_at(path: &std::path::Path, paths: &Paths) -> ExitCode {
    let socket = credential_bridge_config::daemon_settings(path, paths).socket;
    if is_listening(&socket, ALIVE_TIMEOUT) { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

/// `daemon reload`: control request `Reload`. The daemon re-reads its configuration
/// file; if that is invalid it keeps the old one and says why. Afterwards the paths the
/// daemon uses are compared with `[daemon]` and `[vault.keepassxc]`, which change only on
/// a restart. Exit code 1 if it did not reload.
pub fn daemon_reload(ctx: &Context, report: &mut Report) -> ExitCode {
    let config = load_config(ctx).ok();
    let daemon = daemon_config(ctx, config.as_ref());
    let failed = match reload_daemon(&daemon) {
        Ok(true) => None,
        Ok(false) => Some(
            Line::fail("daemon", "not running; it reads the configuration when it starts")
                .with_hint("credential-bridge-ctl daemon start"),
        ),
        Err(ControlError::Daemon(error)) => Some(
            Line::fail(
                "daemon",
                format!("did not reload, it keeps the configuration it had: {}", printable(&error.message)),
            )
            .with_hint("credential-bridge-ctl config check"),
        ),
        Err(error) => Some(Line::fail("daemon", format!("reload failed: {error}"))),
    };
    if let Some(line) = failed {
        report.push(line);
        return ExitCode::FAILURE;
    }
    report.push(Line::ok("daemon", "reloaded the configuration"));
    // Only against a file that loads: the defaults would report every custom path.
    if let Some(config) = &config
        && let Ok(paths) = daemon_paths(&daemon)
    {
        let lines = [moved_paths_line(&paths, &daemon), moved_vault_line(&paths, &config.vault.keepassxc)];
        lines.into_iter().flatten().for_each(|line| report.push(line));
    }
    ExitCode::SUCCESS
}

/// Sends one request that may take a while.
fn slow_request(ctx: &Context, request: &Request) -> anyhow::Result<Response> {
    let config = load_config(ctx).ok();
    let daemon = daemon_config(ctx, config.as_ref());
    let mut client = connect(&daemon, SLOW_CONTROL_TIMEOUT)?;
    Ok(client.request(request)?)
}

/// `server keys`: control request `Keys`.
pub fn keys(ctx: &Context, args: &KeysArgs) -> anyhow::Result<()> {
    if let Some(server) = &args.server
        && let Ok(config) = load_config(ctx)
        && !config.servers.contains_key(server)
    {
        bail!("no [server.{server}] in {}", ctx.config_path.display());
    }
    let keys = match slow_request(ctx, &Request::Keys { server: args.server.clone() })? {
        Response::Keys(keys) => keys,
        _ => return Err(ControlError::Unexpected.into()),
    };
    print!("{}", keys_text(args.server.as_deref(), &keys));
    Ok(())
}

/// What `server keys` prints.
fn keys_text(server: Option<&str>, keys: &[KeyInfo]) -> String {
    let who = server.map_or_else(|| "agent.sock".to_owned(), |server| server.to_owned());
    if keys.is_empty() {
        return format!("{who} sees no keys\n");
    }
    let width = keys.iter().map(|key| key.upstream.len()).max().unwrap_or(0).max(8);
    let mut out = format!("{:<width$}  KEY\n", "UPSTREAM");
    for key in keys {
        let mut line = format!("{:<width$}  {}", printable(&key.upstream), printable(&key.fingerprint));
        if !key.comment.is_empty() {
            line.push_str(&format!("  {}", printable(&key.comment)));
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// A vault with an unlock session, as `vault unlock` and `vault lock` take it.
fn session_vault(name: &str) -> anyhow::Result<VaultKind> {
    let vault: VaultKind = name.parse().map_err(|_| {
        anyhow::anyhow!("unknown vault {name:?}; vaults with an unlock session: bitwarden, keepassxc")
    })?;
    if !vault.has_unlock_session() {
        bail!("{vault} has no unlock session; it is unlocked through its own app or your login");
    }
    Ok(vault)
}

/// `vault unlock`: reads the password without echo (or from stdin) and sends control
/// request `Unlock`.
pub fn unlock(ctx: &Context, args: &UnlockArgs) -> anyhow::Result<()> {
    let vault = session_vault(&args.vault)?;
    let ttl_secs = match &args.ttl {
        Some(ttl) => Some(credential_bridge_config::duration::parse_duration(ttl)?.as_secs()),
        None => None,
    };
    let password = if args.password_stdin {
        read_password_stdin()?
    } else {
        crate::tty::read_password(&format!("{vault} master password: "))?
    };
    if password.is_empty() {
        bail!("no password given");
    }
    let request = Request::Unlock { vault: vault.name().to_owned(), password, ttl_secs };
    match slow_request(ctx, &request)? {
        Response::Unlocked { expires_at } => {
            println!("{vault} unlocked; the session expires {}", relative_time(expires_at));
            Ok(())
        }
        _ => Err(ControlError::Unexpected.into()),
    }
}

/// `vault lock`: control request `Lock` for one vault, or for every vault with `--all`.
/// The session key is dropped in the vault worker; nothing is unlocked afterwards.
pub fn lock(ctx: &Context, args: &VaultLockArgs) -> anyhow::Result<()> {
    let vault = args.vault.as_deref().map(session_vault).transpose()?;
    let request = Request::Lock { vault: vault.map(|vault| vault.name().to_owned()) };
    match slow_request(ctx, &request)? {
        Response::Locked => {
            match vault {
                Some(vault) => println!("{vault} locked"),
                None => println!("every vault locked"),
            }
            Ok(())
        }
        _ => Err(ControlError::Unexpected.into()),
    }
}

/// One line from stdin without its line ending.
fn read_password_stdin() -> anyhow::Result<Secret> {
    let mut line = Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .take(64 * 1024)
        .read_line(&mut line)
        .context("cannot read the password from stdin")?;
    Ok(Secret::new(line.trim_end_matches(['\r', '\n']).to_owned()))
}

/// `server token`: control request `TokenTest`.
pub fn server_token(ctx: &Context, args: &ServerTokenArgs) -> anyhow::Result<()> {
    GitTarget::parse_url(&args.url).map_err(|error| anyhow::anyhow!("{}: {}", error.input, error.reason))?;
    let request = Request::TokenTest { server: args.server.clone(), url: args.url.clone() };
    let result = match slow_request(ctx, &request)? {
        Response::Token(result) => result,
        _ => return Err(ControlError::Unexpected.into()),
    };
    print!("{}", token_text(&args.url, &result));
    if result.rule.is_none() {
        bail!("no rule of profile {} matches {}", result.profile, args.url);
    }
    Ok(())
}

/// What `server token` prints. The token itself never reaches ctl.
fn token_text(url: &str, result: &TokenTestResult) -> String {
    let mut out = format!("url       {url}\nprofile   {}\n", printable(&result.profile));
    let Some(rule) = &result.rule else {
        out.push_str("rule      none matches: git gets no credential\n");
        return out;
    };
    out.push_str(&format!("rule      {}\n", printable(rule)));
    if let Some(source) = &result.source {
        out.push_str(&format!("source    {}\n", printable(source)));
    }
    if let Some(username) = &result.username {
        out.push_str(&format!("username  {}\n", printable(username)));
    }
    let expiry = result.expires_at.map_or_else(String::new, |at| format!(", expires {}", relative_time(at)));
    out.push_str(&format!("token     (redacted){expiry}\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A custom `[daemon] socket` is found even if another part of the configuration is
    /// invalid.
    #[test]
    fn alive_finds_a_custom_socket_despite_other_mistakes() {
        let dir = tempfile::tempdir().unwrap();
        let vars = credential_bridge_config::paths::PathVars {
            home: Some(dir.path().as_os_str().to_owned()),
            ..Default::default()
        };
        let paths = Paths::from_vars(&vars, credential_bridge_config::paths::TargetOs::current()).unwrap();
        let socket = dir.path().join("custom.sock");
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!("version = 2\n[daemon]\nsocket = \"{}\"\n[profile.x]\nunknown = 1\n", socket.display()),
        )
        .unwrap();
        assert_eq!(alive_at(&config, &paths), ExitCode::FAILURE, "nothing listens yet");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        assert_eq!(alive_at(&config, &paths), ExitCode::SUCCESS);
    }

    #[test]
    fn formats_keys() {
        let keys = vec![
            KeyInfo {
                upstream: "yubikey".into(),
                fingerprint: "ssh-ed25519 SHA256:abc".into(),
                comment: "card".into(),
            },
            KeyInfo {
                upstream: "1password".into(),
                fingerprint: "ssh-rsa SHA256:def".into(),
                comment: String::new(),
            },
        ];
        assert_eq!(
            keys_text(Some("buildserver"), &keys),
            "UPSTREAM   KEY\nyubikey    ssh-ed25519 SHA256:abc  card\n1password  ssh-rsa SHA256:def\n"
        );
        assert_eq!(keys_text(None, &[]), "agent.sock sees no keys\n");
    }

    #[test]
    fn token_output_never_has_a_token() {
        let result = TokenTestResult {
            profile: "build".into(),
            rule: Some("https://github.com/my-org/*".into()),
            source: Some("my-org".into()),
            username: Some("x-access-token".into()),
            expires_at: None,
        };
        assert_eq!(
            token_text("https://github.com/my-org/app", &result),
            "url       https://github.com/my-org/app\nprofile   build\nrule      https://github.com/my-org/*\n\
             source    my-org\nusername  x-access-token\ntoken     (redacted)\n"
        );
        let none = TokenTestResult { rule: None, source: None, username: None, ..result };
        assert!(token_text("https://x", &none).contains("none matches"));
    }

    #[test]
    fn unlock_rejects_vaults_without_session() {
        let (_dir, ctx) = crate::commands::test_support::context();
        let args = UnlockArgs { vault: "1password".into(), ttl: None, password_stdin: true };
        assert!(unlock(&ctx, &args).unwrap_err().to_string().contains("no unlock session"));
        let args = UnlockArgs { vault: "lastpass".into(), ttl: None, password_stdin: true };
        assert!(unlock(&ctx, &args).unwrap_err().to_string().contains("unknown vault"));
        let args = UnlockArgs { vault: "bw".into(), ttl: Some("forever".into()), password_stdin: true };
        assert!(unlock(&ctx, &args).is_err());
    }

    #[test]
    fn lock_rejects_vaults_without_session() {
        let (_dir, ctx) = crate::commands::test_support::context();
        let args = VaultLockArgs { vault: Some("1password".into()), all: false };
        assert!(lock(&ctx, &args).unwrap_err().to_string().contains("no unlock session"));
        let args = VaultLockArgs { vault: Some("lastpass".into()), all: false };
        assert!(lock(&ctx, &args).unwrap_err().to_string().contains("unknown vault"));
    }

    #[test]
    fn lock_sends_one_vault_or_all() {
        let (_dir, ctx) = crate::commands::test_support::context();
        crate::commands::test_support::fake_daemon(&ctx.paths.control_socket, Response::Locked);
        lock(&ctx, &VaultLockArgs { vault: Some("bw".into()), all: false }).unwrap();
        lock(&ctx, &VaultLockArgs { vault: None, all: true }).unwrap();
    }

    #[test]
    fn reload_reports_a_reload() {
        let (_dir, ctx) = crate::commands::test_support::context();
        let requests =
            crate::commands::test_support::recording_daemon(&ctx.paths.control_socket, Response::Reloaded);
        let mut report = Report::default();
        assert_eq!(daemon_reload(&ctx, &mut report), ExitCode::SUCCESS);
        assert_eq!(report.text, "✓ daemon               reloaded the configuration\n");
        assert_eq!(requests.lock().unwrap().first(), Some(&Request::Reload));
    }

    #[test]
    fn reload_shows_why_the_daemon_refused() {
        let (_dir, ctx) = crate::commands::test_support::context();
        let error = credential_bridge_proto::ipc::WorkerError::new(
            credential_bridge_proto::ipc::WorkerErrorKind::Invalid,
            "/home/me/config.toml: 1 problem(s): profile.dev: unknown upstream \"fido\"",
        );
        crate::commands::test_support::fake_daemon(&ctx.paths.control_socket, Response::Error(error));
        let mut report = Report::default();
        assert_eq!(daemon_reload(&ctx, &mut report), ExitCode::FAILURE);
        assert_eq!(
            report.text,
            "✗ daemon               did not reload, it keeps the configuration it had: \
             /home/me/config.toml: 1 problem(s): profile.dev: unknown upstream \"fido\"\n  \
             \x20                    → credential-bridge-ctl config check\n"
        );
    }

    /// A file that does not load still names the daemon's control socket: the reload
    /// reaches the daemon, which says what is wrong.
    #[test]
    fn reload_of_an_invalid_file_reaches_a_custom_control_socket() {
        let (dir, ctx) = crate::commands::test_support::context();
        let socket = dir.path().join("custom/control.sock");
        crate::commands::test_support::write_config(
            &ctx,
            &format!(
                "version = 2\n[daemon]\ncontrol_socket = \"{}\"\naudit_log = \"~/elsewhere.log\"\n\
                 [profile.dev]\nssh = {{ keys = [\"fido\"] }}\n",
                socket.display()
            ),
        );
        assert!(load_config(&ctx).is_err());
        // Also `log`, `daemon install` and the vault commands find the custom paths.
        let daemon = daemon_config(&ctx, None);
        assert_eq!((daemon.control_socket, daemon.socket), (socket.clone(), ctx.paths.agent_socket.clone()));
        assert_eq!(daemon.audit_log, ctx.paths.home.join("elsewhere.log"));
        let error = credential_bridge_proto::ipc::WorkerError::new(
            credential_bridge_proto::ipc::WorkerErrorKind::Invalid,
            "profile.dev: unknown upstream \"fido\"",
        );
        let requests = crate::commands::test_support::recording_daemon(&socket, Response::Error(error));
        let mut report = Report::default();
        assert_eq!(daemon_reload(&ctx, &mut report), ExitCode::FAILURE);
        assert!(report.text.contains("did not reload, it keeps the configuration it had"), "{}", report.text);
        assert!(report.text.contains("→ credential-bridge-ctl config check"), "{}", report.text);
        assert_eq!(*requests.lock().unwrap(), vec![Request::Reload]);
    }

    #[test]
    fn reload_without_a_daemon_says_how_to_start_it() {
        let (_dir, ctx) = crate::commands::test_support::context();
        let mut report = Report::default();
        assert_eq!(daemon_reload(&ctx, &mut report), ExitCode::FAILURE);
        assert!(report.text.contains("✗ daemon               not running"), "{}", report.text);
        assert!(report.text.contains("→ credential-bridge-ctl daemon start\n"), "{}", report.text);
    }

    /// After a reload, sockets and KeePassXC files the daemon still uses from before a
    /// `[daemon]` or `[vault]` change need a restart.
    #[test]
    fn reload_reports_daemon_paths_that_need_a_restart() {
        let (_dir, ctx) = crate::commands::test_support::context();
        crate::commands::test_support::write_config(
            &ctx,
            "version = 2\n[vault.keepassxc]\ndatabase = \"~/db.kdbx\"\n",
        );
        let configured = credential_bridge_config::DaemonConfig::from_paths(&ctx.paths);
        let paths = credential_bridge_proto::ipc::control::DaemonPaths {
            socket: "/run/old.sock".into(),
            forward_socket: configured.forward_socket.display().to_string(),
            control_socket: configured.control_socket.display().to_string(),
            audit_log: configured.audit_log.display().to_string(),
            keepassxc_database: Some("/old/db.kdbx".into()),
            keepassxc_key_file: None,
        };
        let socket = &configured.control_socket;
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let answer = match credential_bridge_proto::ipc::read_frame(&mut stream) {
                    Ok(Some(Request::Reload)) => Response::Reloaded,
                    Ok(Some(Request::Ping)) => {
                        Response::Pong { version: crate::commands::VERSION.into(), paths: paths.clone() }
                    }
                    _ => continue,
                };
                let _ = credential_bridge_proto::ipc::write_frame(&mut stream, &answer);
            }
        });
        let mut report = Report::default();
        assert_eq!(daemon_reload(&ctx, &mut report), ExitCode::SUCCESS);
        assert!(report.text.contains("reloaded the configuration"), "{}", report.text);
        assert!(
            report.text.contains(&format!(
                "⚠ daemon               uses socket /run/old.sock (configured: {})",
                configured.socket.display()
            )),
            "{}",
            report.text
        );
        assert!(report.text.contains("[daemon] changes take effect on a restart"), "{}", report.text);
        assert!(
            report.text.contains(&format!(
                "⚠ daemon               uses [vault.keepassxc] database /old/db.kdbx (configured: {})",
                ctx.paths.home.join("db.kdbx").display()
            )),
            "{}",
            report.text
        );
        assert!(report.text.contains("[vault] changes take effect on a restart"), "{}", report.text);
    }

    #[test]
    fn server_token_checks_the_url_first() {
        let (_dir, ctx) = crate::commands::test_support::context();
        let args = ServerTokenArgs { server: "b".into(), url: "not a url".into() };
        assert!(server_token(&ctx, &args).is_err());
    }
}
