//! `daemon install|uninstall|start|stop|status`: the daemon as a service.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use credential_bridge_config::paths::{APP_NAME, TargetOs};
use credential_bridge_platform::service::{
    ServiceManager, ServiceSpec, ServiceState, system_service_manager,
};
use credential_bridge_proto::ipc::control::{Request, Response};

use super::{CONTROL_TIMEOUT, Context, connect, daemon_config, load_config};
use crate::cli::ServiceCommand;
use crate::report::Line;

/// File name of the daemon binary.
const DAEMON_BINARY: &str = "credential-bridged";

/// The service definition `daemon install` writes: the `credential-bridged` next to
/// this binary, logging to `<state>/daemon.log` on macOS.
pub fn service_spec(ctx: &Context) -> anyhow::Result<ServiceSpec> {
    let exe = std::env::current_exe().context("cannot find this program's path")?;
    let dir = exe.parent().context("this program has no directory")?;
    let program = dir.join(DAEMON_BINARY);
    if !program.is_file() {
        bail!("{DAEMON_BINARY} not found next to credential-bridge-ctl (looked for {})", program.display());
    }
    Ok(spec_for(ctx, program, TargetOs::current()))
}

/// The spec for a given daemon binary and system (pure).
fn spec_for(ctx: &Context, program: PathBuf, os: TargetOs) -> ServiceSpec {
    let mut args = vec!["run".to_owned()];
    if ctx.config_path != ctx.paths.config_file {
        args.splice(0..0, ["--config".to_owned(), ctx.config_path.display().to_string()]);
    }
    ServiceSpec {
        name: APP_NAME.to_owned(),
        description: "credential-bridge: ssh-agent proxy with git tokens and gpg".to_owned(),
        program,
        args,
        env: Vec::new(),
        log_file: matches!(os, TargetOs::MacOs).then(|| ctx.paths.state_dir.join("daemon.log")),
    }
}

fn manager(ctx: &Context) -> Box<dyn ServiceManager> {
    let xdg_config = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).filter(|path| path.is_absolute());
    system_service_manager(&ctx.paths.home, xdg_config.as_deref())
}

/// `daemon install|…`: through `credential_bridge_platform::service::system_service_manager`.
pub fn service(ctx: &Context, command: &ServiceCommand) -> anyhow::Result<()> {
    let manager = manager(ctx);
    let spec = match command {
        ServiceCommand::Install => service_spec(ctx)?,
        // Removing, starting and stopping must work even if the binary moved.
        _ => service_spec(ctx)
            .unwrap_or_else(|_| spec_for(ctx, PathBuf::from(DAEMON_BINARY), TargetOs::current())),
    };
    let unit = manager.unit_path(&spec);
    match command {
        ServiceCommand::Install => {
            manager.install(&spec)?;
            println!("installed {} ({}) and started it", unit.display(), manager.name());
            if let Some(line) = leftover_v01_line(ctx) {
                eprintln!(
                    "warning: {}\n  {}",
                    line.detail,
                    line.hint.unwrap_or_default().replace('\n', "\n  ")
                );
            }
        }
        ServiceCommand::Uninstall => {
            manager.uninstall(&spec)?;
            println!("stopped and removed {}", unit.display());
        }
        ServiceCommand::Start => {
            manager.start(&spec)?;
            println!("started");
        }
        ServiceCommand::Stop => {
            manager.stop(&spec)?;
            println!("stopped");
        }
        ServiceCommand::Status => {
            let state = manager.status(&spec)?;
            println!("{}", state_text(&state, &unit));
            if matches!(state, ServiceState::Running { .. }) {
                println!("{}", daemon_text(ctx));
            }
        }
    }
    Ok(())
}

/// How long [`restart`] waits for the restarted daemon to answer.
const RESTART_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Restarts the daemon service (stop, then start) and waits until the daemon answers on
/// its control socket, so it reads `[daemon]` and `[vault]` again (`vault setup`). A
/// daemon that does not run as this service is not touched.
pub(crate) fn restart(ctx: &Context) -> anyhow::Result<()> {
    let manager = manager(ctx);
    let spec = service_spec(ctx)
        .unwrap_or_else(|_| spec_for(ctx, PathBuf::from(DAEMON_BINARY), TargetOs::current()));
    if !matches!(manager.status(&spec)?, ServiceState::Running { .. }) {
        bail!(
            "the daemon does not run as the {} service; restart it yourself (credential-bridge-ctl daemon install \
             sets up the service)",
            manager.name()
        );
    }
    manager.stop(&spec)?;
    manager.start(&spec)?;
    let config = load_config(ctx).ok();
    let daemon = daemon_config(ctx, config.as_ref());
    let deadline = std::time::Instant::now() + RESTART_WAIT;
    loop {
        if let Ok(mut client) = connect(&daemon, CONTROL_TIMEOUT)
            && matches!(client.request(&Request::Ping), Ok(Response::Pong { .. }))
        {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!("the daemon did not answer within {}s after the restart", RESTART_WAIT.as_secs());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// The service definitions credential-bridge 0.1 wrote that are still there: its
/// systemd unit (under the user manager's `XDG_CONFIG_HOME`, `~/.config` by default)
/// and its launchd plist. Its daemon may still run next to this one.
fn leftover_v01(ctx: &Context) -> Vec<PathBuf> {
    let home = &ctx.paths.home;
    let config_home = ctx.paths.config_file.parent().and_then(Path::parent).unwrap_or(home);
    let mut found: Vec<PathBuf> = Vec::new();
    for path in [
        config_home.join("systemd/user/credential-bridged.service"),
        home.join(".config/systemd/user/credential-bridged.service"),
        home.join("Library/LaunchAgents/local.credential-bridge.daemon.plist"),
    ] {
        if path.exists() && !found.contains(&path) {
            found.push(path);
        }
    }
    found
}

/// A warning about [`leftover_v01`] with the removal steps of CHANGELOG.md (0.2.0), if
/// there is any (`check`, `daemon install`).
pub(crate) fn leftover_v01_line(ctx: &Context) -> Option<Line> {
    let found = leftover_v01(ctx);
    if found.is_empty() {
        return None;
    }
    let list: Vec<String> = found.iter().map(|path| path.display().to_string()).collect();
    Some(
        Line::warn(
            "0.1 service",
            format!("credential-bridge 0.1's service is still installed: {}", list.join(", ")),
        )
        .with_hint(
            "stop it and delete the file (CHANGELOG.md, 0.2.0): \
             systemctl --user disable --now credential-bridged.service (Linux) or \
             launchctl bootout gui/$(id -u)/local.credential-bridge.daemon (macOS)",
        ),
    )
}

fn state_text(state: &ServiceState, unit: &Path) -> String {
    match state {
        ServiceState::NotInstalled => {
            "not installed; install with: credential-bridge-ctl daemon install".to_owned()
        }
        ServiceState::Stopped => format!("stopped ({})", unit.display()),
        ServiceState::Running { pid: Some(pid) } => format!("running, pid {pid} ({})", unit.display()),
        ServiceState::Running { pid: None } => format!("running ({})", unit.display()),
        ServiceState::Failed(reason) => format!("failed: {} ({})", super::printable(reason), unit.display()),
    }
}

/// Whether the daemon answers on its control socket.
fn daemon_text(ctx: &Context) -> String {
    let config = load_config(ctx).ok();
    let daemon = daemon_config(ctx, config.as_ref());
    match connect(&daemon, CONTROL_TIMEOUT).and_then(|mut client| client.request(&Request::Ping)) {
        Ok(Response::Pong { version, .. }) => {
            format!("daemon answers, version {}", super::printable(&version))
        }
        Ok(_) => "daemon answers unexpectedly".to_owned(),
        Err(error) => format!("daemon does not answer: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_support::context;

    #[test]
    fn spec_passes_a_non_default_config() {
        let (_dir, mut ctx) = context();
        let spec = spec_for(&ctx, PathBuf::from("/opt/bin/credential-bridged"), TargetOs::Linux);
        assert_eq!(spec.name, "credential-bridge");
        assert_eq!(spec.args, vec!["run"]);
        assert_eq!(spec.log_file, None);

        ctx.config_path = PathBuf::from("/etc/cb.toml");
        let spec = spec_for(&ctx, PathBuf::from("/opt/bin/credential-bridged"), TargetOs::MacOs);
        assert_eq!(spec.args, vec!["--config", "/etc/cb.toml", "run"]);
        assert_eq!(spec.log_file, Some(ctx.paths.state_dir.join("daemon.log")));
    }

    /// A unit or plist that 0.1 left behind is named with the removal steps.
    #[test]
    fn warns_about_a_leftover_v01_service() {
        let (_dir, ctx) = context();
        assert!(leftover_v01_line(&ctx).is_none());
        let unit = ctx.paths.home.join(".config/systemd/user/credential-bridged.service");
        let plist = ctx.paths.home.join("Library/LaunchAgents/local.credential-bridge.daemon.plist");
        for path in [&unit, &plist] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "").unwrap();
        }
        let line = leftover_v01_line(&ctx).unwrap();
        assert_eq!(line.status, crate::report::Status::Warn);
        assert_eq!(
            line.detail,
            format!(
                "credential-bridge 0.1's service is still installed: {}, {}",
                unit.display(),
                plist.display()
            )
        );
        let hint = line.hint.unwrap();
        assert!(hint.contains("systemctl --user disable --now credential-bridged.service"), "{hint}");
        assert!(hint.contains("CHANGELOG.md, 0.2.0"), "{hint}");
    }

    #[test]
    fn describes_states() {
        let unit = Path::new("/u/credential-bridge.service");
        assert_eq!(
            state_text(&ServiceState::Running { pid: Some(7) }, unit),
            "running, pid 7 (/u/credential-bridge.service)"
        );
        assert!(state_text(&ServiceState::NotInstalled, unit).contains("daemon install"));
    }
}
