//! `doctor`: checks the local setup, grouped into Local, Service and Remotes.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use crate::remote::{self, ForwardStatus};
use crate::ui::{self, Level};
use crate::util::{SocketState, is_executable, socket_state, which};
use crate::{Ctx, service};

/// Width of the group labels; checks start in this column.
const LABEL: usize = 10;

/// A problem: one line with a symbol, and the command that fixes it.
#[derive(Debug)]
struct Issue {
    level: Level,
    text: String,
    fix: Option<String>,
}

/// Passed checks are listed inline after the label; issues below it.
#[derive(Debug, Default)]
struct Group {
    passed: Vec<String>,
    issues: Vec<Issue>,
}

impl Group {
    fn pass(&mut self, text: impl Into<String>) {
        self.passed.push(text.into());
    }

    fn issue(&mut self, level: Level, text: impl Into<String>, fix: Option<String>) {
        self.issues.push(Issue { level, text: text.into(), fix });
    }

    fn print(&self, title: &str) {
        let passed: Vec<String> =
            self.passed.iter().map(|text| format!("{} {text}", Level::Ok.symbol())).collect();
        println!("{}{}", ui::bold(&ui::pad(title, LABEL)), passed.join("  "));
        for issue in &self.issues {
            println!("{:LABEL$}{} {}", "", issue.level.symbol(), issue.text);
            if let Some(fix) = &issue.fix {
                println!("{}", ui::fix(LABEL + 2, fix));
            }
        }
    }

    fn count(&self, level: Level) -> usize {
        self.issues.iter().filter(|issue| issue.level == level).count()
    }
}

pub fn run(ctx: &Ctx) -> anyhow::Result<ExitCode> {
    let (local, config) = check_local(ctx);
    let service = check_service();
    let remotes = config.as_ref().map(check_remotes);

    local.print("Local");
    service.print("Service");
    if let Some(remotes) = &remotes {
        remotes.print("Remotes");
    }

    let groups = [Some(&local), Some(&service), remotes.as_ref()];
    let failures: usize = groups.iter().flatten().map(|g| g.count(Level::Fail)).sum();
    let warnings: usize = groups.iter().flatten().map(|g| g.count(Level::Warn)).sum();
    println!();
    match (failures, warnings) {
        (0, 0) => println!("{}", ui::green(&ui::bold("✓ all good"))),
        (0, w) => println!("{}", ui::yellow(&ui::plural(w, "warning", "warnings"))),
        (f, w) => println!(
            "{}{}",
            ui::red(&ui::bold(&ui::plural(f, "problem", "problems"))),
            if w > 0 {
                ui::dim(&format!(", {}", ui::plural(w, "warning", "warnings")))
            } else {
                String::new()
            }
        ),
    }
    Ok(if failures == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

fn check_local(ctx: &Ctx) -> (Group, Option<credential_bridge_core::config::Config>) {
    let mut group = Group::default();
    let config = match ctx.load() {
        Ok(config) => {
            if ctx.config_path.exists() {
                let detail = if ui::verbose() {
                    format!(
                        "{}, {}",
                        ui::home_tilde(&ctx.config_path),
                        ui::plural(config.remotes.len(), "remote", "remotes")
                    )
                } else {
                    ui::plural(config.remotes.len(), "remote", "remotes")
                };
                group.pass(format!("config {}", ui::dim(&format!("({detail})"))));
            } else {
                group.issue(
                    Level::Warn,
                    format!("no config at {}", ui::home_tilde(&ctx.config_path)),
                    Some("credential-bridge-ctl remote add NAME --allow https://github.com/ORG/*".into()),
                );
            }
            Some(config)
        }
        Err(err) => {
            group.issue(
                Level::Fail,
                format!("config: {err:#}"),
                Some("credential-bridge-ctl config edit".into()),
            );
            None
        }
    };

    let git_exec_path = match Command::new("git").arg("--exec-path").output() {
        Ok(out) if out.status.success() => {
            group.pass("git");
            Some(PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()))
        }
        _ => {
            group.issue(Level::Warn, "git not found (needed for backends given by helper name)", None);
            None
        }
    };

    let helpers = remote::available_helpers();
    if helpers.is_empty() {
        group.issue(
            Level::Warn,
            "no helpers for servers found; `remote install` needs `--binary PATH`",
            Some(
                "use a release package, or put helpers into ~/.local/share/credential-bridge/helpers/".into(),
            ),
        );
    } else {
        let platforms: Vec<&str> = helpers.iter().map(|p| p.strip_suffix("-linux").unwrap_or(p)).collect();
        group.pass(format!("helpers {}", ui::dim(&platforms.join(" "))));
    }

    if let Some(config) = &config {
        let backends: BTreeSet<&str> = config
            .remotes
            .iter()
            .map(|remote| remote.backend.as_deref().unwrap_or(&config.backend))
            .collect();
        for backend in backends {
            match check_backend(backend, git_exec_path.as_ref()) {
                BackendCheck::Found(path) => {
                    let name = path
                        .file_name()
                        .map_or_else(|| backend.to_owned(), |n| n.to_string_lossy().into_owned());
                    let detail = if ui::verbose() {
                        format!(" {}", ui::dim(&ui::home_tilde(&path)))
                    } else {
                        String::new()
                    };
                    group.pass(format!("backend {}{detail}", ui::dim(&name)));
                }
                BackendCheck::Missing(program) => group.issue(
                    Level::Fail,
                    format!("backend '{backend}': `{program}` not found in PATH"),
                    Some("install it, or change `backend` with `credential-bridge-ctl config edit`".into()),
                ),
                BackendCheck::Unknown => group.issue(
                    Level::Warn,
                    format!("backend '{backend}' is a shell snippet and cannot be checked"),
                    None,
                ),
            }
        }
    }
    (group, config)
}

fn check_service() -> Group {
    let mut group = Group::default();
    let manager = match service::manager() {
        Ok(manager) => manager,
        Err(err) => {
            group.issue(Level::Warn, format!("{err:#}"), None);
            return group;
        }
    };
    if !manager.is_installed() {
        group.issue(Level::Fail, "not installed", Some("credential-bridge-ctl service install".into()));
        return group;
    }
    if manager.is_active() {
        let info = manager.info();
        let facts: Vec<String> = info
            .pid
            .map(|pid| format!("pid {pid}"))
            .into_iter()
            .chain(info.since.map(|s| format!("since {s}")))
            .collect();
        group.pass(format!("running {}", ui::dim(&facts.join(" · "))).trim_end().to_owned());
    } else {
        group.issue(
            Level::Fail,
            "installed but not running",
            Some("credential-bridge-ctl service start".into()),
        );
    }
    if let Some(program) = manager.installed_program() {
        if service::is_store_path(&program) {
            group.issue(
                Level::Warn,
                format!("daemon runs from the Nix store {}", ui::dim("(breaks after update/GC)")),
                Some(
                    "credential-bridge-ctl service install --daemon-path ~/.local/bin/credential-bridged"
                        .into(),
                ),
            );
        } else if !is_executable(&program) {
            group.issue(
                Level::Fail,
                format!("daemon {} does not exist", ui::home_tilde(&program)),
                Some("credential-bridge-ctl service install".into()),
            );
        }
    }
    group
}

fn check_remotes(config: &credential_bridge_core::config::Config) -> Group {
    let mut group = Group::default();
    if config.remotes.is_empty() {
        group.issue(
            Level::Warn,
            "no remotes configured",
            Some("credential-bridge-ctl remote add NAME --allow https://github.com/ORG/*".into()),
        );
        return group;
    }
    let width = config.remotes.iter().map(|r| r.name.chars().count()).max().unwrap_or(0);
    for remote in &config.remotes {
        let name = ui::pad(&remote.name, width);
        let mut issues: Vec<(Level, String, String)> = Vec::new();
        match config.socket_path(&remote.name).map(|socket| socket_state(&socket)) {
            Ok(SocketState::Listening) => {}
            Ok(state) => issues.push((
                Level::Fail,
                format!("local socket {state}"),
                "credential-bridge-ctl service reload".into(),
            )),
            Err(err) => {
                issues.push((Level::Fail, err.to_string(), "credential-bridge-ctl config edit".into()))
            }
        }
        if remote.remote_socket.is_none() {
            issues.push((
                Level::Warn,
                "not installed on the remote".into(),
                format!("credential-bridge-ctl remote install {}", remote.name),
            ));
        }
        match remote::forward_status(config, remote) {
            Ok(ForwardStatus::Configured) => {}
            Ok(ForwardStatus::Unknown(err)) => issues.push((
                Level::Warn,
                format!("cannot check the ssh config: {err}"),
                format!("ssh -G {}", remote.ssh_target()),
            )),
            Ok(status) => issues.push((
                Level::Fail,
                format!("ssh config {status}"),
                format!("credential-bridge-ctl remote ssh-config {}", remote.name),
            )),
            Err(err) => issues.push((Level::Warn, format!("{err:#}"), String::new())),
        }
        if issues.is_empty() {
            group.issues.push(Issue {
                level: Level::Ok,
                text: format!("{name}  {}", ui::dim("socket · installed · RemoteForward")),
                fix: None,
            });
        }
        for (level, text, fix) in issues {
            group.issue(level, format!("{name}  {text}"), Some(fix).filter(|f| !f.is_empty()));
        }
    }
    group
}

enum BackendCheck {
    Found(PathBuf),
    Missing(String),
    Unknown,
}

/// Resolves the program a backend spec runs (same rules as git).
fn check_backend(spec: &str, git_exec_path: Option<&PathBuf>) -> BackendCheck {
    let spec = spec.trim();
    if let Some(command) = spec.strip_prefix('!') {
        let Some(program) = command.split_whitespace().next() else {
            return BackendCheck::Unknown;
        };
        if program.contains(['(', ')', ';', '{', '$', '|', '&', '=']) {
            return BackendCheck::Unknown;
        }
        return resolve(program);
    }
    let Some(first) = spec.split_whitespace().next() else {
        return BackendCheck::Unknown;
    };
    if first.starts_with('/') {
        return resolve(first);
    }
    let program = format!("git-credential-{first}");
    if let Some(found) = git_exec_path.map(|dir| dir.join(&program)).filter(|p| is_executable(p)) {
        return BackendCheck::Found(found);
    }
    resolve(&program)
}

fn resolve(program: &str) -> BackendCheck {
    if program.contains('/') {
        let path = PathBuf::from(program);
        return if is_executable(&path) {
            BackendCheck::Found(path)
        } else {
            BackendCheck::Missing(program.to_owned())
        };
    }
    which(program).map_or_else(|| BackendCheck::Missing(program.to_owned()), BackendCheck::Found)
}
