//! One function per subcommand.
//!
//! Commands that reach servers have a `*_with` variant taking a
//! [`RemoteShell`](crate::remote::RemoteShell), so tests can run them against a fake.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context as _;
use clap::CommandFactory;
use credential_bridge_config::paths::Paths;
use credential_bridge_config::{Config, ConfigError, DaemonConfig};
use credential_bridge_proto::ipc::control::DaemonPaths;

use crate::cli::{Cli, Command, CompletionsArgs, DaemonCommand, GenerateManArgs, GpgCommand, ServerCommand};
use crate::control::{ControlClient, ControlError};
use crate::report::Report;

mod agent;
mod change;
mod check;
mod config;
mod daemon;
mod github_app;
mod gpg;
mod init;
mod log;
mod probe;
mod profile;
mod server;
mod service;
mod settings;
mod source;
mod vault;

pub use agent::agent;
pub use check::{check, check_with};
pub use config::config;
pub use daemon::{alive, daemon_reload, keys, lock, server_token, unlock};
pub use github_app::{app_manifest, github_app_create};
pub use gpg::{gpg_conf_line, gpg_setup, gpg_setup_with};
pub use init::init;
pub use log::{format_event, log};
pub use profile::profile;
pub use server::{
    server_add, server_add_with, server_list, server_remove, server_remove_with, server_set, server_show,
    server_uninstall, server_uninstall_with, ssh_config,
};
pub use service::{service, service_spec};
pub use settings::{daemon_set, gpg_remove, gpg_set};
pub use source::source;
pub use vault::vault;

/// What every command needs.
#[derive(Debug, Clone)]
pub struct Context {
    /// Well-known paths.
    pub paths: Paths,
    /// The configuration file (`--config` or the default).
    pub config_path: PathBuf,
}

/// Time allowed for quick control requests (ping, status, reload).
pub(crate) const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

/// Time allowed for control requests that may wait for vault tools, touches or the
/// network (unlock, store, source test, server token, server keys).
pub(crate) const SLOW_CONTROL_TIMEOUT: Duration = Duration::from_secs(180);

/// This program's version, compared with the daemon's and the remote binary's.
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Runs `cli`. `daemon alive` returns 0/1 without output; `check` returns 1 if anything
/// failed; every other command returns 1 on error after printing it.
pub fn run(cli: Cli) -> ExitCode {
    let result = match cli.command {
        Command::Daemon(DaemonCommand::Alive) => return alive(cli.config),
        Command::Completions(args) => completions(&args),
        Command::GenerateMan(args) => generate_man(&args),
        command => Paths::discover().map_err(anyhow::Error::from).and_then(|paths| {
            let config_path = cli.config.clone().unwrap_or_else(|| paths.config_file.clone());
            let ctx = Context { paths, config_path };
            dispatch(&ctx, command)
        }),
    };
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("credential-bridge-ctl: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(ctx: &Context, command: Command) -> anyhow::Result<ExitCode> {
    let done = |result: anyhow::Result<()>| result.map(|()| ExitCode::SUCCESS);
    match command {
        Command::Server(ServerCommand::Add(args)) => done(server_add(ctx, &args)),
        Command::Server(ServerCommand::List) => done(server_list(ctx)),
        Command::Server(ServerCommand::Show(args)) => done(server_show(ctx, &args)),
        Command::Server(ServerCommand::Set(args)) => done(server_set(ctx, &args, &mut Report::printing())),
        Command::Server(ServerCommand::Remove(args)) => done(server_remove(ctx, &args)),
        Command::Server(ServerCommand::Uninstall(args)) => done(server_uninstall(ctx, &args)),
        Command::Server(ServerCommand::SshConfig(args)) => done(ssh_config(ctx, &args)),
        Command::Server(ServerCommand::Keys(args)) => done(keys(ctx, &args)),
        Command::Server(ServerCommand::Token(args)) => done(server_token(ctx, &args)),
        Command::Init(args) => done(init(ctx, &args, &mut Report::printing())),
        Command::Config(command) => config(ctx, &command, &mut Report::printing()),
        Command::Daemon(DaemonCommand::Set(args)) => done(daemon_set(ctx, &args, &mut Report::printing())),
        Command::Daemon(DaemonCommand::Reload) => Ok(daemon_reload(ctx, &mut Report::printing())),
        Command::Daemon(DaemonCommand::Service(command)) => done(service(ctx, &command)),
        Command::Agent(command) => done(agent(ctx, &command, &mut Report::printing())),
        Command::Source(command) => done(source(ctx, &command, &mut Report::printing())),
        Command::Profile(command) => done(profile(ctx, &command, &mut Report::printing())),
        Command::Vault(command) => done(vault(ctx, &command, &mut Report::printing())),
        Command::Gpg(GpgCommand::Setup(args)) => done(gpg_setup(ctx, &args)),
        Command::Gpg(GpgCommand::Set(args)) => done(gpg_set(ctx, &args, &mut Report::printing())),
        Command::Gpg(GpgCommand::Remove(args)) => done(gpg_remove(ctx, &args, &mut Report::printing())),
        Command::Check(args) => check(ctx, &args),
        Command::Log(args) => done(log(ctx, &args)),
        Command::Daemon(DaemonCommand::Alive) | Command::Completions(_) | Command::GenerateMan(_) => {
            unreachable!("handled before paths are discovered")
        }
    }
}

/// `completions <shell>`: the completion script on stdout.
fn completions(args: &CompletionsArgs) -> anyhow::Result<ExitCode> {
    let mut command = Cli::command();
    clap_complete::generate(args.shell, &mut command, "credential-bridge-ctl", &mut std::io::stdout());
    Ok(ExitCode::SUCCESS)
}

/// `generate-man <dir>`: one man page per command and subcommand.
fn generate_man(args: &GenerateManArgs) -> anyhow::Result<ExitCode> {
    std::fs::create_dir_all(&args.dir).with_context(|| format!("cannot create {}", args.dir.display()))?;
    clap_mangen::generate_to(Cli::command(), &args.dir)
        .with_context(|| format!("cannot write man pages to {}", args.dir.display()))?;
    Ok(ExitCode::SUCCESS)
}

/// Loads the configuration; a missing file is an empty configuration.
pub(crate) fn load_config(ctx: &Context) -> anyhow::Result<Config> {
    Config::load(&ctx.config_path, &ctx.paths).map_err(config_error)
}

/// Turns a [`ConfigError`] into a message listing every problem on its own line.
pub(crate) fn config_error(error: ConfigError) -> anyhow::Error {
    match error {
        ConfigError::Invalid { path, problems } => {
            let list: Vec<String> = problems.iter().map(|problem| format!("  {problem}")).collect();
            anyhow::anyhow!("{} has {} problem(s):\n{}", path.display(), problems.len(), list.join("\n"))
        }
        other => other.into(),
    }
}

/// The daemon settings of `config`, or, when the file does not load, its `[daemon]` read
/// on its own ([`credential_bridge_config::daemon_settings`]), so ctl still reaches a
/// daemon with custom sockets and can show its error.
pub(crate) fn daemon_config(ctx: &Context, config: Option<&Config>) -> DaemonConfig {
    config.map_or_else(
        || credential_bridge_config::daemon_settings(&ctx.config_path, &ctx.paths),
        |config| config.daemon.clone(),
    )
}

/// Connects to the daemon's control socket.
pub(crate) fn connect(daemon: &DaemonConfig, timeout: Duration) -> Result<ControlClient, ControlError> {
    ControlClient::connect(&daemon.control_socket, timeout)
}

/// The sockets and the audit log the running daemon uses (they differ from `daemon`'s
/// after a change of `[daemon]` without a restart).
pub(crate) fn daemon_paths(daemon: &DaemonConfig) -> Result<DaemonPaths, ControlError> {
    let mut client = connect(daemon, CONTROL_TIMEOUT)?;
    match client.request(&credential_bridge_proto::ipc::control::Request::Ping)? {
        credential_bridge_proto::ipc::control::Response::Pong { paths, .. } => Ok(paths),
        _ => Err(ControlError::Unexpected),
    }
}

/// Asks a running daemon to re-read the configuration. `Ok(false)` if it is not
/// running.
pub(crate) fn reload_daemon(daemon: &DaemonConfig) -> Result<bool, ControlError> {
    let mut client = match connect(daemon, CONTROL_TIMEOUT) {
        Ok(client) => client,
        Err(ControlError::NotRunning(_)) => return Ok(false),
        Err(error) => return Err(error),
    };
    client.request(&credential_bridge_proto::ipc::control::Request::Reload)?;
    Ok(true)
}

/// Asks `question` on the terminal and returns the trimmed answer line. End of input
/// (Ctrl-D) is an error of kind [`std::io::ErrorKind::UnexpectedEof`]; callers treat it
/// as abort, never as the default answer.
pub(crate) fn ask_terminal(question: &str) -> std::io::Result<String> {
    ask_on(question, &mut std::io::stdin().lock(), &mut std::io::stdout().lock())
}

/// [`ask_terminal`] with explicit input and output.
pub(crate) fn ask_on(
    question: &str,
    input: &mut dyn std::io::BufRead,
    output: &mut dyn std::io::Write,
) -> std::io::Result<String> {
    output.write_all(question.as_bytes())?;
    output.flush()?;
    let mut answer = String::new();
    if input.read_line(&mut answer)? == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no answer (end of input)"));
    }
    Ok(answer.trim().to_owned())
}

/// Whether `program` is an executable file in `PATH`.
pub(crate) fn in_path(program: &str) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    let Some(path) = std::env::var_os("PATH") else { return false };
    std::env::split_paths(&path).any(|dir| {
        std::fs::metadata(dir.join(program))
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    })
}

/// Removes control characters (escape sequences from a server, for example) before
/// text reaches the terminal.
pub(crate) fn printable(text: &str) -> String {
    text.chars().map(|c| if c.is_control() { '?' } else { c }).collect()
}

/// Seconds since the Unix epoch.
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}

/// `in 7h59m` / `expired` for a point in time given as seconds since the epoch.
pub(crate) fn relative_time(at: u64) -> String {
    let now = now_secs();
    if at <= now {
        "expired".to_owned()
    } else {
        // Whole minutes are enough here.
        let secs = (at - now).div_ceil(60) * 60;
        format!("in {}", credential_bridge_config::duration::format_duration(Duration::from_secs(secs)))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::cell::RefCell;
    use std::io::{self, Write as _};
    use std::path::Path;

    use credential_bridge_config::paths::{PathVars, TargetOs};

    use super::*;
    use crate::remote::{KnownHostsMatch, ProbeRun, RemoteOutput, RemoteShell, UsedHostKey};

    /// A context whose home is a fresh temporary directory.
    pub(crate) fn context() -> (tempfile::TempDir, Context) {
        let dir = tempfile::tempdir().unwrap();
        let vars = PathVars { home: Some(dir.path().into()), xdg_config_home: None, xdg_state_home: None };
        let paths = Paths::from_vars(&vars, TargetOs::Linux).unwrap();
        let config_path = paths.config_file.clone();
        (dir, Context { paths, config_path })
    }

    /// A syntactically valid ed25519 public key in OpenSSH format, distinct per `seed`.
    pub(crate) fn test_key(seed: u8) -> String {
        let data = ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey([seed; 32]));
        ssh_key::PublicKey::new(data, "").to_openssh().unwrap()
    }

    /// A daemon on `socket` that answers every control request with `answer`, one
    /// request per connection, until the test ends.
    pub(crate) fn fake_daemon(socket: &Path, answer: credential_bridge_proto::ipc::control::Response) {
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let request: Option<credential_bridge_proto::ipc::control::Request> =
                    credential_bridge_proto::ipc::read_frame(&mut stream).unwrap_or_default();
                if request.is_some() {
                    let _ = credential_bridge_proto::ipc::write_frame(&mut stream, &answer);
                }
            }
        });
    }

    /// [`fake_daemon`] that also records every request it gets.
    pub(crate) fn recording_daemon(
        socket: &Path,
        answer: credential_bridge_proto::ipc::control::Response,
    ) -> std::sync::Arc<std::sync::Mutex<Vec<credential_bridge_proto::ipc::control::Request>>> {
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = std::sync::Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let request: Option<credential_bridge_proto::ipc::control::Request> =
                    credential_bridge_proto::ipc::read_frame(&mut stream).unwrap_or_default();
                if let Some(request) = request {
                    record.lock().unwrap().push(request);
                    let _ = credential_bridge_proto::ipc::write_frame(&mut stream, &answer);
                }
            }
        });
        seen
    }

    /// Writes `text` as the configuration file.
    pub(crate) fn write_config(ctx: &Context, text: &str) {
        std::fs::create_dir_all(ctx.config_path.parent().unwrap()).unwrap();
        std::fs::write(&ctx.config_path, text).unwrap();
    }

    /// A [`RemoteShell`] that answers from a script and records every call.
    #[derive(Debug, Default)]
    pub(crate) struct FakeShell {
        /// `(host, command line)` of each call; installs as `install <path>`.
        pub calls: RefCell<Vec<(String, String)>>,
        /// Answers by command prefix; the first matching prefix wins.
        pub answers: Vec<(String, RemoteOutput)>,
        /// The host key ssh "used" (OpenSSH format) for `run_noting_host_key`.
        pub host_key: Option<String>,
        /// Whether ssh "used" it in a host certificate.
        pub host_certificate: bool,
        /// Where ssh "found" the key or the CA in known_hosts.
        pub host_key_verified: Option<KnownHostsMatch>,
        /// What each `keyscan` call returns, in order (then nothing).
        pub keyscans: RefCell<Vec<String>>,
        /// The audit log and the lines "the daemon" appends to it when `probe` runs
        /// (once).
        pub probe_events: RefCell<Option<(PathBuf, Vec<String>)>>,
        /// The ssh process id `probe` reports.
        pub probe_pid: Option<u32>,
        /// The output `probe` reports.
        pub probe_output: RemoteOutput,
        /// What `ssh_g` returns.
        pub ssh_g: String,
        /// How often `ssh_g` ran.
        pub ssh_g_runs: std::cell::Cell<usize>,
        /// What `ssh_version` returns; `None`: a current OpenSSH.
        pub ssh_version: Option<String>,
    }

    impl FakeShell {
        pub(crate) fn answer(mut self, prefix: &str, status: i32, stdout: &str) -> FakeShell {
            self.answers.push((
                prefix.to_owned(),
                RemoteOutput { status: Some(status), stdout: stdout.to_owned(), stderr: String::new() },
            ));
            self
        }

        pub(crate) fn commands(&self) -> Vec<String> {
            self.calls.borrow().iter().map(|(_, command)| command.clone()).collect()
        }
    }

    impl RemoteShell for FakeShell {
        fn run(&self, host: &str, argv: &[&str]) -> io::Result<RemoteOutput> {
            let line = argv.join(" ");
            self.calls.borrow_mut().push((host.to_owned(), line.clone()));
            Ok(self
                .answers
                .iter()
                .find(|(prefix, _)| line.starts_with(prefix.as_str()))
                .map(|(_, output)| output.clone())
                .unwrap_or(RemoteOutput {
                    status: Some(127),
                    stdout: String::new(),
                    stderr: "not found".into(),
                }))
        }

        fn install_file(&self, host: &str, local: &Path, remote_path: &str) -> io::Result<()> {
            assert!(local.is_file(), "{} must exist", local.display());
            self.calls.borrow_mut().push((host.to_owned(), format!("install {remote_path}")));
            Ok(())
        }

        fn run_noting_host_key(
            &self,
            host: &str,
            argv: &[&str],
        ) -> io::Result<(RemoteOutput, Option<UsedHostKey>)> {
            let output = self.run(host, argv)?;
            let used = self.host_key.as_deref().map(|line| {
                let key = ssh_key::PublicKey::from_openssh(line).unwrap();
                UsedHostKey {
                    algorithm: key.algorithm().to_string(),
                    fingerprint: key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
                    certificate: self.host_certificate,
                    verified: self.host_key_verified.clone(),
                }
            });
            Ok((output, used))
        }

        fn probe(&self, host: &str, forward_socket: &Path) -> io::Result<ProbeRun> {
            self.calls.borrow_mut().push((host.to_owned(), format!("probe {}", forward_socket.display())));
            if let Some((log, lines)) = self.probe_events.borrow_mut().take() {
                let mut file = std::fs::OpenOptions::new().create(true).append(true).open(log)?;
                for line in lines {
                    writeln!(file, "{line}")?;
                }
            }
            Ok(ProbeRun { output: self.probe_output.clone(), pid: self.probe_pid })
        }

        fn ssh_g(&self, _host: &str) -> io::Result<String> {
            self.ssh_g_runs.set(self.ssh_g_runs.get() + 1);
            Ok(self.ssh_g.clone())
        }

        fn keyscan(&self, hostname: &str, port: u16, key_type: &str) -> io::Result<String> {
            self.calls
                .borrow_mut()
                .push((hostname.to_owned(), format!("ssh-keyscan -t {key_type} -p {port}")));
            let mut answers = self.keyscans.borrow_mut();
            Ok(if answers.is_empty() { String::new() } else { answers.remove(0) })
        }

        fn ssh_version(&self) -> io::Result<String> {
            Ok(self
                .ssh_version
                .clone()
                .unwrap_or_else(|| "OpenSSH_10.2p1, OpenSSL 3.5.5 27 Jan 2026\n".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_times() {
        assert_eq!(relative_time(0), "expired");
        assert_eq!(relative_time(now_secs() + 3600), "in 1h");
    }

    #[test]
    fn asking_treats_end_of_input_as_no_answer() {
        let mut output = Vec::new();
        let answer = ask_on("go? ", &mut &b" yes \n"[..], &mut output).unwrap();
        assert_eq!((answer.as_str(), output.as_slice()), ("yes", &b"go? "[..]));
        // An empty line is an answer (the default); end of input is not.
        assert_eq!(ask_on("go? ", &mut &b"\n"[..], &mut Vec::new()).unwrap(), "");
        let error = ask_on("go? ", &mut &b""[..], &mut Vec::new()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn strips_control_characters() {
        assert_eq!(printable("a\u{1b}[2Jb\nc"), "a?[2Jb?c");
    }

    #[test]
    fn writes_man_pages() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("man");
        let _ = generate_man(&GenerateManArgs { dir: out.clone() }).unwrap();
        assert!(out.join("credential-bridge-ctl.1").is_file());
        assert!(out.join("credential-bridge-ctl-server-add.1").is_file());
    }

    #[test]
    fn missing_config_is_empty() {
        let (_dir, ctx) = test_support::context();
        let config = load_config(&ctx).unwrap();
        assert!(config.servers.is_empty());
        assert_eq!(config.daemon.control_socket, ctx.paths.control_socket);
    }

    #[test]
    fn invalid_config_lists_problems() {
        let (_dir, ctx) = test_support::context();
        test_support::write_config(&ctx, "version = 2\n[server.a]\nhost_keys = []\nprofile = \"nope\"\n");
        let message = format!("{:#}", load_config(&ctx).unwrap_err());
        assert!(message.contains("problem"), "{message}");
    }
}
