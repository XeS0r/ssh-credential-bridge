//! `git-credential-bridge`: runs on the remote, invoked by git.

mod setup;

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::builder::FalseyValueParser;
use clap::{CommandFactory, Parser, Subcommand};
use credential_bridge_proto::client::{ClientError, exchange};
use credential_bridge_proto::{Credential, Operation, REMOTE_SOCKET_RELATIVE, Request, Status, split_fix};

const LONG_ABOUT: &str = "\
Git credential helper that forwards requests to credential-bridged on your
local machine, through a unix socket forwarded by SSH (`RemoteForward`).

Warnings appear in git's output as `credential-bridge: …`; set
CREDENTIAL_BRIDGE_VERBOSE=1 for technical details. Git runs this helper itself. `git-credential-bridge setup <URL>...` registers it
with git (`credential-bridge-ctl remote install` does that for you), e.g.:

    [credential \"https://github.com\"]
        helper =
        helper = /home/me/.local/bin/git-credential-bridge --socket /home/me/.local/state/credential-bridge/bridge.sock

If the socket is not available (no forwarding on this connection) or the
request is denied, the helper prints a warning and returns no credential, so
git falls back to its other helpers or prompts.";

const AFTER_HELP: &str = "\
Run `git-credential-bridge ping` on the remote to check the forwarding,
`git-credential-bridge uninstall --remove-binary` to remove it again.";

/// Git credential helper that asks credential-bridged through an SSH-forwarded socket.
#[derive(Debug, Parser)]
#[command(name = "git-credential-bridge", version, long_about = LONG_ABOUT, after_help = AFTER_HELP)]
struct Cli {
    /// Forwarded socket [default: $HOME/.local/state/credential-bridge/bridge.sock]
    #[arg(long, global = true, env = "CREDENTIAL_BRIDGE_SOCK", value_name = "PATH")]
    socket: Option<PathBuf>,

    /// Seconds to wait for the local daemon
    #[arg(long, global = true, default_value_t = 60, value_name = "SECS")]
    timeout: u64,

    /// Do not print warnings to stderr
    #[arg(short, long, global = true, env = "CREDENTIAL_BRIDGE_QUIET", value_parser = FalseyValueParser::new())]
    quiet: bool,

    /// Add technical details (socket path, OS errors) to warnings
    #[arg(short, long, global = true, env = "CREDENTIAL_BRIDGE_VERBOSE", value_parser = FalseyValueParser::new())]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Return a credential for the request on stdin (called by git)
    Get,
    /// Report a credential that worked (called by git)
    Store,
    /// Report a credential that was rejected (called by git)
    Erase,
    /// Check that credential-bridged is reachable through the socket
    Ping,
    /// Register this helper with git for the hosts of URL patterns and create the socket directory
    Setup {
        /// URL patterns as in the remote's allow list, e.g. https://github.com/my-org/*
        #[arg(required = true, value_name = "URL")]
        patterns: Vec<String>,
        /// Only create the socket directory; leave git's configuration alone
        #[arg(long)]
        no_git_config: bool,
        /// Only print what would be done
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove every entry for this helper from git's global configuration
    Uninstall {
        /// Delete this binary as well
        #[arg(long)]
        remove_binary: bool,
        /// Only print what would be done
        #[arg(long)]
        dry_run: bool,
    },
    /// Write man pages to DIR
    #[command(hide = true)]
    GenerateMan { dir: PathBuf },
    /// Git may add operations in the future; helpers must ignore unknown ones.
    #[command(external_subcommand)]
    Unknown(#[allow(dead_code, reason = "accepted and ignored")] Vec<String>),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let operation = match &cli.command {
        Commands::Get => Operation::Get,
        Commands::Store => Operation::Store,
        Commands::Erase => Operation::Erase,
        Commands::Ping => return ping(&cli),
        Commands::Setup { patterns, no_git_config, dry_run } => {
            return report(setup(&cli, patterns, *no_git_config, *dry_run));
        }
        Commands::Uninstall { remove_binary, dry_run } => return report(uninstall(*remove_binary, *dry_run)),
        Commands::GenerateMan { dir } => return generate_man(dir),
        Commands::Unknown(_) => return ExitCode::SUCCESS,
    };
    // Whatever happens, git must not abort because of this helper: on failure
    // we return no credential and let git try its other helpers.
    if let Err(notice) = forward(&cli, operation) {
        warn(&cli, &notice);
    }
    ExitCode::SUCCESS
}

fn socket_path(cli: &Cli) -> Result<PathBuf, String> {
    if let Some(socket) = &cli.socket {
        return Ok(socket.clone());
    }
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty()).ok_or("$HOME is not set; pass --socket")?;
    // The same default ctl records, from the shared crate.
    Ok(PathBuf::from(home).join(REMOTE_SOCKET_RELATIVE))
}

fn timeout(cli: &Cli) -> Option<Duration> {
    Some(Duration::from_secs(cli.timeout)).filter(|t| !t.is_zero())
}

/// A warning for the user, printed between git's own output:
/// what is wrong, how to fix it, and (with `-v`) technical details.
#[derive(Debug, PartialEq)]
struct Notice {
    problem: String,
    fix: Option<String>,
    detail: Option<String>,
}

impl Notice {
    /// From a daemon message (`problem → fix`).
    fn from_message(message: &str) -> Self {
        let (problem, fix) = split_fix(message);
        Notice { problem: problem.to_owned(), fix: fix.map(str::to_owned), detail: None }
    }

    fn plain(problem: impl Into<String>) -> Self {
        Notice { problem: problem.into(), fix: None, detail: None }
    }
}

impl From<String> for Notice {
    fn from(problem: String) -> Self {
        Notice::plain(problem)
    }
}

fn forward(cli: &Cli, operation: Operation) -> Result<(), Notice> {
    let socket = socket_path(cli)?;
    let credential = Credential::read_from(&mut io::stdin().lock())
        .map_err(|err| format!("cannot read the request from git: {err}"))?;
    let response =
        exchange(&socket, &Request::new(operation, credential), timeout(cli)).map_err(client_notice)?;
    match response.status {
        Status::Ok => {
            if operation == Operation::Get && !response.credential.has_secret() {
                // Let git fall back to its other helpers or prompt, but say why.
                if let Some(message) = &response.message {
                    warn(cli, &Notice::from_message(message));
                }
            }
            if operation == Operation::Get {
                let mut stdout = io::stdout().lock();
                response
                    .credential
                    .write_to(&mut stdout)
                    .and_then(|()| stdout.flush())
                    .map_err(|err| format!("cannot write the answer to git: {err}"))?;
            }
            Ok(())
        }
        // git reports every credential it used with `store` (and failures
        // with `erase`); with the default get-only policy those are refused
        // on every clone, which is expected and not worth a warning.
        Status::Denied if operation != Operation::Get => Ok(()),
        Status::Denied | Status::Error => {
            Err(Notice::from_message(response.message.as_deref().unwrap_or("the request was refused")))
        }
    }
}

fn client_notice(err: ClientError) -> Notice {
    match &err {
        ClientError::Connect { path, source } => Notice {
            problem: "not connected to your local machine".into(),
            fix: Some(
                "reconnect via ssh with RemoteForward (locally: credential-bridge-ctl remote check)".into(),
            ),
            detail: Some(format!("{}: {source}", path.display())),
        },
        _ => Notice {
            problem: "the local daemon did not answer properly".into(),
            fix: None,
            detail: Some(err.to_string()),
        },
    }
}

/// Colors only on a terminal and without NO_COLOR.
fn paint(code: &str, text: &str) -> String {
    let color = io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    if color { format!("\x1b[{code}m{text}\x1b[0m") } else { text.to_owned() }
}

fn render(notice: &Notice, verbose: bool) -> String {
    let mut out = format!("{} {}", paint("33", "credential-bridge:"), notice.problem);
    if let Some(fix) = &notice.fix {
        out += &format!("\n{}", paint("2", &format!("  → {fix}")));
    }
    if let (true, Some(detail)) = (verbose, &notice.detail) {
        out += &format!("\n{}", paint("2", &format!("  {detail}")));
    }
    out
}

fn warn(cli: &Cli, notice: &Notice) {
    if !cli.quiet {
        eprintln!("{}", render(notice, cli.verbose));
    }
}

fn ping(cli: &Cli) -> ExitCode {
    let result = socket_path(cli).map_err(Notice::plain).and_then(|socket| {
        let response = exchange(&socket, &Request::new(Operation::Ping, Credential::new()), timeout(cli))
            .map_err(client_notice)?;
        match response.status {
            Status::Ok => Ok((socket, response.message.unwrap_or_default())),
            _ => Err(Notice::from_message(response.message.as_deref().unwrap_or("unexpected answer"))),
        }
    });
    match result {
        Ok((socket, message)) => {
            println!("{} connected to your local machine ({message})", paint("32", "✓"));
            if cli.verbose {
                println!("{}", paint("2", &format!("  via {}", socket.display())));
            }
            ExitCode::SUCCESS
        }
        Err(notice) => {
            eprintln!("{}", render(&notice, cli.verbose));
            ExitCode::FAILURE
        }
    }
}

fn report(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{} {message}", paint("33", "credential-bridge:"));
            ExitCode::FAILURE
        }
    }
}

fn own_path() -> Result<String, String> {
    std::env::current_exe()
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(|err| format!("cannot determine the path of this program: {err}"))
}

fn run_steps(steps: &[setup::Step], dry_run: bool) -> Result<(), String> {
    if dry_run {
        steps.iter().for_each(|step| println!("{step}"));
        return Ok(());
    }
    setup::apply(steps)
}

fn setup(cli: &Cli, patterns: &[String], no_git_config: bool, dry_run: bool) -> Result<(), String> {
    let origins = setup::origins(patterns)?;
    let socket = socket_path(cli)?;
    if !socket.is_absolute() {
        return Err(format!("the socket path must be absolute: {}", socket.display()));
    }
    let git_config = !no_git_config && setup::has_git();
    if !no_git_config && !git_config {
        eprintln!("credential-bridge: git not found; skipping the git configuration");
    }
    let helper = own_path()?;
    let socket = socket.to_string_lossy();
    let current = if git_config { setup::read_git_credentials()? } else { setup::GitCredentials::default() };
    run_steps(&setup::setup_steps(&helper, &socket, &origins, git_config, &current), dry_run)?;
    if !dry_run {
        println!("socket directory ready for {socket}");
        if git_config {
            let hosts = origins.keys().map(String::as_str).collect::<Vec<_>>().join(", ");
            println!("git uses {helper} for {hosts}");
        }
    }
    Ok(())
}

fn uninstall(remove_binary: bool, dry_run: bool) -> Result<(), String> {
    let current =
        if setup::has_git() { setup::read_git_credentials()? } else { setup::GitCredentials::default() };
    let binary = if remove_binary { Some(own_path()?) } else { None };
    let steps = setup::uninstall_steps(&current, binary.as_deref());
    run_steps(&steps, dry_run)?;
    if !dry_run {
        let removed = current.ours().len();
        println!(
            "removed the git configuration for {removed} {}",
            if removed == 1 { "host" } else { "hosts" }
        );
        if let Some(binary) = binary {
            println!("removed {binary}");
        }
    }
    Ok(())
}

fn generate_man(dir: &std::path::Path) -> ExitCode {
    let result = std::fs::create_dir_all(dir).and_then(|()| clap_mangen::generate_to(Cli::command(), dir));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("credential-bridge: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_notices() {
        let notice = Notice::from_message(
            "no credential for github.com on your local machine → locally: gh auth login",
        );
        assert_eq!(
            render(&notice, false),
            "credential-bridge: no credential for github.com on your local machine\n  → locally: gh auth login"
        );
        let mut notice = Notice::plain("x");
        notice.detail = Some("/s.sock: refused".into());
        assert_eq!(render(&notice, false), "credential-bridge: x");
        assert_eq!(render(&notice, true), "credential-bridge: x\n  /s.sock: refused");
    }
}
