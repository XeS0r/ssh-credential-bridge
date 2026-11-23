//! Command line.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use credential_bridge_proto::ipc::WorkerKind;

/// credential-bridge daemon: ssh-agent proxy with key mux, git tokens and gpg.
#[derive(Debug, Parser)]
#[command(name = "credential-bridged", version)]
pub struct Cli {
    /// Configuration file (default: $XDG_CONFIG_HOME/credential-bridge/config.toml).
    #[arg(long, env = "CREDENTIAL_BRIDGE_CONFIG", global = true)]
    pub config: Option<PathBuf>,
    /// What to run; without a subcommand the daemon runs.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the daemon in the foreground (the default).
    Run,
    /// Internal: run a worker. Started by the daemon with its channel on stdin.
    #[command(hide = true)]
    Worker {
        /// Which worker.
        #[arg(value_parser = parse_worker_kind)]
        kind: WorkerKind,
    },
    /// Write the man page of credential-bridged into a directory (for packaging).
    #[command(hide = true)]
    GenerateMan {
        /// Output directory (created if missing).
        dir: PathBuf,
    },
}

/// Logs to stderr (the journal / launchd log file) with the filter from `RUST_LOG`,
/// default `info`. Workers inherit `RUST_LOG` and log to the daemon's stderr.
pub fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    // A second initialisation (tests) is harmless.
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();
}

fn parse_worker_kind(value: &str) -> Result<WorkerKind, String> {
    value.parse().map_err(|error: credential_bridge_proto::ipc::UnknownWorkerKind| error.to_string())
}

/// Entry point: parses arguments, then runs [`crate::core::run`] or
/// [`crate::worker::run`]. Errors are printed to stderr and yield exit code 1.
pub fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging();
    match cli.command.unwrap_or(Command::Run) {
        Command::Run => match crate::core::run(cli.config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("credential-bridged: {error:#}");
                ExitCode::FAILURE
            }
        },
        Command::Worker { kind } => crate::worker::run(kind),
        Command::GenerateMan { dir } => match generate_man(&dir) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("credential-bridged: cannot write man page to {}: {error}", dir.display());
                ExitCode::FAILURE
            }
        },
    }
}

/// Writes `credential-bridged.1` into `dir`; hidden subcommands are left out.
fn generate_man(dir: &std::path::Path) -> std::io::Result<()> {
    use clap::CommandFactory;
    std::fs::create_dir_all(dir)?;
    clap_mangen::Man::new(Cli::command()).generate_to(dir).map(|_| ())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_worker_kind() {
        let cli = Cli::try_parse_from(["credential-bridged", "worker", "git"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Worker { kind: WorkerKind::Git })));
        assert!(Cli::try_parse_from(["credential-bridged", "worker", "nope"]).is_err());
    }

    #[test]
    fn writes_the_man_page() {
        let dir = tempfile::tempdir().unwrap();
        generate_man(dir.path()).unwrap();
        let page = std::fs::read_to_string(dir.path().join("credential-bridged.1")).unwrap();
        assert!(page.contains("credential\\-bridged"), "{page}");
        assert!(!page.contains("generate\\-man"), "{page}");
    }
}
