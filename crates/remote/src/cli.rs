//! Command line.

use std::ffi::OsString;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// credential-bridge on the server: git credential helper, gpg shim, setup.
#[derive(Debug, Parser)]
#[command(name = "credential-bridge-remote", version)]
pub struct Cli {
    /// What to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// git credential helper (`credential.helper`); git passes the action.
    Git {
        /// `get`, `store` or `erase` (`store` is ignored).
        action: String,
    },
    /// gpg shim (`agent-program` in gpg.conf); accepts the arguments gpg passes.
    Gpg {
        /// Arguments from gpg, passed on to a real gpg-agent when stepping aside.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// Add git config entries for credential-bridge (never changes or removes existing
    /// entries).
    Setup(SetupArgs),
    /// Remove the git config entries that point to this binary.
    Uninstall {
        /// Also delete this binary.
        #[arg(long)]
        remove_binary: bool,
    },
    /// Check whether SSH_AUTH_SOCK leads to a credential-bridge proxy; prints the
    /// supported extensions. Exit code 0 if it does, 1 if not.
    Query,
}

/// Arguments of `setup`.
#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct SetupArgs {
    /// A git host (`host[:port]`) to add a helper entry for; repeatable.
    #[arg(long = "host", value_name = "HOST")]
    pub hosts: Vec<String>,
    /// A host that also needs `credential.<url>.useHttpPath = true`; repeatable.
    #[arg(long = "http-path", value_name = "HOST")]
    pub http_path: Vec<String>,
    /// Set up ssh signing of commits with this public key (`signing = "ssh"`).
    #[arg(long, value_name = "PUBLIC_KEY")]
    pub signing_key: Option<String>,
    /// Print the git config commands instead of running them (`git_config = false`).
    #[arg(long)]
    pub print: bool,
}

/// Options gpg passes first when it starts an `agent-program`.
const AGENT_PROGRAM_OPTIONS: &[&str] = &["--homedir", "--use-standard-socket", "--daemon", "--supervised"];

/// If `args` (with the program name first) is gpg starting this binary as its
/// `agent-program`, returns the arguments for the shim.
///
/// gpg runs `<program> --homedir <dir> --use-standard-socket [<arg>] --daemon`, with no
/// way to put a subcommand first (see `credential_bridge_gpg::shim`), so a command line
/// that starts with one of gpg-agent's options is the gpg shim. A stray `gpg` (from
/// `agent-program <program>|gpg`) is dropped.
pub fn agent_program_args(args: &[OsString]) -> Option<Vec<OsString>> {
    let first = args.get(1)?.to_str()?;
    let is_agent_option = AGENT_PROGRAM_OPTIONS.iter().any(|option| {
        first == *option || first.strip_prefix(option).is_some_and(|rest| rest.starts_with('='))
    });
    is_agent_option.then(|| args[1..].iter().filter(|arg| *arg != "gpg").cloned().collect())
}

/// Entry point.
pub fn main() -> ExitCode {
    // The git helper holds tokens, the gpg shim decrypted data. Failures are not
    // printed: git and gpg show a helper's stderr to the user.
    let _ = credential_bridge_platform::harden::harden_process();
    let args: Vec<OsString> = std::env::args_os().collect();
    if let Some(shim_args) = agent_program_args(&args) {
        return crate::gpg_shim::main(&shim_args);
    }
    let cli = Cli::parse_from(args);
    match cli.command {
        Command::Git { action } => crate::git_helper::main(&action),
        Command::Gpg { args } => crate::gpg_shim::main(&args),
        Command::Setup(args) => report(crate::setup::setup(&args)),
        Command::Uninstall { remove_binary } => report(crate::setup::uninstall(remove_binary)),
        Command::Query => crate::agent::query_main(),
    }
}

fn report(result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("credential-bridge-remote: {error:#}");
            ExitCode::FAILURE
        }
    }
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
    fn gpg_accepts_agent_arguments() {
        let cli = Cli::try_parse_from(["x", "gpg", "--homedir", "/h", "--use-standard-socket"]).unwrap();
        let Command::Gpg { args } = cli.command else { panic!("not gpg") };
        assert_eq!(args.len(), 3);
    }

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn recognises_gpg_agent_program_invocation() {
        let argv = os(&["/bin/cbr", "--homedir", "/h", "--use-standard-socket", "gpg", "--daemon"]);
        assert_eq!(
            agent_program_args(&argv),
            Some(os(&["--homedir", "/h", "--use-standard-socket", "--daemon"]))
        );
        assert!(agent_program_args(&os(&["/bin/cbr", "--homedir=/h", "--daemon"])).is_some());
        assert!(agent_program_args(&os(&["/bin/cbr", "--daemon"])).is_some());
        assert_eq!(agent_program_args(&os(&["/bin/cbr", "git", "get"])), None);
        assert_eq!(agent_program_args(&os(&["/bin/cbr", "--version"])), None);
        assert_eq!(agent_program_args(&os(&["/bin/cbr", "--homedirx"])), None);
        assert_eq!(agent_program_args(&os(&["/bin/cbr"])), None);
    }
}
