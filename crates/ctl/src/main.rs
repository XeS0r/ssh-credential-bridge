//! `credential-bridge-ctl`: everything the user needs to set up and run credential-bridge.

mod config_cmd;
mod doctor;
mod remote;
mod service;
mod ssh;
mod ui;
mod util;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use credential_bridge_core::config::Config;
use credential_bridge_core::edit::ConfigDocument;
use credential_bridge_core::paths;

const LONG_ABOUT: &str = "\
Manage credential-bridge.

credential-bridge lets git on SSH remotes use the credentials of your local
machine (by default those of `gh`) without storing any token on the remote:

  local:   credential-bridged ── one unix socket per remote
                 │                        ▲
                 ▼                        │ ssh RemoteForward
           gh / keychain / …             │
  remote:  git ─▶ git-credential-bridge ─┘

Typical setup:

  credential-bridge-ctl service install
  credential-bridge-ctl remote add buildserver --allow https://github.com
  credential-bridge-ctl remote install buildserver
  credential-bridge-ctl remote ssh-config buildserver >> ~/.ssh/config   (review first)
  credential-bridge-ctl remote check buildserver";

/// Manage credential-bridge: the local daemon service and the SSH remotes it serves.
#[derive(Debug, Parser)]
#[command(name = "credential-bridge-ctl", version, long_about = LONG_ABOUT, propagate_version = true)]
struct Cli {
    /// Configuration file [default: $XDG_CONFIG_HOME/credential-bridge/config.toml]
    #[arg(short, long, global = true, env = "CREDENTIAL_BRIDGE_CONFIG", value_name = "PATH")]
    config: Option<PathBuf>,

    /// When to use colors (NO_COLOR is honoured with `auto`)
    #[arg(long, global = true, value_enum, default_value_t = ui::ColorChoice::Auto, value_name = "WHEN")]
    color: ui::ColorChoice,

    /// Show technical details: ssh commands, output from the remote
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Manage the credential-bridged user service (systemd on Linux, launchd on macOS)
    #[command(subcommand)]
    Service(ServiceCommand),
    /// Manage SSH remotes, their policies and the helper installed on them
    #[command(subcommand)]
    Remote(RemoteCommand),
    /// Inspect and edit the configuration file
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Send a test request for URL through REMOTE's socket, as the remote would
    Test(TestArgs),
    /// Check the local setup and report problems
    Doctor,
    /// Print a shell completion script
    Completions {
        /// Target shell
        shell: Shell,
    },
    /// Write man pages to DIR
    #[command(hide = true)]
    GenerateMan { dir: PathBuf },
}

#[derive(Debug, Subcommand)]
pub enum ServiceCommand {
    /// Install the user service, enable it at login and start it
    Install {
        /// Path of credential-bridged [default: next to this program, then $PATH]
        #[arg(long, value_name = "PATH")]
        daemon_path: Option<PathBuf>,
        /// Install and enable, but do not start now
        #[arg(long)]
        no_start: bool,
    },
    /// Stop the service and remove it
    Uninstall,
    /// Start the service
    Start,
    /// Stop the service
    Stop,
    /// Restart the service
    Restart,
    /// Reload the configuration without a restart (SIGHUP)
    Reload,
    /// Show the service status
    Status {
        /// Print the service manager's own status output instead
        #[arg(long)]
        raw: bool,
    },
    /// Show the service log
    Logs {
        /// Keep printing new log lines
        #[arg(short, long)]
        follow: bool,
        /// Number of lines to show
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
    },
}

#[derive(Debug, Subcommand)]
pub enum RemoteCommand {
    /// Add a remote with its own socket and policy
    Add(AddArgs),
    /// Remove a remote from the configuration (see also `remote uninstall`)
    #[command(visible_alias = "rm")]
    Remove {
        /// Remote name
        name: String,
    },
    /// List remotes and whether their sockets are being served
    #[command(visible_alias = "ls")]
    List,
    /// Show the details of a remote
    Show {
        /// Remote name
        name: String,
    },
    /// Print the ~/.ssh/config lines that forward a remote's socket
    SshConfig {
        /// Remote name
        name: String,
    },
    /// Change a remote's allow list, operations, ssh destination or backend
    Edit(EditArgs),
    /// Copy git-credential-bridge to the remote and configure git there
    Install(InstallArgs),
    /// Check the whole chain: daemon, ssh config, helper and git config on the remote,
    /// and a request from the remote through the forwarded socket
    Check {
        /// Remote name
        name: String,
    },
    /// Remove git-credential-bridge and its git configuration from the remote
    Uninstall {
        /// Remote name
        name: String,
        /// Only print what would be done
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// Remote name; also the socket file name and the default ssh destination
    pub name: String,
    /// URL pattern the remote may ask credentials for (repeatable),
    /// e.g. https://github.com or https://github.com/my-org/*
    #[arg(long = "allow", value_name = "URL", required = true)]
    pub allow: Vec<String>,
    /// ssh destination, if different from NAME (e.g. me@build.example.com)
    #[arg(long, value_name = "DEST")]
    pub ssh_host: Option<String>,
    /// Operation the remote may perform (repeatable) [default: get]
    #[arg(long = "operation", value_name = "OP", value_parser = ["get", "store", "erase"])]
    pub operations: Vec<String>,
    /// Backend for this remote, overriding the global one (git credential.helper syntax)
    #[arg(long, value_name = "SPEC")]
    pub backend: Option<String>,
    /// Socket path on the remote [default: set by `remote install`]
    #[arg(long, value_name = "PATH")]
    pub remote_socket: Option<String>,
}

#[derive(Debug, Args)]
#[command(group = clap::ArgGroup::new("change").required(true).multiple(true))]
pub struct EditArgs {
    /// Remote name
    pub name: String,
    /// Add a URL pattern to the allow list (repeatable)
    #[arg(long, value_name = "URL", group = "change")]
    pub add_allow: Vec<String>,
    /// Remove a URL pattern from the allow list (repeatable)
    #[arg(long, value_name = "URL", group = "change")]
    pub remove_allow: Vec<String>,
    /// Replace the permitted operations (repeatable)
    #[arg(long = "operation", value_name = "OP", value_parser = ["get", "store", "erase"], group = "change")]
    pub operations: Vec<String>,
    /// Set the ssh destination
    #[arg(long, value_name = "DEST", group = "change")]
    pub ssh_host: Option<String>,
    /// Use this backend for the remote (git credential.helper syntax)
    #[arg(long, value_name = "SPEC", group = "change", conflicts_with = "default_backend")]
    pub backend: Option<String>,
    /// Use the global backend again
    #[arg(long, group = "change")]
    pub default_backend: bool,
}

#[derive(Debug, Args)]
pub struct InstallArgs {
    /// Remote name
    pub name: String,
    /// Helper binary to upload [default: from $CREDENTIAL_BRIDGE_HELPER_DIR for the remote's platform]
    #[arg(long, value_name = "PATH")]
    pub binary: Option<PathBuf>,
    /// Only upload the helper; do not touch the remote's git configuration
    #[arg(long)]
    pub no_git_config: bool,
    /// Only probe the remote and print what would be done
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Print the configuration file path
    Path,
    /// Print the configuration file
    Show,
    /// Write a commented example configuration (if none exists)
    Init,
    /// Open the configuration in $VISUAL / $EDITOR, then validate and reload
    Edit,
    /// Validate the configuration
    Validate,
}

#[derive(Debug, Args)]
pub struct TestArgs {
    /// Remote whose socket and policy to use
    pub remote: String,
    /// URL to ask a credential for, e.g. https://github.com/my-org/repo
    pub url: String,
    /// Operation to send
    #[arg(long, default_value = "get", value_parser = ["get", "store", "erase", "ping"])]
    pub operation: String,
}

/// Resolved global options, passed to every command.
#[derive(Debug)]
pub struct Ctx {
    pub config_path: PathBuf,
    /// Whether the path was given explicitly (and must be passed on to the service).
    pub explicit_config: bool,
}

impl Ctx {
    pub fn load(&self) -> anyhow::Result<Config> {
        Ok(Config::load(&self.config_path)?)
    }

    pub fn document(&self) -> anyhow::Result<ConfigDocument> {
        Ok(ConfigDocument::load(&self.config_path)?)
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("credential-bridge-ctl: error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    ui::init(cli.color, cli.verbose);
    let ctx = Ctx {
        explicit_config: cli.config.is_some(),
        config_path: match cli.config {
            Some(path) => path,
            None => paths::default_config_file()?,
        },
    };
    match cli.command {
        Commands::Service(cmd) => service::run(&ctx, cmd)?,
        Commands::Remote(cmd) => remote::run(&ctx, cmd)?,
        Commands::Config(cmd) => config_cmd::run(&ctx, cmd)?,
        Commands::Test(args) => return remote::test(&ctx, &args),
        Commands::Doctor => return doctor::run(&ctx),
        Commands::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "credential-bridge-ctl",
                &mut std::io::stdout(),
            );
        }
        Commands::GenerateMan { dir } => {
            std::fs::create_dir_all(&dir)?;
            clap_mangen::generate_to(Cli::command(), &dir)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }
}
