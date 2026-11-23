//! `credential-bridge-ctl`: writes and changes the configuration, manages servers,
//! checks the setup, unlocks vaults, creates GitHub Apps and installs the service.
//!
//! ctl never edits `~/.ssh/config` and never gpg files. It changes `config.toml` only
//! through `credential_bridge_config::edit` (comments kept, the result validated before
//! it is written, `--dry-run` as a diff). It talks to the daemon on `control.sock`
//! ([`control`]) and to servers through the user's `ssh` ([`remote`]).

pub mod audit;
pub mod cli;
pub mod commands;
pub mod control;
pub mod diff;
pub mod remote;
pub mod report;
pub mod ssh_config;
mod tty;
