//! `credential-bridge-remote`: the program ctl installs on servers.
//!
//! - `git`: git credential helper over `git-credential@credential-bridge`
//!   ([`git_helper`]);
//! - `gpg`: gpg shim started by gpg as `agent-program` ([`gpg_shim`]); gpg's own
//!   agent-program command line (`--homedir … --daemon`) is recognised as well;
//! - `setup` / `uninstall`: additive git config changes, run by ctl over ssh
//!   ([`setup`]);
//! - `query`: reports whether `SSH_AUTH_SOCK` leads to a bridge ([`agent`]).
//!
//! Both helper and shim step aside for callers without a bridge: no `SSH_AUTH_SOCK`, no
//! agent, or `query` without our extension means the git helper prints nothing (git
//! carries on with the next helper) and the shim hands over to a real gpg-agent. No
//! policy, references or secrets live on the server.
//!
//! Must build as a static Linux musl binary: blocking I/O only, no async runtime.

pub mod agent;
pub mod cli;
pub mod git_helper;
pub mod gpg_shim;
pub mod setup;

#[cfg(test)]
mod testutil;
