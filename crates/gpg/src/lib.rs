//! The gpg bridge's protocol logic, shared by the local gpg worker (in
//! `credential-bridged`) and the remote shim (`credential-bridge-remote gpg`).
//!
//! Sans-I/O: every type here consumes and produces bytes; callers own the sockets. That
//! keeps the code fuzzable (`cargo-fuzz` targets: [`assuan`] parsers, [`filter`],
//! [`framing`]).
//!
//! - [`assuan`]: Assuan line parsing and formatting.
//! - [`filter`]: the command allowlist (sign / decrypt policy, always-blocked commands).
//! - [`framing`]: how Assuan traffic is cut into `gpg-agent@credential-bridge` messages.
//! - [`session`]: the worker-side state machine combining filter and framing.
//! - [`shim`]: helpers for the remote shim (the `agent-program` arguments).

pub mod assuan;
pub mod filter;
pub mod framing;
pub mod session;
pub mod shim;

pub use credential_bridge_proto::ipc::gpg::GpgPolicy;

/// Errors of the gpg bridge.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GpgError {
    /// A line exceeds [`assuan::MAX_LINE_LEN`].
    #[error("assuan line too long")]
    LineTooLong,
    /// A line does not follow the Assuan syntax.
    #[error("malformed assuan line: {0}")]
    Malformed(&'static str),
    /// Traffic out of order, e.g. `D` lines from the client without an `INQUIRE`, or a
    /// new command while a reply is pending.
    #[error("assuan protocol violation: {0}")]
    Protocol(&'static str),
    /// A unit exceeds [`credential_bridge_proto::ext::MAX_GPG_CHUNK`].
    #[error("gpg unit too large")]
    TooLarge,
}
