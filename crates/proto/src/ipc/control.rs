//! Messages between `credential-bridge-ctl` and the daemon on `control.sock`.
//!
//! `control.sock` sits next to the agent sockets, accepts only the own user or root and
//! carries [`super`] frames. It exists because `agent.sock` answers no extensions and
//! `agent-forward.sock` is always treated as a server.

use serde::{Deserialize, Serialize};

use super::WorkerError;
use super::vault::VaultStatus;
use crate::secret::Secret;

/// ctl to daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Liveness check.
    Ping,
    /// Daemon, upstream and worker state for `ctl check`.
    Status,
    /// Re-read the configuration. Answered with an error listing the problems if it is
    /// invalid; the old configuration then stays active.
    Reload,
    /// The keys a server would see (`ctl server keys <server>`); `None` for `agent.sock`.
    Keys {
        /// Name of a `[server.*]` table.
        server: Option<String>,
    },
    /// Resolve a token as if `server` asked for `url` (`ctl server token`). The token
    /// itself is never returned, only a description.
    TokenTest {
        /// Name of a `[server.*]` table.
        server: String,
        /// e.g. `https://github.com/my-org/app`.
        url: String,
    },
    /// Forwarded to the vault worker as [`super::vault::Request::Unlock`].
    Unlock {
        /// Vault kind name.
        vault: String,
        /// Master password.
        password: Secret,
        /// Session lifetime in seconds.
        ttl_secs: Option<u64>,
    },
    /// Forwarded to the vault worker as [`super::vault::Request::Lock`]; the core then
    /// drops the git worker's tokens from that vault (all with `None`) with
    /// [`super::git::Request::Forget`].
    Lock {
        /// Vault kind name, or all.
        vault: Option<String>,
    },
    /// Forwarded to the vault worker as [`super::vault::Request::Store`]
    /// (`ctl source add github --auth app --create`).
    StoreSecret {
        /// Where to write.
        reference: String,
        /// The value.
        value: Secret,
    },
    /// Resolve what a source reads locally (`ctl source test`, and `ctl source add`
    /// right after writing): each secret reference through the vault worker, for a `gh`
    /// source its login. Only the outcome comes back, never a value.
    SourceTest {
        /// Name of a `[source.*]` table.
        source: String,
    },
}

/// One upstream agent in [`DaemonStatus`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamStatus {
    /// `[[agent.upstream]]` name.
    pub name: String,
    /// The resolved socket path.
    pub socket: String,
    /// Whether a connection and `REQUEST_IDENTITIES` succeeded.
    pub reachable: bool,
    /// Number of keys listed, if reachable.
    pub keys: Option<usize>,
    /// Why it is not reachable: `timeout` if it did not answer in time, else the error.
    /// `None` if reachable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One worker in [`DaemonStatus`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerStatus {
    /// `git`, `vault` or `gpg`.
    pub kind: super::WorkerKind,
    /// Process id if running.
    pub pid: Option<u32>,
    /// Restarts since the daemon started.
    pub restarts: u32,
    /// Sandbox layers that could not be applied.
    pub degraded: Vec<String>,
}

/// The paths a running daemon uses: those of `[daemon]` and `[vault.keepassxc]` when it
/// started (it binds the sockets, opens the audit log and starts the vault worker once;
/// a changed `[daemon]` or `[vault]` takes effect on a restart, so the configuration
/// file may name others).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonPaths {
    /// `agent.sock`.
    pub socket: String,
    /// `agent-forward.sock`.
    pub forward_socket: String,
    /// `control.sock`.
    pub control_socket: String,
    /// The audit log.
    pub audit_log: String,
    /// `[vault.keepassxc] database`, if set.
    #[serde(default)]
    pub keepassxc_database: Option<String>,
    /// `[vault.keepassxc] key_file`, if set.
    #[serde(default)]
    pub keepassxc_key_file: Option<String>,
}

/// Answer to [`Request::Status`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// Daemon version (`CARGO_PKG_VERSION`).
    pub version: String,
    /// Daemon process id.
    pub pid: u32,
    /// Path of the loaded configuration file.
    pub config: String,
    /// The sockets and the audit log in use.
    pub paths: DaemonPaths,
    /// Whether the proxy is locked (`ssh-add -x`).
    pub locked: bool,
    /// Upstream agents.
    pub upstreams: Vec<UpstreamStatus>,
    /// Workers.
    pub workers: Vec<WorkerStatus>,
    /// Vaults, if the vault worker could be asked.
    pub vaults: Vec<VaultStatus>,
}

/// One key in [`Response::Keys`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyInfo {
    /// The upstream that listed it.
    pub upstream: String,
    /// `ssh-ed25519 SHA256:…`.
    pub fingerprint: String,
    /// The comment.
    pub comment: String,
}

/// Answer to [`Request::TokenTest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenTestResult {
    /// The profile used.
    pub profile: String,
    /// The matching rule's URL pattern, `None` if no rule matched.
    pub rule: Option<String>,
    /// The source name.
    pub source: Option<String>,
    /// The username that would be handed to git.
    pub username: Option<String>,
    /// Expiry in seconds since the epoch.
    pub expires_at: Option<u64>,
}

/// One check in [`Response::SourceTested`]. It holds the outcome only: the secret it
/// resolved stays in the daemon and is dropped there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceCheck {
    /// What was checked: the reference as written in the configuration, or
    /// `gh login for <host>`.
    pub what: String,
    /// `None` if it worked, else why not (user-safe, as every [`WorkerError`]).
    pub error: Option<WorkerError>,
}

/// daemon to ctl.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    /// Answer to [`Request::Ping`].
    Pong {
        /// Daemon version.
        version: String,
        /// The sockets and the audit log in use.
        paths: DaemonPaths,
    },
    /// Answer to [`Request::Status`].
    Status(DaemonStatus),
    /// Answer to [`Request::Reload`].
    Reloaded,
    /// Answer to [`Request::Keys`].
    Keys(Vec<KeyInfo>),
    /// Answer to [`Request::TokenTest`].
    Token(TokenTestResult),
    /// Answer to [`Request::Unlock`]: session end in seconds since the epoch.
    Unlocked {
        /// Session end.
        expires_at: u64,
    },
    /// Answer to [`Request::Lock`].
    Locked,
    /// Answer to [`Request::StoreSecret`].
    Stored,
    /// Answer to [`Request::SourceTest`]: one check per secret reference (or the `gh`
    /// login); empty for a source with nothing to resolve (a credential helper).
    SourceTested(Vec<SourceCheck>),
    /// Any request failed.
    Error(WorkerError),
}
