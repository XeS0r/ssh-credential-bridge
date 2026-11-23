//! Messages of the vault worker: secret references, unlock sessions, and the `gh` and
//! `helper` git sources (all of which run external programs).

use serde::{Deserialize, Serialize};

use super::git::{GitToken, TokenTarget};
use crate::secret::Secret;

/// What git asked for, for the `gh` and `helper` sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialAction {
    /// `get`
    Get,
    /// `erase` (forwarded to helpers; `gh` ignores it)
    Erase,
}

/// Core to vault worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Resolve a secret reference string (validated by the configuration).
    Resolve {
        /// e.g. `op://Dev/bridge-app/private-key`.
        reference: String,
    },
    /// Write a secret into a vault (`ctl source add github --auth app --create`). Refused
    /// for `cmd:`.
    Store {
        /// Where to write.
        reference: String,
        /// The value.
        value: Secret,
    },
    /// Open an unlock session (`ctl vault unlock <vault>`).
    Unlock {
        /// Vault kind name as in `ctl vault unlock`, e.g. `bitwarden`, `keepassxc`.
        vault: String,
        /// The master password, used once to obtain a session and then dropped.
        password: Secret,
        /// Session lifetime in seconds; `None` for the vault's default.
        ttl_secs: Option<u64>,
    },
    /// End the session of one vault, or of all with `None`.
    Lock {
        /// Vault kind name, or `None` for all.
        vault: Option<String>,
    },
    /// Report availability and unlock state of every vault kind.
    Status,
    /// `gh auth git-credential get` for the target.
    GhCredential {
        /// The repository.
        target: TokenTarget,
        /// `get` or `erase`.
        action: CredentialAction,
    },
    /// Run an existing git credential helper (`git credential-<helper>` or an absolute
    /// command, as git interprets `credential.helper`).
    HelperCredential {
        /// The helper as configured, e.g. `manager` or `/usr/bin/git-credential-foo`.
        helper: String,
        /// The repository.
        target: TokenTarget,
        /// `get` or `erase`.
        action: CredentialAction,
    },
}

/// State of one vault kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultStatus {
    /// Vault kind name.
    pub vault: String,
    /// Whether its tool or service is present on this machine.
    pub available: bool,
    /// End of the unlock session in seconds since the epoch, if one is open.
    pub unlocked_until: Option<u64>,
    /// Extra information for `ctl check`, e.g. `bw not found in PATH`.
    pub note: Option<String>,
}

/// Vault worker to core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    /// Answer to [`Request::Resolve`].
    Secret(Secret),
    /// Answer to [`Request::Store`].
    Stored,
    /// Answer to [`Request::Unlock`]: session end in seconds since the epoch.
    Unlocked {
        /// Session end.
        expires_at: u64,
    },
    /// Answer to [`Request::Lock`].
    Locked,
    /// Answer to [`Request::Status`].
    Status(Vec<VaultStatus>),
    /// Answer to `GhCredential`/`HelperCredential` `get`: `None` if the tool had none.
    Credential(Option<GitToken>),
    /// Answer to `GhCredential`/`HelperCredential` `erase`.
    Erased,
}
