//! Errors of the vault worker.

use credential_bridge_config::VaultKind;
use credential_bridge_proto::ipc::{WorkerError, WorkerErrorKind};

/// A vault operation failed. `Display` is safe to show on the server: it names vaults,
/// references and programs, never secret values or tool output that could contain them.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    /// The vault needs `ctl vault unlock` (or the desktop app is locked).
    #[error("vault {vault} is locked: run credential-bridge-ctl vault unlock {vault}")]
    Locked {
        /// The vault.
        vault: VaultKind,
    },
    /// The vault was locked while `ctl vault unlock` ran; the lock won and the unlock did not
    /// open the vault.
    #[error("vault {vault} was locked while it was being unlocked; unlock it again")]
    LockedDuringUnlock {
        /// The vault.
        vault: VaultKind,
    },
    /// The vault is locked in a way only its own app or the desktop session can fix
    /// (1Password app, KeePassXC database on Linux, keyring, gpg-agent).
    #[error("vault {vault} is locked: {hint}")]
    LockedElsewhere {
        /// The vault.
        vault: VaultKind,
        /// What to do, e.g. `open the database in the KeePassXC app`.
        hint: String,
    },
    /// An unlock of the vault is already running; a second one would make the first
    /// one's session key useless (Bitwarden).
    #[error("an unlock of {vault} is already running")]
    UnlockRunning {
        /// The vault.
        vault: VaultKind,
    },
    /// The reference names nothing.
    #[error("{reference} not found")]
    NotFound {
        /// The reference string.
        reference: String,
    },
    /// The vault's program is not installed.
    #[error("vault {vault} needs {program}, which is not in PATH")]
    ToolMissing {
        /// The vault.
        vault: VaultKind,
        /// The program name.
        program: String,
    },
    /// A program that is not a vault tool (`gh`, a git credential helper) is missing.
    #[error("{program} is not installed on this machine (not in PATH)")]
    ProgramMissing {
        /// The program name.
        program: String,
    },
    /// The program failed. `detail` is a short summary, never raw stdout.
    #[error("{program} failed: {detail}")]
    ToolFailed {
        /// The program name.
        program: String,
        /// Exit status and a sanitized first stderr line.
        detail: String,
    },
    /// The program did not finish in time.
    #[error("{program} did not answer in time")]
    Timeout {
        /// The program name.
        program: String,
    },
    /// A store did not finish within its deadline; it wrote nothing afterwards.
    #[error("storing in {vault} did not finish in time")]
    StoreTimeout {
        /// The vault.
        vault: VaultKind,
    },
    /// The vault is not available on this platform or build.
    #[error("vault {vault} is not supported here: {reason}")]
    Unsupported {
        /// The vault.
        vault: VaultKind,
        /// Why.
        reason: String,
    },
    /// Writing is not possible (`cmd:`).
    #[error("{reference} is read-only")]
    ReadOnly {
        /// The reference string.
        reference: String,
    },
    /// The request is malformed (unparsable reference, unknown vault name).
    #[error("{0}")]
    Invalid(String),
}

impl VaultError {
    /// The category for IPC.
    pub fn kind(&self) -> WorkerErrorKind {
        match self {
            VaultError::Locked { .. }
            | VaultError::LockedDuringUnlock { .. }
            | VaultError::LockedElsewhere { .. } => WorkerErrorKind::Locked,
            VaultError::NotFound { .. } => WorkerErrorKind::NotFound,
            VaultError::ToolMissing { .. }
            | VaultError::ProgramMissing { .. }
            | VaultError::Unsupported { .. } => WorkerErrorKind::Unavailable,
            VaultError::ToolFailed { .. } => WorkerErrorKind::Upstream,
            VaultError::Timeout { .. } | VaultError::StoreTimeout { .. } => WorkerErrorKind::Timeout,
            VaultError::ReadOnly { .. } => WorkerErrorKind::Denied,
            VaultError::UnlockRunning { .. } => WorkerErrorKind::Busy,
            VaultError::Invalid(_) => WorkerErrorKind::Invalid,
        }
    }
}

impl From<VaultError> for WorkerError {
    fn from(error: VaultError) -> Self {
        WorkerError::new(error.kind(), error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_message_says_how_to_unlock() {
        let error = VaultError::Locked { vault: VaultKind::Bitwarden };
        assert_eq!(
            error.to_string(),
            "vault bitwarden is locked: run credential-bridge-ctl vault unlock bitwarden"
        );
        assert_eq!(WorkerError::from(error).kind, WorkerErrorKind::Locked);
    }

    /// A second unlock is told to wait, not refused: it is no policy decision.
    #[test]
    fn a_running_unlock_is_busy_not_denied() {
        let error = WorkerError::from(VaultError::UnlockRunning { vault: VaultKind::Bitwarden });
        assert_eq!(error.kind, WorkerErrorKind::Busy);
        assert_eq!(error.message, "an unlock of bitwarden is already running");
        let read_only = VaultError::ReadOnly { reference: "bw://item/x".into() };
        assert_eq!(read_only.kind(), WorkerErrorKind::Denied);
    }
}
