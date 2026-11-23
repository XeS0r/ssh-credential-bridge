//! Unlock sessions (`ctl vault unlock <vault>`). Session keys live only in the vault worker's
//! memory and expire; nothing is written to disk.

use std::collections::BTreeMap;
use std::time::SystemTime;

use credential_bridge_config::VaultKind;
use credential_bridge_proto::secret::Secret;

/// One open session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// What the vault needs on later calls: Bitwarden's `BW_SESSION` key, the KeePassXC
    /// database password (macOS, `keepassxc-cli`).
    pub key: Secret,
    /// When the session ends.
    pub expires_at: SystemTime,
}

/// Open sessions by vault.
#[derive(Debug, Clone, Default)]
pub struct UnlockSessions {
    /// Sessions, at most one per vault.
    sessions: BTreeMap<VaultKind, Session>,
    /// Lock counters: per vault, and one for [`UnlockSessions::clear`]. An unlock that
    /// started before a lock must not open the vault again when it finishes.
    locks: BTreeMap<VaultKind, u64>,
    /// Number of [`UnlockSessions::clear`] calls.
    clears: u64,
}

/// The lock state of one vault when an unlock started; see
/// [`UnlockSessions::lock_generation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockGeneration(u64, u64);

impl UnlockSessions {
    /// No sessions.
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens or replaces the session of `vault`.
    pub fn insert(&mut self, vault: VaultKind, session: Session) {
        self.sessions.insert(vault, session);
    }

    /// The current lock state of `vault`, taken before an unlock program runs.
    pub fn lock_generation(&self, vault: VaultKind) -> LockGeneration {
        LockGeneration(self.locks.get(&vault).copied().unwrap_or(0), self.clears)
    }

    /// Opens the session of `vault` unless it was locked since `generation` was taken;
    /// returns whether the session was opened. A refused session is dropped (and its
    /// key zeroized).
    pub fn insert_unless_locked(
        &mut self,
        vault: VaultKind,
        session: Session,
        generation: LockGeneration,
    ) -> bool {
        if self.lock_generation(vault) != generation {
            return false;
        }
        self.insert(vault, session);
        true
    }

    /// The session of `vault` if it has not expired at `now`.
    pub fn get(&self, vault: VaultKind, now: SystemTime) -> Option<&Session> {
        self.sessions.get(&vault).filter(|session| session.expires_at > now)
    }

    /// Ends the session of `vault`; returns whether one was open.
    pub fn remove(&mut self, vault: VaultKind) -> bool {
        *self.locks.entry(vault).or_default() += 1;
        self.sessions.remove(&vault).is_some()
    }

    /// Ends all sessions.
    pub fn clear(&mut self) {
        self.clears += 1;
        self.sessions.clear();
    }

    /// Drops sessions that expired at `now` (their keys are zeroized on drop).
    pub fn purge_expired(&mut self, now: SystemTime) {
        self.sessions.retain(|_, session| session.expires_at > now);
    }

    /// Whether any session is open at `now`.
    pub fn any_open(&self, now: SystemTime) -> bool {
        self.sessions.values().any(|session| session.expires_at > now)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_lock_during_unlock_wins() {
        let session = || Session { key: Secret::new("key".into()), expires_at: SystemTime::UNIX_EPOCH };
        let mut sessions = UnlockSessions::new();
        let before = sessions.lock_generation(VaultKind::Bitwarden);
        sessions.remove(VaultKind::Bitwarden);
        assert!(!sessions.insert_unless_locked(VaultKind::Bitwarden, session(), before));
        let before = sessions.lock_generation(VaultKind::Bitwarden);
        sessions.clear();
        assert!(!sessions.insert_unless_locked(VaultKind::Bitwarden, session(), before));
        // Locking another vault does not matter.
        let before = sessions.lock_generation(VaultKind::Bitwarden);
        sessions.remove(VaultKind::KeePassXc);
        assert!(sessions.insert_unless_locked(VaultKind::Bitwarden, session(), before));
    }

    use std::time::Duration;

    use super::*;

    #[test]
    fn sessions_expire() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let mut sessions = UnlockSessions::new();
        let session = Session { key: Secret::new("key".into()), expires_at: start + Duration::from_secs(60) };
        sessions.insert(VaultKind::Bitwarden, session);
        assert!(sessions.get(VaultKind::Bitwarden, start).is_some());
        assert!(sessions.any_open(start));
        let later = start + Duration::from_secs(61);
        assert!(sessions.get(VaultKind::Bitwarden, later).is_none());
        sessions.purge_expired(later);
        assert!(!sessions.remove(VaultKind::Bitwarden));
    }
}
