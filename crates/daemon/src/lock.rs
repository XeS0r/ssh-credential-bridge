//! `ssh-add -x` / `-X`: locking the proxy locks all upstreams with it.
//!
//! The upstream agents themselves are not locked: while the proxy is locked nothing
//! reaches them through it, which is what a client of the proxy can observe.

use std::sync::Mutex;
use std::time::Duration;

use credential_bridge_proto::secret::SecretBytes;

/// Delay added per failed unlock before answering, as ssh-agent does.
const FAILURE_STEP: Duration = Duration::from_millis(100);

/// The longest delay after failed unlocks.
const MAX_FAILURE_DELAY: Duration = Duration::from_secs(10);

/// The proxy lock. While locked, identity lists are empty and every request but
/// `SSH_AGENTC_UNLOCK` fails (on both sockets).
#[derive(Debug, Default)]
pub struct ProxyLock {
    /// The passphrase while locked (compared in constant time on unlock) and the number
    /// of failed unlocks since it was set.
    state: Mutex<LockState>,
    /// Held for a whole unlock attempt, the delay after a failure included, so that
    /// attempts run one after the other however many connections make them (ssh-agent
    /// gets the same from its single loop).
    attempts: tokio::sync::Mutex<()>,
}

/// What [`ProxyLock`] guards.
#[derive(Debug, Default)]
struct LockState {
    /// The passphrase while locked.
    passphrase: Option<SecretBytes>,
    /// Failed unlocks while locked.
    failures: u32,
}

/// The outcome of [`ProxyLock::unlock`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unlock {
    /// The proxy is unlocked now.
    Unlocked,
    /// Not locked, or a wrong passphrase. The caller waits `delay` before answering, so
    /// a client of `agent.sock` cannot try passphrases at full speed.
    Failed {
        /// 100 ms per failure since locking, at most 10 s.
        delay: Duration,
    },
}

impl ProxyLock {
    /// The state, also after a panic elsewhere.
    fn state(&self) -> std::sync::MutexGuard<'_, LockState> {
        crate::sync::lock(&self.state)
    }

    /// Whether the proxy is locked.
    pub fn is_locked(&self) -> bool {
        self.state().passphrase.is_some()
    }

    /// Locks with `passphrase`. Returns `false` if already locked (as ssh-agent).
    pub fn lock(&self, passphrase: SecretBytes) -> bool {
        let mut state = self.state();
        if state.passphrase.is_some() {
            return false;
        }
        state.passphrase = Some(passphrase);
        state.failures = 0;
        true
    }

    /// One unlock attempt as a client sees it: waits for earlier attempts (and their
    /// delays) to finish, then unlocks if `passphrase` matches, else waits the delay of
    /// [`ProxyLock::unlock`] before returning `false`. Attempts from all connections run
    /// one at a time, so passphrases cannot be tried in parallel.
    pub async fn attempt_unlock(&self, passphrase: &SecretBytes) -> bool {
        let _turn = self.attempts.lock().await;
        match self.unlock(passphrase) {
            Unlock::Unlocked => true,
            Unlock::Failed { delay } => {
                tokio::time::sleep(delay).await;
                false
            }
        }
    }

    /// Unlocks if `passphrase` matches. Fails if not locked or on mismatch; every
    /// mismatch makes the next delay longer. The caller must wait the delay before the
    /// next attempt; [`ProxyLock::attempt_unlock`] does.
    pub fn unlock(&self, passphrase: &SecretBytes) -> Unlock {
        let mut state = self.state();
        let Some(stored) = state.passphrase.as_ref() else {
            return Unlock::Failed { delay: Duration::ZERO };
        };
        if constant_time_eq(stored.expose(), passphrase.expose()) {
            state.passphrase = None;
            state.failures = 0;
            return Unlock::Unlocked;
        }
        state.failures = state.failures.saturating_add(1);
        let delay = FAILURE_STEP.saturating_mul(state.failures).min(MAX_FAILURE_DELAY);
        Unlock::Failed { delay }
    }
}

/// Compares two byte strings without an early exit on the first difference. The length
/// is not hidden, as in ssh-agent.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let difference = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(difference) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(text: &str) -> SecretBytes {
        SecretBytes::new(text.as_bytes().to_vec())
    }

    fn unlocked(lock: &ProxyLock, text: &str) -> bool {
        lock.unlock(&secret(text)) == Unlock::Unlocked
    }

    #[test]
    fn lock_and_unlock() {
        let lock = ProxyLock::default();
        assert!(!lock.is_locked());
        assert!(!unlocked(&lock, "x"), "unlocking an unlocked proxy fails");
        assert!(lock.lock(secret("pass")));
        assert!(lock.is_locked());
        assert!(!lock.lock(secret("other")), "locking twice fails");
        assert!(!unlocked(&lock, "wrong"));
        assert!(!unlocked(&lock, "pas"));
        assert!(lock.is_locked());
        assert!(unlocked(&lock, "pass"));
        assert!(!lock.is_locked());
    }

    #[test]
    fn failed_unlocks_slow_down() {
        let lock = ProxyLock::default();
        assert_eq!(lock.unlock(&secret("x")), Unlock::Failed { delay: Duration::ZERO });
        assert!(lock.lock(secret("pass")));
        assert_eq!(lock.unlock(&secret("a")), Unlock::Failed { delay: Duration::from_millis(100) });
        assert_eq!(lock.unlock(&secret("b")), Unlock::Failed { delay: Duration::from_millis(200) });
        for _ in 0..200 {
            lock.unlock(&secret("c"));
        }
        assert_eq!(lock.unlock(&secret("d")), Unlock::Failed { delay: MAX_FAILURE_DELAY });
        assert!(unlocked(&lock, "pass"));
        // A new lock starts counting again.
        assert!(lock.lock(secret("pass")));
        assert_eq!(lock.unlock(&secret("a")), Unlock::Failed { delay: Duration::from_millis(100) });
    }

    #[test]
    fn empty_passphrase_works() {
        let lock = ProxyLock::default();
        assert!(lock.lock(secret("")));
        assert!(unlocked(&lock, ""));
    }

    /// Unlock attempts from many connections run one after the other, each with its
    /// delay: a burst of wrong guesses takes the sum of the delays, and the right
    /// passphrase sent meanwhile waits its turn.
    #[tokio::test(start_paused = true)]
    async fn unlock_attempts_are_serialised() {
        let lock = std::sync::Arc::new(ProxyLock::default());
        assert!(lock.lock(secret("pass")));
        let start = tokio::time::Instant::now();
        let guesses: Vec<_> = (0..5)
            .map(|n| {
                let lock = std::sync::Arc::clone(&lock);
                tokio::spawn(async move { lock.attempt_unlock(&secret(&format!("guess{n}"))).await })
            })
            .collect();
        tokio::task::yield_now().await;
        let right = {
            let lock = std::sync::Arc::clone(&lock);
            tokio::spawn(async move { lock.attempt_unlock(&secret("pass")).await })
        };
        for guess in guesses {
            assert!(!guess.await.unwrap());
        }
        // 100 + 200 + 300 + 400 + 500 ms, one after the other.
        assert!(start.elapsed() >= Duration::from_millis(1500), "{:?}", start.elapsed());
        assert!(right.await.unwrap());
        assert!(!lock.is_locked());
    }

    /// Not locked: an attempt fails without delay.
    #[tokio::test(start_paused = true)]
    async fn unlocking_an_unlocked_proxy_fails_at_once() {
        let lock = ProxyLock::default();
        let start = tokio::time::Instant::now();
        assert!(!lock.attempt_unlock(&secret("x")).await);
        assert_eq!(start.elapsed(), Duration::ZERO);
    }
}
