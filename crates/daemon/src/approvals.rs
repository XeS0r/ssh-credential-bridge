//! Approvals for ssh signatures (`confirm` in a profile).
//!
//! The answer is remembered per (server, key, local process, hop or not) for the
//! profile's duration. A denial or a dialog error is not remembered. While a dialog for a
//! combination is open, further requests for it wait for the same answer. Requests that
//! must not be remembered (connections without a server bind, which all share one label)
//! get a dialog of their own every time.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use credential_bridge_platform::approval::{ApprovalAnswer, ApprovalDialog, ApprovalRequest};
use tokio::sync::watch;

/// How long a dialog may stay open.
pub const DIALOG_TIMEOUT: Duration = Duration::from_secs(60);

/// What an approval covers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApprovalKey {
    /// Server name from the bind, or `local`.
    pub server: String,
    /// Key fingerprint (`SHA256:…`).
    pub key: String,
    /// Local process name (from the peer pid), if known.
    pub process: Option<String>,
    /// Whether the request comes from a hop behind the server.
    pub hop: bool,
}

/// Remembered approvals.
#[derive(Debug, Default)]
pub struct ApprovalCache {
    /// Approval expiry by key, and how often the cache was cleared.
    entries: Mutex<Entries>,
    /// Dialogs that are open: waiters subscribe for the answer (`None` until known).
    pending: Mutex<HashMap<ApprovalKey, watch::Receiver<Option<bool>>>>,
}

/// What [`ApprovalCache::entries`] guards: both under one lock, so that an approval is
/// never stored after a [`ApprovalCache::clear`] it did not see.
#[derive(Debug, Default)]
struct Entries {
    /// Approval expiry by key.
    approvals: HashMap<ApprovalKey, Instant>,
    /// Number of [`ApprovalCache::clear`] calls.
    generation: u64,
}

impl ApprovalCache {
    /// Whether `key` was approved and the approval is still valid at `now`.
    pub fn is_approved(&self, key: &ApprovalKey, now: Instant) -> bool {
        let entries = crate::sync::lock(&self.entries);
        entries.approvals.get(key).is_some_and(|until| *until > now)
    }

    /// The current generation, taken before a dialog is shown; see
    /// [`ApprovalCache::approve`].
    pub fn generation(&self) -> u64 {
        crate::sync::lock(&self.entries).generation
    }

    /// Remembers an approval for `valid_for` from `now`, unless the cache was cleared
    /// since `generation` was taken (a lock, or a reload that changed profiles or
    /// servers, while the dialog was open); returns whether it was remembered.
    pub fn approve(&self, key: ApprovalKey, now: Instant, valid_for: Duration, generation: u64) -> bool {
        let mut entries = crate::sync::lock(&self.entries);
        if entries.generation != generation {
            return false;
        }
        entries.approvals.retain(|_, until| *until > now);
        entries.approvals.insert(key, now + valid_for);
        true
    }

    /// Forgets everything (on a reload that changes profiles or servers, and on
    /// `ssh-add -x`), including what dialogs open now will answer.
    pub fn clear(&self) {
        let mut entries = crate::sync::lock(&self.entries);
        entries.generation += 1;
        entries.approvals.clear();
    }
}

/// Removes the pending entry when the dialog's owner finishes (also on cancellation).
struct PendingGuard<'a> {
    /// The cache.
    cache: &'a ApprovalCache,
    /// The key.
    key: ApprovalKey,
    /// Publishes the answer.
    sender: watch::Sender<Option<bool>>,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        // Waiters that see no answer (owner cancelled) count it as a denial.
        if self.sender.borrow().is_none() {
            let _ = self.sender.send(Some(false));
        }
        crate::sync::lock(&self.cache.pending).remove(&self.key);
    }
}

/// Asks the user (unless remembered) and returns whether the signature may proceed.
/// Runs the platform dialog on a blocking thread; every error counts as a denial.
/// `remember` is how long an approval is remembered; `None` asks every time, neither
/// using nor filling the cache and without sharing a dialog with other requests.
///
/// The dialog is shared (`Arc`) because it runs on a blocking thread that may outlive
/// the caller's borrow.
pub async fn confirm(
    cache: &ApprovalCache,
    dialog: Arc<dyn ApprovalDialog>,
    key: ApprovalKey,
    remember: Option<Duration>,
) -> bool {
    let Some(remember) = remember else {
        return show(dialog, &key, None).await;
    };
    loop {
        if cache.is_approved(&key, Instant::now()) {
            return true;
        }
        let waiting = {
            let mut pending = crate::sync::lock(&cache.pending);
            match pending.get(&key) {
                Some(receiver) => Ok(receiver.clone()),
                None => {
                    let (sender, receiver) = watch::channel(None);
                    pending.insert(key.clone(), receiver);
                    Err(sender)
                }
            }
        };
        match waiting {
            Ok(mut receiver) => {
                let answer = receiver.wait_for(Option::is_some).await.map(|answer| *answer == Some(true));
                match answer {
                    Ok(answer) => return answer,
                    // The owner vanished without an answer: start over.
                    Err(_) => continue,
                }
            }
            Err(sender) => {
                let guard = PendingGuard { cache, key: key.clone(), sender };
                return ask(cache, dialog, guard, remember).await;
            }
        }
    }
}

/// Shows the dialog as the owner of `guard`, remembers an approval (unless the cache was
/// cleared while the dialog was open) and publishes the answer to waiters.
///
/// The answer still holds for the requests that waited for it: a lock meanwhile is
/// checked by the caller, which must not pass a signature on while the proxy is locked.
async fn ask(
    cache: &ApprovalCache,
    dialog: Arc<dyn ApprovalDialog>,
    guard: PendingGuard<'_>,
    remember: Duration,
) -> bool {
    let generation = cache.generation();
    let allowed = show(dialog, &guard.key, Some(remember)).await;
    if allowed && !cache.approve(guard.key.clone(), Instant::now(), remember, generation) {
        tracing::info!("approval not remembered: approvals were cleared while the dialog was open");
    }
    let _ = guard.sender.send(Some(allowed));
    allowed
}

/// Shows the dialog for `key` and returns whether the user allowed.
async fn show(dialog: Arc<dyn ApprovalDialog>, key: &ApprovalKey, remember: Option<Duration>) -> bool {
    let request = ApprovalRequest {
        server: key.server.clone(),
        key: key.key.clone(),
        process: key.process.clone(),
        hop: key.hop,
        remember,
    };
    let answer = tokio::task::spawn_blocking(move || dialog.ask(&request, DIALOG_TIMEOUT)).await;
    match answer {
        Ok(Ok(ApprovalAnswer::Allow)) => true,
        Ok(Ok(ApprovalAnswer::Deny)) => false,
        Ok(Err(error)) => {
            tracing::warn!("approval dialog: {error}");
            false
        }
        Err(error) => {
            tracing::warn!("approval dialog task failed: {error}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use credential_bridge_platform::approval::ApprovalError;

    use super::*;

    #[test]
    fn approvals_expire() {
        let cache = ApprovalCache::default();
        let key = ApprovalKey { server: "build".into(), key: "SHA256:x".into(), process: None, hop: false };
        let now = Instant::now();
        assert!(cache.approve(key.clone(), now, Duration::from_secs(10), cache.generation()));
        assert!(cache.is_approved(&key, now));
        assert!(!cache.is_approved(&key, now + Duration::from_secs(10)));
        cache.clear();
        assert!(!cache.is_approved(&key, now));
    }

    /// Answers with a fixed result after a delay and counts calls.
    #[derive(Debug)]
    struct FakeDialog {
        answer: Option<ApprovalAnswer>,
        calls: AtomicUsize,
        delay: Duration,
        /// The requests shown.
        requests: Mutex<Vec<ApprovalRequest>>,
    }

    impl ApprovalDialog for FakeDialog {
        fn ask(
            &self,
            request: &ApprovalRequest,
            _timeout: Duration,
        ) -> Result<ApprovalAnswer, ApprovalError> {
            assert_eq!(request.server, "build");
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.requests.lock().unwrap().push(request.clone());
            std::thread::sleep(self.delay);
            self.answer.ok_or(ApprovalError::Timeout)
        }
    }

    fn key() -> ApprovalKey {
        ApprovalKey {
            server: "build".into(),
            key: "SHA256:k".into(),
            process: Some("ssh".into()),
            hop: false,
        }
    }

    fn dialog(answer: Option<ApprovalAnswer>, delay: Duration) -> Arc<FakeDialog> {
        Arc::new(FakeDialog { answer, calls: AtomicUsize::new(0), delay, requests: Mutex::default() })
    }

    #[tokio::test]
    async fn allow_is_remembered_and_shared() {
        let cache = ApprovalCache::default();
        let fake = dialog(Some(ApprovalAnswer::Allow), Duration::from_millis(100));
        let remember = Some(Duration::from_secs(60));
        let (a, b) = tokio::join!(
            confirm(&cache, fake.clone(), key(), remember),
            confirm(&cache, fake.clone(), key(), remember)
        );
        assert!(a && b);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1, "one dialog for concurrent requests");
        assert!(confirm(&cache, fake.clone(), key(), remember).await);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1, "remembered");
        let other = ApprovalKey { process: Some("git".into()), ..key() };
        assert!(confirm(&cache, fake.clone(), other, remember).await);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 2, "another process asks again");
    }

    #[tokio::test]
    async fn deny_and_errors_are_not_remembered() {
        let cache = ApprovalCache::default();
        let deny = dialog(Some(ApprovalAnswer::Deny), Duration::from_millis(50));
        let (a, b) = tokio::join!(
            confirm(&cache, deny.clone(), key(), Some(Duration::from_secs(60))),
            confirm(&cache, deny.clone(), key(), Some(Duration::from_secs(60)))
        );
        assert!(!a && !b);
        assert_eq!(deny.calls.load(Ordering::SeqCst), 1);
        assert!(!confirm(&cache, deny.clone(), key(), Some(Duration::from_secs(60))).await);
        assert_eq!(deny.calls.load(Ordering::SeqCst), 2);
        let failing = dialog(None, Duration::ZERO);
        assert!(!confirm(&cache, failing, key(), Some(Duration::from_secs(60))).await);
        assert!(!cache.is_approved(&key(), Instant::now()));
    }

    #[tokio::test]
    async fn hops_are_approved_separately_and_shown() {
        let cache = ApprovalCache::default();
        let fake = dialog(Some(ApprovalAnswer::Allow), Duration::ZERO);
        let remember = Some(Duration::from_secs(60));
        assert!(confirm(&cache, fake.clone(), key(), remember).await);
        let hop = ApprovalKey { hop: true, ..key() };
        assert!(confirm(&cache, fake.clone(), hop.clone(), remember).await);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 2, "an approval for the server does not cover a hop");
        assert!(confirm(&cache, fake.clone(), hop, remember).await);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 2, "the hop approval is remembered");
        let requests = fake.requests.lock().unwrap();
        assert!(!requests[0].hop);
        assert!(requests[1].hop);
        assert_eq!(requests[1].remember, remember);
    }

    #[tokio::test]
    async fn unremembered_requests_ask_every_time() {
        let cache = ApprovalCache::default();
        let fake = dialog(Some(ApprovalAnswer::Allow), Duration::from_millis(100));
        let (a, b) = tokio::join!(
            confirm(&cache, fake.clone(), key(), None),
            confirm(&cache, fake.clone(), key(), None)
        );
        assert!(a && b);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 2, "no shared dialog");
        assert!(confirm(&cache, fake.clone(), key(), None).await);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 3, "not remembered");
        assert!(!cache.is_approved(&key(), Instant::now()));
        assert!(fake.requests.lock().unwrap().iter().all(|request| request.remember.is_none()));
        // A remembered approval does not answer an unremembered request either.
        cache.approve(key(), Instant::now(), Duration::from_secs(60), cache.generation());
        assert!(confirm(&cache, fake.clone(), key(), None).await);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn a_clear_wins_over_an_older_generation() {
        let cache = ApprovalCache::default();
        let now = Instant::now();
        let before = cache.generation();
        cache.clear();
        assert!(!cache.approve(key(), now, Duration::from_secs(60), before));
        assert!(!cache.is_approved(&key(), now));
        assert!(cache.approve(key(), now, Duration::from_secs(60), cache.generation()));
        assert!(cache.is_approved(&key(), now));
    }

    /// A clear (lock or reload) while the dialog is open: the answer reaches the request
    /// and its waiters, but is not remembered.
    #[tokio::test]
    async fn an_approval_given_during_a_clear_is_not_remembered() {
        let cache = Arc::new(ApprovalCache::default());
        let fake = dialog(Some(ApprovalAnswer::Allow), Duration::from_millis(300));
        let remember = Some(Duration::from_secs(60));
        let asking = {
            let (cache, fake) = (Arc::clone(&cache), fake.clone());
            tokio::spawn(async move { confirm(&cache, fake, key(), remember).await })
        };
        let waiting = {
            let (cache, fake) = (Arc::clone(&cache), fake.clone());
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                confirm(&cache, fake, key(), remember).await
            })
        };
        tokio::time::sleep(Duration::from_millis(150)).await;
        cache.clear();
        assert!(asking.await.unwrap());
        assert!(waiting.await.unwrap());
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1, "the waiter shared the dialog");
        assert!(!cache.is_approved(&key(), Instant::now()));
        assert!(confirm(&cache, fake.clone(), key(), remember).await);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 2, "asked again after the clear");
    }
}
