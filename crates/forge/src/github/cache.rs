//! Caches of the git worker: installation ids and tokens. Both live only in memory and
//! are dropped when the worker exits after its idle period; tokens also on
//! [`credential_bridge_proto::ipc::git::Request::Forget`].

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use credential_bridge_proto::ipc::git::{GitToken, Permissions, SourceSpec};

/// A cached token is handed out only while it is valid for at least this long.
pub const REFRESH_MARGIN: Duration = Duration::from_secs(5 * 60);

/// How long an installation id is cached.
pub const INSTALLATION_TTL: Duration = Duration::from_secs(60 * 60);

/// What a cached token covers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TokenScopeKey {
    /// A stored token (PAT, GitLab, Forgejo): one per source.
    Static,
    /// A minted token for one repository: `owner/repo`.
    Repo(String),
    /// A minted token for all repositories of the owner's installation.
    Owner(String),
}

/// Cache key: source and its configuration, installation, repository and rights.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenKey {
    /// `[source.*]` name.
    pub source: String,
    /// The source's configuration (secret reference, App ID, API URL). A reload that
    /// changes it makes old tokens unreachable instead of handing them out again.
    pub spec: SourceSpec,
    /// Installation id for App tokens.
    pub installation: Option<u64>,
    /// What the token covers.
    pub scope: TokenScopeKey,
    /// Rights of a minted token (empty otherwise).
    pub permissions: Permissions,
}

/// Tokens by key. Thread-safe.
#[derive(Debug, Default)]
pub struct TokenCache {
    /// The entries.
    entries: Mutex<HashMap<TokenKey, GitToken>>,
    /// Counts [`TokenCache::forget`] calls; changed only while `entries` is locked.
    generation: AtomicU64,
}

impl TokenCache {
    /// The token for `key` if it is still fresh at `now` (see [`is_fresh`]). A stale
    /// entry is dropped, as it is never handed out again.
    pub fn get(&self, key: &TokenKey, now: SystemTime) -> Option<GitToken> {
        let mut entries = self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let token = entries.get(key)?;
        if is_fresh(token, now) {
            return Some(token.clone());
        }
        entries.remove(key);
        None
    }

    /// The current generation, taken before the secrets of a new token are fetched and
    /// passed to [`TokenCache::insert`].
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Stores `token` under `key`, replacing an older one, and drops every entry that is
    /// stale at `now`, so the cache does not grow with expired tokens.
    ///
    /// Nothing is stored if [`TokenCache::forget`] ran since `generation` was taken: the
    /// token was made while a vault was being locked and must not outlive the lock.
    /// Returns whether it was stored.
    pub fn insert(&self, key: TokenKey, token: GitToken, now: SystemTime, generation: u64) -> bool {
        let mut entries = self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.retain(|_, token| is_fresh(token, now));
        if self.generation.load(Ordering::SeqCst) != generation {
            return false;
        }
        entries.insert(key, token);
        true
    }

    /// Number of entries, stale ones included until the next `get` or `insert`.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
    }

    /// Drops the token under `key` (`git credential erase`); returns whether one existed.
    pub fn remove(&self, key: &TokenKey) -> bool {
        let mut entries = self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.remove(key).is_some()
    }

    /// Drops every token whose key matches `matches`; returns how many were dropped. Used
    /// by `erase` for App tokens when the installation id is no longer cached.
    pub fn remove_where(&self, matches: impl Fn(&TokenKey) -> bool) -> usize {
        let mut entries = self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = entries.len();
        entries.retain(|key, _| !matches(key));
        before - entries.len()
    }

    /// Drops every token whose key matches `matches` and starts a new generation, so
    /// tokens being made right now are not stored either (vault lock, `ssh-add -x`).
    /// Returns how many were dropped.
    pub fn forget(&self, matches: impl Fn(&TokenKey) -> bool) -> usize {
        let mut entries = self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        self.generation.fetch_add(1, Ordering::SeqCst);
        let before = entries.len();
        entries.retain(|key, _| !matches(key));
        before - entries.len()
    }
}

/// Whether `token` has no expiry or expires more than [`REFRESH_MARGIN`] after `now`.
fn is_fresh(token: &GitToken, now: SystemTime) -> bool {
    match token.expires_at {
        None => true,
        Some(secs) => SystemTime::UNIX_EPOCH + Duration::from_secs(secs) > now + REFRESH_MARGIN,
    }
}

/// Whether an installation id looked up at `at` is still valid at `now`.
fn is_recent(at: SystemTime, now: SystemTime) -> bool {
    now.duration_since(at).unwrap_or_default() < INSTALLATION_TTL
}

/// Key of the installation cache.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InstallationKey {
    /// API base URL.
    pub api_url: String,
    /// The App ID.
    pub app_id: u64,
    /// The owner (organisation or user), compared case-insensitively (store lower case).
    pub owner: String,
}

/// Installation ids by key, each valid for [`INSTALLATION_TTL`]. Thread-safe.
#[derive(Debug, Default)]
pub struct InstallationCache {
    /// Id and time of lookup.
    entries: Mutex<HashMap<InstallationKey, (u64, SystemTime)>>,
}

impl InstallationCache {
    /// The cached id, if looked up less than [`INSTALLATION_TTL`] before `now`. A stale
    /// entry is dropped.
    pub fn get(&self, key: &InstallationKey, now: SystemTime) -> Option<u64> {
        let mut entries = self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let &(id, at) = entries.get(key)?;
        if is_recent(at, now) {
            return Some(id);
        }
        entries.remove(key);
        None
    }

    /// Stores an id looked up at `now`, replacing an older one, and drops every entry
    /// that is stale at `now`.
    pub fn insert(&self, key: InstallationKey, id: u64, now: SystemTime) {
        let mut entries = self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.retain(|_, &mut (_, at)| is_recent(at, now));
        entries.insert(key, (id, now));
    }

    /// Number of entries, stale ones included until the next `get` or `insert`.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
    }

    /// Drops an id (e.g. after the installation answered 404).
    pub fn remove(&self, key: &InstallationKey) {
        let mut entries = self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use credential_bridge_proto::secret::Secret;

    fn key() -> TokenKey {
        TokenKey {
            source: "my-org".into(),
            spec: SourceSpec::GithubPat { token: "op://v/i/f".into() },
            installation: Some(1),
            scope: TokenScopeKey::Repo("my-org/app".into()),
            permissions: Permissions::new(),
        }
    }

    #[test]
    fn tokens_are_refreshed_before_expiry() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let cache = TokenCache::default();
        let token = GitToken {
            username: "x-access-token".into(),
            password: Secret::new("t".into()),
            expires_at: Some(10_000 + 600),
        };
        cache.insert(key(), token, now, cache.generation());
        assert!(cache.get(&key(), now).is_some());
        assert!(cache.remove(&key()));
    }

    fn token(expires_at: Option<u64>) -> GitToken {
        GitToken { username: "x-access-token".into(), password: Secret::new("t".into()), expires_at }
    }

    fn repo_key(repo: &str) -> TokenKey {
        TokenKey { scope: TokenScopeKey::Repo(format!("my-org/{repo}")), ..key() }
    }

    #[test]
    fn stale_tokens_are_dropped_on_get() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let cache = TokenCache::default();
        cache.insert(key(), token(Some(10_000 + 600)), now, 0);
        assert!(cache.get(&key(), now + Duration::from_secs(301)).is_none());
        assert_eq!(cache.len(), 0);
        assert!(!cache.remove(&key()));
    }

    #[test]
    fn insert_purges_stale_tokens() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let cache = TokenCache::default();
        cache.insert(repo_key("old"), token(Some(10_000 + 600)), now, 0);
        cache.insert(repo_key("static"), token(None), now, 0);
        assert_eq!(cache.len(), 2);
        let later = now + Duration::from_secs(3600);
        cache.insert(repo_key("new"), token(Some(10_000 + 7200)), later, 0);
        assert_eq!(cache.len(), 2, "the expired token is purged");
        assert!(cache.get(&repo_key("old"), later).is_none());
        assert!(cache.get(&repo_key("static"), later).is_some());
        assert!(cache.get(&repo_key("new"), later).is_some());
    }

    #[test]
    fn forget_drops_matching_tokens_and_blocks_older_inserts() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let cache = TokenCache::default();
        let before = cache.generation();
        assert!(cache.insert(repo_key("app"), token(None), now, before));
        assert!(cache.insert(repo_key("lib"), token(None), now, before));
        assert_eq!(cache.forget(|key| key.scope == TokenScopeKey::Repo("my-org/app".into())), 1);
        assert!(cache.get(&repo_key("app"), now).is_none());
        assert!(cache.get(&repo_key("lib"), now).is_some());
        // A token whose secrets were fetched before the forget is handed out but not kept.
        assert!(!cache.insert(repo_key("app"), token(None), now, before));
        assert!(cache.get(&repo_key("app"), now).is_none());
        assert!(cache.insert(repo_key("app"), token(None), now, cache.generation()));
        assert_eq!(cache.forget(|_| true), 2);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn installations_expire() {
        let now = SystemTime::UNIX_EPOCH;
        let cache = InstallationCache::default();
        let key = InstallationKey { api_url: "x".into(), app_id: 1, owner: "o".into() };
        cache.insert(key.clone(), 42, now);
        assert_eq!(cache.get(&key, now), Some(42));
        assert_eq!(cache.get(&key, now + INSTALLATION_TTL), None);
    }

    fn installation(owner: &str) -> InstallationKey {
        InstallationKey { api_url: "x".into(), app_id: 1, owner: owner.into() }
    }

    #[test]
    fn stale_installations_are_dropped_on_get() {
        let now = SystemTime::UNIX_EPOCH;
        let cache = InstallationCache::default();
        cache.insert(installation("o"), 42, now);
        assert_eq!(cache.get(&installation("o"), now + INSTALLATION_TTL - Duration::from_secs(1)), Some(42));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&installation("o"), now + INSTALLATION_TTL), None);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn insert_purges_stale_installations() {
        let now = SystemTime::UNIX_EPOCH;
        let cache = InstallationCache::default();
        cache.insert(installation("old"), 1, now);
        cache.insert(installation("recent"), 2, now + Duration::from_secs(60));
        assert_eq!(cache.len(), 2);
        let later = now + INSTALLATION_TTL + Duration::from_secs(1);
        cache.insert(installation("new"), 3, later);
        assert_eq!(cache.len(), 2, "only the stale entry is dropped");
        assert_eq!(cache.get(&installation("recent"), later), Some(2));
        assert_eq!(cache.get(&installation("new"), later), Some(3));
        assert_eq!(cache.get(&installation("old"), later), None);
    }
}
