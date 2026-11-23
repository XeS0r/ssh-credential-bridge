//! The git worker's logic: turns a resolved rule ([`TokenRequest`]) into a token.
//!
//! Sources: GitHub fine-grained PAT, GitHub App (JWT, installation lookup, minting,
//! caches), GitLab token, Forgejo/Gitea token. `gh` and `helper` sources are not here;
//! they run in the vault worker.
//!
//! The git worker is sandboxed (TCP 443 only) and **never starts programs**. Secrets come
//! through [`SecretProvider`], which the daemon's `worker git` loop implements with
//! [`credential_bridge_proto::ipc::Callback::Secret`] round trips to the core. The GitHub
//! API base URL comes from the request ([`SourceSpec::GithubApp::api_url`]), so tests
//! point it at a local mock server.
//!
//! [`TokenRequest`]: credential_bridge_proto::ipc::git::TokenRequest
//! [`SourceSpec::GithubApp::api_url`]: credential_bridge_proto::ipc::git::SourceSpec::GithubApp

mod error;
pub mod github;
pub mod tokens;

use std::fmt::Debug;
use std::future::Future;
use std::time::SystemTime;

pub use error::ForgeError;

use credential_bridge_proto::ipc::WorkerError;
use credential_bridge_proto::ipc::git::{
    GitToken, Permissions, Request, Response, SourceSpec, TokenRequest, TokenScope, TokenTarget,
};
use credential_bridge_proto::secret::Secret;

use crate::github::GithubClient;
use crate::github::app::app_jwt;
use crate::github::cache::{InstallationCache, InstallationKey, TokenCache, TokenKey, TokenScopeKey};
use crate::tokens::{FORGEJO_USERNAME, GITHUB_USERNAME, GITLAB_USERNAME};

/// Gets secrets for the git worker (from the core, which asks the vault worker).
pub trait SecretProvider: Send + Sync {
    /// Resolves a secret reference string.
    ///
    /// Errors: [`ForgeError::Secret`] carrying the vault worker's error (e.g. a locked
    /// vault), passed on to git unchanged.
    fn secret(&self, reference: &str) -> impl Future<Output = Result<Secret, ForgeError>> + Send;
}

/// A source of the current time (fake in tests).
pub trait Clock: Debug + Send + Sync {
    /// Now.
    fn now(&self) -> SystemTime;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Request handling of the git worker. `handle` takes `&self` so the worker loop can
/// serve requests concurrently; caches use interior mutability.
#[derive(Debug)]
pub struct GitWorker<S: SecretProvider, C: Clock> {
    /// Where secrets come from.
    pub secrets: S,
    /// The clock for token and JWT lifetimes.
    pub clock: C,
    /// The GitHub REST client.
    pub github: GithubClient,
    /// Installation ids by (API URL, App ID, owner).
    pub installations: InstallationCache,
    /// Tokens by cache key.
    pub tokens: TokenCache,
}

impl<S: SecretProvider, C: Clock> GitWorker<S, C> {
    /// A worker with empty caches.
    pub fn new(secrets: S, clock: C, github: GithubClient) -> Self {
        Self {
            secrets,
            clock,
            github,
            installations: InstallationCache::default(),
            tokens: TokenCache::default(),
        }
    }

    /// Handles one request.
    ///
    /// `Get`: returns a cached token valid for at least
    /// [`github::cache::REFRESH_MARGIN`], else makes one: PAT/GitLab/Forgejo resolve the
    /// token reference ([`tokens`]); App resolves the private key, signs a JWT, looks up
    /// the installation for the target's owner (cached) and mints a token for the
    /// repository (`per = repo`, needs a path) or all repositories (`per = owner`) with
    /// the request's permissions. With `cache = false` the token cache is neither read
    /// nor written: every request resolves the secret again or mints a new token (the
    /// installation id is still cached). `Erase`: drops the cached token for the cache key.
    /// `Forget`: drops every cached token of the named sources (all with `None`), and
    /// keeps tokens being made at that moment out of the cache. Installation ids stay:
    /// they are public and need a JWT from the private key to be of use.
    ///
    /// Errors (as [`WorkerError`] via [`ForgeError`]): `Invalid` for an App request
    /// without path when `per = repo`; `NotFound` when the App is not installed for the
    /// owner; `Denied` when GitHub refuses the permissions (its message is passed on);
    /// errors from [`SecretProvider`] unchanged.
    pub async fn handle(&self, request: Request) -> Result<Response, WorkerError> {
        match request {
            Request::Get(request) => Ok(Response::Token(self.get(&request).await?)),
            Request::Erase(request) => {
                self.erase(&request);
                Ok(Response::Erased)
            }
            Request::Forget { sources } => {
                self.tokens
                    .forget(|key| sources.as_ref().is_none_or(|sources| sources.contains(&key.source)));
                Ok(Response::Forgotten)
            }
        }
    }

    /// Returns a token for `request`, from the cache or freshly made.
    async fn get(&self, request: &TokenRequest) -> Result<GitToken, ForgeError> {
        match &request.source {
            SourceSpec::GithubPat { token } => self.stored_token(request, token, GITHUB_USERNAME).await,
            SourceSpec::GitlabToken { token } => self.stored_token(request, token, GITLAB_USERNAME).await,
            SourceSpec::ForgejoToken { token } => self.stored_token(request, token, FORGEJO_USERNAME).await,
            SourceSpec::GithubApp { app_id, private_key, api_url } => {
                self.app_token(request, *app_id, private_key, api_url).await
            }
        }
    }

    /// Drops the cached token for `request`'s cache key. Never fails: a request that
    /// could not have produced a token has nothing cached.
    fn erase(&self, request: &TokenRequest) {
        match &request.source {
            SourceSpec::GithubApp { .. } => {
                let Ok(target) = AppTarget::parse(&request.target, request.per) else {
                    return;
                };
                // The installation id may have left its cache before the token did, so
                // match the key without it.
                self.tokens.remove_where(|key| {
                    key.source == request.source_name
                        && key.spec == request.source
                        && key.installation.is_some()
                        && key.scope == target.scope
                        && key.permissions == request.permissions
                });
            }
            SourceSpec::GithubPat { .. }
            | SourceSpec::GitlabToken { .. }
            | SourceSpec::ForgejoToken { .. } => {
                self.tokens.remove(&static_key(request));
            }
        }
    }

    /// A token stored in a vault, cached until `erase` or `Forget` (not at all with
    /// `cache = false`).
    async fn stored_token(
        &self,
        request: &TokenRequest,
        reference: &str,
        username: &str,
    ) -> Result<GitToken, ForgeError> {
        let key = static_key(request);
        if request.cache
            && let Some(token) = self.tokens.get(&key, self.clock.now())
        {
            return Ok(token);
        }
        let generation = self.tokens.generation();
        let secret = self.secrets.secret(reference).await?;
        let trimmed = secret.expose().trim();
        if trimmed.is_empty() {
            return Err(ForgeError::Invalid(format!("the token of source {} is empty", request.source_name)));
        }
        let secret = if trimmed.len() == secret.len() { secret } else { Secret::new(trimmed.to_owned()) };
        let token = tokens::static_token(username, secret);
        if request.cache {
            self.tokens.insert(key, token.clone(), self.clock.now(), generation);
        }
        Ok(token)
    }

    /// A minted GitHub App installation token, cached until shortly before it expires
    /// (not at all with `cache = false`).
    async fn app_token(
        &self,
        request: &TokenRequest,
        app_id: u64,
        private_key: &str,
        api_url: &str,
    ) -> Result<GitToken, ForgeError> {
        let target = AppTarget::parse(&request.target, request.per)?;
        let api = github::api_base(api_url)?;
        let installation_key =
            InstallationKey { api_url: api.to_owned(), app_id, owner: target.owner.to_ascii_lowercase() };
        let token_key = |installation: u64| TokenKey {
            source: request.source_name.clone(),
            spec: request.source.clone(),
            installation: Some(installation),
            scope: target.scope.clone(),
            permissions: request.permissions.clone(),
        };

        let now = self.clock.now();
        let cached_installation = self.installations.get(&installation_key, now);
        if request.cache
            && let Some(token) = cached_installation.and_then(|id| self.tokens.get(&token_key(id), now))
        {
            return Ok(token);
        }

        let generation = self.tokens.generation();
        let pem = self.secrets.secret(private_key).await?;
        let jwt = app_jwt(app_id, &pem, now)?;
        drop(pem);

        let installation = match cached_installation {
            Some(id) => id,
            None => self.lookup_installation(api, &jwt, &installation_key, &target.owner).await?,
        };
        if request.cache
            && cached_installation.is_none()
            && let Some(token) = self.tokens.get(&token_key(installation), now)
        {
            return Ok(token);
        }

        let repositories = target.repository.as_ref().map(std::slice::from_ref);
        let mint = |installation| {
            self.github.create_installation_token(api, &jwt, installation, repositories, &request.permissions)
        };
        let (installation, minted) = match mint(installation).await {
            // A cached installation id can be stale (App uninstalled and installed
            // again): look it up once more.
            Err(ForgeError::Api { status: 404, .. }) if cached_installation.is_some() => {
                self.installations.remove(&installation_key);
                let fresh = self.lookup_installation(api, &jwt, &installation_key, &target.owner).await?;
                (fresh, mint(fresh).await?)
            }
            result => (installation, result?),
        };

        let expires_at =
            minted.expires_at.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs();
        let token = GitToken {
            username: GITHUB_USERNAME.to_owned(),
            password: minted.token,
            expires_at: Some(expires_at),
        };
        if request.cache {
            self.tokens.insert(token_key(installation), token.clone(), self.clock.now(), generation);
        }
        Ok(token)
    }

    /// Looks up and caches the installation for `owner`.
    async fn lookup_installation(
        &self,
        api: &str,
        jwt: &Secret,
        key: &InstallationKey,
        owner: &str,
    ) -> Result<u64, ForgeError> {
        let id = self.github.installation_for_owner(api, jwt, key.app_id, owner).await?;
        self.installations.insert(key.clone(), id, self.clock.now());
        Ok(id)
    }
}

/// Cache key of a stored token: one per source and configuration of it.
fn static_key(request: &TokenRequest) -> TokenKey {
    TokenKey {
        source: request.source_name.clone(),
        spec: request.source.clone(),
        installation: None,
        scope: TokenScopeKey::Static,
        permissions: Permissions::new(),
    }
}

/// What an App token is minted for, from git's repository path.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AppTarget {
    /// The owner (organisation or user) as written in the path.
    owner: String,
    /// The repository name for `per = "repo"`, `None` for `per = "owner"`.
    repository: Option<String>,
    /// The token cache scope (lower case: GitHub names are case-insensitive).
    scope: TokenScopeKey,
}

impl AppTarget {
    /// Parses `owner/repo[.git]` (leading and trailing slashes ignored). `per = "repo"`
    /// needs exactly owner and repository; `per = "owner"` needs at least the owner.
    fn parse(target: &TokenTarget, per: TokenScope) -> Result<AppTarget, ForgeError> {
        let Some(path) = target.path.as_deref().filter(|path| !path.trim_matches('/').is_empty()) else {
            return Err(ForgeError::Invalid(format!(
                "a GitHub App token needs the repository path: set credential.useHttpPath for {} in git's configuration",
                target.host
            )));
        };
        let path = path.trim_matches('/');
        let path = path.strip_suffix(".git").unwrap_or(path);
        let segments: Vec<&str> = path.split('/').collect();
        let owner = segments[0];
        github::check_name("owner", owner)?;
        match per {
            TokenScope::Owner => Ok(AppTarget {
                owner: owner.to_owned(),
                repository: None,
                scope: TokenScopeKey::Owner(owner.to_ascii_lowercase()),
            }),
            TokenScope::Repo => {
                let [_, repository] = segments[..] else {
                    return Err(ForgeError::Invalid(format!(
                        "{} is not a GitHub repository path (owner/repository)",
                        target.path.as_deref().unwrap_or_default()
                    )));
                };
                github::check_name("repository", repository)?;
                Ok(AppTarget {
                    owner: owner.to_owned(),
                    repository: Some(repository.to_owned()),
                    scope: TokenScopeKey::Repo(format!("{owner}/{repository}").to_ascii_lowercase()),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use credential_bridge_proto::ipc::WorkerErrorKind;
    use credential_bridge_proto::ipc::git::Access;

    use super::*;
    use crate::github::app::test_key;
    use crate::github::cache::REFRESH_MARGIN;
    use crate::github::mock::{MockServer, Recorded, Reply};

    const KEY_REF: &str = "op://Dev/bridge-app/private-key";
    const APP_ID: u64 = 123_456;

    /// Secrets from a map; counts lookups.
    #[derive(Debug, Default)]
    struct FakeSecrets {
        values: HashMap<String, Result<String, WorkerError>>,
        calls: AtomicUsize,
    }

    impl FakeSecrets {
        fn with(mut self, reference: &str, value: Result<&str, WorkerError>) -> Self {
            self.values.insert(reference.to_owned(), value.map(str::to_owned));
            self
        }
    }

    impl SecretProvider for FakeSecrets {
        async fn secret(&self, reference: &str) -> Result<Secret, ForgeError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.values.get(reference) {
                Some(Ok(value)) => Ok(Secret::new(value.clone())),
                Some(Err(error)) => Err(ForgeError::Secret(error.clone())),
                None => Err(ForgeError::Secret(WorkerError::new(WorkerErrorKind::NotFound, "no such item"))),
            }
        }
    }

    /// A clock that only moves when told.
    #[derive(Debug, Clone)]
    struct FakeClock(Arc<Mutex<SystemTime>>);

    impl FakeClock {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(SystemTime::UNIX_EPOCH + Duration::from_secs(1_900_000_000))))
        }

        fn advance(&self, by: Duration) {
            *self.0.lock().unwrap() += by;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> SystemTime {
            *self.0.lock().unwrap()
        }
    }

    fn new_worker(secrets: FakeSecrets) -> (GitWorker<FakeSecrets, FakeClock>, FakeClock) {
        let clock = FakeClock::new();
        (GitWorker::new(secrets, clock.clone(), GithubClient::new().unwrap()), clock)
    }

    /// A worker whose GitHub client talks to `server` (API URL [`MockServer::API`]).
    fn mock_worker(
        secrets: FakeSecrets,
        server: &MockServer,
    ) -> (GitWorker<FakeSecrets, FakeClock>, FakeClock) {
        let clock = FakeClock::new();
        (GitWorker::new(secrets, clock.clone(), server.client()), clock)
    }

    fn app_secrets() -> FakeSecrets {
        FakeSecrets::default().with(KEY_REF, Ok(&test_key::pkcs1_pem()))
    }

    fn app_request(
        api: &str,
        path: Option<&str>,
        per: TokenScope,
        permissions: &[(&str, Access)],
    ) -> TokenRequest {
        TokenRequest {
            source_name: "my-org".into(),
            source: SourceSpec::GithubApp {
                app_id: APP_ID,
                private_key: KEY_REF.into(),
                api_url: api.into(),
            },
            target: TokenTarget {
                protocol: "https".into(),
                host: "github.com".into(),
                path: path.map(Into::into),
            },
            permissions: permissions.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect(),
            per,
            cache: true,
        }
    }

    fn stored_request(source: SourceSpec) -> TokenRequest {
        TokenRequest {
            source_name: "stored".into(),
            source,
            target: TokenTarget { protocol: "https".into(), host: "forge.example.com".into(), path: None },
            permissions: Permissions::new(),
            per: TokenScope::Repo,
            cache: true,
        }
    }

    /// Expiry one hour after the fake clock's start.
    const EXPIRES: &str = "2030-03-17T18:46:40Z";
    const EXPIRES_SECS: u64 = 1_900_000_000 + 3600;

    /// A GitHub where `my-org` is an organisation with installation 42 and each minted
    /// token is numbered.
    async fn github() -> MockServer {
        let counter = AtomicUsize::new(0);
        MockServer::start(move |request: &Recorded| {
            let (iss, ..) = test_key::verify(&request.bearer().expect("JWT"));
            assert_eq!(iss, APP_ID);
            match (request.method.as_str(), request.path.as_str()) {
                ("GET", "/orgs/my-org/installation") => Reply::json(200, r#"{"id":42}"#),
                ("GET", "/orgs/alice/installation") => Reply::json(404, r#"{"message":"Not Found"}"#),
                ("GET", "/users/alice/installation") => Reply::json(200, r#"{"id":7}"#),
                ("GET", _) => Reply::json(404, r#"{"message":"Not Found"}"#),
                ("POST", "/app/installations/42/access_tokens" | "/app/installations/7/access_tokens") => {
                    if request.json().get("permissions").and_then(|p| p.get("administration")).is_some() {
                        return Reply::json(
                            422,
                            r#"{"message":"The permissions requested are not granted to this installation."}"#,
                        );
                    }
                    let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    Reply::json(201, format!(r#"{{"token":"ghs_{n}","expires_at":"{EXPIRES}"}}"#))
                }
                _ => Reply::json(404, r#"{"message":"Not Found"}"#),
            }
        })
        .await
    }

    async fn get(
        worker: &GitWorker<FakeSecrets, FakeClock>,
        request: &TokenRequest,
    ) -> Result<GitToken, WorkerError> {
        match worker.handle(Request::Get(request.clone())).await? {
            Response::Token(token) => Ok(token),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn app_token_per_repo_is_minted_and_cached() {
        let server = github().await;
        let (worker, _) = mock_worker(app_secrets(), &server);
        let request = app_request(
            MockServer::API,
            Some("my-org/app.git"),
            TokenScope::Repo,
            &[("contents", Access::Write)],
        );

        let token = get(&worker, &request).await.unwrap();
        assert_eq!(token.username, "x-access-token");
        assert_eq!(token.password.expose(), "ghs_1");
        assert_eq!(token.expires_at, Some(EXPIRES_SECS));
        assert_eq!(
            server.paths(),
            ["GET /orgs/my-org/installation", "POST /app/installations/42/access_tokens"]
        );
        assert_eq!(
            server.requests()[1].json(),
            serde_json::json!({"repositories": ["app"], "permissions": {"contents": "write"}})
        );

        // From the cache: no request, no secret lookup.
        let again = get(&worker, &request).await.unwrap();
        assert_eq!(again.password.expose(), "ghs_1");
        assert_eq!(server.requests().len(), 2);
        assert_eq!(worker.secrets.calls.load(Ordering::SeqCst), 1);

        // Same repository in other spelling hits the same entry.
        let other_case = app_request(
            MockServer::API,
            Some("/My-Org/App/"),
            TokenScope::Repo,
            &[("contents", Access::Write)],
        );
        assert_eq!(get(&worker, &other_case).await.unwrap().password.expose(), "ghs_1");

        // Other rights or another repository: a new token, installation from the cache.
        let read = app_request(
            MockServer::API,
            Some("my-org/app.git"),
            TokenScope::Repo,
            &[("contents", Access::Read)],
        );
        assert_eq!(get(&worker, &read).await.unwrap().password.expose(), "ghs_2");
        let lib = app_request(
            MockServer::API,
            Some("my-org/lib"),
            TokenScope::Repo,
            &[("contents", Access::Write)],
        );
        assert_eq!(get(&worker, &lib).await.unwrap().password.expose(), "ghs_3");
        assert_eq!(server.paths().iter().filter(|p| p.starts_with("GET")).count(), 1);
    }

    #[tokio::test]
    async fn app_token_is_refreshed_shortly_before_expiry() {
        let server = github().await;
        let (worker, clock) = mock_worker(app_secrets(), &server);
        let request = app_request(MockServer::API, Some("my-org/app"), TokenScope::Repo, &[]);
        assert_eq!(get(&worker, &request).await.unwrap().password.expose(), "ghs_1");
        clock.advance(Duration::from_secs(3600) - REFRESH_MARGIN - Duration::from_secs(1));
        assert_eq!(get(&worker, &request).await.unwrap().password.expose(), "ghs_1");
        clock.advance(Duration::from_secs(2));
        assert_eq!(get(&worker, &request).await.unwrap().password.expose(), "ghs_2");
        // No permissions in the rule: GitHub's default (all of the installation's).
        assert_eq!(server.requests().last().unwrap().json(), serde_json::json!({"repositories": ["app"]}));
    }

    #[tokio::test]
    async fn app_token_per_owner_covers_all_repositories() {
        let server = github().await;
        let (worker, _) = mock_worker(app_secrets(), &server);
        let app = app_request(
            MockServer::API,
            Some("my-org/app.git"),
            TokenScope::Owner,
            &[("contents", Access::Read)],
        );
        let lib = app_request(
            MockServer::API,
            Some("my-org/lib.git"),
            TokenScope::Owner,
            &[("contents", Access::Read)],
        );
        assert_eq!(get(&worker, &app).await.unwrap().password.expose(), "ghs_1");
        assert_eq!(get(&worker, &lib).await.unwrap().password.expose(), "ghs_1");
        assert_eq!(server.requests()[1].json(), serde_json::json!({"permissions": {"contents": "read"}}));
        assert_eq!(server.requests().len(), 2);
    }

    #[tokio::test]
    async fn app_installation_of_a_user() {
        let server = github().await;
        let (worker, _) = mock_worker(app_secrets(), &server);
        let request = app_request(MockServer::API, Some("alice/dotfiles"), TokenScope::Repo, &[]);
        assert_eq!(get(&worker, &request).await.unwrap().password.expose(), "ghs_1");
        assert_eq!(
            server.paths(),
            [
                "GET /orgs/alice/installation",
                "GET /users/alice/installation",
                "POST /app/installations/7/access_tokens"
            ]
        );
    }

    #[tokio::test]
    async fn erase_drops_the_cached_token() {
        let server = github().await;
        let (worker, clock) = mock_worker(app_secrets(), &server);
        let request = app_request(
            MockServer::API,
            Some("my-org/app"),
            TokenScope::Repo,
            &[("contents", Access::Write)],
        );
        let other = app_request(
            MockServer::API,
            Some("my-org/lib"),
            TokenScope::Repo,
            &[("contents", Access::Write)],
        );
        assert_eq!(get(&worker, &request).await.unwrap().password.expose(), "ghs_1");
        assert_eq!(get(&worker, &other).await.unwrap().password.expose(), "ghs_2");

        assert_eq!(worker.handle(Request::Erase(request.clone())).await.unwrap(), Response::Erased);
        assert_eq!(get(&worker, &request).await.unwrap().password.expose(), "ghs_3");
        assert_eq!(get(&worker, &other).await.unwrap().password.expose(), "ghs_2");

        // Also after the installation id left its cache.
        worker.installations.remove(&InstallationKey {
            api_url: MockServer::API.into(),
            app_id: APP_ID,
            owner: "my-org".into(),
        });
        worker.handle(Request::Erase(other.clone())).await.unwrap();
        assert!(
            worker
                .tokens
                .get(
                    &TokenKey {
                        source: "my-org".into(),
                        spec: other.source.clone(),
                        installation: Some(42),
                        scope: TokenScopeKey::Repo("my-org/lib".into()),
                        permissions: other.permissions.clone(),
                    },
                    clock.now()
                )
                .is_none()
        );

        // Erasing something never fetched is fine.
        let missing = app_request(MockServer::API, None, TokenScope::Repo, &[]);
        assert_eq!(worker.handle(Request::Erase(missing)).await.unwrap(), Response::Erased);
    }

    #[tokio::test]
    async fn app_errors_from_github_are_passed_on() {
        let server = github().await;
        let (worker, _) = mock_worker(app_secrets(), &server);

        let too_much = app_request(
            MockServer::API,
            Some("my-org/app"),
            TokenScope::Repo,
            &[("administration", Access::Write)],
        );
        let error = get(&worker, &too_much).await.unwrap_err();
        assert_eq!(error.kind, WorkerErrorKind::Denied);
        assert!(
            error
                .message
                .ends_with("answered 422: The permissions requested are not granted to this installation."),
            "{}",
            error.message
        );

        let stranger = app_request(MockServer::API, Some("stranger/app"), TokenScope::Repo, &[]);
        let error = get(&worker, &stranger).await.unwrap_err();
        assert_eq!(error.kind, WorkerErrorKind::NotFound);
        assert_eq!(error.message, "GitHub App 123456 is not installed for stranger");
    }

    #[tokio::test]
    async fn stale_installation_is_looked_up_again() {
        let installation = Arc::new(AtomicUsize::new(42));
        let current = Arc::clone(&installation);
        let server = MockServer::start(move |request: &Recorded| {
            let id = current.load(Ordering::SeqCst);
            match (request.method.as_str(), request.path.as_str()) {
                ("GET", "/orgs/my-org/installation") => Reply::json(200, format!(r#"{{"id":{id}}}"#)),
                ("POST", path) if path == format!("/app/installations/{id}/access_tokens") => {
                    Reply::json(201, format!(r#"{{"token":"ghs_{id}","expires_at":"{EXPIRES}"}}"#))
                }
                _ => Reply::json(404, r#"{"message":"Not Found"}"#),
            }
        })
        .await;
        let (worker, _) = mock_worker(app_secrets(), &server);
        let app = app_request(MockServer::API, Some("my-org/app"), TokenScope::Repo, &[]);
        assert_eq!(get(&worker, &app).await.unwrap().password.expose(), "ghs_42");

        installation.store(43, Ordering::SeqCst);
        let lib = app_request(MockServer::API, Some("my-org/lib"), TokenScope::Repo, &[]);
        assert_eq!(get(&worker, &lib).await.unwrap().password.expose(), "ghs_43");
        assert_eq!(
            server.paths()[2..],
            [
                "POST /app/installations/42/access_tokens",
                "GET /orgs/my-org/installation",
                "POST /app/installations/43/access_tokens"
            ]
        );
    }

    #[tokio::test]
    async fn app_requests_need_a_usable_path() {
        let (worker, _) = new_worker(app_secrets());
        let api = MockServer::API;
        for (path, per) in [
            (None, TokenScope::Repo),
            (None, TokenScope::Owner),
            (Some("/"), TokenScope::Owner),
            (Some("my-org"), TokenScope::Repo),
            (Some("my-org/app/extra"), TokenScope::Repo),
            (Some("my-org/../x"), TokenScope::Repo),
            (Some("../app"), TokenScope::Owner),
        ] {
            let error = get(&worker, &app_request(api, path, per, &[])).await.unwrap_err();
            assert_eq!(error.kind, WorkerErrorKind::Invalid, "{path:?}");
        }
        let error = get(&worker, &app_request(api, None, TokenScope::Repo, &[])).await.unwrap_err();
        assert!(error.message.contains("credential.useHttpPath for github.com"), "{}", error.message);

        let plain_http = app_request("http://api.example.com", Some("my-org/app"), TokenScope::Repo, &[]);
        assert_eq!(get(&worker, &plain_http).await.unwrap_err().kind, WorkerErrorKind::Invalid);
        // Nothing was fetched for invalid requests.
        assert_eq!(worker.secrets.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn app_key_problems() {
        let locked = WorkerError::new(
            WorkerErrorKind::Locked,
            "vault bitwarden is locked: run credential-bridge-ctl vault unlock bitwarden",
        );
        let (worker, _) = new_worker(FakeSecrets::default().with(KEY_REF, Err(locked.clone())));
        let request = app_request(MockServer::API, Some("my-org/app"), TokenScope::Repo, &[]);
        assert_eq!(get(&worker, &request).await.unwrap_err(), locked);

        let (worker, _) = new_worker(FakeSecrets::default().with(KEY_REF, Ok("garbage")));
        assert_eq!(get(&worker, &request).await.unwrap_err().kind, WorkerErrorKind::Invalid);
    }

    #[tokio::test]
    async fn stored_tokens_use_the_forges_username() {
        let secrets = FakeSecrets::default()
            .with("op://pat", Ok("github_pat_x\n"))
            .with("bw://gitlab", Ok("glpat-x"))
            .with("pass://forgejo", Ok("fj-x"));
        let (worker, _) = new_worker(secrets);
        for (source, username, password) in [
            (SourceSpec::GithubPat { token: "op://pat".into() }, "x-access-token", "github_pat_x"),
            (SourceSpec::GitlabToken { token: "bw://gitlab".into() }, "oauth2", "glpat-x"),
            (SourceSpec::ForgejoToken { token: "pass://forgejo".into() }, "token", "fj-x"),
        ] {
            let mut request = stored_request(source);
            request.source_name = username.to_owned();
            let token = get(&worker, &request).await.unwrap();
            assert_eq!(
                (token.username.as_str(), token.password.expose(), token.expires_at),
                (username, password, None)
            );
        }
    }

    #[tokio::test]
    async fn stored_tokens_are_cached_until_erase() {
        let (worker, _) = new_worker(FakeSecrets::default().with("op://pat", Ok("tok")));
        let request = stored_request(SourceSpec::GithubPat { token: "op://pat".into() });
        get(&worker, &request).await.unwrap();
        get(&worker, &request).await.unwrap();
        assert_eq!(worker.secrets.calls.load(Ordering::SeqCst), 1);
        worker.handle(Request::Erase(request.clone())).await.unwrap();
        get(&worker, &request).await.unwrap();
        assert_eq!(worker.secrets.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn forget_drops_the_tokens_of_the_named_sources_or_all() {
        let server = github().await;
        let secrets = app_secrets().with("op://pat", Ok("pat")).with("bw://gitlab", Ok("glpat"));
        let (worker, _) = mock_worker(secrets, &server);
        let mut pat = stored_request(SourceSpec::GithubPat { token: "op://pat".into() });
        pat.source_name = "pat".into();
        let mut gitlab = stored_request(SourceSpec::GitlabToken { token: "bw://gitlab".into() });
        gitlab.source_name = "gitlab".into();
        let app = app_request(MockServer::API, Some("my-org/app"), TokenScope::Repo, &[]);
        let fetch_all = async || {
            let mut passwords = Vec::new();
            for request in [&pat, &gitlab, &app] {
                passwords.push(get(&worker, request).await.unwrap().password.expose().to_owned());
            }
            passwords
        };
        assert_eq!(fetch_all().await, ["pat", "glpat", "ghs_1"]);
        assert_eq!(worker.secrets.calls.load(Ordering::SeqCst), 3);

        // The sources of one vault: the others stay cached.
        let sources = Some(["pat".to_owned(), "my-org".to_owned()].into());
        assert_eq!(worker.handle(Request::Forget { sources }).await.unwrap(), Response::Forgotten);
        assert_eq!(fetch_all().await, ["pat", "glpat", "ghs_2"]);
        assert_eq!(worker.secrets.calls.load(Ordering::SeqCst), 5);
        // The installation id stays cached.
        assert_eq!(server.paths().iter().filter(|p| p.starts_with("GET")).count(), 1);

        // All of them.
        assert_eq!(worker.handle(Request::Forget { sources: None }).await.unwrap(), Response::Forgotten);
        assert_eq!(fetch_all().await, ["pat", "glpat", "ghs_3"]);
        assert_eq!(worker.secrets.calls.load(Ordering::SeqCst), 8);

        // Unknown sources and an empty cache are fine.
        let sources = Some(["nope".to_owned()].into());
        assert_eq!(worker.handle(Request::Forget { sources }).await.unwrap(), Response::Forgotten);
        let (empty, _) = new_worker(FakeSecrets::default());
        assert_eq!(empty.handle(Request::Forget { sources: None }).await.unwrap(), Response::Forgotten);
    }

    #[tokio::test]
    async fn without_cache_every_request_resolves_or_mints_again() {
        let server = github().await;
        let secrets = app_secrets().with("op://pat", Ok("pat")).with("bw://gitlab", Ok("glpat"));
        let (worker, clock) = mock_worker(secrets, &server);
        let mut pat = stored_request(SourceSpec::GithubPat { token: "op://pat".into() });
        pat.cache = false;
        let mut gitlab = stored_request(SourceSpec::GitlabToken { token: "bw://gitlab".into() });
        gitlab.cache = false;
        let mut app = app_request(MockServer::API, Some("my-org/app"), TokenScope::Repo, &[]);
        app.cache = false;

        for round in 1..=2 {
            assert_eq!(get(&worker, &pat).await.unwrap().password.expose(), "pat");
            assert_eq!(get(&worker, &gitlab).await.unwrap().password.expose(), "glpat");
            let token = get(&worker, &app).await.unwrap();
            assert_eq!(token.password.expose(), format!("ghs_{round}"));
            assert_eq!(token.expires_at, Some(EXPIRES_SECS));
            assert_eq!(worker.secrets.calls.load(Ordering::SeqCst), 3 * round);
        }
        // Nothing went into the token cache; the installation id is still cached.
        assert!(worker.tokens.get(&static_key(&pat), clock.now()).is_none());
        assert!(worker.tokens.get(&static_key(&gitlab), clock.now()).is_none());
        let app_key = TokenKey {
            source: app.source_name.clone(),
            spec: app.source.clone(),
            installation: Some(42),
            scope: TokenScopeKey::Repo("my-org/app".into()),
            permissions: app.permissions.clone(),
        };
        assert!(worker.tokens.get(&app_key, clock.now()).is_none());
        assert_eq!(server.paths().iter().filter(|p| p.starts_with("GET")).count(), 1);

        // A token cached while the source still had cache = true is not handed out.
        app.cache = true;
        assert_eq!(get(&worker, &app).await.unwrap().password.expose(), "ghs_3");
        assert_eq!(get(&worker, &app).await.unwrap().password.expose(), "ghs_3");
        app.cache = false;
        assert_eq!(get(&worker, &app).await.unwrap().password.expose(), "ghs_4");
    }

    #[tokio::test]
    async fn changed_source_configuration_misses_the_cache() {
        let secrets =
            FakeSecrets::default().with("op://old", Ok("old-token")).with("op://new", Ok("new-token"));
        let (worker, _) = new_worker(secrets);
        let old = stored_request(SourceSpec::GithubPat { token: "op://old".into() });
        assert_eq!(get(&worker, &old).await.unwrap().password.expose(), "old-token");
        // Same source name after a reload with another reference.
        let new = stored_request(SourceSpec::GithubPat { token: "op://new".into() });
        assert_eq!(new.source_name, old.source_name);
        assert_eq!(get(&worker, &new).await.unwrap().password.expose(), "new-token");
    }

    #[tokio::test]
    async fn stored_token_errors() {
        let locked = WorkerError::new(
            WorkerErrorKind::Locked,
            "vault bitwarden is locked: run credential-bridge-ctl vault unlock bitwarden",
        );
        let secrets =
            FakeSecrets::default().with("bw://locked", Err(locked.clone())).with("op://empty", Ok(" \n"));
        let (worker, _) = new_worker(secrets);
        let request = stored_request(SourceSpec::GitlabToken { token: "bw://locked".into() });
        assert_eq!(get(&worker, &request).await.unwrap_err(), locked);
        let request = stored_request(SourceSpec::ForgejoToken { token: "op://empty".into() });
        assert_eq!(get(&worker, &request).await.unwrap_err().kind, WorkerErrorKind::Invalid);
        // Failures are not cached.
        assert!(worker.tokens.get(&static_key(&request), SystemTime::now()).is_none());
    }
}
