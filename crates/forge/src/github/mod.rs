//! GitHub: App JWTs, installation lookup, token minting, the manifest flow.
//!
//! Every call takes the REST API base URL (`https://api.github.com`, or
//! `https://<host>/api/v3` for GitHub Enterprise Server). Errors from GitHub are passed
//! on with their HTTP status and GitHub's `message` field, so git on the server and the
//! log show why GitHub refused a request.

pub mod app;
pub mod cache;
pub mod manifest;
mod timestamp;

use std::time::{Duration, SystemTime};

use credential_bridge_proto::ipc::git::Permissions;
use credential_bridge_proto::secret::Secret;
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::ForgeError;

/// REST API base URL of github.com.
pub const GITHUB_API: &str = "https://api.github.com";

/// `User-Agent` sent with every request (GitHub requires one).
pub const USER_AGENT: &str = concat!("credential-bridge/", env!("CARGO_PKG_VERSION"));

/// The REST API version requested with `X-GitHub-Api-Version`.
const API_VERSION: &str = "2022-11-28";

/// Time allowed to establish a connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Time allowed for a whole request; git waits for the answer.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Responses larger than this are not read (GitHub's answers here are a few KiB).
const MAX_RESPONSE_LEN: usize = 1024 * 1024;

/// GitHub's `message` is cut to this many characters before it is passed on.
const MAX_MESSAGE_LEN: usize = 300;

/// A minted installation token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationToken {
    /// The token.
    pub token: Secret,
    /// `expires_at` from GitHub.
    pub expires_at: SystemTime,
}

/// A GitHub REST client (HTTPS via rustls). The API base URL is passed per call and
/// checked with [`credential_bridge_proto::api_url::check`].
///
/// The HTTP client is built on first use, so a machine without a usable CA store only
/// fails requests that go to the API; tokens from vaults (PAT, GitLab, Forgejo) still
/// work.
#[derive(Debug, Clone, Default)]
pub struct GithubClient {
    /// The HTTP client, once built.
    http: std::sync::OnceLock<reqwest::Client>,
    /// Tests: send every request to this plain-HTTP mock server instead of the (checked)
    /// API base URL.
    #[cfg(test)]
    mock: Option<String>,
}

impl GithubClient {
    /// A client with [`USER_AGENT`] and timeouts suited to a request git waits for.
    /// Redirects are not followed, so the JWT is never sent anywhere else.
    ///
    /// Errors: none today; a TLS backend that cannot be initialised (no CA
    /// certificates) shows up as [`ForgeError::Network`] on the first request.
    pub fn new() -> Result<GithubClient, ForgeError> {
        Ok(GithubClient::default())
    }

    /// A client whose requests go to the mock server at `base` (`http://127.0.0.1:…`);
    /// API URLs are still checked as in production.
    #[cfg(test)]
    pub(crate) fn with_mock(base: String) -> GithubClient {
        GithubClient { mock: Some(base), ..GithubClient::default() }
    }

    /// The URL of `path` (starting with `/`) under the checked API base `api`.
    fn endpoint(&self, api: &str, path: &str) -> String {
        #[cfg(test)]
        if let Some(mock) = &self.mock {
            return format!("{mock}{path}");
        }
        format!("{api}{path}")
    }

    /// The HTTP client, built on the first call.
    ///
    /// Errors: [`ForgeError::Network`] if the TLS backend cannot be initialised.
    fn http(&self) -> Result<&reqwest::Client, ForgeError> {
        if let Some(http) = self.http.get() {
            return Ok(http);
        }
        let http = Self::build_http()?;
        Ok(self.http.get_or_init(|| http))
    }

    fn build_http() -> Result<reqwest::Client, ForgeError> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/vnd.github+json"));
        headers.insert("X-GitHub-Api-Version", HeaderValue::from_static(API_VERSION));
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .default_headers(headers)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| ForgeError::Network {
                api: "GitHub API".to_owned(),
                message: format!("cannot set up the HTTP client: {}", error_chain(&error)),
            })?;
        Ok(http)
    }

    /// The installation id of App (authenticated by `jwt`) for `owner`:
    /// `GET /orgs/{owner}/installation`, then `GET /users/{owner}/installation`.
    ///
    /// Errors: [`ForgeError::NotInstalled`] if both answer 404; others as they come.
    pub async fn installation_for_owner(
        &self,
        api_url: &str,
        jwt: &Secret,
        app_id: u64,
        owner: &str,
    ) -> Result<u64, ForgeError> {
        #[derive(Deserialize)]
        struct Installation {
            id: u64,
        }

        let api = api_base(api_url)?;
        check_name("owner", owner)?;
        for kind in ["orgs", "users"] {
            let url = self.endpoint(api, &format!("/{kind}/{owner}/installation"));
            let response = self.send(api, self.http()?.get(url).bearer_auth(jwt.expose())).await?;
            match response.status {
                200 => return Ok(response.json::<Installation>(api)?.id),
                404 => continue,
                _ => return Err(response.error(api)),
            }
        }
        Err(ForgeError::NotInstalled { app_id, owner: owner.to_owned() })
    }

    /// `POST /app/installations/{id}/access_tokens` with `repositories` (names without
    /// owner; `None` for all repositories of the installation) and `permissions` (empty:
    /// all permissions of the installation).
    ///
    /// Errors: [`ForgeError::Api`] with GitHub's message (e.g. permissions the
    /// installation does not have, 422).
    pub async fn create_installation_token(
        &self,
        api_url: &str,
        jwt: &Secret,
        installation_id: u64,
        repositories: Option<&[String]>,
        permissions: &Permissions,
    ) -> Result<InstallationToken, ForgeError> {
        #[derive(Deserialize)]
        struct AccessToken {
            token: Secret,
            expires_at: String,
        }

        let api = api_base(api_url)?;
        for repository in repositories.unwrap_or_default() {
            check_name("repository", repository)?;
        }
        let mut body = serde_json::Map::new();
        if let Some(repositories) = repositories {
            body.insert("repositories".to_owned(), serde_json::json!(repositories));
        }
        if !permissions.is_empty() {
            body.insert("permissions".to_owned(), serde_json::json!(permissions));
        }

        let url = self.endpoint(api, &format!("/app/installations/{installation_id}/access_tokens"));
        let request = self.http()?.post(url).bearer_auth(jwt.expose()).json(&body);
        let response = self.send(api, request).await?;
        if response.status != 201 {
            return Err(response.error(api));
        }
        let minted: AccessToken = response.json(api)?;
        let expires_at = timestamp::parse_rfc3339(&minted.expires_at)
            .ok_or_else(|| response.unexpected(api, "invalid expires_at"))?;
        Ok(InstallationToken { token: minted.token, expires_at })
    }

    /// Sends a request and reads the whole response (bounded by [`MAX_RESPONSE_LEN`]).
    async fn send(&self, api: &str, request: reqwest::RequestBuilder) -> Result<RawResponse, ForgeError> {
        let network = |error: reqwest::Error| ForgeError::Network {
            api: api.to_owned(),
            message: error_chain(&error.without_url()),
        };
        let mut response = request.send().await.map_err(network)?;
        let status = response.status().as_u16();
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(network)? {
            if body.len() + chunk.len() > MAX_RESPONSE_LEN {
                return Err(ForgeError::Api {
                    api: api.to_owned(),
                    status,
                    message: "response too large".to_owned(),
                });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(RawResponse { status, body })
    }
}

/// A complete HTTP response. The body is overwritten on drop, as it may hold a token or
/// a private key.
struct RawResponse {
    status: u16,
    body: Zeroizing<Vec<u8>>,
}

impl RawResponse {
    /// Decodes the JSON body.
    fn json<T: for<'de> Deserialize<'de>>(&self, api: &str) -> Result<T, ForgeError> {
        serde_json::from_slice(&self.body).map_err(|_| self.unexpected(api, "unexpected response body"))
    }

    /// An error for a response that has the right status but cannot be used.
    fn unexpected(&self, api: &str, what: &str) -> ForgeError {
        ForgeError::Api { api: api.to_owned(), status: self.status, message: what.to_owned() }
    }

    /// The error for an unexpected status, with GitHub's `message`.
    fn error(&self, api: &str) -> ForgeError {
        #[derive(Deserialize)]
        struct ErrorBody {
            message: Option<String>,
        }

        let message = serde_json::from_slice::<ErrorBody>(&self.body)
            .ok()
            .and_then(|body| body.message)
            .map(|message| sanitize(&message))
            .filter(|message| !message.is_empty())
            .or_else(|| {
                reqwest::StatusCode::from_u16(self.status)
                    .ok()
                    .and_then(|status| status.canonical_reason())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "no message".to_owned());
        ForgeError::Api { api: api.to_owned(), status: self.status, message }
    }
}

/// Checks an API base URL with [`credential_bridge_proto::api_url::check`] (the check
/// config validation uses, too: `https` on port 443, the only port the git worker's
/// sandbox allows) and strips trailing slashes.
pub(crate) fn api_base(api_url: &str) -> Result<&str, ForgeError> {
    let base = api_url.trim_end_matches('/');
    credential_bridge_proto::api_url::check(base)
        .map_err(|why| ForgeError::Invalid(format!("API URL {api_url}: {why}")))?;
    Ok(base)
}

/// Checks that `name` is a single GitHub path segment (owner, repository, manifest code)
/// before it is put into an API path.
pub(crate) fn check_name(what: &str, name: &str) -> Result<(), ForgeError> {
    let valid = !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= 100
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if valid { Ok(()) } else { Err(ForgeError::Invalid(format!("invalid GitHub {what} name: {name:?}"))) }
}

/// Makes a message from GitHub safe to show on one line: control characters become
/// spaces and the length is bounded.
fn sanitize(message: &str) -> String {
    let mut clean: String =
        message.chars().map(|c| if c.is_control() { ' ' } else { c }).take(MAX_MESSAGE_LEN).collect();
    if message.chars().count() > MAX_MESSAGE_LEN {
        clean.push('…');
    }
    clean.trim().to_owned()
}

/// An error and its sources as one line.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(inner) = source {
        let text = inner.to_string();
        if !message.contains(&text) {
            message.push_str(": ");
            message.push_str(&text);
        }
        source = inner.source();
    }
    message
}

#[cfg(test)]
pub(crate) mod mock;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::mock::{MockServer, Reply};

    fn jwt() -> Secret {
        Secret::new("header.claims.signature".to_owned())
    }

    #[test]
    fn api_urls_must_use_https_on_port_443() {
        assert_eq!(api_base("https://api.github.com/").unwrap(), "https://api.github.com");
        assert_eq!(api_base("https://ghe.example.com/api/v3").unwrap(), "https://ghe.example.com/api/v3");
        assert!(api_base("https://ghe.example.com:443/api/v3").is_ok());
        // The same answers as config validation for inputs a hand-written check got
        // wrong.
        for good in ["HTTPS://h.com", "https://h.com:", "https://h.com:0443"] {
            assert!(api_base(good).is_ok(), "{good}");
        }
        let Err(ForgeError::Invalid(why)) = api_base("https://ghe.example.com:8443") else { panic!() };
        assert!(why.contains("port 443"), "{why}");
        for bad in [
            "https://ghe.example.com:8443/api/v3",
            "https://127.0.0.1:8443",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
            "http://localhost:8080",
            "http://api.github.com",
            "https://h.com.",
            "https://[1::2::3]",
            "https://999.1.1.1",
            "ftp://api.github.com",
            "https://user:pw@api.github.com",
            "https://api.github.com?x=1",
            "not a url",
        ] {
            assert!(matches!(api_base(bad), Err(ForgeError::Invalid(_))), "{bad}");
        }
    }

    #[test]
    fn names_are_single_segments() {
        for good in ["my-org", "app.rs", "repo_name", "A1"] {
            assert!(check_name("x", good).is_ok(), "{good}");
        }
        for bad in ["", ".", "..", "a/b", "a?b", "a%2fb", "a b", "ä"] {
            assert!(check_name("x", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn messages_are_sanitized() {
        assert_eq!(sanitize("bad\ncredentials\r"), "bad credentials");
        let long = "x".repeat(MAX_MESSAGE_LEN + 10);
        assert_eq!(sanitize(&long).chars().count(), MAX_MESSAGE_LEN + 1);
    }

    #[tokio::test]
    async fn installation_falls_back_to_users() {
        let server = MockServer::start(|request| match request.path.as_str() {
            "/orgs/alice/installation" => Reply::json(404, r#"{"message":"Not Found"}"#),
            "/users/alice/installation" => Reply::json(200, r#"{"id":77,"account":{"login":"alice"}}"#),
            _ => Reply::json(500, "{}"),
        })
        .await;
        let client = server.client();
        let id = client.installation_for_owner(MockServer::API, &jwt(), 1, "alice").await.unwrap();
        assert_eq!(id, 77);
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].header("authorization").as_deref(), Some("Bearer header.claims.signature"));
        assert_eq!(requests[0].header("accept").as_deref(), Some("application/vnd.github+json"));
        assert_eq!(requests[0].header("x-github-api-version").as_deref(), Some(API_VERSION));
        assert_eq!(requests[0].header("user-agent").as_deref(), Some(USER_AGENT));
    }

    #[tokio::test]
    async fn missing_installation_is_reported() {
        let server = MockServer::start(|_| Reply::json(404, r#"{"message":"Not Found"}"#)).await;
        let client = server.client();
        let error = client.installation_for_owner(MockServer::API, &jwt(), 9, "nobody").await.unwrap_err();
        assert_eq!(error, ForgeError::NotInstalled { app_id: 9, owner: "nobody".into() });
    }

    #[tokio::test]
    async fn api_errors_carry_githubs_message() {
        let server =
            MockServer::start(|_| Reply::json(401, r#"{"message":"A JSON web token could not be decoded"}"#))
                .await;
        let client = server.client();
        let error = client.installation_for_owner(MockServer::API, &jwt(), 1, "o").await.unwrap_err();
        assert_eq!(
            error,
            ForgeError::Api {
                api: MockServer::API.into(),
                status: 401,
                message: "A JSON web token could not be decoded".into()
            }
        );

        let server = MockServer::start(|_| Reply::json(502, "<html>bad gateway</html>")).await;
        let client = server.client();
        let error = client.installation_for_owner(MockServer::API, &jwt(), 1, "o").await.unwrap_err();
        assert_eq!(
            error,
            ForgeError::Api { api: MockServer::API.into(), status: 502, message: "Bad Gateway".into() }
        );
    }

    #[tokio::test]
    async fn minting_sends_repositories_and_permissions() {
        let server = MockServer::start(|_| {
            Reply::json(201, r#"{"token":"ghs_minted","expires_at":"2030-01-01T00:00:00Z","permissions":{}}"#)
        })
        .await;
        let client = server.client();
        let permissions =
            Permissions::from([("contents".to_owned(), credential_bridge_proto::ipc::git::Access::Write)]);
        let repositories = ["app".to_owned()];
        let token = client
            .create_installation_token(MockServer::API, &jwt(), 42, Some(&repositories), &permissions)
            .await
            .unwrap();
        assert_eq!(token.token.expose(), "ghs_minted");
        assert_eq!(token.expires_at, timestamp::parse_rfc3339("2030-01-01T00:00:00Z").unwrap());

        let requests = server.requests();
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].path, "/app/installations/42/access_tokens");
        assert_eq!(
            requests[0].json(),
            serde_json::json!({"repositories": ["app"], "permissions": {"contents": "write"}})
        );

        // All repositories, all permissions of the installation: an empty object.
        client
            .create_installation_token(MockServer::API, &jwt(), 42, None, &Permissions::new())
            .await
            .unwrap();
        assert_eq!(server.requests()[1].json(), serde_json::json!({}));
    }

    #[tokio::test]
    async fn network_errors_name_the_api() {
        let server = MockServer::start(|_| Reply::json(200, "{}")).await;
        let client = server.client();
        drop(server);
        let error = client.installation_for_owner(MockServer::API, &jwt(), 1, "o").await.unwrap_err();
        assert!(matches!(&error, ForgeError::Network { api, .. } if api == MockServer::API), "{error:?}");
    }
}
