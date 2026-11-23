//! Sources whose token is a stored secret: GitHub PAT, GitLab, Forgejo/Gitea.
//!
//! git sends a username and a password over HTTPS basic auth; the token is the password.
//! The username each forge expects with a token:
//!
//! - **GitHub** ignores the username for tokens; `x-access-token` is the name GitHub
//!   documents for installation tokens and works for PATs too, so both App and PAT
//!   sources use it.
//! - **GitLab** accepts any non-empty username with a personal, project or group access
//!   token; `oauth2` is the name it documents for OAuth tokens and is accepted for the
//!   others as well.
//! - **Forgejo / Gitea** take an access token as the password with any username (the
//!   token decides the user); `token` is a neutral placeholder.

use credential_bridge_proto::ipc::git::GitToken;
use credential_bridge_proto::secret::Secret;

/// Username git sends with a GitHub token.
pub const GITHUB_USERNAME: &str = "x-access-token";
/// Username git sends with a GitLab token.
pub const GITLAB_USERNAME: &str = "oauth2";
/// Username git sends with a Forgejo / Gitea token.
pub const FORGEJO_USERNAME: &str = "token";

/// Wraps a stored token with the username the forge expects; no expiry is known.
pub fn static_token(username: &str, token: Secret) -> GitToken {
    GitToken { username: username.to_owned(), password: token, expires_at: None }
}
