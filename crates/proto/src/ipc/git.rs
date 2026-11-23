//! Messages of the git worker: tokens for GitHub (PAT, App), GitLab and Forgejo.
//!
//! The core has already matched the rule and checked policy; the worker only makes or
//! drops tokens. Sources `gh` and `helper` never reach this worker: they run in the vault
//! worker ([`super::vault::Request::GhCredential`], [`super::vault::Request::HelperCredential`]).
//! Secrets named by references are fetched through [`super::Callback::Secret`].

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::secret::Secret;

/// The repository a token is for, from git's credential request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenTarget {
    /// `https` (other protocols never get tokens).
    pub protocol: String,
    /// Host, with `:port` if git sent one.
    pub host: String,
    /// Repository path, e.g. `my-org/app.git`; `None` without `useHttpPath`.
    pub path: Option<String>,
}

/// Access level of one permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    /// `read`
    Read,
    /// `write` (includes read)
    Write,
    /// `admin` (includes write)
    Admin,
}

impl Access {
    /// The name as written in the configuration: `read`, `write` or `admin`.
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Read => "read",
            Access::Write => "write",
            Access::Admin => "admin",
        }
    }
}

impl std::fmt::Display for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Access {
    type Err = ParseNameError;

    fn from_str(text: &str) -> Result<Access, ParseNameError> {
        [Access::Read, Access::Write, Access::Admin]
            .into_iter()
            .find(|access| access.as_str() == text)
            .ok_or_else(|| ParseNameError { text: text.to_owned(), expected: "read, write or admin" })
    }
}

/// A name that [`Access`] or [`TokenScope`] does not know.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{text:?} is not {expected}")]
pub struct ParseNameError {
    /// The text given.
    pub text: String,
    /// The names that are accepted, e.g. `read, write or admin`.
    pub expected: &'static str,
}

/// GitHub App permissions, e.g. `{ contents = "write" }`. Keys are GitHub's permission
/// names (`contents`, `pull_requests`, `metadata`, …), passed to GitHub unchanged.
pub type Permissions = BTreeMap<String, Access>;

/// How many repositories one minted token covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenScope {
    /// One token per repository (default).
    #[default]
    Repo,
    /// One token for all repositories of the installation (only for `owner/*` rules).
    Owner,
}

impl TokenScope {
    /// The name as written in the configuration (`per = …`): `repo` or `owner`.
    pub fn as_str(self) -> &'static str {
        match self {
            TokenScope::Repo => "repo",
            TokenScope::Owner => "owner",
        }
    }
}

impl std::fmt::Display for TokenScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TokenScope {
    type Err = ParseNameError;

    fn from_str(text: &str) -> Result<TokenScope, ParseNameError> {
        [TokenScope::Repo, TokenScope::Owner]
            .into_iter()
            .find(|scope| scope.as_str() == text)
            .ok_or_else(|| ParseNameError { text: text.to_owned(), expected: "repo or owner" })
    }
}

/// The resolved source of a rule, with everything the worker needs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceSpec {
    /// GitHub fine-grained PAT from a vault. Username `x-access-token`.
    GithubPat {
        /// Secret reference of the token.
        token: String,
    },
    /// GitHub App: JWT from the private key, installation looked up by owner, token
    /// minted per request with `permissions` and `per`.
    GithubApp {
        /// The App ID.
        app_id: u64,
        /// Secret reference of the PEM private key.
        private_key: String,
        /// REST API base URL, `https://api.github.com` for github.com; configurable for
        /// GitHub Enterprise and tests.
        api_url: String,
    },
    /// GitLab personal, project or group token. Username `oauth2`.
    GitlabToken {
        /// Secret reference of the token.
        token: String,
    },
    /// Forgejo / Gitea token. Username `token`.
    ForgejoToken {
        /// Secret reference of the token.
        token: String,
    },
}

/// One token request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRequest {
    /// Name of the `[source.*]` table, part of every cache key.
    pub source_name: String,
    /// The source.
    pub source: SourceSpec,
    /// The repository.
    pub target: TokenTarget,
    /// Rights for a minted token (App only; ignored otherwise). Already checked against
    /// the source's `max_permissions` by the configuration.
    pub permissions: Permissions,
    /// Token scope for a minted token (App only).
    pub per: TokenScope,
    /// The source's `cache`: `false` keeps the token out of the worker's cache, so every
    /// request resolves the secret again (PAT, GitLab, Forgejo) or mints a new token
    /// (App).
    pub cache: bool,
}

/// Core to git worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Return a token, from cache or freshly made.
    Get(TokenRequest),
    /// Drop cached tokens for this request's cache key (`git credential erase`).
    Erase(TokenRequest),
    /// Drop every cached token of these sources, or all with `None`: sent by the core
    /// when a vault is locked (the sources whose secrets live in it), on `vault lock
    /// --all`, on the proxy lock (`ssh-add -x`) and after a reload (the sources it
    /// removed or changed). Never fails.
    Forget {
        /// `[source.*]` names, or `None` for all.
        sources: Option<BTreeSet<String>>,
    },
}

/// A token for git.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitToken {
    /// Username to hand to git.
    pub username: String,
    /// The token.
    pub password: Secret,
    /// Expiry in seconds since the epoch, if known (git's `password_expiry_utc`).
    pub expires_at: Option<u64>,
}

/// Git worker to core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    /// Answer to [`Request::Get`].
    Token(GitToken),
    /// Answer to [`Request::Erase`].
    Erased,
    /// Answer to [`Request::Forget`].
    Forgotten,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names match the serde names, so the configuration and the wire agree.
    #[test]
    fn names_round_trip_and_match_serde() {
        for access in [Access::Read, Access::Write, Access::Admin] {
            assert_eq!(access.as_str().parse::<Access>().unwrap(), access);
            assert_eq!(serde_json::to_string(&access).unwrap(), format!("\"{access}\""));
        }
        for scope in [TokenScope::Repo, TokenScope::Owner] {
            assert_eq!(scope.as_str().parse::<TokenScope>().unwrap(), scope);
            assert_eq!(serde_json::to_string(&scope).unwrap(), format!("\"{scope}\""));
        }
        assert_eq!(
            "Write".parse::<Access>().unwrap_err().to_string(),
            "\"Write\" is not read, write or admin"
        );
        assert_eq!("all".parse::<TokenScope>().unwrap_err().to_string(), "\"all\" is not repo or owner");
    }
}
