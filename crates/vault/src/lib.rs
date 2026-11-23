//! The vault worker's logic: resolves [`SecretRef`]s, keeps unlock sessions, and runs the
//! `gh` and `helper` git sources.
//!
//! This is the only worker that starts external programs (`op`, `bw`, `keepassxc-cli`,
//! `pass`/`gopass`, `gh`, git credential helpers, `sh -c` for `cmd:`); it is not
//! sandboxed because sandboxes are inherited by children. Every program runs through a
//! [`runner::CommandRunner`] so tests use fakes. Native vaults (macOS Keychain via
//! `security-framework`, Secret Service via D-Bus with feature `secret-service`) need no
//! program.
//!
//! The daemon's `worker vault` main loop decodes [`ipc::vault::Request`] frames and calls
//! [`VaultWorker::handle`] for each of them concurrently. No request waits for another
//! request's program: the unlock sessions sit behind a short lock that is never held
//! while a program runs (see [`Vaults`]).
//!
//! [`SecretRef`]: credential_bridge_config::SecretRef
//! [`ipc::vault::Request`]: credential_bridge_proto::ipc::vault::Request

mod error;
pub mod git_sources;
pub mod runner;
pub mod session;
mod tool;
mod vaults;

pub use error::VaultError;
pub use vaults::{Clock, DEFAULT_SESSION_TTL, STORE_DEADLINE, SystemClock, Vaults};

use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use credential_bridge_config::{SecretRef, VaultKind};
use credential_bridge_proto::ipc::WorkerError;
use credential_bridge_proto::ipc::vault::{CredentialAction, Request, Response};

use crate::runner::CommandRunner;

/// Request handling of the vault worker.
#[derive(Debug)]
pub struct VaultWorker<R: CommandRunner, C: Clock> {
    /// The vaults and their sessions.
    pub vaults: Vaults<R, C>,
}

impl<R: CommandRunner, C: Clock> VaultWorker<R, C> {
    /// A worker without open sessions.
    pub fn new(vaults: Vaults<R, C>) -> Self {
        Self { vaults }
    }

    /// Handles one request; requests may run concurrently. Errors carry user-safe
    /// messages (see [`VaultError`]). `Resolve` and `Store` parse the reference with
    /// `credential_bridge_config::SecretRef::from_str`; an unparsable reference is
    /// `WorkerErrorKind::Invalid`. Drops expired sessions first.
    pub async fn handle(&self, request: Request) -> Result<Response, WorkerError> {
        self.vaults.purge_expired();
        let response = match request {
            Request::Unlock { vault, password, ttl_secs } => {
                let vault = parse_vault(&vault)?;
                let end = self.vaults.unlock(vault, password, ttl_secs.map(Duration::from_secs)).await?;
                Response::Unlocked { expires_at: epoch_secs(end) }
            }
            Request::Lock { vault } => {
                let vault = vault.as_deref().map(parse_vault).transpose()?;
                self.vaults.lock(vault);
                Response::Locked
            }
            Request::Resolve { reference } => {
                Response::Secret(self.vaults.resolve(&parse_reference(&reference)?).await?)
            }
            Request::Store { reference, value } => {
                self.vaults.store(&parse_reference(&reference)?, &value).await?;
                Response::Stored
            }
            Request::Status => Response::Status(self.vaults.status().await),
            Request::GhCredential { target, action } => {
                let token = git_sources::gh_credential(&self.vaults.runner, &target, action).await?;
                credential_response(token, action)
            }
            Request::HelperCredential { helper, target, action } => {
                let token =
                    git_sources::helper_credential(&self.vaults.runner, &helper, &target, action).await?;
                credential_response(token, action)
            }
        };
        Ok(response)
    }

    /// Whether the worker must stay alive although idle (an unlock session is open).
    pub fn keep_alive(&self) -> bool {
        self.vaults.any_session_open()
    }
}

/// Parses a reference; the error names the reference, which is not secret.
fn parse_reference(reference: &str) -> Result<SecretRef, VaultError> {
    SecretRef::from_str(reference).map_err(|error| VaultError::Invalid(error.to_string()))
}

/// Parses a vault name as `ctl vault unlock` takes it.
fn parse_vault(name: &str) -> Result<VaultKind, VaultError> {
    VaultKind::from_str(name).map_err(|_| VaultError::Invalid(format!("unknown vault {name:?}")))
}

/// Seconds since the epoch (0 before it).
fn epoch_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map(|since| since.as_secs()).unwrap_or(0)
}

/// The answer to a `gh`/`helper` request: the token for `get`, `Erased` for `erase`.
fn credential_response(
    token: Option<credential_bridge_proto::ipc::git::GitToken>,
    action: CredentialAction,
) -> Response {
    match action {
        CredentialAction::Get => Response::Credential(token),
        CredentialAction::Erase => Response::Erased,
    }
}

#[cfg(test)]
mod tests {
    use credential_bridge_proto::ipc::WorkerErrorKind;
    use credential_bridge_proto::ipc::git::TokenTarget;
    use credential_bridge_proto::secret::Secret;

    use super::*;
    use crate::vaults::tests::{FakeBin, FakeClock};

    fn worker(bin: &FakeBin) -> VaultWorker<runner::SystemRunner, FakeClock> {
        VaultWorker::new(bin.vaults())
    }

    #[tokio::test]
    async fn resolves_and_refuses_by_reference_string() {
        let bin = FakeBin::new();
        let worker = worker(&bin);
        let response = worker.handle(Request::Resolve { reference: "cmd:printf tok".into() }).await.unwrap();
        assert_eq!(response, Response::Secret(Secret::new("tok".into())));

        let error = worker.handle(Request::Resolve { reference: "nope://x".into() }).await.unwrap_err();
        assert_eq!(error.kind, WorkerErrorKind::Invalid);

        let store = Request::Store { reference: "cmd:printf tok".into(), value: Secret::new("v".into()) };
        assert_eq!(worker.handle(store).await.unwrap_err().kind, WorkerErrorKind::Denied);

        let error =
            worker.handle(Request::Resolve { reference: "bw://app/password".into() }).await.unwrap_err();
        assert_eq!(error.kind, WorkerErrorKind::Locked);
        assert_eq!(
            error.message,
            "vault bitwarden is locked: run credential-bridge-ctl vault unlock bitwarden"
        );
    }

    #[tokio::test]
    async fn unlock_keeps_the_worker_alive_until_expiry_or_lock() {
        let bin = FakeBin::new();
        bin.script("bw", "printf session-key");
        let worker = worker(&bin);
        assert!(!worker.keep_alive());
        let unlock =
            |ttl| Request::Unlock { vault: "bw".into(), password: Secret::new("pw".into()), ttl_secs: ttl };
        let response = worker.handle(unlock(Some(30))).await.unwrap();
        assert_eq!(response, Response::Unlocked { expires_at: 1_000_030 });
        assert!(worker.keep_alive());
        worker.vaults.clock.advance(Duration::from_secs(31));
        assert!(!worker.keep_alive());

        worker.handle(unlock(None)).await.unwrap();
        assert!(worker.keep_alive());
        assert_eq!(worker.handle(Request::Lock { vault: None }).await.unwrap(), Response::Locked);
        assert!(!worker.keep_alive());

        let error = worker.handle(Request::Lock { vault: Some("nope".into()) }).await.unwrap_err();
        assert_eq!(error.kind, WorkerErrorKind::Invalid);
    }

    #[tokio::test]
    async fn gh_and_helper_sources_run_from_path() {
        let bin = FakeBin::new();
        bin.script(
            "gh",
            r#"[ "$*" = "auth git-credential get" ] || exit 9
grep -q '^host=github.com$' || exit 0
printf 'username=octo\npassword=gho_token\n'"#,
        );
        bin.script(
            "git-credential-fake",
            r#"[ "$1" = get ] && printf 'username=u\npassword=helper-token\n'"#,
        );
        let worker = worker(&bin);
        let target = TokenTarget { protocol: "https".into(), host: "github.com".into(), path: None };

        let gh = Request::GhCredential { target: target.clone(), action: CredentialAction::Get };
        let Response::Credential(Some(token)) = worker.handle(gh).await.unwrap() else { panic!("no token") };
        assert_eq!((token.username.as_str(), token.password.expose()), ("octo", "gho_token"));

        let helper = format!("{}/git-credential-fake", bin.path().display());
        let request = Request::HelperCredential {
            helper: helper.clone(),
            target: target.clone(),
            action: CredentialAction::Get,
        };
        let Response::Credential(Some(token)) = worker.handle(request).await.unwrap() else {
            panic!("no token")
        };
        assert_eq!(token.password.expose(), "helper-token");

        let erase = Request::HelperCredential { helper, target, action: CredentialAction::Erase };
        assert_eq!(worker.handle(erase).await.unwrap(), Response::Erased);
    }

    #[tokio::test]
    async fn status_lists_every_vault() {
        let bin = FakeBin::new();
        let worker = worker(&bin);
        let Response::Status(status) = worker.handle(Request::Status).await.unwrap() else {
            panic!("no status")
        };
        let names: Vec<&str> = status.iter().map(|s| s.vault.as_str()).collect();
        assert_eq!(names, VaultKind::ALL.map(VaultKind::name));
    }
}
