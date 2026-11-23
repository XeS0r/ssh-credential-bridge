//! Handling of `query`, `git-credential@credential-bridge` and
//! `gpg-agent@credential-bridge` on `agent-forward.sock`.

use std::collections::BTreeSet;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use credential_bridge_config::{Config, GitRule, GitTarget, Source, SourceKind, VaultKind};
use credential_bridge_proto::credential::Credential;
use credential_bridge_proto::ext::{GitAction, GitReply, GitRequest, GpgReply, GpgRequest};
use credential_bridge_proto::ipc::git::{self, GitToken, SourceSpec, TokenRequest, TokenTarget};
use credential_bridge_proto::ipc::vault::{self, CredentialAction};
use credential_bridge_proto::ipc::{WorkerError, WorkerErrorKind, gpg};

use credential_bridge_proto::secret::SecretBytes;

use crate::audit::AuditEvent;
use crate::core::Core;
use crate::policy::{Decision, RequestContext, allows_git, allows_gpg};
use crate::supervisor::WorkerGeneration;

/// The names answered to `query` on `agent-forward.sock`.
pub const SUPPORTED: &[&str] = &[
    credential_bridge_proto::ext::QUERY,
    credential_bridge_proto::ext::SESSION_BIND,
    credential_bridge_proto::ext::GIT_CREDENTIAL,
    credential_bridge_proto::ext::GPG_AGENT,
];

/// What resolving a rule gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenOutcome {
    /// A token.
    Token(GitToken),
    /// The source had none (`gh` not logged in for the host, helper without answer).
    NoToken,
    /// `erase` was processed.
    Erased,
    /// The proxy was locked (`ssh-add -x`) while the token was made: it is not handed
    /// out, and not cached.
    Locked,
}

/// How long a lock waits for the git worker to drop its tokens before it answers.
const FORGET_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolves `rule` for `target` with its source: the git worker for PAT, App, GitLab
/// and Forgejo; the vault worker for `gh` and `helper`. Shared by the extension and
/// `ctl server token`.
///
/// `forgets` is [`Core::forget_count`] as the caller read it before it checked the
/// lock. A token made while the proxy was locked is refused ([`TokenOutcome::Locked`]);
/// one made while tokens were dropped (a lock, a reload that changed the source) is
/// dropped from the git worker's cache, as that Forget may have missed it.
///
/// Errors: the worker's error (user-safe), `Unavailable` if the worker is missing.
pub async fn resolve_token(
    core: &Core,
    source: &Source,
    rule: &GitRule,
    target: &GitTarget,
    action: GitAction,
    forgets: u64,
) -> Result<TokenOutcome, WorkerError> {
    let token_target = TokenTarget {
        protocol: target.protocol.clone(),
        host: target.host.clone(),
        path: target.path.clone(),
    };
    let spec = match &source.kind {
        SourceKind::GithubGh { .. } | SourceKind::Helper { .. } => {
            // gh and local helpers keep no token of ours: an `erase` from a server must
            // never reach them, or it would delete the local machine's stored credentials.
            if action == GitAction::Erase {
                return Ok(TokenOutcome::Erased);
            }
            let vault = core.workers.vault.as_ref().ok_or_else(|| unavailable("vault"))?;
            let action = CredentialAction::Get;
            let request = match &source.kind {
                SourceKind::Helper { helper } => {
                    vault::Request::HelperCredential { helper: helper.clone(), target: token_target, action }
                }
                _ => vault::Request::GhCredential { target: token_target, action },
            };
            return match vault.request(request).await? {
                // Nothing of it is cached in the bridge; only the lock counts.
                vault::Response::Credential(Some(_)) if core.lock.is_locked() => Ok(TokenOutcome::Locked),
                vault::Response::Credential(Some(token)) => Ok(TokenOutcome::Token(token)),
                vault::Response::Credential(None) => Ok(TokenOutcome::NoToken),
                vault::Response::Erased => Ok(TokenOutcome::Erased),
                _ => Err(WorkerError::new(
                    WorkerErrorKind::Internal,
                    "unexpected answer from the vault worker",
                )),
            };
        }
        SourceKind::GithubPat { token, .. } => SourceSpec::GithubPat { token: token.to_string() },
        SourceKind::GitlabToken { token, .. } => SourceSpec::GitlabToken { token: token.to_string() },
        SourceKind::ForgejoToken { token, .. } => SourceSpec::ForgejoToken { token: token.to_string() },
        SourceKind::GithubApp { api_url, app_id, private_key, .. } => SourceSpec::GithubApp {
            app_id: *app_id,
            private_key: private_key.to_string(),
            api_url: api_url.clone(),
        },
    };
    let request = TokenRequest {
        source_name: source.name.clone(),
        source: spec,
        target: token_target,
        permissions: rule.permissions.clone(),
        per: rule.per,
        cache: source.cache,
    };
    let worker = core.workers.git.as_ref().ok_or_else(|| unavailable("git"))?;
    let request = match action {
        GitAction::Get => git::Request::Get(request),
        GitAction::Erase => git::Request::Erase(request),
    };
    let token = match worker.request(request).await? {
        git::Response::Token(token) => token,
        git::Response::Erased => return Ok(TokenOutcome::Erased),
        git::Response::Forgotten => {
            return Err(WorkerError::new(WorkerErrorKind::Internal, "unexpected answer from the git worker"));
        }
    };
    let check = TokenCheck {
        locked: core.lock.is_locked(),
        forgets_before: forgets,
        forgets_now: core.forget_count(),
        // A reload removed or changed the source while the token was being made.
        source_changed: core.config().sources.get(&source.name) != Some(source),
    };
    let after = check.after();
    if after != AfterToken::Hand {
        let sources = BTreeSet::from([source.name.clone()]);
        forget(core, Some(sources), &format!("the source {}, made during a lock or reload", source.name))
            .await;
    }
    Ok(match after {
        AfterToken::ForgetAndRefuse => TokenOutcome::Locked,
        AfterToken::Hand | AfterToken::ForgetAndHand => TokenOutcome::Token(token),
    })
}

/// What happened while the git worker made a token.
#[derive(Debug, Clone, Copy)]
struct TokenCheck {
    /// Whether the proxy is locked now.
    locked: bool,
    /// [`Core::forget_count`] before the request's lock check.
    forgets_before: u64,
    /// [`Core::forget_count`] now.
    forgets_now: u64,
    /// Whether the current configuration defines the source differently.
    source_changed: bool,
}

/// What to do with a token the git worker made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AfterToken {
    /// Hand it out.
    Hand,
    /// Drop it from the worker's cache, then hand it out.
    ForgetAndHand,
    /// Drop it from the worker's cache and refuse the request.
    ForgetAndRefuse,
}

impl TokenCheck {
    /// The worker keeps a token out of its cache if a Forget arrived while it was made.
    /// A Forget can still miss it: one that reached the worker before this request did,
    /// one lost because the worker was being started (it is never started for a
    /// Forget), one for the old configuration of a reloaded source. Any Forget since
    /// the lock check, or a changed source, drops the token once more; a lock also
    /// refuses it (`ssh-add -x` wins over a request in flight, as for a signature).
    fn after(self) -> AfterToken {
        if self.locked {
            AfterToken::ForgetAndRefuse
        } else if self.forgets_now != self.forgets_before || self.source_changed {
            AfterToken::ForgetAndHand
        } else {
            AfterToken::Hand
        }
    }
}

/// Drops the tokens the git worker has cached from `vault`: those of every source whose
/// secret reference (token or App private key) points into it in the current
/// configuration. `None` drops every cached token (`vault lock --all`, `ssh-add -x`).
/// `gh` and `helper` sources cache nothing in the bridge.
///
/// A git worker that does not run has nothing cached and is not started. Failures are
/// logged only: the lock itself has already happened. The lock answers after at most
/// [`FORGET_TIMEOUT`]; a request whose token is cached later sees the raised
/// [`Core::forget_count`] and drops it ([`resolve_token`]).
pub async fn forget_tokens(core: &Core, vault: Option<VaultKind>) {
    if core.workers.git.is_none() {
        return;
    }
    let sources = match vault {
        None => None,
        Some(vault) => {
            let sources = sources_in_vault(&core.snapshot().config, vault);
            if sources.is_empty() {
                return;
            }
            Some(sources)
        }
    };
    let what = match vault {
        Some(vault) => format!("the sources in vault {vault}"),
        None => "all sources".to_owned(),
    };
    if tokio::time::timeout(FORGET_TIMEOUT, forget(core, sources, &what)).await.is_err() {
        tracing::warn!("cannot drop cached tokens of {what}: the git worker did not answer in time");
    }
}

/// Drops the tokens the git worker has cached for `sources`, which a reload removed or
/// changed ([`crate::core::stale_token_sources`]). Called after the new configuration is
/// in place; a request that still used the old one is covered by [`resolve_token`].
/// Like [`forget_tokens`], it never starts the git worker and only logs failures.
pub async fn forget_stale_tokens(core: &Core, sources: BTreeSet<String>) {
    if sources.is_empty() {
        return;
    }
    let what = format!(
        "the removed or changed sources {}",
        sources.iter().map(String::as_str).collect::<Vec<_>>().join(", ")
    );
    forget(core, Some(sources), &what).await;
}

/// Sends [`git::Request::Forget`] to the git worker if it runs; `what` names the sources
/// in the log. Raises [`Core::forget_count`] first, also if the worker does not run:
/// it may be starting for a request whose token this Forget then cannot reach.
async fn forget(core: &Core, sources: Option<BTreeSet<String>>, what: &str) {
    let Some(worker) = &core.workers.git else { return };
    core.note_forget();
    match worker.request_running(git::Request::Forget { sources }).await {
        Ok(Some(git::Response::Forgotten)) => tracing::info!("dropped cached tokens of {what}"),
        Ok(None) => {}
        Ok(Some(_)) => {
            tracing::warn!("cannot drop cached tokens of {what}: unexpected answer from the git worker");
        }
        Err(error) => tracing::warn!("cannot drop cached tokens of {what}: {}", error.message),
    }
}

/// The names of the sources with a secret reference into `vault`.
fn sources_in_vault(config: &Config, vault: VaultKind) -> BTreeSet<String> {
    config
        .sources
        .iter()
        .filter(|(_, source)| source.kind.secret_refs().iter().any(|reference| reference.vault() == vault))
        .map(|(name, _)| name.clone())
        .collect()
}

/// The error for a worker that is not available.
fn unavailable(kind: &str) -> WorkerError {
    WorkerError::new(WorkerErrorKind::Unavailable, format!("the {kind} worker is not available"))
}

/// Whether a configuration names `reference` as a secret of one of its sources. Only
/// such references are resolved for the git worker.
pub fn is_configured_secret(config: &Config, reference: &str) -> bool {
    config
        .sources
        .values()
        .flat_map(|source| source.kind.secret_refs())
        .any(|known| known.to_string() == reference)
}

/// Serves one git credential request: checks [`crate::policy::allows_git`], matches the
/// profile's rules, then asks the git worker (PAT, App, GitLab, Forgejo) or the vault
/// worker (`gh`, `helper`). Audits the outcome (server, host, path, rule, source; never
/// the token).
pub async fn git_credential(core: &Core, ctx: &RequestContext<'_>, request: GitRequest) -> GitReply {
    let target = GitTarget::parse_credential(&request.credential);
    // A rejected request is audited without the raw (server-supplied) path.
    let target_text = match &target {
        Ok(target) => match &target.path {
            Some(path) => format!("{}://{}/{path}", target.protocol, target.host),
            None => format!("{}://{}", target.protocol, target.host),
        },
        Err(_) => "(invalid request)".to_owned(),
    };
    let audit = |rule: Option<&GitRule>, outcome: String| {
        core.audit.record(&AuditEvent::Git {
            server: ctx.server_label(),
            target: target_text.clone(),
            rule: rule.map(|rule| rule.url.as_str().to_owned()),
            outcome,
        });
    };
    if let Decision::Refuse(reason) = allows_git(ctx) {
        audit(None, format!("denied: {reason}"));
        return GitReply::Denied(reason.to_owned());
    }
    let target = match target {
        Ok(target) => target,
        Err(error) => {
            audit(None, format!("denied: {}", error.reason));
            return GitReply::Denied(format!("invalid request: {}", error.reason));
        }
    };
    let Some(profile) = ctx.profile else { return GitReply::NoMatch };
    let Some(rule) = profile.git_rule_for(&target) else {
        audit(None, "no matching rule".to_owned());
        return GitReply::NoMatch;
    };
    let Some(source) = ctx.config.sources.get(&rule.source) else {
        audit(Some(rule), "failed: unknown source".to_owned());
        return GitReply::Failed(format!("source {} is not configured", rule.source));
    };
    match resolve_token(core, source, rule, &target, request.action, ctx.forgets).await {
        Ok(TokenOutcome::Token(token)) => {
            audit(Some(rule), format!("token from source {}", source.name));
            GitReply::Credential(Credential {
                username: Some(token.username),
                password: Some(token.password),
                password_expiry_utc: token.expires_at,
                ..Credential::default()
            })
        }
        Ok(TokenOutcome::NoToken) => {
            audit(Some(rule), format!("source {} had no token", source.name));
            GitReply::NoMatch
        }
        Ok(TokenOutcome::Erased) => {
            audit(Some(rule), "erased".to_owned());
            GitReply::Erased
        }
        Ok(TokenOutcome::Locked) => {
            let reason = "proxy is locked";
            audit(Some(rule), format!("denied: {reason}"));
            GitReply::Denied(reason.to_owned())
        }
        Err(error) => {
            tracing::info!("git credential for {target_text} failed: {}", error.message);
            audit(Some(rule), format!("failed: {}", error.message));
            GitReply::Failed(error.message)
        }
    }
}

/// Tunnel ids for the gpg worker, unique for the daemon's lifetime.
static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

/// The gpg tunnel of one agent connection (at most one).
#[derive(Debug, Default)]
pub struct GpgTunnel {
    /// While open: the gpg worker's connection id and the worker process that holds it.
    /// After that process is gone, nothing more is sent for the tunnel (and no worker is
    /// started for it).
    conn: Option<(credential_bridge_proto::ipc::gpg::ConnId, WorkerGeneration)>,
}

impl GpgTunnel {
    /// Whether the tunnel is open.
    pub fn is_open(&self) -> bool {
        self.conn.is_some()
    }

    /// A tunnel that counts as open, without a gpg worker behind it.
    #[cfg(test)]
    pub(crate) fn opened_for_test() -> GpgTunnel {
        GpgTunnel { conn: Some((1, WorkerGeneration::for_test())) }
    }

    /// Serves one gpg request: `Open` checks [`crate::policy::allows_gpg`], connects to
    /// the gpg-agent extra socket and hands the descriptor to the gpg worker; `Input` and
    /// `Close` are relayed. The tunnel is closed when the agent connection ends.
    pub async fn handle(&mut self, core: &Core, ctx: &RequestContext<'_>, request: GpgRequest) -> GpgReply {
        let server = ctx.server_label();
        let audit = |command: &str, outcome: &'static str| {
            core.audit.record(&AuditEvent::Gpg {
                server: server.clone(),
                command: command.to_owned(),
                outcome,
            });
        };
        let Some(worker) = core.workers.gpg.as_ref() else {
            return GpgReply::Failed("credential-bridge: gpg is not available".to_owned());
        };
        match request {
            GpgRequest::Open => {
                if let Decision::Refuse(reason) = allows_gpg(ctx) {
                    core.audit.record(&AuditEvent::Refused { server: server.clone(), reason });
                    return GpgReply::Failed(format!("credential-bridge: {reason}"));
                }
                if self.is_open() {
                    return GpgReply::Failed("credential-bridge: the gpg tunnel is already open".to_owned());
                }
                let fd = match connect_gpg_agent(core).await {
                    Ok(fd) => fd,
                    Err(message) => {
                        tracing::warn!("gpg: {message}");
                        return GpgReply::Failed(format!("credential-bridge: {message}"));
                    }
                };
                let conn = NEXT_CONN.fetch_add(1, Ordering::Relaxed);
                let policy = ctx.profile.map(|profile| profile.gpg).unwrap_or_default();
                match worker.request_with_fd_tracked(gpg::Request::Open { conn, policy }, fd).await {
                    Ok((gpg::Response::Opened(greeting), generation)) => {
                        self.conn = Some((conn, generation));
                        worker.hold();
                        audit("open", "allowed");
                        GpgReply::Opened(greeting.into_zeroizing())
                    }
                    Ok(_) => GpgReply::Failed(
                        "credential-bridge: unexpected answer from the gpg worker".to_owned(),
                    ),
                    Err(error) => GpgReply::Failed(error.message),
                }
            }
            GpgRequest::Input(data) => {
                let Some((conn, generation)) = self.conn else {
                    return GpgReply::Failed("credential-bridge: the gpg tunnel is not open".to_owned());
                };
                match worker
                    .request_if_running(
                        generation,
                        gpg::Request::Input { conn, data: SecretBytes::from_zeroizing(data) },
                    )
                    .await
                {
                    Ok(gpg::Response::Output { data, command, denied }) => {
                        if let Some(verb) = command {
                            audit(&verb, if denied { "denied" } else { "allowed" });
                        }
                        GpgReply::Output(data.into_zeroizing())
                    }
                    Ok(_) => GpgReply::Failed(
                        "credential-bridge: unexpected answer from the gpg worker".to_owned(),
                    ),
                    Err(error) => {
                        // The worker dropped the tunnel, or it is in an unknown state.
                        self.close(core).await;
                        GpgReply::Failed(error.message)
                    }
                }
            }
            GpgRequest::Close => {
                self.close(core).await;
                GpgReply::Closed
            }
        }
    }

    /// Closes the tunnel if it is open (end of the agent connection, or `Close`). `Close`
    /// goes only to the worker process that opened the tunnel: after a crash or restart
    /// the tunnel is already gone, and no worker is started just to close it.
    pub async fn close(&mut self, core: &Core) {
        let Some((conn, generation)) = self.conn.take() else { return };
        if let Some(worker) = core.workers.gpg.as_ref() {
            worker.release();
            if let Err(error) = worker.request_if_running(generation, gpg::Request::Close { conn }).await {
                tracing::debug!("closing gpg tunnel {conn}: {}", error.message);
            }
        }
    }
}

/// Connects to the gpg-agent extra socket of the current configuration.
async fn connect_gpg_agent(core: &Core) -> Result<OwnedFd, String> {
    let socket = core.snapshot().gpg_socket.clone().ok_or("the gpg-agent socket is not configured")?;
    let stream = tokio::time::timeout(Duration::from_secs(5), tokio::net::UnixStream::connect(&socket))
        .await
        .map_err(|_| "connecting to gpg-agent timed out".to_owned())?
        .map_err(|error| format!("cannot connect to gpg-agent at {}: {error}", socket.display()))?;
    let stream = stream.into_std().map_err(|error| format!("gpg-agent connection: {error}"))?;
    Ok(OwnedFd::from(stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A token is handed out as made only if nothing was forgotten since the request's
    /// lock check and its source is unchanged; a lock refuses it, and every case but the
    /// first drops it from the cache again.
    #[test]
    fn tokens_after_a_forget_are_dropped_and_after_a_lock_refused() {
        let check = |locked, forgets_now, source_changed| {
            TokenCheck { locked, forgets_before: 3, forgets_now, source_changed }.after()
        };
        assert_eq!(check(false, 3, false), AfterToken::Hand);
        // A Forget began meanwhile (vault lock, reload): it may have missed the token.
        assert_eq!(check(false, 4, false), AfterToken::ForgetAndHand);
        // A reload changed the source, its Forget not counted yet.
        assert_eq!(check(false, 3, true), AfterToken::ForgetAndHand);
        // ssh-add -x: also before its Forget is counted, and after it.
        assert_eq!(check(true, 3, false), AfterToken::ForgetAndRefuse);
        assert_eq!(check(true, 4, true), AfterToken::ForgetAndRefuse);
    }
}
