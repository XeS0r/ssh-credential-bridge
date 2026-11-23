//! `control.sock`: requests from `credential-bridge-ctl`.

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use credential_bridge_config::{GitTarget, SourceKind, VaultKind};
use credential_bridge_proto::ext::GitAction;
use credential_bridge_proto::ipc::control::{
    DaemonPaths, DaemonStatus, KeyInfo, Request, Response, SourceCheck, TokenTestResult, UpstreamStatus,
};
use credential_bridge_proto::ipc::git::TokenTarget;
use credential_bridge_proto::ipc::vault::VaultStatus;
use credential_bridge_proto::ipc::{IpcError, WorkerError, WorkerErrorKind, decode_body, vault};
use tokio::io::AsyncRead;
use tokio::net::UnixStream;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};
use zeroize::Zeroizing;

use crate::bind::Replay;
use crate::core::{Core, Resolved};
use crate::extensions::{TokenOutcome, forget_tokens, resolve_token};
use crate::frame::{IpcReader, write_ipc};
use crate::upstream::{UpstreamError, UpstreamSet, UpstreamTarget};

/// Serves one control connection: one request per frame, answered in order, until the
/// client closes it or `stop` turns true (or its sender is gone). A frame that does not
/// decode ends the connection with an error. A stop ends the wait for the next request
/// at once; a request that has begun to arrive is read, handled and answered first.
pub async fn serve(core: Arc<Core>, mut stream: UnixStream, mut stop: watch::Receiver<bool>) {
    let (reader, mut writer) = stream.split();
    let mut reader = IpcReader::new(reader);
    loop {
        let body = match next_request(&mut reader, &mut stop).await {
            Ok(Some(body)) => body,
            Ok(None) => return,
            Err(error) => {
                tracing::debug!("control connection: {error}");
                return;
            }
        };
        let response = match decode_body::<Request>(&body) {
            Ok(request) => handle(&core, request).await,
            Err(error) => {
                let response =
                    error_response(WorkerErrorKind::Invalid, format!("bad control request: {error}"));
                let _ = write_ipc(&mut writer, &response).await;
                return;
            }
        };
        drop(body);
        if write_ipc(&mut writer, &response).await.is_err() {
            return;
        }
    }
}

/// The next request body, or `Ok(None)` at the end of the stream or when `stop` turns
/// true between requests. [`IpcReader::next_body`] is cancel-safe, so a stop that comes
/// while a frame is arriving loses nothing: that frame is then read to its end.
async fn next_request<R: AsyncRead + Unpin>(
    reader: &mut IpcReader<R>,
    stop: &mut watch::Receiver<bool>,
) -> Result<Option<Zeroizing<Vec<u8>>>, IpcError> {
    tokio::select! {
        biased;
        body = reader.next_body() => return body,
        _ = stop.wait_for(|stop| *stop) => {}
    }
    if reader.between_frames() { Ok(None) } else { reader.next_body().await }
}

/// An error response.
fn error_response(kind: WorkerErrorKind, message: impl Into<String>) -> Response {
    Response::Error(WorkerError::new(kind, message))
}

/// Serves one control request. Responses never contain secrets: `TokenTest` describes
/// the token without it, `SourceTest` says only whether each secret resolved; `Unlock`
/// and `StoreSecret` pass their secrets on to the vault worker only.
pub async fn handle(core: &Core, request: Request) -> Response {
    match request {
        Request::Ping => {
            Response::Pong { version: env!("CARGO_PKG_VERSION").to_owned(), paths: daemon_paths(core) }
        }
        Request::Status => Response::Status(status(core).await),
        Request::Reload => reload(core).await,
        Request::Keys { server } => keys(core, server.as_deref()).await,
        Request::TokenTest { server, url } => token_test(core, &server, &url).await,
        Request::Unlock { vault: name, password, ttl_secs } => {
            match vault_request(core, vault::Request::Unlock { vault: name, password, ttl_secs }).await {
                Ok(vault::Response::Unlocked { expires_at }) => {
                    if let Some(handle) = &core.workers.vault {
                        handle.extend_keep_alive(UNIX_EPOCH + Duration::from_secs(expires_at));
                    }
                    Response::Unlocked { expires_at }
                }
                Ok(_) => unexpected(),
                Err(error) => Response::Error(error),
            }
        }
        Request::Lock { vault: name } => {
            // An unknown name is refused by the vault worker (if it runs).
            let forget = match name.as_deref().map(str::parse::<VaultKind>) {
                None => Some(None),
                Some(Ok(vault)) => Some(Some(vault)),
                Some(Err(_)) => None,
            };
            let response = lock_vaults(core, name).await;
            // Tokens cached from the vault go too, even if the vault worker failed.
            if let Some(vault) = forget {
                forget_tokens(core, vault).await;
            }
            response
        }
        Request::StoreSecret { reference, value } => {
            match vault_request(core, vault::Request::Store { reference, value }).await {
                Ok(vault::Response::Stored) => Response::Stored,
                Ok(_) => unexpected(),
                Err(error) => Response::Error(error),
            }
        }
        Request::SourceTest { source } => source_test(core, &source).await,
    }
}

/// Ends the unlock session of the vault `name`, or of all with `None`.
async fn lock_vaults(core: &Core, name: Option<String>) -> Response {
    let Some(handle) = &core.workers.vault else { return Response::Locked };
    // Nothing is unlocked in a worker that does not run.
    if !handle.is_running() {
        return Response::Locked;
    }
    let all = name.is_none();
    match handle.request(vault::Request::Lock { vault: name }).await {
        Ok(vault::Response::Locked) => {
            if all {
                handle.keep_alive_until(None);
            }
            Response::Locked
        }
        Ok(_) => unexpected(),
        Err(error) => Response::Error(error),
    }
}

/// An answer that does not fit the request.
fn unexpected() -> Response {
    Response::Error(unexpected_error())
}

/// Sends a request to the vault worker.
async fn vault_request(core: &Core, request: vault::Request) -> Result<vault::Response, WorkerError> {
    let handle =
        core.workers.vault.as_ref().ok_or_else(|| {
            WorkerError::new(WorkerErrorKind::Unavailable, "the vault worker is not available")
        })?;
    handle.request(request).await
}

/// Re-reads the configuration.
async fn reload(core: &Core) -> Response {
    // `reload` is blocking but short; the control connection waits for it anyway.
    let multi_thread =
        tokio::runtime::Handle::current().runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread;
    let result = if multi_thread { tokio::task::block_in_place(|| core.reload()) } else { core.reload() };
    match result {
        Ok(stale) => {
            crate::extensions::forget_stale_tokens(core, stale).await;
            Response::Reloaded
        }
        Err(error) => error_response(WorkerErrorKind::Invalid, error.to_string()),
    }
}

/// How long `status` may take as a whole: clearly under ctl's 10 s `CONTROL_TIMEOUT`,
/// so `ctl check` always gets an answer. Upstreams and the vault worker that do not
/// answer in time are reported as such.
const STATUS_DEADLINE: Duration = Duration::from_secs(7);

/// Daemon, upstream, worker and vault state.
async fn status(core: &Core) -> DaemonStatus {
    status_within(core, STATUS_DEADLINE).await
}

/// [`status`] with the deadline `limit`: the upstreams (concurrently) and the vault
/// worker are asked at the same time, each bounded by it.
async fn status_within(core: &Core, limit: Duration) -> DaemonStatus {
    let deadline = Instant::now() + limit;
    let snapshot = core.snapshot();
    let (upstreams, vaults) = tokio::join!(
        upstream_statuses(&snapshot.upstreams, deadline),
        vault_statuses(core, &snapshot, deadline)
    );
    DaemonStatus {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        pid: std::process::id(),
        config: core.config_path.display().to_string(),
        paths: daemon_paths(core),
        locked: core.lock.is_locked(),
        upstreams,
        workers: core.workers.statuses(),
        vaults,
    }
}

/// The sockets, the audit log and the KeePassXC files the daemon uses since it started.
fn daemon_paths(core: &Core) -> DaemonPaths {
    let daemon = &core.started;
    let keepassxc = &core.started_vault.keepassxc;
    let text = |path: &Option<std::path::PathBuf>| path.as_ref().map(|path| path.display().to_string());
    DaemonPaths {
        socket: daemon.socket.display().to_string(),
        forward_socket: daemon.forward_socket.display().to_string(),
        control_socket: daemon.control_socket.display().to_string(),
        audit_log: daemon.audit_log.display().to_string(),
        keepassxc_database: text(&keepassxc.database),
        keepassxc_key_file: text(&keepassxc.key_file),
    }
}

/// Lists the identities of every upstream concurrently (the quick identity-list path);
/// an upstream that fails or does not answer by `deadline` is unreachable, with
/// [`upstream_error`] as the reason (also logged).
async fn upstream_statuses(targets: &[UpstreamTarget], deadline: Instant) -> Vec<UpstreamStatus> {
    let mut statuses: Vec<UpstreamStatus> = targets
        .iter()
        .map(|target| UpstreamStatus {
            name: target.name.clone(),
            socket: target.socket.display().to_string(),
            reachable: false,
            keys: None,
            error: Some(TIMEOUT.to_owned()),
        })
        .collect();
    let mut tasks = JoinSet::new();
    for (index, target) in targets.iter().enumerate() {
        let target = target.clone();
        tasks.spawn(async move {
            let name = target.name.clone();
            let mut set = UpstreamSet::new(vec![target]);
            let result = match timeout_at(deadline, set.identities_of(0, &[])).await {
                Ok(Ok(keys)) => Ok(keys.len()),
                Ok(Err(error)) => Err(upstream_error(&error)),
                Err(_) => Err(TIMEOUT.to_owned()),
            };
            if let Err(error) = &result {
                tracing::warn!("upstream {name}: {error} (status)");
            }
            (index, result)
        });
    }
    while let Some(joined) = tasks.join_next().await {
        let Ok((index, result)) = joined else { continue };
        let Some(status) = statuses.get_mut(index) else { continue };
        match result {
            Ok(keys) => {
                status.reachable = true;
                status.keys = Some(keys);
                status.error = None;
            }
            Err(error) => status.error = Some(error),
        }
    }
    statuses
}

/// [`UpstreamStatus::error`] for an upstream that did not answer in time.
const TIMEOUT: &str = "timeout";

/// [`UpstreamStatus::error`] for `error`, without the upstream's name.
fn upstream_error(error: &UpstreamError) -> String {
    match error {
        UpstreamError::Timeout { .. } => TIMEOUT.to_owned(),
        UpstreamError::Connect { source, .. } => format!("cannot connect: {source}"),
        UpstreamError::Protocol { source, .. } => source.to_string(),
    }
}

/// The vault worker's status by `deadline`. Every source needs the vault worker (secret
/// references, gh, helpers); without sources it is asked only if it already runs (e.g.
/// after `ctl vault unlock`). A failure or a missed deadline marks every vault unavailable
/// with the reason as note.
async fn vault_statuses(core: &Core, snapshot: &Resolved, deadline: Instant) -> Vec<VaultStatus> {
    let vault_needed = !snapshot.config.sources.is_empty()
        || core.workers.vault.as_ref().is_some_and(|handle| handle.is_running());
    if !vault_needed {
        return Vec::new();
    }
    let note = match timeout_at(deadline, vault_request(core, vault::Request::Status)).await {
        Ok(Ok(vault::Response::Status(status))) => return status,
        Ok(Ok(_)) => "unexpected answer from the vault worker".to_owned(),
        Ok(Err(error)) => format!("the vault worker failed: {}", error.message),
        Err(_) => "timeout: the vault worker did not answer in time".to_owned(),
    };
    unavailable_vaults(&note)
}

/// Every vault kind as unavailable, with `note`.
fn unavailable_vaults(note: &str) -> Vec<VaultStatus> {
    VaultKind::ALL
        .iter()
        .map(|vault| VaultStatus {
            vault: vault.name().to_owned(),
            available: false,
            unlocked_until: None,
            note: Some(note.to_owned()),
        })
        .collect()
}

/// The keys `server` would see (`None`: what `agent.sock` shows).
async fn keys(core: &Core, server: Option<&str>) -> Response {
    let snapshot = core.snapshot();
    let config = &snapshot.config;
    let profile = match server {
        None => None,
        Some(name) => {
            let Some(server) = config.servers.get(name) else {
                return error_response(
                    WorkerErrorKind::NotFound,
                    format!("no server {name} in the configuration"),
                );
            };
            match config.profile_for(Some(server)) {
                Some(profile) => Some(profile),
                None => return Response::Keys(Vec::new()),
            }
        }
    };
    if config.agent.is_none() {
        return Response::Keys(Vec::new());
    }
    if core.lock.is_locked() {
        // Servers see an empty list now; say why instead of listing keys they cannot use.
        return locked_response();
    }
    let mut set = UpstreamSet::new(snapshot.upstreams.clone());
    let lists = set.all_identities(&Replay::default()).await;
    let visible = |index: usize| match profile {
        None => true,
        Some(profile) => {
            snapshot.upstreams.get(index).is_some_and(|target| profile.shows_upstream(&target.name))
        }
    };
    let map = crate::keymux::KeyMap::merge(lists, visible);
    let keys = map
        .entries()
        .iter()
        .map(|(identity, index)| KeyInfo {
            upstream: snapshot.upstreams.get(*index).map(|target| target.name.clone()).unwrap_or_default(),
            fingerprint: describe_key(&identity.key_blob),
            comment: identity.comment_lossy(),
        })
        .collect();
    Response::Keys(keys)
}

/// `ssh-ed25519 SHA256:…` for a key blob.
fn describe_key(key_blob: &[u8]) -> String {
    match ssh_key::PublicKey::from_bytes(key_blob) {
        Ok(key) => format!("{} {}", key.algorithm().as_str(), key.fingerprint(ssh_key::HashAlg::Sha256)),
        Err(_) => crate::connection::fingerprint(key_blob),
    }
}

/// Resolves a token as `server` would, without returning it.
async fn token_test(core: &Core, server: &str, url: &str) -> Response {
    let config = core.config();
    let Some(server) = config.servers.get(server) else {
        return error_response(WorkerErrorKind::NotFound, format!("no server {server} in the configuration"));
    };
    let Some(profile) = config.profile_for(Some(server)) else {
        return error_response(
            WorkerErrorKind::NotFound,
            format!("profile {} does not exist", server.profile),
        );
    };
    let target = match GitTarget::parse_url(url) {
        Ok(target) => target,
        Err(error) => return error_response(WorkerErrorKind::Invalid, error.to_string()),
    };
    let mut result = TokenTestResult {
        profile: profile.name.clone(),
        rule: None,
        source: None,
        username: None,
        expires_at: None,
    };
    let Some(rule) = profile.git_rule_for(&target) else { return Response::Token(result) };
    result.rule = Some(rule.url.as_str().to_owned());
    result.source = Some(rule.source.clone());
    let Some(source) = config.sources.get(&rule.source) else {
        return error_response(WorkerErrorKind::NotFound, format!("source {} does not exist", rule.source));
    };
    // Read before the lock check, as for a server's request (`resolve_token`).
    let forgets = core.forget_count();
    if core.lock.is_locked() {
        return locked_response();
    }
    match resolve_token(core, source, rule, &target, GitAction::Get, forgets).await {
        Ok(TokenOutcome::Token(token)) => {
            result.username = Some(token.username);
            result.expires_at = token.expires_at;
            Response::Token(result)
        }
        Ok(TokenOutcome::NoToken | TokenOutcome::Erased) => Response::Token(result),
        Ok(TokenOutcome::Locked) => locked_response(),
        Err(error) => Response::Error(error),
    }
}

/// The answer while the proxy is locked: no keys, no tokens.
fn locked_response() -> Response {
    error_response(WorkerErrorKind::Locked, "the proxy is locked: run ssh-add -X to unlock it")
}

/// Resolves what source `name` reads on this machine and keeps only the outcome: each
/// secret reference through the vault worker; for a `gh` source `gh auth git-credential`
/// for its host (gh reads its stored login, nothing goes to the network). A credential
/// helper is not run: it is asked per repository and may prompt, so there is nothing to
/// resolve ahead of a request. Every secret is dropped here.
async fn source_test(core: &Core, name: &str) -> Response {
    let config = core.config();
    let Some(source) = config.sources.get(name) else {
        return error_response(
            WorkerErrorKind::NotFound,
            format!("no source {name} in the configuration the daemon uses"),
        );
    };
    let mut checks = Vec::new();
    match &source.kind {
        SourceKind::GithubGh { host } => {
            let target = TokenTarget { protocol: "https".into(), host: host.clone(), path: None };
            let request = vault::Request::GhCredential { target, action: vault::CredentialAction::Get };
            let error = match vault_request(core, request).await {
                Ok(vault::Response::Credential(Some(_token))) => None,
                Ok(vault::Response::Credential(None)) => Some(WorkerError::new(
                    WorkerErrorKind::NotFound,
                    format!("gh has no login for {host}: run gh auth login --hostname {host}"),
                )),
                Ok(_) => Some(unexpected_error()),
                Err(error) => Some(error),
            };
            checks.push(SourceCheck { what: format!("gh login for {host}"), error });
        }
        SourceKind::Helper { .. } => {}
        kind => {
            for reference in kind.secret_refs() {
                let reference = reference.to_string();
                let request = vault::Request::Resolve { reference: reference.clone() };
                let error = match vault_request(core, request).await {
                    Ok(vault::Response::Secret(_secret)) => None,
                    Ok(_) => Some(unexpected_error()),
                    Err(error) => Some(error),
                };
                checks.push(SourceCheck { what: reference, error });
            }
        }
    }
    Response::SourceTested(checks)
}

/// The error of an answer that does not fit the request.
fn unexpected_error() -> WorkerError {
    WorkerError::new(WorkerErrorKind::Internal, "unexpected answer from the vault worker")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use credential_bridge_config::paths::{PathVars, Paths, TargetOs};
    use credential_bridge_config::{AgentConfig, Config, SocketSpec, Upstream};
    use credential_bridge_proto::agent::Message;

    use super::*;
    use crate::supervisor::Workers;

    fn upstream(name: &str, socket: PathBuf) -> Upstream {
        Upstream { name: name.into(), socket: SocketSpec::Path(socket) }
    }

    /// One upstream answers, one never does, one does not exist: the status comes back
    /// by the deadline and tells them apart.
    #[tokio::test]
    async fn status_reports_silent_upstreams_within_the_deadline() {
        let dir = tempfile::Builder::new().prefix("cbc").tempdir_in("/tmp").unwrap();
        let (good, silent) = (dir.path().join("good"), dir.path().join("silent"));
        let good_listener = tokio::net::UnixListener::bind(&good).unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = good_listener.accept().await {
                tokio::spawn(async move {
                    while let Ok(Some(_)) = crate::frame::read_agent_frame(&mut stream).await {
                        let answer = Message::IdentitiesAnswer(Vec::new()).encode();
                        let _ = crate::frame::write_agent_frame(&mut stream, &answer).await;
                    }
                });
            }
        });
        // Accepts (the kernel queues the connection) but never reads or answers.
        let _silent_listener = tokio::net::UnixListener::bind(&silent).unwrap();

        let config = Config {
            agent: Some(AgentConfig {
                add_to: None,
                upstreams: vec![
                    upstream("good", good),
                    upstream("silent", silent),
                    upstream("missing", dir.path().join("missing")),
                ],
            }),
            ..Config::default()
        };
        let vars = PathVars { home: Some(dir.path().as_os_str().to_owned()), ..PathVars::default() };
        let paths = Paths::from_vars(&vars, TargetOs::current()).unwrap();
        let core = Core::new(paths, dir.path().join("config.toml"), config, Workers::none());

        let started = std::time::Instant::now();
        let status = status_within(&core, Duration::from_millis(500)).await;
        assert!(started.elapsed() < Duration::from_secs(3), "took {:?}", started.elapsed());
        let summary: Vec<(&str, bool, Option<usize>)> =
            status.upstreams.iter().map(|up| (up.name.as_str(), up.reachable, up.keys)).collect();
        assert_eq!(summary, [("good", true, Some(0)), ("silent", false, None), ("missing", false, None)]);
        let errors: Vec<Option<&str>> = status.upstreams.iter().map(|up| up.error.as_deref()).collect();
        assert_eq!(errors[0], None);
        assert_eq!(errors[1], Some("timeout"), "a silent upstream is reported as timeout");
        assert!(errors[2].is_some_and(|e| e.starts_with("cannot connect: ")), "{:?}", errors[2]);
        assert!(status.vaults.is_empty(), "no source, no running vault worker: not asked");
    }

    /// Without a vault worker every reference fails as unavailable; a helper source has
    /// nothing to resolve; an unknown source is named.
    #[tokio::test]
    async fn source_test_reports_outcomes_only() {
        let dir = tempfile::tempdir().unwrap();
        let text = "version = 2\n[source.ci]\ntype = \"gitlab\"\nhost = \"gl.example.org\"\n\
                    token = \"cmd:printf secret\"\n[source.mgr]\ntype = \"helper\"\nhelper = \"manager\"\n";
        let vars = PathVars { home: Some(dir.path().as_os_str().to_owned()), ..PathVars::default() };
        let paths = Paths::from_vars(&vars, TargetOs::current()).unwrap();
        let config = Config::parse(text, &paths).unwrap();
        let core = Core::new(paths, dir.path().join("config.toml"), config, Workers::none());
        let Response::SourceTested(checks) = handle(&core, Request::SourceTest { source: "ci".into() }).await
        else {
            panic!("no SourceTested")
        };
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].what, "cmd:printf secret");
        assert_eq!(checks[0].error.as_ref().map(|e| e.kind), Some(WorkerErrorKind::Unavailable));
        assert_eq!(
            handle(&core, Request::SourceTest { source: "mgr".into() }).await,
            Response::SourceTested(vec![])
        );
        let Response::Error(error) = handle(&core, Request::SourceTest { source: "x".into() }).await else {
            panic!("an unknown source is an error")
        };
        assert_eq!(error.kind, WorkerErrorKind::NotFound);
    }

    #[test]
    fn unavailable_vaults_carry_the_reason() {
        let vaults = unavailable_vaults("timeout");
        assert_eq!(vaults.len(), VaultKind::ALL.len());
        assert!(vaults.iter().all(|v| !v.available && v.note.as_deref() == Some("timeout")));
    }
}
