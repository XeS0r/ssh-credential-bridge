//! The core: shared state and the accept loops of the three sockets.

use std::collections::{BTreeSet, HashMap};
use std::ffi::OsString;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use anyhow::Context as _;
use credential_bridge_config::paths::Paths;
use credential_bridge_config::{Config, DaemonConfig, SocketSpec, VaultConfig};
use credential_bridge_platform::approval::ApprovalDialog;
use credential_bridge_platform::peer::{self, PeerCredentials};
use credential_bridge_proto::ipc::{
    Callback, CallbackReply, WorkerError, WorkerErrorKind, WorkerKind, vault,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::approvals::ApprovalCache;
use crate::audit::{AuditEvent, AuditLog};
use crate::client::ClientCache;
use crate::lock::ProxyLock;
use crate::policy::SocketRole;
use crate::recognition::ServerRecognition;
use crate::slots::ServerSlots;
use crate::supervisor::{CallbackHandler, WorkerObserver, Workers};
use crate::upstream::UpstreamTarget;

/// At most this many client connections are served at once per socket; further ones
/// wait in the listen queue.
const MAX_CONNECTIONS: usize = 256;

/// How long open connections may finish at shutdown before they are aborted.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// How long `gpgconf --list-dirs` may take.
const GPGCONF_TIMEOUT: Duration = Duration::from_secs(10);

/// The configuration with its sockets resolved (`gpgconf:` turned into paths). Swapped
/// as a whole on reload; a connection keeps the one it started with, except that a bound
/// forwarded connection moves to the current one while its server, profile and
/// upstreams stay the same, and ends otherwise.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// The configuration.
    pub config: Arc<Config>,
    /// `[[agent.upstream]]` in configuration order (same indices); empty without
    /// `[agent]`.
    pub upstreams: Vec<UpstreamTarget>,
    /// The gpg-agent extra socket, if `[gpg]` is configured and resolvable.
    pub gpg_socket: Option<PathBuf>,
}

impl Resolved {
    /// Resolves the sockets of `config`. `gpgconf:` entries that cannot be resolved are
    /// logged; such an upstream gets an empty path and is unreachable.
    pub fn new(config: Arc<Config>) -> Resolved {
        let mut cache = HashMap::new();
        let mut resolve = |spec: &SocketSpec, what: &str| -> Option<PathBuf> {
            match spec {
                SocketSpec::Path(path) => Some(path.clone()),
                SocketSpec::Gpgconf(name) => {
                    let result = cache.entry(name.clone()).or_insert_with(|| gpgconf_dir(name)).clone();
                    result.map_err(|error| tracing::warn!("{what}: gpgconf:{name}: {error}")).ok()
                }
            }
        };
        let upstreams = config.agent.as_ref().map_or_else(Vec::new, |agent| {
            agent
                .upstreams
                .iter()
                .map(|upstream| UpstreamTarget {
                    name: upstream.name.clone(),
                    socket: resolve(&upstream.socket, &format!("upstream {}", upstream.name))
                        .unwrap_or_default(),
                })
                .collect()
        });
        let gpg_socket = config.gpg.as_ref().and_then(|gpg| resolve(&gpg.socket, "[gpg] socket"));
        Resolved { config, upstreams, gpg_socket }
    }
}

/// Runs `gpgconf --list-dirs <name>` and returns the path it prints (percent escapes
/// decoded).
fn gpgconf_dir(name: &str) -> Result<PathBuf, String> {
    let mut child = std::process::Command::new("gpgconf")
        .arg("--list-dirs")
        .arg(name)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| format!("cannot run gpgconf: {error}"))?;
    let deadline = std::time::Instant::now() + GPGCONF_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("gpgconf did not answer".to_owned());
            }
            Err(error) => return Err(format!("gpgconf: {error}")),
        }
    }
    let output = child.wait_with_output().map_err(|error| format!("gpgconf: {error}"))?;
    if !output.status.success() {
        return Err(format!("gpgconf failed ({})", output.status));
    }
    let text = String::from_utf8(output.stdout).map_err(|_| "gpgconf printed no UTF-8".to_owned())?;
    let path = credential_bridge_proto::text::percent_decode_gpgconf(text.trim_end_matches(['\n', '\r']));
    if path.is_empty() || !Path::new(&path).is_absolute() {
        return Err(format!("gpgconf knows no directory {name}"));
    }
    Ok(PathBuf::from(path))
}

/// State shared by all connections.
#[derive(Debug)]
pub struct Core {
    /// Well-known paths.
    pub paths: Paths,
    /// The configuration file in use.
    pub config_path: PathBuf,
    /// `[daemon]` as it was when the daemon started: the sockets it serves and the audit
    /// log it writes (a changed `[daemon]` takes effect on a restart).
    pub started: DaemonConfig,
    /// `[vault]` as it was when the daemon started: the vault worker uses it until a
    /// restart.
    pub started_vault: VaultConfig,
    /// The active configuration with resolved sockets; replaced as a whole on reload.
    /// Connections take a snapshot (`Arc`) when they start; bound forwarded connections
    /// move to a newer one on their next request or end. [`Core::config`] is its
    /// configuration, so the two cannot disagree.
    pub resolved: RwLock<Arc<Resolved>>,
    /// Held for a whole [`Core::reload`], so reloads (`SIGHUP`, `ctl`) run one at a time
    /// and the last one to finish is the one that read the file last.
    reloading: Mutex<()>,
    /// The workers.
    pub workers: Workers,
    /// Remembered approvals.
    pub approvals: ApprovalCache,
    /// The audit log.
    pub audit: AuditLog,
    /// `ssh-add -x` state.
    pub lock: ProxyLock,
    /// The approval dialog; `None` uses the system's dialog, looked up per request.
    pub dialog: Option<Arc<dyn ApprovalDialog>>,
    /// Connection budgets per server on `agent-forward.sock`.
    pub forward_slots: Arc<ServerSlots>,
    /// OpenSSH versions of local ssh clients, per executable.
    pub clients: Arc<ClientCache>,
    /// Host key → server, from pinned keys and known_hosts.
    pub recognition: Arc<ServerRecognition>,
    /// The number of the last accepted agent connection (audit events `connect`,
    /// `client` and `server` carry it).
    connections: AtomicU64,
    /// How many times cached tokens were dropped (locks, reloads); see
    /// [`Core::forget_count`].
    forgets: AtomicU64,
}

impl Core {
    /// A core for `config`, with sockets resolved now.
    pub fn new(paths: Paths, config_path: PathBuf, config: Config, workers: Workers) -> Core {
        let audit = AuditLog::new(config.daemon.audit_log.clone());
        let started = config.daemon.clone();
        let started_vault = config.vault.clone();
        let config = Arc::new(config);
        let recognition = Arc::new(ServerRecognition::default());
        recognition.rebuild(&config);
        let resolved = Resolved::new(Arc::clone(&config));
        Core {
            paths,
            config_path,
            started,
            started_vault,
            resolved: RwLock::new(Arc::new(resolved)),
            reloading: Mutex::new(()),
            workers,
            approvals: ApprovalCache::default(),
            audit,
            lock: ProxyLock::default(),
            dialog: None,
            forward_slots: Arc::default(),
            clients: Arc::default(),
            recognition,
            connections: AtomicU64::new(0),
            forgets: AtomicU64::new(0),
        }
    }

    /// A new connection number, unique while the daemon runs.
    pub fn next_connection(&self) -> u64 {
        self.connections.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// How many Forget requests to the git worker have begun. Raised before each is
    /// sent, so a request that read it before its lock check and finds it raised once
    /// its token has arrived knows that a Forget may have missed that token: it reached
    /// the worker before the request did, or was lost while the worker was starting.
    pub fn forget_count(&self) -> u64 {
        self.forgets.load(Ordering::SeqCst)
    }

    /// Raises [`Core::forget_count`]; called before a Forget is sent.
    pub(crate) fn note_forget(&self) {
        self.forgets.fetch_add(1, Ordering::SeqCst);
    }

    /// The current configuration snapshot (that of [`Core::snapshot`]).
    pub fn config(&self) -> Arc<Config> {
        Arc::clone(&self.snapshot().config)
    }

    /// The current configuration with resolved sockets.
    pub fn snapshot(&self) -> Arc<Resolved> {
        Arc::clone(&crate::sync::read(&self.resolved))
    }

    /// The approval dialog to use now.
    pub fn approval_dialog(&self) -> Result<Arc<dyn ApprovalDialog>, String> {
        match &self.dialog {
            Some(dialog) => Ok(Arc::clone(dialog)),
            None => credential_bridge_platform::approval::system_dialog()
                .map(Arc::from)
                .map_err(|error| error.to_string()),
        }
    }

    /// Loads the configuration again and swaps it in if valid. Returns the sources
    /// whose tokens the git worker may have cached and that are now stale: see
    /// [`stale_token_sources`]. The caller drops them with
    /// [`crate::extensions::forget_stale_tokens`] once this returns, i.e. after the new
    /// configuration is in place.
    ///
    /// Errors: the load error; the old configuration stays active.
    ///
    /// Remembered approvals are forgotten only if what they were given under changed:
    /// a profile (including `profile.unregistered`) or a server. Other changes (sources,
    /// agents, `[gpg]`, `[daemon]`, `[vault]`) keep them.
    ///
    /// Blocking (reads the file, may run `gpgconf`, waits for a running reload); async
    /// callers use `spawn_blocking`. Reloads run one at a time. Socket paths, the audit
    /// log path and the vault settings take effect only after a restart.
    pub fn reload(&self) -> Result<BTreeSet<String>, credential_bridge_config::ConfigError> {
        let _one_reload = crate::sync::lock(&self.reloading);
        let config = Config::load(&self.config_path, &self.paths)?;
        let old = self.config();
        if config.daemon != old.daemon {
            tracing::warn!("[daemon] changed: socket and audit log paths take effect after a restart");
        }
        if config.vault != old.vault {
            tracing::warn!("[vault] changed: the vault settings take effect after a restart");
        }
        let approvals_stale = config.profiles != old.profiles
            || config.unregistered != old.unregistered
            || config.servers != old.servers;
        let stale_tokens = stale_token_sources(&old, &config);
        let config = Arc::new(config);
        self.recognition.rebuild(&config);
        let resolved = Arc::new(Resolved::new(config));
        *crate::sync::write(&self.resolved) = resolved;
        if approvals_stale {
            self.approvals.clear();
            tracing::info!("profiles or servers changed: remembered approvals are forgotten");
        }
        tracing::info!("configuration reloaded from {}", self.config_path.display());
        Ok(stale_tokens)
    }

    /// Resolves a secret for the git worker through the vault worker, if the current
    /// configuration names the reference (a compromised git worker gets nothing else).
    pub async fn secret_for_git_worker(&self, reference: &str) -> Result<CallbackReply, WorkerError> {
        if !crate::extensions::is_configured_secret(&self.config(), reference) {
            tracing::warn!("the git worker asked for a secret that no source uses");
            return Err(WorkerError::new(
                WorkerErrorKind::Denied,
                "secret reference is not used by any source",
            ));
        }
        let vault = self.workers.vault.as_ref().ok_or_else(|| {
            WorkerError::new(WorkerErrorKind::Unavailable, "the vault worker is not available")
        })?;
        match vault.request(vault::Request::Resolve { reference: reference.to_owned() }).await? {
            vault::Response::Secret(secret) => Ok(CallbackReply::Secret(secret)),
            _ => Err(WorkerError::new(WorkerErrorKind::Internal, "unexpected answer from the vault worker")),
        }
    }
}

/// The sources of `old` whose tokens the git worker may have cached and that `new`
/// removed or defines differently in any way (type, auth, host, API URL, App ID, secret
/// reference, permissions, `cache`, ...). A renamed source counts as removed under its
/// old name, a moved reference as changed. Only sources with a secret reference count:
/// `gh` and `helper` sources cache nothing in the bridge.
pub fn stale_token_sources(old: &Config, new: &Config) -> BTreeSet<String> {
    old.sources
        .iter()
        .filter(|(_, source)| !source.kind.secret_refs().is_empty())
        .filter(|(name, source)| new.sources.get(*name) != Some(*source))
        .map(|(name, _)| name.clone())
        .collect()
}

/// The git worker's callback handler, bound to the core it belongs to.
fn git_callbacks(core: Weak<Core>) -> CallbackHandler {
    Arc::new(move |callback: Callback| {
        let core = core.clone();
        Box::pin(async move {
            let core = core.upgrade().ok_or_else(|| {
                WorkerError::new(WorkerErrorKind::Unavailable, "the daemon is shutting down")
            })?;
            match callback {
                Callback::Secret { reference } => core.secret_for_git_worker(&reference).await,
            }
        })
    })
}

/// Writes worker lifecycle events to the audit log of `core`.
fn worker_observer(core: Weak<Core>) -> WorkerObserver {
    Arc::new(move |kind: WorkerKind, message: String| {
        if let Some(core) = core.upgrade() {
            core.audit.record(&AuditEvent::Worker { kind: kind.as_str(), message });
        }
    })
}

/// Runs the daemon until SIGTERM/SIGINT: hardens the process, loads the configuration
/// (`config` or the default path), prepares the state directory, binds `agent.sock`,
/// `agent-forward.sock` and `control.sock` (own user or root only), resolves `gpgconf:`
/// sockets, and serves connections. SIGHUP reloads the configuration.
///
/// Errors: invalid configuration, sockets that cannot be bound (e.g. another daemon is
/// running).
pub fn run(config: Option<PathBuf>) -> anyhow::Result<()> {
    let hardening = credential_bridge_platform::harden::harden_process();
    for failure in &hardening.failures {
        tracing::warn!("{failure}");
    }
    let paths = Paths::discover().context("cannot determine the home directory")?;
    let config_path = config.unwrap_or_else(|| paths.config_file.clone());
    let loaded = Config::load(&config_path, &paths)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("credential-bridged")
        .build()
        .context("cannot start the runtime")?;
    runtime.block_on(serve(paths, config_path, loaded))
}

/// The bound listening sockets.
struct Listeners {
    /// `agent.sock`.
    local: UnixListener,
    /// `agent-forward.sock`.
    forward: UnixListener,
    /// `control.sock`.
    control: UnixListener,
    /// The paths, removed on exit.
    paths: Vec<PathBuf>,
}

/// Binds the three sockets in private directories.
fn bind_sockets(config: &Config) -> anyhow::Result<Listeners> {
    let daemon = &config.daemon;
    let mut listeners = Vec::new();
    for path in [&daemon.socket, &daemon.forward_socket, &daemon.control_socket] {
        if let Some(parent) = path.parent() {
            credential_bridge_platform::socket::ensure_private_dir(parent)
                .with_context(|| format!("socket directory {}", parent.display()))?;
        }
        let listener = credential_bridge_platform::socket::bind_private(path)
            .with_context(|| format!("cannot listen on {}", path.display()))?;
        listeners.push(UnixListener::from_std(listener)?);
    }
    let mut listeners = listeners.into_iter();
    let (Some(local), Some(forward), Some(control)) = (listeners.next(), listeners.next(), listeners.next())
    else {
        unreachable!("three sockets were bound");
    };
    Ok(Listeners {
        local,
        forward,
        control,
        paths: vec![daemon.socket.clone(), daemon.forward_socket.clone(), daemon.control_socket.clone()],
    })
}

/// Sets up the core and serves until a termination signal.
async fn serve(paths: Paths, config_path: PathBuf, config: Config) -> anyhow::Result<()> {
    // Signal handlers come first: once the sockets exist, a SIGTERM/SIGINT must shut down
    // cleanly (removing them) and a SIGHUP must reload instead of killing the daemon.
    let mut hangup = signal(SignalKind::hangup())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let listeners = bind_sockets(&config)?;
    let exe = std::env::current_exe().context("cannot find the daemon's own executable")?;
    let env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let vault_env = crate::worker::vault::keepassxc_env(&config.vault.keepassxc);
    let core = Arc::new_cyclic(|weak: &Weak<Core>| {
        let workers = Workers::new(
            exe,
            env,
            vault_env,
            git_callbacks(weak.clone()),
            Some(worker_observer(weak.clone())),
        );
        Core::new(paths, config_path, config, workers)
    });
    tracing::info!(
        "listening on {} (local) and {} (forward); configuration {}",
        listeners.paths[0].display(),
        listeners.paths[1].display(),
        core.config_path.display()
    );
    let (stop, stopped) = watch::channel(false);
    let accept = vec![
        tokio::spawn(accept_agent(Arc::clone(&core), listeners.local, SocketRole::Local, stopped.clone())),
        tokio::spawn(accept_agent(
            Arc::clone(&core),
            listeners.forward,
            SocketRole::Forward,
            stopped.clone(),
        )),
        tokio::spawn(accept_control(Arc::clone(&core), listeners.control, stopped)),
    ];
    sd_notify("READY=1\nSTATUS=serving");
    loop {
        tokio::select! {
            _ = hangup.recv() => {
                sd_notify("RELOADING=1");
                let reloading = Arc::clone(&core);
                match tokio::task::spawn_blocking(move || reloading.reload()).await {
                    Ok(Ok(stale)) => crate::extensions::forget_stale_tokens(&core, stale).await,
                    Ok(Err(error)) => tracing::error!("reload failed, keeping the old configuration: {error}"),
                    Err(error) => tracing::error!("reload failed: {error}"),
                }
                sd_notify("READY=1");
            }
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
        }
    }
    tracing::info!("shutting down");
    sd_notify("STOPPING=1");
    shut_down(&core, &stop, accept, SHUTDOWN_GRACE).await;
    for path in &listeners.paths {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

/// Ends serving in an order that loses no audit event: stop accepting, give open
/// connections `grace` to finish and abort the rest, shut the workers down (their exit
/// events are recorded), then write the audit log and join its writer thread.
async fn shut_down(
    core: &Core,
    stop: &watch::Sender<bool>,
    accept: Vec<JoinHandle<JoinSet<()>>>,
    grace: Duration,
) {
    let _ = stop.send(true);
    let mut connections = Vec::with_capacity(accept.len());
    for task in accept {
        match task.await {
            Ok(set) => connections.push(set),
            Err(error) => tracing::error!("an accept loop failed: {error}"),
        }
    }
    let finish = async {
        for set in &mut connections {
            while set.join_next().await.is_some() {}
        }
    };
    if tokio::time::timeout(grace, finish).await.is_err() {
        let open: usize = connections.iter().map(JoinSet::len).sum();
        tracing::info!("closing {open} connections that are still open");
        for set in &mut connections {
            set.abort_all();
            while set.join_next().await.is_some() {}
        }
    }
    core.workers.shutdown().await;
    tokio::task::block_in_place(|| core.audit.close());
}

/// Reads the peer credentials and applies security rule 6.
fn check_peer(stream: &UnixStream, socket: &str) -> Option<PeerCredentials> {
    match peer::peer_credentials(stream) {
        Ok(peer) if peer::is_trusted(&peer, peer::current_uid()) => Some(peer),
        Ok(peer) => {
            tracing::warn!("{socket}: refused a connection from uid {}", peer.uid);
            None
        }
        Err(error) => {
            tracing::warn!("{socket}: cannot check the peer: {error}");
            None
        }
    }
}

/// Counts connections of one socket; the guard decrements.
struct ConnectionSlot(Arc<AtomicUsize>);

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Accepts a connection, waiting while [`MAX_CONNECTIONS`] are served. Transient
/// accept errors (too many open files) are retried after a pause.
async fn accept_one(listener: &UnixListener, active: &Arc<AtomicUsize>) -> (UnixStream, ConnectionSlot) {
    loop {
        while active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        match listener.accept().await {
            Ok((stream, _)) => {
                active.fetch_add(1, Ordering::Relaxed);
                return (stream, ConnectionSlot(Arc::clone(active)));
            }
            Err(error) => {
                tracing::warn!("accept failed: {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Accepts connections on `listener` until `stop` turns true (or its sender is gone)
/// and returns the connection tasks still running. `start` checks a new connection and
/// returns the future that serves it, or `None` to close it.
async fn accept_loop<F, Fut>(
    listener: UnixListener,
    mut stop: watch::Receiver<bool>,
    mut start: F,
) -> JoinSet<()>
where
    F: FnMut(UnixStream) -> Option<Fut>,
    Fut: Future<Output = ()> + Send + 'static,
{
    let active = Arc::new(AtomicUsize::new(0));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.wait_for(|stop| *stop) => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            (stream, slot) = accept_one(&listener, &active) => {
                let Some(serve) = start(stream) else { continue };
                connections.spawn(async move {
                    serve.await;
                    drop(slot);
                });
            }
        }
    }
    connections
}

/// Serves `agent.sock` or `agent-forward.sock` (see [`accept_loop`]).
async fn accept_agent(
    core: Arc<Core>,
    listener: UnixListener,
    role: SocketRole,
    stop: watch::Receiver<bool>,
) -> JoinSet<()> {
    let connection_stop = stop.clone();
    accept_loop(listener, stop, move |stream| {
        let peer = check_peer(&stream, role.as_str())?;
        Some(crate::connection::serve(Arc::clone(&core), stream, role, peer, connection_stop.clone()))
    })
    .await
}

/// Serves `control.sock` (see [`accept_loop`]).
async fn accept_control(core: Arc<Core>, listener: UnixListener, stop: watch::Receiver<bool>) -> JoinSet<()> {
    let connection_stop = stop.clone();
    accept_loop(listener, stop, move |stream| {
        check_peer(&stream, "control")?;
        Some(crate::control::serve(Arc::clone(&core), stream, connection_stop.clone()))
    })
    .await
}

/// Tells systemd about the daemon's state (`sd_notify`), if `NOTIFY_SOCKET` is set.
/// Supports path and abstract (`@name`) sockets; errors are logged.
fn sd_notify(state: &str) {
    if let Some(target) = std::env::var_os("NOTIFY_SOCKET")
        && let Err(error) = notify_to(&target, state)
    {
        tracing::warn!("sd_notify: {error}");
    }
}

/// Sends `state` to the notification socket `target`.
fn notify_to(target: &std::ffi::OsStr, state: &str) -> std::io::Result<()> {
    let socket = UnixDatagram::unbound()?;
    match target.as_encoded_bytes().strip_prefix(b"@") {
        #[cfg(target_os = "linux")]
        Some(name) => {
            use std::os::linux::net::SocketAddrExt;
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
            socket.send_to_addr(state.as_bytes(), &addr)?;
        }
        #[cfg(not(target_os = "linux"))]
        Some(_) => return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "abstract sockets")),
        None => {
            socket.send_to(state.as_bytes(), Path::new(target))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifies_systemd() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        let receiver = UnixDatagram::bind(&path).unwrap();
        notify_to(path.as_os_str(), "READY=1").unwrap();
        let mut buf = [0u8; 64];
        let n = receiver.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");
        assert!(notify_to(dir.path().join("missing").as_os_str(), "READY=1").is_err());
    }

    /// A core with an audit log in `dir` and no workers.
    fn test_core(dir: &Path) -> Core {
        let vars = credential_bridge_config::paths::PathVars {
            home: Some(dir.as_os_str().to_owned()),
            ..Default::default()
        };
        let paths = Paths::from_vars(&vars, credential_bridge_config::paths::TargetOs::current()).unwrap();
        let mut config = Config::default();
        config.daemon.audit_log = dir.join("audit.log");
        Core::new(paths, dir.join("config.toml"), config, Workers::none())
    }

    /// Reloads from many threads while the file changes: the configuration and the
    /// snapshot never disagree, and the last reload leaves the file's final content.
    #[test]
    fn concurrent_reloads_stay_consistent() {
        let dir = tempfile::tempdir().unwrap();
        let core = Arc::new(test_core(dir.path()));
        let config_path = dir.path().join("config.toml");
        let write = |n: usize| {
            let text = format!(
                "version = 2\n[daemon]\naudit_log = \"{}\"\n[source.s{n}]\ntype = \"helper\"\nhelper = \"h\"\n",
                dir.path().join("audit.log").display()
            );
            let temp = dir.path().join(format!("config.{n}.tmp"));
            std::fs::write(&temp, text).unwrap();
            std::fs::rename(&temp, &config_path).unwrap();
        };
        write(0);
        std::thread::scope(|scope| {
            for thread in 0..4 {
                let core = Arc::clone(&core);
                let write = &write;
                scope.spawn(move || {
                    for round in 0..25 {
                        write(thread * 100 + round + 1);
                        core.reload().unwrap();
                        assert_eq!(core.config().sources.len(), 1);
                    }
                });
            }
        });
        write(1000);
        core.reload().unwrap();
        let config = core.config();
        assert!(Arc::ptr_eq(&config, &core.snapshot().config));
        assert_eq!(config.sources.keys().collect::<Vec<_>>(), ["s1000"]);
    }

    /// A reload reports the sources with possibly cached tokens that it removed or
    /// changed in any way; unchanged sources and `gh`/`helper` sources are not reported.
    #[test]
    fn reload_reports_removed_and_changed_token_sources() {
        let dir = tempfile::tempdir().unwrap();
        let core = test_core(dir.path());
        let audit = dir.path().join("audit.log");
        let reload = |sources: &[(&str, &str)]| {
            let mut text = format!("version = 2\n[daemon]\naudit_log = \"{}\"\n", audit.display());
            for (name, body) in sources {
                text.push_str(&format!("[source.{name}]\n{body}\n"));
            }
            std::fs::write(dir.path().join("config.toml"), text).unwrap();
            core.reload().unwrap().into_iter().collect::<Vec<_>>()
        };
        let pat = "type = \"github\"\nauth = \"pat\"\ntoken = \"pass://pat\"";
        let lab = "type = \"gitlab\"\nhost = \"gitlab.example\"\ntoken = \"pass://lab\"";
        let app = "type = \"github\"\nauth = \"app\"\napp_id = 1\nprivate_key = \"pass://app\"\nmax_permissions = { contents = \"read\" }";
        let gh = "type = \"github\"\nauth = \"gh\"";
        let helper = "type = \"helper\"\nhelper = \"h\"";
        let all = [("pat", pat), ("lab", lab), ("app", app), ("gh", gh), ("helper", helper)];
        assert!(reload(&all).is_empty(), "new sources have nothing cached");
        assert!(reload(&all).is_empty(), "an equal configuration");
        // Moved to another vault, another host, another App ID, renamed, removed.
        let pat_moved = "type = \"github\"\nauth = \"pat\"\ntoken = \"cmd:printf x\"";
        let lab_host = "type = \"gitlab\"\nhost = \"other.example\"\ntoken = \"pass://lab\"";
        let app_id = "type = \"github\"\nauth = \"app\"\napp_id = 2\nprivate_key = \"pass://app\"\nmax_permissions = { contents = \"read\" }";
        assert_eq!(reload(&[("pat", pat_moved), ("lab", lab), ("app", app_id), ("gh2", gh)]), ["app", "pat"]);
        assert_eq!(reload(&[("pat", pat_moved), ("lab", lab_host), ("app2", app_id)]), ["app", "lab"]);
        assert_eq!(reload(&[("helper", helper)]), ["app2", "lab", "pat"]);
        // A failed reload reports nothing and changes nothing.
        std::fs::write(dir.path().join("config.toml"), "version = 2\n[source.x]\n").unwrap();
        assert!(core.reload().is_err());
    }

    /// Approvals survive a reload unless a profile or a server changed.
    #[test]
    fn reload_keeps_approvals_unless_profiles_or_servers_change() {
        use std::time::Instant;

        use crate::approvals::ApprovalKey;

        let dir = tempfile::tempdir().unwrap();
        let core = test_core(dir.path());
        let audit = dir.path().join("audit.log");
        let key = ApprovalKey { server: "box".into(), key: "SHA256:k".into(), process: None, hop: false };
        let approve = || {
            let generation = core.approvals.generation();
            assert!(core.approvals.approve(
                key.clone(),
                Instant::now(),
                Duration::from_secs(3600),
                generation
            ));
        };
        let reload = |body: &str| {
            let text = format!("version = 2\n[daemon]\naudit_log = \"{}\"\n{body}", audit.display());
            std::fs::write(dir.path().join("config.toml"), text).unwrap();
            core.reload().unwrap();
            core.approvals.is_approved(&key, Instant::now())
        };
        approve();
        assert!(reload(""), "an equal configuration");
        assert!(
            reload(
                "[vault.keepassxc]\ndatabase = \"/db.kdbx\"\n[source.s]\ntype = \"helper\"\nhelper = \"h\"\n"
            ),
            "vault and sources"
        );
        assert!(!reload("[profile.dev]\n"), "a new profile");
        approve();
        assert!(!reload("[profile.dev]\n[profile.unregistered]\nssh = { keys = \"all\" }\n"), "unregistered");
        approve();
        assert!(reload("[profile.dev]\n[profile.unregistered]\nssh = { keys = \"all\" }\n[gpg]\n"), "[gpg]");
        let server = format!(
            "[server.box]\nhost_keys = [\"{}\"]\nprofile = \"dev\"\n",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"
        );
        assert!(
            !reload(&format!(
                "[profile.dev]\n[profile.unregistered]\nssh = {{ keys = \"all\" }}\n[gpg]\n{server}"
            )),
            "a server"
        );
    }

    /// A reload waits for a running one instead of overlapping it.
    #[test]
    fn reloads_run_one_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let core = Arc::new(test_core(dir.path()));
        let running = crate::sync::lock(&core.reloading);
        let reload = {
            let core = Arc::clone(&core);
            std::thread::spawn(move || core.reload())
        };
        std::thread::sleep(Duration::from_millis(100));
        assert!(!reload.is_finished(), "the reload did not wait");
        drop(running);
        reload.join().unwrap().unwrap();
    }

    fn audit_events(path: &Path) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        text.lines().map(|line| serde_json::from_str(line).unwrap()).collect()
    }

    /// Shutdown waits for a connection that is finishing, aborts one that hangs, and
    /// writes an event recorded just before it ends.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_keeps_events_of_finishing_connections() {
        let dir = tempfile::tempdir().unwrap();
        let core = Arc::new(test_core(dir.path()));
        let socket = dir.path().join("test.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (stop, stopped) = watch::channel(false);
        let (served, mut started) = tokio::sync::mpsc::unbounded_channel();
        let accept = {
            let core = Arc::clone(&core);
            tokio::spawn(accept_loop(listener, stopped, move |stream| {
                let core = Arc::clone(&core);
                let served = served.clone();
                Some(async move {
                    let _stream = stream;
                    let _ = served.send(());
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    core.audit.record(&AuditEvent::Hop { host_key: "finishing".into() });
                })
            }))
        };
        let _finishing = UnixStream::connect(&socket).await.unwrap();
        started.recv().await.unwrap();

        let begun = std::time::Instant::now();
        shut_down(&core, &stop, vec![accept], Duration::from_secs(5)).await;
        assert!(begun.elapsed() < Duration::from_secs(4), "waited for the full grace period");
        let events = audit_events(&dir.path().join("audit.log"));
        assert!(events.iter().any(|event| event["host_key"] == "finishing"), "{events:?}");
        assert!(UnixStream::connect(&socket).await.is_err(), "still accepting");
    }

    /// An idle agent connection ends as soon as shutdown begins, instead of using up the
    /// grace period; a request sent before still gets its answer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_ends_idle_agent_connections_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let core = Arc::new(test_core(dir.path()));
        let socket = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (stop, stopped) = watch::channel(false);
        let accept = tokio::spawn(accept_agent(Arc::clone(&core), listener, SocketRole::Local, stopped));
        let mut idle = UnixStream::connect(&socket).await.unwrap();
        // One request and answer, so the connection is being served and then idle.
        let request = credential_bridge_proto::agent::Message::RequestIdentities.encode();
        crate::frame::write_agent_frame(&mut idle, &request).await.unwrap();
        assert!(crate::frame::read_agent_frame(&mut idle).await.unwrap().is_some(), "no answer");

        let begun = std::time::Instant::now();
        shut_down(&core, &stop, vec![accept], Duration::from_secs(5)).await;
        assert!(begun.elapsed() < Duration::from_secs(1), "waited {:?}", begun.elapsed());
        let mut buf = [0u8; 1];
        let read = tokio::io::AsyncReadExt::read(&mut idle, &mut buf).await.unwrap();
        assert_eq!(read, 0, "the idle connection is closed");
    }

    /// An idle control connection ends as soon as shutdown begins, instead of using up
    /// the grace period; a request sent before still gets its answer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_ends_idle_control_connections_at_once() {
        use credential_bridge_proto::ipc::control::{Request, Response};

        let dir = tempfile::tempdir().unwrap();
        let core = Arc::new(test_core(dir.path()));
        let socket = dir.path().join("control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (stop, stopped) = watch::channel(false);
        let accept = tokio::spawn(accept_control(Arc::clone(&core), listener, stopped));
        let mut idle = UnixStream::connect(&socket).await.unwrap();
        // One request and answer, so the connection is being served and then idle.
        crate::frame::write_ipc(&mut idle, &Request::Ping).await.unwrap();
        let body = crate::frame::read_ipc_body(&mut idle).await.unwrap().expect("no answer");
        let answer: Response = credential_bridge_proto::ipc::decode_body(&body).unwrap();
        assert!(matches!(answer, Response::Pong { .. }), "{answer:?}");

        let begun = std::time::Instant::now();
        shut_down(&core, &stop, vec![accept], Duration::from_secs(5)).await;
        assert!(begun.elapsed() < Duration::from_secs(1), "waited {:?}", begun.elapsed());
        let mut buf = [0u8; 1];
        let read = tokio::io::AsyncReadExt::read(&mut idle, &mut buf).await.unwrap();
        assert_eq!(read, 0, "the idle control connection is closed");
    }

    /// A connection that does not finish within the grace period is aborted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_aborts_hanging_connections() {
        let dir = tempfile::tempdir().unwrap();
        let core = Arc::new(test_core(dir.path()));
        let socket = dir.path().join("test.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (stop, stopped) = watch::channel(false);
        let (served, mut started) = tokio::sync::mpsc::unbounded_channel();
        let accept = tokio::spawn(accept_loop(listener, stopped, move |stream| {
            let served = served.clone();
            Some(async move {
                let _stream = stream;
                let _ = served.send(());
                std::future::pending::<()>().await;
            })
        }));
        let mut hanging = UnixStream::connect(&socket).await.unwrap();
        started.recv().await.unwrap();
        core.audit.record(&AuditEvent::Hop { host_key: "before".into() });

        let begun = std::time::Instant::now();
        shut_down(&core, &stop, vec![accept], Duration::from_millis(200)).await;
        assert!(begun.elapsed() < Duration::from_secs(3));
        let mut buf = [0u8; 1];
        let read = tokio::io::AsyncReadExt::read(&mut hanging, &mut buf).await.unwrap();
        assert_eq!(read, 0, "the aborted connection is closed");
        let events = audit_events(&dir.path().join("audit.log"));
        assert!(events.iter().any(|event| event["host_key"] == "before"), "{events:?}");
    }

    #[test]
    fn resolves_paths_and_missing_gpgconf_names() {
        let config = Config {
            agent: Some(credential_bridge_config::AgentConfig {
                add_to: None,
                upstreams: vec![credential_bridge_config::Upstream {
                    name: "a".into(),
                    socket: SocketSpec::Path(PathBuf::from("/tmp/a.sock")),
                }],
            }),
            ..Config::default()
        };
        let resolved = Resolved::new(Arc::new(config));
        assert_eq!(
            resolved.upstreams,
            [UpstreamTarget { name: "a".into(), socket: PathBuf::from("/tmp/a.sock") }]
        );
        assert_eq!(resolved.gpg_socket, None);
    }
}
