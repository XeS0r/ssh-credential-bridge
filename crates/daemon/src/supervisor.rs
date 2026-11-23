//! Worker supervision: re-exec, channel, restart with back-off, idle exit.
//!
//! A worker is started on its first request and only if its building block is
//! configured: `credential-bridged worker <kind>` (the daemon's own executable), with the
//! worker end of a socketpair as stdin, stdout to `/dev/null`, stderr into the daemon's
//! log, and the environment cleared except for the kind's allowlist. The worker answers
//! with `FromWorker::Ready` first. A crashed worker fails its in-flight requests with
//! `WorkerErrorKind::Internal` and is restarted on the next request after the
//! [`Backoff`] delay. After [`WorkerConfig::idle_timeout`] without requests the core
//! sends `Shutdown` (the vault worker is kept while an unlock session is open, see
//! [`WorkerHandle::keep_alive_until`]; the gpg worker while a tunnel is open, see
//! [`WorkerHandle::hold`]).
//!
//! The reader task of a worker does not decode responses: it routes each frame body by
//! its id to the waiting request, which decodes it into its own type. Bodies may carry
//! secrets and are wiped after use.

use std::collections::HashMap;
use std::ffi::OsString;
use std::future::Future;
use std::marker::PhantomData;
use std::os::fd::{AsFd, OwnedFd};
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use credential_bridge_proto::ipc::control::WorkerStatus;
use credential_bridge_proto::ipc::{
    Callback, CallbackReply, FromWorker, RequestId, ToWorker, WorkerError, WorkerErrorKind, WorkerKind,
    decode_body, encode_frame, git, gpg, vault,
};
use serde::Serialize;
use serde::de::{DeserializeOwned, IgnoredAny};
use tokio::io::{AsyncWriteExt, Interest};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot, watch};
use zeroize::Zeroizing;

use crate::frame::read_ipc_body;

/// Environment variables the vault worker gets (if set in the daemon).
pub const VAULT_ENV: &[&str] = &[
    "HOME",
    "PATH",
    "USER",
    "LOGNAME",
    "LANG",
    "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "GNUPGHOME",
    "PASSWORD_STORE_DIR",
    "BW_CLIENTID",
    "OP_ACCOUNT",
];

/// Environment variables the git worker gets: only what TLS needs to find CAs
/// (`NIX_SSL_CERT_FILE` on NixOS).
pub const GIT_ENV: &[&str] = &["SSL_CERT_FILE", "SSL_CERT_DIR", "NIX_SSL_CERT_FILE"];

/// Environment variables the gpg worker gets: none.
pub const GPG_ENV: &[&str] = &[];

/// Always passed: the log filter.
pub const LOG_ENV: &str = "RUST_LOG";

/// How long a started worker may take to send `Ready`.
const READY_TIMEOUT: Duration = Duration::from_secs(15);

/// How long [`WorkerHandle::shutdown`] waits before killing the worker.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// A request waits for a pending restart at most this long; a longer back-off answers
/// `Unavailable` at once.
const MAX_BACKOFF_WAIT: Duration = Duration::from_secs(2);

/// A worker that ran this long before crashing resets the back-off.
const BACKOFF_RESET_AFTER: Duration = Duration::from_secs(60);

/// Picks the allowlisted variables for `kind` from `env` (usually `std::env::vars_os`).
pub fn worker_env(
    kind: WorkerKind,
    env: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    let allowed = match kind {
        WorkerKind::Git => GIT_ENV,
        WorkerKind::Vault => VAULT_ENV,
        WorkerKind::Gpg => GPG_ENV,
    };
    env.into_iter()
        .filter(|(name, _)| name == LOG_ENV || allowed.iter().any(|allowed| name == allowed))
        .collect()
}

/// Restart delays: 100 ms doubling up to 30 s; reset after a worker ran for a minute.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Backoff {
    /// Restarts since the last reset.
    attempt: u32,
}

impl Backoff {
    /// First delay.
    pub const INITIAL: Duration = Duration::from_millis(100);
    /// Largest delay.
    pub const MAX: Duration = Duration::from_secs(30);

    /// The delay before the next restart; advances the attempt counter.
    pub fn next_delay(&mut self) -> Duration {
        let delay = Self::INITIAL.saturating_mul(1 << self.attempt.min(16)).min(Self::MAX);
        self.attempt = self.attempt.saturating_add(1);
        delay
    }

    /// Back to [`Backoff::INITIAL`].
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// How to run one worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerConfig {
    /// The kind.
    pub kind: WorkerKind,
    /// The daemon's executable (`/proc/self/exe` resolved at start).
    pub exe: PathBuf,
    /// The environment ([`worker_env`]).
    pub env: Vec<(OsString, OsString)>,
    /// Exit after this long without requests.
    pub idle_timeout: Duration,
    /// Deadline per request; long enough for touch, PIN and approval dialogs.
    pub request_timeout: Duration,
}

/// Deadline of a vault worker request: 10 s above the vault's program timeout (100 s)
/// and the deadline of a whole store, which may run several programs.
pub const VAULT_REQUEST_TIMEOUT: Duration =
    Duration::from_secs(credential_bridge_vault::runner::DEFAULT_TIMEOUT.as_secs() + 10);

const _: () = assert!(
    credential_bridge_vault::STORE_DEADLINE.as_secs() < VAULT_REQUEST_TIMEOUT.as_secs(),
    "a store must end before the core gives up on it"
);

/// Deadline of a git worker request: a secret callback through the vault worker
/// ([`VAULT_REQUEST_TIMEOUT`]) plus GitHub API calls, below the remote helper's 180 s.
pub const GIT_REQUEST_TIMEOUT: Duration = Duration::from_secs(170);

/// Deadline of a gpg worker request: above the worker's own deadline for a gpg-agent
/// turn (110 s), in which pinentry and card PINs happen.
pub const GPG_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

impl WorkerConfig {
    /// The defaults for `kind`: idle exit after 10 minutes; per request
    /// [`GIT_REQUEST_TIMEOUT`], [`VAULT_REQUEST_TIMEOUT`] or [`GPG_REQUEST_TIMEOUT`].
    /// Deadlines grow from the inside out, so the innermost one fires first and its
    /// error is the one the user sees.
    pub fn new(kind: WorkerKind, exe: PathBuf, env: Vec<(OsString, OsString)>) -> Self {
        let request_timeout = match kind {
            WorkerKind::Git => GIT_REQUEST_TIMEOUT,
            WorkerKind::Vault => VAULT_REQUEST_TIMEOUT,
            WorkerKind::Gpg => GPG_REQUEST_TIMEOUT,
        };
        Self { kind, exe, env, idle_timeout: Duration::from_secs(600), request_timeout }
    }
}

/// Answers a worker's callbacks (the git worker's secret requests go to the vault
/// worker).
pub type CallbackHandler = Arc<
    dyn Fn(Callback) -> Pin<Box<dyn Future<Output = Result<CallbackReply, WorkerError>> + Send>>
        + Send
        + Sync,
>;

/// Told about worker starts, exits and degraded sandboxes (the core writes them to the
/// audit log).
pub type WorkerObserver = Arc<dyn Fn(WorkerKind, String) + Send + Sync>;

/// A frame for the writer task, with an optional descriptor for its first byte.
struct Outgoing {
    /// The complete frame.
    frame: Zeroizing<Vec<u8>>,
    /// Sent with `SCM_RIGHTS`.
    fd: Option<OwnedFd>,
}

/// A waiting request's answer: the frame body, or why there is none.
type Answer = Result<Zeroizing<Vec<u8>>, WorkerError>;

/// One running worker process.
struct Running {
    /// Distinguishes this process from earlier and later ones.
    generation: u64,
    /// The process id.
    pid: Option<u32>,
    /// When it started.
    started: Instant,
    /// Frames to the worker.
    writer: mpsc::UnboundedSender<Outgoing>,
    /// Requests waiting for their answer.
    pending: HashMap<RequestId, oneshot::Sender<Answer>>,
    /// `Shutdown` was sent: the exit is expected, not a crash.
    stopping: bool,
    /// Kills the process.
    kill: Option<oneshot::Sender<()>>,
    /// Becomes `true` when the process exited.
    exited: watch::Receiver<bool>,
}

/// Mutable state of a handle.
#[derive(Default)]
struct State {
    /// The current process.
    running: Option<Running>,
    /// Generation counter.
    generations: u64,
    /// Unexpected exits since the daemon started.
    restarts: u32,
    /// Sandbox layers the current or last process lacked.
    degraded: Vec<String>,
    /// Restart delays.
    backoff: Backoff,
    /// No restart before this instant (after a crash).
    retry_at: Option<Instant>,
    /// Last request start or end.
    last_activity: Option<Instant>,
    /// Requests in flight.
    in_flight: usize,
    /// Open sessions that need the process (gpg tunnels).
    holds: usize,
    /// Do not exit for idleness before this time (vault unlock sessions).
    keep_until: Option<SystemTime>,
}

/// State shared with the reader, writer and idle tasks.
struct Shared {
    /// The worker kind.
    kind: WorkerKind,
    /// The state.
    state: Mutex<State>,
    /// Request ids.
    next_id: AtomicU64,
    /// Lifecycle notifications.
    observer: Option<WorkerObserver>,
}

impl Shared {
    /// Locks the state, ignoring poisoning (every critical section leaves it consistent).
    fn lock(&self) -> MutexGuard<'_, State> {
        crate::sync::lock(&self.state)
    }

    /// Logs and reports a lifecycle event.
    fn notify(&self, message: String) {
        tracing::info!("worker {}: {message}", self.kind);
        if let Some(observer) = &self.observer {
            observer(self.kind, message);
        }
    }

    /// The process of `generation` is gone: fail its requests, and arm the back-off if
    /// the exit was not requested.
    fn process_gone(&self, generation: u64, why: &str) {
        let mut state = self.lock();
        let Some(running) = state.running.take_if(|running| running.generation == generation) else { return };
        let crashed = !running.stopping;
        let error = WorkerError::new(WorkerErrorKind::Internal, format!("worker {} exited", self.kind));
        for (_, waiter) in running.pending {
            let _ = waiter.send(Err(error.clone()));
        }
        if crashed {
            if running.started.elapsed() >= BACKOFF_RESET_AFTER {
                state.backoff.reset();
            }
            let delay = state.backoff.next_delay();
            state.retry_at = Some(Instant::now() + delay);
            state.restarts = state.restarts.saturating_add(1);
            drop(state);
            self.notify(format!(
                "exited unexpectedly ({why}); restart allowed after {} ms",
                delay.as_millis()
            ));
        } else {
            drop(state);
            self.notify(format!("stopped ({why})"));
        }
    }
}

/// Identifies one worker process of a handle (it changes with every start).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerGeneration(u64);

impl WorkerGeneration {
    /// A generation no process of a handle has.
    #[cfg(test)]
    pub(crate) fn for_test() -> WorkerGeneration {
        WorkerGeneration(u64::MAX)
    }
}

/// Where [`WorkerHandle::send`] may deliver a request.
#[derive(Debug, Clone, Copy)]
enum Target {
    /// The running process; one is started if none runs.
    Start,
    /// Only the process of this generation; nothing is started.
    Only(WorkerGeneration),
    /// The running process, if any; nothing is started.
    Running,
}

/// A typed handle to one worker; starts it on demand.
pub struct WorkerHandle<Req, Resp> {
    /// How to run it.
    config: WorkerConfig,
    /// Callback handling, for workers that send callbacks.
    callbacks: Option<CallbackHandler>,
    /// Request and response types.
    types: PhantomData<fn(Req) -> Resp>,
    /// State shared with the background tasks.
    shared: Arc<Shared>,
    /// Serializes starts.
    starting: tokio::sync::Mutex<()>,
}

impl<Req, Resp> std::fmt::Debug for WorkerHandle<Req, Resp> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerHandle")
            .field("config", &self.config)
            .field("callbacks", &self.callbacks.is_some())
            .finish()
    }
}

/// Decrements the in-flight count when a request ends, also when it is cancelled.
struct InFlight<'a>(&'a Shared);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        let mut state = self.0.lock();
        state.in_flight = state.in_flight.saturating_sub(1);
        state.last_activity = Some(Instant::now());
    }
}

impl<Req: Serialize + Send, Resp: DeserializeOwned + Send> WorkerHandle<Req, Resp> {
    /// A handle; nothing is started yet.
    pub fn new(config: WorkerConfig, callbacks: Option<CallbackHandler>) -> Self {
        Self::with_observer(config, callbacks, None)
    }

    /// As [`WorkerHandle::new`], reporting lifecycle events to `observer`.
    pub fn with_observer(
        config: WorkerConfig,
        callbacks: Option<CallbackHandler>,
        observer: Option<WorkerObserver>,
    ) -> Self {
        let shared = Arc::new(Shared {
            kind: config.kind,
            state: Mutex::new(State::default()),
            next_id: AtomicU64::new(1),
            observer,
        });
        Self { config, callbacks, types: PhantomData, shared, starting: tokio::sync::Mutex::new(()) }
    }

    /// The configuration.
    pub fn config(&self) -> &WorkerConfig {
        &self.config
    }

    /// Sends a request (starting the worker if needed) and waits for the response.
    ///
    /// Errors: the worker's error; `Timeout` after `request_timeout`; `Internal` if the
    /// worker crashed or cannot be started; `Unavailable` during back-off.
    pub async fn request(&self, body: Req) -> Result<Resp, WorkerError> {
        self.send(body, None, Target::Start).await.map(|(response, _)| response)
    }

    /// As [`WorkerHandle::request`], with `fd` attached (`SCM_RIGHTS`) to the frame.
    pub async fn request_with_fd(&self, body: Req, fd: OwnedFd) -> Result<Resp, WorkerError> {
        self.send(body, Some(fd), Target::Start).await.map(|(response, _)| response)
    }

    /// As [`WorkerHandle::request_with_fd`], also returning the generation of the process
    /// that answered: state opened by this request (a gpg tunnel) lives only in that
    /// process; later requests about it go through [`WorkerHandle::request_if_running`].
    pub async fn request_with_fd_tracked(
        &self,
        body: Req,
        fd: OwnedFd,
    ) -> Result<(Resp, WorkerGeneration), WorkerError> {
        self.send(body, Some(fd), Target::Start).await
    }

    /// Sends a request only to the process of `generation` and never starts one: after a
    /// crash or restart the state the request is about is gone anyway.
    ///
    /// Errors: `Unavailable` if that process no longer runs; otherwise as
    /// [`WorkerHandle::request`].
    pub async fn request_if_running(
        &self,
        generation: WorkerGeneration,
        body: Req,
    ) -> Result<Resp, WorkerError> {
        self.send(body, None, Target::Only(generation)).await.map(|(response, _)| response)
    }

    /// Sends a request to the running process and never starts one: `Ok(None)` if none
    /// runs. For requests about state that lives only in a running worker (cached
    /// tokens to drop).
    ///
    /// Errors: as [`WorkerHandle::request`].
    pub async fn request_running(&self, body: Req) -> Result<Option<Resp>, WorkerError> {
        match self.send(body, None, Target::Running).await {
            Ok((response, _)) => Ok(Some(response)),
            Err(error) if error.kind == WorkerErrorKind::Unavailable && !self.is_running() => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Sends `Shutdown` and waits for the process to exit.
    pub async fn shutdown(&self) {
        let _starting = self.starting.lock().await;
        let exited = {
            let mut state = self.shared.lock();
            let Some(running) = state.running.as_mut() else { return };
            running.stopping = true;
            let frame = encode_frame(&ToWorker::<()>::Shutdown).map(Zeroizing::new);
            if let Ok(frame) = frame {
                let _ = running.writer.send(Outgoing { frame, fd: None });
            }
            (running.exited.clone(), running.kill.take())
        };
        let (mut exited, kill) = exited;
        if tokio::time::timeout(SHUTDOWN_GRACE, exited.wait_for(|done| *done)).await.is_err() {
            tracing::warn!("worker {} did not exit after Shutdown; killing it", self.config.kind);
            if let Some(kill) = kill {
                let _ = kill.send(());
            }
            let _ = exited.wait_for(|done| *done).await;
        }
    }

    /// State for `ctl check`.
    pub fn status(&self) -> WorkerStatus {
        let state = self.shared.lock();
        WorkerStatus {
            kind: self.config.kind,
            pid: state.running.as_ref().filter(|r| !r.stopping).and_then(|r| r.pid),
            restarts: state.restarts,
            degraded: state.degraded.clone(),
        }
    }

    /// Whether a worker process is running (and not shutting down).
    pub fn is_running(&self) -> bool {
        self.shared.lock().running.as_ref().is_some_and(|running| !running.stopping)
    }

    /// Keeps the worker from exiting for idleness until `until` (`None`: no longer).
    /// The core sets it from the vault worker's unlock answers.
    pub fn keep_alive_until(&self, until: Option<SystemTime>) {
        self.shared.lock().keep_until = until;
    }

    /// Extends [`WorkerHandle::keep_alive_until`] to at least `until` (an unlock session
    /// that ends then).
    pub fn extend_keep_alive(&self, until: SystemTime) {
        let mut state = self.shared.lock();
        state.keep_until = Some(state.keep_until.map_or(until, |current| current.max(until)));
    }

    /// Registers an open session that needs the worker process (a gpg tunnel); the
    /// worker does not exit for idleness until [`WorkerHandle::release`].
    pub fn hold(&self) {
        let mut state = self.shared.lock();
        state.holds = state.holds.saturating_add(1);
    }

    /// Ends a [`WorkerHandle::hold`].
    pub fn release(&self) {
        let mut state = self.shared.lock();
        state.holds = state.holds.saturating_sub(1);
        state.last_activity = Some(Instant::now());
    }

    /// Encodes, sends to `target` and waits; returns the answer and the generation of the
    /// process that gave it.
    async fn send(
        &self,
        body: Req,
        fd: Option<OwnedFd>,
        target: Target,
    ) -> Result<(Resp, WorkerGeneration), WorkerError> {
        let id = self.shared.next_id.fetch_add(1, Ordering::Relaxed);
        let frame =
            encode_frame(&ToWorker::Request { id, body: &body }).map(Zeroizing::new).map_err(|error| {
                WorkerError::new(WorkerErrorKind::Internal, format!("cannot encode request: {error}"))
            })?;
        drop(body);
        if matches!(target, Target::Start) {
            self.ensure_running().await?;
        }
        let (tx, rx) = oneshot::channel();
        let generation = {
            let mut state = self.shared.lock();
            let running = state.running.as_mut().filter(|running| !running.stopping);
            let running = match (running, target) {
                (Some(running), Target::Start | Target::Running) => running,
                (Some(running), Target::Only(wanted)) if running.generation == wanted.0 => running,
                (_, Target::Only(_)) => {
                    return Err(WorkerError::new(
                        WorkerErrorKind::Unavailable,
                        format!("worker {} was restarted or stopped", self.config.kind),
                    ));
                }
                (None, Target::Running) => {
                    return Err(WorkerError::new(
                        WorkerErrorKind::Unavailable,
                        format!("worker {} is not running", self.config.kind),
                    ));
                }
                (None, Target::Start) => {
                    return Err(WorkerError::new(
                        WorkerErrorKind::Internal,
                        format!("worker {} exited", self.config.kind),
                    ));
                }
            };
            running.pending.insert(id, tx);
            if running.writer.send(Outgoing { frame, fd }).is_err() {
                running.pending.remove(&id);
                return Err(WorkerError::new(
                    WorkerErrorKind::Internal,
                    format!("worker {} exited", self.config.kind),
                ));
            }
            let generation = running.generation;
            state.in_flight += 1;
            state.last_activity = Some(Instant::now());
            generation
        };
        let _in_flight = InFlight(&self.shared);
        let answer = match tokio::time::timeout(self.config.request_timeout, rx).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) => Err(WorkerError::new(
                WorkerErrorKind::Internal,
                format!("worker {} exited", self.config.kind),
            )),
            Err(_) => {
                let mut state = self.shared.lock();
                if let Some(running) = state.running.as_mut().filter(|r| r.generation == generation) {
                    running.pending.remove(&id);
                }
                return Err(WorkerError::new(
                    WorkerErrorKind::Timeout,
                    format!(
                        "worker {} did not answer within {} s",
                        self.config.kind,
                        self.config.request_timeout.as_secs()
                    ),
                ));
            }
        }?;
        match decode_body::<FromWorker<Resp>>(&answer) {
            Ok(FromWorker::Response { result, .. }) => {
                result.map(|response| (response, WorkerGeneration(generation)))
            }
            Ok(_) => Err(WorkerError::new(WorkerErrorKind::Internal, "unexpected frame from worker")),
            Err(error) => {
                Err(WorkerError::new(WorkerErrorKind::Internal, format!("bad response from worker: {error}")))
            }
        }
    }

    /// Starts the worker unless it runs; honours the back-off after a crash.
    async fn ensure_running(&self) -> Result<(), WorkerError> {
        let _starting = self.starting.lock().await;
        let wait = {
            let mut state = self.shared.lock();
            if state.running.as_ref().is_some_and(|running| !running.stopping) {
                // Counts as activity, so the idle loop cannot stop the worker between
                // this check and `send` queueing the request.
                state.last_activity = Some(Instant::now());
                return Ok(());
            }
            state.retry_at.map(|at| at.saturating_duration_since(Instant::now()))
        };
        if let Some(wait) = wait.filter(|wait| !wait.is_zero()) {
            if wait > MAX_BACKOFF_WAIT {
                return Err(WorkerError::new(
                    WorkerErrorKind::Unavailable,
                    format!(
                        "worker {} crashed and restarts in {} s",
                        self.config.kind,
                        wait.as_secs().max(1)
                    ),
                ));
            }
            tokio::time::sleep(wait).await;
        }
        match self.start().await {
            Ok(()) => Ok(()),
            Err(message) => {
                let mut state = self.shared.lock();
                let delay = state.backoff.next_delay();
                state.retry_at = Some(Instant::now() + delay);
                drop(state);
                self.shared.notify(format!("could not start: {message}"));
                Err(WorkerError::new(
                    WorkerErrorKind::Internal,
                    format!("worker {} could not start: {message}", self.config.kind),
                ))
            }
        }
    }

    /// Spawns the process, waits for `Ready` and starts the background tasks.
    async fn start(&self) -> Result<(), String> {
        let (core_end, worker_end) =
            credential_bridge_platform::channel::channel_pair().map_err(|e| format!("socketpair: {e}"))?;
        let mut command = tokio::process::Command::new(&self.config.exe);
        command
            .arg("worker")
            .arg(self.config.kind.as_str())
            .env_clear()
            .envs(self.config.env.iter().map(|(k, v)| (k.as_os_str(), v.as_os_str())))
            .stdin(Stdio::from(worker_end))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let mut child =
            command.spawn().map_err(|e| format!("cannot run {}: {e}", self.config.exe.display()))?;
        let pid = child.id();
        // `command` holds the worker end of the channel until it is dropped; drop it so
        // the core sees EOF when the worker exits.
        drop(command);

        let stream = std::os::unix::net::UnixStream::from(core_end);
        let stream = stream
            .set_nonblocking(true)
            .and_then(|()| UnixStream::from_std(stream))
            .map_err(|e| format!("channel: {e}"))?;
        let (mut reader, writer) = stream.into_split();

        let degraded = match tokio::time::timeout(READY_TIMEOUT, read_ipc_body(&mut reader)).await {
            Ok(Ok(Some(body))) => match decode_body::<FromWorker<IgnoredAny>>(&body) {
                Ok(FromWorker::Ready { degraded }) => degraded,
                Ok(_) => return Err("first frame was not Ready".to_owned()),
                Err(error) => return Err(format!("bad Ready frame: {error}")),
            },
            Ok(Ok(None)) => {
                let status = child.wait().await.map(|s| s.to_string()).unwrap_or_default();
                return Err(format!("exited before it was ready ({status})"));
            }
            Ok(Err(error)) => return Err(format!("channel: {error}")),
            Err(_) => return Err("not ready in time".to_owned()),
        };

        let (writer_tx, writer_rx) = mpsc::unbounded_channel();
        let (kill_tx, kill_rx) = oneshot::channel();
        let (exited_tx, exited_rx) = watch::channel(false);
        let generation = {
            let mut state = self.shared.lock();
            state.generations += 1;
            let generation = state.generations;
            state.degraded = degraded.clone();
            state.retry_at = None;
            state.last_activity = Some(Instant::now());
            state.running = Some(Running {
                generation,
                pid,
                started: Instant::now(),
                writer: writer_tx.clone(),
                pending: HashMap::new(),
                stopping: false,
                kill: Some(kill_tx),
                exited: exited_rx,
            });
            generation
        };
        let pid_text = pid.map_or_else(|| "?".to_owned(), |p| p.to_string());
        self.shared.notify(format!("started (pid {pid_text})"));
        for layer in &degraded {
            self.shared.notify(format!("runs without sandbox layer: {layer}"));
        }

        tokio::spawn(write_loop(writer, writer_rx));
        tokio::spawn(read_loop(
            Arc::clone(&self.shared),
            generation,
            reader,
            writer_tx,
            self.callbacks.clone(),
        ));
        tokio::spawn(wait_loop(Arc::clone(&self.shared), generation, child, kill_rx, exited_tx));
        tokio::spawn(idle_loop(Arc::clone(&self.shared), generation, self.config.idle_timeout));
        Ok(())
    }
}

/// Writes frames to the worker until the sender side is dropped or writing fails.
async fn write_loop(mut writer: OwnedWriteHalf, mut frames: mpsc::UnboundedReceiver<Outgoing>) {
    while let Some(outgoing) = frames.recv().await {
        let result = match outgoing.fd {
            Some(fd) => write_with_fd(&mut writer, &outgoing.frame, fd).await,
            None => writer.write_all(&outgoing.frame).await,
        };
        if let Err(error) = result {
            tracing::warn!("writing to a worker failed: {error}");
            return;
        }
    }
}

/// Sends the first part of `frame` with `fd` attached, then the rest.
async fn write_with_fd(writer: &mut OwnedWriteHalf, frame: &[u8], fd: OwnedFd) -> std::io::Result<()> {
    let stream: &UnixStream = writer.as_ref();
    let sent = loop {
        stream.writable().await?;
        match stream.try_io(Interest::WRITABLE, || {
            credential_bridge_platform::channel::send_with_fds(stream, frame, &[fd.as_fd()])
        }) {
            Ok(sent) => break sent,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
    };
    // The descriptor is in flight; the core's copy is closed here.
    drop(fd);
    writer.write_all(&frame[sent..]).await
}

/// Routes the worker's frames: responses to their requests, callbacks to the handler.
async fn read_loop(
    shared: Arc<Shared>,
    generation: u64,
    mut reader: OwnedReadHalf,
    writer: mpsc::UnboundedSender<Outgoing>,
    callbacks: Option<CallbackHandler>,
) {
    let why = loop {
        let body = match read_ipc_body(&mut reader).await {
            Ok(Some(body)) => body,
            Ok(None) => break "channel closed".to_owned(),
            Err(error) => break format!("channel error: {error}"),
        };
        let frame = match decode_body::<FromWorker<IgnoredAny>>(&body) {
            Ok(frame) => frame,
            Err(error) => break format!("bad frame: {error}"),
        };
        match frame {
            FromWorker::Ready { .. } => tracing::warn!("worker {}: unexpected second Ready", shared.kind),
            FromWorker::Response { id, .. } => {
                let waiter = shared
                    .lock()
                    .running
                    .as_mut()
                    .filter(|running| running.generation == generation)
                    .and_then(|running| running.pending.remove(&id));
                match waiter {
                    Some(waiter) => {
                        let _ = waiter.send(Ok(body));
                    }
                    None => tracing::debug!("worker {}: answer to unknown request {id}", shared.kind),
                }
            }
            FromWorker::Callback { id, for_request, body } => {
                let known = shared.lock().running.as_ref().is_some_and(|running| {
                    running.generation == generation && running.pending.contains_key(&for_request)
                });
                let handler = callbacks.clone();
                let writer = writer.clone();
                let kind = shared.kind;
                tokio::spawn(async move {
                    let result = match (known, handler) {
                        (false, _) => {
                            Err(WorkerError::new(WorkerErrorKind::Invalid, "callback for no pending request"))
                        }
                        (true, None) => Err(WorkerError::new(
                            WorkerErrorKind::Invalid,
                            format!("worker {kind} may not send callbacks"),
                        )),
                        (true, Some(handler)) => handler(body).await,
                    };
                    match encode_frame(&ToWorker::<()>::CallbackReply { id, result }) {
                        Ok(frame) => {
                            let _ = writer.send(Outgoing { frame: Zeroizing::new(frame), fd: None });
                        }
                        Err(error) => tracing::warn!("cannot encode a callback reply: {error}"),
                    }
                });
            }
        }
    };
    shared.process_gone(generation, &why);
}

/// Reaps the process (or kills it on request) and reports its exit.
async fn wait_loop(
    shared: Arc<Shared>,
    generation: u64,
    mut child: tokio::process::Child,
    kill: oneshot::Receiver<()>,
    exited: watch::Sender<bool>,
) {
    let status = tokio::select! {
        status = child.wait() => status,
        Ok(()) = kill => {
            let _ = child.start_kill();
            child.wait().await
        }
    };
    let why = match status {
        Ok(status) => status.to_string(),
        Err(error) => format!("wait failed: {error}"),
    };
    shared.process_gone(generation, &why);
    let _ = exited.send(true);
}

/// Sends `Shutdown` after `idle_timeout` without requests, unless held.
async fn idle_loop(shared: Arc<Shared>, generation: u64, idle_timeout: Duration) {
    let interval = (idle_timeout / 4).clamp(Duration::from_millis(50), Duration::from_secs(30));
    loop {
        tokio::time::sleep(interval).await;
        let mut state = shared.lock();
        let held = state.in_flight > 0
            || state.holds > 0
            || state.keep_until.is_some_and(|until| until > SystemTime::now());
        let idle_since = state.last_activity.map_or(Duration::ZERO, |at| at.elapsed());
        let Some(running) = state.running.as_mut().filter(|running| running.generation == generation) else {
            return;
        };
        if running.stopping {
            return;
        }
        if !held && idle_since >= idle_timeout {
            running.stopping = true;
            if let Ok(frame) = encode_frame(&ToWorker::<()>::Shutdown) {
                let _ = running.writer.send(Outgoing { frame: Zeroizing::new(frame), fd: None });
            }
            tracing::debug!("worker {}: idle, shutting down", shared.kind);
            return;
        }
    }
}

/// The three workers. Handles start nothing by themselves: the core sends a worker
/// requests only when the configuration needs it (a git rule with such a source, a
/// secret reference, a gpg profile), so a building block that is not configured never
/// starts its worker, and one added by a reload works without a restart. `None` means
/// the worker is not available at all (tests, embedders).
#[derive(Debug)]
pub struct Workers {
    /// The git worker (any rule with a PAT, App, GitLab or Forgejo source).
    pub git: Option<WorkerHandle<git::Request, git::Response>>,
    /// The vault worker (any source or secret reference, or `gh`/`helper`).
    pub vault: Option<WorkerHandle<vault::Request, vault::Response>>,
    /// The gpg worker (`[gpg]` and a profile with gpg rights).
    pub gpg: Option<WorkerHandle<gpg::Request, gpg::Response>>,
}

impl Workers {
    /// No workers (tests).
    pub fn none() -> Workers {
        Workers { git: None, vault: None, gpg: None }
    }

    /// All three handles for `exe` with the allowlisted environment from `env`; the vault
    /// worker also gets `vault_env` (its settings from the configuration).
    pub fn new(
        exe: PathBuf,
        env: Vec<(OsString, OsString)>,
        vault_env: Vec<(OsString, OsString)>,
        git_callbacks: CallbackHandler,
        observer: Option<WorkerObserver>,
    ) -> Workers {
        let config = |kind| {
            let mut env = worker_env(kind, env.clone());
            if kind == WorkerKind::Vault {
                env.extend(vault_env.iter().cloned());
            }
            WorkerConfig::new(kind, exe.clone(), env)
        };
        Workers {
            git: Some(WorkerHandle::with_observer(
                config(WorkerKind::Git),
                Some(git_callbacks),
                observer.clone(),
            )),
            vault: Some(WorkerHandle::with_observer(config(WorkerKind::Vault), None, observer.clone())),
            gpg: Some(WorkerHandle::with_observer(config(WorkerKind::Gpg), None, observer)),
        }
    }

    /// Statuses of the configured workers.
    pub fn statuses(&self) -> Vec<WorkerStatus> {
        let mut statuses = Vec::new();
        if let Some(handle) = &self.git {
            statuses.push(handle.status());
        }
        if let Some(handle) = &self.vault {
            statuses.push(handle.status());
        }
        if let Some(handle) = &self.gpg {
            statuses.push(handle.status());
        }
        statuses
    }

    /// Shuts every running worker down.
    pub async fn shutdown(&self) {
        let git = async {
            if let Some(handle) = &self.git {
                handle.shutdown().await;
            }
        };
        let vault = async {
            if let Some(handle) = &self.vault {
                handle.shutdown().await;
            }
        };
        let gpg = async {
            if let Some(handle) = &self.gpg {
                handle.shutdown().await;
            }
        };
        tokio::join!(git, vault, gpg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_caps() {
        let mut backoff = Backoff::default();
        assert_eq!(backoff.next_delay(), Duration::from_millis(100));
        assert_eq!(backoff.next_delay(), Duration::from_millis(200));
        for _ in 0..20 {
            backoff.next_delay();
        }
        assert_eq!(backoff.next_delay(), Backoff::MAX);
        backoff.reset();
        assert_eq!(backoff.next_delay(), Backoff::INITIAL);
    }

    #[test]
    fn env_is_allowlisted() {
        let env = [("HOME", "/h"), ("PATH", "/bin"), ("SECRET", "x"), ("RUST_LOG", "debug")]
            .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let git: Vec<_> = worker_env(WorkerKind::Git, env.clone()).into_iter().map(|(k, _)| k).collect();
        assert_eq!(git, ["RUST_LOG"]);
        let vault: Vec<_> = worker_env(WorkerKind::Vault, env).into_iter().map(|(k, _)| k).collect();
        assert_eq!(vault, ["HOME", "PATH", "RUST_LOG"]);
    }

    #[tokio::test]
    async fn missing_executable_fails_with_backoff() {
        let config =
            WorkerConfig::new(WorkerKind::Vault, PathBuf::from("/nonexistent/credential-bridged"), vec![]);
        let handle: WorkerHandle<vault::Request, vault::Response> = WorkerHandle::new(config, None);
        let error = handle.request(vault::Request::Status).await.unwrap_err();
        assert_eq!(error.kind, WorkerErrorKind::Internal);
        assert!(!handle.is_running());
        assert_eq!(handle.status().pid, None);
        handle.shutdown().await;
    }
}
