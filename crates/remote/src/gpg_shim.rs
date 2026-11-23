//! `credential-bridge-remote gpg`: the gpg shim.
//!
//! gpg starts it as `agent-program` when no agent listens on its socket. The shim binds
//! gpg's agent socket (`gpgconf --list-dirs agent-socket`), detaches, and serves
//! connections until idle: for each connection it reads the caller's pid with
//! `SO_PEERCRED`, reads that process's `SSH_AUTH_SOCK` from `/proc/<pid>/environ`, and
//! tunnels Assuan over `gpg-agent@credential-bridge` on that agent (one agent connection
//! per gpg connection, cut into units with
//! [`credential_bridge_gpg::framing::ClientFramer`]). Callers without a bridge are passed
//! to a real gpg-agent started on demand. A dead `SSH_AUTH_SOCK` yields an `ERR` with a
//! clear message.
//!
//! # Set-up
//!
//! In `~/.gnupg/gpg.conf` on the server:
//!
//! ```text
//! agent-program /home/me/.local/bin/credential-bridge-remote
//! ```
//!
//! gpg runs the program as `<program> --homedir <dir> --use-standard-socket [<arg>]
//! --daemon` (see [`credential_bridge_gpg::shim`]), without a `gpg` subcommand; the
//! command line ([`crate::cli::main`]) recognises these arguments. `agent-program
//! <program>|gpg` works as well.
//!
//! # Details
//!
//! - **Detaching.** With `--daemon` the shim starts itself again in the background
//!   (own process group, standard streams on `/dev/null`) and returns once the socket
//!   accepts connections, as gpg-agent does.
//! - **The real gpg-agent.** gpg's standard socket is taken by the shim, so a second
//!   daemon could not listen there. Instead every caller without a bridge gets its own
//!   `gpg-agent --server` with the connection as stdin and stdout. Such an agent caches
//!   passphrases only for that connection.
//! - **`KILLAGENT`** (`gpgconf --kill gpg-agent`) from a bridged caller stops the shim.
//! - **Exit.** The shim exits after [`IDLE_TIMEOUT`] without connections, or when its
//!   socket file is removed or replaced.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use credential_bridge_gpg::assuan::{ClientLine, err_line, parse_client_line};
use credential_bridge_gpg::framing::{ClientFramer, Turn, TurnEnd};
use credential_bridge_platform::peer::{PeerCredentials, current_uid, is_trusted, peer_credentials};
use credential_bridge_proto::agent::{AgentClient, ExtensionReply};
use credential_bridge_proto::ext::{GPG_AGENT, GpgReply, GpgRequest};
use credential_bridge_proto::text::percent_decode_gpgconf;
use zeroize::Zeroizing;

use crate::agent;

/// Hidden argument that marks the detached server process.
pub const FOREGROUND_ARG: &str = "--credential-bridge-foreground";
/// The shim exits after this long without any connection.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// How long the detaching process waits for the server to listen.
const START_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the accept loop checks for shutdown, idleness and its socket file.
const TICK: Duration = Duration::from_millis(500);

/// Source "gpg-agent" in gpg-error codes.
const SOURCE_AGENT: u32 = 4 << 24;
/// `GPG_ERR_GENERAL` from gpg-agent.
pub const ERR_GENERAL: u32 = SOURCE_AGENT | 1;
/// `GPG_ERR_NO_AGENT` from gpg-agent: sent as the greeting when the caller's
/// `SSH_AUTH_SOCK` is dead or no gpg-agent can be started.
pub const ERR_NO_AGENT: u32 = SOURCE_AGENT | 77;

/// The arguments gpg passes to `agent-program`, as far as the shim needs them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShimArgs {
    /// `--homedir`.
    pub homedir: Option<PathBuf>,
    /// Everything, for starting the real gpg-agent with the same arguments.
    pub raw: Vec<OsString>,
    /// `--daemon`: detach and return once the socket listens.
    pub daemon: bool,
    /// [`FOREGROUND_ARG`]: this is the detached server process (not part of `raw`).
    pub foreground: bool,
}

impl ShimArgs {
    /// Parses gpg's arguments; unknown ones are kept in `raw` and otherwise ignored.
    pub fn parse(args: &[OsString]) -> ShimArgs {
        let foreground = args.iter().any(|arg| arg == FOREGROUND_ARG);
        let rest = args.iter().filter(|arg| *arg != FOREGROUND_ARG).cloned();
        let parsed = credential_bridge_gpg::shim::AgentProgramArgs::parse(rest);
        ShimArgs { homedir: parsed.homedir, raw: parsed.raw, daemon: parsed.daemon, foreground }
    }
}

/// Runs `gpgconf` with `--homedir` if given and returns its stdout.
fn gpgconf(homedir: Option<&Path>, args: &[&str]) -> io::Result<String> {
    let mut command = Command::new("gpgconf");
    if let Some(homedir) = homedir {
        command.arg("--homedir").arg(homedir);
    }
    let output = command.args(args).stdin(Stdio::null()).stderr(Stdio::piped()).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "gpgconf {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "gpgconf printed invalid UTF-8"))
}

/// The `gpg-agent` path in `gpgconf --list-components` output
/// (`name:description:path` per line).
fn agent_from_components(listing: &str) -> Option<PathBuf> {
    listing.lines().find_map(|line| {
        let mut fields = line.split(':');
        if fields.next()? != "gpg-agent" {
            return None;
        }
        let path = percent_decode_gpgconf(fields.nth(1)?);
        (!path.is_empty()).then(|| PathBuf::from(path))
    })
}

/// Where the real gpg-agent is: the `gpg-agent` entry of `gpgconf --list-components`.
pub fn real_agent_program() -> std::io::Result<PathBuf> {
    let listing = gpgconf(None, &["--list-components"])?;
    agent_from_components(&listing)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "gpgconf lists no gpg-agent"))
}

/// gpg's agent socket for `homedir` (`gpgconf --list-dirs agent-socket`).
pub fn agent_socket_path(homedir: Option<&Path>) -> io::Result<PathBuf> {
    let path = percent_decode_gpgconf(gpgconf(homedir, &["--list-dirs", "agent-socket"])?.trim());
    if !path.starts_with('/') {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("gpgconf reported {path:?}")));
    }
    Ok(PathBuf::from(path))
}

/// The `SSH_AUTH_SOCK` of the process behind a gpg connection, from
/// `/proc/<pid>/environ` (via `credential_bridge_platform::process::environ_var`).
/// `Ok(None)` if the caller has none (it then gets the real gpg-agent). Errors: no pid
/// or an unreadable environment.
pub fn caller_auth_sock(
    peer: &credential_bridge_platform::peer::PeerCredentials,
) -> std::io::Result<Option<PathBuf>> {
    let pid = peer
        .pid
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "the caller's process id is not visible"))?;
    let value = credential_bridge_platform::process::environ_var(pid, agent::SSH_AUTH_SOCK)?;
    Ok(value.filter(|v| !v.is_empty()).map(PathBuf::from))
}

/// Sends one gpg request and decodes the reply. A refusal (`SSH_AGENT_FAILURE`) and
/// an unknown extension become [`GpgReply::Failed`] with a message.
fn gpg_request(agent: &mut AgentClient<UnixStream>, request: &GpgRequest) -> io::Result<GpgReply> {
    let contents =
        Zeroizing::new(request.encode().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?);
    match agent.extension(GPG_AGENT, &contents) {
        Ok(ExtensionReply::Success(reply)) => GpgReply::decode(&reply).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("invalid reply from the local proxy: {e}"))
        }),
        Ok(ExtensionReply::Failure) => Ok(GpgReply::Failed(
            "the local proxy refused gpg for this server (see credential-bridge-ctl log on your machine)"
                .into(),
        )),
        Ok(ExtensionReply::ExtensionFailure) => Ok(GpgReply::Failed(
            "the local proxy does not understand this gpg request: credential-bridge-remote and \
             credential-bridged are different versions"
                .into(),
        )),
        Err(error) => Err(io::Error::other(format!("no answer from the local proxy: {error}"))),
    }
}

/// Writes `ERR <code> credential-bridge: <message>` to gpg, ignoring write errors (the
/// connection is ending anyway).
fn send_err(gpg: &mut UnixStream, code: u32, message: &str) {
    let line = err_line(code, &format!("credential-bridge: {message}"));
    let _ = gpg.write_all(&line);
}

/// Asks the proxy to close the tunnel; the answer does not matter.
fn close_tunnel(agent: &mut AgentClient<UnixStream>) {
    let _ = gpg_request(agent, &GpgRequest::Close);
}

/// The upper-case verb of a unit that is a command line.
fn unit_verb(unit: &[u8]) -> Option<String> {
    let line = unit.strip_suffix(b"\n").unwrap_or(unit);
    match parse_client_line(line) {
        Ok(ClientLine::Command { verb, .. }) => Some(verb.to_ascii_uppercase()),
        _ => None,
    }
}

/// Relays one gpg connection through the bridge until either side closes: cuts gpg's
/// bytes into units with `framer`, sends each as `GpgRequest::Input`, writes the turn
/// back. Opens the tunnel first and closes it at the end.
pub fn tunnel(
    gpg: std::os::unix::net::UnixStream,
    agent: credential_bridge_proto::agent::AgentClient<std::os::unix::net::UnixStream>,
    framer: credential_bridge_gpg::framing::ClientFramer,
) -> std::io::Result<()> {
    run_tunnel(gpg, agent, framer).map(|_| ())
}

/// How a tunnel ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelEnd {
    /// gpg or the proxy closed it.
    Closed,
    /// gpg sent `KILLAGENT`: the shim should exit.
    Kill,
}

fn run_tunnel(
    mut gpg: UnixStream,
    mut agent: AgentClient<UnixStream>,
    mut framer: ClientFramer,
) -> io::Result<TunnelEnd> {
    match gpg_request(&mut agent, &GpgRequest::Open) {
        Ok(GpgReply::Opened(greeting)) => match Turn::parse(&greeting) {
            Ok(turn) if turn.end == TurnEnd::Ok => gpg.write_all(&greeting)?,
            _ => {
                send_err(&mut gpg, ERR_GENERAL, "invalid greeting from the local proxy");
                close_tunnel(&mut agent);
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid greeting"));
            }
        },
        Ok(GpgReply::Failed(message)) => {
            send_err(&mut gpg, ERR_NO_AGENT, &message);
            return Ok(TunnelEnd::Closed);
        }
        Ok(GpgReply::Output(_) | GpgReply::Closed) => {
            send_err(&mut gpg, ERR_GENERAL, "unexpected reply from the local proxy");
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected reply to open"));
        }
        Err(error) => {
            send_err(&mut gpg, ERR_NO_AGENT, &error.to_string());
            return Err(error);
        }
    }

    let mut buf = Zeroizing::new([0u8; 8192]);
    loop {
        let n = match gpg.read(&mut buf[..]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                close_tunnel(&mut agent);
                return Err(error);
            }
        };
        if let Err(error) = framer.push(&buf[..n]) {
            send_err(&mut gpg, ERR_GENERAL, &error.to_string());
            close_tunnel(&mut agent);
            return Err(io::Error::new(io::ErrorKind::InvalidData, error));
        }
        loop {
            let unit = match framer.next_unit() {
                Ok(Some(unit)) => unit,
                Ok(None) => break,
                Err(error) => {
                    send_err(&mut gpg, ERR_GENERAL, &error.to_string());
                    close_tunnel(&mut agent);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, error));
                }
            };
            let verb = unit_verb(&unit);
            if verb.as_deref() == Some("KILLAGENT") {
                gpg.write_all(b"OK closing connection\n")?;
                close_tunnel(&mut agent);
                return Ok(TunnelEnd::Kill);
            }
            let reply = match gpg_request(&mut agent, &GpgRequest::Input(unit)) {
                Ok(reply) => reply,
                Err(error) => {
                    send_err(&mut gpg, ERR_GENERAL, &error.to_string());
                    return Err(error);
                }
            };
            match reply {
                GpgReply::Output(turn) => {
                    let end = match Turn::parse(&turn) {
                        Ok(parsed) => parsed.end,
                        Err(error) => {
                            send_err(&mut gpg, ERR_GENERAL, "invalid reply from the local proxy");
                            close_tunnel(&mut agent);
                            return Err(io::Error::new(io::ErrorKind::InvalidData, error));
                        }
                    };
                    gpg.write_all(&turn)?;
                    framer.turn_ended(end == TurnEnd::Inquire);
                    if verb.as_deref() == Some("BYE") && end == TurnEnd::Ok {
                        close_tunnel(&mut agent);
                        return Ok(TunnelEnd::Closed);
                    }
                }
                GpgReply::Failed(message) => {
                    send_err(&mut gpg, ERR_GENERAL, &message);
                    return Ok(TunnelEnd::Closed);
                }
                GpgReply::Closed => return Ok(TunnelEnd::Closed),
                GpgReply::Opened(_) => {
                    send_err(&mut gpg, ERR_GENERAL, "unexpected reply from the local proxy");
                    close_tunnel(&mut agent);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected opened"));
                }
            }
        }
    }
    close_tunnel(&mut agent);
    Ok(TunnelEnd::Closed)
}

/// Where a caller's connection goes.
#[derive(Debug)]
enum Route {
    /// A credential-bridge proxy with the gpg extension.
    Bridge(AgentClient<UnixStream>),
    /// No bridge: the real gpg-agent.
    RealAgent,
    /// `SSH_AUTH_SOCK` is set but nobody answers there.
    Dead(String),
}

/// Decides where a caller with `auth_sock` goes.
fn route(auth_sock: Option<&Path>) -> Route {
    let Some(socket) = auth_sock else {
        return Route::RealAgent;
    };
    match agent::connect(socket) {
        Err(error) => Route::Dead(format!(
            "SSH_AUTH_SOCK {} of the calling process does not answer ({error}); the ssh session \
             that set it may be gone (tmux, screen): reconnect or update SSH_AUTH_SOCK",
            socket.display()
        )),
        Ok(mut client) => match agent::extensions(&mut client) {
            Ok(names) if names.iter().any(|name| name == GPG_AGENT) => Route::Bridge(client),
            _ => Route::RealAgent,
        },
    }
}

/// Finds the `SSH_AUTH_SOCK` of a connection's caller.
type Resolver = dyn Fn(&PeerCredentials) -> io::Result<Option<PathBuf>> + Send + Sync;

/// The shared state of a running shim.
struct Shim {
    /// gpg's `--homedir`, passed to the real gpg-agent.
    homedir: Option<PathBuf>,
    /// The real gpg-agent; `None` means [`real_agent_program`].
    real_agent: Option<PathBuf>,
    /// How callers are mapped to their agent socket.
    resolve: Box<Resolver>,
    /// Set by `KILLAGENT`.
    shutdown: AtomicBool,
    /// Connections being served.
    active: AtomicUsize,
    /// When the last connection ended or started.
    last_activity: Mutex<Instant>,
}

impl std::fmt::Debug for Shim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shim").field("homedir", &self.homedir).field("real_agent", &self.real_agent).finish()
    }
}

impl Shim {
    fn new(homedir: Option<PathBuf>, real_agent: Option<PathBuf>, resolve: Box<Resolver>) -> Shim {
        Shim {
            homedir,
            real_agent,
            resolve,
            shutdown: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            last_activity: Mutex::new(Instant::now()),
        }
    }

    fn touch(&self) {
        if let Ok(mut last) = self.last_activity.lock() {
            *last = Instant::now();
        }
    }

    fn idle_for(&self) -> Duration {
        self.last_activity.lock().map(|last| last.elapsed()).unwrap_or_default()
    }

    /// Serves one accepted connection.
    fn handle(&self, gpg: UnixStream) {
        let peer = match peer_credentials(&gpg) {
            Ok(peer) => peer,
            Err(error) => {
                eprintln!("credential-bridge-remote gpg: cannot identify the caller: {error}");
                return;
            }
        };
        if !is_trusted(&peer, current_uid()) {
            eprintln!("credential-bridge-remote gpg: refused a connection from uid {}", peer.uid);
            return;
        }
        // An unreadable environment (another PID namespace, a non-dumpable caller) is
        // treated like no SSH_AUTH_SOCK: the caller gets the real gpg-agent.
        let auth_sock = (self.resolve)(&peer).unwrap_or_else(|error| {
            eprintln!("credential-bridge-remote gpg: cannot read the caller's environment: {error}");
            None
        });
        if let Err(error) = self.serve_caller(gpg, auth_sock.as_deref()) {
            eprintln!("credential-bridge-remote gpg: {error}");
        }
    }

    /// Serves a caller whose `SSH_AUTH_SOCK` is `auth_sock`.
    fn serve_caller(&self, mut gpg: UnixStream, auth_sock: Option<&Path>) -> io::Result<()> {
        match route(auth_sock) {
            Route::Bridge(client) => {
                if run_tunnel(gpg, client, ClientFramer::new())? == TunnelEnd::Kill {
                    self.shutdown.store(true, Ordering::SeqCst);
                }
                Ok(())
            }
            Route::RealAgent => self.hand_to_real_agent(gpg),
            Route::Dead(message) => {
                send_err(&mut gpg, ERR_NO_AGENT, &message);
                Ok(())
            }
        }
    }

    /// Starts `gpg-agent --server` with the connection as stdin and stdout and waits for
    /// it to finish.
    fn hand_to_real_agent(&self, mut gpg: UnixStream) -> io::Result<()> {
        let program = match &self.real_agent {
            Some(program) => program.clone(),
            None => match real_agent_program() {
                Ok(program) => program,
                Err(error) => {
                    send_err(
                        &mut gpg,
                        ERR_NO_AGENT,
                        &format!("no bridge for this caller and no gpg-agent: {error}"),
                    );
                    return Err(error);
                }
            },
        };
        let output = gpg.try_clone()?;
        let mut command = Command::new(&program);
        if let Some(homedir) = &self.homedir {
            command.arg("--homedir").arg(homedir);
        }
        command
            .arg("--server")
            .stdin(Stdio::from(OwnedFd::from(gpg.try_clone()?)))
            .stdout(Stdio::from(OwnedFd::from(output)))
            .stderr(Stdio::null());
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                send_err(&mut gpg, ERR_NO_AGENT, &format!("cannot start {}: {error}", program.display()));
                return Err(error);
            }
        };
        drop(command);
        drop(gpg);
        child.wait()?;
        Ok(())
    }
}

/// The identity of a socket file, to notice when it is removed or replaced. The change
/// time is part of it because a new file may get the inode number of a removed one.
fn socket_identity(path: &Path) -> Option<(u64, u64, i64, i64)> {
    std::fs::symlink_metadata(path).ok().map(|meta| (meta.dev(), meta.ino(), meta.ctime(), meta.ctime_nsec()))
}

/// Accepts connections on `listener` (bound at `socket`) until `KILLAGENT`, until
/// nothing happened for `idle_timeout`, or until the socket file changes. Removes the
/// socket file if it is still the one this shim bound.
fn serve(listener: UnixListener, socket: &Path, shim: Arc<Shim>, idle_timeout: Duration) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let identity = socket_identity(socket);
    let tick =
        rustix::event::Timespec::try_from(TICK).unwrap_or(rustix::event::Timespec { tv_sec: 0, tv_nsec: 0 });
    loop {
        if shim.shutdown.load(Ordering::SeqCst) {
            break;
        }
        if shim.active.load(Ordering::SeqCst) == 0 && shim.idle_for() >= idle_timeout {
            break;
        }
        if socket_identity(socket) != identity {
            // Someone removed or replaced the socket (e.g. a real gpg-agent took over).
            return Ok(());
        }
        let mut fds = [rustix::event::PollFd::new(&listener, rustix::event::PollFlags::IN)];
        match rustix::event::poll(&mut fds, Some(&tick)) {
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                shim.touch();
                shim.active.fetch_add(1, Ordering::SeqCst);
                let worker = Arc::clone(&shim);
                let spawned = std::thread::Builder::new().name("gpg-connection".into()).spawn(move || {
                    worker.handle(stream);
                    worker.touch();
                    worker.active.fetch_sub(1, Ordering::SeqCst);
                });
                if let Err(error) = spawned {
                    shim.active.fetch_sub(1, Ordering::SeqCst);
                    eprintln!("credential-bridge-remote gpg: cannot start a thread: {error}");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                eprintln!("credential-bridge-remote gpg: accept failed: {error}");
                std::thread::sleep(TICK);
            }
        }
    }
    if socket_identity(socket) == identity {
        let _ = std::fs::remove_file(socket);
    }
    Ok(())
}

/// Binds gpg's agent socket, creating gpg's socket directory if needed. `Ok(None)`
/// if another agent already listens there.
fn bind_agent_socket(homedir: Option<&Path>, socket: &Path) -> io::Result<Option<UnixListener>> {
    if let Some(parent) = socket.parent()
        && !parent.is_dir()
    {
        // gpgconf creates /run/user/<uid>/gnupg (and d.<hash> for other homedirs).
        let _ = gpgconf(homedir, &["--create-socketdir"]);
        if !parent.is_dir() {
            credential_bridge_platform::socket::ensure_private_dir(parent)?;
        }
    }
    match credential_bridge_platform::socket::bind_private(socket) {
        Ok(listener) => Ok(Some(listener)),
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => Ok(None),
        Err(error) => Err(error),
    }
}

/// Starts the server in the background and waits until `socket` accepts connections.
fn detach(args: &ShimArgs, socket: &Path) -> io::Result<()> {
    let exe = std::env::current_exe()?;
    let mut child = Command::new(exe)
        .arg("gpg")
        .arg(FOREGROUND_ARG)
        .args(&args.raw)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    let deadline = Instant::now() + START_TIMEOUT;
    while Instant::now() < deadline {
        if credential_bridge_platform::socket::is_listening(socket, Duration::from_millis(100)) {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            return Err(io::Error::other(format!("the gpg shim exited at start ({status})")));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, format!("{} does not accept connections", socket.display())))
}

/// Binds and serves in this process.
fn run_server(args: &ShimArgs, socket: &Path) -> io::Result<()> {
    let Some(listener) = bind_agent_socket(args.homedir.as_deref(), socket)? else {
        // gpg started us although an agent runs (a race); that agent serves gpg.
        return Ok(());
    };
    let shim = Arc::new(Shim::new(args.homedir.clone(), None, Box::new(caller_auth_sock)));
    serve(listener, socket, shim, IDLE_TIMEOUT)
}

/// Entry point.
pub fn main(args: &[OsString]) -> ExitCode {
    let args = ShimArgs::parse(args);
    let result = agent_socket_path(args.homedir.as_deref()).and_then(|socket| {
        if args.daemon && !args.foreground { detach(&args, &socket) } else { run_server(&args, &socket) }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("credential-bridge-remote gpg: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};

    use credential_bridge_proto::agent::Message;
    use credential_bridge_proto::ext::GIT_CREDENTIAL;

    use super::*;
    use crate::testutil::{FakeAgent, extension_contents, query_only, query_reply};

    /// A bridge whose gpg-agent behind the proxy follows a fixed script.
    fn bridge() -> FakeAgent {
        FakeAgent::start(|request| {
            if let Some(answer) = query_reply(request, &[GIT_CREDENTIAL, GPG_AGENT]) {
                return answer;
            }
            let Some(contents) = extension_contents(request, GPG_AGENT) else {
                return Message::Failure;
            };
            let reply = match GpgRequest::decode(contents).unwrap() {
                GpgRequest::Open => GpgReply::Opened(b"OK Pleased to meet you\n".to_vec().into()),
                GpgRequest::Close => GpgReply::Closed,
                GpgRequest::Input(unit) => match unit.as_slice() {
                    b"GETINFO version\n" => GpgReply::Output(b"D 2.4.8\nOK\n".to_vec().into()),
                    b"PKSIGN\n" => {
                        GpgReply::Output(b"INQUIRE PINENTRY_LAUNCHED 4711 gtk2 1.2.1 - - -\n".to_vec().into())
                    }
                    b"END\n" => GpgReply::Output(b"D (7:sig-val)\nOK\n".to_vec().into()),
                    b"SCD SERIALNO\n" => {
                        GpgReply::Output(b"ERR 67109115 Forbidden <credential-bridge>\n".to_vec().into())
                    }
                    b"BYE\n" => GpgReply::Output(b"OK closing connection\n".to_vec().into()),
                    b"BROKEN\n" => GpgReply::Failed("gpg-agent went away".into()),
                    b"GARBAGE\n" => GpgReply::Output(b"no terminator\n".to_vec().into()),
                    _ => GpgReply::Output(b"OK\n".to_vec().into()),
                },
            };
            Message::Success { contents: reply.encode().unwrap().to_vec() }
        })
    }

    /// The gpg side of a connection: writes lines, reads turns.
    struct Gpg {
        writer: UnixStream,
        reader: BufReader<UnixStream>,
    }

    impl Gpg {
        fn new(stream: UnixStream) -> Gpg {
            stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            Gpg { writer: stream.try_clone().unwrap(), reader: BufReader::new(stream) }
        }

        /// Reads lines up to and including the next OK, ERR or INQUIRE.
        fn turn(&mut self) -> String {
            let mut turn = String::new();
            loop {
                let mut line = String::new();
                assert_ne!(self.reader.read_line(&mut line).unwrap(), 0, "closed after {turn:?}");
                turn.push_str(&line);
                if line.starts_with("OK") || line.starts_with("ERR") || line.starts_with("INQUIRE") {
                    return turn;
                }
            }
        }

        fn send(&mut self, bytes: &[u8]) {
            self.writer.write_all(bytes).unwrap();
        }

        fn ask(&mut self, bytes: &[u8]) -> String {
            self.send(bytes);
            self.turn()
        }

        fn at_eof(&mut self) -> bool {
            let mut rest = String::new();
            self.reader.read_line(&mut rest).unwrap() == 0
        }
    }

    /// Runs a tunnel to `agent` in a thread; returns gpg's end and the thread.
    fn start_tunnel(agent: &FakeAgent) -> (Gpg, std::thread::JoinHandle<io::Result<TunnelEnd>>) {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let client = agent::connect(agent.path()).unwrap();
        let handle = std::thread::spawn(move || run_tunnel(theirs, client, ClientFramer::new()));
        (Gpg::new(ours), handle)
    }

    fn sent_units(agent: &FakeAgent) -> Vec<GpgRequest> {
        agent
            .requests()
            .iter()
            .filter_map(|r| extension_contents(r, GPG_AGENT))
            .map(|c| GpgRequest::decode(c).unwrap())
            .collect()
    }

    #[test]
    fn parses_gpg_autostart_arguments() {
        let raw: Vec<OsString> = ["--homedir", "/home/u/.gnupg", "--use-standard-socket", "gpg", "--daemon"]
            .map(Into::into)
            .into();
        let args = ShimArgs::parse(&raw);
        assert_eq!(args.homedir.as_deref(), Some(Path::new("/home/u/.gnupg")));
        assert!(args.daemon);
        assert!(!args.foreground);
        assert_eq!(args.raw, raw);

        let mut with_marker = vec![OsString::from(FOREGROUND_ARG)];
        with_marker.extend(raw.iter().cloned());
        let args = ShimArgs::parse(&with_marker);
        assert!(args.foreground);
        assert_eq!(args.raw, raw);
    }

    #[test]
    fn finds_gpg_agent_in_components() {
        let listing = "gpg:OpenPGP:/usr/bin/gpg\ngpg-agent:Private Keys:/opt/gnu%3apg/bin/gpg-agent\n\
                       scdaemon:Smartcards:/usr/lib/gnupg/scdaemon\n";
        assert_eq!(agent_from_components(listing), Some(PathBuf::from("/opt/gnu:pg/bin/gpg-agent")));
        assert_eq!(agent_from_components("gpg:OpenPGP:/usr/bin/gpg\n"), None);
        let plus = "gpg-agent:Private Keys:/opt/x%+fy/gpg-agent\n";
        assert_eq!(agent_from_components(plus), Some(PathBuf::from("/opt/x%+fy/gpg-agent")));
    }

    #[test]
    fn tunnels_a_signature_with_inquire() {
        let agent = bridge();
        let (mut gpg, handle) = start_tunnel(&agent);
        assert_eq!(gpg.turn(), "OK Pleased to meet you\n");
        // Comments are dropped by the framer; the reply is the command's turn.
        assert_eq!(gpg.ask(b"# hello\nGETINFO version\n"), "D 2.4.8\nOK\n");
        assert_eq!(gpg.ask(b"PKSIGN\n"), "INQUIRE PINENTRY_LAUNCHED 4711 gtk2 1.2.1 - - -\n");
        assert_eq!(gpg.ask(b"END\n"), "D (7:sig-val)\nOK\n");
        assert!(gpg.ask(b"SCD SERIALNO\n").starts_with("ERR 67109115"));
        assert_eq!(gpg.ask(b"BYE\n"), "OK closing connection\n");
        assert_eq!(handle.join().unwrap().unwrap(), TunnelEnd::Closed);
        assert!(gpg.at_eof());
        assert_eq!(
            sent_units(&agent),
            [
                GpgRequest::Open,
                GpgRequest::Input(b"GETINFO version\n".to_vec().into()),
                GpgRequest::Input(b"PKSIGN\n".to_vec().into()),
                GpgRequest::Input(b"END\n".to_vec().into()),
                GpgRequest::Input(b"SCD SERIALNO\n".to_vec().into()),
                GpgRequest::Input(b"BYE\n".to_vec().into()),
                GpgRequest::Close,
            ]
        );
    }

    #[test]
    fn closes_the_tunnel_when_gpg_hangs_up() {
        let agent = bridge();
        let (mut gpg, handle) = start_tunnel(&agent);
        gpg.turn();
        assert_eq!(gpg.ask(b"OPTION ttyname=/dev/pts/1\n"), "OK\n");
        drop(gpg);
        assert_eq!(handle.join().unwrap().unwrap(), TunnelEnd::Closed);
        assert_eq!(sent_units(&agent).last(), Some(&GpgRequest::Close));
    }

    #[test]
    fn proxy_failure_becomes_err() {
        let agent = bridge();
        let (mut gpg, handle) = start_tunnel(&agent);
        gpg.turn();
        let turn = gpg.ask(b"BROKEN\n");
        assert_eq!(turn, "ERR 67108865 credential-bridge: gpg-agent went away\n");
        handle.join().unwrap().unwrap();
        assert!(gpg.at_eof());
    }

    #[test]
    fn invalid_turn_from_proxy_is_rejected() {
        let agent = bridge();
        let (mut gpg, handle) = start_tunnel(&agent);
        gpg.turn();
        assert!(gpg.ask(b"GARBAGE\n").starts_with("ERR 67108865 credential-bridge: invalid reply"));
        assert!(handle.join().unwrap().is_err());
    }

    #[test]
    fn data_without_inquire_is_a_protocol_error() {
        let agent = bridge();
        let (mut gpg, handle) = start_tunnel(&agent);
        gpg.turn();
        assert!(gpg.ask(b"D stray\n").starts_with("ERR 67108865"));
        assert!(handle.join().unwrap().is_err());
        assert_eq!(sent_units(&agent), [GpgRequest::Open, GpgRequest::Close]);
    }

    #[test]
    fn killagent_stops_the_tunnel_locally() {
        let agent = bridge();
        let (mut gpg, handle) = start_tunnel(&agent);
        gpg.turn();
        assert_eq!(gpg.ask(b"KILLAGENT\n"), "OK closing connection\n");
        assert_eq!(handle.join().unwrap().unwrap(), TunnelEnd::Kill);
        assert_eq!(sent_units(&agent), [GpgRequest::Open, GpgRequest::Close]);
    }

    #[test]
    fn refused_open_reaches_gpg() {
        let agent = FakeAgent::start(query_only(&[GPG_AGENT]));
        let (mut gpg, handle) = start_tunnel(&agent);
        let turn = gpg.turn();
        assert!(turn.starts_with("ERR 67108941 credential-bridge: the local proxy refused gpg"), "{turn}");
        handle.join().unwrap().unwrap();
    }

    /// A fake `gpg-agent --server`: greets with its arguments, answers OK, exits on BYE.
    fn fake_real_agent(dir: &Path) -> PathBuf {
        let path = dir.join("gpg-agent");
        write_script(
            &path,
            "echo \"OK real agent $*\"\nwhile read line; do\n  case \"$line\" in\n    \
             BYE*) echo \"OK closing connection\"; exit 0;;\n    *) echo OK;;\n  esac\ndone",
        );
        path
    }

    /// Writes `#!/bin/sh` and `body` to `path` and makes it executable. Written by a child `sh`, so this process never holds the file open for writing: a
    /// test thread that forks meanwhile would inherit such a descriptor until its child
    /// execs, and running the script in that window fails with ETXTBSY ("Text file busy").
    fn write_script(path: &std::path::Path, body: &str) {
        use std::io::Write as _;
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
            .arg(path)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(format!("#!/bin/sh\n{body}\n").as_bytes()).unwrap();
        assert!(child.wait().unwrap().success(), "writing {} failed", path.display());
    }

    fn shim_with(dir: &Path, auth_sock: Option<PathBuf>) -> Shim {
        Shim::new(
            Some(PathBuf::from("/home/u/.gnupg")),
            Some(fake_real_agent(dir)),
            Box::new(move |_| Ok(auth_sock.clone())),
        )
    }

    #[test]
    fn caller_without_agent_gets_the_real_agent() {
        let dir = tempfile::tempdir().unwrap();
        let shim = shim_with(dir.path(), None);
        let (ours, theirs) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || shim.serve_caller(theirs, None));
        let mut gpg = Gpg::new(ours);
        assert_eq!(gpg.turn(), "OK real agent --homedir /home/u/.gnupg --server\n");
        assert_eq!(gpg.ask(b"GETINFO version\n"), "OK\n");
        assert_eq!(gpg.ask(b"BYE\n"), "OK closing connection\n");
        handle.join().unwrap().unwrap();
    }

    /// An agent without our extension: one that answers `query`, and one that answers it
    /// with `SSH_AGENT_FAILURE` like OpenSSH's ssh-agent (and like the bridge towards a
    /// host without `[server.*]` entry, which it hides from).
    #[test]
    fn caller_with_plain_agent_gets_the_real_agent() {
        let dir = tempfile::tempdir().unwrap();
        let plain = FakeAgent::start(query_only(&["session-bind@openssh.com"]));
        let failing = FakeAgent::start(|_: &Message| Message::Failure);
        for agent in [&plain, &failing] {
            let shim = shim_with(dir.path(), None);
            let (ours, theirs) = UnixStream::pair().unwrap();
            let path = agent.path().to_owned();
            let handle = std::thread::spawn(move || shim.serve_caller(theirs, Some(&path)));
            let mut gpg = Gpg::new(ours);
            assert!(gpg.turn().starts_with("OK real agent"));
            gpg.ask(b"BYE\n");
            handle.join().unwrap().unwrap();
            assert_eq!(agent.requests().len(), 1, "only query");
        }
    }

    #[test]
    fn dead_auth_sock_gets_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let shim = shim_with(dir.path(), None);
        let dead = dir.path().join("agent.4711");
        let (ours, theirs) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || shim.serve_caller(theirs, Some(&dead)));
        let mut gpg = Gpg::new(ours);
        let turn = gpg.turn();
        assert!(turn.starts_with("ERR 67108941 credential-bridge: SSH_AUTH_SOCK "), "{turn}");
        assert!(turn.contains("reconnect"), "{turn}");
        handle.join().unwrap().unwrap();
        assert!(gpg.at_eof());
    }

    #[test]
    fn server_routes_connections_and_stops_on_killagent() {
        let dir = tempfile::tempdir().unwrap();
        let agent = bridge();
        let socket = dir.path().join("S.gpg-agent");
        let listener = credential_bridge_platform::socket::bind_private(&socket).unwrap();
        let shim = Arc::new(shim_with(dir.path(), Some(agent.path().to_owned())));
        let server = {
            let socket = socket.clone();
            std::thread::spawn(move || serve(listener, &socket, shim, Duration::from_secs(60)))
        };

        let mut first = Gpg::new(UnixStream::connect(&socket).unwrap());
        let mut second = Gpg::new(UnixStream::connect(&socket).unwrap());
        assert_eq!(first.turn(), "OK Pleased to meet you\n");
        assert_eq!(second.turn(), "OK Pleased to meet you\n");
        assert_eq!(second.ask(b"GETINFO version\n"), "D 2.4.8\nOK\n");
        assert_eq!(first.ask(b"KILLAGENT\n"), "OK closing connection\n");

        server.join().unwrap().unwrap();
        assert!(!socket.exists(), "the shim removes its socket");
    }

    #[test]
    fn server_exits_when_idle() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("S.gpg-agent");
        let listener = credential_bridge_platform::socket::bind_private(&socket).unwrap();
        let shim = Arc::new(shim_with(dir.path(), None));
        let started = Instant::now();
        serve(listener, &socket, shim, Duration::from_millis(200)).unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!socket.exists());
    }

    #[test]
    fn server_exits_when_its_socket_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("S.gpg-agent");
        let listener = credential_bridge_platform::socket::bind_private(&socket).unwrap();
        let shim = Arc::new(shim_with(dir.path(), None));
        let replacer = {
            let socket = socket.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                std::fs::remove_file(&socket).unwrap();
                UnixListener::bind(&socket).unwrap()
            })
        };
        let started = Instant::now();
        serve(listener, &socket, shim, Duration::from_secs(60)).unwrap();
        assert!(started.elapsed() < Duration::from_secs(10));
        let _replacement = replacer.join().unwrap();
        assert!(socket.exists(), "somebody else's socket stays");
    }

    #[test]
    fn bind_reports_a_running_agent() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("S.gpg-agent");
        let _running = UnixListener::bind(&socket).unwrap();
        assert!(bind_agent_socket(None, &socket).unwrap().is_none());
    }

    #[test]
    fn caller_auth_sock_needs_a_pid() {
        let peer = PeerCredentials { uid: current_uid(), pid: None };
        assert!(caller_auth_sock(&peer).is_err());
    }
}
