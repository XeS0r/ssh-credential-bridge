//! Talking to the proxy through `SSH_AUTH_SOCK`.

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use credential_bridge_proto::agent::{AgentClient, AgentError};
use credential_bridge_proto::ext::{GIT_CREDENTIAL, GPG_AGENT};
use rustix::io::Errno;
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

/// Timeout for connecting.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Timeout for each request. Long, because the local side may wait for a touch, a PIN
/// or an approval dialog.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(180);

/// Name of the environment variable sshd sets for the forwarded agent.
pub const SSH_AUTH_SOCK: &str = "SSH_AUTH_SOCK";

/// Pause between connection attempts while the listener's backlog is full.
const CONNECT_RETRY: Duration = Duration::from_millis(5);

/// Connects to the agent at `socket` with the timeouts above.
///
/// Errors: [`AgentError::Io`] if the socket does not exist, refuses the connection, or
/// does not accept it within [`CONNECT_TIMEOUT`] ([`io::ErrorKind::TimedOut`]).
pub fn connect(socket: &Path) -> Result<AgentClient<UnixStream>, AgentError> {
    let stream = connect_stream(socket, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    Ok(AgentClient::new(stream))
}

/// Connects a unix stream socket without blocking longer than `timeout`.
///
/// A blocking `connect` on a unix socket can hang while the listener's backlog is full,
/// so the socket is non-blocking during the connect and switched back afterwards.
fn connect_stream(path: &Path, timeout: Duration) -> io::Result<UnixStream> {
    let addr = SocketAddrUnix::new(path)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let flags = SocketFlags::CLOEXEC | SocketFlags::NONBLOCK;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let flags = SocketFlags::empty();
    let socket = rustix::net::socket_with(AddressFamily::UNIX, SocketType::STREAM, flags, None)?;
    // Where the flags above are not available, set them now. The gpg shim starts
    // gpg-agent processes from other threads, which must not inherit this descriptor.
    rustix::io::fcntl_setfd(&socket, rustix::io::FdFlags::CLOEXEC)?;
    rustix::io::ioctl_fionbio(&socket, true)?;
    let deadline = Instant::now() + timeout;
    loop {
        match rustix::net::connect(&socket, &addr) {
            Ok(()) | Err(Errno::ISCONN) => break,
            // Linux answers EAGAIN while the backlog is full; other systems complete the
            // connect in the background (EINPROGRESS, then EALREADY until it is done).
            Err(Errno::AGAIN | Errno::INPROGRESS | Errno::ALREADY | Errno::INTR) => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("{}: the agent does not accept connections", path.display()),
                    ));
                }
                std::thread::sleep(CONNECT_RETRY);
            }
            Err(error) => return Err(error.into()),
        }
    }
    rustix::io::ioctl_fionbio(&socket, false)?;
    Ok(UnixStream::from(socket))
}

/// The extensions the agent behind `client` announces via `query`. An agent that
/// answers `query` with a failure supports none.
pub fn extensions(client: &mut AgentClient<UnixStream>) -> Result<Vec<String>, AgentError> {
    client.query_extensions()
}

/// Whether the agent at `socket` is a proxy that supports `extension` (via `query`).
/// Any error means no.
pub fn supports(socket: &Path, extension: &str) -> bool {
    connect(socket)
        .and_then(|mut client| extensions(&mut client))
        .is_ok_and(|names| names.iter().any(|name| name == extension))
}

/// `SSH_AUTH_SOCK` of this process, if set and not empty.
pub fn auth_sock_from_env() -> Option<PathBuf> {
    std::env::var_os(SSH_AUTH_SOCK).filter(|value| !value.is_empty()).map(PathBuf::from)
}

/// What `query` found out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryOutcome {
    /// `SSH_AUTH_SOCK` is not set: the session has no agent forwarding.
    NoAuthSock,
    /// The agent socket could not be reached (e.g. a dead socket in a tmux pane).
    Unreachable(String),
    /// An agent answered; these are the extensions it announced.
    Agent(Vec<String>),
}

impl QueryOutcome {
    /// Whether a credential-bridge proxy answered: at least one of our extensions.
    pub fn is_bridge(&self) -> bool {
        match self {
            QueryOutcome::Agent(names) => names.iter().any(|n| n == GIT_CREDENTIAL || n == GPG_AGENT),
            _ => false,
        }
    }
}

/// Asks the agent at `auth_sock` which extensions it supports.
pub fn query(auth_sock: Option<&Path>) -> QueryOutcome {
    let Some(socket) = auth_sock else {
        return QueryOutcome::NoAuthSock;
    };
    match connect(socket).and_then(|mut client| extensions(&mut client)) {
        Ok(names) => QueryOutcome::Agent(names),
        Err(error) => QueryOutcome::Unreachable(error.to_string()),
    }
}

/// Writes the human-readable report of `query` for `auth_sock` to `out` and returns
/// whether a credential-bridge proxy answered.
pub fn write_query_report<W: Write>(auth_sock: Option<&Path>, mut out: W) -> io::Result<bool> {
    let outcome = query(auth_sock);
    if let Some(socket) = auth_sock {
        writeln!(out, "agent:     {}", socket.display())?;
    }
    match &outcome {
        QueryOutcome::NoAuthSock => {
            writeln!(out, "agent:     none (SSH_AUTH_SOCK is not set; connect with agent forwarding)")?;
        }
        QueryOutcome::Unreachable(error) => {
            writeln!(out, "status:    unreachable: {error}")?;
            writeln!(out, "hint:      the ssh session that set SSH_AUTH_SOCK may be gone (tmux, screen)")?;
        }
        QueryOutcome::Agent(names) => {
            if names.is_empty() {
                writeln!(out, "extension: none")?;
            }
            for name in names {
                writeln!(out, "extension: {name}")?;
            }
        }
    }
    let bridge = outcome.is_bridge();
    if bridge {
        let mut offers = Vec::new();
        if let QueryOutcome::Agent(names) = &outcome {
            if names.iter().any(|n| n == GIT_CREDENTIAL) {
                offers.push("git credentials");
            }
            if names.iter().any(|n| n == GPG_AGENT) {
                offers.push("gpg");
            }
        }
        writeln!(out, "bridge:    yes ({})", offers.join(", "))?;
    } else {
        writeln!(out, "bridge:    no")?;
    }
    Ok(bridge)
}

/// `credential-bridge-remote query`.
pub fn query_main() -> ExitCode {
    let auth_sock = auth_sock_from_env();
    let stdout = io::stdout();
    match write_query_report(auth_sock.as_deref(), stdout.lock()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("credential-bridge-remote: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeAgent, query_only};
    use credential_bridge_proto::agent::Message;

    #[test]
    fn supports_finds_our_extension() {
        let agent = FakeAgent::start(query_only(&[GIT_CREDENTIAL, GPG_AGENT]));
        assert!(supports(agent.path(), GIT_CREDENTIAL));
        assert!(supports(agent.path(), GPG_AGENT));
        assert!(!supports(agent.path(), "other@example.com"));
    }

    #[test]
    fn plain_agent_supports_nothing() {
        let agent = FakeAgent::start(|_: &Message| Message::Failure);
        assert!(!supports(agent.path(), GIT_CREDENTIAL));
        assert_eq!(query(Some(agent.path())), QueryOutcome::Agent(vec![]));
    }

    #[test]
    fn missing_socket_is_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gone.sock");
        assert!(!supports(&path, GIT_CREDENTIAL));
        assert!(matches!(query(Some(&path)), QueryOutcome::Unreachable(_)));
        assert_eq!(query(None), QueryOutcome::NoAuthSock);
    }

    #[test]
    fn stale_socket_file_fails_fast() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stale.sock");
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        let started = Instant::now();
        let error = connect(&path).unwrap_err();
        assert!(started.elapsed() < CONNECT_TIMEOUT);
        let AgentError::Io(io) = error else { panic!("not an i/o error") };
        assert_eq!(io.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[test]
    fn report_names_the_offers() {
        let agent = FakeAgent::start(query_only(&["session-bind@openssh.com", GIT_CREDENTIAL]));
        let mut out = Vec::new();
        assert!(write_query_report(Some(agent.path()), &mut out).unwrap());
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("extension: git-credential@credential-bridge"), "{text}");
        assert!(text.contains("bridge:    yes (git credentials)"), "{text}");
    }

    #[test]
    fn report_without_agent() {
        let mut out = Vec::new();
        assert!(!write_query_report(None, &mut out).unwrap());
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("SSH_AUTH_SOCK is not set"), "{text}");
        assert!(text.contains("bridge:    no"), "{text}");
    }
}
