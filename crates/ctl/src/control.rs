//! A blocking client for the daemon's `control.sock`.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use credential_bridge_proto::ipc::control::{Request, Response};
use credential_bridge_proto::ipc::{self, IpcError, WorkerError, WorkerErrorKind};

/// Errors of control requests.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// The daemon is not running (no socket, or nobody accepts).
    #[error("the daemon is not running ({0}); start it with: credential-bridge-ctl daemon start")]
    NotRunning(std::io::Error),
    /// Framing failed; a version mismatch suggests restarting the service.
    #[error("talking to the daemon failed: {0}")]
    Ipc(#[from] IpcError),
    /// The daemon answered with an error (see [`daemon_message`]).
    #[error("{}", daemon_message(.0))]
    Daemon(WorkerError),
    /// The daemon answered with a response that does not fit the request.
    #[error("unexpected answer from the daemon")]
    Unexpected,
}

/// What ctl says for an error of the daemon: its message, which says what failed. A
/// [`WorkerErrorKind::Busy`] error is no refusal, so the user is told to try again.
fn daemon_message(error: &WorkerError) -> String {
    match error.kind {
        WorkerErrorKind::Busy => format!("{}; try again when it has finished", error.message),
        WorkerErrorKind::Locked
        | WorkerErrorKind::NotFound
        | WorkerErrorKind::Denied
        | WorkerErrorKind::Unavailable
        | WorkerErrorKind::Upstream
        | WorkerErrorKind::Timeout
        | WorkerErrorKind::Invalid
        | WorkerErrorKind::Internal => error.message.clone(),
    }
}

/// A connection to `control.sock`.
#[derive(Debug)]
pub struct ControlClient {
    /// The connection.
    stream: UnixStream,
}

impl ControlClient {
    /// Connects with `timeout` for connecting and for each request.
    pub fn connect(socket: &Path, timeout: Duration) -> Result<ControlClient, ControlError> {
        let stream = UnixStream::connect(socket).map_err(ControlError::NotRunning)?;
        stream.set_read_timeout(Some(timeout)).map_err(|error| ControlError::Ipc(error.into()))?;
        stream.set_write_timeout(Some(timeout)).map_err(|error| ControlError::Ipc(error.into()))?;
        Ok(ControlClient { stream })
    }

    /// Changes the timeout for the following requests (e.g. for an unlock that waits for
    /// a slow vault tool).
    pub fn set_timeout(&mut self, timeout: Duration) -> Result<(), ControlError> {
        self.stream.set_read_timeout(Some(timeout)).map_err(|error| ControlError::Ipc(error.into()))?;
        self.stream.set_write_timeout(Some(timeout)).map_err(|error| ControlError::Ipc(error.into()))?;
        Ok(())
    }

    /// Sends one request and reads the response. `Response::Error` becomes
    /// [`ControlError::Daemon`].
    pub fn request(&mut self, request: &Request) -> Result<Response, ControlError> {
        ipc::write_frame(&mut self.stream, request)?;
        match ipc::read_frame::<_, Response>(&mut self.stream)? {
            None => Err(ControlError::Ipc(IpcError::Truncated)),
            Some(Response::Error(error)) => Err(ControlError::Daemon(error)),
            Some(response) => Ok(response),
        }
    }

    /// Returns the underlying stream.
    pub fn into_inner(self) -> UnixStream {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use credential_bridge_proto::ipc::control::DaemonPaths;

    use super::*;

    /// Serves `answers` in order, one per request, on a socket in a temporary directory.
    fn serve(
        answers: Vec<Response>,
    ) -> (tempfile::TempDir, std::path::PathBuf, std::thread::JoinHandle<Vec<Request>>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            for answer in answers {
                let request: Request = ipc::read_frame(&mut stream).unwrap().unwrap();
                seen.push(request);
                ipc::write_frame(&mut stream, &answer).unwrap();
            }
            seen
        });
        (dir, path, handle)
    }

    #[test]
    fn requests_and_errors() {
        let error = WorkerError::new(WorkerErrorKind::Locked, "vault bitwarden is locked");
        let (_dir, path, handle) = serve(vec![
            Response::Pong { version: "0.1.0".into(), paths: DaemonPaths::default() },
            Response::Error(error.clone()),
        ]);
        let mut client = ControlClient::connect(&path, Duration::from_secs(5)).unwrap();
        assert_eq!(
            client.request(&Request::Ping).unwrap(),
            Response::Pong { version: "0.1.0".into(), paths: DaemonPaths::default() }
        );
        match client.request(&Request::Lock { vault: None }) {
            Err(ControlError::Daemon(got)) => assert_eq!(got, error),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(handle.join().unwrap(), vec![Request::Ping, Request::Lock { vault: None }]);
        // The server closed the connection.
        assert!(matches!(client.request(&Request::Ping), Err(ControlError::Ipc(_))));
    }

    /// A busy daemon is shown as "try again", other errors by their message alone.
    #[test]
    fn busy_errors_say_try_again() {
        let busy = WorkerError::new(WorkerErrorKind::Busy, "an unlock of bitwarden is already running");
        assert_eq!(
            ControlError::Daemon(busy).to_string(),
            "an unlock of bitwarden is already running; try again when it has finished"
        );
        let denied = WorkerError::new(WorkerErrorKind::Denied, "secret reference is read-only");
        assert_eq!(ControlError::Daemon(denied).to_string(), "secret reference is read-only");
    }

    #[test]
    fn missing_socket_is_not_running() {
        let dir = tempfile::tempdir().unwrap();
        let error =
            ControlClient::connect(&dir.path().join("none.sock"), Duration::from_secs(1)).unwrap_err();
        assert!(matches!(error, ControlError::NotRunning(_)));
        assert!(error.to_string().contains("daemon start"));
    }
}
