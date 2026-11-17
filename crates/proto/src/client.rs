//! Blocking client for one request/response exchange over a unix socket.

use std::io::{self, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{FrameError, Request, Response};

/// Errors while talking to the daemon.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("cannot connect to {}: {source}", .path.display())]
    Connect {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("I/O error talking to credential-bridged: {0}")]
    Io(#[from] io::Error),
    #[error("invalid response from credential-bridged: {0}")]
    Frame(#[from] FrameError),
}

/// Sends `request` to the socket at `socket` and waits for the response.
///
/// `timeout` applies to each read and write; `None` waits forever.
pub fn exchange(
    socket: &Path,
    request: &Request,
    timeout: Option<Duration>,
) -> Result<Response, ClientError> {
    let mut stream = UnixStream::connect(socket)
        .map_err(|source| ClientError::Connect { path: socket.to_owned(), source })?;
    let timeout = timeout.filter(|t| !t.is_zero());
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;

    let mut frame = Vec::new();
    request.write_to(&mut frame)?;
    stream.write_all(&frame)?;
    stream.shutdown(Shutdown::Write)?;

    Ok(Response::read_from(&mut BufReader::new(stream))?)
}
