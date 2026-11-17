//! Request/response framing between `git-credential-bridge` and `credential-bridged`.

use std::fmt;
use std::io::{self, BufRead, Read, Write};
use std::str::FromStr;

use crate::credential::{Credential, ParseError, strip_eol};

/// Protocol identifier sent at the start of every frame.
pub const PROTOCOL: &str = "credential-bridge/1";

const MAX_HEADER_BYTES: u64 = 1024;
/// Longest status message, in bytes; together with the status line it stays
/// well below the header limit, whatever characters it contains.
pub const MAX_MESSAGE_BYTES: usize = 512;

/// What the remote side asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// Look up a credential (git `get`).
    Get,
    /// Store a credential that worked (git `store`).
    Store,
    /// Erase a credential that was rejected (git `erase`).
    Erase,
    /// Liveness check; never reaches a backend.
    Ping,
}

impl Operation {
    /// The operations that correspond to git credential helper actions.
    pub const CREDENTIAL_OPERATIONS: [Operation; 3] = [Operation::Get, Operation::Store, Operation::Erase];

    pub fn as_str(self) -> &'static str {
        match self {
            Operation::Get => "get",
            Operation::Store => "store",
            Operation::Erase => "erase",
            Operation::Ping => "ping",
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Operation {
    type Err = FrameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "get" => Ok(Operation::Get),
            "store" => Ok(Operation::Store),
            "erase" => Ok(Operation::Erase),
            "ping" => Ok(Operation::Ping),
            other => Err(FrameError::UnknownOperation(other.to_owned())),
        }
    }
}

/// Outcome reported by the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The request was processed; the credential may still be empty.
    Ok,
    /// The remote's policy does not permit the request.
    Denied,
    /// The request could not be processed.
    Error,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Denied => "denied",
            Status::Error => "error",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Status {
    type Err = FrameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ok" => Ok(Status::Ok),
            "denied" => Ok(Status::Denied),
            "error" => Ok(Status::Error),
            other => Err(FrameError::UnknownStatus(other.to_owned())),
        }
    }
}

/// Errors while reading a frame.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("connection closed before a frame was received")]
    Empty,
    #[error("malformed frame header")]
    BadHeader,
    #[error("unsupported protocol version {0:?} (expected {PROTOCOL})")]
    Version(String),
    #[error("unknown operation {0:?}")]
    UnknownOperation(String),
    #[error("unknown status {0:?}")]
    UnknownStatus(String),
    #[error(transparent)]
    Credential(#[from] ParseError),
}

/// A request from the remote helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub operation: Operation,
    pub credential: Credential,
}

impl Request {
    pub fn new(operation: Operation, credential: Credential) -> Self {
        Self { operation, credential }
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writeln!(writer, "{PROTOCOL} {}", self.operation)?;
        self.credential.write_to(writer)?;
        writer.write_all(b"\n")
    }

    pub fn read_from<R: BufRead>(reader: &mut R) -> Result<Self, FrameError> {
        let operation = read_header(reader)?.parse()?;
        let credential = Credential::read_from(reader)?;
        Ok(Self { operation, credential })
    }
}

/// The daemon's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: Status,
    /// Single-line, human-readable explanation.
    pub message: Option<String>,
    pub credential: Credential,
}

impl Response {
    pub fn ok(credential: Credential) -> Self {
        Self { status: Status::Ok, message: None, credential }
    }

    pub fn denied(message: impl Into<String>) -> Self {
        Self { status: Status::Denied, message: Some(message.into()), credential: Credential::new() }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self { status: Status::Error, message: Some(message.into()), credential: Credential::new() }
    }

    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        write!(writer, "{PROTOCOL} {}", self.status)?;
        if let Some(message) = &self.message {
            write!(writer, " {}", sanitize(message))?;
        }
        writer.write_all(b"\n")?;
        self.credential.write_to(writer)?;
        writer.write_all(b"\n")
    }

    pub fn read_from<R: BufRead>(reader: &mut R) -> Result<Self, FrameError> {
        let header = read_header(reader)?;
        let (status, message) = match header.split_once(' ') {
            Some((status, message)) => (status, Some(message.to_owned())),
            None => (header.as_str(), None),
        };
        let status = status.parse()?;
        let credential = Credential::read_from(reader)?;
        Ok(Self { status, message, credential })
    }
}

/// Reads the header line and returns everything after the protocol identifier.
fn read_header<R: BufRead>(reader: &mut R) -> Result<String, FrameError> {
    let mut buf = Vec::new();
    let read = reader.by_ref().take(MAX_HEADER_BYTES).read_until(b'\n', &mut buf)?;
    if read == 0 {
        return Err(FrameError::Empty);
    }
    if !buf.ends_with(b"\n") {
        return Err(FrameError::BadHeader);
    }
    let line = std::str::from_utf8(strip_eol(&buf)).map_err(|_| FrameError::BadHeader)?;
    let (protocol, rest) = line.split_once(' ').ok_or(FrameError::BadHeader)?;
    if protocol != PROTOCOL {
        return Err(if protocol.starts_with("credential-bridge/") {
            FrameError::Version(protocol.to_owned())
        } else {
            FrameError::BadHeader
        });
    }
    Ok(rest.to_owned())
}

fn sanitize(message: &str) -> String {
    let clean: String = message.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    crate::truncate(&clean, MAX_MESSAGE_BYTES).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multibyte_messages_survive_the_round_trip() {
        let response = Response::denied("ü".repeat(700));
        let mut buf = Vec::new();
        response.write_to(&mut buf).unwrap();
        let back = Response::read_from(&mut buf.as_slice()).unwrap();
        assert_eq!(back.status, Status::Denied);
        assert!(back.message.unwrap().len() <= MAX_MESSAGE_BYTES);
    }

    fn cred(pairs: &[(&str, &str)]) -> Credential {
        let mut cred = Credential::new();
        for (k, v) in pairs {
            cred.push(*k, *v);
        }
        cred
    }

    #[test]
    fn request_round_trip() {
        let request = Request::new(Operation::Get, cred(&[("protocol", "https"), ("host", "github.com")]));
        let mut buf = Vec::new();
        request.write_to(&mut buf).unwrap();
        assert_eq!(buf, b"credential-bridge/1 get\nprotocol=https\nhost=github.com\n\n");
        assert_eq!(Request::read_from(&mut buf.as_slice()).unwrap(), request);
    }

    #[test]
    fn empty_request_round_trip() {
        let request = Request::new(Operation::Ping, Credential::new());
        let mut buf = Vec::new();
        request.write_to(&mut buf).unwrap();
        assert_eq!(buf, b"credential-bridge/1 ping\n\n");
        assert_eq!(Request::read_from(&mut buf.as_slice()).unwrap(), request);
    }

    #[test]
    fn response_round_trip_with_message() {
        let response = Response::ok(cred(&[("username", "u"), ("password", "p")])).with_message("remote x");
        let mut buf = Vec::new();
        response.write_to(&mut buf).unwrap();
        assert_eq!(Response::read_from(&mut buf.as_slice()).unwrap(), response);
    }

    #[test]
    fn response_messages_stay_on_one_line() {
        let mut buf = Vec::new();
        Response::denied("line one\nhost=evil").write_to(&mut buf).unwrap();
        let parsed = Response::read_from(&mut buf.as_slice()).unwrap();
        assert_eq!(parsed.status, Status::Denied);
        assert_eq!(parsed.message.as_deref(), Some("line one host=evil"));
        assert!(parsed.credential.is_empty());
    }

    #[test]
    fn rejects_bad_headers() {
        assert!(matches!(Request::read_from(&mut &b""[..]), Err(FrameError::Empty)));
        assert!(matches!(Request::read_from(&mut &b"hello\n\n"[..]), Err(FrameError::BadHeader)));
        assert!(matches!(
            Request::read_from(&mut &b"credential-bridge/9 get\n\n"[..]),
            Err(FrameError::Version(_))
        ));
        assert!(matches!(
            Request::read_from(&mut &b"credential-bridge/1 steal\n\n"[..]),
            Err(FrameError::UnknownOperation(_))
        ));
    }
}
