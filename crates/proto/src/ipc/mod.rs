//! Versioned frames between the core and its workers, and between ctl and the core.
//!
//! **Frame:** big-endian `uint32` length `n`, then `n` bytes: one version byte
//! ([`IPC_VERSION`]) followed by the message as JSON (`serde_json`). `n` includes the
//! version byte and is at most [`MAX_IPC_FRAME`]. A frame with another version is a fatal
//! channel error: core and workers are always the same binary, ctl and daemon may differ
//! and ctl then tells the user to restart the service.
//!
//! **Worker channel:** one stream `socketpair` per worker. The core sends
//! [`ToWorker`]`<Req>`, the worker sends [`FromWorker`]`<Resp>`, where `Req`/`Resp` are
//! the per-worker types in [`git`], [`vault`] and [`gpg`]. Requests carry an id chosen by
//! the core; several requests may be in flight and responses may come in any order. A
//! worker may ask the core for something it must not do itself ([`Callback`]), with an
//! id chosen by the worker; the core answers with [`ToWorker::CallbackReply`].
//!
//! **Control channel:** ctl sends one [`control::Request`] per frame on `control.sock`
//! and reads one [`control::Response`]; requests on one connection are sequential.
//!
//! **File descriptors:** the gpg worker receives each gpg-agent connection as an
//! `SCM_RIGHTS` file descriptor attached to the `sendmsg` that carries the first byte of
//! the frame with [`gpg::Request::Open`]. No other frame carries descriptors.

pub mod control;
pub mod git;
pub mod gpg;
pub mod vault;

use std::fmt;
use std::io::{Read, Write};
use std::str::FromStr;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::secret::Secret;

/// Version byte of every IPC frame.
pub const IPC_VERSION: u8 = 1;

/// Largest frame body (version byte + JSON) in bytes: 1 MiB.
pub const MAX_IPC_FRAME: usize = 1024 * 1024;

/// Id of a request (chosen by the sender of the request) or callback (chosen by the
/// worker). Unique among the sender's in-flight requests.
pub type RequestId = u64;

/// Errors of IPC framing.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// Reading or writing failed.
    #[error("ipc i/o: {0}")]
    Io(#[from] std::io::Error),
    /// The frame length is 0 or above [`MAX_IPC_FRAME`], or the encoded message is.
    #[error("ipc frame of {0} bytes is out of range")]
    FrameSize(usize),
    /// The version byte is not [`IPC_VERSION`].
    #[error("ipc version {0} is not supported")]
    Version(u8),
    /// The JSON body does not match the expected type.
    #[error("ipc decode: {0}")]
    Decode(#[from] serde_json::Error),
    /// The stream ended inside a frame.
    #[error("ipc stream ended inside a frame")]
    Truncated,
}

/// Validates a frame header and returns the body length that follows it.
/// Errors: [`IpcError::FrameSize`].
pub fn frame_len(header: [u8; 4]) -> Result<usize, IpcError> {
    let len = usize::try_from(u32::from_be_bytes(header)).unwrap_or(usize::MAX);
    check_len(len)?;
    Ok(len)
}

/// Rejects body lengths outside `1..=MAX_IPC_FRAME`.
fn check_len(len: usize) -> Result<(), IpcError> {
    if len == 0 || len > MAX_IPC_FRAME { Err(IpcError::FrameSize(len)) } else { Ok(()) }
}

/// Maps an unexpected end of stream to [`IpcError::Truncated`].
fn map_eof(err: std::io::Error) -> IpcError {
    if err.kind() == std::io::ErrorKind::UnexpectedEof { IpcError::Truncated } else { IpcError::Io(err) }
}

/// Encodes `message` to a complete frame (length prefix, version byte, JSON).
/// Errors: [`IpcError::FrameSize`] if the result would exceed [`MAX_IPC_FRAME`];
/// [`IpcError::Decode`] if `message` cannot be serialized (e.g. a map with non-string
/// keys).
pub fn encode_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, IpcError> {
    // Serialized straight into the frame buffer behind a placeholder header. Frames may
    // carry secrets, so the buffer is wiped when it is not handed out, and it grows only
    // into new buffers, wiping the old ones (no copy is left behind in freed memory).
    let mut writer = WipingWriter(zeroize::Zeroizing::new(Vec::with_capacity(256)));
    writer.0.extend_from_slice(&[0, 0, 0, 0, IPC_VERSION]);
    serde_json::to_writer(&mut writer, message).map_err(IpcError::Decode)?;
    let mut frame = std::mem::take(&mut *writer.0);
    let body_len = frame.len() - 4;
    if let Err(err) = check_len(body_len) {
        zeroize::Zeroize::zeroize(&mut frame);
        return Err(err);
    }
    let header = u32::try_from(body_len).expect("checked against MAX_IPC_FRAME").to_be_bytes();
    frame[..4].copy_from_slice(&header);
    Ok(frame)
}

/// An [`std::io::Write`] into a wiped buffer that never reallocates in place.
struct WipingWriter(zeroize::Zeroizing<Vec<u8>>);

impl std::io::Write for WipingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let needed = self.0.len() + bytes.len();
        if needed > self.0.capacity() {
            let mut larger = zeroize::Zeroizing::new(Vec::with_capacity(needed.max(self.0.capacity() * 2)));
            larger.extend_from_slice(&self.0);
            // The old buffer is wiped as it is dropped here.
            self.0 = larger;
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Decodes a frame body (version byte + JSON, without the length prefix).
/// Errors: [`IpcError::Version`], [`IpcError::Decode`], [`IpcError::FrameSize`] if empty.
pub fn decode_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, IpcError> {
    let (&version, json) = body.split_first().ok_or(IpcError::FrameSize(0))?;
    if version != IPC_VERSION {
        return Err(IpcError::Version(version));
    }
    Ok(serde_json::from_slice(json)?)
}

/// Reads one frame. `Ok(None)` on a clean end of stream before the header;
/// [`IpcError::Truncated`] inside a frame.
pub fn read_frame<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<Option<T>, IpcError> {
    let mut header = [0u8; 4];
    if !crate::agent::read_full(reader, &mut header, true).map_err(map_eof)? {
        return Ok(None);
    }
    let len = frame_len(header)?;
    // The body may contain secrets (resolved tokens, passwords).
    let mut body = zeroize::Zeroizing::new(vec![0u8; len]);
    crate::agent::read_full(reader, &mut body, false).map_err(map_eof)?;
    decode_body(&body).map(Some)
}

/// Writes one frame.
pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, message: &T) -> Result<(), IpcError> {
    let frame = zeroize::Zeroizing::new(encode_frame(message)?);
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

/// The three worker kinds. The string form is the argument of
/// `credential-bridged worker <kind>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkerKind {
    /// Mints and caches git tokens (sandboxed: TCP 443 only).
    Git,
    /// Runs gh, git helpers and vault CLIs (not sandboxed).
    Vault,
    /// Filters Assuan traffic to gpg-agent (sandboxed: no file system).
    Gpg,
}

impl WorkerKind {
    /// `git`, `vault` or `gpg`.
    pub fn as_str(self) -> &'static str {
        match self {
            WorkerKind::Git => "git",
            WorkerKind::Vault => "vault",
            WorkerKind::Gpg => "gpg",
        }
    }
}

impl fmt::Display for WorkerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error of parsing a [`WorkerKind`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown worker kind {0:?}")]
pub struct UnknownWorkerKind(pub String);

impl FromStr for WorkerKind {
    type Err = UnknownWorkerKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "git" => Ok(WorkerKind::Git),
            "vault" => Ok(WorkerKind::Vault),
            "gpg" => Ok(WorkerKind::Gpg),
            other => Err(UnknownWorkerKind(other.to_owned())),
        }
    }
}

/// Core to worker.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ToWorker<Req> {
    /// A request; the worker answers with [`FromWorker::Response`] with the same id.
    Request {
        /// Chosen by the core.
        id: RequestId,
        /// The worker-specific request.
        body: Req,
    },
    /// The answer to [`FromWorker::Callback`] with the same id.
    CallbackReply {
        /// The worker's callback id.
        id: RequestId,
        /// The result.
        result: Result<CallbackReply, WorkerError>,
    },
    /// Finish in-flight requests, drop secrets and exit.
    Shutdown,
}

/// Worker to core.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FromWorker<Resp> {
    /// First frame after start: the worker has set up its sandbox. `degraded` names
    /// sandbox layers the kernel lacked (logged by the core), empty if all applied.
    Ready {
        /// Human-readable notes, one per missing layer.
        degraded: Vec<String>,
    },
    /// The answer to [`ToWorker::Request`] with the same id.
    Response {
        /// The core's request id.
        id: RequestId,
        /// The result.
        result: Result<Resp, WorkerError>,
    },
    /// The worker needs something from the core to finish request `for_request`.
    Callback {
        /// Chosen by the worker.
        id: RequestId,
        /// The request this callback belongs to (for timeouts and audit).
        for_request: RequestId,
        /// What is needed.
        body: Callback,
    },
}

/// What a worker may ask the core for. Only the git worker uses callbacks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Callback {
    /// Resolve a secret reference (as written in the configuration, e.g.
    /// `op://Dev/bridge-app/private-key`). The core forwards it to the vault worker.
    Secret {
        /// The reference string.
        reference: String,
    },
}

/// The core's answer to a [`Callback`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallbackReply {
    /// The resolved secret.
    Secret(Secret),
}

/// A failure reported across IPC. `message` must be safe to show to the user and on the
/// server: it never contains secret values or upstream message contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{kind:?}: {message}")]
pub struct WorkerError {
    /// The category, used by the core for policy (e.g. `Locked` is not retried).
    pub kind: WorkerErrorKind,
    /// Human-readable explanation, e.g.
    /// `vault bitwarden is locked: run credential-bridge-ctl vault unlock bitwarden`.
    pub message: String,
}

impl WorkerError {
    /// Builds an error.
    pub fn new(kind: WorkerErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into() }
    }
}

/// Categories of [`WorkerError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WorkerErrorKind {
    /// A vault is locked; the message says how to unlock it.
    Locked,
    /// The reference, item, installation or credential does not exist.
    NotFound,
    /// Refused by policy or by the remote service (e.g. GitHub 403).
    Denied,
    /// Another operation on the same thing is running (an unlock of the same vault);
    /// the same request may succeed once it has finished. Not a refusal.
    Busy,
    /// A needed tool or service is missing or unreachable (`op` not installed, no D-Bus).
    Unavailable,
    /// The remote service or tool failed (HTTP 5xx, non-zero exit).
    Upstream,
    /// A deadline passed.
    Timeout,
    /// The request is malformed or names something unknown to the worker.
    Invalid,
    /// A bug or unexpected state in the worker.
    Internal,
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    type GitToWorker = ToWorker<git::Request>;

    fn token_request() -> git::TokenRequest {
        git::TokenRequest {
            source_name: "my-org".into(),
            source: git::SourceSpec::GithubApp {
                app_id: 1,
                private_key: "op://Dev/app/key".into(),
                api_url: "https://api.github.com".into(),
            },
            target: git::TokenTarget {
                protocol: "https".into(),
                host: "github.com".into(),
                path: Some("o/r.git".into()),
            },
            permissions: [("contents".to_owned(), git::Access::Write)].into(),
            per: git::TokenScope::Repo,
            cache: true,
        }
    }

    #[test]
    fn frame_layout_and_round_trip() {
        let message: GitToWorker = ToWorker::Request { id: 7, body: git::Request::Get(token_request()) };
        let frame = encode_frame(&message).unwrap();
        let len = frame_len(frame[..4].try_into().unwrap()).unwrap();
        assert_eq!(len, frame.len() - 4);
        assert_eq!(frame[4], IPC_VERSION);
        assert!(frame[5..].starts_with(b"{"));
        let back: GitToWorker = decode_body(&frame[4..]).unwrap();
        assert_eq!(back, message);
    }

    #[test]
    fn stream_round_trip() {
        let messages: Vec<FromWorker<git::Response>> = vec![
            FromWorker::Ready { degraded: vec!["landlock network rules".into()] },
            FromWorker::Callback {
                id: 1,
                for_request: 7,
                body: Callback::Secret { reference: "op://x".into() },
            },
            FromWorker::Response {
                id: 7,
                result: Ok(git::Response::Token(git::GitToken {
                    username: "x-access-token".into(),
                    password: Secret::new("ghs_secret".into()),
                    expires_at: Some(10),
                })),
            },
            FromWorker::Response {
                id: 8,
                result: Err(WorkerError::new(WorkerErrorKind::Locked, "vault bw is locked")),
            },
        ];
        let mut buf = Vec::new();
        for message in &messages {
            write_frame(&mut buf, message).unwrap();
        }
        let mut reader = Cursor::new(buf);
        for message in &messages {
            let read: FromWorker<git::Response> = read_frame(&mut reader).unwrap().unwrap();
            assert_eq!(&read, message);
        }
        assert!(read_frame::<_, FromWorker<git::Response>>(&mut reader).unwrap().is_none());
    }

    #[test]
    fn control_messages_round_trip() {
        let requests = [
            control::Request::Ping,
            control::Request::Keys { server: None },
            control::Request::Unlock {
                vault: "bitwarden".into(),
                password: Secret::new("pw".into()),
                ttl_secs: Some(60),
            },
            control::Request::SourceTest { source: "work".into() },
        ];
        for request in requests {
            let frame = encode_frame(&request).unwrap();
            assert_eq!(decode_body::<control::Request>(&frame[4..]).unwrap(), request);
        }
        let responses = [
            control::Response::Error(WorkerError::new(WorkerErrorKind::Invalid, "bad")),
            control::Response::SourceTested(vec![
                control::SourceCheck { what: "op://Dev/github/token".into(), error: None },
                control::SourceCheck {
                    what: "bw://ci/token".into(),
                    error: Some(WorkerError::new(WorkerErrorKind::Locked, "vault bitwarden is locked")),
                },
            ]),
        ];
        for response in responses {
            let frame = encode_frame(&response).unwrap();
            assert_eq!(decode_body::<control::Response>(&frame[4..]).unwrap(), response);
        }
    }

    /// Kinds travel as their plain names, like every other unit variant.
    #[test]
    fn error_kinds_are_plain_names() {
        let error = WorkerError::new(WorkerErrorKind::Busy, "an unlock of bitwarden is already running");
        let json = serde_json::to_string(&error).unwrap();
        assert_eq!(json, r#"{"kind":"Busy","message":"an unlock of bitwarden is already running"}"#);
        assert_eq!(serde_json::from_str::<WorkerError>(&json).unwrap(), error);
        assert_eq!(serde_json::to_string(&WorkerErrorKind::Denied).unwrap(), r#""Denied""#);
    }

    #[test]
    fn rejects_bad_frames() {
        assert!(matches!(frame_len([0; 4]), Err(IpcError::FrameSize(0))));
        assert!(matches!(frame_len(((MAX_IPC_FRAME + 1) as u32).to_be_bytes()), Err(IpcError::FrameSize(_))));
        assert_eq!(frame_len((MAX_IPC_FRAME as u32).to_be_bytes()).unwrap(), MAX_IPC_FRAME);
        assert!(matches!(decode_body::<control::Request>(&[]), Err(IpcError::FrameSize(0))));
        assert!(matches!(decode_body::<control::Request>(b"\x02\"Ping\""), Err(IpcError::Version(2))));
        assert!(matches!(decode_body::<control::Request>(b"\x01\"Pong\""), Err(IpcError::Decode(_))));
        assert_eq!(decode_body::<control::Request>(b"\x01\"Ping\"").unwrap(), control::Request::Ping);

        let huge = "x".repeat(MAX_IPC_FRAME);
        assert!(matches!(encode_frame(&huge), Err(IpcError::FrameSize(_))));
        let mut out = Vec::new();
        assert!(write_frame(&mut out, &huge).is_err());
        assert!(out.is_empty());

        let read = |bytes: Vec<u8>| read_frame::<_, control::Request>(&mut Cursor::new(bytes));
        assert!(matches!(read(vec![0, 0]), Err(IpcError::Truncated)));
        assert!(matches!(read(vec![0, 0, 0, 5, 1]), Err(IpcError::Truncated)));
        assert!(matches!(read(vec![0xff, 0, 0, 0]), Err(IpcError::FrameSize(_))));
    }

    #[test]
    fn worker_kind_strings() {
        for kind in [WorkerKind::Git, WorkerKind::Vault, WorkerKind::Gpg] {
            assert_eq!(kind.as_str().parse::<WorkerKind>().unwrap(), kind);
            assert_eq!(serde_json::to_string(&kind).unwrap(), format!("\"{kind}\""));
        }
        assert_eq!("ssh".parse::<WorkerKind>(), Err(UnknownWorkerKind("ssh".into())));
    }

    #[test]
    fn secrets_stay_out_of_debug_output() {
        let message: ToWorker<git::Request> = ToWorker::CallbackReply {
            id: 1,
            result: Ok(CallbackReply::Secret(Secret::new("private-key-pem".into()))),
        };
        assert!(!format!("{message:?}").contains("private-key-pem"));
    }
}
