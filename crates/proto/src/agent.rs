//! The ssh-agent protocol (draft-miller-ssh-agent, OpenSSH `PROTOCOL.agent`).
//!
//! A frame is a big-endian `uint32` length followed by that many payload bytes; the
//! payload is one message type byte and the message body. Frames longer than
//! [`MAX_MESSAGE_LEN`] are rejected before any allocation, as in OpenSSH.
//!
//! **Raw-byte preservation.** [`Message`] keeps every field as the exact bytes it was
//! decoded from (key blobs, signatures, private key material, extension contents), so
//! for every payload `p` that [`Message::decode`] accepts,
//! `Message::decode(p)?.encode() == p`. The proxy relies on this to pass sign requests and
//! answers through unchanged. Messages the proxy does not interpret decode to
//! [`Message::Other`], which also re-encodes byte for byte.

use std::io::{Read, Write};

use crate::secret::SecretBytes;
use crate::wire::{Reader, WireError, Writer};

/// Largest accepted payload (type byte + body) in bytes: 256 KiB, as OpenSSH's
/// `AGENT_MAX_LEN`.
pub const MAX_MESSAGE_LEN: usize = 256 * 1024;

/// Message type numbers.
pub mod msg_type {
    /// `SSH_AGENT_FAILURE`
    pub const FAILURE: u8 = 5;
    /// `SSH_AGENT_SUCCESS`
    pub const SUCCESS: u8 = 6;
    /// `SSH_AGENTC_REQUEST_IDENTITIES`
    pub const REQUEST_IDENTITIES: u8 = 11;
    /// `SSH_AGENT_IDENTITIES_ANSWER`
    pub const IDENTITIES_ANSWER: u8 = 12;
    /// `SSH_AGENTC_SIGN_REQUEST`
    pub const SIGN_REQUEST: u8 = 13;
    /// `SSH_AGENT_SIGN_RESPONSE`
    pub const SIGN_RESPONSE: u8 = 14;
    /// `SSH_AGENTC_ADD_IDENTITY`
    pub const ADD_IDENTITY: u8 = 17;
    /// `SSH_AGENTC_REMOVE_IDENTITY`
    pub const REMOVE_IDENTITY: u8 = 18;
    /// `SSH_AGENTC_REMOVE_ALL_IDENTITIES`
    pub const REMOVE_ALL_IDENTITIES: u8 = 19;
    /// `SSH_AGENTC_ADD_SMARTCARD_KEY`
    pub const ADD_SMARTCARD_KEY: u8 = 20;
    /// `SSH_AGENTC_REMOVE_SMARTCARD_KEY`
    pub const REMOVE_SMARTCARD_KEY: u8 = 21;
    /// `SSH_AGENTC_LOCK`
    pub const LOCK: u8 = 22;
    /// `SSH_AGENTC_UNLOCK`
    pub const UNLOCK: u8 = 23;
    /// `SSH_AGENTC_ADD_ID_CONSTRAINED`
    pub const ADD_ID_CONSTRAINED: u8 = 25;
    /// `SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED`
    pub const ADD_SMARTCARD_KEY_CONSTRAINED: u8 = 26;
    /// `SSH_AGENTC_EXTENSION`
    pub const EXTENSION: u8 = 27;
    /// `SSH_AGENT_EXTENSION_FAILURE`
    pub const EXTENSION_FAILURE: u8 = 28;
    /// `SSH_AGENT_EXTENSION_RESPONSE` (draft; OpenSSH answers extensions with
    /// `SSH_AGENT_SUCCESS`). Decodes to [`super::Message::Other`].
    pub const EXTENSION_RESPONSE: u8 = 29;
}

/// Flags of `SSH_AGENTC_SIGN_REQUEST`.
pub mod sign_flags {
    /// `SSH_AGENT_RSA_SHA2_256`
    pub const RSA_SHA2_256: u32 = 2;
    /// `SSH_AGENT_RSA_SHA2_512`
    pub const RSA_SHA2_512: u32 = 4;
}

/// Errors of agent framing and message decoding.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// Reading or writing the stream failed.
    #[error("agent i/o: {0}")]
    Io(#[from] std::io::Error),
    /// The length prefix announced more than [`MAX_MESSAGE_LEN`] bytes.
    #[error("agent message of {len} bytes exceeds the limit")]
    TooLarge {
        /// The announced length.
        len: usize,
    },
    /// The stream ended inside a frame.
    #[error("agent stream ended inside a message")]
    Truncated,
    /// A frame with length 0 (no type byte).
    #[error("empty agent message")]
    Empty,
    /// A message of a known type whose body does not match its layout.
    #[error("malformed agent message of type {msg_type}: {source}")]
    Malformed {
        /// The message type byte.
        msg_type: u8,
        /// What was wrong.
        source: WireError,
    },
    /// The peer answered with a message that does not fit the request
    /// (e.g. no `SSH_AGENT_IDENTITIES_ANSWER` to `SSH_AGENTC_REQUEST_IDENTITIES`).
    #[error("unexpected agent reply of type {msg_type}")]
    UnexpectedReply {
        /// The type byte of the reply.
        msg_type: u8,
    },
}

/// Validates a frame header and returns the payload length that follows it.
///
/// Errors: [`AgentError::Empty`] for 0, [`AgentError::TooLarge`] above
/// [`MAX_MESSAGE_LEN`]. Async readers call this before allocating the payload buffer.
pub fn frame_len(header: [u8; 4]) -> Result<usize, AgentError> {
    let len = usize::try_from(u32::from_be_bytes(header)).unwrap_or(usize::MAX);
    check_len(len)?;
    Ok(len)
}

/// Rejects payload lengths outside `1..=MAX_MESSAGE_LEN`.
fn check_len(len: usize) -> Result<(), AgentError> {
    match len {
        0 => Err(AgentError::Empty),
        len if len > MAX_MESSAGE_LEN => Err(AgentError::TooLarge { len }),
        _ => Ok(()),
    }
}

/// Fills `buf` completely, retrying on `Interrupted`. Returns `Ok(false)` if the stream
/// ended before the first byte and `allow_eof` is set; an end of stream anywhere else is
/// an [`std::io::ErrorKind::UnexpectedEof`] error.
pub(crate) fn read_full<R: Read>(reader: &mut R, buf: &mut [u8], allow_eof: bool) -> std::io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 && allow_eof => return Ok(false),
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => filled += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(true)
}

/// Maps an unexpected end of stream to [`AgentError::Truncated`].
fn map_eof(err: std::io::Error) -> AgentError {
    if err.kind() == std::io::ErrorKind::UnexpectedEof { AgentError::Truncated } else { AgentError::Io(err) }
}

/// Reads one frame and returns its payload (type byte + body).
///
/// Returns `Ok(None)` on a clean end of stream before the first header byte and
/// [`AgentError::Truncated`] if the stream ends later inside the frame.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, AgentError> {
    let mut header = [0u8; 4];
    if !read_full(reader, &mut header, true).map_err(map_eof)? {
        return Ok(None);
    }
    let len = frame_len(header)?;
    let mut payload = vec![0u8; len];
    read_full(reader, &mut payload, false).map_err(map_eof)?;
    Ok(Some(payload))
}

/// [`read_frame`] into a buffer that is wiped when dropped.
fn read_frame_zeroizing<R: Read>(reader: &mut R) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, AgentError> {
    let mut header = [0u8; 4];
    if !read_full(reader, &mut header, true).map_err(map_eof)? {
        return Ok(None);
    }
    let len = frame_len(header)?;
    let mut payload = zeroize::Zeroizing::new(vec![0u8; len]);
    read_full(reader, &mut payload, false).map_err(map_eof)?;
    Ok(Some(payload))
}

/// Writes `payload` (type byte + body) as one frame.
///
/// Errors: [`AgentError::TooLarge`] if `payload` exceeds [`MAX_MESSAGE_LEN`],
/// [`AgentError::Empty`] if it is empty; nothing is written in those cases.
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), AgentError> {
    check_len(payload.len())?;
    // Header and payload are written separately so no unzeroized copy of a payload with
    // key material is made; callers wanting one write use a buffered writer.
    writer.write_all(&frame_header(payload.len()))?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

/// The length prefix for a payload of `len` bytes. Callers keep `len` within
/// [`MAX_MESSAGE_LEN`] or accept the saturated value for oversized payloads.
fn frame_header(len: usize) -> [u8; 4] {
    u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes()
}

/// One entry of `SSH_AGENT_IDENTITIES_ANSWER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The public key blob in SSH wire format, exactly as the upstream sent it.
    pub key_blob: Vec<u8>,
    /// The comment bytes as sent (not necessarily UTF-8).
    pub comment: Vec<u8>,
}

impl Identity {
    /// The comment as text, with invalid UTF-8 replaced.
    pub fn comment_lossy(&self) -> String {
        String::from_utf8_lossy(&self.comment).into_owned()
    }
}

/// A decoded agent message. See the module documentation for the raw-byte guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// `SSH_AGENTC_REQUEST_IDENTITIES` (no body).
    RequestIdentities,
    /// `SSH_AGENT_IDENTITIES_ANSWER`: `uint32 nkeys`, then `string key_blob`,
    /// `string comment` per key.
    IdentitiesAnswer(Vec<Identity>),
    /// `SSH_AGENTC_SIGN_REQUEST`: `string key_blob`, `string data`, `uint32 flags`.
    SignRequest {
        /// Public key blob of the key to sign with.
        key_blob: Vec<u8>,
        /// The data to sign.
        data: Vec<u8>,
        /// [`sign_flags`].
        flags: u32,
    },
    /// `SSH_AGENT_SIGN_RESPONSE`: `string signature`.
    SignResponse {
        /// The signature blob, passed on unchanged.
        signature: Vec<u8>,
    },
    /// `SSH_AGENTC_ADD_IDENTITY` or `SSH_AGENTC_ADD_ID_CONSTRAINED`. The private key and
    /// constraints are not interpreted; `body` is the message body after the type byte.
    AddIdentity {
        /// `true` for `SSH_AGENTC_ADD_ID_CONSTRAINED`.
        constrained: bool,
        /// The unparsed body (private key material).
        body: SecretBytes,
    },
    /// `SSH_AGENTC_REMOVE_IDENTITY`: `string key_blob`.
    RemoveIdentity {
        /// Public key blob of the key to remove.
        key_blob: Vec<u8>,
    },
    /// `SSH_AGENTC_REMOVE_ALL_IDENTITIES` (no body).
    RemoveAllIdentities,
    /// `SSH_AGENTC_ADD_SMARTCARD_KEY` or `..._CONSTRAINED` (`ssh-add -s`). The body (reader
    /// id, PIN, constraints) is not interpreted.
    AddSmartcardKey {
        /// `true` for `SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED`.
        constrained: bool,
        /// The unparsed body (contains the PIN).
        body: SecretBytes,
    },
    /// `SSH_AGENTC_REMOVE_SMARTCARD_KEY` (`ssh-add -e`). The body is not interpreted.
    RemoveSmartcardKey {
        /// The unparsed body (contains the PIN).
        body: SecretBytes,
    },
    /// `SSH_AGENTC_LOCK`: `string passphrase`.
    Lock {
        /// The lock passphrase.
        passphrase: SecretBytes,
    },
    /// `SSH_AGENTC_UNLOCK`: `string passphrase`.
    Unlock {
        /// The unlock passphrase.
        passphrase: SecretBytes,
    },
    /// `SSH_AGENTC_EXTENSION`: `string name`, then extension-specific contents up to the
    /// end of the message. Names that are not UTF-8 decode to [`Message::Other`].
    Extension {
        /// The extension name, e.g. `session-bind@openssh.com`.
        name: String,
        /// Everything after the name, unparsed.
        contents: Vec<u8>,
    },
    /// `SSH_AGENT_SUCCESS`, optionally followed by extension response contents (OpenSSH
    /// answers extensions this way). Empty for a plain success.
    Success {
        /// Bytes after the type byte.
        contents: Vec<u8>,
    },
    /// `SSH_AGENT_FAILURE` (no body).
    Failure,
    /// `SSH_AGENT_EXTENSION_FAILURE` (no body).
    ExtensionFailure,
    /// Any other type, or a type the proxy passes through without interpreting.
    Other {
        /// The message type byte.
        msg_type: u8,
        /// The body after the type byte.
        body: Vec<u8>,
    },
}

impl Message {
    /// Decodes one payload (type byte + body, without the length prefix).
    ///
    /// Errors: [`AgentError::Empty`] for an empty payload, [`AgentError::TooLarge`] above
    /// [`MAX_MESSAGE_LEN`], [`AgentError::Malformed`] when a known type's body does not
    /// match its layout (including trailing bytes where the layout has a fixed end).
    /// Unknown types never fail; they become [`Message::Other`].
    pub fn decode(payload: &[u8]) -> Result<Message, AgentError> {
        check_len(payload.len())?;
        let (&msg_type, body) = payload.split_first().ok_or(AgentError::Empty)?;
        Self::decode_body(msg_type, body).map_err(|source| AgentError::Malformed { msg_type, source })
    }

    /// Decodes the body of a message of type `msg_type`.
    fn decode_body(msg_type: u8, body: &[u8]) -> Result<Message, WireError> {
        let mut r = Reader::new(body);
        let message = match msg_type {
            msg_type::REQUEST_IDENTITIES => Message::RequestIdentities,
            msg_type::IDENTITIES_ANSWER => {
                let count = r.read_u32()?;
                // Every entry takes at least two length prefixes; reject impossible counts
                // before reserving memory for them.
                let count = usize::try_from(count).map_err(|_| WireError::Truncated)?;
                if count > r.remaining() / 8 {
                    return Err(WireError::Truncated);
                }
                let mut identities = Vec::with_capacity(count);
                for _ in 0..count {
                    let key_blob = r.read_string()?.to_vec();
                    let comment = r.read_string()?.to_vec();
                    identities.push(Identity { key_blob, comment });
                }
                Message::IdentitiesAnswer(identities)
            }
            msg_type::SIGN_REQUEST => Message::SignRequest {
                key_blob: r.read_string()?.to_vec(),
                data: r.read_string()?.to_vec(),
                flags: r.read_u32()?,
            },
            msg_type::SIGN_RESPONSE => Message::SignResponse { signature: r.read_string()?.to_vec() },
            msg_type::ADD_IDENTITY | msg_type::ADD_ID_CONSTRAINED => Message::AddIdentity {
                constrained: msg_type == msg_type::ADD_ID_CONSTRAINED,
                body: SecretBytes::new(r.read_rest().to_vec()),
            },
            msg_type::REMOVE_IDENTITY => Message::RemoveIdentity { key_blob: r.read_string()?.to_vec() },
            msg_type::REMOVE_ALL_IDENTITIES => Message::RemoveAllIdentities,
            msg_type::ADD_SMARTCARD_KEY | msg_type::ADD_SMARTCARD_KEY_CONSTRAINED => {
                Message::AddSmartcardKey {
                    constrained: msg_type == msg_type::ADD_SMARTCARD_KEY_CONSTRAINED,
                    body: SecretBytes::new(r.read_rest().to_vec()),
                }
            }
            msg_type::REMOVE_SMARTCARD_KEY => {
                Message::RemoveSmartcardKey { body: SecretBytes::new(r.read_rest().to_vec()) }
            }
            msg_type::LOCK => Message::Lock { passphrase: SecretBytes::new(r.read_string()?.to_vec()) },
            msg_type::UNLOCK => Message::Unlock { passphrase: SecretBytes::new(r.read_string()?.to_vec()) },
            msg_type::EXTENSION => {
                let name = r.read_string()?;
                let contents = r.read_rest().to_vec();
                match std::str::from_utf8(name) {
                    Ok(name) => Message::Extension { name: name.to_owned(), contents },
                    Err(_) => return Ok(Message::Other { msg_type, body: body.to_vec() }),
                }
            }
            msg_type::SUCCESS => Message::Success { contents: r.read_rest().to_vec() },
            msg_type::FAILURE => Message::Failure,
            msg_type::EXTENSION_FAILURE => Message::ExtensionFailure,
            _ => Message::Other { msg_type, body: r.read_rest().to_vec() },
        };
        r.finish()?;
        Ok(message)
    }

    /// Encodes to a payload (type byte + body, without the length prefix). Inverse of
    /// [`Message::decode`] byte for byte.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode_into(&mut w);
        w.into_bytes()
    }

    /// Like [`Message::encode`], for messages that may carry secrets (private keys in
    /// `ADD_IDENTITY`, lock passphrases, extension requests and replies): the buffer is allocated once at its final size
    /// and wiped when dropped.
    pub fn encode_zeroizing(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let body = match self {
            Message::AddIdentity { body, .. }
            | Message::AddSmartcardKey { body, .. }
            | Message::RemoveSmartcardKey { body } => body.expose().len(),
            Message::Lock { passphrase } | Message::Unlock { passphrase } => 4 + passphrase.expose().len(),
            // Extension traffic: gpg-agent output, inquiry answers, git credentials.
            Message::Extension { name, contents } => 4 + name.len() + contents.len(),
            Message::Success { contents } => contents.len(),
            _ => 0,
        };
        let mut w = Writer::with_capacity(1 + body);
        self.encode_into(&mut w);
        zeroize::Zeroizing::new(w.into_bytes())
    }

    /// Appends the payload to `w`.
    fn encode_into(&self, w: &mut Writer) {
        w.put_u8(self.msg_type());
        match self {
            Message::RequestIdentities
            | Message::RemoveAllIdentities
            | Message::Failure
            | Message::ExtensionFailure => {}
            Message::IdentitiesAnswer(identities) => {
                w.put_u32(u32::try_from(identities.len()).expect("more than u32::MAX identities"));
                for identity in identities {
                    w.put_string(&identity.key_blob).put_string(&identity.comment);
                }
            }
            Message::SignRequest { key_blob, data, flags } => {
                w.put_string(key_blob).put_string(data).put_u32(*flags);
            }
            Message::SignResponse { signature } => {
                w.put_string(signature);
            }
            Message::AddIdentity { body, .. }
            | Message::AddSmartcardKey { body, .. }
            | Message::RemoveSmartcardKey { body } => {
                w.put_raw(body.expose());
            }
            Message::RemoveIdentity { key_blob } => {
                w.put_string(key_blob);
            }
            Message::Lock { passphrase } | Message::Unlock { passphrase } => {
                w.put_string(passphrase.expose());
            }
            Message::Extension { name, contents } => {
                w.put_string(name.as_bytes()).put_raw(contents);
            }
            Message::Success { contents } => {
                w.put_raw(contents);
            }
            Message::Other { body, .. } => {
                w.put_raw(body);
            }
        }
    }

    /// Encodes to a complete frame (length prefix + payload).
    pub fn to_frame(&self) -> Vec<u8> {
        let payload = self.encode();
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&frame_header(payload.len()));
        frame.extend_from_slice(&payload);
        frame
    }

    /// The message type byte this message encodes to.
    pub fn msg_type(&self) -> u8 {
        match self {
            Message::RequestIdentities => msg_type::REQUEST_IDENTITIES,
            Message::IdentitiesAnswer(_) => msg_type::IDENTITIES_ANSWER,
            Message::SignRequest { .. } => msg_type::SIGN_REQUEST,
            Message::SignResponse { .. } => msg_type::SIGN_RESPONSE,
            Message::AddIdentity { constrained: false, .. } => msg_type::ADD_IDENTITY,
            Message::AddIdentity { constrained: true, .. } => msg_type::ADD_ID_CONSTRAINED,
            Message::RemoveIdentity { .. } => msg_type::REMOVE_IDENTITY,
            Message::RemoveAllIdentities => msg_type::REMOVE_ALL_IDENTITIES,
            Message::AddSmartcardKey { constrained: false, .. } => msg_type::ADD_SMARTCARD_KEY,
            Message::AddSmartcardKey { constrained: true, .. } => msg_type::ADD_SMARTCARD_KEY_CONSTRAINED,
            Message::RemoveSmartcardKey { .. } => msg_type::REMOVE_SMARTCARD_KEY,
            Message::Lock { .. } => msg_type::LOCK,
            Message::Unlock { .. } => msg_type::UNLOCK,
            Message::Extension { .. } => msg_type::EXTENSION,
            Message::Success { .. } => msg_type::SUCCESS,
            Message::Failure => msg_type::FAILURE,
            Message::ExtensionFailure => msg_type::EXTENSION_FAILURE,
            Message::Other { msg_type, .. } => *msg_type,
        }
    }

    /// Whether this is an agent write command (add/remove identities, smartcard keys,
    /// lock/unlock). The proxy refuses these on `agent-forward.sock`. Types 17-26 count as
    /// write commands even when they arrive as [`Message::Other`] (e.g. type 24, unused).
    pub fn is_write_command(&self) -> bool {
        (msg_type::ADD_IDENTITY..=msg_type::ADD_SMARTCARD_KEY_CONSTRAINED).contains(&self.msg_type())
    }
}

/// The reply to an `SSH_AGENTC_EXTENSION` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionReply {
    /// `SSH_AGENT_SUCCESS` with the response contents (possibly empty), wiped when
    /// dropped: they may carry tokens or gpg-agent output.
    Success(zeroize::Zeroizing<Vec<u8>>),
    /// `SSH_AGENT_FAILURE`: the agent does not know the extension (OpenSSH's ssh-agent
    /// answers so), refused the request, or does not support extensions at all.
    Failure,
    /// `SSH_AGENT_EXTENSION_FAILURE`: the agent knows the extension but the request
    /// failed (for credential-bridge: a payload of a version it does not understand).
    ExtensionFailure,
}

/// A blocking agent client over any byte stream (a unix socket on the server side, a
/// pipe in tests). One request is in flight at a time, as the protocol requires.
#[derive(Debug)]
pub struct AgentClient<S> {
    /// The connection to the agent.
    stream: S,
}

impl<S: Read + Write> AgentClient<S> {
    /// Wraps a connected stream.
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Sends `request` and reads one reply.
    ///
    /// Errors: framing and decoding errors as [`read_frame`]/[`Message::decode`];
    /// [`AgentError::Truncated`] if the agent closes the connection instead of replying.
    pub fn request(&mut self, request: &Message) -> Result<Message, AgentError> {
        write_frame(&mut self.stream, &request.encode())?;
        let reply = read_frame(&mut self.stream)?.ok_or(AgentError::Truncated)?;
        Message::decode(&reply)
    }

    /// `SSH_AGENTC_REQUEST_IDENTITIES`. Errors with [`AgentError::UnexpectedReply`] on
    /// anything but an identities answer.
    pub fn identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        match self.request(&Message::RequestIdentities)? {
            Message::IdentitiesAnswer(identities) => Ok(identities),
            other => Err(AgentError::UnexpectedReply { msg_type: other.msg_type() }),
        }
    }

    /// Sends extension `name` with `contents` and classifies the reply.
    ///
    /// Besides `SSH_AGENT_SUCCESS`, the draft's `SSH_AGENT_EXTENSION_RESPONSE` (`string
    /// name`, then the contents) counts as success when it repeats `name`; its contents
    /// are returned without the name. Errors with [`AgentError::UnexpectedReply`] on any
    /// other reply type, or an extension response for another name.
    ///
    /// Extension requests and replies may carry secrets (inquiry answers, gpg-agent
    /// output, git credentials): every buffer that holds them is allocated once at its
    /// final size and wiped when dropped.
    pub fn extension(&mut self, name: &str, contents: &[u8]) -> Result<ExtensionReply, AgentError> {
        let mut w = Writer::with_capacity(1 + 4 + name.len() + contents.len());
        w.put_u8(msg_type::EXTENSION).put_string(name.as_bytes()).put_raw(contents);
        let request = zeroize::Zeroizing::new(w.into_bytes());
        write_frame(&mut self.stream, &request)?;
        let reply = read_frame_zeroizing(&mut self.stream)?.ok_or(AgentError::Truncated)?;
        let secret = |bytes: &[u8]| zeroize::Zeroizing::new(bytes.to_vec());
        match reply.split_first() {
            Some((&msg_type::SUCCESS, contents)) => Ok(ExtensionReply::Success(secret(contents))),
            Some((&msg_type::EXTENSION_RESPONSE, body)) => {
                let mut r = Reader::new(body);
                match r.read_string() {
                    Ok(reply_name) if reply_name == name.as_bytes() => {
                        Ok(ExtensionReply::Success(secret(r.read_rest())))
                    }
                    _ => Err(AgentError::UnexpectedReply { msg_type: msg_type::EXTENSION_RESPONSE }),
                }
            }
            // Carry nothing secret; decoded as usual (a FAILURE with a body is an error).
            _ => match Message::decode(&reply)? {
                Message::Failure => Ok(ExtensionReply::Failure),
                Message::ExtensionFailure => Ok(ExtensionReply::ExtensionFailure),
                other => Err(AgentError::UnexpectedReply { msg_type: other.msg_type() }),
            },
        }
    }

    /// Asks which extensions the agent supports with the standard `query` extension
    /// ([`crate::ext::QUERY`]). An agent that answers `SSH_AGENT_FAILURE` or
    /// `SSH_AGENT_EXTENSION_FAILURE` supports none: `Ok(vec![])`.
    ///
    /// Both reply forms are accepted: `SSH_AGENT_SUCCESS` with the names, and OpenSSH's
    /// `SSH_AGENT_EXTENSION_RESPONSE` with `string "query"` before the names. Names that
    /// are not UTF-8 cannot be ours and are skipped. A reply whose contents are not a
    /// sequence of strings is [`AgentError::Malformed`] with type `SSH_AGENT_SUCCESS`.
    pub fn query_extensions(&mut self) -> Result<Vec<String>, AgentError> {
        match self.extension(crate::ext::QUERY, &[])? {
            ExtensionReply::Success(contents) => {
                let names = crate::ext::query_reply_names(&contents)
                    .map_err(|source| AgentError::Malformed { msg_type: msg_type::SUCCESS, source })?;
                Ok(names
                    .into_iter()
                    .filter_map(|name| std::str::from_utf8(name).ok().map(str::to_owned))
                    .collect())
            }
            ExtensionReply::Failure | ExtensionReply::ExtensionFailure => Ok(Vec::new()),
        }
    }

    /// Returns the underlying stream.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::wire::Writer;

    /// A stream that replays canned agent output and records what the client wrote.
    struct FakeAgent {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl FakeAgent {
        fn replying(replies: &[Message]) -> Self {
            let input = replies.iter().flat_map(Message::to_frame).collect();
            Self { input: Cursor::new(input), output: Vec::new() }
        }
    }

    impl Read for FakeAgent {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for FakeAgent {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn payload(msg_type: u8, build: impl FnOnce(&mut Writer)) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_u8(msg_type);
        build(&mut w);
        w.into_bytes()
    }

    fn assert_round_trip(payload: &[u8]) -> Message {
        let message = Message::decode(payload).unwrap();
        assert_eq!(message.encode(), payload, "{message:?}");
        message
    }

    #[test]
    fn decodes_known_types_and_keeps_bytes() {
        let answer = payload(msg_type::IDENTITIES_ANSWER, |w| {
            w.put_u32(2)
                .put_string(b"blob1")
                .put_string(b"one")
                .put_string(b"blob2")
                .put_string(&[0xff, 0xfe]);
        });
        let Message::IdentitiesAnswer(ids) = assert_round_trip(&answer) else { panic!() };
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[1].comment_lossy(), "\u{fffd}\u{fffd}");

        let sign = payload(msg_type::SIGN_REQUEST, |w| {
            w.put_string(b"key").put_string(b"data").put_u32(sign_flags::RSA_SHA2_512);
        });
        assert_eq!(
            assert_round_trip(&sign),
            Message::SignRequest { key_blob: b"key".to_vec(), data: b"data".to_vec(), flags: 4 }
        );

        let response = payload(msg_type::SIGN_RESPONSE, |w| {
            w.put_string(b"sig");
        });
        assert_eq!(assert_round_trip(&response), Message::SignResponse { signature: b"sig".to_vec() });

        let ext = payload(msg_type::EXTENSION, |w| {
            w.put_string(b"query").put_raw(b"\x00rest");
        });
        assert_eq!(
            assert_round_trip(&ext),
            Message::Extension { name: "query".into(), contents: b"\x00rest".to_vec() }
        );

        let add = payload(msg_type::ADD_ID_CONSTRAINED, |w| {
            w.put_string(b"ssh-ed25519").put_raw(b"secret material");
        });
        let Message::AddIdentity { constrained: true, body } = assert_round_trip(&add) else { panic!() };
        assert!(!format!("{body:?}").contains("secret"));

        for simple in [msg_type::REQUEST_IDENTITIES, msg_type::REMOVE_ALL_IDENTITIES, msg_type::FAILURE] {
            assert_round_trip(&[simple]);
        }
        assert_eq!(assert_round_trip(&[msg_type::EXTENSION_FAILURE]), Message::ExtensionFailure);
        assert_eq!(assert_round_trip(&[msg_type::SUCCESS, 1, 2]), Message::Success { contents: vec![1, 2] });
        let lock = payload(msg_type::LOCK, |w| {
            w.put_string(b"pw");
        });
        assert!(matches!(assert_round_trip(&lock), Message::Lock { .. }));
        for raw in [
            msg_type::ADD_SMARTCARD_KEY,
            msg_type::ADD_SMARTCARD_KEY_CONSTRAINED,
            msg_type::REMOVE_SMARTCARD_KEY,
        ] {
            assert!(assert_round_trip(&[raw, 0, 0, 0, 1, b'x', 9]).is_write_command());
        }
    }

    #[test]
    fn unknown_types_and_non_utf8_names_are_other() {
        assert_eq!(assert_round_trip(&[200, 1, 2, 3]), Message::Other { msg_type: 200, body: vec![1, 2, 3] });
        assert!(matches!(
            assert_round_trip(&[msg_type::EXTENSION_RESPONSE, 0]),
            Message::Other { msg_type: 29, .. }
        ));
        let ext = payload(msg_type::EXTENSION, |w| {
            w.put_string(&[0xc3, 0x28]).put_raw(b"x");
        });
        assert!(matches!(assert_round_trip(&ext), Message::Other { msg_type: msg_type::EXTENSION, .. }));
    }

    #[test]
    fn rejects_malformed_bodies() {
        let malformed = |p: &[u8]| matches!(Message::decode(p), Err(AgentError::Malformed { .. }));
        assert!(malformed(&[msg_type::REQUEST_IDENTITIES, 0]));
        assert!(malformed(&[msg_type::FAILURE, 0]));
        assert!(malformed(&[msg_type::SIGN_RESPONSE, 0, 0, 0, 2, 1]));
        assert!(malformed(&payload(msg_type::SIGN_REQUEST, |w| {
            w.put_string(b"k").put_string(b"d");
        })));
        assert!(malformed(&payload(msg_type::SIGN_REQUEST, |w| {
            w.put_string(b"k").put_string(b"d").put_u32(0).put_u8(0);
        })));
        assert!(malformed(&payload(msg_type::EXTENSION, |w| {
            w.put_u32(10).put_raw(b"abc");
        })));
        // An identity count that cannot fit the body is refused before allocating.
        assert!(malformed(&payload(msg_type::IDENTITIES_ANSWER, |w| {
            w.put_u32(u32::MAX);
        })));
        assert!(matches!(Message::decode(&[]), Err(AgentError::Empty)));
        let huge = vec![msg_type::SUCCESS; MAX_MESSAGE_LEN + 1];
        assert!(matches!(Message::decode(&huge), Err(AgentError::TooLarge { .. })));
        assert!(Message::decode(&huge[..MAX_MESSAGE_LEN]).is_ok());
    }

    #[test]
    fn framing_limits() {
        assert!(matches!(frame_len([0, 0, 0, 0]), Err(AgentError::Empty)));
        assert!(matches!(frame_len([0xff; 4]), Err(AgentError::TooLarge { .. })));
        assert_eq!(frame_len(256u32.to_be_bytes()).unwrap(), 256);
        assert_eq!(frame_len((MAX_MESSAGE_LEN as u32).to_be_bytes()).unwrap(), MAX_MESSAGE_LEN);
        assert!(matches!(
            frame_len((MAX_MESSAGE_LEN as u32 + 1).to_be_bytes()),
            Err(AgentError::TooLarge { .. })
        ));

        let mut out = Vec::new();
        assert!(matches!(write_frame(&mut out, &[]), Err(AgentError::Empty)));
        assert!(matches!(
            write_frame(&mut out, &vec![0; MAX_MESSAGE_LEN + 1]),
            Err(AgentError::TooLarge { .. })
        ));
        assert!(out.is_empty());
        write_frame(&mut out, &[11]).unwrap();
        assert_eq!(out, [0, 0, 0, 1, 11]);
    }

    #[test]
    fn reads_frames_and_detects_truncation() {
        let mut stream = Cursor::new(vec![0, 0, 0, 2, 6, 7, 0, 0, 0, 1, 5]);
        assert_eq!(read_frame(&mut stream).unwrap(), Some(vec![6, 7]));
        assert_eq!(read_frame(&mut stream).unwrap(), Some(vec![5]));
        assert_eq!(read_frame(&mut stream).unwrap(), None);
        assert!(matches!(read_frame(&mut Cursor::new(vec![0, 0])), Err(AgentError::Truncated)));
        assert!(matches!(read_frame(&mut Cursor::new(vec![0, 0, 0, 3, 1])), Err(AgentError::Truncated)));
        assert!(matches!(
            read_frame(&mut Cursor::new(vec![0x7f, 0, 0, 0])),
            Err(AgentError::TooLarge { .. })
        ));
    }

    #[test]
    fn to_frame_prefixes_the_length() {
        let frame = Message::RequestIdentities.to_frame();
        assert_eq!(frame, [0, 0, 0, 1, msg_type::REQUEST_IDENTITIES]);
    }

    #[test]
    fn client_requests_identities() {
        let id = Identity { key_blob: b"blob".to_vec(), comment: b"me".to_vec() };
        let mut client =
            AgentClient::new(FakeAgent::replying(&[Message::IdentitiesAnswer(vec![id.clone()])]));
        assert_eq!(client.identities().unwrap(), vec![id]);
        assert_eq!(client.into_inner().output, Message::RequestIdentities.to_frame());

        let mut client = AgentClient::new(FakeAgent::replying(&[Message::Failure]));
        assert!(matches!(
            client.identities(),
            Err(AgentError::UnexpectedReply { msg_type: msg_type::FAILURE })
        ));

        let mut client = AgentClient::new(FakeAgent::replying(&[]));
        assert!(matches!(client.identities(), Err(AgentError::Truncated)));
    }

    #[test]
    fn client_classifies_extension_replies() {
        let replies = [
            Message::Success { contents: b"ok".to_vec() },
            Message::Failure,
            Message::ExtensionFailure,
            Message::Other {
                msg_type: msg_type::EXTENSION_RESPONSE,
                body: [&[0, 0, 0, 1][..], b"x", b"tail"].concat(),
            },
            Message::Other {
                msg_type: msg_type::EXTENSION_RESPONSE,
                body: [&[0, 0, 0, 1][..], b"y"].concat(),
            },
            Message::RequestIdentities,
        ];
        let mut client = AgentClient::new(FakeAgent::replying(&replies));
        assert_eq!(client.extension("x", b"in").unwrap(), ExtensionReply::Success(b"ok".to_vec().into()));
        assert_eq!(client.extension("x", b"").unwrap(), ExtensionReply::Failure);
        assert_eq!(client.extension("x", b"").unwrap(), ExtensionReply::ExtensionFailure);
        assert_eq!(client.extension("x", b"").unwrap(), ExtensionReply::Success(b"tail".to_vec().into()));
        assert!(matches!(client.extension("x", b""), Err(AgentError::UnexpectedReply { .. })));
        assert!(matches!(client.extension("x", b""), Err(AgentError::UnexpectedReply { .. })));
        let sent = client.into_inner().output;
        let first = Message::Extension { name: "x".into(), contents: b"in".to_vec() }.to_frame();
        assert_eq!(&sent[..first.len()], first);
    }

    #[test]
    fn query_extensions_accepts_both_reply_forms() {
        let names = crate::ext::encode_query_reply(&["a@b", "c"]);
        let replies = [
            Message::Success { contents: names },
            crate::ext::query_response(&["session-bind@openssh.com"]),
            Message::Failure,
            Message::ExtensionFailure,
            Message::Success { contents: vec![0, 0, 0, 9] },
        ];
        let mut client = AgentClient::new(FakeAgent::replying(&replies));
        assert_eq!(client.query_extensions().unwrap(), ["a@b", "c"]);
        assert_eq!(client.query_extensions().unwrap(), ["session-bind@openssh.com"]);
        assert!(client.query_extensions().unwrap().is_empty());
        assert!(client.query_extensions().unwrap().is_empty());
        assert!(matches!(client.query_extensions(), Err(AgentError::Malformed { .. })));
    }

    #[test]
    fn write_commands_are_types_17_to_26() {
        let add = Message::AddIdentity { constrained: true, body: SecretBytes::default() };
        assert!(add.is_write_command());
        assert!(Message::Lock { passphrase: SecretBytes::default() }.is_write_command());
        assert!(Message::Other { msg_type: 24, body: vec![] }.is_write_command());
        assert!(!Message::RequestIdentities.is_write_command());
        let ext = Message::Extension { name: "query".into(), contents: vec![] };
        assert!(!ext.is_write_command());
    }
}
