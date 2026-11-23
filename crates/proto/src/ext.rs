//! Agent extensions: the standard `query`, `session-bind@openssh.com` (name only, see
//! `bind`) and credential-bridge's own `*@credential-bridge` extensions.
//!
//! Every credential-bridge payload starts with a version byte, [`VERSION`]. A receiver
//! that sees another version answers `SSH_AGENT_EXTENSION_FAILURE` (proxy) or treats the
//! reply as "no bridge" (remote). Requests travel as the contents of
//! `SSH_AGENTC_EXTENSION` after the name; replies as the contents of `SSH_AGENT_SUCCESS`.
//!
//! Wire layouts (SSH wire types, see [`crate::wire`]):
//!
//! | Message               | Layout                                                      |
//! | --------------------- | ----------------------------------------------------------- |
//! | `query` request       | empty                                                       |
//! | `query` reply         | `string` per supported extension name, to the end           |
//! | git request           | `byte version`, `byte action`, `string credential`          |
//! | git reply             | `byte version`, `byte status`, `string credential\|message` |
//! | gpg request           | `byte version`, `byte op`, `string data`                    |
//! | gpg reply             | `byte version`, `byte status`, `string data\|message`       |
//!
//! `credential` is the git attribute text of [`crate::credential`]. Numeric codes are the
//! `#[repr(u8)]` values of [`GitAction`], [`GitStatus`], [`GpgOp`] and [`GpgStatus`].
//! Statuses without a message or data (`NoMatch`, `Erased`, `Closed`) and the requests
//! `Open` and `Close` carry an empty `string`; anything else there is rejected.
//!
//! **`query` reply forms.** draft-miller-ssh-agent originally answered `query` with
//! `SSH_AGENT_SUCCESS` and the names; OpenSSH's `ssh-agent` and the current IETF draft
//! answer with `SSH_AGENT_EXTENSION_RESPONSE`, `string "query"`, then the names.
//! [`encode_query_reply`] produces the bare name list (for `SSH_AGENT_SUCCESS`),
//! [`query_response`] the OpenSSH form; [`crate::agent::AgentClient::query_extensions`]
//! accepts both.

use crate::agent::{Message, msg_type};
use crate::credential::{Credential, CredentialError};
use crate::wire::{Reader, WireError, Writer};

use zeroize::Zeroizing;

/// Name of the git credential extension.
pub const GIT_CREDENTIAL: &str = "git-credential@credential-bridge";
/// Name of the gpg-agent tunnel extension.
pub const GPG_AGENT: &str = "gpg-agent@credential-bridge";
/// Name of the standard extension that lists supported extensions.
pub const QUERY: &str = "query";
/// Name of OpenSSH's session binding extension.
pub const SESSION_BIND: &str = "session-bind@openssh.com";

/// Version byte at the start of every `*@credential-bridge` payload.
pub const VERSION: u8 = 1;

/// Largest data chunk in one gpg request or reply; well below the agent message limit.
pub const MAX_GPG_CHUNK: usize = 64 * 1024;

/// Errors of decoding extension payloads.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExtError {
    /// The payload carries a version other than [`VERSION`].
    #[error("unsupported extension version {0}")]
    Version(u8),
    /// A code byte that does not name an action, op or status.
    #[error("unknown code {0}")]
    UnknownCode(u8),
    /// The layout does not match (including trailing bytes).
    #[error("malformed extension payload: {0}")]
    Malformed(#[from] WireError),
    /// The embedded credential text is invalid.
    #[error("invalid credential: {0}")]
    Credential(#[from] CredentialError),
    /// A message is not valid UTF-8.
    #[error("extension text is not UTF-8")]
    InvalidUtf8,
    /// A gpg data chunk exceeds [`MAX_GPG_CHUNK`].
    #[error("gpg chunk too large")]
    ChunkTooLarge,
}

/// Encodes the reply to `query`: one `string` per name.
pub fn encode_query_reply(names: &[&str]) -> Vec<u8> {
    let mut w = Writer::new();
    for name in names {
        w.put_string(name.as_bytes());
    }
    w.into_bytes()
}

/// Decodes the reply to `query`. Errors with [`ExtError::Malformed`] or
/// [`ExtError::InvalidUtf8`].
pub fn decode_query_reply(contents: &[u8]) -> Result<Vec<String>, ExtError> {
    query_reply_names(contents)?
        .into_iter()
        .map(|name| std::str::from_utf8(name).map(str::to_owned).map_err(|_| ExtError::InvalidUtf8))
        .collect()
}

/// Splits `query` reply contents into the raw names, without requiring UTF-8.
pub fn query_reply_names(contents: &[u8]) -> Result<Vec<&[u8]>, WireError> {
    let mut r = Reader::new(contents);
    let mut names = Vec::new();
    while r.remaining() > 0 {
        names.push(r.read_string()?);
    }
    Ok(names)
}

/// The complete answer to `query` in OpenSSH's form: `SSH_AGENT_EXTENSION_RESPONSE`,
/// `string "query"`, one `string` per name.
pub fn query_response(names: &[&str]) -> Message {
    let mut body = Writer::new();
    body.put_string(QUERY.as_bytes()).put_raw(&encode_query_reply(names));
    Message::Other { msg_type: msg_type::EXTENSION_RESPONSE, body: body.into_bytes() }
}

/// Reads `byte version`, `byte code`, `string payload` and checks the version and the end.
fn decode_versioned(contents: &[u8]) -> Result<(u8, &[u8]), ExtError> {
    let mut r = Reader::new(contents);
    let version = r.read_u8()?;
    if version != VERSION {
        return Err(ExtError::Version(version));
    }
    let code = r.read_u8()?;
    let payload = r.read_string()?;
    r.finish()?;
    Ok((code, payload))
}

/// Writes `byte version`, `byte code`, `string payload`.
fn encode_versioned(code: u8, payload: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u8(VERSION).put_u8(code).put_string(payload);
    w.into_bytes()
}

/// [`encode_versioned`] into a buffer allocated once at its final size and wiped when
/// dropped, for gpg traffic (signatures, decrypted session keys, inquiry answers).
fn encode_versioned_zeroizing(code: u8, payload: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut w = Writer::with_capacity(2 + 4 + payload.len());
    w.put_u8(VERSION).put_u8(code).put_string(payload);
    Zeroizing::new(w.into_bytes())
}

/// Requires an empty payload for codes that carry nothing.
fn expect_empty(payload: &[u8]) -> Result<(), ExtError> {
    match payload.len() {
        0 => Ok(()),
        n => Err(ExtError::Malformed(WireError::TrailingBytes(n))),
    }
}

/// Decodes a user-facing message.
fn decode_text(payload: &[u8]) -> Result<String, ExtError> {
    std::str::from_utf8(payload).map(str::to_owned).map_err(|_| ExtError::InvalidUtf8)
}

/// Checks a gpg data chunk against [`MAX_GPG_CHUNK`].
fn check_chunk(data: &[u8]) -> Result<&[u8], ExtError> {
    if data.len() > MAX_GPG_CHUNK { Err(ExtError::ChunkTooLarge) } else { Ok(data) }
}

/// What git asked the helper to do. `store` is never sent: the helper ignores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GitAction {
    /// `git credential get`.
    Get = 0,
    /// `git credential erase`: drop cached tokens for this target.
    Erase = 1,
}

/// A `git-credential@credential-bridge` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRequest {
    /// The action.
    pub action: GitAction,
    /// What git sent on stdin (protocol, host, path, maybe username).
    pub credential: Credential,
}

impl GitRequest {
    /// Encodes the extension contents (after the name).
    pub fn encode(&self) -> Result<Vec<u8>, ExtError> {
        Ok(encode_versioned(self.action as u8, &self.credential.to_bytes()?))
    }

    /// Decodes the extension contents. Errors: see [`ExtError`].
    pub fn decode(contents: &[u8]) -> Result<GitRequest, ExtError> {
        let (code, payload) = decode_versioned(contents)?;
        let action = match code {
            0 => GitAction::Get,
            1 => GitAction::Erase,
            other => return Err(ExtError::UnknownCode(other)),
        };
        let credential = Credential::parse(payload)?;
        credential.check_writable()?;
        Ok(GitRequest { action, credential })
    }
}

/// Status byte of a git reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GitStatus {
    /// A credential follows.
    Credential = 0,
    /// No rule matched; the helper answers nothing so git tries the next helper.
    NoMatch = 1,
    /// The request was refused by policy (no forwarding bind, hop without `git`); a
    /// message for the user follows.
    Denied = 2,
    /// Resolving failed (locked vault, GitHub error); a message for the user follows.
    Failed = 3,
    /// `erase` was processed.
    Erased = 4,
}

/// A `git-credential@credential-bridge` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitReply {
    /// The credential to print to git (username, password, maybe expiry).
    Credential(Credential),
    /// No matching rule.
    NoMatch,
    /// Refused by policy, with a message safe to show on the server.
    Denied(String),
    /// Failed, with a message safe to show on the server, e.g.
    /// `vault bitwarden is locked: run credential-bridge-ctl vault unlock bitwarden`.
    Failed(String),
    /// `erase` done.
    Erased,
}

impl GitReply {
    /// Encodes the reply contents (inside `SSH_AGENT_SUCCESS`).
    pub fn encode(&self) -> Result<Vec<u8>, ExtError> {
        Ok(match self {
            GitReply::Credential(credential) => {
                encode_versioned(GitStatus::Credential as u8, &credential.to_bytes()?)
            }
            GitReply::NoMatch => encode_versioned(GitStatus::NoMatch as u8, &[]),
            GitReply::Denied(message) => encode_versioned(GitStatus::Denied as u8, message.as_bytes()),
            GitReply::Failed(message) => encode_versioned(GitStatus::Failed as u8, message.as_bytes()),
            GitReply::Erased => encode_versioned(GitStatus::Erased as u8, &[]),
        })
    }

    /// Decodes reply contents. Errors: see [`ExtError`].
    pub fn decode(contents: &[u8]) -> Result<GitReply, ExtError> {
        let (code, payload) = decode_versioned(contents)?;
        match code {
            0 => {
                let credential = Credential::parse(payload)?;
                credential.check_writable()?;
                Ok(GitReply::Credential(credential))
            }
            1 => expect_empty(payload).map(|()| GitReply::NoMatch),
            2 => decode_text(payload).map(GitReply::Denied),
            3 => decode_text(payload).map(GitReply::Failed),
            4 => expect_empty(payload).map(|()| GitReply::Erased),
            other => Err(ExtError::UnknownCode(other)),
        }
    }
}

/// Operation byte of a gpg request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GpgOp {
    /// Open the gpg-agent connection for this agent connection; data is empty.
    Open = 0,
    /// One unit of client traffic (see the gpg crate's framing); data is the bytes.
    Input = 1,
    /// Close the gpg-agent connection; data is empty.
    Close = 2,
}

/// A `gpg-agent@credential-bridge` request. One agent connection carries at most one
/// gpg-agent connection: `Open` once, then `Input`s, then `Close` or end of connection.
///
/// The bytes may hold inquiry answers, so they are wiped when the request is dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GpgRequest {
    /// Open the tunnel.
    Open,
    /// Client bytes: one Assuan command line, or one inquiry answer (`D` lines + `END`
    /// or `CAN`), at most [`MAX_GPG_CHUNK`] bytes.
    Input(Zeroizing<Vec<u8>>),
    /// Close the tunnel.
    Close,
}

impl GpgRequest {
    /// Encodes the extension contents (after the name), wiped when dropped.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ExtError> {
        Ok(match self {
            GpgRequest::Open => encode_versioned_zeroizing(GpgOp::Open as u8, &[]),
            GpgRequest::Input(data) => encode_versioned_zeroizing(GpgOp::Input as u8, check_chunk(data)?),
            GpgRequest::Close => encode_versioned_zeroizing(GpgOp::Close as u8, &[]),
        })
    }

    /// Decodes the extension contents. Errors: see [`ExtError`].
    pub fn decode(contents: &[u8]) -> Result<GpgRequest, ExtError> {
        let (code, payload) = decode_versioned(contents)?;
        match code {
            0 => expect_empty(payload).map(|()| GpgRequest::Open),
            1 => Ok(GpgRequest::Input(Zeroizing::new(check_chunk(payload)?.to_vec()))),
            2 => expect_empty(payload).map(|()| GpgRequest::Close),
            other => Err(ExtError::UnknownCode(other)),
        }
    }
}

/// Status byte of a gpg reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GpgStatus {
    /// Tunnel open; data is gpg-agent's greeting line(s).
    Opened = 0,
    /// Data is gpg-agent output up to and including the next `OK`, `ERR` or `INQUIRE`
    /// line, or a filter `ERR` line produced by the proxy.
    Output = 1,
    /// Tunnel closed; data is empty.
    Closed = 2,
    /// The tunnel failed or was refused; data is a message for the user.
    Failed = 3,
}

/// A `gpg-agent@credential-bridge` reply. gpg-agent's output (signatures, decrypted
/// session keys) is wiped when the reply is dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GpgReply {
    /// See [`GpgStatus::Opened`].
    Opened(Zeroizing<Vec<u8>>),
    /// See [`GpgStatus::Output`].
    Output(Zeroizing<Vec<u8>>),
    /// See [`GpgStatus::Closed`].
    Closed,
    /// See [`GpgStatus::Failed`].
    Failed(String),
}

impl GpgReply {
    /// Encodes the reply contents (inside `SSH_AGENT_SUCCESS`), wiped when dropped.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ExtError> {
        Ok(match self {
            GpgReply::Opened(data) => encode_versioned_zeroizing(GpgStatus::Opened as u8, check_chunk(data)?),
            GpgReply::Output(data) => encode_versioned_zeroizing(GpgStatus::Output as u8, check_chunk(data)?),
            GpgReply::Closed => encode_versioned_zeroizing(GpgStatus::Closed as u8, &[]),
            GpgReply::Failed(message) => {
                encode_versioned_zeroizing(GpgStatus::Failed as u8, message.as_bytes())
            }
        })
    }

    /// Decodes reply contents. Errors: see [`ExtError`].
    pub fn decode(contents: &[u8]) -> Result<GpgReply, ExtError> {
        let (code, payload) = decode_versioned(contents)?;
        match code {
            0 => Ok(GpgReply::Opened(Zeroizing::new(check_chunk(payload)?.to_vec()))),
            1 => Ok(GpgReply::Output(Zeroizing::new(check_chunk(payload)?.to_vec()))),
            2 => expect_empty(payload).map(|()| GpgReply::Closed),
            3 => decode_text(payload).map(GpgReply::Failed),
            other => Err(ExtError::UnknownCode(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn git_messages_with_unwritable_values_are_rejected() {
        // Found by fuzzing: `parse` keeps a value ending in `\r`, which `encode` refuses.
        let request = encode_versioned(GitAction::Erase as u8, b"path=a\r\r\n");
        assert!(GitRequest::decode(&request).is_err());
        let reply = encode_versioned(GitStatus::Credential as u8, b"password=a\r\r\n");
        assert!(GitReply::decode(&reply).is_err());
    }

    use super::*;
    use crate::secret::Secret;

    fn credential() -> Credential {
        Credential {
            protocol: Some("https".into()),
            host: Some("github.com".into()),
            path: Some("my-org/app.git".into()),
            ..Credential::default()
        }
    }

    #[test]
    fn query_reply_round_trip() {
        let names = [GIT_CREDENTIAL, GPG_AGENT, SESSION_BIND];
        let encoded = encode_query_reply(&names);
        assert_eq!(decode_query_reply(&encoded).unwrap(), names);
        assert!(decode_query_reply(&[]).unwrap().is_empty());
        assert_eq!(decode_query_reply(&[0, 0, 0, 2, b'a']), Err(ExtError::Malformed(WireError::Truncated)));
        assert_eq!(decode_query_reply(&[0, 0, 0, 1, 0xff]), Err(ExtError::InvalidUtf8));
    }

    #[test]
    fn query_response_matches_openssh_layout() {
        let message = query_response(&["session-bind@openssh.com"]);
        let mut expected = vec![msg_type::EXTENSION_RESPONSE, 0, 0, 0, 5];
        expected.extend_from_slice(b"query");
        expected.extend_from_slice(&[0, 0, 0, 24]);
        expected.extend_from_slice(b"session-bind@openssh.com");
        assert_eq!(message.encode(), expected);
    }

    #[test]
    fn git_request_layout() {
        let request = GitRequest { action: GitAction::Erase, credential: credential() };
        let encoded = request.encode().unwrap();
        assert_eq!(&encoded[..2], [VERSION, 1]);
        let text = b"protocol=https\nhost=github.com\npath=my-org/app.git\n";
        assert_eq!(&encoded[2..6], (text.len() as u32).to_be_bytes());
        assert_eq!(&encoded[6..], text);
        assert_eq!(GitRequest::decode(&encoded).unwrap(), request);
    }

    #[test]
    fn git_request_errors() {
        assert_eq!(GitRequest::decode(&[2, 0, 0, 0, 0, 0]), Err(ExtError::Version(2)));
        assert_eq!(GitRequest::decode(&[VERSION, 7, 0, 0, 0, 0]), Err(ExtError::UnknownCode(7)));
        assert_eq!(GitRequest::decode(&[]), Err(ExtError::Malformed(WireError::Truncated)));
        assert_eq!(
            GitRequest::decode(&[VERSION, 0, 0, 0, 0, 0, 9]),
            Err(ExtError::Malformed(WireError::TrailingBytes(1)))
        );
        let mut bad = vec![VERSION, 0, 0, 0, 0, 3];
        bad.extend_from_slice(b"abc");
        assert!(matches!(GitRequest::decode(&bad), Err(ExtError::Credential(_))));
        let mut invalid = credential();
        invalid.host = Some("evil\nhost=x".into());
        assert!(matches!(
            GitRequest { action: GitAction::Get, credential: invalid }.encode(),
            Err(ExtError::Credential(CredentialError::InvalidValue { key: "host" }))
        ));
    }

    #[test]
    fn git_reply_round_trip() {
        let mut token = credential();
        token.username = Some("x-access-token".into());
        token.password = Some(Secret::new("ghs_abc".into()));
        token.password_expiry_utc = Some(1_700_000_000);
        for reply in [
            GitReply::Credential(token),
            GitReply::NoMatch,
            GitReply::Denied("no forwarding bind".into()),
            GitReply::Failed(
                "vault bitwarden is locked: run credential-bridge-ctl vault unlock bitwarden".into(),
            ),
            GitReply::Erased,
        ] {
            let encoded = reply.encode().unwrap();
            assert_eq!(encoded[0], VERSION);
            assert_eq!(GitReply::decode(&encoded).unwrap(), reply);
        }
        assert_eq!(GitReply::decode(&[VERSION, 5, 0, 0, 0, 0]), Err(ExtError::UnknownCode(5)));
        assert_eq!(GitReply::decode(&[VERSION, 2, 0, 0, 0, 1, 0xff]), Err(ExtError::InvalidUtf8));
        assert_eq!(
            GitReply::decode(&[VERSION, 1, 0, 0, 0, 1, b'x']),
            Err(ExtError::Malformed(WireError::TrailingBytes(1)))
        );
        assert_eq!(GitReply::decode(&[0, 1, 0, 0, 0, 0]), Err(ExtError::Version(0)));
    }

    #[test]
    fn gpg_round_trip_and_limits() {
        for request in [GpgRequest::Open, GpgRequest::Input(b"PKSIGN\n".to_vec().into()), GpgRequest::Close] {
            assert_eq!(GpgRequest::decode(&request.encode().unwrap()).unwrap(), request);
        }
        for reply in [
            GpgReply::Opened(b"OK Pleased to meet you\n".to_vec().into()),
            GpgReply::Output(b"D data\nOK\n".to_vec().into()),
            GpgReply::Closed,
            GpgReply::Failed("gpg is not allowed for this server".into()),
        ] {
            assert_eq!(GpgReply::decode(&reply.encode().unwrap()).unwrap(), reply);
        }
        assert_eq!(*GpgRequest::encode(&GpgRequest::Open).unwrap(), [VERSION, 0, 0, 0, 0, 0]);
        // Allocated once at the final size: no reallocation left a copy behind.
        let encoded = GpgRequest::Input(vec![b'D'; 1000].into()).encode().unwrap();
        assert_eq!(encoded.capacity(), encoded.len());

        let max = vec![b'D'; MAX_GPG_CHUNK];
        assert!(GpgRequest::Input(max.clone().into()).encode().is_ok());
        let over = vec![b'D'; MAX_GPG_CHUNK + 1];
        assert_eq!(GpgRequest::Input(over.clone().into()).encode(), Err(ExtError::ChunkTooLarge));
        assert_eq!(GpgReply::Output(over.clone().into()).encode(), Err(ExtError::ChunkTooLarge));
        let mut w = Writer::new();
        w.put_u8(VERSION).put_u8(1).put_string(&over);
        assert_eq!(GpgRequest::decode(&w.clone().into_bytes()), Err(ExtError::ChunkTooLarge));
        assert_eq!(GpgReply::decode(&w.into_bytes()), Err(ExtError::ChunkTooLarge));

        assert_eq!(GpgRequest::decode(&[VERSION, 3, 0, 0, 0, 0]), Err(ExtError::UnknownCode(3)));
        assert_eq!(
            GpgRequest::decode(&[VERSION, 0, 0, 0, 0, 1, b'x']),
            Err(ExtError::Malformed(WireError::TrailingBytes(1)))
        );
        assert_eq!(GpgReply::decode(&[9, 0, 0, 0, 0, 0]), Err(ExtError::Version(9)));
        assert_eq!(GpgReply::decode(&[VERSION, 3, 0, 0, 0, 1, 0xfe]), Err(ExtError::InvalidUtf8));
    }
}
