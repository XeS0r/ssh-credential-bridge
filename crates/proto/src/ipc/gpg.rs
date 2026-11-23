//! Messages of the gpg worker. The core opens a connection to the gpg-agent extra socket
//! per tunnel and hands it over as a file descriptor with [`Request::Open`]; the worker
//! filters and relays Assuan traffic on it.

use serde::{Deserialize, Serialize};

use crate::secret::SecretBytes;

/// What the profile allows beyond housekeeping commands (`gpg = ["sign", "decrypt"]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct GpgPolicy {
    /// Allow `PKSIGN`.
    pub sign: bool,
    /// Allow `PKDECRYPT`.
    pub decrypt: bool,
}

/// Identifies one tunnel; chosen by the core, unique for the worker's lifetime.
pub type ConnId = u64;

/// Core to gpg worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Take over the gpg-agent connection attached as `SCM_RIGHTS` descriptor, read its
    /// greeting and answer [`Response::Opened`].
    Open {
        /// The tunnel.
        conn: ConnId,
        /// The profile's gpg rights.
        policy: GpgPolicy,
    },
    /// Client bytes from the shim (one Assuan command line or one inquiry answer). The
    /// worker filters them and answers [`Response::Output`] with the agent's reply up to
    /// the next `OK`/`ERR`/`INQUIRE`, or with the filter's local `OK` or `ERR` line, and
    /// says what the filter decided.
    Input {
        /// The tunnel.
        conn: ConnId,
        /// The bytes (inquiry answers may hold secrets; wiped when dropped).
        data: SecretBytes,
    },
    /// Close the gpg-agent connection.
    Close {
        /// The tunnel.
        conn: ConnId,
    },
}

/// Gpg worker to core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    /// The agent's greeting.
    Opened(SecretBytes),
    /// The answer to an [`Request::Input`]. Core and worker are one binary, so the
    /// decision travels here instead of being guessed from `data`.
    Output {
        /// Agent output (signatures, decrypted session keys; wiped when dropped), or the
        /// filter's local `OK` or `ERR` line.
        data: SecretBytes,
        /// The verb of the command this answers, upper case (for the audit log); `None`
        /// for an inquiry answer.
        command: Option<String>,
        /// Whether the filter denied the command (`data` is then its `ERR` line).
        denied: bool,
    },
    /// The connection is closed.
    Closed,
}
