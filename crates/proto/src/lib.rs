//! Wire formats shared by the credential-bridge programs.
//!
//! This crate is a leaf: it depends on no other credential-bridge crate and does no I/O
//! beyond the blocking `std::io::{Read, Write}` helpers. Async callers use the pure
//! encode/decode functions and the `*_len` header helpers with their own runtime.
//!
//! - [`agent`]: the ssh-agent protocol (framing, [`agent::Message`], a blocking client).
//! - [`api_url`]: the check of GitHub API base URLs (feature `api-url`).
//! - [`bind`]: `session-bind@openssh.com` parsing and verification (feature `bind`).
//! - [`ext`]: the `*@credential-bridge` extensions and the standard `query` extension.
//! - [`ipc`]: versioned frames between the core, its workers and ctl.
//! - [`credential`]: the git credential attribute format.
//! - [`wire`]: SSH wire encoding primitives (`uint32`, `string`, `boolean`).
//! - [`secret`]: zeroizing secret containers with redacted `Debug`.
//! - [`text`]: shell quoting and gpgconf's percent-decoding.

pub mod agent;
#[cfg(feature = "api-url")]
pub mod api_url;
#[cfg(feature = "bind")]
pub mod bind;
pub mod credential;
pub mod ext;
pub mod ipc;
pub mod secret;
pub mod text;
pub mod wire;

pub use secret::{Secret, SecretBytes};
