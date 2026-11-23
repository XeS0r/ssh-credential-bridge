//! Platform interfaces of credential-bridge, with Linux and macOS implementations.
//!
//! Everything that depends on the operating system lives here, one module per concern,
//! so that Windows can be added later as a third implementation without touching other
//! crates: peer checks ([`peer`]), process information ([`process`]), the OpenSSH
//! version of the local ssh client ([`ssh_client`]), memory protection
//! ([`harden`]), worker sandboxes ([`sandbox`]), worker channels and descriptor passing
//! ([`channel`]), local sockets ([`socket`]), approval dialogs ([`approval`]) and service
//! managers ([`service`]).
//!
//! Functions return `std::io::Error` with [`std::io::ErrorKind::Unsupported`] where a
//! platform lacks a feature. The Linux code is safe Rust (`rustix`, `landlock`,
//! `seccompiler`). macOS needs a few foreign calls that neither `std` nor `rustix` offer
//! (`getpeereid`, `LOCAL_PEERPID`, `proc_pidpath`, `PT_DENY_ATTACH`, `sandbox_init`);
//! they are the only `unsafe` code of credential-bridge and live in one private module,
//! with `#[allow(unsafe_code)]` on each wrapper and a `SAFETY` comment on each call.

#![cfg(unix)]

pub mod approval;
pub mod channel;
pub mod harden;
pub mod peer;
pub mod process;
pub mod sandbox;
pub mod service;
pub mod socket;
pub mod ssh_client;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(test)]
mod testutil;
