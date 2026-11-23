//! `credential-bridged`: the local ssh-agent proxy (core) and, re-executed as
//! `credential-bridged worker <git|vault|gpg>`, its workers.
//!
//! The core is the only process with the agent sockets. Per connection it checks the
//! local ssh client ([`client`]), tracks binds ([`bind`]), maps host keys to servers
//! ([`recognition`]), applies policy ([`policy`]), routes agent messages to upstream agents
//! ([`upstream`], [`keymux`]), answers extensions on `agent-forward.sock`
//! ([`extensions`]), shows approval dialogs ([`approvals`]), writes the audit log
//! ([`audit`]) and supervises workers ([`supervisor`]). ctl talks to it on `control.sock`
//! ([`control`]). [`worker`] holds the worker processes' main loops.
//!
//! This is a library + binary so the modules can be tested; nothing outside this crate
//! depends on it.

pub mod approvals;
pub mod audit;
pub mod bind;
pub mod cli;
pub mod client;
pub mod connection;
pub mod control;
pub mod core;
pub mod extensions;
mod frame;
pub mod keymux;
pub mod lock;
pub mod policy;
pub mod recognition;
pub mod slots;
pub mod supervisor;
mod sync;
pub mod upstream;
pub mod worker;
