//! Configuration of credential-bridge, schema version 2 (`docs/architecture.md`, section
//! "Configuration").
//!
//! Five terms, from the outside in: a [`Server`] has a [`Profile`]; the profile says what
//! is allowed and holds [`GitRule`]s; a rule points to a [`Source`]; the source takes
//! secrets from a [`SecretRef`].
//!
//! [`Config::load`] parses **and validates**: a [`Config`] value always satisfies the
//! invariants documented on its types (references resolve, patterns parse, owner scope
//! only for `owner/*` patterns, permissions within `max_permissions`). A configuration
//! file from 0.1 is rejected with [`ConfigError::Legacy`].
//!
//! ctl edits the file through [`edit::ConfigDocument`], which preserves comments and
//! formatting.

pub mod duration;
pub mod edit;
mod error;
pub mod file;
pub mod host_keys;
pub mod known_hosts;
mod load;
mod model;
pub mod paths;
pub mod pattern;
pub mod secret_ref;
mod validate;

pub use error::{ConfigError, Problem};
pub use load::daemon_settings;
pub use model::{
    AgentConfig, Config, Confirm, DaemonConfig, GitRule, GpgConfig, Hops, KeepassxcConfig, KeySelection,
    KnownHost, Profile, Server, ServerKeys, Signing, SocketSpec, Source, SourceKind, SshPolicy, Upstream,
    VaultConfig,
};
pub use pattern::{GitTarget, PatternError, UrlPattern};
pub use secret_ref::{SecretRef, SecretRefError, VaultKind};

/// The schema version this crate reads (`version = 2`).
pub const CONFIG_VERSION: u32 = 2;

/// Name of the built-in profile for recognised hosts without a `[server.*]` entry.
pub const UNREGISTERED_PROFILE: &str = "unregistered";

#[cfg(test)]
pub(crate) mod test_support {
    /// A syntactically valid ed25519 public key in OpenSSH format, distinct per `seed`.
    /// Only public test data; no private key exists for it.
    pub(crate) fn test_key(seed: u8) -> String {
        let data = ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey([seed; 32]));
        ssh_key::PublicKey::new(data, "").to_openssh().expect("encodes")
    }
}
