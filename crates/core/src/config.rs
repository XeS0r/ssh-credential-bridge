//! The configuration file (`config.toml`).

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use credential_bridge_proto::Operation;
use serde::Deserialize;

use crate::paths::{self, MAX_SOCKET_PATH_LEN, PathError};
use crate::policy::{Policy, UrlPattern};

/// Backend used when neither the file nor the remote names one.
pub const DEFAULT_BACKEND: &str = "!gh auth git-credential";
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;
const MAX_NAME_LEN: usize = 64;

/// Commented starting point written by `credential-bridge-ctl config init`.
pub const EXAMPLE_CONFIG: &str = r#"# credential-bridge configuration
#
# Backend used to look up credentials locally. Same syntax as git's
# credential.helper setting:
#   "!<shell command>"   run the command, e.g. "!gh auth git-credential"
#   "/absolute/path"     run that program
#   "<name>"             run `git credential-<name>`, e.g. "osxkeychain",
#                        "libsecret", "manager", "cache"
backend = "!gh auth git-credential"

# Seconds to wait for the backend before giving up.
timeout_secs = 30

# Directory holding one socket per remote.
# Default: $XDG_STATE_HOME/credential-bridge/sockets
# socket_dir = "~/.local/state/credential-bridge/sockets"

# One [[remote]] block per SSH host. Every remote gets its own socket, so the
# daemon always knows which remote a request comes from and applies only that
# remote's policy. Manage these with `credential-bridge-ctl remote add/remove`.
#
# [[remote]]
# name = "buildserver"                  # socket: <socket_dir>/buildserver.sock
# ssh_host = "buildserver"              # ssh destination (default: name)
# allow = ["https://github.com"]        # URL patterns, e.g. "https://github.com/my-org/*"
# operations = ["get"]                  # any of "get", "store", "erase"
# backend = "osxkeychain"               # optional, overrides the global backend
# remote_socket = "/home/me/.local/state/credential-bridge/bridge.sock"  # set by `remote install`
"#;

/// Errors while loading, validating or saving the configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {}: {source}", .path.display())]
    Read { path: PathBuf, source: io::Error },
    #[error("cannot write {}: {source}", .path.display())]
    Write { path: PathBuf, source: io::Error },
    #[error("invalid TOML in {}: {message}", .path.display())]
    Toml { path: PathBuf, message: String },
    #[error("invalid configuration: {0}")]
    Invalid(String),
    #[error(transparent)]
    Path(#[from] PathError),
}

fn default_backend() -> String {
    DEFAULT_BACKEND.to_owned()
}

fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

fn default_operations() -> Vec<String> {
    vec!["get".to_owned()]
}

/// The whole configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_backend")]
    pub backend: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub socket_dir: Option<PathBuf>,
    #[serde(default, rename = "remote")]
    pub remotes: Vec<RemoteConfig>,
}

/// One `[[remote]]` block.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteConfig {
    pub name: String,
    #[serde(default)]
    pub ssh_host: Option<String>,
    #[serde(default)]
    pub remote_socket: Option<String>,
    pub allow: Vec<String>,
    #[serde(default = "default_operations")]
    pub operations: Vec<String>,
    #[serde(default)]
    pub backend: Option<String>,
}

/// A remote with everything the daemon needs, validated.
#[derive(Debug, Clone)]
pub struct ResolvedRemote {
    pub name: String,
    pub socket: PathBuf,
    pub policy: Policy,
    pub backend: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            backend: default_backend(),
            timeout_secs: default_timeout(),
            socket_dir: None,
            remotes: Vec::new(),
        }
    }
}

impl Config {
    /// Loads and validates `path`. A missing file yields the defaults (no remotes).
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        match fs::read_to_string(path) {
            Ok(text) => Self::parse(&text, path),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(ConfigError::Read { path: path.to_owned(), source }),
        }
    }

    /// Like [`Config::load`], plus the [`credential_bridge_proto::fingerprint`]
    /// of the text it was parsed from (of `""` for a missing file).
    pub fn load_with_fingerprint(path: &Path) -> Result<(Self, String), ConfigError> {
        match fs::read_to_string(path) {
            Ok(text) => Ok((Self::parse(&text, path)?, credential_bridge_proto::fingerprint(&text))),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                Ok((Self::default(), credential_bridge_proto::fingerprint("")))
            }
            Err(source) => Err(ConfigError::Read { path: path.to_owned(), source }),
        }
    }

    /// Parses and validates `text`; `origin` is only used in error messages.
    pub fn parse(text: &str, origin: &Path) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text).map_err(|err| ConfigError::Toml {
            path: origin.to_owned(),
            message: err.message().to_owned(),
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.resolve().map(drop)
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }

    pub fn socket_dir(&self) -> Result<PathBuf, ConfigError> {
        match &self.socket_dir {
            Some(dir) => {
                let dir = paths::expand_tilde(dir)?;
                if dir.is_relative() {
                    return Err(ConfigError::Invalid(format!(
                        "socket_dir must be absolute: {}",
                        dir.display()
                    )));
                }
                Ok(dir)
            }
            None => Ok(paths::default_socket_dir()?),
        }
    }

    pub fn remote(&self, name: &str) -> Option<&RemoteConfig> {
        self.remotes.iter().find(|remote| remote.name == name)
    }

    /// Local socket path of the remote called `name`.
    pub fn socket_path(&self, name: &str) -> Result<PathBuf, ConfigError> {
        Ok(self.socket_dir()?.join(format!("{name}.sock")))
    }

    /// Validates everything and returns the remotes ready to serve.
    pub fn resolve(&self) -> Result<Vec<ResolvedRemote>, ConfigError> {
        if self.timeout_secs == 0 {
            return Err(ConfigError::Invalid("timeout_secs must be greater than 0".into()));
        }
        if self.backend.trim().is_empty() {
            return Err(ConfigError::Invalid("backend must not be empty".into()));
        }
        // Names become socket file names, which collide without case on
        // macOS' default file system.
        let mut seen = HashSet::new();
        let mut resolved = Vec::with_capacity(self.remotes.len());
        for remote in &self.remotes {
            validate_name(&remote.name)?;
            if !seen.insert(remote.name.to_ascii_lowercase()) {
                return Err(ConfigError::Invalid(format!(
                    "remote '{}' is defined twice (names are compared without case)",
                    remote.name
                )));
            }
            let context = |msg: String| ConfigError::Invalid(format!("remote '{}': {msg}", remote.name));

            if remote.allow.is_empty() {
                return Err(context("allow must list at least one URL pattern".into()));
            }
            let allow = remote.patterns().map_err(|err| context(err.to_string()))?;
            let operations = remote.parsed_operations().map_err(context)?;
            let backend = remote.backend.as_deref().unwrap_or(&self.backend);
            if backend.trim().is_empty() {
                return Err(context("backend must not be empty".into()));
            }
            let socket = self.socket_path(&remote.name)?;
            let socket_len = socket.as_os_str().len();
            if socket_len > MAX_SOCKET_PATH_LEN {
                return Err(context(format!(
                    "socket path {} is {socket_len} bytes long (max {MAX_SOCKET_PATH_LEN}); \
                     choose a shorter name or socket_dir",
                    socket.display()
                )));
            }
            resolved.push(ResolvedRemote {
                name: remote.name.clone(),
                socket,
                policy: Policy { allow, operations },
                backend: backend.to_owned(),
            });
        }
        Ok(resolved)
    }
}

impl RemoteConfig {
    /// The ssh destination: `ssh_host` or, if unset, the remote's name.
    pub fn ssh_target(&self) -> &str {
        self.ssh_host.as_deref().unwrap_or(&self.name)
    }

    pub fn patterns(&self) -> Result<Vec<UrlPattern>, crate::policy::PatternError> {
        self.allow.iter().map(|p| p.parse()).collect()
    }

    fn parsed_operations(&self) -> Result<Vec<Operation>, String> {
        if self.operations.is_empty() {
            return Err("operations must list at least one of get, store, erase".into());
        }
        self.operations
            .iter()
            .map(|op| match op.parse::<Operation>() {
                Ok(op) if Operation::CREDENTIAL_OPERATIONS.contains(&op) => Ok(op),
                _ => Err(format!("unknown operation '{op}' (expected get, store or erase)")),
            })
            .collect()
    }
}

/// Remote names become file names, so keep them simple.
pub fn validate_name(name: &str) -> Result<(), ConfigError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && !name.starts_with(['.', '-'])
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if valid {
        Ok(())
    } else {
        Err(ConfigError::Invalid(format!(
            "invalid remote name '{name}': use up to {MAX_NAME_LEN} of A-Z a-z 0-9 . _ -, \
             not starting with '.' or '-'"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_names_must_differ_in_more_than_case() {
        let text = "[[remote]]\nname = \"Build\"\nallow = [\"https://github.com\"]\n\
                    [[remote]]\nname = \"build\"\nallow = [\"https://github.com\"]\n";
        let err = Config::parse(text, Path::new("t.toml")).unwrap_err().to_string();
        assert!(err.contains("defined twice"), "{err}");
    }

    fn parse(text: &str) -> Result<Config, ConfigError> {
        Config::parse(text, Path::new("test.toml"))
    }

    #[test]
    fn example_config_is_valid() {
        let config = parse(EXAMPLE_CONFIG).unwrap();
        assert_eq!(config.backend, DEFAULT_BACKEND);
        assert!(config.remotes.is_empty());
    }

    #[test]
    fn resolves_remotes_with_defaults() {
        let config = parse(
            r#"
            socket_dir = "/run/cb"
            [[remote]]
            name = "build"
            allow = ["https://github.com"]

            [[remote]]
            name = "dev"
            ssh_host = "me@dev.example.com"
            allow = ["https://github.com/org/*"]
            operations = ["get", "erase"]
            backend = "osxkeychain"
            "#,
        )
        .unwrap();
        let remotes = config.resolve().unwrap();
        assert_eq!(remotes[0].socket, PathBuf::from("/run/cb/build.sock"));
        assert_eq!(remotes[0].backend, DEFAULT_BACKEND);
        assert_eq!(remotes[0].policy.operations, [Operation::Get]);
        assert_eq!(remotes[1].backend, "osxkeychain");
        assert_eq!(remotes[1].policy.operations, [Operation::Get, Operation::Erase]);
        assert_eq!(config.remote("dev").unwrap().ssh_target(), "me@dev.example.com");
        assert_eq!(config.remote("build").unwrap().ssh_target(), "build");
    }

    #[test]
    fn rejects_invalid_configs() {
        let cases = [
            "unknown = 1",
            "timeout_secs = 0",
            "[[remote]]\nname = \"x\"\nallow = []",
            "[[remote]]\nname = \"../x\"\nallow = [\"https://github.com\"]",
            "[[remote]]\nname = \"x\"\nallow = [\"github.com\"]",
            "[[remote]]\nname = \"x\"\nallow = [\"https://github.com\"]\noperations = [\"ping\"]",
            "[[remote]]\nname = \"x\"\nallow = [\"https://a\"]\n[[remote]]\nname = \"x\"\nallow = [\"https://a\"]",
            "socket_dir = \"relative\"\n[[remote]]\nname = \"x\"\nallow = [\"https://a\"]",
        ];
        for case in cases {
            assert!(parse(case).is_err(), "should be rejected:\n{case}");
        }
    }

    #[test]
    fn rejects_overlong_socket_paths() {
        let text = format!(
            "socket_dir = \"/{}\"\n[[remote]]\nname = \"x\"\nallow = [\"https://a\"]",
            "d".repeat(100)
        );
        assert!(parse(&text).is_err());
    }

    #[test]
    fn missing_file_yields_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load(&dir.path().join("absent.toml")).unwrap();
        assert!(config.remotes.is_empty());
    }
}
