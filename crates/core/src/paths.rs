//! Well-known file locations.
//!
//! Linux and macOS both follow the XDG base directory layout, so dotfiles and
//! SSH config snippets look the same on both systems.

use std::env;
use std::path::{Path, PathBuf};

pub const APP_NAME: &str = "credential-bridge";
pub use credential_bridge_proto::{HELPER_BINARY, REMOTE_HELPER_RELATIVE, REMOTE_SOCKET_RELATIVE};
pub const DAEMON_BINARY: &str = "credential-bridged";

/// Longest usable unix socket path (macOS `sun_path` is 104 bytes including NUL).
pub const MAX_SOCKET_PATH_LEN: usize = 103;

#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("$HOME is not set")]
    NoHome,
}

pub fn home_dir() -> Result<PathBuf, PathError> {
    env::var_os("HOME").filter(|home| !home.is_empty()).map(PathBuf::from).ok_or(PathError::NoHome)
}

fn xdg_dir(var: &str, fallback: &str) -> Result<PathBuf, PathError> {
    match env::var_os(var).map(PathBuf::from) {
        Some(dir) if dir.is_absolute() => Ok(dir),
        _ => Ok(home_dir()?.join(fallback)),
    }
}

pub fn config_home() -> Result<PathBuf, PathError> {
    xdg_dir("XDG_CONFIG_HOME", ".config")
}

pub fn data_home() -> Result<PathBuf, PathError> {
    xdg_dir("XDG_DATA_HOME", ".local/share")
}

pub fn state_home() -> Result<PathBuf, PathError> {
    xdg_dir("XDG_STATE_HOME", ".local/state")
}

/// `$XDG_CONFIG_HOME/credential-bridge/config.toml`
pub fn default_config_file() -> Result<PathBuf, PathError> {
    Ok(config_home()?.join(APP_NAME).join("config.toml"))
}

/// `$XDG_STATE_HOME/credential-bridge/loaded-config`: the fingerprint of the
/// configuration the running daemon has applied. Local only; ctl waits for it
/// after a reload.
pub fn loaded_config_file() -> Result<PathBuf, PathError> {
    Ok(state_home()?.join(APP_NAME).join("loaded-config"))
}

/// `$XDG_STATE_HOME/credential-bridge/sockets`
pub fn default_socket_dir() -> Result<PathBuf, PathError> {
    Ok(state_home()?.join(APP_NAME).join("sockets"))
}

/// Expands a leading `~/`.
pub fn expand_tilde(path: &Path) -> Result<PathBuf, PathError> {
    match path.strip_prefix("~") {
        Ok(rest) => Ok(home_dir()?.join(rest)),
        Err(_) => Ok(path.to_owned()),
    }
}

/// Default socket path on a remote whose home directory is `remote_home`.
pub fn default_remote_socket(remote_home: &str) -> String {
    format!("{}/{REMOTE_SOCKET_RELATIVE}", remote_home.trim_end_matches('/'))
}

/// Default helper path on a remote whose home directory is `remote_home`.
pub fn default_remote_helper(remote_home: &str) -> String {
    format!("{}/{REMOTE_HELPER_RELATIVE}", remote_home.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_paths() {
        assert_eq!(default_remote_socket("/home/me/"), "/home/me/.local/state/credential-bridge/bridge.sock");
        assert_eq!(default_remote_helper("/home/me"), "/home/me/.local/bin/git-credential-bridge");
    }

    #[test]
    fn leaves_absolute_paths_alone() {
        assert_eq!(expand_tilde(Path::new("/tmp/x")).unwrap(), PathBuf::from("/tmp/x"));
    }
}
