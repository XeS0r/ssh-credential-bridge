//! Well-known locations.
//!
//! Linux and macOS both use the XDG layout, so ssh config snippets look the same on both
//! systems; only the log directory differs on macOS.
//!
//! | Item            | Path                                                               |
//! | --------------- | ------------------------------------------------------------------ |
//! | configuration   | `$XDG_CONFIG_HOME/credential-bridge/config.toml` (`~/.config`)     |
//! | state directory | `$XDG_STATE_HOME/credential-bridge/` (`~/.local/state`), mode 0700 |
//! | agent socket    | `<state>/agent.sock`                                               |
//! | forward socket  | `<state>/agent-forward.sock`                                       |
//! | control socket  | `<state>/control.sock`                                             |
//! | audit log       | `<state>/audit.log`; macOS `~/Library/Logs/credential-bridge/audit.log` |
//!
//! XDG variables are honoured only if set to an absolute path.
//!
//! Unix socket paths are limited by `sun_path`: 104 bytes on macOS and 108 bytes on
//! Linux, both including the terminating NUL. [`check_socket_path`] enforces this.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// Application directory name.
pub const APP_NAME: &str = "credential-bridge";

/// Longest usable unix socket path in bytes on every supported system (macOS `sun_path`
/// is 104 bytes with NUL). See [`max_socket_path_len`] for the per-system value.
pub const MAX_SOCKET_PATH_LEN: usize = 103;

/// The operating system whose conventions apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetOs {
    /// Linux (also WSL).
    Linux,
    /// macOS.
    MacOs,
}

impl TargetOs {
    /// The system this binary was built for.
    pub fn current() -> TargetOs {
        if cfg!(target_os = "macos") { TargetOs::MacOs } else { TargetOs::Linux }
    }
}

/// Longest usable unix socket path in bytes on `os`, without the terminating NUL:
/// 103 on macOS, 107 on Linux.
pub fn max_socket_path_len(os: TargetOs) -> usize {
    match os {
        TargetOs::MacOs => MAX_SOCKET_PATH_LEN,
        TargetOs::Linux => 107,
    }
}

/// Checks that `path` can be used as a unix socket path on `os`: absolute and at most
/// [`max_socket_path_len`] bytes long.
pub fn check_socket_path(path: &Path, os: TargetOs) -> Result<(), PathsError> {
    if !path.is_absolute() {
        return Err(PathsError::SocketNotAbsolute { path: path.to_owned() });
    }
    let len = path.as_os_str().len();
    let max = max_socket_path_len(os);
    if len > max {
        return Err(PathsError::SocketPathTooLong { path: path.to_owned(), len, max });
    }
    Ok(())
}

/// The environment variables paths are derived from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathVars {
    /// `HOME`.
    pub home: Option<OsString>,
    /// `XDG_CONFIG_HOME`.
    pub xdg_config_home: Option<OsString>,
    /// `XDG_STATE_HOME`.
    pub xdg_state_home: Option<OsString>,
}

impl PathVars {
    /// Reads the variables from the process environment.
    pub fn from_env() -> PathVars {
        PathVars {
            home: std::env::var_os("HOME"),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
            xdg_state_home: std::env::var_os("XDG_STATE_HOME"),
        }
    }
}

/// Error of deriving or checking paths.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathsError {
    /// `HOME` is unset, empty or relative.
    #[error("$HOME is not set to an absolute path")]
    NoHome,
    /// A socket path is relative.
    #[error("socket path {} is not absolute", path.display())]
    SocketNotAbsolute {
        /// The path.
        path: PathBuf,
    },
    /// A socket path is longer than the system allows.
    #[error("socket path {} is {len} bytes long; at most {max} bytes are possible", path.display())]
    SocketPathTooLong {
        /// The path.
        path: PathBuf,
        /// Its length in bytes.
        len: usize,
        /// The limit on this system.
        max: usize,
    },
}

/// All well-known locations, absolute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// The home directory.
    pub home: PathBuf,
    /// The configuration file.
    pub config_file: PathBuf,
    /// The state directory (sockets, log on Linux).
    pub state_dir: PathBuf,
    /// Default `daemon.socket`.
    pub agent_socket: PathBuf,
    /// Default `daemon.forward_socket`.
    pub forward_socket: PathBuf,
    /// Default `daemon.control_socket`.
    pub control_socket: PathBuf,
    /// Default `daemon.audit_log`.
    pub audit_log: PathBuf,
}

impl Paths {
    /// Paths for this process: [`PathVars::from_env`] and [`TargetOs::current`].
    pub fn discover() -> Result<Paths, PathsError> {
        Paths::from_vars(&PathVars::from_env(), TargetOs::current())
    }

    /// Paths for the given variables and system (pure; for tests).
    pub fn from_vars(vars: &PathVars, os: TargetOs) -> Result<Paths, PathsError> {
        let home = absolute(vars.home.as_ref()).ok_or(PathsError::NoHome)?;
        let config_home = absolute(vars.xdg_config_home.as_ref()).unwrap_or_else(|| home.join(".config"));
        let state_home =
            absolute(vars.xdg_state_home.as_ref()).unwrap_or_else(|| home.join(".local").join("state"));
        let state_dir = state_home.join(APP_NAME);
        let audit_log = match os {
            TargetOs::Linux => state_dir.join("audit.log"),
            TargetOs::MacOs => home.join("Library").join("Logs").join(APP_NAME).join("audit.log"),
        };
        Ok(Paths {
            config_file: config_home.join(APP_NAME).join("config.toml"),
            agent_socket: state_dir.join("agent.sock"),
            forward_socket: state_dir.join("agent-forward.sock"),
            control_socket: state_dir.join("control.sock"),
            audit_log,
            state_dir,
            home,
        })
    }

    /// [`expand_home`] with [`Paths::home`].
    pub fn expand_home(&self, path: &Path) -> PathBuf {
        expand_home(&self.home, path)
    }
}

/// Expands a leading `~` or `~/` with `home`; other paths are returned unchanged (`~user`
/// is not supported and stays as is). The one `~` expansion of the configuration and ctl.
pub fn expand_home(home: &Path, path: &Path) -> PathBuf {
    let mut components = path.components();
    match components.next() {
        Some(Component::Normal(first)) if first == "~" => home.join(components.as_path()),
        _ => path.to_owned(),
    }
}

/// The variable as a path if it is set to an absolute path.
fn absolute(var: Option<&OsString>) -> Option<PathBuf> {
    var.map(PathBuf::from).filter(|path| path.is_absolute())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(home: &str) -> PathVars {
        PathVars { home: Some(home.into()), ..PathVars::default() }
    }

    #[test]
    fn linux_defaults() {
        let paths = Paths::from_vars(&vars("/home/u"), TargetOs::Linux).unwrap();
        assert_eq!(paths.home, Path::new("/home/u"));
        assert_eq!(paths.config_file, Path::new("/home/u/.config/credential-bridge/config.toml"));
        assert_eq!(paths.state_dir, Path::new("/home/u/.local/state/credential-bridge"));
        assert_eq!(paths.agent_socket, Path::new("/home/u/.local/state/credential-bridge/agent.sock"));
        assert_eq!(
            paths.forward_socket,
            Path::new("/home/u/.local/state/credential-bridge/agent-forward.sock")
        );
        assert_eq!(paths.control_socket, Path::new("/home/u/.local/state/credential-bridge/control.sock"));
        assert_eq!(paths.audit_log, Path::new("/home/u/.local/state/credential-bridge/audit.log"));
    }

    #[test]
    fn macos_uses_xdg_layout_and_library_logs() {
        let paths = Paths::from_vars(&vars("/Users/u"), TargetOs::MacOs).unwrap();
        assert_eq!(paths.config_file, Path::new("/Users/u/.config/credential-bridge/config.toml"));
        assert_eq!(paths.agent_socket, Path::new("/Users/u/.local/state/credential-bridge/agent.sock"));
        assert_eq!(paths.audit_log, Path::new("/Users/u/Library/Logs/credential-bridge/audit.log"));
    }

    #[test]
    fn honours_absolute_xdg_variables_only() {
        let mut v = vars("/home/u");
        v.xdg_config_home = Some("/cfg".into());
        v.xdg_state_home = Some("/state".into());
        let paths = Paths::from_vars(&v, TargetOs::Linux).unwrap();
        assert_eq!(paths.config_file, Path::new("/cfg/credential-bridge/config.toml"));
        assert_eq!(paths.forward_socket, Path::new("/state/credential-bridge/agent-forward.sock"));

        v.xdg_config_home = Some("relative/cfg".into());
        v.xdg_state_home = Some("".into());
        let paths = Paths::from_vars(&v, TargetOs::Linux).unwrap();
        assert_eq!(paths.config_file, Path::new("/home/u/.config/credential-bridge/config.toml"));
        assert_eq!(paths.state_dir, Path::new("/home/u/.local/state/credential-bridge"));
    }

    #[test]
    fn requires_absolute_home() {
        for home in [None, Some(""), Some("relative")] {
            let v = PathVars { home: home.map(Into::into), ..PathVars::default() };
            assert_eq!(Paths::from_vars(&v, TargetOs::Linux), Err(PathsError::NoHome));
        }
    }

    #[test]
    fn expands_home() {
        let paths = Paths::from_vars(&vars("/home/u"), TargetOs::Linux).unwrap();
        assert_eq!(paths.expand_home(Path::new("~")), Path::new("/home/u"));
        assert_eq!(paths.expand_home(Path::new("~/")), Path::new("/home/u"));
        assert_eq!(paths.expand_home(Path::new("~/.ssh/agent.sock")), Path::new("/home/u/.ssh/agent.sock"));
        assert_eq!(paths.expand_home(Path::new("~other/x")), Path::new("~other/x"));
        assert_eq!(paths.expand_home(Path::new("/abs/~/x")), Path::new("/abs/~/x"));
        assert_eq!(paths.expand_home(Path::new("rel")), Path::new("rel"));
    }

    #[test]
    fn socket_path_limits() {
        assert_eq!(max_socket_path_len(TargetOs::MacOs), 103);
        assert_eq!(max_socket_path_len(TargetOs::Linux), 107);

        let at = |len: usize| PathBuf::from(format!("/{}", "a".repeat(len - 1)));
        assert_eq!(check_socket_path(&at(103), TargetOs::MacOs), Ok(()));
        assert_eq!(
            check_socket_path(&at(104), TargetOs::MacOs),
            Err(PathsError::SocketPathTooLong { path: at(104), len: 104, max: 103 })
        );
        assert_eq!(check_socket_path(&at(107), TargetOs::Linux), Ok(()));
        assert!(matches!(
            check_socket_path(&at(108), TargetOs::Linux),
            Err(PathsError::SocketPathTooLong { len: 108, max: 107, .. })
        ));
        assert!(matches!(
            check_socket_path(Path::new("agent.sock"), TargetOs::Linux),
            Err(PathsError::SocketNotAbsolute { .. })
        ));
    }
}
