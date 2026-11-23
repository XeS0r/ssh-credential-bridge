//! Suggestions for and checks of `~/.ssh/config`. ctl never edits it.

use std::path::{Path, PathBuf};

/// The command ssh runs in `Match exec` to see whether the daemon is up.
pub const ALIVE_COMMAND: &str = "credential-bridge-ctl daemon alive";

/// The snippet printed by `server ssh-config` (`docs/architecture.md`, section "ssh configuration"):
/// `IdentityAgent` for all hosts and `ForwardAgent` for `servers`; with `fallback`, the
/// `Match exec "credential-bridge-ctl daemon alive"` form followed by a `Host *` block using the
/// fallback agent. Socket paths are written with `~` where they are under `home`. Pure.
///
/// The `Match` form uses `originalhost`, which compares the name given on the command
/// line like `Host` does; `Match host` would compare the name after `HostName`
/// substitution and miss aliases.
pub fn suggestion(
    servers: &[&str],
    agent_socket: &Path,
    forward_socket: &Path,
    home: &Path,
    fallback: Option<&Path>,
) -> String {
    let agent = config_path(agent_socket, home);
    let forward = config_path(forward_socket, home);
    let mut out = String::new();
    match fallback {
        None => {
            out.push_str(&format!("Host *\n  IdentityAgent {agent}\n"));
            if !servers.is_empty() {
                out.push_str(&format!("\nHost {}\n  ForwardAgent {forward}\n", servers.join(" ")));
            }
        }
        Some(fallback) => {
            out.push_str(&format!("Match exec \"{ALIVE_COMMAND}\"\n  IdentityAgent {agent}\n"));
            if !servers.is_empty() {
                out.push_str(&format!(
                    "Match originalhost {} exec \"{ALIVE_COMMAND}\"\n  ForwardAgent {forward}\n",
                    servers.join(",")
                ));
            }
            out.push_str(&format!("\nHost *\n  IdentityAgent {}\n", config_path(fallback, home)));
        }
    }
    out
}

/// `path` as written into ssh config: `~/…` under `home`, double-quoted if it contains
/// whitespace or quotes.
fn config_path(path: &Path, home: &Path) -> String {
    let text = match path.strip_prefix(home) {
        Ok(rest) if !rest.as_os_str().is_empty() && home.is_absolute() => format!("~/{}", rest.display()),
        _ => path.display().to_string(),
    };
    if text.chars().any(|c| c.is_whitespace() || c == '"' || c == '\'') {
        format!("\"{}\"", text.replace('"', "\\\""))
    } else {
        text
    }
}

/// What `ssh -G <host>` reports that matters here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveSshConfig {
    /// `identityagent`, `None` if unset.
    pub identity_agent: Option<String>,
    /// `forwardagent` (`yes`, `no` or a socket path).
    pub forward_agent: Option<String>,
}

impl EffectiveSshConfig {
    /// Parses `ssh -G` output (lower-case `key value` lines).
    pub fn parse(ssh_g_output: &str) -> EffectiveSshConfig {
        let mut config = EffectiveSshConfig::default();
        for line in ssh_g_output.lines() {
            let line = line.trim();
            let (key, value) = match line.split_once(char::is_whitespace) {
                Some((key, value)) => (key, value.trim()),
                None => continue,
            };
            let value = unquote(value);
            match key.to_ascii_lowercase().as_str() {
                "identityagent" => config.identity_agent = Some(value),
                "forwardagent" => config.forward_agent = Some(value),
                _ => {}
            }
        }
        config
    }

    /// Whether `ForwardAgent` points to `forward_socket` (after `~` expansion with
    /// `home`).
    pub fn forwards_to(&self, forward_socket: &Path, home: &Path) -> bool {
        self.forward_agent.as_deref().is_some_and(|value| same_socket(value, forward_socket, home))
    }

    /// Whether `IdentityAgent` points to `agent_socket` (after `~` expansion with
    /// `home`).
    pub fn identity_agent_is(&self, agent_socket: &Path, home: &Path) -> bool {
        self.identity_agent.as_deref().is_some_and(|value| same_socket(value, agent_socket, home))
    }
}

/// Removes one pair of surrounding double quotes.
fn unquote(value: &str) -> String {
    value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value).to_owned()
}

/// Whether an ssh config socket value names `socket`. `yes`, `no`, `none` and
/// `SSH_AUTH_SOCK` never do.
fn same_socket(value: &str, socket: &Path, home: &Path) -> bool {
    if matches!(value, "yes" | "no" | "none" | "SSH_AUTH_SOCK") {
        return false;
    }
    expand(value, home) == socket
}

/// Expands what ssh expands in socket paths that matters for a comparison: a leading
/// `~`, the `%d` token and `${HOME}`.
fn expand(value: &str, home: &Path) -> PathBuf {
    let home_text = home.display().to_string();
    let replaced = value.replace("%d", &home_text).replace("${HOME}", &home_text);
    match replaced.strip_prefix('~') {
        Some("") => home.to_owned(),
        Some(rest) if rest.starts_with('/') => home.join(rest.trim_start_matches('/')),
        _ => PathBuf::from(replaced),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "/home/me";

    fn sockets() -> (PathBuf, PathBuf) {
        (
            PathBuf::from("/home/me/.local/state/credential-bridge/agent.sock"),
            PathBuf::from("/home/me/.local/state/credential-bridge/agent-forward.sock"),
        )
    }

    #[test]
    fn simple_suggestion_matches_the_design() {
        let (agent, forward) = sockets();
        let text = suggestion(&["buildserver", "devbox"], &agent, &forward, Path::new(HOME), None);
        assert_eq!(
            text,
            "Host *\n  IdentityAgent ~/.local/state/credential-bridge/agent.sock\n\n\
             Host buildserver devbox\n  ForwardAgent ~/.local/state/credential-bridge/agent-forward.sock\n"
        );
    }

    #[test]
    fn fallback_suggestion_puts_match_first() {
        let (agent, forward) = sockets();
        let text = suggestion(
            &["buildserver", "devbox"],
            &agent,
            &forward,
            Path::new(HOME),
            Some(Path::new("/home/me/.1password/agent.sock")),
        );
        assert_eq!(
            text,
            "Match exec \"credential-bridge-ctl daemon alive\"\n  IdentityAgent ~/.local/state/credential-bridge/agent.sock\n\
             Match originalhost buildserver,devbox exec \"credential-bridge-ctl daemon alive\"\n  \
             ForwardAgent ~/.local/state/credential-bridge/agent-forward.sock\n\n\
             Host *\n  IdentityAgent ~/.1password/agent.sock\n"
        );
    }

    #[test]
    fn suggestion_without_servers_has_no_forward_block() {
        let (agent, forward) = sockets();
        let text = suggestion(&[], &agent, &forward, Path::new(HOME), None);
        assert!(!text.contains("ForwardAgent"));
        let text = suggestion(&[], &agent, &forward, Path::new(HOME), Some(Path::new("/run/agent")));
        assert!(!text.contains("ForwardAgent"));
        assert!(text.ends_with("Host *\n  IdentityAgent /run/agent\n"));
    }

    #[test]
    fn paths_outside_home_and_with_spaces() {
        assert_eq!(config_path(Path::new("/run/user/1000/a.sock"), Path::new(HOME)), "/run/user/1000/a.sock");
        assert_eq!(config_path(Path::new("/home/me/My Sockets/a"), Path::new(HOME)), "\"~/My Sockets/a\"");
        assert_eq!(config_path(Path::new("/home/meme/a"), Path::new(HOME)), "/home/meme/a");
    }

    #[test]
    fn parses_ssh_g_and_compares_sockets() {
        let (agent, forward) = sockets();
        let home = Path::new(HOME);
        let config = EffectiveSshConfig::parse(
            "user me\nhostname build\nforwardagent ~/.local/state/credential-bridge/agent-forward.sock\n\
             identityagent %d/.local/state/credential-bridge/agent.sock\n",
        );
        assert!(config.forwards_to(&forward, home));
        assert!(config.identity_agent_is(&agent, home));
        assert!(!config.forwards_to(&agent, home));

        let config = EffectiveSshConfig::parse("forwardagent yes\n");
        assert_eq!(config.forward_agent.as_deref(), Some("yes"));
        assert_eq!(config.identity_agent, None);
        assert!(!config.forwards_to(&forward, home));

        let config = EffectiveSshConfig::parse(
            "forwardagent \"${HOME}/.local/state/credential-bridge/agent-forward.sock\"\n",
        );
        assert!(config.forwards_to(&forward, home));
        assert!(!EffectiveSshConfig::default().forwards_to(&forward, home));
    }
}
