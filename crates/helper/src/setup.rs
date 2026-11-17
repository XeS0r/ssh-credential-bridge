//! `setup` and `uninstall`: the helper registers itself with git on the remote,
//! the way `gh auth setup-git` does locally.
//!
//! For every allowed host the helper replaces git's helpers with itself. What
//! was configured there before, the helpers (with an empty `helper =` reset)
//! and `useHttpPath`, is kept under `bridgeSavedHelper` and
//! `bridgeSavedUseHttpPath` and put back when the host is no longer allowed
//! (`setup` with a smaller allow list) or the helper is removed (`uninstall`).

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use credential_bridge_proto::{HELPER_BINARY, PatternError, UrlPattern, git_sections, sh_quote};

/// Directory name we may restrict to mode 0700 even if it existed already.
const OWN_DIR: &str = "credential-bridge";
/// Where a host's previous helpers are kept while ours replaces them,
/// including an empty `helper =` reset.
const SAVED: &str = "bridgeSavedHelper";
/// Where a host's previous `useHttpPath` is kept.
const SAVED_PATH: &str = "bridgeSavedUseHttpPath";

/// `credential.<origin>` sections for the URL patterns, with whether the
/// request path is needed (`useHttpPath`). The very rule ctl uses, from the
/// shared crate.
pub fn origins(patterns: &[String]) -> Result<BTreeMap<String, bool>, String> {
    let patterns = patterns
        .iter()
        .map(|p| p.parse::<UrlPattern>().map_err(|err: PatternError| err.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(git_sections(&patterns))
}

/// The global `credential.<origin>.*` entries, from
/// `git config --global --get-regexp '^credential\.'`.
#[derive(Debug, Default)]
pub struct GitCredentials {
    /// (origin, lowercased key name, value)
    entries: Vec<(String, String, String)>,
}

impl GitCredentials {
    pub fn parse(output: &str) -> Self {
        let entries = output
            .lines()
            .filter_map(|line| {
                let (key, value) = line.split_once(' ').unwrap_or((line, ""));
                let (origin, name) = key.strip_prefix("credential.")?.rsplit_once('.')?;
                Some((origin.to_owned(), name.to_ascii_lowercase(), value.to_owned()))
            })
            .collect();
        GitCredentials { entries }
    }

    fn values<'a>(&'a self, origin: &'a str, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.entries.iter().filter(move |(o, n, _)| o == origin && n == name).map(|(_, _, v)| v.as_str())
    }

    fn is_ours(&self, origin: &str) -> bool {
        self.values(origin, "helper").any(|v| v.contains(HELPER_BINARY))
    }

    /// Origins whose helper is this one.
    pub fn ours(&self) -> Vec<&str> {
        let mut origins: Vec<&str> = self
            .entries
            .iter()
            .filter(|(_, n, v)| n == "helper" && v.contains(HELPER_BINARY))
            .map(|(o, _, _)| o.as_str())
            .collect();
        origins.dedup();
        origins
    }
}

/// One step of `setup` / `uninstall`, printed in `--dry-run`.
#[derive(Debug, PartialEq)]
pub enum Step {
    SocketDir(String),
    Git(Vec<String>),
    RemoveFile(String),
}

impl std::fmt::Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Step::SocketDir(dir) => write!(f, "mkdir -p {0}  # mode 700 if created here", sh_quote(dir)),
            Step::Git(args) => {
                write!(f, "git")?;
                args.iter().try_for_each(|arg| write!(f, " {}", sh_quote(arg)))
            }
            Step::RemoveFile(path) => write!(f, "rm -f {}", sh_quote(path)),
        }
    }
}

fn git(args: &[&str]) -> Step {
    Step::Git(args.iter().map(|&a| a.to_owned()).collect())
}

fn unset_all(key: &str) -> Step {
    git(&["config", "--global", "--unset-all", key])
}

/// git's value for `credential.<url>.helper`. git runs a value as a shell
/// command only if it starts with `!` or `/`; a quoted path starts with `'`
/// and would be taken for a helper name, so it gets the `!`.
pub fn helper_value(helper: &str, socket: &str) -> String {
    let command = format!("{} --socket {}", sh_quote(helper), sh_quote(socket));
    if command.starts_with('/') { command } else { format!("!{command}") }
}

/// Removes our entries for `origin` and puts back what was there before.
fn restore(origin: &str, current: &GitCredentials) -> Vec<Step> {
    let section = format!("credential.{origin}");
    let mut steps =
        vec![unset_all(&format!("{section}.helper")), unset_all(&format!("{section}.useHttpPath"))];
    for (saved, key) in [(SAVED, "helper"), (SAVED_PATH, "useHttpPath")] {
        let saved_key = saved.to_ascii_lowercase();
        let values: Vec<&str> = current.values(origin, &saved_key).collect();
        for value in &values {
            steps.push(git(&["config", "--global", "--add", &format!("{section}.{key}"), value]));
        }
        if !values.is_empty() {
            steps.push(unset_all(&format!("{section}.{saved}")));
        }
    }
    steps
}

/// Steps that make git use `helper` (this binary) through `socket` for exactly
/// the hosts in `origins`, given the current global configuration.
pub fn setup_steps(
    helper: &str,
    socket: &str,
    origins: &BTreeMap<String, bool>,
    git_config: bool,
    current: &GitCredentials,
) -> Vec<Step> {
    let socket_dir = Path::new(socket).parent().map_or("/".into(), |p| p.to_string_lossy().into_owned());
    let mut steps = vec![Step::SocketDir(socket_dir)];
    if !git_config {
        return steps;
    }
    // Hosts that were allowed before but are not any more.
    for origin in current.ours() {
        if !origins.contains_key(origin) {
            steps.extend(restore(origin, current));
        }
    }
    let value = helper_value(helper, socket);
    for (origin, use_path) in origins {
        let section = format!("credential.{origin}");
        let key = format!("{section}.helper");
        // Keep what the user had for this host, once (not our own entries):
        // every helper value, the empty reset too, and useHttpPath.
        if !current.is_ours(origin) {
            for previous in current.values(origin, "helper") {
                steps.push(git(&["config", "--global", "--add", &format!("{section}.{SAVED}"), previous]));
            }
            for previous in current.values(origin, "usehttppath") {
                steps.push(git(&[
                    "config",
                    "--global",
                    "--add",
                    &format!("{section}.{SAVED_PATH}"),
                    previous,
                ]));
            }
        }
        // The empty value first resets helpers that other config files define
        // for this host (like `gh auth setup-git`).
        steps.push(unset_all(&key));
        steps.push(git(&["config", "--global", "--add", &key, ""]));
        steps.push(git(&["config", "--global", "--add", &key, &value]));
        if *use_path {
            steps.push(git(&["config", "--global", &format!("{section}.useHttpPath"), "true"]));
        } else if current.is_ours(origin) {
            steps.push(unset_all(&format!("{section}.useHttpPath")));
        }
    }
    steps
}

/// Steps that remove every git entry pointing at this helper and restore the
/// helpers it replaced.
pub fn uninstall_steps(current: &GitCredentials, binary: Option<&str>) -> Vec<Step> {
    let mut steps: Vec<Step> =
        current.ours().into_iter().flat_map(|origin| restore(origin, current)).collect();
    if let Some(binary) = binary {
        steps.push(Step::RemoveFile(binary.to_owned()));
    }
    steps
}

/// Runs `steps`. Unsetting keys that do not exist is not an error.
pub fn apply(steps: &[Step]) -> Result<(), String> {
    for step in steps {
        match step {
            Step::SocketDir(dir) => socket_dir(Path::new(dir))?,
            Step::Git(args) => {
                let status = Command::new("git")
                    .args(args)
                    .status()
                    .map_err(|err| format!("cannot run git: {err}"))?;
                // `git config --unset*` exits 5 if the key does not exist.
                let missing_key = args.iter().any(|a| a.starts_with("--unset")) && status.code() == Some(5);
                if !status.success() && !missing_key {
                    return Err(format!("`{step}` failed ({status})"));
                }
            }
            Step::RemoveFile(path) => match fs::remove_file(path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(format!("cannot remove {path}: {err}")),
            },
        }
    }
    Ok(())
}

/// Creates the socket's directory. Only a directory created here, or our own
/// `credential-bridge` directory, is restricted to 0700: a socket placed
/// directly in `$HOME` or `/tmp` must not change those.
fn socket_dir(dir: &Path) -> Result<(), String> {
    let existed = dir.is_dir();
    fs::create_dir_all(dir).map_err(|err| format!("cannot create {}: {err}", dir.display()))?;
    if !existed || dir.file_name().is_some_and(|name| name == OWN_DIR) {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|err| format!("cannot restrict {}: {err}", dir.display()))?;
    }
    Ok(())
}

/// The global `credential.*` configuration.
pub fn read_git_credentials() -> Result<GitCredentials, String> {
    let output = Command::new("git")
        .args(["config", "--global", "--get-regexp", r"^credential\."])
        .output()
        .map_err(|err| format!("cannot run git: {err}"))?;
    // Exit 1: no matching entries.
    if !output.status.success() && output.status.code() != Some(1) {
        return Err(format!("`git config --get-regexp` failed ({})", output.status));
    }
    Ok(GitCredentials::parse(&String::from_utf8_lossy(&output.stdout)))
}

pub fn has_git() -> bool {
    Command::new("git").arg("--version").output().is_ok_and(|out| out.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(steps: &[Step]) -> Vec<String> {
        steps.iter().map(ToString::to_string).collect()
    }

    const OURS: &str = "/home/me/.local/bin/git-credential-bridge --socket /home/me/s/bridge.sock";

    #[test]
    fn derives_origins_like_ctl() {
        let o = origins(&[
            "https://GitHub.com".into(),
            "https://github.com/org/*".into(),
            "https://git.example.com/".into(),
            "https://**.example.org".into(),
        ])
        .unwrap();
        assert_eq!(
            o.into_iter().collect::<Vec<_>>(),
            [
                ("https://*.example.org".to_owned(), false),
                ("https://git.example.com".to_owned(), false),
                ("https://github.com".to_owned(), true)
            ]
        );
        assert!(origins(&["github.com".into()]).is_err());
        assert!(origins(&["https://me@github.com".into()]).is_err());
        assert!(origins(&["ht tp://x".into()]).is_err(), "same protocol check as ctl");
    }

    #[test]
    fn setup_configures_git_and_keeps_the_previous_helper() {
        let o = origins(&["https://github.com/org/*".into()]).unwrap();
        let current = GitCredentials::parse("credential.https://github.com.helper !gh auth git-credential\n");
        assert_eq!(
            text(&setup_steps(
                "/home/me/.local/bin/git-credential-bridge",
                "/home/me/s/bridge.sock",
                &o,
                true,
                &current
            )),
            [
                "mkdir -p /home/me/s  # mode 700 if created here",
                "git config --global --add credential.https://github.com.bridgeSavedHelper '!gh auth git-credential'",
                "git config --global --unset-all credential.https://github.com.helper",
                "git config --global --add credential.https://github.com.helper ''",
                &format!("git config --global --add credential.https://github.com.helper '{OURS}'"),
                "git config --global credential.https://github.com.useHttpPath true",
            ]
        );
        assert_eq!(setup_steps("/h", "/s/b.sock", &o, false, &current), [Step::SocketDir("/s".into())]);
    }

    #[test]
    fn setup_again_does_not_save_its_own_entry() {
        let o = origins(&["https://github.com".into()]).unwrap();
        let current = GitCredentials::parse(&format!(
            "credential.https://github.com.helper \ncredential.https://github.com.helper {OURS}\n\
             credential.https://github.com.usehttppath true\n"
        ));
        let steps = text(&setup_steps("/h", "/s/b.sock", &o, true, &current));
        assert!(!steps.iter().any(|s| s.contains("bridgeSavedHelper")), "{steps:#?}");
        assert!(
            steps.contains(
                &"git config --global --unset-all credential.https://github.com.useHttpPath".into()
            )
        );
    }

    #[test]
    fn setup_drops_hosts_no_longer_allowed_and_restores_their_helper() {
        let o = origins(&["https://gitlab.com".into()]).unwrap();
        let current = GitCredentials::parse(&format!(
            "credential.https://github.com.helper \ncredential.https://github.com.helper {OURS}\n\
             credential.https://github.com.bridgesavedhelper !gh auth git-credential\n"
        ));
        let steps = text(&setup_steps("/h", "/s/b.sock", &o, true, &current));
        assert_eq!(
            steps[1..5],
            [
                "git config --global --unset-all credential.https://github.com.helper",
                "git config --global --unset-all credential.https://github.com.useHttpPath",
                "git config --global --add credential.https://github.com.helper '!gh auth git-credential'",
                "git config --global --unset-all credential.https://github.com.bridgeSavedHelper",
            ]
        );
        assert!(steps.iter().any(|s| s.contains("credential.https://gitlab.com.helper '/h --socket")));
    }

    #[test]
    fn setup_and_uninstall_give_back_exactly_what_was_there() {
        // gh auth setup-git style: an empty reset, the helper, and the user's useHttpPath.
        let before = GitCredentials::parse(
            "credential.helper store\ncredential.https://github.com.helper \n\
             credential.https://github.com.helper !gh auth git-credential\n\
             credential.https://github.com.usehttppath true\n",
        );
        let o = origins(&["https://github.com".into()]).unwrap();
        let setup = text(&setup_steps("/h", "/s/b.sock", &o, true, &before));
        assert!(
            setup.contains(
                &"git config --global --add credential.https://github.com.bridgeSavedHelper ''".into()
            ),
            "{setup:#?}"
        );
        assert!(setup.contains(
            &"git config --global --add credential.https://github.com.bridgeSavedUseHttpPath true".into()
        ));

        // The state after setup, as git would report it.
        let after = GitCredentials::parse(
            "credential.helper store\ncredential.https://github.com.helper \n\
             credential.https://github.com.helper /home/me/.local/bin/git-credential-bridge --socket /s/b.sock\n\
             credential.https://github.com.usehttppath true\n\
             credential.https://github.com.bridgesavedhelper \n\
             credential.https://github.com.bridgesavedhelper !gh auth git-credential\n\
             credential.https://github.com.bridgesavedusehttppath true\n",
        );
        assert_eq!(
            text(&uninstall_steps(&after, None)),
            [
                "git config --global --unset-all credential.https://github.com.helper",
                "git config --global --unset-all credential.https://github.com.useHttpPath",
                "git config --global --add credential.https://github.com.helper ''",
                "git config --global --add credential.https://github.com.helper '!gh auth git-credential'",
                "git config --global --unset-all credential.https://github.com.bridgeSavedHelper",
                "git config --global --add credential.https://github.com.useHttpPath true",
                "git config --global --unset-all credential.https://github.com.bridgeSavedUseHttpPath",
            ]
        );
    }

    #[test]
    fn quoted_paths_become_shell_commands() {
        assert_eq!(helper_value("/home/me/x", "/s.sock"), "/home/me/x --socket /s.sock");
        assert_eq!(
            helper_value("/home/my user/x", "/home/my user/s.sock"),
            "!'/home/my user/x' --socket '/home/my user/s.sock'"
        );
    }

    #[test]
    fn uninstall_removes_only_our_entries_and_restores() {
        let current = GitCredentials::parse(&format!(
            "credential.https://github.com.helper \ncredential.https://github.com.helper {OURS}\n\
             credential.https://github.com.bridgesavedhelper store\n\
             credential.https://gitlab.com.helper store\ncredential.helper cache\n"
        ));
        assert_eq!(
            text(&uninstall_steps(&current, Some("/home/me/.local/bin/git-credential-bridge"))),
            [
                "git config --global --unset-all credential.https://github.com.helper",
                "git config --global --unset-all credential.https://github.com.useHttpPath",
                "git config --global --add credential.https://github.com.helper store",
                "git config --global --unset-all credential.https://github.com.bridgeSavedHelper",
                "rm -f /home/me/.local/bin/git-credential-bridge",
            ]
        );
        assert!(uninstall_steps(&GitCredentials::default(), None).is_empty());
    }

    #[test]
    fn socket_dir_restricts_only_its_own_directory() {
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o755)).unwrap();

        socket_dir(&home).unwrap();
        assert_eq!(mode(&home), 0o755, "an existing foreign directory keeps its mode");

        let fresh = home.join("sockets");
        socket_dir(&fresh).unwrap();
        assert_eq!(mode(&fresh), 0o700);

        let own = home.join(OWN_DIR);
        fs::create_dir(&own).unwrap();
        fs::set_permissions(&own, fs::Permissions::from_mode(0o755)).unwrap();
        socket_dir(&own).unwrap();
        assert_eq!(mode(&own), 0o700);
    }
}
