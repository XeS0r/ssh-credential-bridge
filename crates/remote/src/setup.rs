//! `setup` and `uninstall`: additive changes to the account's global git config.
//!
//! Entries are added with `git config --global --add`; an entry is skipped if the exact
//! key/value already exists. Every helper entry that names a `credential-bridge-remote`
//! binary by an absolute path with exactly the `git` subcommand counts as this tool's
//! (see [`is_own_helper`]), whoever wrote it and wherever the binary lies: `setup`
//! replaces such entries in place when the binary has moved, so a host never gets a
//! second, stale helper, and `uninstall` removes all of them. In a shared account
//! everybody shares the one global git config and with it one such helper entry, so
//! `setup` or `uninstall` by one person changes it for all. Other entries, such as other
//! credential helpers, are never changed or removed.
//!
//! `uninstall` removes the helper entries only: `useHttpPath` and the signing settings
//! cannot be told apart from ones somebody else set, so they stay.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, bail};
use credential_bridge_proto::text::shell_quote;

use crate::cli::SetupArgs;

/// One git config entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitConfigEntry {
    /// e.g. `credential.https://github.com.helper`.
    pub key: String,
    /// e.g. `/home/me/.local/bin/credential-bridge-remote git`.
    pub value: String,
}

/// A change to the global git config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// `git config --global --add key value`.
    Add(GitConfigEntry),
    /// Replace the entry of `key` whose value is exactly `old` with `new`, in place.
    Replace {
        /// The key.
        key: String,
        /// The value written by an earlier setup.
        old: String,
        /// The value naming this binary.
        new: String,
    },
    /// Remove the entries of `key` whose value is exactly `value`.
    Remove(GitConfigEntry),
}

/// Computes the changes for `args`, given this binary's path and the existing global
/// entries (key/value pairs as `git config --global --list` reports them):
///
/// - per host a `credential.https://<host>.helper` entry naming `<binary> git`. An
///   existing helper entry of this tool for that key that names another path (the
///   binary moved) is replaced; further such entries for the key are removed;
/// - `credential.https://<host>.useHttpPath = true` for `--http-path` hosts;
/// - with `--signing-key`: `gpg.format = ssh`, `user.signingkey = key::<key>` and
///   `commit.gpgsign = true`, each only if that key is not set yet.
///
/// Pure; existing identical entries are skipped. A `--http-path` host also gets a
/// helper entry. `useHttpPath` is skipped if the key has any value already (adding a
/// second entry would override somebody else's choice).
pub fn plan(args: &SetupArgs, binary: &Path, existing: &[(String, String)]) -> Vec<Change> {
    let existing: Vec<(String, &str)> =
        existing.iter().map(|(key, value)| (normalize_key(key), value.as_str())).collect();
    let has_key = |key: &str| {
        let key = normalize_key(key);
        existing.iter().any(|(k, _)| *k == key)
    };
    let has_entry = |key: &str, value: &str| {
        let key = normalize_key(key);
        existing.iter().any(|(k, v)| *k == key && *v == value)
    };

    let mut planned: Vec<Change> = Vec::new();
    // Adds an entry once.
    let push = |planned: &mut Vec<Change>, key: String, value: String| {
        let normalized = normalize_key(&key);
        let known = planned.iter().any(|change| match change {
            Change::Add(entry) => normalize_key(&entry.key) == normalized && entry.value == value,
            Change::Replace { .. } | Change::Remove(_) => false,
        });
        if !known {
            planned.push(Change::Add(GitConfigEntry { key, value }));
        }
    };

    let helper = helper_value(binary);
    let mut helper_keys: Vec<String> = Vec::new();
    for host in args.hosts.iter().chain(&args.http_path) {
        let key = helper_key(host);
        let normalized = normalize_key(&key);
        if helper_keys.contains(&normalized) {
            continue;
        }
        helper_keys.push(normalized.clone());
        let mut stale: Vec<&str> = Vec::new();
        for (k, v) in &existing {
            if *k == normalized && *v != helper && is_own_helper(v, binary) && !stale.contains(v) {
                stale.push(v);
            }
        }
        let mut stale = stale.into_iter();
        if !has_entry(&key, &helper) {
            match stale.next() {
                Some(old) => planned.push(Change::Replace {
                    key: key.clone(),
                    old: old.to_owned(),
                    new: helper.clone(),
                }),
                None => push(&mut planned, key.clone(), helper.clone()),
            }
        }
        for old in stale {
            planned.push(Change::Remove(GitConfigEntry { key: key.clone(), value: old.to_owned() }));
        }
    }
    for host in &args.http_path {
        let key = format!("credential.https://{host}.useHttpPath");
        if !has_key(&key) {
            push(&mut planned, key, "true".to_owned());
        }
    }
    if let Some(signing_key) = &args.signing_key {
        let signing_key = signing_key.trim();
        let value = if signing_key.starts_with("key::") {
            signing_key.to_owned()
        } else {
            format!("key::{signing_key}")
        };
        for (key, value) in [
            ("gpg.format", "ssh".to_owned()),
            ("user.signingkey", value),
            ("commit.gpgsign", "true".to_owned()),
        ] {
            if !has_key(key) {
                push(&mut planned, key.to_owned(), value);
            }
        }
    }
    planned
}

/// Whether `value` is a helper entry written by this tool: an absolute program path
/// (plain or shell-quoted) that is `binary` or whose file name is
/// `credential-bridge-remote`, followed by exactly the `git` subcommand.
pub fn is_own_helper(value: &str, binary: &Path) -> bool {
    let Some(words) = shell_words(value) else { return false };
    let [program, subcommand] = words.as_slice() else { return false };
    let path = Path::new(program);
    subcommand == "git"
        && path.is_absolute()
        && (path == binary || path.file_name().is_some_and(|name| name == "credential-bridge-remote"))
}

/// Splits `value` into words as the shell would for plain words, single quotes and
/// backslash escapes (what [`shell_quote`] produces); `None` for anything else (double
/// quotes, variables, unbalanced quotes), which this tool never writes.
fn shell_words(value: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word: Option<String> = None;
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => words.extend(word.take()),
            '\'' => {
                let current = word.get_or_insert_with(String::new);
                loop {
                    match chars.next()? {
                        '\'' => break,
                        c => current.push(c),
                    }
                }
            }
            '\\' => word.get_or_insert_with(String::new).push(chars.next()?),
            '"' | '$' | '`' | ';' | '&' | '|' | '<' | '>' | '(' | ')' | '\n' => return None,
            c => word.get_or_insert_with(String::new).push(c),
        }
    }
    words.extend(word);
    Some(words)
}

/// `credential.https://<host>.helper`.
fn helper_key(host: &str) -> String {
    format!("credential.https://{host}.helper")
}

/// The helper value naming `binary`: `<binary> git`, the path shell-quoted if needed
/// (git runs helpers given as absolute paths through the shell).
pub fn helper_value(binary: &Path) -> String {
    format!("{} git", shell_quote(&binary.to_string_lossy()))
}

/// git compares the section and the variable name case-insensitively and the
/// subsection (`https://host`) exactly; `git config --list` prints the former in lower
/// case. Normalizes a key the same way.
fn normalize_key(key: &str) -> String {
    match (key.find('.'), key.rfind('.')) {
        (Some(first), Some(last)) if first < last => format!(
            "{}{}{}",
            key[..first].to_ascii_lowercase(),
            &key[first..last],
            key[last..].to_ascii_lowercase()
        ),
        _ => key.to_ascii_lowercase(),
    }
}

/// Escapes `value` for a POSIX extended regular expression (git's value patterns).
fn regex_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for c in value.chars() {
        if r"\.[](){}*+?^$|".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The value pattern (`git config` `value-regex`) that matches exactly `value`: anchored
/// and escaped, rather than `--fixed-value` (git 2.30), so old servers work.
fn exact_value_pattern(value: &str) -> String {
    format!("^{}$", regex_escape(value))
}

/// Checks a `--host` / `--http-path` value: `host`, `host:port` or `[v6]:port`. Keeps
/// anything that could break out of the config key out of it.
fn validate_host(host: &str) -> anyhow::Result<()> {
    let valid = !host.is_empty()
        && !host.starts_with(['.', '-', ':'])
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:[]_".contains(&b));
    if !valid {
        bail!("invalid git host {host:?}: expected host or host:port");
    }
    Ok(())
}

/// Checks `--signing-key`: one line, an ssh public key.
fn validate_signing_key(key: &str) -> anyhow::Result<()> {
    let key = key.trim();
    let key = key.strip_prefix("key::").unwrap_or(key);
    let looks_like_key = key.starts_with("ssh-") || key.starts_with("ecdsa-") || key.starts_with("sk-");
    if !looks_like_key || key.contains(['\n', '\r', '\0']) {
        bail!("invalid signing key: expected one ssh public key line such as \"ssh-ed25519 AAAA…\"");
    }
    Ok(())
}

/// Runs `git config --global` with a fixed program and extra environment (tests point
/// `GIT_CONFIG_GLOBAL` at a temporary file).
#[derive(Debug, Clone)]
struct GitConfig {
    program: OsString,
    env: Vec<(OsString, OsString)>,
}

impl GitConfig {
    /// `git` from `PATH`.
    fn system() -> GitConfig {
        GitConfig { program: "git".into(), env: Vec::new() }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.envs(self.env.iter().map(|(k, v)| (k, v))).args(["config", "--global"]).stdin(Stdio::null());
        command
    }

    fn run(&self, args: &[&str]) -> anyhow::Result<std::process::Output> {
        self.command().args(args).output().context("cannot run git (is it installed?)")
    }

    /// All global entries. `--get-regexp` (unlike `--list`) is not an error when the
    /// global file does not exist; exit code 1 means no entries.
    fn list(&self) -> anyhow::Result<Vec<(String, String)>> {
        let output = self.run(&["--null", "--get-regexp", "."])?;
        match output.status.code() {
            Some(0) => Ok(parse_null_list(&output.stdout)),
            Some(1) => Ok(Vec::new()),
            _ => bail!("git config --global failed: {}", String::from_utf8_lossy(&output.stderr).trim()),
        }
    }

    fn add(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let output = self.run(&["--add", key, value])?;
        if !output.status.success() {
            bail!(
                "git config --global --add {key} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    /// Replaces the entry of `key` whose value is exactly `old` with `new` (in place
    /// when there is one such entry).
    fn replace_exact(&self, key: &str, old: &str, new: &str) -> anyhow::Result<()> {
        let pattern = exact_value_pattern(old);
        let output = self.run(&["--replace-all", key, new, &pattern])?;
        if !output.status.success() {
            bail!(
                "git config --global --replace-all {key} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    /// Removes the entries of `key` whose value is exactly `value` (see
    /// [`exact_value_pattern`]).
    fn unset_exact(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let pattern = exact_value_pattern(value);
        let output = self.run(&["--unset-all", key, &pattern])?;
        // 5: nothing matched (already gone).
        if !output.status.success() && output.status.code() != Some(5) {
            bail!(
                "git config --global --unset-all {key} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }
}

/// Parses `git config --null` output: `key\nvalue\0` per entry, `key\0` for an entry
/// without a value.
fn parse_null_list(output: &[u8]) -> Vec<(String, String)> {
    output
        .split(|&b| b == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let entry = String::from_utf8_lossy(entry);
            match entry.split_once('\n') {
                Some((key, value)) => (key.to_owned(), value.to_owned()),
                None => (entry.into_owned(), String::new()),
            }
        })
        .collect()
}

/// The running binary.
fn current_binary() -> anyhow::Result<PathBuf> {
    let binary = std::env::current_exe().context("cannot find the path of this program")?;
    if binary.to_str().is_none() {
        bail!("the path of this program is not UTF-8: {}", binary.display());
    }
    Ok(binary)
}

/// Runs `setup`: reads the existing config, computes [`plan`], then adds the entries or,
/// with `--print`, prints the `git config --global --add` commands.
pub fn setup(args: &SetupArgs) -> anyhow::Result<()> {
    let binary = current_binary()?;
    setup_with(&GitConfig::system(), args, &binary, io::stdout().lock(), io::stderr().lock())
}

fn setup_with(
    git: &GitConfig,
    args: &SetupArgs,
    binary: &Path,
    mut out: impl Write,
    mut err: impl Write,
) -> anyhow::Result<()> {
    for host in args.hosts.iter().chain(&args.http_path) {
        validate_host(host)?;
    }
    if let Some(key) = &args.signing_key {
        validate_signing_key(key)?;
    }
    let existing = match git.list() {
        Ok(existing) => existing,
        // Printing needs no git; without the list every entry is printed.
        Err(_) if args.print => Vec::new(),
        Err(error) => return Err(error),
    };
    for host in &args.http_path {
        let key = normalize_key(&format!("credential.https://{host}.useHttpPath"));
        let disabled = existing.iter().any(|(k, v)| {
            normalize_key(k) == key && matches!(v.to_ascii_lowercase().as_str(), "false" | "no" | "off" | "0")
        });
        if disabled {
            writeln!(
                err,
                "warning: credential.https://{host}.useHttpPath is false; tokens that need the \
                 repository path will not work for {host}"
            )?;
        }
    }

    let changes = plan(args, binary, &existing);
    if args.print {
        for change in &changes {
            let exact = |value: &str| shell_quote(&exact_value_pattern(value));
            match change {
                Change::Add(entry) => writeln!(
                    out,
                    "git config --global --add {} {}",
                    shell_quote(&entry.key),
                    shell_quote(&entry.value)
                )?,
                Change::Replace { key, old, new } => writeln!(
                    out,
                    "git config --global --replace-all {} {} {}",
                    shell_quote(key),
                    shell_quote(new),
                    exact(old)
                )?,
                Change::Remove(entry) => writeln!(
                    out,
                    "git config --global --unset-all {} {}",
                    shell_quote(&entry.key),
                    exact(&entry.value)
                )?,
            }
        }
        return Ok(());
    }
    if changes.is_empty() {
        writeln!(out, "git config: up to date")?;
    }
    for change in &changes {
        match change {
            Change::Add(entry) => {
                git.add(&entry.key, &entry.value)?;
                writeln!(out, "added: {} = {}", entry.key, entry.value)?;
            }
            Change::Replace { key, old, new } => {
                git.replace_exact(key, old, new)?;
                writeln!(out, "replaced: {key} = {old} -> {new}")?;
            }
            Change::Remove(entry) => {
                git.unset_exact(&entry.key, &entry.value)?;
                writeln!(out, "removed: {} = {}", entry.key, entry.value)?;
            }
        }
    }
    Ok(())
}

/// The helper entries of `existing` written by this tool ([`is_own_helper`]), each
/// key/value pair once.
fn own_entries(existing: &[(String, String)], binary: &Path) -> Vec<GitConfigEntry> {
    let mut own: Vec<GitConfigEntry> = Vec::new();
    for (key, value) in existing {
        let normalized = normalize_key(key);
        let entry = GitConfigEntry { key: key.clone(), value: value.clone() };
        if normalized.starts_with("credential.")
            && normalized.ends_with(".helper")
            && is_own_helper(value, binary)
            && !own.contains(&entry)
        {
            own.push(entry);
        }
    }
    own
}

/// Runs `uninstall`; with `remove_binary` also deletes the running binary.
pub fn uninstall(remove_binary: bool) -> anyhow::Result<()> {
    let binary = current_binary()?;
    uninstall_with(&GitConfig::system(), &binary, io::stdout().lock())?;
    if remove_binary {
        std::fs::remove_file(&binary).with_context(|| format!("cannot remove {}", binary.display()))?;
        println!("removed: {}", binary.display());
    }
    Ok(())
}

fn uninstall_with(git: &GitConfig, binary: &Path, mut out: impl Write) -> anyhow::Result<()> {
    let entries = own_entries(&git.list()?, binary);
    if entries.is_empty() {
        writeln!(out, "git config: no credential-bridge-remote entries")?;
    }
    for entry in &entries {
        git.unset_exact(&entry.key, &entry.value)?;
        writeln!(out, "removed: {} = {}", entry.key, entry.value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BINARY: &str = "/home/me/.local/bin/credential-bridge-remote";

    fn args(hosts: &[&str], http_path: &[&str]) -> SetupArgs {
        SetupArgs {
            hosts: hosts.iter().map(|h| (*h).to_owned()).collect(),
            http_path: http_path.iter().map(|h| (*h).to_owned()).collect(),
            ..SetupArgs::default()
        }
    }

    /// The entries of a plan that only adds.
    fn pairs(changes: &[Change]) -> Vec<(&str, &str)> {
        changes
            .iter()
            .map(|change| match change {
                Change::Add(e) => (e.key.as_str(), e.value.as_str()),
                other => panic!("not an addition: {other:?}"),
            })
            .collect()
    }

    fn existing(entries: &[(&str, &str)]) -> Vec<(String, String)> {
        entries.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    #[test]
    fn plan_adds_helpers_and_http_path() {
        let planned =
            plan(&args(&["github.com", "gitlab.example.com"], &["github.com"]), Path::new(BINARY), &[]);
        assert_eq!(
            pairs(&planned),
            [
                ("credential.https://github.com.helper", "/home/me/.local/bin/credential-bridge-remote git"),
                (
                    "credential.https://gitlab.example.com.helper",
                    "/home/me/.local/bin/credential-bridge-remote git"
                ),
                ("credential.https://github.com.useHttpPath", "true"),
            ]
        );
    }

    #[test]
    fn plan_skips_existing_entries_and_keeps_others() {
        let existing = existing(&[
            // git --list prints section and name in lower case.
            ("credential.https://github.com.helper", "/home/me/.local/bin/credential-bridge-remote git"),
            ("credential.https://github.com.usehttppath", "false"),
            // Somebody else's helper for the same host stays and does not stop ours.
            ("credential.https://gitlab.example.com.helper", "/usr/bin/git-credential-manager"),
        ]);
        let planned =
            plan(&args(&["github.com", "gitlab.example.com"], &["github.com"]), Path::new(BINARY), &existing);
        assert_eq!(
            pairs(&planned),
            [(
                "credential.https://gitlab.example.com.helper",
                "/home/me/.local/bin/credential-bridge-remote git"
            )]
        );
    }

    #[test]
    fn plan_http_path_host_gets_a_helper_too() {
        let planned = plan(&args(&[], &["github.com"]), Path::new(BINARY), &[]);
        assert_eq!(planned.len(), 2);
        assert_eq!(pairs(&planned)[0].0, "credential.https://github.com.helper");
    }

    #[test]
    fn plan_deduplicates_hosts() {
        let planned =
            plan(&args(&["github.com", "github.com"], &["github.com", "github.com"]), Path::new(BINARY), &[]);
        assert_eq!(planned.len(), 2);
    }

    #[test]
    fn plan_signing_only_where_unset() {
        let setup =
            SetupArgs { signing_key: Some("ssh-ed25519 AAAAC3Nz me@host".into()), ..SetupArgs::default() };
        let planned = plan(&setup, Path::new(BINARY), &existing(&[("commit.gpgsign", "false")]));
        assert_eq!(
            pairs(&planned),
            [("gpg.format", "ssh"), ("user.signingkey", "key::ssh-ed25519 AAAAC3Nz me@host")]
        );
    }

    #[test]
    fn helper_value_quotes_odd_paths() {
        assert_eq!(helper_value(Path::new("/opt/my tools/cbr")), "'/opt/my tools/cbr' git");
        assert_eq!(helper_value(Path::new("/opt/it's/cbr")), r"'/opt/it'\''s/cbr' git");
    }

    #[test]
    fn normalizes_keys_like_git() {
        assert_eq!(
            normalize_key("Credential.https://GitHub.com.useHttpPath"),
            "credential.https://GitHub.com.usehttppath"
        );
        assert_eq!(normalize_key("commit.gpgSign"), "commit.gpgsign");
    }

    #[test]
    fn rejects_bad_input() {
        assert!(validate_host("github.com").is_ok());
        assert!(validate_host("git.example.com:8443").is_ok());
        assert!(validate_host("[::1]:8443").is_ok());
        assert!(validate_host("evil.com.helper=x\n").is_err());
        assert!(validate_host("a/b").is_err());
        assert!(validate_host("").is_err());
        assert!(validate_signing_key("ssh-ed25519 AAAA").is_ok());
        assert!(validate_signing_key("key::sk-ssh-ed25519@openssh.com AAAA").is_ok());
        assert!(validate_signing_key("ssh-ed25519 AAAA\ncore.pager=x").is_err());
        assert!(validate_signing_key("/home/me/.ssh/id_ed25519.pub").is_err());
    }

    #[test]
    fn own_entries_match_only_this_tool() {
        let existing = existing(&[
            ("credential.https://github.com.helper", "/home/me/.local/bin/credential-bridge-remote git"),
            // An older install elsewhere, quoted.
            ("credential.https://github.com.helper", "'/opt/old place/credential-bridge-remote' git"),
            ("credential.https://github.com.helper", "/home/me/.local/bin/credential-bridge-remote-old git"),
            ("credential.helper", "/home/me/.local/bin/credential-bridge-remote git"),
            ("credential.https://github.com.usehttppath", "true"),
            ("alias.x", "/home/me/.local/bin/credential-bridge-remote git"),
        ]);
        let own = own_entries(&existing, Path::new(BINARY));
        assert_eq!(own.len(), 3);
        assert!(own.iter().all(|e| e.key.ends_with(".helper")));
        assert!(own.iter().all(|e| !e.value.contains("-old")));
    }

    #[test]
    fn recognises_own_helper_values() {
        let binary = Path::new(BINARY);
        for own in [
            "/home/me/.local/bin/credential-bridge-remote git",
            "/usr/local/bin/credential-bridge-remote git",
            "'/opt/my tools/credential-bridge-remote' git",
            r"'/opt/it'\''s/credential-bridge-remote' git",
            "/opt/my\\ tools/credential-bridge-remote git",
            "  /srv/credential-bridge-remote   git ",
        ] {
            assert!(is_own_helper(own, binary), "{own}");
        }
        // A renamed binary is recognised by its exact path only.
        assert!(is_own_helper("/opt/cbr git", Path::new("/opt/cbr")));
        for other in [
            "/usr/bin/git-credential-manager",
            "cache",
            "credential-bridge-remote git",
            "!/home/me/.local/bin/credential-bridge-remote git",
            "/home/me/.local/bin/credential-bridge-remote",
            "/home/me/.local/bin/credential-bridge-remote get",
            "/home/me/.local/bin/credential-bridge-remote git --extra",
            "/home/me/.local/bin/credential-bridge-remote-old git",
            "/home/me/credential-bridge-remote/helper git",
            "'/opt/unbalanced/credential-bridge-remote git",
            "\"/opt/x/credential-bridge-remote\" git",
            "/opt/x/credential-bridge-remote git; rm -rf ~",
            "",
        ] {
            assert!(!is_own_helper(other, binary), "{other}");
        }
    }

    #[test]
    fn plan_replaces_helpers_of_a_moved_binary() {
        let existing = existing(&[
            ("credential.https://github.com.helper", "/usr/bin/other-helper"),
            ("credential.https://github.com.helper", "/opt/old/credential-bridge-remote git"),
            ("credential.https://github.com.helper", "'/opt/older one/credential-bridge-remote' git"),
            // Current and stale: only the stale one goes.
            (
                "credential.https://gitlab.example.com.helper",
                "/home/me/.local/bin/credential-bridge-remote git",
            ),
            ("credential.https://gitlab.example.com.helper", "/opt/old/credential-bridge-remote git"),
        ]);
        let planned = plan(
            &args(&["github.com", "gitlab.example.com", "new.example.com"], &[]),
            Path::new(BINARY),
            &existing,
        );
        let entry = |key: &str, value: &str| GitConfigEntry { key: key.to_owned(), value: value.to_owned() };
        assert_eq!(
            planned,
            [
                Change::Replace {
                    key: "credential.https://github.com.helper".into(),
                    old: "/opt/old/credential-bridge-remote git".into(),
                    new: format!("{BINARY} git"),
                },
                Change::Remove(entry(
                    "credential.https://github.com.helper",
                    "'/opt/older one/credential-bridge-remote' git"
                )),
                Change::Remove(entry(
                    "credential.https://gitlab.example.com.helper",
                    "/opt/old/credential-bridge-remote git"
                )),
                Change::Add(entry("credential.https://new.example.com.helper", &format!("{BINARY} git"))),
            ]
        );
    }

    #[test]
    fn parses_null_output() {
        let parsed = parse_null_list(b"user.name\nMe\0core.bare\0credential.helper\n\0");
        assert_eq!(parsed, existing(&[("user.name", "Me"), ("core.bare", ""), ("credential.helper", "")]));
    }

    #[test]
    fn regex_escape_covers_metacharacters() {
        assert_eq!(regex_escape("/a.b/c+d (x) git"), r"/a\.b/c\+d \(x\) git");
        assert_eq!(exact_value_pattern("/a.b git"), r"^/a\.b git$");
    }

    /// git with a temporary global config; `None` if git is not installed.
    fn temp_git(dir: &Path) -> Option<GitConfig> {
        let ok = Command::new("git").arg("--version").output().is_ok_and(|o| o.status.success());
        if !ok {
            eprintln!("git not found; skipping");
            return None;
        }
        Some(GitConfig {
            program: "git".into(),
            env: vec![
                ("GIT_CONFIG_GLOBAL".into(), dir.join("gitconfig").into_os_string()),
                ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
                ("HOME".into(), dir.as_os_str().to_owned()),
            ],
        })
    }

    #[test]
    fn setup_and_uninstall_with_git() {
        let dir = tempfile::tempdir().unwrap();
        let Some(git) = temp_git(dir.path()) else { return };
        let binary = Path::new("/opt/cb tools/credential-bridge-remote");
        git.add("credential.https://github.com.helper", "/usr/bin/other-helper").unwrap();
        git.add("credential.helper", "cache").unwrap();

        let setup = args(&["github.com", "gitlab.example.com"], &["github.com"]);
        let mut out = Vec::new();
        setup_with(&git, &setup, binary, &mut out, io::sink()).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 3, "{text}");

        // A second run adds nothing.
        let mut out = Vec::new();
        setup_with(&git, &setup, binary, &mut out, io::sink()).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "git config: up to date\n");

        let list = git.list().unwrap();
        let helpers: Vec<&str> = list
            .iter()
            .filter(|(k, _)| k == "credential.https://github.com.helper")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(helpers, ["/usr/bin/other-helper", "'/opt/cb tools/credential-bridge-remote' git"]);

        let mut out = Vec::new();
        uninstall_with(&git, binary, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap().lines().count(), 2);
        let mut after = git.list().unwrap();
        after.sort();
        assert_eq!(
            after,
            existing(&[
                ("credential.helper", "cache"),
                ("credential.https://github.com.helper", "/usr/bin/other-helper"),
                ("credential.https://github.com.usehttppath", "true"),
            ])
        );
    }

    #[test]
    fn setup_replaces_and_uninstall_removes_moved_helpers_with_git() {
        let dir = tempfile::tempdir().unwrap();
        let Some(git) = temp_git(dir.path()) else { return };
        let key = "credential.https://github.com.helper";
        git.add(key, "/usr/bin/first-helper").unwrap();
        git.add(key, "'/opt/old place/credential-bridge-remote' git").unwrap();
        git.add(key, "/usr/bin/last-helper").unwrap();

        let mut out = Vec::new();
        setup_with(&git, &args(&["github.com"], &[]), Path::new(BINARY), &mut out, io::sink()).unwrap();
        assert!(String::from_utf8(out).unwrap().starts_with("replaced: "));
        let helpers = |git: &GitConfig| -> Vec<String> {
            git.list().unwrap().into_iter().filter(|(k, _)| k == key).map(|(_, v)| v).collect()
        };
        // Replaced in place: the order of the helpers stays.
        assert_eq!(
            helpers(&git),
            ["/usr/bin/first-helper", &format!("{BINARY} git"), "/usr/bin/last-helper"]
        );

        // Uninstall from yet another place removes it, and an old entry left by hand.
        git.add(key, "/srv/credential-bridge-remote git").unwrap();
        uninstall_with(&git, Path::new("/elsewhere/credential-bridge-remote"), io::sink()).unwrap();
        assert_eq!(helpers(&git), ["/usr/bin/first-helper", "/usr/bin/last-helper"]);
    }

    #[test]
    fn print_mode_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let Some(git) = temp_git(dir.path()) else { return };
        let mut out = Vec::new();
        let setup = SetupArgs { print: true, ..args(&["github.com"], &["github.com"]) };
        setup_with(&git, &setup, Path::new(BINARY), &mut out, io::sink()).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "git config --global --add credential.https://github.com.helper \
             '/home/me/.local/bin/credential-bridge-remote git'\n\
             git config --global --add credential.https://github.com.useHttpPath true\n"
        );
        assert!(git.list().unwrap().is_empty());
    }

    #[test]
    fn warns_about_disabled_http_path() {
        let dir = tempfile::tempdir().unwrap();
        let Some(git) = temp_git(dir.path()) else { return };
        git.add("credential.https://github.com.useHttpPath", "false").unwrap();
        let mut err = Vec::new();
        setup_with(&git, &args(&[], &["github.com"]), Path::new(BINARY), io::sink(), &mut err).unwrap();
        assert!(String::from_utf8(err).unwrap().contains("useHttpPath is false"));
    }
}
