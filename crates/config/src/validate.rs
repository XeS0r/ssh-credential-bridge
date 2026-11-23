//! Semantic checks of a configuration (see [`crate::Config::parse`] for the list).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use credential_bridge_proto::ipc::git::{Permissions, TokenScope};

use crate::error::Problem;
use crate::known_hosts;
use crate::model::{
    Config, Confirm, GitRule, KeySelection, Profile, Server, ServerKeys, SocketSpec, Source, SourceKind,
};
use crate::paths::{TargetOs, check_socket_path};
use crate::pattern::valid_host;

/// All problems of `config`. Rules naming a source in `broken_sources` (one that failed
/// to convert and was already reported) are not checked against that source.
pub(crate) fn check(config: &Config, broken_sources: &BTreeSet<String>) -> Vec<Problem> {
    check_on(config, broken_sources, TargetOs::current())
}

/// [`check`] for the system `os`.
pub(crate) fn check_on(config: &Config, broken_sources: &BTreeSet<String>, os: TargetOs) -> Vec<Problem> {
    let mut checker = Checker { config, broken_sources, problems: Vec::new(), os };
    checker.daemon();
    checker.agent();
    checker.gpg();
    checker.vault();
    for (key, source) in &config.sources {
        checker.source(key, source);
    }
    for (key, profile) in &config.profiles {
        checker.profile(key, profile);
    }
    checker.unregistered();
    checker.servers();
    checker.problems
}

struct Checker<'a> {
    config: &'a Config,
    broken_sources: &'a BTreeSet<String>,
    problems: Vec<Problem>,
    os: TargetOs,
}

/// `[A-Za-z0-9._-]+`.
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

impl Checker<'_> {
    fn problem(&mut self, location: impl Into<String>, message: impl Into<String>) {
        self.problems.push(Problem::new(location, message));
    }

    fn name(&mut self, location: &str, what: &str, name: &str) {
        if !valid_name(name) {
            self.problem(
                location,
                format!("invalid {what} name {name:?}: use letters, digits, '.', '_' and '-'"),
            );
        }
    }

    fn socket_path(&mut self, location: &str, path: &Path) {
        if let Err(err) = check_socket_path(path, self.os) {
            self.problem(location, err.to_string());
        }
    }

    fn socket_spec(&mut self, location: &str, spec: &SocketSpec) {
        match spec {
            SocketSpec::Path(path) => self.socket_path(location, path),
            SocketSpec::Gpgconf(name) => {
                let valid =
                    name.ends_with("-socket") && name.chars().all(|c| c.is_ascii_lowercase() || c == '-');
                if !valid {
                    self.problem(
                        location,
                        format!("gpgconf:{name} is not a gpgconf socket name, e.g. gpgconf:agent-ssh-socket"),
                    );
                }
            }
        }
    }

    fn daemon(&mut self) {
        let daemon = &self.config.daemon;
        let sockets = [
            ("daemon.socket", &daemon.socket),
            ("daemon.forward_socket", &daemon.forward_socket),
            ("daemon.control_socket", &daemon.control_socket),
        ];
        for (i, (location, path)) in sockets.iter().enumerate() {
            self.socket_path(location, path);
            if let Some((other, _)) = sockets[..i].iter().find(|(_, earlier)| earlier == path) {
                self.problem(*location, format!("the same path as {other}; every socket needs its own"));
            }
        }
        if !daemon.audit_log.is_absolute() {
            self.problem("daemon.audit_log", format!("{} is not absolute", daemon.audit_log.display()));
        }
    }

    fn agent(&mut self) {
        let Some(agent) = &self.config.agent else { return };
        let mut seen = BTreeSet::new();
        for (i, upstream) in agent.upstreams.iter().enumerate() {
            let loc = format!("agent.upstream[{i}]");
            self.name(&format!("{loc}.name"), "upstream", &upstream.name);
            if !seen.insert(upstream.name.as_str()) {
                self.problem(format!("{loc}.name"), format!("upstream {:?} is defined twice", upstream.name));
            }
            self.socket_spec(&format!("{loc}.socket"), &upstream.socket);
            if let SocketSpec::Path(path) = &upstream.socket {
                self.not_the_proxy(&format!("{loc}.socket"), path);
            }
        }
        if let Some(add_to) = &agent.add_to
            && !seen.contains(add_to.as_str())
        {
            self.problem("agent.add_to", format!("{add_to:?} is not an [[agent.upstream]] name"));
        }
    }

    /// An upstream socket must not be one of the proxy's own agent sockets: the proxy
    /// would ask itself for keys.
    fn not_the_proxy(&mut self, location: &str, path: &Path) {
        let daemon = &self.config.daemon;
        for (key, own) in
            [("daemon.socket", &daemon.socket), ("daemon.forward_socket", &daemon.forward_socket)]
        {
            if same_file(path, own) {
                self.problem(
                    location,
                    format!(
                        "{} is the proxy's own socket ({key} = {}); an upstream must be another agent",
                        path.display(),
                        own.display()
                    ),
                );
            }
        }
    }

    fn gpg(&mut self) {
        if let Some(gpg) = &self.config.gpg {
            self.socket_spec("gpg.socket", &gpg.socket);
        }
    }

    fn vault(&mut self) {
        let keepassxc = &self.config.vault.keepassxc;
        for (location, path) in [
            ("vault.keepassxc.database", &keepassxc.database),
            ("vault.keepassxc.key_file", &keepassxc.key_file),
        ] {
            if let Some(path) = path
                && !path.is_absolute()
            {
                self.problem(location, format!("{} is not absolute", path.display()));
            }
        }
        if keepassxc.key_file.is_some() && keepassxc.database.is_none() {
            self.problem("vault.keepassxc.key_file", "key_file needs database");
        }
        if keepassxc.database.is_none() && self.os == TargetOs::MacOs {
            let users: Vec<&str> = self
                .config
                .sources
                .iter()
                .filter(|(_, source)| {
                    source.kind.secret_refs().iter().any(|r| r.vault() == crate::VaultKind::KeePassXc)
                })
                .map(|(name, _)| name.as_str())
                .collect();
            if !users.is_empty() {
                self.problem(
                    "vault.keepassxc.database",
                    format!(
                        "on macOS keepassxc:// references need [vault.keepassxc] database \
                         (the .kdbx file for keepassxc-cli); used by source {}; set it with \
                         credential-bridge-ctl vault setup keepassxc",
                        users.join(", ")
                    ),
                );
            }
        }
    }

    fn source(&mut self, key: &str, source: &Source) {
        let loc = format!("source.{key}");
        self.name(&loc, "source", key);
        if source.name != *key {
            self.problem(&loc, format!("name {:?} differs from the table name", source.name));
        }
        if let Some(host) = source.kind.host()
            && (!valid_host(host) || host.chars().any(|c| c.is_ascii_uppercase()))
        {
            self.problem(format!("{loc}.host"), format!("invalid host {host:?}, expected e.g. github.com"));
        }
        match &source.kind {
            SourceKind::GithubApp { api_url, app_id, max_permissions, .. } => {
                if let Some(problem) = api_url_problem(api_url) {
                    self.problem(format!("{loc}.api_url"), problem);
                }
                if *app_id == 0 {
                    self.problem(format!("{loc}.app_id"), "app_id must be a positive number");
                }
                if max_permissions.is_empty() {
                    self.problem(
                        format!("{loc}.max_permissions"),
                        "max_permissions is empty, so no rule can use this source",
                    );
                }
                self.permission_names(&format!("{loc}.max_permissions"), max_permissions);
            }
            SourceKind::Helper { helper } if helper.trim().is_empty() => {
                self.problem(format!("{loc}.helper"), "helper is empty");
            }
            _ => {}
        }
    }

    fn permission_names(&mut self, location: &str, permissions: &Permissions) {
        for name in permissions.keys() {
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
                self.problem(
                    location,
                    format!("{name:?} is not a GitHub permission name, e.g. contents or pull_requests"),
                );
            }
        }
    }

    fn profile(&mut self, key: &str, profile: &Profile) {
        let loc = format!("profile.{key}");
        self.name(&loc, "profile", key);
        if profile.name != *key {
            self.problem(&loc, format!("name {:?} differs from the table name", profile.name));
        }
        if let Some(ssh) = &profile.ssh {
            if let KeySelection::Upstreams(names) = &ssh.keys {
                for name in names {
                    let known = self
                        .config
                        .agent
                        .as_ref()
                        .is_some_and(|agent| agent.upstreams.iter().any(|u| &u.name == name));
                    if !known {
                        self.problem(
                            format!("{loc}.ssh.keys"),
                            format!("{name:?} is not an [[agent.upstream]] name"),
                        );
                    }
                }
            }
            if let Confirm::Remember(confirm) = ssh.confirm
                && (confirm.is_zero() || confirm > crate::duration::MAX_DURATION)
            {
                self.problem(format!("{loc}.ssh.confirm"), "confirm must be between 1s and 365d");
            }
        }
        // profile.unregistered may not allow gpg at all (see `unregistered`).
        if (profile.gpg.sign || profile.gpg.decrypt)
            && self.config.gpg.is_none()
            && key != crate::UNREGISTERED_PROFILE
        {
            self.problem(format!("{loc}.gpg"), "the profile allows gpg, but there is no [gpg] table");
        }
        for (i, rule) in profile.git.iter().enumerate() {
            self.rule(&format!("{loc}.git[{i}]"), rule);
        }
    }

    /// `profile.unregistered`: the checks of every profile, and nothing a host without a
    /// `[server.*]` entry may never get (git rules, gpg, signing, hops for git and gpg).
    fn unregistered(&mut self) {
        let profile = &self.config.unregistered;
        let loc = format!("profile.{}", crate::UNREGISTERED_PROFILE);
        if self.config.profiles.contains_key(crate::UNREGISTERED_PROFILE) {
            self.problem(&loc, "profile.unregistered is built in and must not be among the other profiles");
        }
        self.profile(crate::UNREGISTERED_PROFILE, profile);
        let never = "hosts without a [server.*] entry never get tokens, gpg or signing; \
                     register the server with credential-bridge-ctl server add NAME --profile PROFILE";
        if !profile.git.is_empty() {
            self.problem(format!("{loc}.git"), format!("git rules are not allowed here: {never}"));
        }
        if profile.gpg.sign || profile.gpg.decrypt {
            self.problem(format!("{loc}.gpg"), format!("gpg is not allowed here: {never}"));
        }
        if profile.signing.is_some() {
            self.problem(format!("{loc}.signing"), format!("signing is not allowed here: {never}"));
        }
        if profile.hops.git || profile.hops.gpg {
            self.problem(format!("{loc}.hops"), format!("only hops.ssh is allowed here: {never}"));
        }
    }

    fn rule(&mut self, loc: &str, rule: &GitRule) {
        if self.broken_sources.contains(&rule.source) {
            return;
        }
        let Some(source) = self.config.sources.get(&rule.source) else {
            self.problem(format!("{loc}.source"), format!("{:?} is not a [source.*] name", rule.source));
            return;
        };
        if let Some(host) = source.kind.host() {
            if rule.url.scheme() != "https" {
                self.problem(
                    format!("{loc}.url"),
                    format!("{} must use https:// for source {:?}", rule.url, rule.source),
                );
            }
            if rule.url.host() != host {
                self.problem(
                    format!("{loc}.url"),
                    format!(
                        "host {} does not match host {host} of source {:?}",
                        rule.url.host(),
                        rule.source
                    ),
                );
            }
        }
        let max = match &source.kind {
            SourceKind::GithubApp { max_permissions, .. } => Some(max_permissions),
            _ => None,
        };
        match max {
            Some(max) => {
                if rule.permissions.is_empty() {
                    self.problem(
                        format!("{loc}.permissions"),
                        format!(
                            "source {:?} is a GitHub App: the rule needs permissions, e.g. {{ contents = \"read\" }}",
                            rule.source
                        ),
                    );
                }
                self.permission_names(&format!("{loc}.permissions"), &rule.permissions);
                for (name, access) in &rule.permissions {
                    let allowed = max.get(name);
                    if allowed.is_none_or(|allowed| access > allowed) {
                        let limit =
                            allowed.map_or("nothing".to_owned(), |a| format!("{name} = {:?}", a.as_str()));
                        self.problem(
                            format!("{loc}.permissions"),
                            format!(
                                "{name} = {:?} exceeds max_permissions of source {:?} (allows {limit})",
                                access.as_str(),
                                rule.source
                            ),
                        );
                    }
                }
            }
            None => {
                if !rule.permissions.is_empty() {
                    self.problem(
                        format!("{loc}.permissions"),
                        format!(
                            "permissions only apply to GitHub App sources; {:?} is {}",
                            rule.source,
                            source.kind.describe()
                        ),
                    );
                }
            }
        }
        if rule.per == TokenScope::Owner {
            if max.is_none() {
                self.problem(
                    format!("{loc}.per"),
                    format!(
                        "per only applies to GitHub App sources; {:?} is {}",
                        rule.source,
                        source.kind.describe()
                    ),
                );
            } else if rule.url.owner_wildcard().is_none() {
                self.problem(
                    format!("{loc}.per"),
                    format!(
                        "per = \"owner\" needs a pattern of the form https://<host>/<owner>/*, not {}",
                        rule.url
                    ),
                );
            }
        }
    }

    fn servers(&mut self) {
        let mut pinned: BTreeMap<Vec<u8>, &str> = BTreeMap::new();
        for (key, server) in &self.config.servers {
            let loc = format!("server.{key}");
            self.name(&loc, "server", key);
            if server.name != *key {
                self.problem(&loc, format!("name {:?} differs from the table name", server.name));
            }
            if server.profile == crate::UNREGISTERED_PROFILE {
                self.problem(
                    format!("{loc}.profile"),
                    "profile.unregistered is for hosts without a [server.*] entry; give the server a profile of its own",
                );
            } else if !self.config.profiles.contains_key(&server.profile) {
                self.problem(
                    format!("{loc}.profile"),
                    format!("{:?} is not a [profile.*] name", server.profile),
                );
            }
            self.host_keys(&loc, server, &mut pinned);
        }
    }

    fn host_keys<'s>(&mut self, loc: &str, server: &'s Server, pinned: &mut BTreeMap<Vec<u8>, &'s str>) {
        let keys = match &server.keys {
            ServerKeys::KnownHost(known) => {
                if let Some(problem) = known_hosts::lookup_name_problem(&known.name) {
                    self.problem(format!("{loc}.known_host"), format!("{:?} {problem}", known.name));
                }
                if known.files.is_empty() {
                    self.problem(
                        format!("{loc}.known_hosts_files"),
                        "no file listed; leave known_hosts_files out for OpenSSH's defaults",
                    );
                }
                for (i, file) in known.files.iter().enumerate() {
                    if !file.is_absolute() {
                        self.problem(
                            format!("{loc}.known_hosts_files[{i}]"),
                            format!("{} must be absolute (or start with ~/)", file.display()),
                        );
                    }
                }
                return;
            }
            ServerKeys::Pinned(keys) => keys,
        };
        if keys.is_empty() {
            self.problem(
                format!("{loc}.host_keys"),
                "no host key pinned; run credential-bridge-ctl server add",
            );
        }
        for host_key in keys {
            // Key data without the comment identifies a key.
            let Ok(blob) = host_key.to_bytes() else { continue };
            match pinned.get(&blob) {
                Some(other) if *other == server.name => {
                    self.problem(format!("{loc}.host_keys"), "the same host key is listed twice");
                }
                Some(other) => {
                    self.problem(
                        format!("{loc}.host_keys"),
                        format!(
                            "host key {} is also pinned for server {other:?}",
                            host_key.fingerprint(Default::default())
                        ),
                    );
                }
                None => {
                    pinned.insert(blob, &server.name);
                }
            }
        }
    }
}

/// See [`Config::warnings`].
pub(crate) fn warnings(config: &Config) -> Vec<Problem> {
    let mut warnings = Vec::new();
    let mut followed: Vec<(&str, BTreeSet<&Path>, &str)> = Vec::new();
    for (key, server) in &config.servers {
        let ServerKeys::KnownHost(known) = &server.keys else { continue };
        let files: BTreeSet<&Path> = known.files.iter().map(PathBuf::as_path).collect();
        if let Some((_, _, other)) =
            followed.iter().find(|(name, other_files, _)| *name == known.name && *other_files == files)
        {
            warnings.push(Problem::new(
                format!("server.{key}.known_host"),
                format!(
                    "server {other:?} follows {:?} in the same known_hosts files: every key belongs to both \
                     servers, so neither is recognised; remove one of them",
                    known.name
                ),
            ));
        }
        followed.push((&known.name, files, key));
    }
    warnings
}

/// Whether `a` and `b` name the same file: equal paths, or the same file once links are
/// resolved (only for paths that exist).
fn same_file(a: &Path, b: &Path) -> bool {
    a == b || matches!((std::fs::canonicalize(a), std::fs::canonicalize(b)), (Ok(x), Ok(y)) if x == y)
}

/// The problem with an App source's `api_url`, from the check the forge client applies
/// as well ([`credential_bridge_proto::api_url::check`]).
fn api_url_problem(api_url: &str) -> Option<String> {
    credential_bridge_proto::api_url::check(api_url).err().map(|why| format!("{api_url:?} {why}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for name in ["build", "my-org", "a.b_c-1", "X"] {
            assert!(valid_name(name), "{name}");
        }
        for name in ["", "a b", "a/b", "ä", "a:b"] {
            assert!(!valid_name(name), "{name}");
        }
    }

    #[test]
    fn api_urls_use_the_shared_check() {
        // Inputs where a hand-written check and the url crate used to disagree.
        for good in ["https://api.github.com", "HTTPS://h.com", "https://h.com:", "https://h.com:0443"] {
            assert_eq!(api_url_problem(good), None, "{good}");
        }
        for (bad, hint) in [
            ("https://h.com.", "invalid host"),
            ("https://[1::2::3]", "invalid host"),
            ("https://999.1.1.1", "invalid host"),
            ("https://ghe.example.com:8443/api/v3", "port 443"),
            ("http://127.0.0.1:8080", "https://"),
            // The url crate drops these, the forge client would not.
            ("https://api.github.com ", "whitespace"),
            ("https://api.github.com\n", "whitespace"),
        ] {
            let problem = api_url_problem(bad).expect(bad);
            assert!(problem.contains(hint), "{bad}: {problem}");
        }
    }
}
