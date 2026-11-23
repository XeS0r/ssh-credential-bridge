//! Typed edits of every section, for ctl.
//!
//! Each operation changes only the [`toml_edit`] document: what it touches is written in
//! the layout ctl uses (`ssh = { … }` inline tables, `[[profile.<name>.git]]` tables),
//! values it replaces keep their comments, and everything else stays as it was. An
//! operation checks what it can see locally (names, values, references it would break);
//! the whole configuration is validated by [`ConfigDocument::check`] and again by
//! [`ConfigDocument::save`] before anything is written.

use std::str::FromStr;

use credential_bridge_proto::ipc::git::{Permissions, TokenScope};
use toml_edit::{ArrayOfTables, InlineTable, Item, Table, TableLike, Value};

use super::{ConfigDocument, EditError};
use crate::UNREGISTERED_PROFILE;
use crate::duration::{MAX_DURATION, parse_duration};
use crate::pattern::UrlPattern;
use crate::secret_ref::SecretRef;
use crate::validate::valid_name;

/// What [`ConfigDocument::add_source`] writes: one variant per kind of `[source.*]`
/// (see [`crate::SourceKind`]). Secrets are references, never values.
#[derive(Debug, Clone, PartialEq)]
pub enum NewSource {
    /// `type = "github"`, `auth = "gh"`.
    GithubGh {
        /// `host`; `None` for github.com.
        host: Option<String>,
    },
    /// `type = "github"`, `auth = "pat"`.
    GithubPat {
        /// `host`; `None` for github.com.
        host: Option<String>,
        /// `token`.
        token: SecretRef,
    },
    /// `type = "github"`, `auth = "app"`.
    GithubApp {
        /// `host`; `None` for github.com.
        host: Option<String>,
        /// `api_url`; `None` for the default derived from the host.
        api_url: Option<String>,
        /// `app_id`.
        app_id: u64,
        /// `private_key`.
        private_key: SecretRef,
        /// `max_permissions`.
        max_permissions: Permissions,
    },
    /// `type = "gitlab"`, `auth = "token"`.
    Gitlab {
        /// `host`.
        host: String,
        /// `token`.
        token: SecretRef,
    },
    /// `type = "forgejo"` (or `"gitea"`), `auth = "token"`.
    Forgejo {
        /// Write `type = "gitea"` instead of `"forgejo"` (an alias).
        gitea: bool,
        /// `host`.
        host: String,
        /// `token`.
        token: SecretRef,
    },
    /// `type = "helper"`.
    Helper {
        /// `helper`, as in `credential.helper`.
        helper: String,
    },
}

/// One git rule for [`ConfigDocument::add_rule`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRule {
    /// `url`, a URL pattern.
    pub url: String,
    /// `source`.
    pub source: String,
    /// `permissions`; written only if not empty.
    pub permissions: Permissions,
    /// `per`; written only if given.
    pub per: Option<TokenScope>,
}

/// A profile field `profile set` can change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileKey {
    /// `ssh.keys`.
    SshKeys,
    /// `ssh.confirm`.
    SshConfirm,
    /// `hops.ssh`.
    HopsSsh,
    /// `hops.git`.
    HopsGit,
    /// `hops.gpg`.
    HopsGpg,
    /// `signing`.
    Signing,
    /// `gpg`.
    Gpg,
}

impl ProfileKey {
    /// Every key, in the order of the documentation.
    pub const ALL: [ProfileKey; 7] = [
        ProfileKey::SshKeys,
        ProfileKey::SshConfirm,
        ProfileKey::HopsSsh,
        ProfileKey::HopsGit,
        ProfileKey::HopsGpg,
        ProfileKey::Signing,
        ProfileKey::Gpg,
    ];

    /// The dotted name, e.g. `ssh.keys`.
    pub fn name(self) -> &'static str {
        match self {
            ProfileKey::SshKeys => "ssh.keys",
            ProfileKey::SshConfirm => "ssh.confirm",
            ProfileKey::HopsSsh => "hops.ssh",
            ProfileKey::HopsGit => "hops.git",
            ProfileKey::HopsGpg => "hops.gpg",
            ProfileKey::Signing => "signing",
            ProfileKey::Gpg => "gpg",
        }
    }

    /// The table key and, for nested keys, the key inside it.
    fn parts(self) -> (&'static str, Option<&'static str>) {
        match self {
            ProfileKey::SshKeys => ("ssh", Some("keys")),
            ProfileKey::SshConfirm => ("ssh", Some("confirm")),
            ProfileKey::HopsSsh => ("hops", Some("ssh")),
            ProfileKey::HopsGit => ("hops", Some("git")),
            ProfileKey::HopsGpg => ("hops", Some("gpg")),
            ProfileKey::Signing => ("signing", None),
            ProfileKey::Gpg => ("gpg", None),
        }
    }

    /// Whether `profile.unregistered` may set this key: only `ssh` and `hops.ssh`.
    pub fn allowed_in_unregistered(self) -> bool {
        matches!(self, ProfileKey::SshKeys | ProfileKey::SshConfirm | ProfileKey::HopsSsh)
    }

    /// The accepted values, for messages.
    pub fn expected(self) -> &'static str {
        match self {
            ProfileKey::SshKeys => "all, none, or upstream names separated by commas (fido,yubikey)",
            ProfileKey::SshConfirm => "always, never, or a duration such as 8h or 1h30m (at most 365d)",
            ProfileKey::HopsSsh | ProfileKey::HopsGit | ProfileKey::HopsGpg => "true or false",
            ProfileKey::Signing => "ssh",
            ProfileKey::Gpg => "sign, decrypt, sign,decrypt or none",
        }
    }
}

impl FromStr for ProfileKey {
    type Err = EditError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        ProfileKey::ALL.into_iter().find(|key| key.name() == text).ok_or_else(|| EditError::Value {
            key: text.to_owned(),
            message: format!(
                "unknown profile key; known keys: {}",
                ProfileKey::ALL.map(ProfileKey::name).join(", ")
            ),
        })
    }
}

/// `KEY=VALUE` for [`ConfigDocument::set_profile`], parsed and checked.
#[derive(Debug, Clone)]
pub struct ProfileSetting {
    key: ProfileKey,
    value: Value,
}

impl ProfileSetting {
    /// The key.
    pub fn key(&self) -> ProfileKey {
        self.key
    }

    /// Parses `KEY=VALUE`, e.g. `ssh.keys=fido,yubikey`, `ssh.confirm=8h`, `hops.ssh=false`,
    /// `signing=ssh`, `gpg=sign,decrypt`.
    pub fn parse(text: &str) -> Result<ProfileSetting, EditError> {
        let Some((key, value)) = text.split_once('=') else {
            return Err(EditError::Value {
                key: text.to_owned(),
                message: "expected KEY=VALUE, e.g. ssh.keys=all".to_owned(),
            });
        };
        let key: ProfileKey = key.trim().parse()?;
        let value = value.trim();
        let invalid = || EditError::Value {
            key: key.name().to_owned(),
            message: format!("expected {}", key.expected()),
        };
        let value: Value = match key {
            ProfileKey::SshKeys => match value {
                "all" => "all".into(),
                "none" | "" => Value::Array(toml_edit::Array::new()),
                list => {
                    let mut names = toml_edit::Array::new();
                    for name in list.split(',').map(str::trim) {
                        if !valid_name(name) || name == "all" || name == "none" {
                            return Err(EditError::Value {
                                key: key.name().to_owned(),
                                message: format!(
                                    "{name:?} is not an upstream name; expected {}",
                                    key.expected()
                                ),
                            });
                        }
                        if !names.iter().any(|known| known.as_str() == Some(name)) {
                            names.push(name);
                        }
                    }
                    Value::Array(names)
                }
            },
            ProfileKey::SshConfirm => match value {
                "always" | "never" => value.into(),
                duration => match parse_duration(duration) {
                    Ok(parsed) if !parsed.is_zero() && parsed <= MAX_DURATION => duration.into(),
                    _ => return Err(invalid()),
                },
            },
            ProfileKey::HopsSsh | ProfileKey::HopsGit | ProfileKey::HopsGpg => match value {
                "true" => true.into(),
                "false" => false.into(),
                _ => return Err(invalid()),
            },
            ProfileKey::Signing => match value {
                "ssh" => "ssh".into(),
                _ => return Err(invalid()),
            },
            ProfileKey::Gpg => {
                let mut operations = toml_edit::Array::new();
                if value != "none" {
                    for operation in value.split(',').map(str::trim) {
                        if !matches!(operation, "sign" | "decrypt") {
                            return Err(invalid());
                        }
                        if !operations.iter().any(|known| known.as_str() == Some(operation)) {
                            operations.push(operation);
                        }
                    }
                }
                Value::Array(operations)
            }
        };
        Ok(ProfileSetting { key, value })
    }
}

/// A `[daemon]` key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonKey {
    /// `socket`.
    Socket,
    /// `forward_socket`.
    ForwardSocket,
    /// `control_socket`.
    ControlSocket,
    /// `audit_log`.
    AuditLog,
}

impl DaemonKey {
    /// Every key.
    pub const ALL: [DaemonKey; 4] =
        [DaemonKey::Socket, DaemonKey::ForwardSocket, DaemonKey::ControlSocket, DaemonKey::AuditLog];

    /// The TOML key.
    pub fn name(self) -> &'static str {
        match self {
            DaemonKey::Socket => "socket",
            DaemonKey::ForwardSocket => "forward_socket",
            DaemonKey::ControlSocket => "control_socket",
            DaemonKey::AuditLog => "audit_log",
        }
    }
}

/// A `[vault.keepassxc]` key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepassxcKey {
    /// `database`.
    Database,
    /// `key_file`.
    KeyFile,
}

impl KeepassxcKey {
    /// The TOML key.
    pub fn name(self) -> &'static str {
        match self {
            KeepassxcKey::Database => "database",
            KeepassxcKey::KeyFile => "key_file",
        }
    }
}

/// The message for a part of the file written in a form ctl does not edit.
fn unsupported(location: impl Into<String>) -> EditError {
    EditError::Unsupported { location: location.into() }
}

/// Replaces the value of `key` in `table`, keeping the comments around an old value, or
/// adds it.
fn set_value(table: &mut dyn TableLike, key: &str, mut value: Value) {
    match table.get_mut(key) {
        Some(Item::Value(old)) => {
            *value.decor_mut() = old.decor().clone();
            *old = value;
        }
        _ => {
            table.insert(key, Item::Value(value));
        }
    }
}

/// Adds `key` at the end of `table`. In an inline table the new value takes over the
/// spacing before the closing brace, so `{ a = 1 }` becomes `{ a = 1, b = 2 }`.
fn append_value(table: &mut dyn TableLike, key: &str, mut value: Value, inline: bool) {
    if !inline {
        table.insert(key, Item::Value(value));
        return;
    }
    let last = table.iter().last().map(|(last, _)| last.to_owned());
    let inline = last.as_deref().and_then(|last| table.get_mut(last)).and_then(|item| item.as_value_mut());
    match inline {
        Some(previous) => {
            let suffix = previous.decor().suffix().cloned().unwrap_or_else(|| " ".into());
            previous.decor_mut().set_suffix("");
            value.decor_mut().set_prefix(" ");
            value.decor_mut().set_suffix(suffix);
        }
        None => {
            value.decor_mut().set_prefix(" ");
            value.decor_mut().set_suffix(" ");
        }
    }
    table.insert(key, Item::Value(value));
}

/// Removes `key` from `table`. In an inline table the spacing before the closing brace
/// moves to the value that is now last, so `{ a = 1, b = 2 }` becomes `{ a = 1 }`.
fn remove_value(table: &mut dyn TableLike, key: &str, inline: bool) {
    let keys: Vec<String> = table.iter().map(|(key, _)| key.to_owned()).collect();
    let Some(removed) = table.remove(key) else { return };
    let was_last = keys.last().is_some_and(|last| last == key);
    if !inline || !was_last || keys.len() < 2 {
        return;
    }
    let suffix = removed.as_value().and_then(|value| value.decor().suffix().cloned());
    if let (Some(suffix), Some(previous)) =
        (suffix, table.get_mut(&keys[keys.len() - 2]).and_then(Item::as_value_mut))
    {
        previous.decor_mut().set_suffix(suffix);
    }
}

/// The string value of `key` in a table-like item.
fn string_in<'a>(table: &'a dyn TableLike, key: &str) -> Option<&'a str> {
    table.get(key).and_then(Item::as_str)
}

/// A rule as shown in messages: `profile.dev.git[0] (https://github.com/*)`.
fn rule_label(profile: &str, index: usize, url: &str) -> String {
    format!("profile.{profile}.git[{index}] ({url})")
}

/// Quotes a shell word if needed, for the commands in messages.
fn shell_word(word: &str) -> String {
    if !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':' | ',' | '='))
    {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

impl ConfigDocument {
    // ── Reading ────────────────────────────────────────────────────────────────────

    /// The table-like item at `path`, if every part exists and is a table.
    fn table_like(&self, path: &[&str]) -> Option<&dyn TableLike> {
        let mut table: &dyn TableLike = self.doc.as_table();
        for key in path {
            table = table.get(key)?.as_table_like()?;
        }
        Some(table)
    }

    /// The table-like item at `path`, mutable.
    fn table_like_mut(&mut self, path: &[&str]) -> Option<&mut dyn TableLike> {
        let mut table: &mut dyn TableLike = self.doc.as_table_mut();
        for key in path {
            table = table.get_mut(key)?.as_table_like_mut()?;
        }
        Some(table)
    }

    /// The table at `path`, created if missing: intermediate tables as implicit tables
    /// (no header of their own), a new last one with a header. Existing tables keep how
    /// they are written.
    fn ensure_table(&mut self, path: &[&str]) -> Result<&mut Table, EditError> {
        let mut table = self.doc.as_table_mut();
        for (index, key) in path.iter().enumerate() {
            let last = index + 1 == path.len();
            let item = table.entry(key).or_insert_with(|| {
                let mut new = Table::new();
                new.set_implicit(!last);
                Item::Table(new)
            });
            table = item.as_table_mut().ok_or_else(|| unsupported(path[..=index].join(".")))?;
        }
        Ok(table)
    }

    /// Whether the file writes the key at the dotted `path`, e.g.
    /// `["profile", "dev", "ssh", "confirm"]` (`config show` marks the rest as built in).
    pub fn contains(&self, path: &[&str]) -> bool {
        match path.split_last() {
            None => true,
            Some((last, parents)) => self.table_like(parents).is_some_and(|table| table.contains_key(last)),
        }
    }

    /// The string written at the dotted `path`, if any.
    pub fn string_at(&self, path: &[&str]) -> Option<&str> {
        let (last, parents) = path.split_last()?;
        self.table_like(parents).and_then(|table| string_in(table, last))
    }

    /// Whether git rule `index` of profile `profile` writes `key`.
    pub fn rule_contains(&self, profile: &str, index: usize, key: &str) -> bool {
        match self.table_like(&["profile", profile]).and_then(|table| table.get("git")) {
            Some(Item::ArrayOfTables(rules)) => rules.get(index).is_some_and(|rule| rule.contains_key(key)),
            _ => false,
        }
    }

    /// The names of the tables under `section` (`source`, `profile`, `server`).
    fn names(&self, section: &str) -> Vec<String> {
        self.table_like(&[section])
            .map(|table| table.iter().map(|(name, _)| name.to_owned()).collect())
            .unwrap_or_default()
    }

    /// The `[[agent.upstream]]` names, in file order.
    pub fn upstream_names(&self) -> Vec<String> {
        let Some(item) = self.table_like(&["agent"]).and_then(|agent| agent.get("upstream")) else {
            return Vec::new();
        };
        match item {
            Item::ArrayOfTables(array) => {
                array.iter().filter_map(|table| string_in(table, "name").map(str::to_owned)).collect()
            }
            Item::Value(Value::Array(array)) => array
                .iter()
                .filter_map(|value| value.as_inline_table().and_then(|t| t.get("name")?.as_str()))
                .map(str::to_owned)
                .collect(),
            _ => Vec::new(),
        }
    }

    /// `agent.add_to`, if written.
    fn add_to(&self) -> Option<String> {
        self.table_like(&["agent"]).and_then(|agent| string_in(agent, "add_to")).map(str::to_owned)
    }

    /// Profiles whose `ssh.keys` list names `upstream`, with the list.
    fn profiles_showing(&self, upstream: &str) -> Vec<(String, Vec<String>)> {
        let mut found = Vec::new();
        for name in self.names("profile") {
            let Some(keys) = self
                .table_like(&["profile", &name, "ssh"])
                .and_then(|ssh| ssh.get("keys"))
                .and_then(Item::as_array)
            else {
                continue;
            };
            let keys: Vec<String> = keys.iter().filter_map(|key| key.as_str().map(str::to_owned)).collect();
            if keys.iter().any(|key| key == upstream) {
                found.push((name, keys));
            }
        }
        found
    }

    /// `(profile, index, url, source)` of every git rule.
    fn rules(&self) -> Vec<(String, usize, String, String)> {
        let mut found = Vec::new();
        for profile in self.names("profile") {
            let Some(Item::ArrayOfTables(rules)) =
                self.table_like(&["profile", &profile]).and_then(|table| table.get("git"))
            else {
                continue;
            };
            for (index, rule) in rules.iter().enumerate() {
                found.push((
                    profile.clone(),
                    index,
                    string_in(rule, "url").unwrap_or_default().to_owned(),
                    string_in(rule, "source").unwrap_or_default().to_owned(),
                ));
            }
        }
        found
    }

    /// The servers whose `profile` is `profile`.
    fn servers_with_profile(&self, profile: &str) -> Vec<String> {
        self.names("server")
            .into_iter()
            .filter(|server| {
                self.table_like(&["server", server]).and_then(|t| string_in(t, "profile")) == Some(profile)
            })
            .collect()
    }

    /// Whether `[section.name]` exists.
    fn has(&self, section: &str, name: &str) -> bool {
        self.table_like(&[section]).is_some_and(|table| table.contains_key(name))
    }

    // ── [agent] ────────────────────────────────────────────────────────────────────

    /// Appends `[[agent.upstream]]` with `name` and `socket` (a path or
    /// `gpgconf:<name>`), creating `[agent]` if needed.
    pub fn add_upstream(&mut self, name: &str, socket: &str) -> Result<(), EditError> {
        if self.upstream_names().iter().any(|known| known == name) {
            return Err(EditError::Exists { table: format!("[[agent.upstream]] {name:?}") });
        }
        let existed = self.table_like(&["agent"]).is_some();
        let agent = self.ensure_table(&["agent"])?;
        if !existed {
            // Only [[agent.upstream]] below: no [agent] header of its own.
            agent.set_implicit(true);
        }
        let item = agent.entry("upstream").or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()));
        let upstreams = item.as_array_of_tables_mut().ok_or_else(|| unsupported("agent.upstream"))?;
        let mut table = Table::new();
        table.insert("name", toml_edit::value(name));
        table.insert("socket", toml_edit::value(socket));
        upstreams.push(table);
        Ok(())
    }

    /// Changes the socket of `[[agent.upstream]]` `name`.
    pub fn set_upstream_socket(&mut self, name: &str, socket: &str) -> Result<(), EditError> {
        let table = self.upstream_mut(name)?;
        set_value(table, "socket", socket.into());
        Ok(())
    }

    fn upstream_mut(&mut self, name: &str) -> Result<&mut Table, EditError> {
        let not_found = || EditError::NotFound { table: format!("[[agent.upstream]] {name:?}") };
        let item = self
            .table_like_mut(&["agent"])
            .and_then(|agent| agent.get_mut("upstream"))
            .ok_or_else(not_found)?;
        let upstreams = item.as_array_of_tables_mut().ok_or_else(|| unsupported("agent.upstream"))?;
        upstreams.iter_mut().find(|table| string_in(*table, "name") == Some(name)).ok_or_else(not_found)
    }

    /// Removes `[[agent.upstream]]` `name`. Refused while `agent.add_to` or a profile's
    /// `ssh.keys` names it.
    pub fn remove_upstream(&mut self, name: &str) -> Result<(), EditError> {
        self.upstream_mut(name)?;
        let mut users = Vec::new();
        let mut fixes = Vec::new();
        if self.add_to().as_deref() == Some(name) {
            users.push("agent.add_to".to_owned());
            fixes.push("credential-bridge-ctl agent set --add-to OTHER (or --no-add-to)".to_owned());
        }
        for (profile, keys) in self.profiles_showing(name) {
            users.push(format!("profile.{profile}.ssh.keys"));
            let rest: Vec<&str> = keys.iter().map(String::as_str).filter(|key| *key != name).collect();
            let value = if rest.is_empty() { "none".to_owned() } else { rest.join(",") };
            fixes.push(format!(
                "credential-bridge-ctl profile set {} ssh.keys={}",
                shell_word(&profile),
                shell_word(&value)
            ));
        }
        if !users.is_empty() {
            return Err(EditError::InUse { item: format!("upstream {name:?}"), users, fixes });
        }
        let Some(Item::ArrayOfTables(upstreams)) =
            self.table_like_mut(&["agent"]).and_then(|agent| agent.get_mut("upstream"))
        else {
            return Err(unsupported("agent.upstream"));
        };
        upstreams.retain(|table| string_in(table, "name") != Some(name));
        let empty = upstreams.is_empty();
        if empty && let Some(agent) = self.table_like_mut(&["agent"]) {
            agent.remove("upstream");
            if agent.is_empty() {
                self.doc.remove("agent");
            }
        }
        Ok(())
    }

    /// Sets `agent.add_to` to `name` (an existing upstream), or removes it with `None`.
    pub fn set_add_to(&mut self, name: Option<&str>) -> Result<(), EditError> {
        match name {
            Some(name) => {
                if !self.upstream_names().iter().any(|known| known == name) {
                    return Err(EditError::NotFound { table: format!("[[agent.upstream]] {name:?}") });
                }
                let agent = self.ensure_table(&["agent"])?;
                agent.set_implicit(false);
                set_value(agent, "add_to", name.into());
            }
            None => {
                if let Some(agent) = self.table_like_mut(&["agent"]) {
                    agent.remove("add_to");
                    if agent.is_empty() {
                        self.doc.remove("agent");
                    }
                }
            }
        }
        Ok(())
    }

    // ── [source.*] ─────────────────────────────────────────────────────────────────

    /// Adds `[source.<name>]`. Errors with [`EditError::Exists`] if the table exists.
    pub fn add_source(&mut self, name: &str, source: &NewSource) -> Result<(), EditError> {
        if self.has("source", name) {
            return Err(EditError::Exists { table: format!("source.{name}") });
        }
        let mut table = Table::new();
        let host = |table: &mut Table, host: &Option<String>| {
            if let Some(host) = host.as_deref().filter(|host| *host != crate::load::GITHUB_HOST) {
                table.insert("host", toml_edit::value(host));
            }
        };
        match source {
            NewSource::GithubGh { host: h } => {
                table.insert("type", toml_edit::value("github"));
                table.insert("auth", toml_edit::value("gh"));
                host(&mut table, h);
            }
            NewSource::GithubPat { host: h, token } => {
                table.insert("type", toml_edit::value("github"));
                table.insert("auth", toml_edit::value("pat"));
                host(&mut table, h);
                table.insert("token", toml_edit::value(token.to_string()));
            }
            NewSource::GithubApp { host: h, api_url, app_id, private_key, max_permissions } => {
                let app_id = i64::try_from(*app_id).map_err(|_| EditError::Value {
                    key: format!("source.{name}.app_id"),
                    message: "app_id is too large".to_owned(),
                })?;
                table.insert("type", toml_edit::value("github"));
                table.insert("auth", toml_edit::value("app"));
                host(&mut table, h);
                if let Some(api_url) = api_url {
                    table.insert("api_url", toml_edit::value(api_url.as_str()));
                }
                table.insert("app_id", toml_edit::value(app_id));
                table.insert("private_key", toml_edit::value(private_key.to_string()));
                table.insert("max_permissions", toml_edit::value(permissions_table(max_permissions)));
            }
            NewSource::Gitlab { host, token } | NewSource::Forgejo { host, token, .. } => {
                let kind = match source {
                    NewSource::Gitlab { .. } => "gitlab",
                    NewSource::Forgejo { gitea: true, .. } => "gitea",
                    _ => "forgejo",
                };
                table.insert("type", toml_edit::value(kind));
                table.insert("host", toml_edit::value(host.as_str()));
                table.insert("auth", toml_edit::value("token"));
                table.insert("token", toml_edit::value(token.to_string()));
            }
            NewSource::Helper { helper } => {
                table.insert("type", toml_edit::value("helper"));
                table.insert("helper", toml_edit::value(helper.as_str()));
            }
        }
        let sources = self.parent_table("source")?;
        sources.insert(name, Item::Table(table));
        Ok(())
    }

    /// Removes `[source.<name>]`. Refused while a git rule uses it.
    pub fn remove_source(&mut self, name: &str) -> Result<(), EditError> {
        if !self.has("source", name) {
            return Err(EditError::NotFound { table: format!("source.{name}") });
        }
        let (users, fixes): (Vec<String>, Vec<String>) = self
            .rules()
            .into_iter()
            .filter(|(_, _, _, source)| source == name)
            .map(|(profile, index, url, _)| {
                (
                    rule_label(&profile, index, &url),
                    format!(
                        "credential-bridge-ctl profile rule remove {} {}",
                        shell_word(&profile),
                        shell_word(&url)
                    ),
                )
            })
            .unzip();
        if !users.is_empty() {
            return Err(EditError::InUse { item: format!("source {name:?}"), users, fixes });
        }
        self.remove_child("source", name);
        Ok(())
    }

    /// Sets `cache` of `[source.<name>]`: `false` writes `cache = false`, `true` removes
    /// the key (the default). Whether the source's kind takes `cache` is checked when the
    /// document is validated.
    pub fn set_source_cache(&mut self, name: &str, cache: bool) -> Result<(), EditError> {
        let source = self
            .table_like_mut(&["source", name])
            .ok_or_else(|| EditError::NotFound { table: format!("source.{name}") })?;
        if cache {
            source.remove("cache");
        } else {
            set_value(source, "cache", false.into());
        }
        Ok(())
    }

    /// Removes `[section.name]` and an implicit `[section]` left empty.
    fn remove_child(&mut self, section: &str, name: &str) -> bool {
        let Some(table) = self.table_like_mut(&[section]) else { return false };
        let removed = table.remove(name).is_some();
        if table.is_empty() && self.doc.get(section).and_then(Item::as_table).is_some_and(Table::is_implicit)
        {
            self.doc.remove(section);
        }
        removed
    }

    // ── [profile.*] ────────────────────────────────────────────────────────────────

    /// Adds an empty `[profile.<name>]` (a profile without `ssh` shows no keys and has
    /// no rules). `unregistered` is built in and cannot be added.
    pub fn add_profile(&mut self, name: &str) -> Result<(), EditError> {
        if name == UNREGISTERED_PROFILE {
            return Err(EditError::Value {
                key: format!("profile.{name}"),
                message: "profile.unregistered is built in; change it with \
                          credential-bridge-ctl profile set unregistered KEY=VALUE"
                    .to_owned(),
            });
        }
        if self.has("profile", name) {
            return Err(EditError::Exists { table: format!("profile.{name}") });
        }
        let profiles = self.parent_table("profile")?;
        profiles.insert(name, Item::Table(Table::new()));
        Ok(())
    }

    /// The table of profile `name`; `[profile.unregistered]` is created if missing.
    fn profile_mut(&mut self, name: &str) -> Result<&mut dyn TableLike, EditError> {
        if name == UNREGISTERED_PROFILE && !self.has("profile", name) {
            let profiles = self.parent_table("profile")?;
            profiles.insert(name, Item::Table(Table::new()));
        }
        if !self.has("profile", name) {
            return Err(EditError::NotFound { table: format!("profile.{name}") });
        }
        self.table_like_mut(&["profile", name]).ok_or_else(|| unsupported(format!("profile.{name}")))
    }

    /// Sets one field of profile `name`. In `profile.unregistered` only `ssh.keys`,
    /// `ssh.confirm` and `hops.ssh` may be set; `[profile.unregistered]` is created when
    /// needed.
    pub fn set_profile(&mut self, name: &str, setting: &ProfileSetting) -> Result<(), EditError> {
        if name == UNREGISTERED_PROFILE && !setting.key.allowed_in_unregistered() {
            return Err(EditError::Value {
                key: format!("profile.{name}.{}", setting.key.name()),
                message: "profile.unregistered allows only ssh.keys, ssh.confirm and hops.ssh: hosts \
                          without a [server.*] entry never get tokens, gpg or signing"
                    .to_owned(),
            });
        }
        let profile = self.profile_mut(name)?;
        let (outer, inner) = setting.key.parts();
        match inner {
            None => set_value(profile, outer, setting.value.clone()),
            Some(inner) => {
                if profile.get(outer).is_none() {
                    profile.insert(outer, Item::Value(Value::InlineTable(InlineTable::new())));
                }
                let inline = profile.get(outer).is_some_and(Item::is_inline_table);
                let table = profile
                    .get_mut(outer)
                    .and_then(Item::as_table_like_mut)
                    .ok_or_else(|| unsupported(format!("profile.{name}.{outer}")))?;
                match table.get_mut(inner) {
                    Some(_) => set_value(table, inner, setting.value.clone()),
                    None => append_value(table, inner, setting.value.clone(), inline),
                }
            }
        }
        Ok(())
    }

    /// Removes one field of profile `name`; a `ssh` or `hops` table left empty goes too.
    /// Nothing happens if it is not set.
    pub fn unset_profile(&mut self, name: &str, key: ProfileKey) -> Result<(), EditError> {
        if name == UNREGISTERED_PROFILE && !self.has("profile", name) {
            return Ok(());
        }
        let profile = self.profile_mut(name)?;
        let (outer, inner) = key.parts();
        match inner {
            None => {
                profile.remove(outer);
            }
            Some(inner) => {
                let inline = profile.get(outer).is_some_and(Item::is_inline_table);
                let Some(table) = profile.get_mut(outer).and_then(Item::as_table_like_mut) else {
                    return Ok(());
                };
                remove_value(table, inner, inline);
                if table.is_empty() {
                    profile.remove(outer);
                }
            }
        }
        Ok(())
    }

    /// Removes `[profile.<name>]` with its rules. Refused while a server uses it.
    /// Removing `profile.unregistered` brings back the built-in defaults.
    pub fn remove_profile(&mut self, name: &str) -> Result<(), EditError> {
        if name == UNREGISTERED_PROFILE {
            self.remove_child("profile", name);
            return Ok(());
        }
        if !self.has("profile", name) {
            return Err(EditError::NotFound { table: format!("profile.{name}") });
        }
        let users: Vec<String> = self.servers_with_profile(name);
        if !users.is_empty() {
            let fixes = users
                .iter()
                .map(|server| {
                    let server = shell_word(server);
                    format!(
                        "credential-bridge-ctl server set {server} --profile OTHER \
                         (or credential-bridge-ctl server remove {server})"
                    )
                })
                .collect();
            let users = users.iter().map(|server| format!("server.{server}")).collect();
            return Err(EditError::InUse { item: format!("profile {name:?}"), users, fixes });
        }
        self.remove_child("profile", name);
        Ok(())
    }

    /// Appends a `[[profile.<name>.git]]` rule, or inserts it before the rule whose
    /// `url` is `before`. A second rule with the same URL is refused: it could never
    /// match.
    pub fn add_rule(&mut self, profile: &str, rule: &NewRule, before: Option<&str>) -> Result<(), EditError> {
        if profile == UNREGISTERED_PROFILE {
            return Err(EditError::Value {
                key: format!("profile.{profile}.git"),
                message: "git rules are not allowed in profile.unregistered: hosts without a \
                          [server.*] entry never get tokens"
                    .to_owned(),
            });
        }
        if let Err(error) = UrlPattern::parse(&rule.url) {
            return Err(EditError::Value { key: "url".to_owned(), message: error.reason.to_owned() });
        }
        let rules = self.rules();
        if let Some((_, index, _, _)) = rules.iter().find(|(p, _, url, _)| p == profile && *url == rule.url) {
            return Err(EditError::Exists { table: rule_label(profile, *index, &rule.url) });
        }
        let position = match before {
            None => None,
            Some(before) => match rules.iter().find(|(p, _, url, _)| p == profile && url == before) {
                Some((_, index, _, _)) => Some(*index),
                None => {
                    return Err(EditError::NotFound {
                        table: format!("profile.{profile}.git rule {before}"),
                    });
                }
            },
        };
        let mut table = Table::new();
        table.insert("url", toml_edit::value(rule.url.as_str()));
        table.insert("source", toml_edit::value(rule.source.as_str()));
        if !rule.permissions.is_empty() {
            table.insert("permissions", toml_edit::value(permissions_table(&rule.permissions)));
        }
        if let Some(per) = rule.per {
            table.insert("per", toml_edit::value(per.as_str()));
        }
        let table_location = format!("profile.{profile}");
        let profile_table = self.profile_mut(profile)?;
        if profile_table.get("git").is_none() {
            profile_table.insert("git", Item::ArrayOfTables(ArrayOfTables::new()));
        }
        let git = profile_table
            .get_mut("git")
            .and_then(Item::as_array_of_tables_mut)
            .ok_or_else(|| unsupported(format!("{table_location}.git")))?;
        match position {
            Some(index) => git.insert(index, table),
            None => git.push(table),
        }
        Ok(())
    }

    /// Removes the git rule of profile `profile` whose `url` is `url`.
    pub fn remove_rule(&mut self, profile: &str, url: &str) -> Result<(), EditError> {
        let not_found = || EditError::NotFound { table: format!("profile.{profile}.git rule {url}") };
        let location = format!("profile.{profile}.git");
        let profile_table = self.profile_mut(profile)?;
        let Some(item) = profile_table.get_mut("git") else { return Err(not_found()) };
        let git = item.as_array_of_tables_mut().ok_or_else(|| unsupported(location))?;
        let index = git.iter().position(|rule| string_in(rule, "url") == Some(url)).ok_or_else(not_found)?;
        git.remove(index);
        if git.is_empty() {
            profile_table.remove("git");
        }
        Ok(())
    }

    // ── [server.*] ─────────────────────────────────────────────────────────────────

    /// Changes the `profile` of `[server.<name>]`.
    pub fn set_server_profile(&mut self, name: &str, profile: &str) -> Result<(), EditError> {
        let server = self
            .table_like_mut(&["server", name])
            .ok_or_else(|| EditError::NotFound { table: format!("server.{name}") })?;
        set_value(server, "profile", profile.into());
        Ok(())
    }

    // ── [vault], [gpg], [daemon] ───────────────────────────────────────────────────

    /// Sets (`Some`) or removes (`None`) one key of the table at `path`, which is created
    /// with a header when a value is set.
    fn set_string(&mut self, path: &[&str], key: &str, value: Option<&str>) -> Result<(), EditError> {
        match value {
            Some(value) => {
                let table = self.ensure_table(path)?;
                set_value(table, key, value.into());
            }
            None => {
                if let Some(table) = self.table_like_mut(path) {
                    table.remove(key);
                }
            }
        }
        Ok(())
    }

    /// Sets or removes one key of `[vault.keepassxc]`.
    pub fn set_keepassxc(&mut self, key: KeepassxcKey, value: Option<&str>) -> Result<(), EditError> {
        self.set_string(&["vault", "keepassxc"], key.name(), value)
    }

    /// Removes `[vault.keepassxc]` (and `[vault]` if nothing else is left). Returns
    /// whether it existed.
    pub fn remove_keepassxc(&mut self) -> bool {
        let Some(vault) = self.table_like_mut(&["vault"]) else { return false };
        let removed = vault.remove("keepassxc").is_some();
        if vault.is_empty() {
            self.doc.remove("vault");
        }
        removed
    }

    /// Creates `[gpg]` if missing and changes its `socket`: `None` keeps it as it is,
    /// `Some(None)` removes it (so the default `gpgconf:agent-extra-socket` applies),
    /// `Some(Some(socket))` sets it.
    pub fn set_gpg(&mut self, socket: Option<Option<&str>>) -> Result<(), EditError> {
        let table = self.ensure_table(&["gpg"])?;
        match socket {
            None => {}
            Some(Some(socket)) => set_value(table, "socket", socket.into()),
            Some(None) => {
                table.remove("socket");
            }
        }
        Ok(())
    }

    /// Removes `[gpg]`. Refused while a profile allows gpg. Returns whether it existed.
    pub fn remove_gpg(&mut self) -> Result<bool, EditError> {
        let users: Vec<String> = self
            .names("profile")
            .into_iter()
            .filter(|profile| {
                self.table_like(&["profile", profile])
                    .and_then(|table| table.get("gpg"))
                    .and_then(Item::as_array)
                    .is_some_and(|operations| !operations.is_empty())
            })
            .collect();
        if !users.is_empty() {
            let fixes = users
                .iter()
                .map(|profile| format!("credential-bridge-ctl profile set {} gpg=none", shell_word(profile)))
                .collect();
            let users = users.iter().map(|profile| format!("profile.{profile}.gpg")).collect();
            return Err(EditError::InUse { item: "[gpg]".to_owned(), users, fixes });
        }
        Ok(self.doc.remove("gpg").is_some())
    }

    /// Sets or removes one key of `[daemon]`.
    pub fn set_daemon(&mut self, key: DaemonKey, value: Option<&str>) -> Result<(), EditError> {
        self.set_string(&["daemon"], key.name(), value)
    }
}

/// `{ contents = "write", … }`.
pub(crate) fn permissions_table(permissions: &Permissions) -> InlineTable {
    let mut table = InlineTable::new();
    for (permission, access) in permissions {
        table.insert(permission, access.as_str().into());
    }
    table
}

#[cfg(test)]
mod tests;
