//! Parsing and validation.
//!
//! Parsing runs in stages: TOML syntax, 0.1 detection and version check on the generic
//! TOML table, then the schema (serde, unknown keys rejected), then conversion into the
//! model, which collects every problem it finds, and finally the semantic checks of
//! [`crate::validate`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use credential_bridge_proto::ipc::git::{Permissions, TokenScope};
use credential_bridge_proto::ipc::gpg::GpgPolicy;
use serde::Deserialize;

use crate::duration::parse_duration;
use crate::error::{ConfigError, Problem};
use crate::known_hosts;
use crate::model::{
    AgentConfig, Config, Confirm, DaemonConfig, GitRule, GpgConfig, Hops, KeepassxcConfig, KeySelection,
    KnownHost, Profile, Server, ServerKeys, Signing, SocketSpec, Source, SourceKind, SshPolicy, Upstream,
    VaultConfig,
};
use crate::paths::Paths;
use crate::pattern::UrlPattern;
use crate::secret_ref::SecretRef;
use crate::{CONFIG_VERSION, UNREGISTERED_PROFILE, validate};

/// Path reported by [`Config::parse`], which has no file.
const STRING_PATH: &str = "<string>";

/// Prefix of [`SocketSpec::Gpgconf`] sockets.
pub(crate) const GPGCONF_PREFIX: &str = "gpgconf:";

/// Default `[gpg] socket`.
const DEFAULT_GPG_SOCKET: &str = "agent-extra-socket";

/// The name of the profile 0.2 development versions used for unknown servers; now
/// rejected in favour of [`UNREGISTERED_PROFILE`].
const REMOVED_DEFAULT_PROFILE: &str = "default";

/// Default GitHub host.
pub(crate) const GITHUB_HOST: &str = "github.com";

impl Config {
    /// Reads, parses and validates `path`.
    ///
    /// A missing file yields `Config` with only `daemon` defaults from `paths` (no agent,
    /// no profiles: token-only mode where every server gets nothing).
    ///
    /// Errors: [`ConfigError::Io`] for other read errors, and everything
    /// [`Config::parse`] returns, with `path` filled in.
    pub fn load(path: &Path, paths: &Paths) -> Result<Config, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(text) => parse_at(&text, paths, path),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Config::empty(paths)),
            Err(source) => Err(ConfigError::Io { path: path.to_owned(), source }),
        }
    }

    /// Parses and validates configuration text. `paths` supplies the home directory for
    /// `~/` expansion and the `[daemon]` defaults.
    ///
    /// Order of checks: TOML syntax ([`ConfigError::Syntax`]); then 0.1 detection
    /// ([`ConfigError::Legacy`]: no `version` key, or a `remote` key; a document without
    /// any key is an empty configuration); then [`ConfigError::Version`]; then the schema
    /// ([`ConfigError::Syntax`], unknown keys and wrong types are errors); then all
    /// semantic rules, collected into one [`ConfigError::Invalid`]:
    ///
    /// - names (upstream, source, profile, server) match `[A-Za-z0-9._-]+`;
    /// - references resolve (`profile`, `source`, `add_to`, `ssh.keys`);
    /// - URL patterns, secret references, host keys and durations parse;
    /// - `per = "owner"` only for `owner/*` patterns;
    /// - rule `permissions` only for App sources and within `max_permissions`;
    /// - a rule's host equals its source's host;
    /// - `[gpg]` present if a profile allows gpg;
    /// - no `profile.default` (removed; `profile.unregistered` replaces it), no git rules,
    ///   gpg, signing, `hops.git` or `hops.gpg` in `profile.unregistered`, and no server
    ///   with `profile = "unregistered"`;
    /// - socket paths absolute after expansion and at most
    ///   [`crate::paths::max_socket_path_len`] bytes on this system;
    /// - `[vault.keepassxc]` paths absolute after expansion, `key_file` only with
    ///   `database`, and on macOS `database` set if a `keepassxc://` reference is used;
    /// - every server has exactly one of `known_host` (a single host name or
    ///   `[host]:port`, with `known_hosts_files` absolute after expansion if given) and
    ///   `host_keys` (non-empty, no key pinned twice or for two servers).
    pub fn parse(text: &str, paths: &Paths) -> Result<Config, ConfigError> {
        parse_at(text, paths, Path::new(STRING_PATH))
    }

    /// Re-runs the semantic checks of [`Config::parse`] on a (possibly hand-built)
    /// configuration. Empty when valid. `ctl check` uses this to list every problem.
    pub fn validate(&self) -> Vec<Problem> {
        validate::check(self, &BTreeSet::new())
    }

    /// What loads but is most likely a mistake: two servers that follow the same
    /// `known_host` in the same known_hosts files (each of their keys belongs to both,
    /// so neither is recognised). Not an error: the file stays loadable, `ctl check`
    /// and every ctl change show these as warnings.
    pub fn warnings(&self) -> Vec<Problem> {
        validate::warnings(self)
    }
}

/// `[daemon]` of the configuration at `path`, for ctl where the file may not load (`ctl
/// daemon alive`, which runs on every ssh call, and every command that only talks to the
/// daemon): read with a minimal parse that ignores the rest of the file, so a mistake
/// elsewhere (which [`Config::load`] would reject) does not send ctl to the wrong socket
/// or audit log. Paths are handled as [`Config::load`] does (`~/` expanded); the default
/// from `paths` is used for a key that is absent, not a string or not absolute, and for
/// all of them when the file is missing or unreadable or not valid TOML (then nothing in
/// it can be trusted; `ctl check` names the error).
pub fn daemon_settings(path: &Path, paths: &Paths) -> DaemonConfig {
    let Ok(text) = std::fs::read_to_string(path) else { return DaemonConfig::from_paths(paths) };
    daemon_settings_in(&text, paths)
}

/// [`daemon_settings`] for configuration text.
fn daemon_settings_in(text: &str, paths: &Paths) -> DaemonConfig {
    let table = text.parse::<toml::Table>().ok();
    let daemon = table.as_ref().and_then(|table| table.get("daemon")).and_then(toml::Value::as_table);
    let pick = |key: &str, default: &PathBuf| {
        match daemon.and_then(|daemon| daemon.get(key)) {
            Some(toml::Value::String(value)) => Some(paths.expand_home(Path::new(value))),
            _ => None,
        }
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| default.clone())
    };
    DaemonConfig {
        socket: pick("socket", &paths.agent_socket),
        forward_socket: pick("forward_socket", &paths.forward_socket),
        control_socket: pick("control_socket", &paths.control_socket),
        audit_log: pick("audit_log", &paths.audit_log),
    }
}

/// [`Config::parse`] with `path` in the errors.
pub(crate) fn parse_at(text: &str, paths: &Paths, path: &Path) -> Result<Config, ConfigError> {
    let syntax = |err: toml::de::Error| ConfigError::Syntax {
        path: path.to_owned(),
        message: err.to_string().trim_end().to_owned(),
    };
    let table: toml::Table = text.parse().map_err(syntax)?;
    if table.is_empty() {
        return Ok(Config::empty(paths));
    }
    if table.contains_key("remote") {
        return Err(ConfigError::Legacy { path: path.to_owned() });
    }
    match table.get("version") {
        None => return Err(ConfigError::Legacy { path: path.to_owned() }),
        Some(toml::Value::Integer(version)) if *version == i64::from(CONFIG_VERSION) => {}
        Some(toml::Value::Integer(version)) => {
            return Err(ConfigError::Version { path: path.to_owned(), version: *version });
        }
        Some(_) => {
            return Err(ConfigError::Syntax {
                path: path.to_owned(),
                message: format!("version must be an integer, e.g. version = {CONFIG_VERSION}"),
            });
        }
    }
    let raw: RawConfig = toml::from_str(text).map_err(syntax)?;

    let mut converter = Converter { paths, problems: Vec::new(), broken_sources: BTreeSet::new() };
    let config = converter.config(raw);
    let mut problems = converter.problems;
    let checked = validate::check(&config, &converter.broken_sources);
    // A value that failed to convert was replaced by a stand-in; drop follow-up
    // problems about the same spot so each mistake is reported once.
    let reported: Vec<String> = problems.iter().map(|p| p.location.clone()).collect();
    problems.extend(checked.into_iter().filter(|p| !reported.iter().any(|loc| related(loc, &p.location))));
    if problems.is_empty() {
        Ok(config)
    } else {
        Err(ConfigError::Invalid { path: path.to_owned(), problems })
    }
}

/// Whether one location is the other or lies inside it (`a.b` and `a.b[0].c`).
fn related(a: &str, b: &str) -> bool {
    let inside = |outer: &str, inner: &str| {
        inner.strip_prefix(outer).is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '[']))
    };
    inside(a, b) || inside(b, a)
}

// ── Schema ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    /// Checked before deserializing.
    #[allow(dead_code)]
    version: i64,
    daemon: Option<RawDaemon>,
    agent: Option<RawAgent>,
    gpg: Option<RawGpg>,
    #[serde(default)]
    vault: RawVault,
    #[serde(default)]
    source: BTreeMap<String, RawSource>,
    #[serde(default)]
    profile: BTreeMap<String, RawProfile>,
    #[serde(default)]
    server: BTreeMap<String, RawServer>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDaemon {
    socket: Option<String>,
    forward_socket: Option<String>,
    control_socket: Option<String>,
    audit_log: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgent {
    add_to: Option<String>,
    #[serde(default)]
    upstream: Vec<RawUpstream>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUpstream {
    name: String,
    socket: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGpg {
    socket: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVault {
    #[serde(default)]
    keepassxc: RawKeepassxc,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKeepassxc {
    database: Option<String>,
    key_file: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSource {
    #[serde(rename = "type")]
    kind: String,
    auth: Option<String>,
    host: Option<String>,
    api_url: Option<String>,
    app_id: Option<u64>,
    private_key: Option<String>,
    max_permissions: Option<Permissions>,
    token: Option<String>,
    helper: Option<String>,
    cache: Option<bool>,
}

impl RawSource {
    /// The optional keys that are set (all but `type` and `auth`).
    fn present_keys(&self) -> Vec<&'static str> {
        [
            ("host", self.host.is_some()),
            ("api_url", self.api_url.is_some()),
            ("app_id", self.app_id.is_some()),
            ("private_key", self.private_key.is_some()),
            ("max_permissions", self.max_permissions.is_some()),
            ("token", self.token.is_some()),
            ("helper", self.helper.is_some()),
            ("cache", self.cache.is_some()),
        ]
        .into_iter()
        .filter_map(|(key, set)| set.then_some(key))
        .collect()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    ssh: Option<RawSsh>,
    gpg: Option<Vec<String>>,
    hops: Option<RawHops>,
    signing: Option<String>,
    #[serde(default)]
    git: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSsh {
    keys: Option<RawKeys>,
    confirm: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawKeys {
    Word(String),
    List(Vec<String>),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHops {
    ssh: Option<bool>,
    git: Option<bool>,
    gpg: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    url: String,
    source: String,
    #[serde(default)]
    permissions: Permissions,
    #[serde(default)]
    per: TokenScope,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    known_host: Option<String>,
    known_hosts_files: Option<Vec<String>>,
    host_keys: Option<Vec<String>>,
    profile: String,
    #[serde(default = "default_true")]
    git_config: bool,
}

fn default_true() -> bool {
    true
}

// ── Conversion ─────────────────────────────────────────────────────────────────────

/// Turns the schema into the model, recording problems of single values.
struct Converter<'a> {
    paths: &'a Paths,
    problems: Vec<Problem>,
    /// Sources that could not be converted; rules naming them are not checked further.
    broken_sources: BTreeSet<String>,
}

impl Converter<'_> {
    fn problem(&mut self, location: impl Into<String>, message: impl Into<String>) {
        self.problems.push(Problem::new(location, message));
    }

    fn config(&mut self, raw: RawConfig) -> Config {
        let daemon = self.daemon(raw.daemon.unwrap_or_default());
        let agent = raw.agent.map(|agent| AgentConfig {
            add_to: agent.add_to,
            upstreams: agent
                .upstream
                .into_iter()
                .map(|u| Upstream { name: u.name, socket: self.socket_spec(&u.socket) })
                .collect(),
        });
        let gpg = raw.gpg.map(|gpg| GpgConfig {
            socket: gpg
                .socket
                .map_or_else(|| SocketSpec::Gpgconf(DEFAULT_GPG_SOCKET.to_owned()), |s| self.socket_spec(&s)),
        });
        let vault = VaultConfig {
            keepassxc: KeepassxcConfig {
                database: raw.vault.keepassxc.database.map(|path| self.path(&path)),
                key_file: raw.vault.keepassxc.key_file.map(|path| self.path(&path)),
            },
        };
        let mut sources = BTreeMap::new();
        for (name, raw) in raw.source {
            let cache = raw.cache.unwrap_or(true);
            match self.source(&name, raw) {
                Some(kind) => {
                    sources.insert(name.clone(), Source { name, kind, cache });
                }
                None => {
                    self.broken_sources.insert(name);
                }
            }
        }
        let mut raw_profiles = raw.profile;
        if raw_profiles.remove(REMOVED_DEFAULT_PROFILE).is_some() {
            self.problem(
                format!("profile.{REMOVED_DEFAULT_PROFILE}"),
                "profile.default was removed: hosts without a [server.*] entry get the built-in \
                 profile.unregistered (no keys, a dialog for every signature, no tokens, no gpg); \
                 to loosen it, write [profile.unregistered], e.g. ssh = { keys = [\"fido\"], confirm = \"8h\" }",
            );
        }
        let unregistered = match raw_profiles.remove(UNREGISTERED_PROFILE) {
            Some(raw) => self.profile(UNREGISTERED_PROFILE, raw, &Profile::unregistered()),
            None => Profile::unregistered(),
        };
        let registered = Profile {
            name: String::new(),
            ssh: None,
            gpg: GpgPolicy::default(),
            hops: Hops::default(),
            signing: None,
            git: Vec::new(),
        };
        let profiles = raw_profiles
            .into_iter()
            .map(|(name, raw)| {
                let profile = self.profile(&name, raw, &registered);
                (name, profile)
            })
            .collect();
        let servers = raw
            .server
            .into_iter()
            .map(|(name, raw)| {
                let server = self.server(&name, raw);
                (name, server)
            })
            .collect();
        Config { daemon, agent, gpg, vault, sources, profiles, unregistered, servers }
    }

    fn path(&self, text: &str) -> PathBuf {
        self.paths.expand_home(Path::new(text))
    }

    fn daemon(&self, raw: RawDaemon) -> DaemonConfig {
        let pick = |value: Option<String>, default: &PathBuf| {
            value.map_or_else(|| default.clone(), |v| self.path(&v))
        };
        DaemonConfig {
            socket: pick(raw.socket, &self.paths.agent_socket),
            forward_socket: pick(raw.forward_socket, &self.paths.forward_socket),
            control_socket: pick(raw.control_socket, &self.paths.control_socket),
            audit_log: pick(raw.audit_log, &self.paths.audit_log),
        }
    }

    fn socket_spec(&self, text: &str) -> SocketSpec {
        match text.strip_prefix(GPGCONF_PREFIX) {
            Some(name) => SocketSpec::Gpgconf(name.to_owned()),
            None => SocketSpec::Path(self.path(text)),
        }
    }

    fn secret_ref(&mut self, location: String, text: &str) -> Option<SecretRef> {
        match text.parse() {
            Ok(reference) => Some(reference),
            Err(err) => {
                self.problem(location, err.to_string());
                None
            }
        }
    }

    /// The source kind, or `None` after recording why it is invalid.
    fn source(&mut self, name: &str, raw: RawSource) -> Option<SourceKind> {
        let loc = format!("source.{name}");
        let (allowed, label): (&[&str], String) = match (raw.kind.as_str(), raw.auth.as_deref()) {
            ("github", Some("gh")) => (&["host"], "type = \"github\", auth = \"gh\"".into()),
            ("github", Some("pat")) => {
                (&["host", "token", "cache"], "type = \"github\", auth = \"pat\"".into())
            }
            ("github", Some("app")) => (
                &["host", "api_url", "app_id", "private_key", "max_permissions", "cache"],
                "type = \"github\", auth = \"app\"".into(),
            ),
            ("github", None) => {
                self.problem(format!("{loc}.auth"), "missing auth: \"gh\", \"pat\" or \"app\"");
                return None;
            }
            ("github", Some(other)) => {
                self.problem(
                    format!("{loc}.auth"),
                    format!(
                        "unknown auth {other:?} for type = \"github\": expected \"gh\", \"pat\" or \"app\""
                    ),
                );
                return None;
            }
            (kind @ ("gitlab" | "forgejo" | "gitea"), None | Some("token")) => {
                (&["host", "token", "cache"], format!("type = {kind:?}"))
            }
            (kind @ ("gitlab" | "forgejo" | "gitea"), Some(other)) => {
                self.problem(
                    format!("{loc}.auth"),
                    format!("unknown auth {other:?} for type = {kind:?}: expected \"token\""),
                );
                return None;
            }
            ("helper", None) => (&["helper"], "type = \"helper\"".into()),
            ("helper", Some(_)) => {
                self.problem(format!("{loc}.auth"), "type = \"helper\" takes no auth");
                return None;
            }
            (other, _) => {
                self.problem(
                    format!("{loc}.type"),
                    format!(
                        "unknown type {other:?}: expected \"github\", \"gitlab\", \"forgejo\", \"gitea\" or \"helper\""
                    ),
                );
                return None;
            }
        };
        let mut ok = true;
        for key in raw.present_keys() {
            if !allowed.contains(&key) {
                let why = if key == "cache" {
                    ": the bridge caches no tokens of gh and helper sources"
                } else {
                    ""
                };
                self.problem(format!("{loc}.{key}"), format!("{key} is not used with {label}{why}"));
                ok = false;
            }
        }
        let require = |this: &mut Self, key: &str, value: Option<String>| {
            if value.is_none() {
                this.problem(format!("{loc}.{key}"), format!("{label} needs {key}"));
            }
            value
        };
        let host = raw.host.map(|h| h.to_ascii_lowercase());
        let kind = match (raw.kind.as_str(), raw.auth.as_deref()) {
            ("github", Some("gh")) => Some(SourceKind::GithubGh { host: host.unwrap_or_else(github_host) }),
            ("github", Some("pat")) => {
                let token = require(self, "token", raw.token);
                let token = token.and_then(|t| self.secret_ref(format!("{loc}.token"), &t));
                token.map(|token| SourceKind::GithubPat { host: host.unwrap_or_else(github_host), token })
            }
            ("github", Some("app")) => {
                let host = host.unwrap_or_else(github_host);
                let api_url = raw
                    .api_url
                    .map_or_else(|| default_api_url(&host), |url| url.trim_end_matches('/').to_owned());
                let app_id = raw.app_id;
                if app_id.is_none() {
                    self.problem(format!("{loc}.app_id"), format!("{label} needs app_id"));
                }
                let max_permissions = raw.max_permissions;
                if max_permissions.is_none() {
                    self.problem(
                        format!("{loc}.max_permissions"),
                        format!("{label} needs max_permissions, e.g. {{ contents = \"read\" }}"),
                    );
                }
                let key = require(self, "private_key", raw.private_key);
                let key = key.and_then(|k| self.secret_ref(format!("{loc}.private_key"), &k));
                match (app_id, key, max_permissions) {
                    (Some(app_id), Some(private_key), Some(max_permissions)) => {
                        Some(SourceKind::GithubApp { host, api_url, app_id, private_key, max_permissions })
                    }
                    _ => None,
                }
            }
            (kind, _) if kind != "helper" => {
                if host.is_none() {
                    self.problem(format!("{loc}.host"), format!("{label} needs host"));
                }
                let token = require(self, "token", raw.token);
                let token = token.and_then(|t| self.secret_ref(format!("{loc}.token"), &t));
                match (host, token) {
                    (Some(host), Some(token)) if kind == "gitlab" => {
                        Some(SourceKind::GitlabToken { host, token })
                    }
                    (Some(host), Some(token)) => Some(SourceKind::ForgejoToken { host, token }),
                    _ => None,
                }
            }
            _ => require(self, "helper", raw.helper).map(|helper| SourceKind::Helper { helper }),
        };
        kind.filter(|_| ok)
    }

    /// The profile `name`; what `raw` leaves out comes from `defaults` (`ssh`, `hops`,
    /// and `confirm` for a written `ssh`, `"never"` without a default `ssh`).
    fn profile(&mut self, name: &str, raw: RawProfile, defaults: &Profile) -> Profile {
        let loc = format!("profile.{name}");
        let default_confirm = defaults.ssh.as_ref().map_or(Confirm::Never, |ssh| ssh.confirm);
        let ssh = match raw.ssh {
            None => defaults.ssh.clone(),
            Some(ssh) => {
                let keys = match ssh.keys {
                    Some(RawKeys::Word(word)) if word == "all" => KeySelection::All,
                    Some(RawKeys::Word(word)) => {
                        self.problem(
                            format!("{loc}.ssh.keys"),
                            format!("keys must be \"all\" or a list of upstream names, not {word:?}"),
                        );
                        KeySelection::Upstreams(Vec::new())
                    }
                    Some(RawKeys::List(names)) => KeySelection::Upstreams(names),
                    None => {
                        self.problem(
                            format!("{loc}.ssh.keys"),
                            "ssh needs keys: \"all\", a list of upstream names, or [] for none",
                        );
                        KeySelection::Upstreams(Vec::new())
                    }
                };
                let confirm = match ssh.confirm {
                    None => default_confirm,
                    Some(text) => self.confirm(&format!("{loc}.ssh.confirm"), &text, default_confirm),
                };
                Some(SshPolicy { keys, confirm })
            }
        };
        let mut gpg = GpgPolicy::default();
        for word in raw.gpg.unwrap_or_default() {
            match word.as_str() {
                "sign" => gpg.sign = true,
                "decrypt" => gpg.decrypt = true,
                other => self.problem(
                    format!("{loc}.gpg"),
                    format!("unknown gpg operation {other:?}: expected \"sign\" or \"decrypt\""),
                ),
            }
        }
        let defaults = defaults.hops;
        let hops = raw.hops.map_or(defaults, |h| Hops {
            ssh: h.ssh.unwrap_or(defaults.ssh),
            git: h.git.unwrap_or(defaults.git),
            gpg: h.gpg.unwrap_or(defaults.gpg),
        });
        let signing = raw.signing.and_then(|word| match word.as_str() {
            "ssh" => Some(Signing::Ssh),
            other => {
                self.problem(
                    format!("{loc}.signing"),
                    format!("unknown signing {other:?}: expected \"ssh\""),
                );
                None
            }
        });
        let git = raw
            .git
            .into_iter()
            .enumerate()
            .map(|(i, rule)| {
                let url = UrlPattern::parse(&rule.url).unwrap_or_else(|err| {
                    self.problem(format!("{loc}.git[{i}].url"), err.to_string());
                    UrlPattern::unparsed(&rule.url)
                });
                GitRule { url, source: rule.source, permissions: rule.permissions, per: rule.per }
            })
            .collect();
        Profile { name: name.to_owned(), ssh, gpg, hops, signing, git }
    }

    /// `confirm`: `"always"`, `"never"` or a duration; `fallback` after recording a
    /// problem.
    fn confirm(&mut self, location: &str, text: &str, fallback: Confirm) -> Confirm {
        match text {
            "always" => Confirm::Always,
            "never" => Confirm::Never,
            _ => match parse_duration(text) {
                Ok(duration) => Confirm::Remember(duration),
                Err(_) => {
                    self.problem(
                        location,
                        format!(
                            "invalid confirm {text:?}: expected \"always\", \"never\" or a duration \
                             such as \"8h\" or \"1h30m\" (at most 365d)"
                        ),
                    );
                    fallback
                }
            },
        }
    }

    fn server(&mut self, name: &str, raw: RawServer) -> Server {
        let loc = format!("server.{name}");
        let keys = match (raw.known_host, raw.host_keys) {
            (Some(_), Some(_)) => {
                self.problem(
                    &loc,
                    "known_host and host_keys exclude each other: follow known_hosts (known_host) or pin \
                     keys (host_keys), not both",
                );
                ServerKeys::Pinned(Vec::new())
            }
            (None, None) => {
                self.problem(
                    &loc,
                    "needs known_host (the server's name in known_hosts) or host_keys (pinned keys); \
                     run credential-bridge-ctl server add",
                );
                ServerKeys::Pinned(Vec::new())
            }
            (Some(known_host), None) => {
                let files = match raw.known_hosts_files {
                    Some(files) => files.iter().map(|file| self.path(file)).collect(),
                    None => known_hosts::default_files(&self.paths.home),
                };
                // ssh lowercases the name before it looks it up or hashes it.
                ServerKeys::KnownHost(KnownHost { name: known_host.to_ascii_lowercase(), files })
            }
            (None, Some(host_keys)) => {
                if raw.known_hosts_files.is_some() {
                    self.problem(
                        format!("{loc}.known_hosts_files"),
                        "known_hosts_files needs known_host; pinned host_keys read no known_hosts file",
                    );
                }
                let keys = host_keys
                    .iter()
                    .enumerate()
                    .filter_map(|(i, text)| match ssh_key::PublicKey::from_openssh(text) {
                        Ok(key) => Some(key),
                        Err(err) => {
                            self.problem(
                                format!("{loc}.host_keys[{i}]"),
                                format!("not a public key in OpenSSH format (\"ssh-ed25519 AAAA…\"): {err}"),
                            );
                            None
                        }
                    })
                    .collect();
                ServerKeys::Pinned(keys)
            }
        };
        Server { name: name.to_owned(), keys, profile: raw.profile, git_config: raw.git_config }
    }
}

fn github_host() -> String {
    GITHUB_HOST.to_owned()
}

/// `https://api.github.com` for github.com, else the GitHub Enterprise layout.
fn default_api_url(host: &str) -> String {
    if host == GITHUB_HOST { "https://api.github.com".to_owned() } else { format!("https://{host}/api/v3") }
}

#[cfg(test)]
mod tests;
