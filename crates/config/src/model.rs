//! The validated configuration model.
//!
//! These types are produced only by [`Config::load`]/[`Config::parse`] (or built in tests)
//! and are not deserialized directly; the TOML layout is described on each type.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use credential_bridge_proto::ipc::git::{Permissions, TokenScope};
use credential_bridge_proto::ipc::gpg::GpgPolicy;

use crate::pattern::{GitTarget, UrlPattern};
use crate::secret_ref::SecretRef;

/// The whole configuration (`version = 2`).
///
/// Invariants after loading: every `profile` named by a server exists in `profiles`;
/// every `source` named by a rule exists; `agent.add_to` and every name in `ssh.keys`
/// name an upstream; upstream, source, profile and server names are unique (map keys);
/// `unregistered` has no git rules, no gpg and no signing; see [`GitRule`] for rule
/// invariants.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// `[daemon]`.
    pub daemon: DaemonConfig,
    /// `[agent]`; `None` means token-only mode: the proxy answers an empty key list.
    pub agent: Option<AgentConfig>,
    /// `[gpg]`; required if any profile allows gpg.
    pub gpg: Option<GpgConfig>,
    /// `[vault]`: settings of single vaults.
    pub vault: VaultConfig,
    /// `[source.<name>]`, by name.
    pub sources: BTreeMap<String, Source>,
    /// `[profile.<name>]`, by name, for servers with a `[server.*]` entry. Never holds
    /// `unregistered`.
    pub profiles: BTreeMap<String, Profile>,
    /// `[profile.unregistered]`: the built-in profile for hosts that are recognised but
    /// have no `[server.*]` entry ([`Profile::unregistered`]), with the fields the
    /// configuration sets.
    pub unregistered: Profile,
    /// `[server.<name>]`, by name (written by ctl).
    pub servers: BTreeMap<String, Server>,
}

impl Config {
    /// Every known_hosts file a server that follows known_hosts reads, without
    /// duplicates, in configuration order.
    pub fn known_hosts_files(&self) -> Vec<&std::path::Path> {
        let mut files: Vec<&std::path::Path> = Vec::new();
        for server in self.servers.values() {
            if let ServerKeys::KnownHost(known) = &server.keys {
                for file in &known.files {
                    if !files.contains(&file.as_path()) {
                        files.push(file);
                    }
                }
            }
        }
        files
    }

    /// The profile for a recognised host: its server's `profile`, or with `None` (a host
    /// key without `[server.*]` entry) `profile.unregistered`. `None` if the server's
    /// profile does not exist (only in a configuration built by hand): it gets nothing.
    /// Connections that are not recognised (no server bind) get no profile at all; the
    /// caller decides that.
    pub fn profile_for(&self, server: Option<&Server>) -> Option<&Profile> {
        match server {
            Some(server) => self.profiles.get(&server.profile),
            None => Some(&self.unregistered),
        }
    }

    /// All git hosts (`host[:port]`) a server's profile has rules for, and whether any
    /// rule for that host needs `credential.useHttpPath` (GitHub App rules, rules with a
    /// path pattern). Used by ctl to write the server's git config.
    ///
    /// Hosts are listed in the order of their first rule. Empty if the profile does not
    /// exist.
    pub fn git_hosts_for(&self, server: &Server) -> Vec<(String, bool)> {
        let mut hosts: Vec<(String, bool)> = Vec::new();
        let Some(profile) = self.profiles.get(&server.profile) else { return hosts };
        for rule in &profile.git {
            let is_app = self
                .sources
                .get(&rule.source)
                .is_some_and(|source| matches!(source.kind, SourceKind::GithubApp { .. }));
            let needs_path = is_app || rule.url.has_path();
            match hosts.iter_mut().find(|(host, _)| host == rule.url.host()) {
                Some((_, path)) => *path |= needs_path,
                None => hosts.push((rule.url.host().to_owned(), needs_path)),
            }
        }
        hosts
    }

    /// An empty configuration: `[daemon]` defaults from `paths`, the built-in
    /// `profile.unregistered`, nothing else. This is what a missing configuration file
    /// means (token-only mode, every server gets nothing).
    pub fn empty(paths: &crate::paths::Paths) -> Config {
        Config { daemon: DaemonConfig::from_paths(paths), ..Config::default() }
    }
}

impl Default for Config {
    /// Nothing configured: empty `[daemon]` paths and the built-in `profile.unregistered`.
    fn default() -> Self {
        Config {
            daemon: DaemonConfig::default(),
            agent: None,
            gpg: None,
            vault: VaultConfig::default(),
            sources: BTreeMap::new(),
            profiles: BTreeMap::new(),
            unregistered: Profile::unregistered(),
            servers: BTreeMap::new(),
        }
    }
}

impl DaemonConfig {
    /// The defaults from [`crate::paths::Paths`].
    pub fn from_paths(paths: &crate::paths::Paths) -> DaemonConfig {
        DaemonConfig {
            socket: paths.agent_socket.clone(),
            forward_socket: paths.forward_socket.clone(),
            control_socket: paths.control_socket.clone(),
            audit_log: paths.audit_log.clone(),
        }
    }
}

/// `[daemon]`. All paths are absolute after loading (`~` expanded, defaults from
/// [`crate::paths::Paths`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DaemonConfig {
    /// `socket`: the local agent socket (`IdentityAgent`).
    pub socket: PathBuf,
    /// `forward_socket`: the socket for servers (`ForwardAgent`).
    pub forward_socket: PathBuf,
    /// `control_socket`: ctl's socket. Not in the configuration example; defaults next to the
    /// others.
    pub control_socket: PathBuf,
    /// `audit_log`: where the audit log is written.
    pub audit_log: PathBuf,
}

/// Where a socket is: a path, or a name for `gpgconf --list-dirs <name>`.
///
/// TOML: a string. `gpgconf:<dir>` (e.g. `gpgconf:agent-ssh-socket`,
/// `gpgconf:agent-extra-socket`) is resolved by the daemon at start; anything else is a
/// path with `~/` expanded, which must then be absolute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketSpec {
    /// An absolute path.
    Path(PathBuf),
    /// The `gpgconf --list-dirs` entry name.
    Gpgconf(String),
}

/// `[agent]`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AgentConfig {
    /// `add_to`: upstream that receives `ssh-add` write commands from `agent.sock`.
    /// `None`: write commands other than lock/unlock fail.
    pub add_to: Option<String>,
    /// `[[agent.upstream]]`, in file order (the key list keeps this order).
    pub upstreams: Vec<Upstream>,
}

/// `[[agent.upstream]]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    /// `name`: unique; referenced by `add_to` and `ssh.keys`.
    pub name: String,
    /// `socket`.
    pub socket: SocketSpec,
}

/// `[gpg]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpgConfig {
    /// `socket`: the local gpg-agent extra socket, default `gpgconf:agent-extra-socket`.
    pub socket: SocketSpec,
}

/// `[vault]`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VaultConfig {
    /// `[vault.keepassxc]`.
    pub keepassxc: KeepassxcConfig,
}

/// `[vault.keepassxc]`. Paths are absolute after loading (`~/` expanded).
///
/// With `database`, `keepassxc://` references are read and written with `keepassxc-cli`
/// on exactly that file, on Linux and macOS, after `ctl vault unlock keepassxc`. Without it,
/// Linux uses the Secret Service of the running KeePassXC app; on macOS `database` is
/// then required as soon as a `keepassxc://` reference is used.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeepassxcConfig {
    /// `database`: the `.kdbx` file.
    pub database: Option<PathBuf>,
    /// `key_file`: passed to `keepassxc-cli` as `--key-file`; needs `database`.
    pub key_file: Option<PathBuf>,
}

/// `[source.<name>]`.
#[derive(Debug, Clone, PartialEq)]
pub struct Source {
    /// The table name.
    pub name: String,
    /// How tokens are made.
    pub kind: SourceKind,
    /// `cache`; default `true`. `false`: the git worker keeps no token of this source
    /// and resolves the secret (or mints an App token) for every request. Only for kinds
    /// whose tokens the bridge caches ([`SourceKind::cached_by_bridge`]).
    pub cache: bool,
}

/// The kinds of source. TOML keys: `type` and `auth` select the variant.
///
/// | `type`    | `auth`  | Variant                    | Other keys                                        |
/// | --------- | ------- | -------------------------- | ------------------------------------------------- |
/// | `github`  | `gh`    | [`SourceKind::GithubGh`]   | `host`                                            |
/// | `github`  | `pat`   | [`SourceKind::GithubPat`]  | `host`, `token`, `cache`                          |
/// | `github`  | `app`   | [`SourceKind::GithubApp`]  | `host`, `api_url`, `app_id`, `private_key`, `max_permissions`, `cache` |
/// | `gitlab`  | `token` | [`SourceKind::GitlabToken`]  | `host`, `token`, `cache`                        |
/// | `forgejo` | `token` | [`SourceKind::ForgejoToken`] | `host`, `token`, `cache` (`type = "gitea"` is an alias) |
/// | `helper`  | –       | [`SourceKind::Helper`]     | `helper`                                          |
///
/// `host` defaults to `github.com` for GitHub and is required for GitLab and Forgejo.
#[derive(Debug, Clone, PartialEq)]
pub enum SourceKind {
    /// `gh auth git-credential`, run by the vault worker.
    GithubGh {
        /// GitHub host.
        host: String,
    },
    /// Fine-grained PAT from a vault.
    GithubPat {
        /// GitHub host.
        host: String,
        /// The token reference.
        token: SecretRef,
    },
    /// GitHub App; token minted per request.
    GithubApp {
        /// GitHub host.
        host: String,
        /// REST API base URL; default `https://api.github.com` for `github.com`, else
        /// `https://<host>/api/v3`.
        api_url: String,
        /// `app_id`.
        app_id: u64,
        /// `private_key`: PEM private key reference.
        private_key: SecretRef,
        /// `max_permissions`: upper bound for every rule using this source.
        max_permissions: Permissions,
    },
    /// GitLab token.
    GitlabToken {
        /// GitLab host.
        host: String,
        /// The token reference.
        token: SecretRef,
    },
    /// Forgejo / Gitea token.
    ForgejoToken {
        /// Forgejo host.
        host: String,
        /// The token reference.
        token: SecretRef,
    },
    /// An existing git credential helper, run by the vault worker.
    Helper {
        /// `helper`: as in `credential.helper` (`manager`, `/path/to/helper --arg`).
        helper: String,
    },
}

impl SourceKind {
    /// The host tokens of this source are for; `None` for helper sources, which serve
    /// any host.
    pub fn host(&self) -> Option<&str> {
        match self {
            SourceKind::GithubGh { host }
            | SourceKind::GithubPat { host, .. }
            | SourceKind::GithubApp { host, .. }
            | SourceKind::GitlabToken { host, .. }
            | SourceKind::ForgejoToken { host, .. } => Some(host),
            SourceKind::Helper { .. } => None,
        }
    }

    /// The secret references this source uses.
    pub fn secret_refs(&self) -> Vec<&SecretRef> {
        match self {
            SourceKind::GithubPat { token, .. }
            | SourceKind::GitlabToken { token, .. }
            | SourceKind::ForgejoToken { token, .. } => vec![token],
            SourceKind::GithubApp { private_key, .. } => vec![private_key],
            SourceKind::GithubGh { .. } | SourceKind::Helper { .. } => vec![],
        }
    }

    /// Whether the git worker serves and caches the tokens of this kind (PAT, App,
    /// GitLab, Forgejo), so `cache` applies. `gh` and `helper` sources keep no token in
    /// the bridge.
    pub fn cached_by_bridge(&self) -> bool {
        !matches!(self, SourceKind::GithubGh { .. } | SourceKind::Helper { .. })
    }

    /// A short description for messages, e.g. `github (app)`.
    pub fn describe(&self) -> &'static str {
        match self {
            SourceKind::GithubGh { .. } => "github (gh)",
            SourceKind::GithubPat { .. } => "github (pat)",
            SourceKind::GithubApp { .. } => "github (app)",
            SourceKind::GitlabToken { .. } => "gitlab (token)",
            SourceKind::ForgejoToken { .. } => "forgejo (token)",
            SourceKind::Helper { .. } => "helper",
        }
    }
}

/// `[profile.<name>]`: what a server may do.
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    /// The table name.
    pub name: String,
    /// `ssh`; `None`: no keys are visible.
    pub ssh: Option<SshPolicy>,
    /// `gpg = ["sign", "decrypt"]`; absent: neither. Requires `[gpg]` if not empty.
    pub gpg: GpgPolicy,
    /// `hops`; absent: [`Hops::default`].
    pub hops: Hops,
    /// `signing`; `Some(Signing::Ssh)` makes ctl set up ssh commit signing on servers.
    pub signing: Option<Signing>,
    /// `[[profile.<name>.git]]`, in file order; the first match wins.
    pub git: Vec<GitRule>,
}

impl Profile {
    /// The built-in `profile.unregistered`: an empty key list (not even public keys are
    /// shown), `confirm = "always"`, no hops, no git rules, no gpg, no signing.
    pub fn unregistered() -> Profile {
        Profile {
            name: crate::UNREGISTERED_PROFILE.to_owned(),
            ssh: Some(SshPolicy { keys: KeySelection::Upstreams(Vec::new()), confirm: Confirm::Always }),
            gpg: GpgPolicy::default(),
            hops: Hops::NONE,
            signing: None,
            git: Vec::new(),
        }
    }

    /// The first rule whose pattern matches `target`.
    pub fn git_rule_for(&self, target: &GitTarget) -> Option<&GitRule> {
        self.git.iter().find(|rule| rule.url.matches(target))
    }

    /// Whether this profile shows the keys of `upstream`.
    /// Without `ssh` no upstream is shown.
    pub fn shows_upstream(&self, upstream: &str) -> bool {
        match &self.ssh {
            None => false,
            Some(SshPolicy { keys: KeySelection::All, .. }) => true,
            Some(SshPolicy { keys: KeySelection::Upstreams(names), .. }) => {
                names.iter().any(|name| name == upstream)
            }
        }
    }
}

/// `ssh = { keys = …, confirm = … }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPolicy {
    /// `keys`: `"all"` or a list of upstream names.
    pub keys: KeySelection,
    /// `confirm`: whether signatures need the approval dialog. Absent: `"never"` in
    /// profiles of registered servers, `"always"` in `profile.unregistered`.
    pub confirm: Confirm,
}

/// `confirm = "always" | "never" | "<duration>"`: the approval dialog for signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirm {
    /// `"never"`: no dialog.
    Never,
    /// `"always"`: a dialog for every signature; no answer is remembered.
    Always,
    /// A duration such as `"8h"` (see [`crate::duration`]): a dialog, its answer
    /// remembered this long per server (host key for unregistered hosts), key, local
    /// process and hop.
    Remember(Duration),
}

impl Confirm {
    /// Whether a signature needs the dialog, and for how long its answer is remembered:
    /// `None` without dialog, `Some(None)` for a dialog every time.
    pub fn dialog(self) -> Option<Option<Duration>> {
        match self {
            Confirm::Never => None,
            Confirm::Always => Some(None),
            Confirm::Remember(duration) => Some(Some(duration)),
        }
    }

    /// The configuration text: `always`, `never` or the duration (`8h`).
    pub fn describe(self) -> String {
        match self {
            Confirm::Never => "never".to_owned(),
            Confirm::Always => "always".to_owned(),
            Confirm::Remember(duration) => crate::duration::format_duration(duration),
        }
    }
}

/// Which upstreams' keys a profile shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySelection {
    /// `"all"`.
    All,
    /// A list of upstream names (validated).
    Upstreams(Vec<String>),
}

/// `hops = { ssh, git, gpg }`: what hop requests may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hops {
    /// Keys visible and usable from hops.
    pub ssh: bool,
    /// git extension from hops.
    pub git: bool,
    /// gpg extension from hops.
    pub gpg: bool,
}

impl Hops {
    /// `{ ssh = false, git = false, gpg = false }`: the default of `profile.unregistered`.
    pub const NONE: Hops = Hops { ssh: false, git: false, gpg: false };
}

impl Default for Hops {
    /// `{ ssh = true, git = false, gpg = false }`, like plain ssh-agent forwarding.
    fn default() -> Self {
        Self { ssh: true, git: false, gpg: false }
    }
}

/// `signing`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signing {
    /// `"ssh"`: git commit signing via the agent channel (`gpg.format = ssh`).
    Ssh,
}

/// `[[profile.<name>.git]]`: one git rule.
///
/// Invariants after loading: `source` names an existing source; `per = Owner` only with
/// a pattern of the form `https://<host>/<owner>/*` ([`UrlPattern::owner_wildcard`]);
/// `permissions` is non-empty only for GitHub App sources and within their
/// `max_permissions`; the pattern's host equals the source's host (helper sources: any).
#[derive(Debug, Clone, PartialEq)]
pub struct GitRule {
    /// `url`.
    pub url: UrlPattern,
    /// `source`.
    pub source: String,
    /// `permissions`; empty if absent.
    pub permissions: Permissions,
    /// `per`; default `repo`.
    pub per: TokenScope,
}

/// `[server.<name>]` (written by ctl).
#[derive(Debug, Clone, PartialEq)]
pub struct Server {
    /// The table name; also the ssh host alias ctl uses.
    pub name: String,
    /// How the server's host keys are known: `known_host` (with `known_hosts_files`) or
    /// `host_keys`; exactly one of them.
    pub keys: ServerKeys,
    /// `profile`: an existing profile name.
    pub profile: String,
    /// `git_config`; default `true`. `false`: ctl prints git config lines instead of
    /// writing them.
    pub git_config: bool,
}

/// Where the host keys that identify a server come from.
#[derive(Debug, Clone, PartialEq)]
pub enum ServerKeys {
    /// `known_host = "<name>"`: the keys the known_hosts files list for this name, read
    /// again whenever they change (see [`crate::known_hosts`]).
    KnownHost(KnownHost),
    /// `host_keys = ["ssh-ed25519 AAAA…"]`: pinned keys in OpenSSH format, non-empty.
    Pinned(Vec<ssh_key::PublicKey>),
}

/// `known_host` and `known_hosts_files` of a server that follows known_hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHost {
    /// `known_host`: the name ssh stores the server under in known_hosts:
    /// `HostKeyAlias` if set, else the host name, as `[host]:port` for a port other
    /// than 22. Lowercase (lowercased on load), as ssh looks it up.
    pub name: String,
    /// `known_hosts_files`: the files to read, absolute after loading. Absent:
    /// OpenSSH's defaults ([`crate::known_hosts::DEFAULT_FILES`]).
    pub files: Vec<std::path::PathBuf>,
}
