//! Command line.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

/// Manage credential-bridge: configuration, agents, sources, profiles, servers, vaults,
/// gpg and the daemon.
#[derive(Debug, Parser)]
#[command(name = "credential-bridge-ctl", version)]
pub struct Cli {
    /// Configuration file (default: $XDG_CONFIG_HOME/credential-bridge/config.toml).
    #[arg(long, env = "CREDENTIAL_BRIDGE_CONFIG", global = true)]
    pub config: Option<PathBuf>,
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Write a first configuration from the agents and the gh login found on this machine.
    Init(InitArgs),
    /// Check what is configured on this machine; with server names or --all, also probe
    /// those servers.
    Check(CheckArgs),
    /// Show the audit log.
    Log(LogArgs),
    /// Show, check or edit the whole configuration file.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Print a shell completion script to stdout.
    Completions(CompletionsArgs),
    /// Manage the upstream agents (`[agent]`, `[[agent.upstream]]`).
    #[command(subcommand)]
    Agent(AgentCommand),
    /// Manage token sources (`[source.*]`).
    #[command(subcommand)]
    Source(SourceCommand),
    /// Manage profiles and their git rules (`[profile.*]`).
    #[command(subcommand)]
    Profile(ProfileCommand),
    /// Manage `[server.*]` entries, the remote side, the ssh config snippet, and test
    /// keys and tokens.
    #[command(subcommand)]
    Server(ServerCommand),
    /// See, set up, unlock and lock the vaults the sources take secrets from
    /// (`[vault.*]`).
    #[command(subcommand)]
    Vault(VaultCommand),
    /// Change `[gpg]` and print the gpg setup for a server.
    #[command(subcommand)]
    Gpg(GpgCommand),
    /// Change `[daemon]` paths, reload the configuration and manage the daemon service
    /// (systemd user unit or launchd agent).
    #[command(subcommand)]
    Daemon(DaemonCommand),
    /// Write man pages for credential-bridge-ctl and its subcommands into a directory.
    #[command(hide = true)]
    GenerateMan(GenerateManArgs),
}

/// Arguments of `completions`.
#[derive(Debug, Clone, Args)]
pub struct CompletionsArgs {
    /// The shell.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

/// Arguments of `generate-man`.
#[derive(Debug, Clone, Args)]
pub struct GenerateManArgs {
    /// Output directory (created if missing).
    pub dir: PathBuf,
}

/// `server …`.
#[derive(Debug, Subcommand)]
pub enum ServerCommand {
    /// Register a server by its known_hosts entry (or pinned keys), install
    /// credential-bridge-remote, set up git config and probe the result.
    Add(ServerAddArgs),
    /// List servers with profile and host keys.
    List,
    /// Show one server and what its profile allows.
    Show(ServerNameArg),
    /// Change the profile of a server.
    Set(ServerSetArgs),
    /// Remove the entry; with --remote also uninstall on the server first.
    Remove(ServerRemoveArgs),
    /// Uninstall credential-bridge-remote and its git config on a server over ssh;
    /// never touches the configuration file.
    Uninstall(ServerUninstallArgs),
    /// Print a suggested ~/.ssh/config snippet for servers (ctl never edits it).
    SshConfig(SshConfigArgs),
    /// List the keys a server would see (or the local socket without a server).
    Keys(KeysArgs),
    /// Resolve a token as if the server asked for the URL; prints the rule and source,
    /// never the token.
    Token(ServerTokenArgs),
}

/// Arguments of `server set`.
#[derive(Debug, Clone, Args)]
pub struct ServerSetArgs {
    /// The `[server.*]` name.
    pub name: String,
    /// The profile to assign.
    #[arg(long)]
    pub profile: String,
    #[command(flatten)]
    pub write: WriteArgs,
}

/// Arguments of `server add`.
#[derive(Debug, Clone, Args)]
pub struct ServerAddArgs {
    /// The ssh host alias (also the `[server.*]` name).
    pub name: String,
    /// The profile to assign.
    #[arg(long)]
    pub profile: String,
    /// Do not touch the git config on the server; print the lines instead.
    #[arg(long)]
    pub no_git_config: bool,
    /// Pin the host keys known_hosts lists now (host_keys) instead of following
    /// known_hosts (known_host); a rotated host key then needs server add --pin again.
    /// Without --pin or --follow a new server follows and an existing one keeps its
    /// mode: a pinned one keeps its pinned keys and is refused if ssh used another key.
    #[arg(long, conflicts_with = "follow")]
    pub pin: bool,
    /// Follow known_hosts (known_host), also for a server pinned before.
    #[arg(long)]
    pub follow: bool,
    /// The credential-bridge-remote binary to install (default: the bundled one for the
    /// server's architecture).
    #[arg(long, value_name = "PATH")]
    pub remote_binary: Option<PathBuf>,
    /// Read the host keys and show the change as a diff; install nothing, write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

/// A server name.
#[derive(Debug, Clone, Args)]
pub struct ServerNameArg {
    /// The `[server.*]` name.
    pub name: String,
}

/// Arguments of `server remove`.
#[derive(Debug, Clone, Args)]
pub struct ServerRemoveArgs {
    /// The `[server.*]` name.
    pub name: String,
    /// Also run `credential-bridge-remote uninstall --remove-binary` on the server.
    #[arg(long)]
    pub remote: bool,
    /// Show the change as a diff; touch neither the server nor the file.
    #[arg(long)]
    pub dry_run: bool,
}

/// Arguments of `server uninstall`.
#[derive(Debug, Clone, Args)]
pub struct ServerUninstallArgs {
    /// Any ssh destination: a host alias or `user@host`, with or without a
    /// `[server.*]` entry. Login goes through your ssh and the proxy as usual; a host
    /// without an entry gets no keys from the bridge.
    pub dest: String,
    /// Show what would run; run nothing.
    #[arg(long)]
    pub dry_run: bool,
}

/// Arguments of `server ssh-config`.
#[derive(Debug, Clone, Args)]
pub struct SshConfigArgs {
    /// Servers to include (default: all).
    pub servers: Vec<String>,
    /// Add a fallback agent used when the daemon is not running (`Match exec`).
    #[arg(long, value_name = "SOCKET")]
    pub fallback: Option<PathBuf>,
}

/// Arguments of `check`.
#[derive(Debug, Clone, Args)]
pub struct CheckArgs {
    /// Servers to check as well: a probe through the daemon, their remote binary, git
    /// config and gpg.conf.
    #[arg(value_name = "NAME", conflicts_with = "all")]
    pub servers: Vec<String>,
    /// Check every configured server as well.
    #[arg(long)]
    pub all: bool,
}

/// Arguments of `server keys`.
#[derive(Debug, Clone, Args)]
pub struct KeysArgs {
    /// The `[server.*]` name; without it, the keys of `agent.sock`.
    pub server: Option<String>,
}

/// Arguments of `vault unlock`.
#[derive(Debug, Clone, Args)]
pub struct UnlockArgs {
    /// The vault: `bitwarden`, `keepassxc`.
    pub vault: String,
    /// Session lifetime, e.g. `8h` (default: 8h).
    #[arg(long, value_name = "DURATION")]
    pub ttl: Option<String>,
    /// Read the password from stdin instead of the terminal.
    #[arg(long)]
    pub password_stdin: bool,
}

/// `gpg …`.
#[derive(Debug, Subcommand)]
pub enum GpgCommand {
    /// Print what to add on a server to use the gpg bridge (ctl never edits gpg files).
    Setup(GpgSetupArgs),
    /// Create `[gpg]` if missing (needed when a profile allows gpg); change its socket
    /// only with --socket or --unset-socket.
    Set(GpgSetArgs),
    /// Remove `[gpg]`; refused while a profile allows gpg.
    Remove(WriteArgs),
}

/// Arguments of `gpg setup`.
#[derive(Debug, Clone, Args)]
pub struct GpgSetupArgs {
    /// The `[server.*]` name.
    pub server: String,
}

/// Arguments of `gpg set`.
#[derive(Debug, Clone, Args)]
pub struct GpgSetArgs {
    /// The local gpg-agent extra socket: a path or `gpgconf:<name>` (default:
    /// `gpgconf:agent-extra-socket`). Without it an existing socket stays.
    #[arg(long, value_name = "SOCKET", conflicts_with = "unset_socket")]
    pub socket: Option<String>,
    /// Remove `socket`, so the default applies.
    #[arg(long)]
    pub unset_socket: bool,
    #[command(flatten)]
    pub write: WriteArgs,
}

/// `vault …`.
#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    /// List the vaults sources use or the configuration sets up: sources, settings,
    /// tool and unlock state, and what to do next.
    List,
    /// Show one vault: references per source, settings, access, state and hints.
    Show(VaultNameArg),
    /// Set up a vault: KeePassXC asks for its database file (and key file), the others
    /// need no setup and say why.
    #[command(after_help = VAULT_SETUP_HELP)]
    Setup(VaultSetupArgs),
    /// Forget the settings of a vault (`[vault.<vault>]`) and end its unlock session; the
    /// vault itself is untouched.
    Forget(VaultForgetArgs),
    /// Open an unlock session for a vault (prompts for the password).
    Unlock(UnlockArgs),
    /// End the unlock session of a vault, or of every vault with --all.
    Lock(VaultLockArgs),
}

/// The help after the options of `vault setup`.
const VAULT_SETUP_HELP: &str = "KeePassXC through keepassxc-cli opens one database file; the daemon reads
[vault.keepassxc] when it starts, so setup offers to restart it and to unlock.
Without a terminal (or with --yes) it asks nothing: give --database.

Examples:
  credential-bridge-ctl vault setup keepassxc
  credential-bridge-ctl vault setup keepassxc --database ~/db.kdbx --no-key-file --yes
  credential-bridge-ctl vault setup bitwarden";

/// A vault name.
#[derive(Debug, Clone, Args)]
pub struct VaultNameArg {
    /// The vault: `1password`, `bitwarden`, `keepassxc`, `keychain`, `secret-service`,
    /// `pass`, `cmd`.
    pub vault: String,
}

/// Arguments of `vault setup`.
#[derive(Debug, Clone, Args)]
pub struct VaultSetupArgs {
    /// The vault: `keepassxc` has settings; `1password`, `bitwarden`, `keychain`,
    /// `secret-service`, `pass` and `cmd` need none.
    pub vault: String,
    /// keepassxc: the `.kdbx` database file (asked for if missing).
    #[arg(long, value_name = "PATH")]
    pub database: Option<String>,
    /// keepassxc: a key file for the database, passed to keepassxc-cli as `--key-file`.
    #[arg(long, value_name = "PATH", conflicts_with = "no_key_file")]
    pub key_file: Option<String>,
    /// keepassxc: the database has no key file (removes `key_file`).
    #[arg(long)]
    pub no_key_file: bool,
    /// Ask nothing: write what the options say (also what happens without a terminal);
    /// restarting the daemon and unlocking are left to you.
    #[arg(long, short)]
    pub yes: bool,
    #[command(flatten)]
    pub write: WriteArgs,
}

/// Arguments of `vault lock`.
#[derive(Debug, Clone, Args)]
pub struct VaultLockArgs {
    /// The vault: `bitwarden`, `keepassxc`.
    #[arg(required_unless_present = "all", conflicts_with = "all")]
    pub vault: Option<String>,
    /// End the sessions of every vault.
    #[arg(long)]
    pub all: bool,
}

/// Arguments of `vault forget`.
#[derive(Debug, Clone, Args)]
pub struct VaultForgetArgs {
    /// The vault with settings: `keepassxc`.
    pub vault: String,
    #[command(flatten)]
    pub write: WriteArgs,
}

/// Options of every command that changes the configuration.
#[derive(Debug, Clone, Copy, Default, Args)]
pub struct WriteArgs {
    /// Show the change as a unified diff and write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

/// A name and the write options.
#[derive(Debug, Clone, Args)]
pub struct NameWriteArgs {
    /// The name.
    pub name: String,
    #[command(flatten)]
    pub write: WriteArgs,
}

/// A name.
#[derive(Debug, Clone, Args)]
pub struct NameArg {
    /// The name.
    pub name: String,
}

/// Arguments of `init`.
#[derive(Debug, Clone, Args)]
pub struct InitArgs {
    /// Write the proposal without asking (also what happens without a terminal).
    #[arg(long, short)]
    pub yes: bool,
    /// Replace an existing configuration; the old file is kept as a timestamped backup.
    #[arg(long)]
    pub force: bool,
    /// Show the file that would be written and write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

/// `config …`.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Print the effective configuration, including built-in values (marked).
    Show,
    /// Print the path of the configuration file.
    Path,
    /// Load and validate the configuration as the daemon does.
    Check,
    /// Edit the file in $VISUAL or $EDITOR; it is saved only if it validates.
    Edit,
}

/// `daemon …`.
#[derive(Debug, Subcommand)]
pub enum DaemonCommand {
    /// Set `[daemon]` paths; they take effect when the daemon restarts.
    Set(DaemonSetArgs),
    /// Make the running daemon re-read the configuration file (as `SIGHUP` does).
    ///
    /// Unlock sessions and approvals stay (approvals are forgotten if profiles or servers
    /// changed). `[daemon]` and `[vault]` settings take effect only when the daemon
    /// restarts. An invalid file is refused and the daemon keeps the configuration it had.
    Reload,
    #[command(flatten)]
    Service(ServiceCommand),
    /// Exit 0 within milliseconds if the daemon accepts connections (for `Match exec`).
    Alive,
}

/// A key of `[daemon]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum DaemonKeyArg {
    /// `socket`.
    Socket,
    /// `forward_socket`.
    #[value(name = "forward_socket", alias = "forward-socket")]
    ForwardSocket,
    /// `control_socket`.
    #[value(name = "control_socket", alias = "control-socket")]
    ControlSocket,
    /// `audit_log`.
    #[value(name = "audit_log", alias = "audit-log")]
    AuditLog,
}

/// Arguments of `daemon set`.
#[derive(Debug, Clone, Args)]
pub struct DaemonSetArgs {
    /// The local agent socket (`IdentityAgent`).
    #[arg(long, value_name = "PATH")]
    pub socket: Option<String>,
    /// The socket for servers (`ForwardAgent`).
    #[arg(long, value_name = "PATH")]
    pub forward_socket: Option<String>,
    /// ctl's socket.
    #[arg(long, value_name = "PATH")]
    pub control_socket: Option<String>,
    /// The audit log file.
    #[arg(long, value_name = "PATH")]
    pub audit_log: Option<String>,
    /// Remove a key, so its default applies; repeatable.
    #[arg(long, value_enum, value_name = "KEY")]
    pub unset: Vec<DaemonKeyArg>,
    #[command(flatten)]
    pub write: WriteArgs,
}

/// `agent …`.
#[derive(Debug, Subcommand)]
pub enum AgentCommand {
    /// Add an upstream agent (`[[agent.upstream]]`) behind the proxy.
    Add(AgentAddArgs),
    /// List the upstream agents with socket, key count and status.
    List,
    /// Change `agent.add_to` or the socket of an upstream.
    Set(AgentSetArgs),
    /// Remove an upstream agent; refused while add_to or a profile names it.
    Remove(NameWriteArgs),
}

/// Arguments of `agent add`.
#[derive(Debug, Clone, Args)]
pub struct AgentAddArgs {
    /// Name, used by `add_to` and a profile's `ssh.keys`.
    pub name: String,
    /// The agent's socket: a path (`~/` allowed) or `gpgconf:<name>`, e.g.
    /// `gpgconf:agent-ssh-socket`.
    pub socket: String,
    /// Also make it `agent.add_to`, where `ssh-add` through the proxy goes.
    #[arg(long)]
    pub add_to: bool,
    #[command(flatten)]
    pub write: WriteArgs,
}

/// Arguments of `agent set`.
#[derive(Debug, Clone, Args)]
pub struct AgentSetArgs {
    /// The upstream whose socket `--socket` changes.
    #[arg(requires = "socket")]
    pub name: Option<String>,
    /// The new socket of upstream NAME.
    #[arg(long, value_name = "SOCKET", requires = "name")]
    pub socket: Option<String>,
    /// The upstream that receives `ssh-add` through the proxy.
    #[arg(long, value_name = "NAME", conflicts_with = "no_add_to")]
    pub add_to: Option<String>,
    /// Remove `agent.add_to`; `ssh-add` through the proxy then fails.
    #[arg(long)]
    pub no_add_to: bool,
    #[command(flatten)]
    pub write: WriteArgs,
}

/// `source …`.
#[derive(Debug, Subcommand)]
pub enum SourceCommand {
    /// Add a token source (`[source.<name>]`); secrets are given as references, which are
    /// tested right after writing if the daemon runs.
    #[command(subcommand)]
    Add(SourceAddCommand),
    /// List the sources with kind, host and the rules using them.
    List,
    /// Show one source.
    Show(NameArg),
    /// Resolve a source's secret reference (or check its gh login) through the daemon;
    /// says whether it works, never shows the secret.
    Test(NameArg),
    /// Remove a source; refused while a git rule uses it.
    Remove(NameWriteArgs),
}

/// `source add …`.
#[derive(Debug, Subcommand)]
pub enum SourceAddCommand {
    /// GitHub: through a logged-in gh (default), a fine-grained PAT, or a GitHub App
    /// (`--auth app --create` makes a new App and adds its source).
    Github(GithubSourceArgs),
    /// GitLab with a token.
    Gitlab(TokenSourceArgs),
    /// Forgejo with a token.
    Forgejo(TokenSourceArgs),
    /// Gitea with a token (`type = "gitea"`, the same as forgejo).
    Gitea(TokenSourceArgs),
    /// An existing git credential helper, e.g. `manager` or `/path/to/helper --arg`.
    Helper(HelperSourceArgs),
}

/// How a GitHub source gets tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum GithubAuth {
    /// `gh auth git-credential`.
    Gh,
    /// A fine-grained personal access token from a vault.
    Pat,
    /// A GitHub App; tokens are minted per request.
    App,
}

/// Arguments of `source add github`.
#[derive(Debug, Clone, Args)]
#[command(after_help = GITHUB_SOURCE_HELP)]
pub struct GithubSourceArgs {
    /// The `[source.*]` name.
    pub name: String,
    /// How tokens are made.
    #[arg(long, value_enum, default_value = "gh")]
    pub auth: GithubAuth,
    /// GitHub host (default: github.com).
    #[arg(long)]
    pub host: Option<String>,
    /// With `--auth pat`: where the token is stored, e.g. `op://CI/github/credential`.
    #[arg(long, value_name = "REFERENCE", required_if_eq("auth", "pat"))]
    pub token: Option<String>,
    /// With `--auth app`: create a new GitHub App through the manifest flow in the
    /// browser and store its private key at `--private-key`.
    #[arg(long, conflicts_with_all = ["app_id", "api_url", "token", "dry_run"])]
    pub create: bool,
    /// With `--auth app`: the App ID (not with --create).
    #[arg(long)]
    pub app_id: Option<u64>,
    /// With `--auth app`: where the App's private key is stored; with --create, where it
    /// is written, e.g. `op://Dev/bridge-app/private-key`.
    #[arg(long, value_name = "REFERENCE", required_if_eq("auth", "app"))]
    pub private_key: Option<String>,
    /// With `--auth app`: the most a rule may ask for, as `name=access`; repeatable or
    /// separated by commas, e.g. `contents=write,pull_requests=read`. With --create, the
    /// permissions the new App requests (default: `contents=write,metadata=read`).
    #[arg(
        long = "max-permission",
        alias = "max-permissions",
        value_name = "NAME=ACCESS",
        value_delimiter = ','
    )]
    pub max_permissions: Vec<String>,
    /// With `--auth app`: the REST API URL (default: from the host; not with --create).
    #[arg(long, value_name = "URL")]
    pub api_url: Option<String>,
    /// With `--auth pat` or `app`: keep no token in the bridge (`cache = false`); every
    /// request reads the vault again (with 1Password: an approval each time) or mints a
    /// new App token.
    #[arg(long)]
    pub no_cache: bool,
    /// With --create: create the App in this organisation instead of the personal
    /// account.
    #[arg(long, requires = "create")]
    pub org: Option<String>,
    /// With --create: the App name on GitHub (default: `credential-bridge-<user>`).
    #[arg(long, value_name = "NAME", requires = "create")]
    pub app_name: Option<String>,
    /// With --create: let other accounts and organisations install the App (default:
    /// only the owner).
    #[arg(long, requires = "create")]
    pub public: bool,
    #[command(flatten)]
    pub write: WriteArgs,
}

/// The help after the options of `source add github`.
const GITHUB_SOURCE_HELP: &str = "Examples:
  credential-bridge-ctl source add github github
  credential-bridge-ctl source add github ci --auth pat --token op://CI/github/credential
  credential-bridge-ctl source add github my-org --auth app --app-id 123456 \\
      --private-key op://Dev/bridge-app/private-key --max-permission contents=write
  credential-bridge-ctl source add github my-org --auth app --create --org my-org \\
      --private-key op://Dev/bridge-app/private-key";

/// Arguments of `source add gitlab|forgejo|gitea`.
#[derive(Debug, Clone, Args)]
pub struct TokenSourceArgs {
    /// The `[source.*]` name.
    pub name: String,
    /// The host, e.g. `gitlab.example.com`.
    #[arg(long)]
    pub host: String,
    /// Where the token is stored, e.g. `bw://gitlab-team/token`.
    #[arg(long, value_name = "REFERENCE")]
    pub token: String,
    /// Keep no token in the bridge (`cache = false`); every request reads the vault
    /// again (with 1Password: an approval each time).
    #[arg(long)]
    pub no_cache: bool,
    #[command(flatten)]
    pub write: WriteArgs,
}

/// Arguments of `source add helper`.
#[derive(Debug, Clone, Args)]
pub struct HelperSourceArgs {
    /// The `[source.*]` name.
    pub name: String,
    /// The helper as in `credential.helper`.
    #[arg(long)]
    pub helper: String,
    #[command(flatten)]
    pub write: WriteArgs,
}

/// `profile …`.
#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// Add a profile, optionally with settings (see `profile set`).
    Add(ProfileAddArgs),
    /// List the profiles with their keys, rules and servers.
    List,
    /// Show what a profile allows (`unregistered`: the effective built-in profile).
    Show(NameArg),
    /// Change profile settings.
    #[command(long_about = PROFILE_SET_HELP)]
    Set(ProfileSetArgs),
    /// Remove a profile with its rules; refused while a server uses it.
    Remove(NameWriteArgs),
    /// Manage the git rules of a profile.
    #[command(subcommand)]
    Rule(RuleCommand),
}

/// The long help of `profile set`.
const PROFILE_SET_HELP: &str = "Change profile settings, given as KEY=VALUE:

  ssh.keys=all|none|NAME[,NAME...]   upstreams whose keys the server sees
  ssh.confirm=always|never|DURATION  approval dialog for signatures, e.g. 8h
  hops.ssh=true|false                keys for hosts behind the server
  hops.git=true|false                git tokens for hosts behind the server
  hops.gpg=true|false                gpg for hosts behind the server
  signing=ssh                        ctl sets up ssh signing of git commits
  gpg=sign|decrypt|sign,decrypt|none what gpg may do (needs [gpg])

The profile `unregistered` (hosts without a [server.*] entry) is built in; only
ssh.keys, ssh.confirm and hops.ssh can be loosened there, with the warnings of
`credential-bridge-ctl check`.";

/// Arguments of `profile add`.
#[derive(Debug, Clone, Args)]
pub struct ProfileAddArgs {
    /// The `[profile.*]` name.
    pub name: String,
    /// Settings as KEY=VALUE, e.g. `ssh.keys=all signing=ssh` (see `profile set`).
    #[arg(value_name = "KEY=VALUE")]
    pub settings: Vec<String>,
    #[command(flatten)]
    pub write: WriteArgs,
}

/// Arguments of `profile set`.
#[derive(Debug, Clone, Args)]
pub struct ProfileSetArgs {
    /// The `[profile.*]` name, or `unregistered`.
    pub name: String,
    /// Settings as KEY=VALUE, e.g. `ssh.keys=fido,yubikey ssh.confirm=8h`.
    #[arg(value_name = "KEY=VALUE")]
    pub settings: Vec<String>,
    /// Remove a setting, so its default applies; repeatable.
    #[arg(long, value_name = "KEY")]
    pub unset: Vec<String>,
    #[command(flatten)]
    pub write: WriteArgs,
}

/// `profile rule …`.
#[derive(Debug, Subcommand)]
pub enum RuleCommand {
    /// Add a git rule (`[[profile.<name>.git]]`); rules are tried in order, the first
    /// match wins.
    Add(RuleAddArgs),
    /// List the rules of a profile in order.
    List(NameArg),
    /// Remove the rule with this URL pattern.
    Remove(RuleRemoveArgs),
}

/// How many repositories one GitHub App token covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum PerArg {
    /// One token per repository (default).
    Repo,
    /// One token for all repositories of the owner (needs an `https://<host>/<owner>/*`
    /// pattern).
    Owner,
}

/// Arguments of `profile rule add`.
#[derive(Debug, Clone, Args)]
pub struct RuleAddArgs {
    /// The `[profile.*]` name.
    pub profile: String,
    /// The URL pattern, e.g. `https://github.com/my-org/*`.
    pub url: String,
    /// The `[source.*]` that makes the tokens.
    #[arg(long)]
    pub source: String,
    /// For GitHub App sources: the rights of the token as `name=access`; repeatable or
    /// separated by commas, e.g. `contents=write`.
    #[arg(long = "permission", alias = "permissions", value_name = "NAME=ACCESS", value_delimiter = ',')]
    pub permissions: Vec<String>,
    /// For GitHub App sources: one token per repository or per owner.
    #[arg(long, value_enum)]
    pub per: Option<PerArg>,
    /// Insert before the rule with this URL pattern instead of appending.
    #[arg(long, value_name = "URL")]
    pub before: Option<String>,
    #[command(flatten)]
    pub write: WriteArgs,
}

/// Arguments of `profile rule remove`.
#[derive(Debug, Clone, Args)]
pub struct RuleRemoveArgs {
    /// The `[profile.*]` name.
    pub profile: String,
    /// The URL pattern of the rule, as written.
    pub url: String,
    #[command(flatten)]
    pub write: WriteArgs,
}

/// Arguments of `server token`.
#[derive(Debug, Clone, Args)]
pub struct ServerTokenArgs {
    /// The `[server.*]` name.
    pub server: String,
    /// e.g. `https://github.com/my-org/app`.
    pub url: String,
}

/// Arguments of `log`.
#[derive(Debug, Clone, Args)]
pub struct LogArgs {
    /// Keep printing new events.
    #[arg(short, long)]
    pub follow: bool,
    /// Show the last N events.
    #[arg(short = 'n', long, default_value_t = 50)]
    pub lines: usize,
    /// Print the raw JSON lines.
    #[arg(long)]
    pub json: bool,
}

/// `daemon install|uninstall|start|stop|status`.
#[derive(Debug, Subcommand)]
pub enum ServiceCommand {
    /// Install and start the service.
    Install,
    /// Stop and remove the service.
    Uninstall,
    /// Start the service.
    Start,
    /// Stop the service.
    Stop,
    /// Show the service state.
    Status,
}

/// Entry point: dispatches to [`crate::commands`]. Errors are printed to stderr with
/// exit code 1; `daemon alive` and `check` choose their own exit codes.
pub fn main() -> ExitCode {
    // ctl handles vault passwords (`vault unlock`) and GitHub App keys (`source add
    // github --auth app --create`).
    let hardening = credential_bridge_platform::harden::harden_process();
    for failure in &hardening.failures {
        eprintln!("warning: {failure}");
    }
    let cli = Cli::parse();
    crate::commands::run(cli)
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }

    /// `check` is local unless servers are named or `--all` is given; there is no `--local`.
    #[test]
    fn check_scope_arguments() {
        let parse = |args: &[&str]| Cli::try_parse_from([&["credential-bridge-ctl"], args].concat());
        let Command::Check(args) = parse(&["check"]).unwrap().command else { panic!() };
        assert!(args.servers.is_empty() && !args.all);
        let Command::Check(args) = parse(&["check", "a", "b"]).unwrap().command else { panic!() };
        assert_eq!(args.servers, ["a", "b"]);
        let Command::Check(args) = parse(&["check", "--all"]).unwrap().command else { panic!() };
        assert!(args.all);
        assert!(parse(&["check", "--local"]).is_err());
        assert!(parse(&["check", "a", "--all"]).is_err());
    }

    #[test]
    fn parses_examples_from_the_design() {
        let examples: &[&[&str]] = &[
            &["server", "add", "buildserver", "--profile", "build"],
            &[
                "source",
                "add",
                "github",
                "my-org",
                "--auth",
                "app",
                "--create",
                "--private-key",
                "op://Dev/bridge-app/private-key",
            ],
            &["vault", "unlock", "bitwarden"],
            &["vault", "lock", "bitwarden"],
            &["vault", "lock", "--all"],
            &["gpg", "setup", "buildserver"],
            &["check"],
            &["server", "keys", "buildserver"],
            &["server", "token", "buildserver", "https://github.com/my-org/app"],
            &["log", "-f"],
            &["daemon", "install"],
            &["daemon", "alive"],
            &["daemon", "reload"],
            &["server", "ssh-config", "buildserver"],
            &["server", "ssh-config", "--fallback", "/home/me/.1password/agent.sock"],
            &["server", "add", "devbox", "--profile", "dev", "--no-git-config"],
            &["server", "remove", "devbox", "--remote"],
            &["server", "uninstall", "me@oldbox", "--dry-run"],
            &["server", "list"],
            &["server", "show", "devbox"],
            &["check", "--all"],
            &["check", "buildserver", "devbox"],
            &["server", "add", "devbox", "--profile", "dev", "--pin"],
            &["server", "keys"],
            &["vault", "unlock", "keepassxc", "--ttl", "1h30m", "--password-stdin"],
            &["log", "-n", "10", "--json"],
            &["daemon", "uninstall"],
            &["daemon", "start"],
            &["daemon", "stop"],
            &["daemon", "status"],
            &["completions", "zsh"],
            &["generate-man", "/tmp/man"],
            &["init"],
            &["init", "--yes", "--force", "--dry-run"],
            &["config", "show"],
            &["config", "path"],
            &["config", "check"],
            &["config", "edit"],
            &["daemon", "set", "--audit-log", "~/audit.log", "--unset", "forward_socket"],
            &["agent", "add", "fido", "~/.ssh/agent.sock", "--add-to"],
            &["agent", "add", "yubikey", "gpgconf:agent-ssh-socket", "--dry-run"],
            &["agent", "list"],
            &["agent", "set", "--add-to", "fido"],
            &["agent", "set", "fido", "--socket", "/run/fido.sock", "--no-add-to"],
            &["agent", "remove", "fido"],
            &["source", "add", "github", "github"],
            &["source", "add", "github", "ci", "--auth", "pat", "--token", "op://CI/gh/token"],
            &[
                "source",
                "add",
                "github",
                "app",
                "--auth",
                "app",
                "--app-id",
                "1",
                "--private-key",
                "op://a/b/c",
                "--max-permission",
                "contents=write,pull_requests=read",
            ],
            &["source", "add", "gitlab", "gl", "--host", "gitlab.example.com", "--token", "bw://gl/token"],
            &["source", "add", "forgejo", "fj", "--host", "codeberg.org", "--token", "pass://fj"],
            &["source", "add", "gitea", "gt", "--host", "gitea.example.com", "--token", "cmd:t"],
            &["source", "add", "helper", "mgr", "--helper", "manager"],
            &["source", "list"],
            &["source", "show", "github"],
            &["source", "remove", "github", "--dry-run"],
            &["profile", "add", "dev", "ssh.keys=all", "signing=ssh"],
            &["profile", "list"],
            &["profile", "show", "unregistered"],
            &["profile", "set", "dev", "ssh.confirm=8h", "--unset", "signing"],
            &["profile", "set", "unregistered", "ssh.keys=fido"],
            &["profile", "remove", "dev"],
            &["profile", "rule", "add", "dev", "https://github.com/my-org/*", "--source", "github"],
            &[
                "profile",
                "rule",
                "add",
                "build",
                "https://github.com/acme/*",
                "--source",
                "app",
                "--permission",
                "contents=write",
                "--per",
                "owner",
                "--before",
                "https://github.com/*",
            ],
            &["profile", "rule", "list", "dev"],
            &["profile", "rule", "remove", "dev", "https://github.com/my-org/*"],
            &["server", "set", "devbox", "--profile", "build"],
            &["server", "add", "devbox", "--profile", "dev", "--dry-run"],
            &["vault", "list"],
            &["vault", "show", "keepassxc"],
            &["vault", "setup", "keepassxc"],
            &["vault", "setup", "keepassxc", "--database", "~/db.kdbx", "--key-file", "~/db.keyx", "--yes"],
            &["vault", "setup", "keepassxc", "--database", "~/db.kdbx", "--no-key-file", "-y", "--dry-run"],
            &["vault", "setup", "bitwarden"],
            &["vault", "forget", "keepassxc"],
            &["vault", "forget", "keepassxc", "--dry-run"],
            &["source", "test", "work"],
            &["gpg", "set", "--socket", "gpgconf:agent-extra-socket"],
            &["gpg", "set", "--unset-socket"],
            &["gpg", "remove"],
            &[
                "source",
                "add",
                "github",
                "my-org",
                "--auth",
                "app",
                "--create",
                "--private-key",
                "bw://app/key",
                "--org",
                "my-org",
                "--app-name",
                "bridge",
                "--max-permission",
                "contents=write",
                "--max-permission",
                "pull_requests=read",
                "--host",
                "github.example.com",
                "--public",
            ],
        ];
        for args in examples {
            let argv = std::iter::once("credential-bridge-ctl").chain(args.iter().copied());
            Cli::try_parse_from(argv).unwrap_or_else(|error| panic!("{args:?}: {error}"));
        }
    }

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("credential-bridge-ctl").chain(args.iter().copied()))
    }

    #[test]
    fn rejects_incomplete_commands() {
        for args in [
            &["server", "add", "buildserver"][..],
            &["server", "add"],
            &["source", "add", "github", "app", "--auth", "app", "--create"],
            &["server", "token", "buildserver"],
            &["vault", "unlock"],
            &["vault", "lock"],
            &["vault", "lock", "bitwarden", "--all"],
            &["gpg-setup", "buildserver"],
            &["gpg", "setup"],
            &["completions", "tcsh"],
            &["source", "add", "github", "ci", "--auth", "pat"],
            &["source", "add", "github", "app", "--auth", "app", "--app-id", "1"],
            &["source", "add", "gitlab", "gl", "--token", "bw://a/b"],
            &["agent", "set", "fido"],
            &["agent", "set", "--add-to", "a", "--no-add-to"],
            &["gpg", "set", "--socket", "x", "--unset-socket"],
            &["vault", "setup"],
            &["vault", "forget"],
            &["vault", "show"],
            &["vault", "setup", "keepassxc", "--key-file", "k", "--no-key-file"],
            &["source", "test"],
            &["server", "set", "devbox"],
            &["profile", "rule", "add", "dev", "https://github.com/*"],
            &["log", "-n", "many"],
            &["frobnicate"],
        ] {
            assert!(parse(args).is_err(), "{args:?} should fail");
        }
    }

    /// The commands that moved below an area are gone from the root.
    #[test]
    fn rejects_old_root_commands() {
        for args in [
            &["ssh-config"][..],
            &["ssh-config", "--fallback", "/run/agent.sock"],
            &["keys", "buildserver"],
            &["token", "test", "buildserver", "https://github.com/my-org/app"],
            &["unlock", "bitwarden"],
            &["lock", "bitwarden"],
            &["github-app", "create", "--key", "op://Dev/bridge-app/private-key"],
            &["service", "install"],
            &["service", "status"],
            &["alive"],
        ] {
            let error = parse(args).expect_err(&format!("{args:?} should fail"));
            assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand, "{args:?}");
        }
    }

    /// `--create` makes a new App; the options of an existing App, `--token` and
    /// `--dry-run` do not go with it, and the options of the new App need it.
    #[test]
    fn github_app_create_constraints() {
        let base = ["source", "add", "github", "my-org", "--auth", "app", "--private-key", "op://a/b/c"];
        let with = |extra: &[&'static str]| parse(&[&base[..], extra].concat());
        let cli = with(&["--create"]).unwrap();
        let Command::Source(SourceCommand::Add(SourceAddCommand::Github(args))) = cli.command else {
            panic!("not source add github")
        };
        assert!(args.create && args.auth == GithubAuth::App && args.app_id.is_none());
        assert!(args.max_permissions.is_empty() && args.app_name.is_none() && !args.public);
        for extra in [
            &["--create", "--app-id", "1"][..],
            &["--create", "--api-url", "https://api.example.com"],
            &["--create", "--dry-run"],
            &["--create", "--token", "op://a/b/token"],
            &["--org", "my-org"],
            &["--app-name", "bridge"],
            &["--public"],
        ] {
            assert!(with(extra).is_err(), "{extra:?} should fail");
        }
        // Without --create, an existing App needs its ID and permissions (checked when
        // the source is built, with a message naming --create).
        assert!(with(&["--app-id", "1", "--max-permission", "contents=write"]).is_ok());
    }

    /// `--no-cache` exists for the sources whose tokens the bridge caches, not for helpers.
    #[test]
    fn no_cache_only_where_the_bridge_caches() {
        let cli =
            parse(&["source", "add", "gitlab", "gl", "--host", "x", "--token", "bw://a/b", "--no-cache"])
                .unwrap();
        let Command::Source(SourceCommand::Add(SourceAddCommand::Gitlab(args))) = cli.command else {
            panic!("not source add gitlab")
        };
        assert!(args.no_cache);
        let cli =
            parse(&["source", "add", "github", "ci", "--auth", "pat", "--token", "op://a/b/c", "--no-cache"])
                .unwrap();
        let Command::Source(SourceCommand::Add(SourceAddCommand::Github(args))) = cli.command else {
            panic!("not source add github")
        };
        assert!(args.no_cache);
        let error =
            parse(&["source", "add", "helper", "h", "--helper", "manager", "--no-cache"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    /// `vault set` and `vault remove` were replaced by `vault setup` and `vault forget`.
    #[test]
    fn rejects_old_vault_commands() {
        for args in [
            &["vault", "set", "keepassxc", "--database", "~/db.kdbx"][..],
            &["vault", "set", "keepassxc", "--unset", "key_file"],
            &["vault", "remove", "keepassxc"],
        ] {
            let error = parse(args).expect_err(&format!("{args:?} should fail"));
            assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand, "{args:?}");
        }
    }

    #[test]
    fn parses_vault_and_source_test() {
        let Command::Vault(VaultCommand::Setup(setup)) =
            parse(&["vault", "setup", "keepassxc", "--database", "~/db.kdbx", "--no-key-file", "--yes"])
                .unwrap()
                .command
        else {
            panic!("not vault setup")
        };
        assert_eq!(setup.vault, "keepassxc");
        assert_eq!(setup.database.as_deref(), Some("~/db.kdbx"));
        assert!(setup.no_key_file && setup.yes && !setup.write.dry_run && setup.key_file.is_none());
        let Command::Vault(VaultCommand::Forget(forget)) =
            parse(&["vault", "forget", "keepassxc", "--dry-run"]).unwrap().command
        else {
            panic!("not vault forget")
        };
        assert_eq!((forget.vault.as_str(), forget.write.dry_run), ("keepassxc", true));
        let Command::Vault(VaultCommand::Show(show)) = parse(&["vault", "show", "bw"]).unwrap().command
        else {
            panic!("not vault show")
        };
        assert_eq!(show.vault, "bw");
        assert!(matches!(parse(&["vault", "list"]).unwrap().command, Command::Vault(VaultCommand::List)));
        let Command::Source(SourceCommand::Test(test)) = parse(&["source", "test", "work"]).unwrap().command
        else {
            panic!("not source test")
        };
        assert_eq!(test.name, "work");
    }

    #[test]
    fn parses_new_paths() {
        let Command::Server(ServerCommand::SshConfig(ssh)) =
            parse(&["server", "ssh-config", "a", "b", "--fallback", "/run/f.sock"]).unwrap().command
        else {
            panic!("not server ssh-config")
        };
        assert_eq!(ssh.servers, ["a", "b"]);
        assert_eq!(ssh.fallback.as_deref(), Some(std::path::Path::new("/run/f.sock")));
        let Command::Server(ServerCommand::Keys(keys)) = parse(&["server", "keys", "a"]).unwrap().command
        else {
            panic!("not server keys")
        };
        assert_eq!(keys.server.as_deref(), Some("a"));
        let Command::Server(ServerCommand::Token(token)) =
            parse(&["server", "token", "a", "https://github.com/o/r"]).unwrap().command
        else {
            panic!("not server token")
        };
        assert_eq!((token.server.as_str(), token.url.as_str()), ("a", "https://github.com/o/r"));
        let Command::Vault(VaultCommand::Unlock(unlock)) =
            parse(&["vault", "unlock", "bw", "--ttl", "1h"]).unwrap().command
        else {
            panic!("not vault unlock")
        };
        assert_eq!((unlock.vault.as_str(), unlock.ttl.as_deref()), ("bw", Some("1h")));
        let Command::Vault(VaultCommand::Lock(lock)) = parse(&["vault", "lock", "bw"]).unwrap().command
        else {
            panic!("not vault lock")
        };
        assert_eq!((lock.vault.as_deref(), lock.all), (Some("bw"), false));
        let Command::Vault(VaultCommand::Lock(lock)) = parse(&["vault", "lock", "--all"]).unwrap().command
        else {
            panic!("not vault lock --all")
        };
        assert_eq!((lock.vault, lock.all), (None, true));
        assert!(matches!(
            parse(&["daemon", "install"]).unwrap().command,
            Command::Daemon(DaemonCommand::Service(ServiceCommand::Install))
        ));
        assert!(matches!(
            parse(&["daemon", "alive"]).unwrap().command,
            Command::Daemon(DaemonCommand::Alive)
        ));
        assert!(matches!(
            parse(&["daemon", "reload"]).unwrap().command,
            Command::Daemon(DaemonCommand::Reload)
        ));
        assert!(parse(&["daemon", "reload", "now"]).is_err());
        assert!(matches!(
            parse(&["daemon", "set", "--socket", "/run/a.sock"]).unwrap().command,
            Command::Daemon(DaemonCommand::Set(_))
        ));
    }

    #[test]
    fn parses_values() {
        let cli = parse(&[
            "--config",
            "/etc/cb.toml",
            "server",
            "add",
            "b",
            "--profile",
            "build",
            "--no-git-config",
        ])
        .unwrap();
        assert_eq!(cli.config.as_deref(), Some(std::path::Path::new("/etc/cb.toml")));
        let Command::Server(ServerCommand::Add(add)) = cli.command else { panic!("not server add") };
        assert_eq!((add.name.as_str(), add.profile.as_str(), add.no_git_config), ("b", "build", true));
        assert_eq!(add.remote_binary, None);

        let cli = parse(&["log", "-f", "-n", "5"]).unwrap();
        let Command::Log(log) = cli.command else { panic!("not log") };
        assert!(log.follow && !log.json);
        assert_eq!(log.lines, 5);

        let cli = parse(&[
            "source",
            "add",
            "github",
            "app",
            "--auth",
            "app",
            "--create",
            "--private-key",
            "op://a/b/c",
            "--max-permission",
            "issues=read",
        ])
        .unwrap();
        let Command::Source(SourceCommand::Add(SourceAddCommand::Github(create))) = cli.command else {
            panic!("not source add github")
        };
        assert_eq!(create.host, None);
        assert_eq!(create.max_permissions, vec!["issues=read".to_owned()]);
        assert!(create.create && !create.public);

        let cli = parse(&["server", "ssh-config"]).unwrap();
        let Command::Server(ServerCommand::SshConfig(ssh)) = cli.command else {
            panic!("not server ssh-config")
        };
        assert!(ssh.servers.is_empty() && ssh.fallback.is_none());
    }
}
