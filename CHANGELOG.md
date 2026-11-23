# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). While the version is 0.x, configuration and
the protocol between the remote binary and the daemon may still change between minor
versions.

The release workflow publishes the section of the tagged version as the release notes.

## [Unreleased]

## [0.2.0] - 2026-11-23

A rewrite: credential-bridge is a local ssh-agent proxy, and everything reaches the
server through the agent channel sshd creates for each session. Configuration, programs
and service are new; nothing of 0.1 is migrated. The design is described in
[docs/architecture.md](https://github.com/XeS0r/ssh-credential-bridge/blob/main/docs/architecture.md).

To remove 0.1 first, with its programs still installed, run
`credential-bridge-ctl remote uninstall NAME` for every remote (or, on the server
itself, `git-credential-bridge uninstall --remove-binary`; both restore the git helpers
0.1 saved) and `credential-bridge-ctl service uninstall`, then remove the
`RemoteForward` lines from `~/.ssh/config` and `~/.local/state/credential-bridge` on the
servers. If 0.2 is already installed, stop the 0.1 service by hand:
`systemctl --user disable --now credential-bridged.service` (Linux) or
`launchctl bootout gui/$(id -u)/local.credential-bridge.daemon` (macOS), and delete its
unit file or plist. The installers (`install.sh`, `nix run .#install`) refuse to install
over 0.1 and name these steps; `ctl check` and `ctl daemon install` warn about a 0.1
unit or plist left behind.

### Added

- `credential-bridged` as an ssh-agent proxy with two sockets: `agent.sock` for your own
  logins and `ssh-add`, `agent-forward.sock` for `ForwardAgent`. It merges the keys of
  several upstream agents (1Password, Bitwarden, OpenSSH's ssh-agent with FIDO2 keys,
  gpg-agent, Secretive), filters them per profile and passes signatures unchanged.
- Servers are recognised by their host key from `session-bind@openssh.com`, which needs
  OpenSSH 8.9 or later on your machine; host certificates by their embedded key (a
  server ssh trusts only through `@cert-authority` is added with `server add --pin`).
  Profiles decide keys, approvals (`confirm`), git rules, gpg and what hosts behind a
  server may use (`hops`).
- `[server.*]` follows the server's known_hosts entry by default (`known_host`, plus
  `known_hosts_files` when ssh reads other files than OpenSSH's defaults): exact plain,
  listed, `[host]:port` and hashed entries count, `@revoked` keys never, wildcard and
  negated patterns and `@cert-authority` lines are not followed; `known_host` is
  compared lowercase, as ssh looks it up. The daemon reads the files on load and reload,
  and again before a lookup when a file changed, so a host key rotation through
  `UpdateHostKeys` needs no `server add` and a removed or `@revoked` key stops counting
  at once, for open connections too (their next request is refused and they end). Files
  that are not regular or larger than 16 MiB are skipped with a warning.
  `server add --pin` pins the keys known_hosts lists instead (`host_keys`); running
  `server add` again keeps the mode and is safe for a pinned server (it keeps the pinned
  keys and refuses a host key ssh used that is not among them; `--pin` pins again), and
  `--follow` makes a pinned server follow. A host key of more than one server selects
  none of them (treated as unregistered, logged once, and reported by `ctl check`); two
  servers following the same name in the same files are a configuration warning. The
  audit log's `server` event names the source of the matching key (`known_hosts` or
  `pinned`); `connect`, `client` and `server` events carry the connection's number.
- git tokens as an agent extension, from `gh`, any git credential helper, GitHub PATs,
  GitHub App tokens minted per request with the rule's rights, GitLab and Forgejo/Gitea
  tokens. Secrets come from 1Password, Bitwarden, KeePassXC, macOS Keychain, Secret
  Service, pass/gopass or a command. With `[vault.keepassxc]` (`database`, optional
  `key_file`, written by `ctl vault setup keepassxc`) KeePassXC is used through
  `keepassxc-cli` after `ctl vault unlock keepassxc`; without it Linux uses the running
  app's Secret Service, and on macOS it is required for `keepassxc://` references. The
  bridge caches PAT, GitLab and Forgejo tokens and minted App tokens; a source with
  `cache = false` (`source add … --no-cache`; not for `gh` and `helper`, which keep no
  token in the bridge) keeps none, so every git request reads the vault again or mints a
  new App token (with 1Password an approval each time, which `vault list` and
  `vault show` point out).
- gpg bridge: a shim on the server (`agent-program`) tunnels Assuan to the local
  gpg-agent's extra socket, filtered to signing and, if allowed, decrypting.
- Approval dialogs per server, key and local process (`confirm = "always"`, `"never"` or
  a duration such as `"8h"` that remembers the answer; a reload forgets it only when a
  profile or a server changed), and `ssh-add -x`/`-X` to lock and unlock the proxy (the
  lock also drops every git token the daemon has cached; a token being made meanwhile is
  neither handed out nor cached).
- An audit log in JSON lines of every signature, token, gpg operation and refusal, with
  the server's host key fingerprint and the reason. It never holds up a connection, is
  reopened after log rotation and reports lost events as `dropped`.
- `credential-bridge-remote`: one static binary for servers (x86_64, aarch64, s390x)
  with the git credential helper, the gpg shim, `setup`, `uninstall` and `query`.
  Someone without a bridge in the same account falls through to their own helper or
  gpg-agent.
- `credential-bridge-ctl`: the entry points `init`, `check`, `log`, `config` and
  `completions`, and one group per area: `agent`, `source`, `profile`, `server`,
  `vault`, `gpg` and `daemon`. Besides managing their part of the configuration,
  `server` has `add/list/show/remove/uninstall`, `ssh-config`, `keys` and `token`;
  `vault` has `list` and `show` (the vaults the sources use, settings, tool and unlock
  state, the next step), `setup` (KeePassXC asks for its database file and key file,
  then offers to restart the daemon whenever it uses other files, and to unlock; the
  other vaults say why they need no setup; several database files found are listed to
  choose by number or path), `forget` (removes the settings and ends the session; the
  vault itself is untouched), `unlock` and `lock` (which also drops the git tokens
  cached from that vault, all with `--all`); `source test` resolves a source's secret
  reference through the daemon, which returns only whether it worked (a daemon that has
  not loaded the source is named as such, with the hint `daemon reload`), and
  `source add` runs the same test as a warning; `source add github --auth app --create`
  creates a GitHub App (manifest flow, key straight into the vault) and adds and tests
  its source; `daemon` has `install/uninstall/start/stop/status` for the service,
  `alive` and `reload`, which makes the running daemon re-read the configuration (as
  `SIGHUP`) and keeps unlock sessions and approvals (open forwarded connections go on
  under the new configuration while their server, its profile apart from git rules and
  `signing`, the upstreams and, with a gpg tunnel open, the gpg-agent socket stay the
  same, and end with their next request otherwise), but drops the git tokens cached for
  every source it removed or changed in any way (a renamed source, a reference moved to
  another vault); ctl suggests it instead of a restart wherever a reload suffices, and a
  restart only for `[daemon]` and `[vault]`. It edits a configuration behind a symbolic
  link in place and says so if the target is read-only (home-manager).
- `server add` takes the host keys from known_hosts only, requires a non-revoked exact
  entry for the server's known_hosts name from `ssh -G`, and stops before installing or
  writing anything if the host key ssh used for its own connection is not among them, if
  the entry would not validate, or if one of its keys belongs to another server (which
  would make both unregistered). With `--pin` a key ssh trusts through a wildcard line
  is pinned as it is, and for a host certificate the key in it, fetched with
  `ssh-keyscan` and accepted only if its fingerprint is the one ssh reported; both only
  if ssh's debug log shows that it verified the key, or the certificate's CA, against
  one of the known_hosts files read (`Found key in …`, `Found CA key in …`), so a key
  accepted with `StrictHostKeyChecking no` is never pinned. Paths in `ssh -G`'s
  known_hosts lists keep their spaces, tabs and trailing spaces; relative paths and
  unexpanded `%` tokens are refused; unreadable known_hosts files are skipped with a
  warning, as ssh skips them, also those of other servers whose keys are compared. It
  hints when `UpdateHostKeys` is off for a followed server. It ends with a probe: one
  connection with the daemon's forward socket as `ForwardAgent`, judged by the daemon's
  audit log (recognised, unregistered with the key used, ambiguous, or a local client
  that is not OpenSSH 8.9 or later; skipped when the daemon is not running). A failed
  probe fails the command and keeps the entry. The probe, `ctl log` and `ctl check` use
  the audit log and sockets the running daemon reports (Ping and Status name them, with
  its KeePassXC database and key file), which differ from the file after a `[daemon]`
  change until a restart; `daemon reload` and `check` name such paths, and those of
  `[vault]`, with the hint to restart.
- `ctl check` covers this machine and connects to no server; `check NAME…` adds those
  servers and `check --all` every server (the probe, the remote binary, git config and
  `gpg.conf`). It reports a followed server without known_hosts entry and a host key of
  several servers, a known_hosts file it cannot read as a warning of its own (which
  `server list`, `server show` and the probe name as well), and lists recent requests
  with such a key apart from unregistered hosts. ctl never connects to the forward
  socket itself, so its own connections never show up as unverified clients.
- Configuration management in ctl: `init` (finds agents and a logged-in `gh`, asks per
  item, `--yes` without questions), `config show|path|check|edit`, and
  `daemon`/`agent`/`source`/`profile`/`profile rule`/`server set`/`vault`/`gpg set`
  commands for every section. Every change keeps comments, is validated like the daemon
  loads it before it is written, reloads a running daemon (not for `[daemon]` or
  `[vault]` alone, which take effect on a restart) and has `--dry-run` (a diff);
  removing something still in use is refused with the fix, and servers whose git setup a
  change makes out of date are named.
- `ctl server uninstall DEST` cleans up `credential-bridge-remote` and its git config on
  any ssh destination without touching the configuration; `server remove` checks the
  entry in the file before it runs anything on the server.
- Validation refuses an `[[agent.upstream]]` whose socket is the proxy's own
  (`daemon.socket` or `daemon.forward_socket`); `init` never proposes them.
- End-to-end test with real ssh agent forwarding, git over HTTPS and an `ed25519-sk` key
  through OpenSSH's sk-dummy provider; fuzz targets for everything parsed from servers,
  with a short run in `nix flake check` and a weekly CI job; a link check of the docs.

### Changed

- New configuration format (`version = 2`): agents, sources, profiles and servers. A 0.1
  configuration is rejected with a message; there is no migration.
- Everything reaches servers through agent forwarding, and servers are recognised only
  behind a local OpenSSH 8.9 or later; `ctl check` and `ctl server add` warn about an
  older `ssh -V`. Hosts without a `[server.*]` entry get the built-in
  `profile.unregistered` (see Security).
- `credential-bridge-remote` replaces `git-credential-bridge`; the release packages and
  the Nix bundle ship it as
  `share/credential-bridge/helpers/credential-bridge-remote-<target>`.
- The systemd unit is `credential-bridge.service` (was `credential-bridged.service`),
  the launchd agent `io.github.xes0r.credential-bridge` (was
  `local.credential-bridge.daemon`).
- ctl commands of 0.1 with a successor: `service install/uninstall/start/stop/status`
  and `service reload` are `daemon …`; `config init` is `init`, `config validate` is
  `config check` (`config path/show/edit` stay); `test REMOTE URL` is
  `server token SERVER URL`.

### Removed

- `RemoteForward` and the per-server `bridge.sock`, together with all `remote` commands
  (`add/remove/list/show/ssh-config/edit/install/check/uninstall`; servers are managed
  with `server …`). Servers without agent forwarding are not supported.
- `doctor` (`check` covers this machine), `service restart` (`daemon stop`, then
  `daemon start`) and `service logs` (the service manager's log; `log` shows the audit
  log).

### Security

- Secure by default: hosts without a `[server.*]` entry get the built-in
  `[profile.unregistered]` with an empty key list (not even public keys are shown), a
  dialog for every signature, no hops, and never tokens, gpg or signing. Writing the
  table overrides single fields (`keys` is required with `ssh`; `confirm` stays
  `"always"` unless set; `"8h"` remembers per host key); git rules, gpg and signing are
  rejected there. Connections that are not recognised get nothing, hard-coded.
- The bridge is hidden from unregistered hosts and unrecognised connections: `query` and
  the bridge's extensions are answered like unknown extensions (`SSH_AGENT_FAILURE`, as
  from OpenSSH's ssh-agent), so the remote helper and the gpg shim step aside silently.
  Registered servers get reasoned refusals. `ctl check` lists recent refused hosts with
  the `server add` command that admits them, shows the effective `profile.unregistered`
  and warns about `keys = "all"` and `confirm = "never"` in it.
- A server is selected only by the first message on a forwarded connection, a verified
  forwarding `session-bind`, and only if the local ssh client is OpenSSH 8.9 or later
  (read from the peer's executable, never run). So a server cannot get another server's
  profile by replaying a genuine bind of that server.
- Binds the proxy refused are replayed to the upstream agents too, so an upstream
  ssh-agent applies its destination constraints (`ssh-add -h`) to the real attempt.
- Workers for git, vaults and gpg run as separate processes; the git and gpg workers run
  with Landlock, seccomp and `no_new_privs` on Linux. Every process is protected from
  tracing and core dumps. gpg traffic (inquiry answers, signatures, session keys) and
  extension replies on the server, git credentials included, are wiped from memory after
  use.
- git requests whose path has an empty, `.` or `..` segment, a `%` or a `\` are denied
  before rule matching, so `team-a/../team-b/repo` cannot escape a rule; patterns may
  not contain such paths either. Rules compare the path as git decoded it, with one
  `.git` suffix stripped.
- Approvals: an askpass helper approves only if it exits with status 0 and answers
  nothing or `yes`, as in OpenSSH. `ssh-add -x` wins over open dialogs. Remembered
  approvals are keyed by server, key, local process and hop, and never reused without a
  server bind. Unlock attempts run one at a time, each with the delay after a failure.
- The gpg filter denies every pinentry mode but `ask`, `default`, `cancel` and `error`,
  so a server cannot answer passphrase inquiries itself.
- ctl quotes every argument of the commands it runs on servers.
- Release packages are built only from tags on `main` after the full checks, and their
  build provenance is attested together with `SHA256SUMS`; verify them with
  `gh attestation verify` and `sha256sum` (see "Verifying a release package" in the
  [README](https://github.com/XeS0r/ssh-credential-bridge/blob/main/README.md#verifying-a-release-package)).

### Known limitations

- macOS is only partly type-checked (crates without C dependencies) and not yet tested
  on a real Mac.
- The aarch64 and s390x remote binaries have only run under emulation.
- 1Password, Bitwarden, hardware keys and the GitHub App flow against real GitHub have
  not been tested yet; KeePassXC only with keepassxc-cli 2.8.0 on Linux and a database
  without key file.
- KeePassXC through `keepassxc-cli` needs the database password: databases opened only
  by a key file or by YubiKey challenge-response are not supported.
- Host key types the proxy does not support (for example `ssh-mldsa44-ed25519`) are
  refused in `session-bind`, so such servers are not recognised and get nothing.
- Host certificates are recognised by their embedded key only; the CA is not checked. A
  followed server gets its profile for any key accepted for its name in ssh, also on
  first contact (`StrictHostKeyChecking accept-new`); `--pin` avoids that.
- Behind older or other ssh clients, or clients the proxy cannot inspect, servers get
  nothing.
- Hidden, not invisible: an unregistered host still sees that an agent is forwarded and
  that it lists no keys.
- An App source's `api_url` must be `https` on port 443, the only port the git worker's
  sandbox allows; GitHub Enterprise Server on another port is not supported.
- Servers must be Linux; no Windows support (WSL works). Release packages are not
  code-signed.

## [0.1.0] - 2026-11-18

First public beta.

### Added

- `credential-bridged`: serves one unix socket per remote, forwarded by ssh
  (`RemoteForward`), and answers git credential requests from the local backend (by
  default `gh auth git-credential`) within each remote's policy: allowed URL patterns
  and operations, `get` only by default.
- Only username, password and expiry reach a remote; no other URLs and no long-lived
  tokens such as refresh tokens. At most eight requests per remote run at once.
- `git-credential-bridge`: static helper for remotes on x86_64, aarch64 and s390x Linux.
  It registers itself with git (`setup`), restores what it replaced (`uninstall`), and
  reports problems in git's output together with the command that fixes them.
- `credential-bridge-ctl`: systemd/launchd user service, `remote add/edit/install/check`
  with an end-to-end check of the whole chain, ssh config hints, `doctor`, logs in
  columns and a status summary.
- Installation with Nix (`nix run github:XeS0r/ssh-credential-bridge#install`) or
  without it from release packages with statically linked programs and `install.sh`.

### Known limitations

- macOS is built and linted, but not yet tested on a real Mac.
- The aarch64 and s390x helpers have only run under emulation.
- Release packages are not signed yet; check them against `SHA256SUMS`.
- No helper for macOS remotes; no Windows support.

[Unreleased]: https://github.com/XeS0r/ssh-credential-bridge/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/XeS0r/ssh-credential-bridge/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/XeS0r/ssh-credential-bridge/releases/tag/v0.1.0
