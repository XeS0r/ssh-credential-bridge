# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). While the version is 0.x, configuration and
the protocol between helper and daemon may still change between minor versions.

The release workflow publishes the section of the tagged version as the release notes.

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

[0.1.0]: https://github.com/XeS0r/ssh-credential-bridge/releases/tag/v0.1.0
