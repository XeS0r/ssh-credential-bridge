# Fuzz targets

`cargo-fuzz` targets for everything credential-bridge parses from servers, workers and
ctl. This is a separate cargo workspace; it needs a nightly toolchain and is not built
by the main workspace.

| Target              | Input                                                  |
| ------------------- | ------------------------------------------------------ |
| `agent_frame`       | ssh-agent frames and messages (raw-byte round trip)    |
| `session_bind`      | `session-bind@openssh.com` contents (parse and verify) |
| `extension_payload` | `git-credential`, `gpg-agent` and `query` payloads     |
| `git_credential`    | git credential attribute text                          |
| `ipc_frame`         | worker and control frames                              |
| `assuan_filter`     | Assuan lines, the gpg command filter and tunnel state  |

The flake provides the nightly toolchain and `cargo-fuzz` (`apps.fuzz`); no dev shell is
needed. From the repository root:

```sh
nix run .#fuzz -- 60                          # every target for 60 seconds each
nix run .#fuzz -- 300 session_bind ipc_frame  # only these targets
just fuzz 300 session_bind                    # the same through just
```

Every target runs even if an earlier one crashed; the command fails at the end and names
the targets that crashed. libFuzzer writes the crashing input to
`fuzz/artifacts/<target>/` (the weekly CI job uploads that directory). Reproduce a crash
with the same toolchain by running the target once on that file:

```sh
nix run .#fuzz -- reproduce session_bind fuzz/artifacts/session_bind/crash-<hash>
```

The corpus grows in `fuzz/corpus/<target>/`. `nix flake check` runs every target for 20
seconds (`checks.fuzz`).

The same properties run on stable as proptest tests in
`crates/proto/tests/roundtrip.rs`.
