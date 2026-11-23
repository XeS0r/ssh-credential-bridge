# Runs every static credential-bridge-remote of the bundle (x86_64, aarch64, s390x) under
# qemu-user against a real credential-bridged: version, `query` on both sockets, a git
# request from a client that is not OpenSSH (the bridge hides itself, the helper steps
# aside without a word, the reason is in the local audit log), the quiet cases without
# an agent, `store`, and `setup --print`. Run with `nix build .#checks.<system>.remotes`.
{ pkgs, package }:
pkgs.runCommand "credential-bridge-remotes-test"
  {
    nativeBuildInputs = [
      pkgs.qemu-user
      pkgs.file
      pkgs.git # `setup` reads the git config
    ];
  }
  ''
    set -euo pipefail
    export HOME=$TMPDIR/home NO_COLOR=1
    mkdir -p $HOME/.config/credential-bridge
    state=$HOME/.local/state/credential-bridge

    cat > $HOME/.config/credential-bridge/config.toml <<EOF
    version = 2

    [source.helper]
    type = "helper"
    helper = "!f() { echo username=fake-user; echo password=fake-token; }; f"

    # Even a loosened profile.unregistered never gets tokens, and these connections
    # are not recognised at all (the remote binary is no OpenSSH client).
    [profile.unregistered]
    ssh = { keys = "all", confirm = "never" }
    EOF

    ${package}/bin/credential-bridged run 2> $TMPDIR/daemon.log &
    daemon=$!
    trap 'kill $daemon; cat $TMPDIR/daemon.log' EXIT
    for _ in $(seq 100); do [ -S $state/agent-forward.sock ] && break; sleep 0.1; done
    forward=$state/agent-forward.sock
    local_sock=$state/agent.sock
    audit=$state/audit.log

    expect() { # expect TEXT OUTPUT
      case "$2" in *"$1"*) ;; *) echo "expected '$1' in: $2" >&2; exit 1 ;; esac
    }
    empty() { # empty WHAT OUTPUT
      [ -z "$2" ] || { echo "$1 was not empty: $2" >&2; exit 1; }
    }

    host=$(uname -m)
    for remote in ${package}/share/credential-bridge/helpers/credential-bridge-remote-*; do
      target=''${remote##*/credential-bridge-remote-}
      arch=''${target%%-*}
      echo "== $target: $(file -bL "$remote" | cut -d, -f1-2,5)"
      run() { if [ "$arch" = "$host" ]; then "$remote" "$@"; else "qemu-$arch" "$remote" "$@"; fi; }
      request='protocol=https\nhost=github.com\npath=org/repo\n\n'

      expect "credential-bridge-remote" "$(run --version)"

      # No verified ssh client (the remote binary itself connects): the bridge hides
      # itself, `query` is answered as by an agent without it.
      if res=$(SSH_AUTH_SOCK=$forward run query); then echo "query without a bind found the bridge: $res" >&2; exit 1; fi
      expect "extension: none" "$res"
      expect "bridge:    no" "$res"

      # agent.sock never answers extensions.
      if res=$(SSH_AUTH_SOCK=$local_sock run query); then echo "query on agent.sock succeeded: $res" >&2; exit 1; fi
      expect "bridge:    no" "$res"

      # No tokens, and not a word on the server: the helper steps aside.
      empty "get without a bind" "$(printf "$request" | SSH_AUTH_SOCK=$forward run git get 2>&1)"

      # Step aside without an agent, with a dead socket and for store.
      empty "get without agent" "$(unset SSH_AUTH_SOCK; printf "$request" | run git get 2>&1)"
      empty "get with a dead socket" "$(printf "$request" | SSH_AUTH_SOCK=$TMPDIR/missing.sock run git get 2>&1)"
      empty "store" "$(printf 'protocol=https\nhost=github.com\nusername=u\npassword=p\n\n' | SSH_AUTH_SOCK=$forward run git store 2>&1)"

      res=$(run setup --host github.com --print)
      expect "git config --global --add credential.https://github.com.helper" "$res"

      echo "   ok"
    done

    # The reason is only in the local audit log (written by a thread: wait for it).
    reason='"reason":"the local ssh client is not OpenSSH 8.9 or later, so the server is not recognised"'
    label='"server":"unrecognised host (local ssh client not verified as OpenSSH 8.9 or later)"'
    for _ in $(seq 50); do grep -q "$reason" $audit && break; sleep 0.1; done
    expect "$reason" "$(grep "$label" $audit)"
    if grep -q 'fake-token' $audit; then echo "token in the audit log" >&2; exit 1; fi
    touch $out
  ''
