# Runs every static remote helper of the bundle (x86_64, aarch64, s390x) under
# qemu-user against a real credential-bridged with a fake backend: version,
# ping, an allowed and a denied get, a quiet store, `setup --dry-run` and the
# message without a daemon. Run with `nix build .#checks.<system>.helpers`.
{ pkgs, package }:
pkgs.runCommand "credential-bridge-helpers-test"
  {
    nativeBuildInputs = [
      pkgs.qemu-user
      pkgs.file
      pkgs.git # `setup` only writes git config if git exists
    ];
  }
  ''
    set -euo pipefail
    export HOME=$TMPDIR/home NO_COLOR=1
    mkdir -p $HOME $TMPDIR/s

    cat > $TMPDIR/config.toml <<EOF
    backend = "!f() { test \"\$1\" = get || exit 0; cat > /dev/null; echo username=fake-user; echo password=fake-token; }; f"
    socket_dir = "$TMPDIR/s"
    [[remote]]
    name = "r"
    allow = ["https://github.com/org/*"]
    EOF

    ${package}/bin/credential-bridged run --config $TMPDIR/config.toml 2> $TMPDIR/daemon.log &
    daemon=$!
    trap 'kill $daemon' EXIT
    for _ in $(seq 50); do [ -S $TMPDIR/s/r.sock ] && break; sleep 0.1; done
    sock=$TMPDIR/s/r.sock

    expect() { # expect TEXT OUTPUT
      case "$2" in *"$1"*) ;; *) echo "expected '$1' in: $2" >&2; exit 1 ;; esac
    }

    host=$(uname -m)
    for helper in ${package}/share/credential-bridge/helpers/git-credential-bridge-*; do
      platform=''${helper##*/git-credential-bridge-}
      arch=''${platform%-linux}
      echo "== $platform: $(file -bL "$helper" | cut -d, -f1-2,5)"
      run() { if [ "$arch" = "$host" ]; then "$helper" "$@"; else "qemu-$arch" "$helper" "$@"; fi; }

      expect "git-credential-bridge" "$(run --version)"
      expect "connected to your local machine (remote r)" "$(run --socket $sock ping)"

      res=$(printf 'protocol=https\nhost=github.com\npath=org/repo\n\n' | run --socket $sock get)
      expect "password=fake-token" "$res"

      err=$(printf 'protocol=https\nhost=github.com\npath=other/repo\n\n' | run --socket $sock get 2>&1 >/dev/null)
      expect "credential-bridge: github.com/other/repo is not allowed for this remote" "$err"

      err=$(printf 'protocol=https\nhost=github.com\npath=org/repo\nusername=u\npassword=p\n\n' | run --socket $sock store 2>&1)
      [ -z "$err" ] || { echo "store was not quiet: $err" >&2; exit 1; }

      res=$(run --socket /home/test/b.sock setup --dry-run 'https://github.com/org/*')
      expect "git config --global --add credential.https://github.com.helper" "$res"
      expect "--socket /home/test/b.sock'" "$res"

      err=$(printf 'protocol=https\nhost=github.com\n\n' | run --socket $TMPDIR/missing.sock get 2>&1)
      expect "credential-bridge: not connected to your local machine" "$err"

      echo "   ok"
    done
    touch $out
  ''
