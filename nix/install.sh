# Installs or removes credential-bridge for the current user, without a Nix profile.
#
# Not run directly: flake.nix prepends `action=install|uninstall` and `package=<bundle>`
# and wraps it as the apps `install` / `uninstall` (`nix run .#install`, `just install`).
#
# The package is the store path of the bundle. It is kept alive by a GC root at
# $XDG_DATA_HOME/credential-bridge/package; everything else links through that root,
# so an update only swaps the root and existing links stay valid. The service unit names
# the credential-bridged of the package, so an update installs the service again.
#
#   $PREFIX/bin/{credential-bridge-ctl,credential-bridged}
#   $PREFIX/share/man/man1/*.1.gz
#   $XDG_DATA_HOME/bash-completion/completions/credential-bridge-ctl
#   $XDG_DATA_HOME/fish/vendor_completions.d/credential-bridge-ctl.fish
#
# PREFIX defaults to ~/.local.

action=${action:?}
package=${package:?}

prefix=${PREFIX:-$HOME/.local}
data_home=${XDG_DATA_HOME:-$HOME/.local/share}
config_home=${XDG_CONFIG_HOME:-$HOME/.config}
root=$data_home/credential-bridge/package

bin_dir=$prefix/bin
man_dir=$prefix/share/man/man1
bash_completion=$data_home/bash-completion/completions/credential-bridge-ctl
fish_completion=$data_home/fish/vendor_completions.d/credential-bridge-ctl.fish

case "$(uname -s)" in
  Darwin) service_definition=$HOME/Library/LaunchAgents/io.github.xes0r.credential-bridge.plist ;;
  *) service_definition=$config_home/systemd/user/credential-bridge.service ;;
esac

programs="credential-bridge-ctl credential-bridged"

# credential-bridge 0.1 must be removed with its own programs before 0.2 is installed
# over it (CHANGELOG.md, 0.2.0). Found by its service, its manifest or a
# credential-bridge-ctl of version 0.1. $1: the bin directory, $2: the
# manifest of a release package installation.
refuse_v01() {
  found=
  for unit in "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/credential-bridged.service" \
    "$HOME/.config/systemd/user/credential-bridged.service" \
    "$HOME/Library/LaunchAgents/local.credential-bridge.daemon.plist"; do
    if [ -e "$unit" ]; then
      found="its service $unit"
      break
    fi
  done
  if [ -z "$found" ] && [ -f "$2" ] && grep -qx 'bin/git-credential-bridge' "$2"; then
    found="its files, listed in $2"
  fi
  if [ -z "$found" ] && [ -x "$1/credential-bridge-ctl" ]; then
    # 0.1 prints "credential-bridge-ctl 0.1.x" and has a remote command; a ctl that
    # does not run at all is not taken for 0.1.
    case "$("$1/credential-bridge-ctl" --version 2>/dev/null)" in
      "credential-bridge-ctl 0.1."*) found="its $1/credential-bridge-ctl" ;;
    esac
    if [ -z "$found" ] && "$1/credential-bridge-ctl" remote --help >/dev/null 2>&1; then
      found="its $1/credential-bridge-ctl"
    fi
  fi
  [ -z "$found" ] && return 0
  cat >&2 <<EOF
credential-bridge 0.1 is installed ($found); nothing was installed.
Remove it first, with its programs still installed (CHANGELOG.md, 0.2.0):
  credential-bridge-ctl remote uninstall NAME   # for every remote
  credential-bridge-ctl service uninstall
then remove the RemoteForward lines from ~/.ssh/config and run this again.
Without the 0.1 programs, stop its service by hand and delete its unit file or plist:
  systemctl --user disable --now credential-bridged.service        # Linux
  launchctl bootout gui/\$(id -u)/local.credential-bridge.daemon    # macOS
EOF
  exit 1
}

# Links $2 -> $1, but never replaces a file that is not a symlink.
link() {
  if [ -e "$2" ] && [ ! -L "$2" ]; then
    echo "warning: $2 exists and is not a symlink; left untouched" >&2
    return
  fi
  mkdir -p "$(dirname "$2")"
  ln -sfn "$1" "$2"
}

# Removes $1 if it is a symlink into our GC root.
unlink_ours() {
  if [ -L "$1" ]; then
    case "$(readlink "$1")" in
      "$root"/*) rm -f "$1" ;;
    esac
  fi
}

do_install() {
  refuse_v01 "$bin_dir" "$prefix/share/credential-bridge/installed-files"
  mkdir -p "$(dirname "$root")"
  # Registers $root as an indirect GC root pointing at the package.
  nix-store --realise "$package" --add-root "$root" >/dev/null

  for program in $programs; do
    link "$root/bin/$program" "$bin_dir/$program"
  done
  for page in "$root"/share/man/man1/*; do
    link "$root/share/man/man1/$(basename "$page")" "$man_dir/$(basename "$page")"
  done
  link "$root/share/bash-completion/completions/credential-bridge-ctl.bash" "$bash_completion"
  link "$root/share/fish/vendor_completions.d/credential-bridge-ctl.fish" "$fish_completion"

  echo "installed $(basename "$package") into $prefix"

  if [ -e "$service_definition" ]; then
    # Points the unit at the new credential-bridged and restarts the daemon.
    "$bin_dir/credential-bridge-ctl" daemon install
  else
    echo "next: credential-bridge-ctl init, profile add dev ssh.keys=all, daemon install,"
    echo "      server add NAME --profile dev, server ssh-config NAME, check (see README.md)"
  fi

  case ":$PATH:" in
    *":$bin_dir:"*) ;;
    *) echo "note: $bin_dir is not in your PATH" >&2 ;;
  esac
}

do_uninstall() {
  if [ -e "$service_definition" ] && [ -x "$bin_dir/credential-bridge-ctl" ]; then
    "$bin_dir/credential-bridge-ctl" daemon uninstall
  fi
  for program in $programs; do
    unlink_ours "$bin_dir/$program"
  done
  if [ -d "$man_dir" ]; then
    for page in "$man_dir"/*; do
      unlink_ours "$page"
    done
  fi
  unlink_ours "$bash_completion"
  unlink_ours "$fish_completion"
  rm -f "$root"
  rmdir "$(dirname "$root")" 2>/dev/null || true
  echo "uninstalled from $prefix (configuration in $config_home/credential-bridge is kept)"
}

case "$action" in
  install) do_install ;;
  uninstall) do_uninstall ;;
  *)
    echo "unknown action: $action" >&2
    exit 2
    ;;
esac
