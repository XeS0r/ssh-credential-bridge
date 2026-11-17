# Installs or removes credential-bridge for the current user, without a Nix profile.
#
# Not run directly: flake.nix prepends `action=install|uninstall` and `package=<bundle>`
# and wraps it as the apps `install` / `uninstall` (`nix run .#install`, `just install`).
#
# The package is the store path of the bundle. It is kept alive by a GC root at
# $XDG_DATA_HOME/credential-bridge/package; everything else links through that root,
# so an update only swaps the root and existing links (and the service unit) stay valid.
#
#   $PREFIX/bin/{credential-bridge-ctl,credential-bridged,git-credential-bridge}
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
  Darwin) service_definition=$HOME/Library/LaunchAgents/local.credential-bridge.daemon.plist ;;
  *) service_definition=$config_home/systemd/user/credential-bridged.service ;;
esac

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
  mkdir -p "$(dirname "$root")"
  # Registers $root as an indirect GC root pointing at the package.
  nix-store --realise "$package" --add-root "$root" >/dev/null

  for program in credential-bridge-ctl credential-bridged git-credential-bridge; do
    link "$root/bin/$program" "$bin_dir/$program"
  done
  for page in "$root"/share/man/man1/*; do
    link "$root/share/man/man1/$(basename "$page")" "$man_dir/$(basename "$page")"
  done
  link "$root/share/bash-completion/completions/credential-bridge-ctl.bash" "$bash_completion"
  link "$root/share/fish/vendor_completions.d/credential-bridge-ctl.fish" "$fish_completion"

  echo "installed $(basename "$package") into $prefix"

  if [ -e "$service_definition" ]; then
    # Rewrites the unit with the stable path and restarts the running daemon.
    "$bin_dir/credential-bridge-ctl" service install --daemon-path "$bin_dir/credential-bridged"
  else
    echo "next: credential-bridge-ctl service install"
  fi

  case ":$PATH:" in
    *":$bin_dir:"*) ;;
    *) echo "note: $bin_dir is not in your PATH" >&2 ;;
  esac
}

do_uninstall() {
  if [ -e "$service_definition" ] && [ -x "$bin_dir/credential-bridge-ctl" ]; then
    "$bin_dir/credential-bridge-ctl" service uninstall
  fi
  for program in credential-bridge-ctl credential-bridged git-credential-bridge; do
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
