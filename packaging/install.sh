#!/bin/sh
# Installs credential-bridge from this release package: no root, no Nix, no
# dependencies. Run it from the unpacked directory.
#
#   ./install.sh                     into ~/.local (bin/, share/)
#   ./install.sh --prefix /usr/local into another prefix (needs write access)
#   ./install.sh --uninstall         removes it again; the configuration stays
#
# Running it again updates an existing installation and restarts the service.

set -eu

usage() {
  sed -n '2,10s/^# \{0,1\}//p' "$0"
}

here=$(cd "$(dirname "$0")" && pwd)
prefix=${PREFIX:-$HOME/.local}
action=install
while [ $# -gt 0 ]; do
  case $1 in
    --prefix) prefix=${2:?--prefix needs a directory}; shift 2 ;;
    --prefix=*) prefix=${1#*=}; shift ;;
    --uninstall) action=uninstall; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "install.sh: unknown option $1 (see --help)" >&2; exit 2 ;;
  esac
done

manifest=$prefix/share/credential-bridge/installed-files
ctl=$prefix/bin/credential-bridge-ctl
case "$(uname -s)" in
  Darwin) service_definition=$HOME/Library/LaunchAgents/io.github.xes0r.credential-bridge.plist ;;
  *) service_definition=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/credential-bridge.service ;;
esac

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

if [ "$action" = uninstall ]; then
  if [ ! -f "$manifest" ]; then
    echo "credential-bridge is not installed in $prefix" >&2
    exit 1
  fi
  "$ctl" daemon uninstall >/dev/null 2>&1 && echo "✓ service removed" || true
  while IFS= read -r file; do
    rm -f "$prefix/$file"
  done < "$manifest"
  rm -f "$manifest"
  rmdir "$prefix/share/credential-bridge/helpers" "$prefix/share/credential-bridge" 2>/dev/null || true
  echo "✓ removed credential-bridge from $prefix (configuration in ~/.config/credential-bridge is kept)"
  exit 0
fi

[ -x "$here/bin/credential-bridge-ctl" ] || {
  echo "install.sh: run me from the unpacked release directory" >&2
  exit 1
}
refuse_v01 "$prefix/bin" "$manifest"

updating=false
[ -f "$manifest" ] && updating=true

# Copy everything below bin/ and share/, remembering each file for --uninstall.
tmp_manifest=$(mktemp)
(cd "$here" && find bin share -type f) | sort | while IFS= read -r file; do
  mkdir -p "$(dirname "$prefix/$file")"
  # Replace instead of overwriting in place: a running daemon keeps its binary.
  cp "$here/$file" "$prefix/$file.new"
  case $file in bin/* | share/credential-bridge/helpers/*) chmod 755 "$prefix/$file.new" ;; *) chmod 644 "$prefix/$file.new" ;; esac
  mv -f "$prefix/$file.new" "$prefix/$file"
  echo "$file" >> "$tmp_manifest"
done
# Files the previous version installed but this one no longer ships.
if [ -f "$manifest" ]; then
  while IFS= read -r file; do
    grep -qxF "$file" "$tmp_manifest" || rm -f "$prefix/$file"
  done < "$manifest"
fi
mkdir -p "$(dirname "$manifest")"
mv -f "$tmp_manifest" "$manifest"
chmod 644 "$manifest"

version=$("$ctl" --version 2>/dev/null | cut -d' ' -f2)
if $updating; then
  echo "✓ updated credential-bridge $version in $prefix"
  # A service that is set up gets reinstalled, which restarts the daemon.
  if [ -e "$service_definition" ] && "$ctl" daemon install >/dev/null 2>&1; then
    echo "✓ service restarted"
  fi
else
  echo "✓ installed credential-bridge $version in $prefix"
fi

case ":$PATH:" in
  *":$prefix/bin:"*) ;;
  *) echo "⚠ $prefix/bin is not in your PATH; add it, e.g. in ~/.profile:"
     echo "    export PATH=\"$prefix/bin:\$PATH\"" ;;
esac

if ! $updating; then
  cat <<EOF

Next (see README.md):
  credential-bridge-ctl init                    # finds your agents, writes the configuration
  credential-bridge-ctl profile add dev ssh.keys=all
  credential-bridge-ctl daemon install
  credential-bridge-ctl server add NAME --profile dev
  credential-bridge-ctl server ssh-config NAME  # add what it prints to ~/.ssh/config
  credential-bridge-ctl check
EOF
fi
