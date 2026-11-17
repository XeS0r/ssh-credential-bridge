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

if [ "$action" = uninstall ]; then
  if [ ! -f "$manifest" ]; then
    echo "credential-bridge is not installed in $prefix" >&2
    exit 1
  fi
  "$ctl" service uninstall >/dev/null 2>&1 && echo "✓ service removed" || true
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
  if "$ctl" service restart >/dev/null 2>&1; then
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

Next:
  credential-bridge-ctl service install
  credential-bridge-ctl remote add NAME --allow 'https://github.com/ORG/*'
  credential-bridge-ctl remote install NAME
  credential-bridge-ctl remote ssh-config NAME >> ~/.ssh/config
  credential-bridge-ctl remote check NAME
EOF
fi
