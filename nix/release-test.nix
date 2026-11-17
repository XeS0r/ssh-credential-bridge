# Uses a release package the way someone without Nix would: unpack, install.sh,
# run the programs with an empty environment, find the helpers, update,
# uninstall. Run with `nix build .#checks.<system>.release`.
{ pkgs, tarball }:
pkgs.runCommand "credential-bridge-release-test" { nativeBuildInputs = [ pkgs.binutils ]; } ''
  set -euo pipefail
  export HOME=$TMPDIR/home NO_COLOR=1
  mkdir -p $HOME
  expect() { case "$2" in *"$1"*) ;; *) echo "expected '$1' in: $2" >&2; exit 1 ;; esac; }

  tar xzf ${tarball}/*.tar.gz -C $TMPDIR
  pkg=$(echo $TMPDIR/credential-bridge-*/)
  for f in $pkg/install.sh $pkg/LICENSE $pkg/README.md; do test -f "$f"; done

  echo "== static binaries"
  for bin in $pkg/bin/*; do
    if readelf -l "$bin" | grep -q "program interpreter"; then echo "$bin is dynamic" >&2; exit 1; fi
    env -i "$bin" --version
  done

  echo "== install.sh"
  res=$(PATH=/usr/bin:/bin:$PATH sh $pkg/install.sh --prefix $TMPDIR/p)
  echo "$res"
  expect "✓ installed credential-bridge" "$res"
  expect "Next:" "$res"
  test -x $TMPDIR/p/bin/credential-bridge-ctl
  test -f $TMPDIR/p/share/man/man1/credential-bridge-ctl.1.gz

  echo "== helpers found without Nix, by full path and via PATH"
  res=$($TMPDIR/p/bin/credential-bridge-ctl doctor || true)
  expect "helpers aarch64 s390x x86_64" "$res"
  res=$(env PATH=$TMPDIR/p/bin:$PATH credential-bridge-ctl doctor || true)
  expect "helpers aarch64 s390x x86_64" "$res"
  res=$(env -i HOME=$HOME $TMPDIR/p/bin/credential-bridge-ctl doctor || true)
  expect "helpers aarch64 s390x x86_64" "$res"

  echo "== update removes what the new version no longer ships"
  old=share/credential-bridge/helpers/git-credential-bridge-retired-linux
  touch $TMPDIR/p/$old
  echo $old >> $TMPDIR/p/share/credential-bridge/installed-files
  res=$(sh $pkg/install.sh --prefix $TMPDIR/p)
  expect "✓ updated credential-bridge" "$res"
  test ! -e $TMPDIR/p/$old
  if grep -q retired $TMPDIR/p/share/credential-bridge/installed-files; then echo "manifest still lists it" >&2; exit 1; fi

  echo "== uninstall"
  res=$(sh $pkg/install.sh --prefix $TMPDIR/p --uninstall)
  expect "✓ removed credential-bridge" "$res"
  test ! -e $TMPDIR/p/bin/credential-bridge-ctl
  test ! -e $TMPDIR/p/share/credential-bridge
  test -z "$(find $TMPDIR/p -type f)"

  touch $out
''
