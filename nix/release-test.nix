# Uses a release package the way someone without Nix would: unpack, install.sh,
# run the programs with an empty environment, check the remote binaries, update,
# uninstall. Run with `nix build .#checks.<system>.release`.
{ pkgs, tarball }:
pkgs.runCommand "credential-bridge-release-test"
  {
    nativeBuildInputs = [
      pkgs.binutils
      pkgs.file
    ];
  }
  ''
    set -euo pipefail
    export HOME=$TMPDIR/home NO_COLOR=1
    mkdir -p $HOME
    expect() { case "$2" in *"$1"*) ;; *) echo "expected '$1' in: $2" >&2; exit 1 ;; esac; }

    tar xzf ${tarball}/*.tar.gz -C $TMPDIR
    pkg=$(echo $TMPDIR/credential-bridge-*/)
    for f in $pkg/install.sh $pkg/LICENSE $pkg/README.md; do test -f "$f"; done

    echo "== static local programs"
    for bin in $pkg/bin/*; do
      if readelf -l "$bin" | grep -q "program interpreter"; then echo "$bin is dynamic" >&2; exit 1; fi
      env -i "$bin" --version
    done
    test "$(ls $pkg/bin)" = "$(printf 'credential-bridge-ctl\ncredential-bridged')"

    echo "== remote binaries under the names credential-bridge-ctl server add looks for"
    helpers=$pkg/share/credential-bridge/helpers
    for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl s390x-unknown-linux-gnu; do
      bin=$helpers/credential-bridge-remote-$target
      info=$(file -b "$bin")
      echo "$target: $info"
      if readelf -l "$bin" | grep -q "program interpreter"; then echo "$bin is dynamic" >&2; exit 1; fi
      case $target in
        x86_64-*) expect "x86-64" "$info" ;;
        aarch64-*) expect "ARM aarch64" "$info" ;;
        s390x-*) expect "S/390" "$info" ;;
      esac
    done

    echo "== install.sh refuses to install over 0.1, before copying anything"
    refused() {
      if msg=$("$@" 2>&1); then echo "installed over 0.1: $msg" >&2; exit 1; fi
      echo "$msg"
      expect "credential-bridge 0.1 is installed" "$msg"
      expect "credential-bridge-ctl service uninstall" "$msg"
      expect "systemctl --user disable --now credential-bridged.service" "$msg"
      test ! -e $TMPDIR/v01/bin/credential-bridged
      test ! -e $TMPDIR/v01/share/credential-bridge/helpers
    }
    unit=$HOME/.config/systemd/user/credential-bridged.service
    mkdir -p $(dirname $unit) $TMPDIR/v01
    touch $unit
    refused sh $pkg/install.sh --prefix $TMPDIR/v01
    expect "its service $unit" "$msg"
    # nix/install.sh (nix run .#install) checks the same before touching the store.
    msg=$(action=install package=/nonexistent PREFIX=$TMPDIR/v01 bash ${./install.sh} 2>&1) && exit 1
    expect "credential-bridge 0.1 is installed (its service $unit)" "$msg"
    rm $unit
    mkdir -p $TMPDIR/v01/share/credential-bridge
    printf 'bin/credential-bridge-ctl\nbin/git-credential-bridge\n' > $TMPDIR/v01/share/credential-bridge/installed-files
    refused sh $pkg/install.sh --prefix $TMPDIR/v01
    expect "its files, listed in" "$msg"
    rm $TMPDIR/v01/share/credential-bridge/installed-files
    mkdir -p $TMPDIR/v01/bin
    fake_ctl() { printf '#!/bin/sh\n%s\nexit 2\n' "$1" > $TMPDIR/v01/bin/credential-bridge-ctl; chmod 755 $TMPDIR/v01/bin/credential-bridge-ctl; }
    # 0.1 by its version, and by its remote command.
    for script in '[ "$1" = --version ] && echo "credential-bridge-ctl 0.1.0" && exit 0' '[ "$1" = remote ] && exit 0'; do
      fake_ctl "$script"
      refused sh $pkg/install.sh --prefix $TMPDIR/v01
      expect "its $TMPDIR/v01/bin/credential-bridge-ctl" "$msg"
      msg=$(action=install package=/nonexistent PREFIX=$TMPDIR/v01 bash ${./install.sh} 2>&1) && exit 1
      expect "its $TMPDIR/v01/bin/credential-bridge-ctl" "$msg"
    done
    # A ctl that does not run (here: fails for everything) is not taken for 0.1.
    fake_ctl 'exit 1'
    # -e as in the installer app: it stops at the missing package, after the 0.1 check.
    msg=$(action=install package=/nonexistent PREFIX=$TMPDIR/v01 bash -e ${./install.sh} 2>&1) && exit 1
    case "$msg" in *"0.1 is installed"*) echo "a broken ctl taken for 0.1: $msg" >&2; exit 1 ;; esac
    res=$(sh $pkg/install.sh --prefix $TMPDIR/v01)
    expect "✓ installed credential-bridge" "$res"
    sh $pkg/install.sh --prefix $TMPDIR/v01 --uninstall > /dev/null

    echo "== install.sh"
    res=$(PATH=/usr/bin:/bin:$PATH sh $pkg/install.sh --prefix $TMPDIR/p)
    echo "$res"
    expect "✓ installed credential-bridge" "$res"
    expect "Next (see README.md):" "$res"
    expect "credential-bridge-ctl init" "$res"
    test -x $TMPDIR/p/bin/credential-bridge-ctl
    test -x $TMPDIR/p/bin/credential-bridged
    test -x $TMPDIR/p/share/credential-bridge/helpers/credential-bridge-remote-x86_64-unknown-linux-musl
    test -f $TMPDIR/p/share/man/man1/credential-bridge-ctl.1.gz
    test -f $TMPDIR/p/share/man/man1/credential-bridged.1.gz
    env -i HOME=$HOME $TMPDIR/p/bin/credential-bridge-ctl server ssh-config > /dev/null

    echo "== update removes what the new version no longer ships"
    old=share/credential-bridge/helpers/credential-bridge-remote-retired
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
