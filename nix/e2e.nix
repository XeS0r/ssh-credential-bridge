# End-to-end test: two NixOS VMs, real ssh, real git, the user service.
#
#   client  alice runs credential-bridged (systemd user service) and ctl;
#           a fake `gh` stands in for the real backend
#   remote  bob@remote with sshd and git; gets the helper via `remote install`
#
# The last subtest repeats the setup without Nix, from the release package.
#
# Run with `just e2e` or `nix build .#checks.<system>.e2e -L`.
{
  pkgs,
  package,
  release,
}:
let
  # Answers like `gh auth git-credential`: a token for github.com, and a
  # silent exit 1 for hosts it is not logged in to.
  fakeGh = pkgs.writeShellScriptBin "gh" ''
    [ "$1 $2" = "auth git-credential" ] || exit 2
    [ "$3" = get ] || exit 0
    host=$(sed -n 's/^host=//p')
    [ "$host" = github.com ] || exit 1
    echo username=fake-user
    echo password=fake-token
  '';
in
pkgs.testers.runNixOSTest {
  name = "credential-bridge-e2e";

  nodes.client = {
    environment.systemPackages = [
      package
      fakeGh
      pkgs.git
      pkgs.openssh
    ];
    users.users.alice = {
      isNormalUser = true;
      uid = 1000;
      linger = true;
    };
  };

  # Edge cases: `bare` has git but sshd without StreamLocalBindUnlink,
  # `nogit` has no git at all.
  nodes.bare = {
    services.openssh.enable = true;
    environment.systemPackages = [ pkgs.git ];
    users.users.bob.isNormalUser = true;
  };
  nodes.nogit = {
    services.openssh.enable = true;
    users.users.bob.isNormalUser = true;
  };

  nodes.remote = {
    services.openssh = {
      enable = true;
      settings.StreamLocalBindUnlink = "yes";
    };
    environment.systemPackages = [ pkgs.git ];
    users.users.bob.isNormalUser = true;
    # A home directory with a space: the helper path in git's config needs quoting.
    users.users.eve = {
      isNormalUser = true;
      home = "/home/eve space";
    };
  };

  testScript = ''
    import shlex

    # Exported, so that every command of a `a && b` chain sees it.
    ENV = "export XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus NO_COLOR=1; "

    def alice(cmd, ok=True):
        full = "su - alice -c " + shlex.quote(ENV + cmd)
        if ok:
            return client.succeed(full)
        return client.fail(full)

    def alice_out(cmd):
        """stdout and stderr together, whatever the exit status."""
        return client.execute("su - alice -c " + shlex.quote(ENV + cmd + " 2>&1"))[1]

    def on_remote(cmd, forward=True):
        opts = "" if forward else "-o ClearAllForwardings=yes "
        return alice_out("ssh " + opts + "remote " + shlex.quote(cmd))

    def expect(text, output):
        assert text in output, f"expected {text!r} in:\n{output}"

    start_all()
    remote.wait_for_unit("sshd.service")
    client.wait_for_unit("user@1000.service")

    with subtest("ssh from alice to bob@remote, bob@bare and bob@nogit"):
        bare.wait_for_unit("sshd.service")
        nogit.wait_for_unit("sshd.service")
        alice("mkdir -p ~/.ssh && ssh-keygen -q -t ed25519 -N ''' -f ~/.ssh/id_ed25519")
        key = alice("cat ~/.ssh/id_ed25519.pub").strip()
        for host in (remote, bare, nogit):
            host.succeed(f"install -d -m 700 -o bob /home/bob/.ssh && echo {shlex.quote(key)} > /home/bob/.ssh/authorized_keys && chown bob /home/bob/.ssh/authorized_keys")
        remote.succeed(f"install -d -m 700 -o eve '/home/eve space/.ssh' && echo {shlex.quote(key)} > '/home/eve space/.ssh/authorized_keys' && chown eve '/home/eve space/.ssh/authorized_keys'")
        alice("printf 'Host remote bare nogit\\n  User bob\\n  StrictHostKeyChecking accept-new\\nHost spaced\\n  HostName remote\\n  User eve\\n  StrictHostKeyChecking accept-new\\n' > ~/.ssh/config")
        alice("ssh remote true && ssh bare true && ssh nogit true && ssh spaced true")

    with subtest("service install uses the stable path, not the Nix store"):
        alice("credential-bridge-ctl service install")
        unit = alice("cat ~/.config/systemd/user/credential-bridged.service")
        expect('ExecStart="/run/current-system/sw/bin/credential-bridged"', unit)
        expect("Type=notify", unit)
        expect("running", alice("credential-bridge-ctl service status"))

    with subtest("a config change right after service install does not kill the daemon"):
        out = alice("credential-bridge-ctl service install && credential-bridge-ctl remote add quick --allow https://github.com")
        expect("reloaded credential-bridged", out)
        expect("active", alice("systemctl --user is-active credential-bridged"))
        alice("test -S ~/.local/state/credential-bridge/sockets/quick.sock")
        alice("credential-bridge-ctl remote remove quick")

    with subtest("remote add, list, doctor before install"):
        alice("credential-bridge-ctl remote add remote --allow 'https://github.com/org/*'")
        expect("not ready", alice("credential-bridge-ctl remote list"))
        doctor = alice_out("credential-bridge-ctl doctor")
        expect("not installed on the remote", doctor)
        expect("no RemoteForward", doctor)

    with subtest("remote install: helper sets itself up"):
        out = alice("credential-bridge-ctl remote install remote")
        expect("✓ connect", out)
        expect("✓ configure git  github.com", out)
        expect("RemoteForward", out)
        helper = on_remote("git config --global --get-all credential.https://github.com.helper")
        expect("git-credential-bridge --socket", helper)

    with subtest("ssh config, check, doctor"):
        alice("credential-bridge-ctl remote ssh-config remote 2>/dev/null >> ~/.ssh/config")
        expect("ready", alice("credential-bridge-ctl remote check remote"))
        expect("all good", alice("credential-bridge-ctl doctor"))
        expect("remote", alice("credential-bridge-ctl remote list"))

    with subtest("ctl and the service agree on a custom XDG_STATE_HOME"):
        alice("XDG_STATE_HOME=/home/alice/xs credential-bridge-ctl service install")
        expect('Environment="XDG_STATE_HOME=/home/alice/xs"', alice("cat ~/.config/systemd/user/credential-bridged.service"))
        alice("test -S ~/xs/credential-bridge/sockets/remote.sock")
        out = alice_out("XDG_STATE_HOME=/home/alice/xs credential-bridge-ctl doctor")
        assert "local socket" not in out, out
        # Reinstalling (as an update does) keeps it, unless it is given again.
        expect("keeping XDG_STATE_HOME=/home/alice/xs", alice("credential-bridge-ctl service install"))
        expect('Environment="XDG_STATE_HOME=/home/alice/xs"', alice("cat ~/.config/systemd/user/credential-bridged.service"))
        alice("credential-bridge-ctl service uninstall && credential-bridge-ctl service install")
        assert "XDG_STATE_HOME" not in alice("cat ~/.config/systemd/user/credential-bridged.service")
        expect("ready", alice("credential-bridge-ctl remote check remote"))

    with subtest("git gets the credential through the forwarded socket"):
        out = on_remote("printf 'url=https://github.com/org/repo\\n\\n' | git credential fill")
        expect("password=fake-token", out)

    with subtest("store and erase stay quiet"):
        out = on_remote("printf 'url=https://github.com/org/repo\\nusername=u\\npassword=p\\n\\n' | git credential approve")
        assert out.strip() == "", f"expected no output, got:\n{out}"

    with subtest("denied path names the fix"):
        out = on_remote("printf 'url=https://github.com/other/repo\\n\\n' | GIT_TERMINAL_PROMPT=0 git credential fill")
        expect("credential-bridge: github.com/other/repo is not allowed for this remote", out)
        expect("remote edit remote --add-allow 'https://github.com/other/*'", out)

    with subtest("edit, reinstall, and the login hint of a backend without credential"):
        alice("credential-bridge-ctl remote edit remote --add-allow https://nologin.example")
        alice("credential-bridge-ctl remote install remote")
        out = on_remote("printf 'url=https://nologin.example/x\\n\\n' | GIT_TERMINAL_PROMPT=0 git credential fill")
        expect("credential-bridge: no credential for nologin.example on your local machine", out)
        expect("gh auth login --hostname nologin.example", out)

    with subtest("without forwarding the helper says so"):
        out = on_remote("printf 'url=https://github.com/org/repo\\n\\n' | GIT_TERMINAL_PROMPT=0 git credential fill", forward=False)
        expect("credential-bridge: not connected to your local machine", out)
        # The documented switch for details works (it used to make git fail).
        out = on_remote("printf 'url=https://github.com/org/repo\\n\\n' | CREDENTIAL_BRIDGE_VERBOSE=1 GIT_TERMINAL_PROMPT=0 git credential fill", forward=False)
        expect("credential-bridge: not connected to your local machine", out)
        expect(".local/state/credential-bridge/bridge.sock", out)

    with subtest("logs are in columns"):
        logs = alice("credential-bridge-ctl service logs -n 50")
        expect("remote  get    ✓ allowed  github.com/org/repo", logs)
        expect("✗ denied", logs)
        expect("∅ none", logs)

    with subtest("--color and -v"):
        expect("\x1b[32m✓", alice("credential-bridge-ctl --color always doctor"))
        assert "\x1b[" not in alice("credential-bridge-ctl --color never doctor")
        assert "\x1b[" not in alice("env -u NO_COLOR credential-bridge-ctl doctor | cat")
        expect("$ ssh -T -o ClearAllForwardings=yes", alice_out("credential-bridge-ctl -v remote install remote"))
        expect("unit:", alice("credential-bridge-ctl -v service status"))

    with subtest("service status --raw and logs -f"):
        expect("credential-bridged.service", alice_out("credential-bridge-ctl service status --raw"))
        # journalctl outlives the killed ctl; keep it off our output pipe.
        logs = alice("timeout 3 credential-bridge-ctl service logs -f -n 20 >/tmp/alice-logs 2>/dev/null; pkill -u alice journalctl; cat /tmp/alice-logs")
        expect("✓ allowed", logs)

    with subtest("test command"):
        out = alice("credential-bridge-ctl test remote https://github.com/org/repo")
        expect("result:  ok username=fake-user password=<redacted>", out)
        assert "fake-token" not in out
        expect("denied", alice_out("credential-bridge-ctl test remote https://github.com/other/repo"))
        alice("credential-bridge-ctl test remote https://github.com/other/repo", ok=False)

    with subtest("remote edit: operations, ssh host, backend, errors"):
        alice("credential-bridge-ctl remote edit remote --operation get --operation store")
        expect('operations = ["get", "store"]', alice("cat ~/.config/credential-bridge/config.toml"))
        expect("result:  ok", alice("credential-bridge-ctl test remote https://github.com/org/repo --operation store"))
        alice("credential-bridge-ctl remote edit remote --operation get")
        # A new destination forgets the socket path of the old one.
        expect("remote install remote", alice("credential-bridge-ctl remote edit remote --ssh-host bob@remote"))
        expect("remote socket:   unknown", alice("credential-bridge-ctl remote show remote"))
        expect("not installed on the remote", alice_out("credential-bridge-ctl remote check remote"))
        alice("credential-bridge-ctl remote install remote")
        expect("ready", alice("credential-bridge-ctl remote check remote"))
        alice("credential-bridge-ctl remote edit remote --ssh-host remote && credential-bridge-ctl remote install remote")
        alice("credential-bridge-ctl remote edit remote --backend '!false'")
        expect('backend = "!false"', alice("cat ~/.config/credential-bridge/config.toml"))
        alice("credential-bridge-ctl remote edit remote --default-backend")
        assert "!false" not in alice("cat ~/.config/credential-bridge/config.toml")
        alice("credential-bridge-ctl remote edit remote", ok=False)
        expect("is not in the allow list", alice_out("credential-bridge-ctl remote edit remote --remove-allow https://nope.example"))

    with subtest("check uses an already open session instead of taking its socket over"):
        alice("ssh -f -N remote </dev/null >/dev/null 2>&1")
        expect("via an open ssh session", alice("credential-bridge-ctl -v remote check remote"))
        expect("password=fake-token", on_remote("printf 'url=https://github.com/org/repo\\n\\n' | git credential fill"))
        alice("pkill -f 'ssh -f -N [r]emote'")

    with subtest("second remote without git, both served at once"):
        alice("credential-bridge-ctl remote add nogit --allow 'https://github.com/org/*'")
        out = alice("credential-bridge-ctl remote install nogit")
        expect("⚠ configure git  skipped: git not found on the remote", out)
        alice("credential-bridge-ctl remote ssh-config nogit 2>/dev/null >> ~/.ssh/config")
        listing = alice("credential-bridge-ctl remote list")
        expect("remote", listing)
        expect("nogit", listing)
        expect("password=fake-token", on_remote("printf 'url=https://github.com/org/repo\\n\\n' | git credential fill"))
        expect("connected to your local machine (remote nogit)", alice_out("ssh nogit .local/bin/git-credential-bridge ping"))

        expect("git on the remote does not use the helper", alice_out("credential-bridge-ctl remote check nogit"))
        alice("credential-bridge-ctl remote uninstall nogit && credential-bridge-ctl remote remove nogit")
        assert "nogit" not in alice("credential-bridge-ctl remote list")

    with subtest("stale socket on a remote without StreamLocalBindUnlink"):
        alice("credential-bridge-ctl remote add bare --allow 'https://github.com/org/*' && credential-bridge-ctl remote install bare")
        alice("credential-bridge-ctl remote ssh-config bare 2>/dev/null >> ~/.ssh/config")
        expect("ready", alice("credential-bridge-ctl remote check bare"))
        # What a connection that ended uncleanly leaves behind.
        bare.succeed("su - bob -c 'touch ~/.local/state/credential-bridge/bridge.sock'")
        out = alice_out("credential-bridge-ctl remote check bare")
        expect("broken", out)
        expect("StreamLocalBindUnlink yes", out)
        bare.succeed("rm /home/bob/.local/state/credential-bridge/bridge.sock")
        expect("ready", alice("credential-bridge-ctl remote check bare"))
        alice("credential-bridge-ctl remote uninstall bare && credential-bridge-ctl remote remove bare")

    with subtest("a host dropped from the allow list gets the user's own helper back"):
        # As `gh auth setup-git` writes it: an empty reset, then the helper.
        on_remote("git config --global --add credential.https://example.org.helper ''' && git config --global --add credential.https://example.org.helper '!echo mine'")
        alice("credential-bridge-ctl remote edit remote --add-allow https://example.org && credential-bridge-ctl remote install remote")
        expect("git-credential-bridge", on_remote("git config --global --get-all credential.https://example.org.helper"))
        alice("credential-bridge-ctl remote edit remote --remove-allow https://example.org && credential-bridge-ctl remote install remote")
        restored = on_remote("git config --global --get-all credential.https://example.org.helper")
        assert restored.splitlines() == ["", "!echo mine"], repr(restored)
        assert on_remote("git config --global --get-all credential.https://example.org.bridgesavedhelper || true").strip() == ""

    with subtest("a home directory with a space"):
        alice("credential-bridge-ctl remote add spaced --allow 'https://github.com/org/*'")
        alice("credential-bridge-ctl remote install spaced")
        expect("!'/home/eve space/.local/bin/git-credential-bridge'", alice_out("ssh spaced git config --global --get-all credential.https://github.com.helper"))
        alice("credential-bridge-ctl remote ssh-config spaced 2>/dev/null >> ~/.ssh/config")
        expect("ready", alice("credential-bridge-ctl remote check spaced"))
        expect("password=fake-token", alice_out("ssh spaced \"printf 'url=https://github.com/org/repo\\\\n\\\\n' | git credential fill\""))
        alice("credential-bridge-ctl remote uninstall spaced && credential-bridge-ctl remote remove spaced")

    with subtest("remote uninstall, then check is broken"):
        expect("removed the helper", alice("credential-bridge-ctl remote uninstall remote"))
        assert on_remote("test -e ~/.local/bin/git-credential-bridge && echo present").strip() == ""
        expect("broken", alice_out("credential-bridge-ctl remote check remote"))

    with subtest("check with a missing helper leaves an open session's socket alone"):
        alice("ssh -f -N remote </dev/null >/dev/null 2>&1")
        out = alice_out("credential-bridge-ctl remote check remote")
        expect("helper is missing", out)
        expect("present", on_remote("test -S ~/.local/state/credential-bridge/bridge.sock && echo present", forward=False))
        alice("pkill -f 'ssh -f -N [r]emote'")

    with subtest("install --dry-run, --no-git-config, --binary"):
        expect("# run on remote", alice("credential-bridge-ctl remote install remote --dry-run"))
        assert on_remote("test -e ~/.local/bin/git-credential-bridge && echo present").strip() == ""
        alice("credential-bridge-ctl remote install remote --no-git-config")
        expect("present", on_remote("test -x ~/.local/bin/git-credential-bridge && echo present"))
        # Only the user's own helper (restored earlier) may be there, none of ours.
        assert "git-credential-bridge" not in on_remote("git config --global --get-regexp credential || true")
        helper = "${package}/share/credential-bridge/helpers/git-credential-bridge-${pkgs.stdenv.hostPlatform.parsed.cpu.name}-linux"
        expect("✓ configure git", alice(f"credential-bridge-ctl remote install remote --binary {helper}"))
        expect("ready", alice("credential-bridge-ctl remote check remote"))

    with subtest("without Nix: release package with install.sh, then service and remote from it"):
        out = alice("tar xzf ${release}/credential-bridge-*.tar.gz -C /tmp && sh /tmp/credential-bridge-*/install.sh")
        expect("✓ installed credential-bridge", out)
        alice("~/.local/bin/credential-bridge-ctl service install")
        expect('ExecStart="/home/alice/.local/bin/credential-bridged"', alice("cat ~/.config/systemd/user/credential-bridged.service"))
        expect("helpers aarch64 s390x x86_64", alice_out("~/.local/bin/credential-bridge-ctl doctor"))
        out = alice("~/.local/bin/credential-bridge-ctl remote install remote")
        expect("✓ upload helper", out)
        expect("ready", alice("~/.local/bin/credential-bridge-ctl remote check remote"))
        expect("password=fake-token", on_remote("printf 'url=https://github.com/org/repo\\n\\n' | git credential fill"))
        expect("✓ updated", alice("sh /tmp/credential-bridge-*/install.sh"))
        out = alice("sh /tmp/credential-bridge-*/install.sh --uninstall")
        expect("✓ service removed", out)
        expect("✓ removed credential-bridge", out)
  '';
}
