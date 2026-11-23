# End-to-end test: four NixOS VMs, real ssh with agent forwarding, real git over HTTPS.
#
#   client  alice sets up her configuration with ctl (init, agent, source, profile) and
#           runs credential-bridged as a systemd user service in front of two OpenSSH
#           agents: `main` (ed25519 keys, SSH_ASKPASS for `ssh-add -c`) and `sk`
#           (an ed25519-sk key through the sk-dummy provider), and keeps one token in
#           a KeePassXC database read with keepassxc-cli. dave is a second person
#           with a plain ssh-agent and no bridge. `ssh-nobind` is an ssh client that
#           sends no session-bind and calls itself OpenSSH 8.8, as OpenSSH before 8.9.
#   remote  bob@remote, the account alice and dave share; set up by `ctl server add`,
#           which follows its known_hosts entry; rotates its host key later
#   hop     bob@hop, reached directly and as a hop behind remote
#   forge   nginx serving git over HTTPS with basic auth (user `token`)
#
# Run with `just e2e` or `nix build .#checks.<system>.e2e -L`.
{
  pkgs,
  package,
  skDummy,
  sshNobind,
}:
let
  token = "s3cret-forge-token";

  # A self-signed certificate for https://forge; remote and hop trust it.
  tls = pkgs.runCommand "forge-tls" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir $out
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -subj /CN=forge -addext subjectAltName=DNS:forge \
      -keyout $out/key.pem -out $out/cert.pem
  '';

  # Approves agent confirmations (`ssh-add -c`) unless /tmp/askpass-deny exists, and
  # logs every question.
  askpass = pkgs.writeShellScript "askpass" ''
    echo "''${SSH_ASKPASS_PROMPT:-} $*" >> /tmp/askpass.log
    [ ! -e /tmp/askpass-deny ]
  '';

  server = {
    services.openssh.enable = true;
    environment.systemPackages = [ pkgs.git ];
    security.pki.certificateFiles = [ "${tls}/cert.pem" ];
    users.users.bob.isNormalUser = true;
  };
in
pkgs.testers.runNixOSTest {
  name = "credential-bridge-e2e";

  nodes.client = {
    environment.systemPackages = [
      package
      pkgs.git
      pkgs.keepassxc
      sshNobind
    ];
    users.users.alice = {
      isNormalUser = true;
      uid = 1000;
      linger = true;
    };
    users.users.dave.isNormalUser = true;
  };

  nodes.remote = {
    imports = [ server ];
    # The ECDSA key is held back at first and offered later, when the ed25519 key is
    # retired: a host key rotation through UpdateHostKeys.
    services.openssh.hostKeys = [
      {
        type = "ed25519";
        path = "/etc/ssh/ssh_host_ed25519_key";
      }
      {
        type = "ecdsa";
        path = "/etc/ssh/ssh_host_ecdsa_key";
      }
    ];
  };
  nodes.hop = server;

  nodes.forge =
    { config, ... }:
    {
      networking.firewall.allowedTCPPorts = [ 443 ];
      users.users.git = {
        isSystemUser = true;
        group = "git";
        home = "/srv/git";
      };
      users.groups.git = { };
      environment.systemPackages = [ pkgs.git ];
      services.fcgiwrap.instances.git = {
        process.user = "git";
        process.group = "git";
        socket.user = "nginx";
        socket.group = "nginx";
      };
      services.nginx = {
        enable = true;
        virtualHosts.forge = {
          onlySSL = true;
          sslCertificate = "${tls}/cert.pem";
          sslCertificateKey = "${tls}/key.pem";
          locations."/".extraConfig = ''
            auth_basic "git";
            auth_basic_user_file ${pkgs.writeText "htpasswd" "token:{PLAIN}${token}\n"};
            include ${config.services.nginx.package}/conf/fastcgi_params;
            fastcgi_pass unix:${config.services.fcgiwrap.instances.git.socket.address};
            fastcgi_param SCRIPT_FILENAME ${pkgs.git}/libexec/git-core/git-http-backend;
            fastcgi_param GIT_PROJECT_ROOT /srv/git;
            fastcgi_param GIT_HTTP_EXPORT_ALL "";
            fastcgi_param PATH_INFO $uri;
            fastcgi_param REMOTE_USER $remote_user;
          '';
        };
      };
    };

  testScript = ''
    import json
    import shlex

    # Exported, so that every command of a `a && b` chain sees it.
    ENV = "export XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus NO_COLOR=1; "
    FILL = "printf 'protocol=https\\nhost=forge\\npath={}\\n\\n' | GIT_TERMINAL_PROMPT=0 git credential fill"
    # The remote helper itself, for hosts without our helper in their git config.
    HELPER = "printf 'protocol=https\\nhost=forge\\npath={}\\n\\n' | .local/bin/credential-bridge-remote git get"

    def alice(cmd, ok=True):
        full = "su - alice -c " + shlex.quote(ENV + cmd)
        if ok:
            return client.succeed(full)
        return client.fail(full)

    def alice_out(cmd):
        """stdout and stderr together, whatever the exit status."""
        return client.execute("su - alice -c " + shlex.quote(ENV + cmd + " 2>&1"))[1]

    def on(host, cmd, opts=""):
        """Runs cmd as bob@host over alice's ssh (with her ssh config); output and errors."""
        return alice_out(f"ssh {opts} {host} " + shlex.quote(cmd))

    def dave(cmd):
        """dave: own key in a plain ssh-agent, forwarded to bob@remote."""
        script = "eval $(ssh-agent) > /dev/null; ssh-add -q ~/.ssh/id_ed25519; " + cmd + "; ssh-agent -k > /dev/null"
        return client.execute("su - dave -c " + shlex.quote(script + " 2>&1"))[1]

    def expect(text, output):
        assert text in output, f"expected {text!r} in:\n{output}"

    def refute(text, output):
        assert text not in output, f"did not expect {text!r} in:\n{output}"

    def sshd_key(action):
        """Parks, offers or retires one of remote's host keys and restarts sshd. A key
        file sshd cannot load (but that is not empty, so it is not generated again)
        makes sshd go on without that key."""
        remote.succeed(f"{action} && systemctl restart sshd.service")
        remote.wait_for_unit("sshd.service")
        remote.wait_for_open_port(22)

    start_all()
    for host in (remote, hop):
        host.wait_for_unit("sshd.service")
    # remote offers only its ed25519 key until the rotation subtest.
    sshd_key("mv /etc/ssh/ssh_host_ecdsa_key /etc/ssh/ecdsa.next && mv /etc/ssh/ssh_host_ecdsa_key.pub /etc/ssh/ecdsa.next.pub && echo parked > /etc/ssh/ssh_host_ecdsa_key")
    forge.wait_for_unit("nginx.service")
    client.wait_for_unit("user@1000.service")

    with subtest("forge serves git over HTTPS with basic auth"):
        forge.succeed(
            "install -d -o git -g git /srv/git/team /srv/git/tools"
            " && cd /tmp && git init -q -b main seed && cd seed"
            " && echo hello > README && git add README"
            " && git -c user.name=seed -c user.email=seed@forge commit -q -m seed"
            " && for repo in team/repo tools/repo; do"
            "      git clone -q --bare /tmp/seed /srv/git/$repo.git"
            "      && git -C /srv/git/$repo.git config http.receivepack true"
            "      && chown -R git:git /srv/git/$repo.git; done"
        )
        remote.succeed("GIT_TERMINAL_PROMPT=0 git ls-remote https://token:${token}@forge/team/repo.git")
        remote.fail("GIT_TERMINAL_PROMPT=0 git ls-remote https://token:wrong@forge/team/repo.git")

    with subtest("upstream agents: main with SSH_ASKPASS, sk with the sk-dummy provider"):
        alice("mkdir -p -m 700 ~/agents ~/keys ~/.ssh")
        alice("SSH_ASKPASS=${askpass} SSH_ASKPASS_REQUIRE=force DISPLAY=:0 ssh-agent -a ~/agents/main.sock > /dev/null")
        alice("ssh-agent -P '/nix/store/*' -a ~/agents/sk.sock > /dev/null")
        for name in ("main", "confirm", "dest"):
            alice(f"ssh-keygen -q -t ed25519 -N ''' -C {name} -f ~/keys/id_{name}")
        alice("ssh-keygen -q -t ed25519-sk -w ${skDummy}/lib/sk-dummy.so -N ''' -C sk -f ~/keys/id_sk")
        # ssh reads `-i <key>.pub` like a private key file first; keep it quiet.
        alice("chmod 600 ~/keys/*.pub")
        alice("SSH_AUTH_SOCK=~/agents/sk.sock ssh-add -q -S ${skDummy}/lib/sk-dummy.so ~/keys/id_sk")
        expect("ED25519-SK", alice("SSH_AUTH_SOCK=~/agents/sk.sock ssh-add -l"))
        keys = {name: alice(f"cat ~/keys/id_{name}.pub").strip() for name in ("main", "confirm", "dest", "sk")}
        authorized = "\n".join(keys.values())
        for host in (remote, hop):
            host.succeed(f"install -d -m 700 -o bob /home/bob/.ssh && echo {shlex.quote(authorized)} > /home/bob/.ssh/authorized_keys && chown bob /home/bob/.ssh/authorized_keys")

    with subtest("dave: a second person with a plain agent in the same account"):
        client.succeed("su - dave -c \"mkdir -p -m 700 ~/.ssh && ssh-keygen -q -t ed25519 -N ''' -f ~/.ssh/id_ed25519\"")
        dave_key = client.succeed("cat /home/dave/.ssh/id_ed25519.pub").strip()
        remote.succeed(f"echo {shlex.quote(dave_key)} >> /home/bob/.ssh/authorized_keys")
        client.succeed("su - dave -c \"printf 'Host *\\n  User bob\\n  StrictHostKeyChecking accept-new\\n' > ~/.ssh/config\"")

    with subtest("ctl writes the configuration: init, agents, sources, profiles, rules"):
        # init finds the agent in SSH_AUTH_SOCK; --dry-run only shows the file.
        out = alice("SSH_AUTH_SOCK=~/agents/main.sock credential-bridge-ctl init --yes --dry-run")
        expect("agent ssh-agent", out)
        expect("+++ /home/alice/.config/credential-bridge/config.toml (new)", out)
        alice("test ! -e ~/.config/credential-bridge/config.toml")
        alice("env -u SSH_AUTH_SOCK credential-bridge-ctl init --yes")
        expect("version = 2", alice("cat ~/.config/credential-bridge/config.toml"))
        expect("exists", alice_out("credential-bridge-ctl init --yes"))
        alice("credential-bridge-ctl agent add main '~/agents/main.sock' --add-to")
        alice("credential-bridge-ctl agent add sk '~/agents/sk.sock'")
        alice("credential-bridge-ctl source add forgejo forge --host forge --token 'cmd:cat ~/forge-token'")
        expect("takes a reference", alice_out("credential-bridge-ctl source add gitlab leak --host forge --token ${token}"))
        helper = '!f() { test "$1" = get || exit 0; cat > /dev/null; echo username=token; echo password=${token}; }; f'
        alice("credential-bridge-ctl source add helper helper --helper " + shlex.quote(helper))
        alice("credential-bridge-ctl profile add work ssh.keys=all")
        alice("credential-bridge-ctl profile rule add work 'https://forge/team/*' --source forge")
        alice("credential-bridge-ctl profile rule add work 'https://forge/tools/*' --source helper")
        alice("credential-bridge-ctl profile add limited ssh.keys=sk")
        config = alice("cat ~/.config/credential-bridge/config.toml")
        refute("s3cret", config.replace("password=${token}", ""))
        # Dry runs and refused removals leave the file alone.
        expect("+[profile.scratch]", alice("credential-bridge-ctl profile add scratch --dry-run"))
        expect("profile.work.git[0]", alice_out("credential-bridge-ctl source remove forge"))
        expect("profile.limited.ssh.keys", alice_out("credential-bridge-ctl agent remove sk"))
        assert alice("cat ~/.config/credential-bridge/config.toml") == config
        expect("✓ config", alice("credential-bridge-ctl config check"))
        expect("ssh.confirm = \"never\"", alice("credential-bridge-ctl config show"))

    with subtest("daemon install starts the daemon"):
        alice("printf '%s\\n' ${token} > ~/forge-token")
        expect("installed", alice("credential-bridge-ctl daemon install"))
        alice("for i in $(seq 50); do test -S ~/.local/state/credential-bridge/agent-forward.sock && break; sleep 0.2; done")
        expect("running", alice("credential-bridge-ctl daemon status"))
        alice("credential-bridge-ctl daemon alive")
        agents = alice("credential-bridge-ctl agent list")
        expect("main (add_to)", agents)
        expect("sk ", agents)

    with subtest("source test resolves through the daemon; source add warns about a source that fails"):
        expect("resolved (the value is not shown)", alice("credential-bridge-ctl source test forge"))
        out = alice("credential-bridge-ctl source add forgejo broken --host forge --token cmd:false --no-cache 2>&1")
        expect("⚠ token", out)
        expect("the source is written; fix this and run credential-bridge-ctl source test broken", out)
        expect("token = \"cmd:false\"\ncache = false\n", alice("cat ~/.config/credential-bridge/config.toml"))
        expect("cache            false: every request reads the vault again", alice("credential-bridge-ctl source show broken"))
        alice("credential-bridge-ctl source remove broken")
        refute("[source.broken]", alice("cat ~/.config/credential-bridge/config.toml"))

    with subtest("ssh-add through agent.sock goes to agent.add_to, with -c and -h"):
        alice("printf 'Host *\\n  User bob\\n  StrictHostKeyChecking accept-new\\n  UpdateHostKeys yes\\n  IdentityAgent ~/.local/state/credential-bridge/agent.sock\\n' > ~/.ssh/config")
        proxy = "SSH_AUTH_SOCK=~/.local/state/credential-bridge/agent.sock "
        alice(proxy + "ssh-add -q ~/keys/id_main")
        alice(proxy + "ssh-add -q -c ~/keys/id_confirm")
        # ssh-add -h needs the host keys in known_hosts.
        alice("ssh -o IdentitiesOnly=yes -i ~/keys/id_main.pub remote true && ssh -o IdentitiesOnly=yes -i ~/keys/id_main.pub hop true")
        alice(proxy + "ssh-add -q -h remote ~/keys/id_dest")
        alice("rm ~/keys/id_main ~/keys/id_confirm ~/keys/id_dest")
        listed = alice(proxy + "ssh-add -l")
        for name in ("main", "confirm", "dest", "sk"):
            expect(f" {name} (", listed)
        expect("ED25519-SK", listed)
        main = alice("SSH_AUTH_SOCK=~/agents/main.sock ssh-add -l")
        expect(" confirm (", main)
        refute(" sk (", main)

    with subtest("ssh-add -h: the key works for remote only"):
        alice("ssh -o IdentitiesOnly=yes -i ~/keys/id_dest.pub remote true")
        alice("ssh -o IdentitiesOnly=yes -i ~/keys/id_dest.pub -o BatchMode=yes hop true", ok=False)

    with subtest("server add follows known_hosts, installs the remote binary, sets up git, probes"):
        out = alice("credential-bridge-ctl server add remote --profile work 2>&1")
        remote_ed25519 = remote.succeed("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | cut -d' ' -f2").strip()
        expect(f"✓ host key             ssh-ed25519 {remote_ed25519} (used by ssh)", out)
        expect("✓ known_hosts          remote: ssh-ed25519", out)
        expect("✓ remote installed", out)
        expect("✓ git config", out)
        expect("no ForwardAgent to the proxy for remote", out)
        # The probe forwards the agent itself, whatever the ssh config says.
        expect("✓ probe                the daemon recognises remote (profile work)", out)
        config = alice("cat ~/.config/credential-bridge/config.toml")
        expect("[server.remote]", config)
        expect('known_host = "remote"', config)
        refute("host_keys", config)
        expect('profile = "work"', config)
        expect("known_hosts remote: ssh-ed25519", alice("credential-bridge-ctl server show remote"))
        helpers = on("remote", "git config --global --get-regexp '^credential'")
        expect("credential-bridge-remote", helpers)
        expect("usehttppath true", helpers.lower())
        out = alice("credential-bridge-ctl server add hop --profile limited --pin 2>&1")
        expect("✓ host keys pinned", out)
        expect("✓ remote installed", out)
        expect("✓ probe                the daemon recognises hop (profile limited)", out)
        expect("pinned: ssh-ed25519", alice("credential-bridge-ctl server list"))

    with subtest("server ssh-config with the fallback, then check"):
        alice("{ credential-bridge-ctl server ssh-config --fallback ~/agents/main.sock remote hop; cat ~/.ssh/config; } > ~/ssh-config.new && mv ~/ssh-config.new ~/.ssh/config")
        expect("ForwardAgent", alice("cat ~/.ssh/config"))
        out = alice("credential-bridge-ctl check 2>&1")
        expect("running, version", out)
        expect("ForwardAgent to the proxy for remote", out)
        expect("ForwardAgent to the proxy for hop", out)
        expect("✓ host keys            2 server(s), each with keys of its own", out)
        # check alone stays on this machine.
        refute("server remote", out)
        out = alice("credential-bridge-ctl check remote 2>&1")
        expect("the daemon recognises remote (profile work)", out)
        refute("server hop", out)
        out = alice("credential-bridge-ctl check --all 2>&1")
        expect("the daemon recognises remote (profile work)", out)
        expect("the daemon recognises hop (profile limited)", out)
        # ctl never connects to the forward socket itself: no unverifiable client of its own.
        refute("cannot open the executable", alice("credential-bridge-ctl log -n 500 --json"))

    with subtest("the server sees the profile's keys; signatures pass unchanged"):
        listed = on("remote", "ssh-add -l")
        for name in ("main", "confirm", "sk"):
            expect(f" {name} (", listed)
        # ssh-agent hides a key restricted to logins to remote from remote itself.
        refute(" dest (", listed)
        expect(" sk (", on("hop", "ssh-add -l"))
        refute(" main (", on("hop", "ssh-add -l"))
        expect("sk", alice("credential-bridge-ctl server keys hop"))
        refute("main", alice("credential-bridge-ctl server keys hop"))
        # git over ssh or a further ssh needs signatures from the forwarded agent.
        on("remote", "ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes hop true")

    with subtest("ed25519-sk signs through the forwarded agent"):
        sign = (
            f"echo {shlex.quote(keys['sk'])} > /tmp/sk.pub && echo hello > /tmp/msg"
            " && rm -f /tmp/msg.sig && ssh-keygen -q -Y sign -f /tmp/sk.pub -n file /tmp/msg"
            f" && echo alice {shlex.quote(keys['sk'])} > /tmp/allowed"
            " && ssh-keygen -Y verify -f /tmp/allowed -I alice -n file -s /tmp/msg.sig < /tmp/msg"
        )
        expect("Good \"file\" signature for alice", on("remote", sign))

    with subtest("ssh-add -c: the upstream agent asks SSH_ASKPASS"):
        client.succeed("rm -f /tmp/askpass.log")
        sign = (
            f"echo {shlex.quote(keys['confirm'])} > /tmp/confirm.pub && echo hello > /tmp/msg"
            " && rm -f /tmp/msg.sig && ssh-keygen -q -Y sign -f /tmp/confirm.pub -n file /tmp/msg && echo signed"
        )
        expect("signed", on("remote", sign))
        expect("confirm", client.succeed("cat /tmp/askpass.log"))
        client.succeed("touch /tmp/askpass-deny")
        refute("signed", on("remote", sign))
        client.succeed("rm /tmp/askpass-deny")

    with subtest("git clone and push over HTTPS with a token from the forge source"):
        expect("password=${token}", on("remote", FILL.format("team/repo.git")))
        on("remote", "rm -rf /tmp/clone && git clone -q https://forge/team/repo.git /tmp/clone")
        out = on(
            "remote",
            "cd /tmp/clone && echo change >> README && git -c user.name=alice -c user.email=alice@client commit -q -am change"
            " && git push -q origin main && echo pushed",
        )
        expect("pushed", out)
        expect("change", forge.succeed("git -c safe.directory='*' -C /srv/git/team/repo.git log --format=%s -1"))
        # The helper source runs in the vault worker.
        on("remote", "rm -rf /tmp/tools && git clone -q https://forge/tools/repo.git /tmp/tools && test -f /tmp/tools/README")

    with subtest("no rule, no token; ctl server token never shows the token"):
        out = on("remote", FILL.format("other/repo.git"))
        refute("password=", out)
        out = alice("credential-bridge-ctl server token remote https://forge/team/repo")
        expect("source    forge", out)
        expect("(redacted)", out)
        refute("${token}", out)

    with subtest("daemon reload refuses an invalid file and keeps the old configuration"):
        alice("cp ~/.config/credential-bridge/config.toml ~/config.good && echo 'garbage [' >> ~/.config/credential-bridge/config.toml")
        out = alice_out("credential-bridge-ctl daemon reload; echo exit=$?")
        expect("did not reload, it keeps the configuration it had", out)
        expect("→ credential-bridge-ctl config check", out)
        expect("exit=1", out)
        expect("password=${token}", on("remote", FILL.format("team/repo.git")))
        alice("mv ~/config.good ~/.config/credential-bridge/config.toml")
        expect("reloaded the configuration", alice("credential-bridge-ctl daemon reload"))

    with subtest("KeePassXC through keepassxc-cli: setup, restart, unlock, a token for git, lock"):
        # A database with the forge token in the entry forge-token (password on stdin;
        # keepassxc-cli asks for a new password once or twice).
        alice("printf 'dbpw\\ndbpw\\n' | keepassxc-cli db-create -q -p -t 100 ~/vault.kdbx")
        alice("printf 'dbpw\\n%s\\n%s\\n' ${token} ${token} | keepassxc-cli add -q -p ~/vault.kdbx forge-token")
        out = alice("credential-bridge-ctl vault setup keepassxc --database ~/vault.kdbx --no-key-file --yes 2>&1")
        expect("[vault.keepassxc] database = ", out)
        expect("after the restart, unlock the database", out)
        # The running daemon still uses no database: reload says so, a restart changes it.
        out = alice("credential-bridge-ctl daemon reload 2>&1")
        expect("uses [vault.keepassxc] database none (configured: /home/alice/vault.kdbx)", out)
        alice("credential-bridge-ctl daemon stop && credential-bridge-ctl daemon start")
        alice("for i in $(seq 100); do credential-bridge-ctl daemon alive && break; sleep 0.2; done")
        alice("credential-bridge-ctl daemon alive")
        refute("uses [vault.keepassxc]", alice("credential-bridge-ctl daemon reload 2>&1"))
        expect("keepassxc unlocked", alice("printf 'dbpw\\n' | credential-bridge-ctl vault unlock keepassxc --password-stdin"))
        out = alice("credential-bridge-ctl source add forgejo kp --host forge --token keepassxc://forge-token/password 2>&1")
        expect("keepassxc://forge-token/password: resolved", out)
        forge.succeed(
            "install -d -o git -g git /srv/git/kp && git clone -q --bare /tmp/seed /srv/git/kp/repo.git"
            " && git -C /srv/git/kp/repo.git config http.receivepack true && chown -R git:git /srv/git/kp"
        )
        alice("credential-bridge-ctl profile rule add work 'https://forge/kp/*' --source kp")
        expect("password=${token}", on("remote", FILL.format("kp/repo.git")))
        out = on(
            "remote",
            "rm -rf /tmp/kp && git clone -q https://forge/kp/repo.git /tmp/kp && cd /tmp/kp && echo kp >> README"
            " && git -c user.name=alice -c user.email=alice@client commit -q -am kp && git push -q origin main && echo pushed",
        )
        expect("pushed", out)
        # A reload keeps the unlock session.
        expect("reloaded the configuration", alice("credential-bridge-ctl daemon reload"))
        expect("password=${token}", on("remote", FILL.format("kp/repo.git")))
        # Locked: the lock also drops the token the git worker cached from the vault, so
        # git gets none, and the reason says how to unlock.
        expect("keepassxc locked", alice("credential-bridge-ctl vault lock keepassxc"))
        out = on("remote", HELPER.format("kp/repo.git"))
        refute("password=", out)
        expect("vault keepassxc is locked: run credential-bridge-ctl vault unlock keepassxc", out)
        out = on("remote", "cd /tmp/kp && GIT_TERMINAL_PROMPT=0 git pull -q && echo pulled || echo failed")
        expect("failed", out)
        refute("pulled", out)
        # Other sources still work.
        expect("password=${token}", on("remote", FILL.format("team/repo.git")))

    with subtest("two sessions in parallel: closing the newer one leaves the older working"):
        alice("rm -f /tmp/older.out; setsid ssh -n remote " + shlex.quote("sleep 8; " + FILL.format("team/repo.git")) + " > /tmp/older.out 2>&1 < /dev/null &")
        client.sleep(2)
        expect("password=${token}", on("remote", FILL.format("team/repo.git")))
        client.wait_until_succeeds("grep -q 'password=${token}' /tmp/older.out", timeout=30)

    with subtest("two people in one account: dave without a bridge falls through"):
        dave_helper = "!f() { test \"$1\" = get || exit 0; cat > /dev/null; echo username=dave; echo password=dave-own; }; f"
        on("remote", "git config --global --add credential.https://forge.helper " + shlex.quote(dave_helper))
        out = dave("ssh -A remote " + shlex.quote(FILL.format("team/repo.git")))
        expect("password=dave-own", out)
        refute("${token}", out)
        out = dave("ssh -A remote " + shlex.quote(".local/bin/credential-bridge-remote query; echo exit=$?"))
        expect("bridge:    no", out)
        expect("exit=1", out)
        # Without any agent the same.
        expect("password=dave-own", dave("ssh -a remote " + shlex.quote(FILL.format("team/repo.git"))))
        # alice still gets her token: our helper comes first.
        expect("password=${token}", on("remote", FILL.format("team/repo.git")))

    with subtest("a hop over a second server: ssh yes, git no (hops default)"):
        def via_hop(cmd):
            return on("remote", "ssh -A -o StrictHostKeyChecking=accept-new -o BatchMode=yes hop " + shlex.quote(cmd))
        listed = via_hop("ssh-add -l")
        expect(" main (", listed)
        out = via_hop(HELPER.format("team/repo.git"))
        refute("password=", out)
        expect("credential-bridge: git from a hop is not allowed (hops.git)", out)
        # hop reached directly has the profile `limited`: no git rules, no token.
        refute("password=", on("hop", HELPER.format("team/repo.git")))

    with subtest("an ssh client before OpenSSH 8.9 (no session-bind): nothing, and no bridge to be seen"):
        def nobind(cmd):
            return alice_out("ssh-nobind remote " + shlex.quote(cmd))
        # Not even public keys.
        expect("The agent has no identities.", nobind("ssh-add -l"))
        # The helper steps aside without a word; the reason stays on alice's machine.
        out = nobind(HELPER.format("team/repo.git"))
        refute("password=", out)
        refute("credential-bridge", out)
        expect("bridge:    no", nobind(".local/bin/credential-bridge-remote query"))
        log = alice("credential-bridge-ctl log -n 200")
        expect("unrecognised host (local ssh client not verified as OpenSSH 8.9 or later)", log)
        expect("the local ssh client is not OpenSSH 8.9 or later, so the server is not recognised", log)
        expect("unrecognised host (local ssh client not verified as OpenSSH 8.9 or later)", alice_out("credential-bridge-ctl check"))

    with subtest("ssh-add -x locks the proxy, -X unlocks it"):
        proxy = "SSH_AUTH_SOCK=~/.local/state/credential-bridge/agent.sock "
        # A session opened before the lock asks for a token while locked.
        remote.succeed("rm -f /tmp/connected /tmp/go")
        waiting = "touch /tmp/connected; until test -e /tmp/go; do sleep 0.2; done; " + HELPER.format("team/repo.git") + "; echo done"
        alice("rm -f /tmp/locked.out; setsid ssh -n remote " + shlex.quote(waiting) + " > /tmp/locked.out 2>&1 < /dev/null &")
        remote.wait_until_succeeds("test -e /tmp/connected", timeout=30)
        alice("printf 'pw\\npw\\n' | " + proxy + "ssh-add -x")
        expect("no identities", alice_out(proxy + "ssh-add -l"))
        expect("locked", alice_out("credential-bridge-ctl check"))
        remote.succeed("touch /tmp/go")
        client.wait_until_succeeds("grep -q done /tmp/locked.out", timeout=30)
        refute("password=", alice("cat /tmp/locked.out"))
        alice("printf 'pw\\n' | " + proxy + "ssh-add -X")
        expect(" main (", alice(proxy + "ssh-add -l"))
        # Unlocked, the token is fetched again.
        expect("password=${token}", on("remote", FILL.format("team/repo.git")))

    with subtest("the audit log names servers and sources, never tokens"):
        log = alice("credential-bridge-ctl log -n 200 --json")
        expect("remote", log)
        expect("forge", log)
        expect("OpenSSH 8.8 sends no session-bind", log)
        refute("${token}", log)

    with subtest("remote rotates its host key (UpdateHostKeys): followed without server add"):
        # 1. remote offers a new key next to the old one; ssh learns it at the next login.
        sshd_key("mv /etc/ssh/ecdsa.next /etc/ssh/ssh_host_ecdsa_key && mv /etc/ssh/ecdsa.next.pub /etc/ssh/ssh_host_ecdsa_key.pub")
        remote_ecdsa = remote.succeed("ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub | cut -d' ' -f2").strip()
        # ssh must still be connected when the server proves the new key.
        client.wait_until_succeeds(
            "su - alice -c 'ssh remote sleep 1 > /dev/null 2>&1; ssh-keygen -F remote' | grep -q ecdsa-sha2-nistp256",
            timeout=60,
        )
        # 2. remote retires the old key; ssh logs in with the new one, and the daemon reads
        # the changed known_hosts again before it looks up the new key: no reload, no
        # server add.
        sshd_key("echo retired > /etc/ssh/ssh_host_ed25519_key && rm /etc/ssh/ssh_host_ed25519_key.pub")
        listed = on("remote", "ssh-add -l")
        expect(" main (", listed)
        expect("password=${token}", on("remote", FILL.format("team/repo.git")))
        events = [json.loads(line) for line in alice("credential-bridge-ctl log -n 500 --json").splitlines()]
        servers = [e for e in events if e.get("event") == "server" and e.get("host_key") == remote_ecdsa]
        assert servers, f"no server event for {remote_ecdsa}"
        assert all(e.get("server") == "remote" and e.get("source") == "known_hosts" for e in servers), servers
        out = alice("credential-bridge-ctl check remote 2>&1")
        expect("the daemon recognises remote (profile work)", out)

    with subtest("an unregistered host gets nothing and sees no bridge"):
        # Without its [server.hop] entry, hop is recognised by its host key but not
        # registered: the built-in profile.unregistered.
        alice("credential-bridge-ctl server remove hop")
        refute("[server.hop]", alice("cat ~/.config/credential-bridge/config.toml"))
        expect("The agent has no identities.", on("hop", "ssh-add -l"))
        out = on("hop", HELPER.format("team/repo.git"))
        refute("password=", out)
        refute("credential-bridge", out)
        out = on("hop", ".local/bin/credential-bridge-remote query; echo exit=$?")
        expect("bridge:    no", out)
        expect("exit=1", out)
        hop_key = hop.succeed("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | cut -d' ' -f2").strip()
        log = alice("credential-bridge-ctl log -n 200")
        expect(f"unregistered host {hop_key}", log)
        expect("the host is not registered (no [server.*] entry for its host key)", log)
        # ctl check lists it with the hint to register it.
        out = alice_out("credential-bridge-ctl check")
        expect(f"unregistered host {hop_key}", out)
        expect("credential-bridge-ctl server add NAME --profile PROFILE", out)
        expect("no keys, no tokens, no gpg", out)
        # A registered server still gets the reason (see the hop subtest above).
        expect("credential-bridge: git from a hop is not allowed (hops.git)", on("remote", "ssh -A -o BatchMode=yes hop " + shlex.quote(HELPER.format("team/repo.git"))))
        out = alice("credential-bridge-ctl server add hop --profile limited 2>&1")
        expect("✓ known_hosts          hop: ssh-ed25519", out)
        expect("✓ probe                the daemon recognises hop (profile limited)", out)

    with subtest("server remove --remote cleans up the server"):
        alice("credential-bridge-ctl server remove hop --remote")
        refute("[server.hop]", alice("cat ~/.config/credential-bridge/config.toml"))
        expect("gone", on("hop", "test -e .local/bin/credential-bridge-remote || echo gone"))

    with subtest("daemon uninstall"):
        alice("credential-bridge-ctl daemon uninstall")
        alice("credential-bridge-ctl daemon alive", ok=False)
  '';
}
