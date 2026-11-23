# An ssh client that behaves like OpenSSH 8.2 to 8.8: it sends no
# `session-bind@openssh.com` and calls itself OpenSSH 8.8.
#
# Built from the same source as `openssh`, with `ssh_agent_bind_hostkey` turned into a
# no-op that fails, so neither login binds nor forwarding binds reach the agent, and with
# the release string of 8.8, which the daemon reads from the client's executable. The
# e2e test uses it as `ssh-nobind` to check that such clients get nothing (no keys, no
# tokens, no gpg) and do not see the bridge.
{ openssh }:
openssh.overrideAttrs (old: {
  pname = "openssh-nobind";
  outputs = [ "out" ];
  postPatch = (old.postPatch or "") + ''
    substituteInPlace authfd.c --replace-fail \
      'if (key == NULL || session_id == NULL || signature == NULL)' \
      'if (1) /* like OpenSSH before 8.9: no session-bind */'
    sed -i 's/^#define SSH_VERSION.*/#define SSH_VERSION "OpenSSH_8.8"/' version.h
    grep -q '^#define SSH_VERSION "OpenSSH_8.8"$' version.h
  '';
  buildPhase = ''
    runHook preBuild
    make ssh
    runHook postBuild
  '';
  doCheck = false;
  doInstallCheck = false;
  installPhase = ''
    runHook preInstall
    install -Dm755 ssh $out/bin/ssh-nobind
    runHook postInstall
  '';
  postInstall = "";
  meta = old.meta // {
    description = "OpenSSH client without session-bind that calls itself 8.8 (like OpenSSH before 8.9)";
  };
})
