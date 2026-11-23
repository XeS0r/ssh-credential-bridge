# The software FIDO provider from the OpenSSH test suite (regress/misc/sk-dummy).
#
# It answers like a security key without hardware: `ssh-keygen -t ed25519-sk -w
# <lib>/sk-dummy.so` creates a key, and ssh-agent signs with it when the provider is
# allowed with `ssh-agent -P`. Built from the same source as `openssh`, so its API
# version matches the ssh-sk-helper that loads it.
{ openssh }:
openssh.overrideAttrs (old: {
  pname = "openssh-sk-dummy";
  outputs = [ "out" ];
  buildPhase = ''
    runHook preBuild
    make regress-prep openbsd-compat/libopenbsd-compat.a
    make regress/misc/sk-dummy/sk-dummy.so
    runHook postBuild
  '';
  doCheck = false;
  doInstallCheck = false;
  installPhase = ''
    runHook preInstall
    install -Dm755 regress/misc/sk-dummy/sk-dummy.so $out/lib/sk-dummy.so
    runHook postInstall
  '';
  postInstall = "";
  meta = old.meta // {
    description = "Software FIDO provider from the OpenSSH regression tests";
  };
})
