# Throwaway NixOS guest for trying credential-bridge by hand: `just vm` / `nix run .#vm`.
#
# sshd on 127.0.0.1:2222, user `test` with password `test`. The root file system is a
# tmpfs, so every start begins from scratch (new host key, no remote binary, no git
# config): `credential-bridge-ctl server add` follows its known_hosts entry, so a new
# host key on each boot only needs accepting in known_hosts (`ssh-keygen -R`, then ssh
# again), and `server add` again installs the remote binary. The console runs in the
# terminal; quit with Ctrl-A X or `sudo poweroff`.
{
  lib,
  pkgs,
  modulesPath,
  ...
}:
{
  imports = [ "${modulesPath}/virtualisation/qemu-vm.nix" ];

  networking.hostName = "testbox";
  system.stateVersion = lib.trivial.release;

  virtualisation = {
    graphics = false;
    memorySize = 1024;
    diskImage = null;
    forwardPorts = [
      {
        from = "host";
        host.address = "127.0.0.1";
        host.port = 2222;
        guest.port = 22;
      }
    ];
  };

  services.openssh = {
    enable = true;
    settings.PasswordAuthentication = true;
  };

  users.users.test = {
    isNormalUser = true;
    password = "test";
    extraGroups = [ "wheel" ];
  };
  security.sudo.wheelNeedsPassword = false;
  services.getty.autologinUser = "test";

  environment.systemPackages = [
    pkgs.git
    pkgs.gnupg
  ];
}
