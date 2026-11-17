{
  description = "credential-bridge: forward local git credentials to SSH remotes";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      crane,
      rust-overlay,
    }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ] (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        inherit (pkgs) lib;

        # Static helpers for the remotes, keyed by `<uname -m>-<os>` as
        # `credential-bridge-ctl remote install` detects it. The musl targets are
        # pure Rust and linked with the bundled rust-lld, without a C toolchain.
        # Rust ships no musl std for s390x, so that one links glibc statically
        # with the cross gcc from nixpkgs (prebuilt in the binary cache).
        s390x = pkgs.pkgsCross.s390x;
        helperTargets = {
          "x86_64-linux".target = "x86_64-unknown-linux-musl";
          "aarch64-linux".target = "aarch64-unknown-linux-musl";
        }
        // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          "s390x-linux" = {
            target = "s390x-unknown-linux-gnu";
            linker = "${s390x.stdenv.cc}/bin/${s390x.stdenv.cc.targetPrefix}cc";
            # static-pie needs glibc's rcrt1.o and crashes at startup; plain static works.
            rustflags = "-C relocation-model=static -C link-arg=-L${s390x.glibc.static}/lib";
          };
        };

        toolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
          ];
          # The macOS target is only type-checked (`checks.macos`), never linked.
          targets = lib.mapAttrsToList (_: helper: helper.target) helperTargets ++ [ "aarch64-apple-darwin" ];
        };
        craneLib = (crane.mkLib pkgs).overrideToolchain (_: toolchain);

        src = craneLib.cleanCargoSource ./.;
        commonArgs = {
          inherit src;
          strictDeps = true;
          pname = "credential-bridge";
          version = (lib.importTOML ./Cargo.toml).workspace.package.version;
        };
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # All three binaries for this machine, with man pages and completions.
        credential-bridge = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
            doCheck = false; # tests run in checks.tests
            nativeBuildInputs = [ pkgs.installShellFiles ];
            postInstall = ''
              mkdir -p man
              for bin in credential-bridged credential-bridge-ctl git-credential-bridge; do
                $out/bin/$bin generate-man man
              done
              installManPage man/*
              installShellCompletion --cmd credential-bridge-ctl \
                --bash <($out/bin/credential-bridge-ctl completions bash) \
                --zsh <($out/bin/credential-bridge-ctl completions zsh) \
                --fish <($out/bin/credential-bridge-ctl completions fish)
            '';
            meta = {
              mainProgram = "credential-bridge-ctl";
              license = lib.licenses.mit;
            };
          }
        );

        mkStaticHelper =
          platform:
          {
            target,
            linker ? "rust-lld",
            rustflags ? "",
          }:
          let
            envTarget = lib.toUpper (builtins.replaceStrings [ "-" ] [ "_" ] target);
          in
          craneLib.buildPackage (
            commonArgs
            // {
              pname = "git-credential-bridge-${platform}";
              cargoExtraArgs = "--locked -p git-credential-bridge";
              CARGO_BUILD_TARGET = target;
              "CARGO_TARGET_${envTarget}_LINKER" = linker;
              "CARGO_TARGET_${envTarget}_RUSTFLAGS" = "-C target-feature=+crt-static ${rustflags}";
              doCheck = false;
            }
          );

        staticHelpers = lib.mapAttrs' (
          platform: helper:
          lib.nameValuePair "git-credential-bridge-${platform}" (mkStaticHelper platform helper)
        ) helperTargets;

        # Release packages for installing without Nix: all three programs
        # statically linked (musl), every server helper, man pages,
        # completions and install.sh. Built on Linux for Linux machines.
        releasePlatforms = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          "x86_64-linux" = "x86_64-unknown-linux-musl";
          "aarch64-linux" = "aarch64-unknown-linux-musl";
        };
        mkStaticTools =
          platform: target:
          let
            envTarget = lib.toUpper (builtins.replaceStrings [ "-" ] [ "_" ] target);
          in
          craneLib.buildPackage (
            commonArgs
            // {
              pname = "credential-bridge-static-${platform}";
              cargoExtraArgs = "--locked";
              CARGO_BUILD_TARGET = target;
              "CARGO_TARGET_${envTarget}_LINKER" = "rust-lld";
              "CARGO_TARGET_${envTarget}_RUSTFLAGS" = "-C target-feature=+crt-static";
              doCheck = false;
            }
          );
        mkRelease =
          platform: target:
          let
            tools = mkStaticTools platform target;
            name = "credential-bridge-${commonArgs.version}-${platform}";
          in
          pkgs.runCommand name { } ''
            mkdir -p ${name}/bin ${name}/share/credential-bridge/helpers
            cp ${tools}/bin/credential-bridge-ctl ${tools}/bin/credential-bridged ${tools}/bin/git-credential-bridge ${name}/bin/
            cp -r ${credential-bridge}/share/man ${credential-bridge}/share/bash-completion \
              ${credential-bridge}/share/fish ${credential-bridge}/share/zsh ${name}/share/
            cp -L ${helperDir}/share/credential-bridge/helpers/* ${name}/share/credential-bridge/helpers/
            install -m 755 ${./packaging/install.sh} ${name}/install.sh
            cp ${./LICENSE} ${name}/LICENSE
            cp ${./README.md} ${name}/README.md
            chmod -R u+w,go-w ${name}
            mkdir -p $out
            tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@1 -czf $out/${name}.tar.gz ${name}
          '';
        releases = lib.mapAttrs mkRelease releasePlatforms;
        release = pkgs.runCommand "credential-bridge-${commonArgs.version}-release" { } ''
          mkdir -p $out
          ${lib.concatMapStrings (r: "cp ${r}/*.tar.gz $out/\n") (builtins.attrValues releases)}
          cd $out && sha256sum *.tar.gz > SHA256SUMS
        '';

        # Directory layout expected by `credential-bridge-ctl remote install`.
        helperDir = pkgs.runCommand "credential-bridge-helpers" { } (
          ''
            mkdir -p $out/share/credential-bridge/helpers
          ''
          + lib.concatStrings (
            lib.mapAttrsToList (name: drv: ''
              ln -s ${drv}/bin/git-credential-bridge $out/share/credential-bridge/helpers/${name}
            '') staticHelpers
          )
        );

        # Local tools plus the static helpers for the remotes.
        bundle = pkgs.symlinkJoin {
          name = "credential-bridge-${commonArgs.version}";
          paths = [
            credential-bridge
            helperDir
          ];
          nativeBuildInputs = [ pkgs.makeWrapper ];
          postBuild = ''
            wrapProgram $out/bin/credential-bridge-ctl \
              --set-default CREDENTIAL_BRIDGE_HELPER_DIR $out/share/credential-bridge/helpers
          '';
          meta = {
            mainProgram = "credential-bridge-ctl";
            license = lib.licenses.mit;
          };
        };

        # `nix run .#install` / `.#uninstall`: links the bundle into ~/.local via a GC root.
        mkInstaller =
          action:
          pkgs.writeShellApplication {
            name = "credential-bridge-${action}";
            text = ''
              action=${action}
              package=${bundle}
            ''
            + builtins.readFile ./nix/install.sh;
          };

        # Throwaway NixOS guest for manual tests (`nix run .#vm`); Linux hosts only.
        testbox = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          vm =
            (nixpkgs.lib.nixosSystem {
              inherit system;
              modules = [ ./nix/testbox.nix ];
            }).config.system.build.vm;
        };
      in
      {
        packages = {
          default = bundle;
          inherit credential-bridge;
          helpers = helperDir;
        }
        // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux { inherit release; }
        // staticHelpers
        // testbox;

        apps = {
          default = flake-utils.lib.mkApp {
            drv = bundle;
            name = "credential-bridge-ctl";
          };
          credential-bridged = flake-utils.lib.mkApp {
            drv = bundle;
            name = "credential-bridged";
          };
          install = flake-utils.lib.mkApp { drv = mkInstaller "install"; };
          uninstall = flake-utils.lib.mkApp { drv = mkInstaller "uninstall"; };
        }
        // lib.optionalAttrs (testbox ? vm) {
          vm = flake-utils.lib.mkApp {
            drv = testbox.vm;
            name = "run-testbox-vm";
          };
        };

        checks = {
          inherit credential-bridge;
          clippy = craneLib.cargoClippy (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            }
          );
          fmt = craneLib.cargoFmt commonArgs;
          tests = craneLib.cargoNextest (
            commonArgs
            // {
              inherit cargoArtifacts;
            }
          );
        }
        // staticHelpers
        # macOS code paths (launchd) are cfg'd out on Linux; type-check and
        # lint them for aarch64-apple-darwin without a Mac.
        // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          macos = craneLib.mkCargoDerivation (
            commonArgs
            // {
              pname = "credential-bridge-macos-check";
              cargoArtifacts = null;
              doInstallCargoArtifacts = false;
              buildPhaseCargoCommand = "cargo clippy --locked --target aarch64-apple-darwin --workspace --all-targets -- --deny warnings";
              installPhaseCommand = "touch $out";
            }
          );
        }
        # Two VMs, real ssh and git: needs KVM, so Linux only (`just e2e`).
        // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          markdown =
            pkgs.runCommand "credential-bridge-markdown"
              {
                src = lib.fileset.toSource {
                  root = ./.;
                  fileset = lib.fileset.unions [
                    (lib.fileset.fileFilter (file: file.hasExt "md") ./.)
                    ./.prettierrc.yaml
                    ./.markdownlint-cli2.yaml
                  ];
                };
                nativeBuildInputs = [
                  pkgs.prettier
                  pkgs.markdownlint-cli2
                ];
              }
              ''
                cd $src
                prettier --check '**/*.md'
                markdownlint-cli2
                touch $out
              '';
          # The release workflow takes its notes from CHANGELOG.md; a version
          # bump without a changelog section fails here, not at release time.
          changelog = pkgs.runCommand "credential-bridge-changelog" { } ''
            sh ${./packaging/release-notes.sh} ${commonArgs.version} ${./CHANGELOG.md} > /dev/null
            touch $out
          '';
          release = import ./nix/release-test.nix {
            inherit pkgs;
            tarball = releases.${system};
          };
          helpers = import ./nix/helpers-test.nix {
            inherit pkgs;
            package = bundle;
          };
          e2e = import ./nix/e2e.nix {
            inherit pkgs;
            package = bundle;
            release = releases.${system};
          };
        };

        formatter = pkgs.nixfmt;

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};
          packages = [
            pkgs.cargo-nextest
            pkgs.just
            pkgs.markdownlint-cli2
            pkgs.nixfmt
            pkgs.prettier
          ];
        };
      }
    );
}
