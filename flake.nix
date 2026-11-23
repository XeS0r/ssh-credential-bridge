{
  description = "credential-bridge: ssh-agent proxy that brings ssh keys, git tokens and gpg to your servers";

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
        isLinux = pkgs.stdenv.hostPlatform.isLinux;

        # Turns a target triple into the suffix of cargo's per-target variables.
        envTarget = target: lib.toUpper (builtins.replaceStrings [ "-" ] [ "_" ] target);
        ccTarget = target: builtins.replaceStrings [ "-" ] [ "_" ] target;

        # Static `credential-bridge-remote` for the servers, keyed by the target triple
        # `credential-bridge-ctl server add` looks for. It has no C dependencies, so the
        # musl targets link with the bundled rust-lld. Rust ships no musl std for s390x;
        # that one links glibc statically with the cross gcc from nixpkgs.
        s390x = pkgs.pkgsCross.s390x;
        remoteTargets = {
          "x86_64-unknown-linux-musl" = { };
          "aarch64-unknown-linux-musl" = { };
        }
        // lib.optionalAttrs isLinux {
          "s390x-unknown-linux-gnu" = {
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
          targets = builtins.attrNames remoteTargets ++ [ "aarch64-apple-darwin" ];
        };
        craneLib = (crane.mkLib pkgs).overrideToolchain (_: toolchain);

        src = craneLib.cleanCargoSource ./.;
        version = (lib.importTOML ./Cargo.toml).workspace.package.version;
        commonArgs = {
          inherit src version;
          strictDeps = true;
          pname = "credential-bridge";
          buildInputs = lib.optionals pkgs.stdenv.hostPlatform.isDarwin [ pkgs.libiconv ];
        };
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # The local programs, credential-bridged and credential-bridge-ctl, with man
        # pages and completions.
        credential-bridge = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
            cargoExtraArgs = "--locked -p credential-bridged -p credential-bridge-ctl";
            doCheck = false; # tests run in checks.tests
            nativeBuildInputs = [ pkgs.installShellFiles ];
            postInstall = ''
              $out/bin/credential-bridged generate-man man
              $out/bin/credential-bridge-ctl generate-man man
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

        mkRemote =
          target:
          {
            linker ? "rust-lld",
            rustflags ? "",
          }:
          craneLib.buildPackage (
            commonArgs
            // {
              pname = "credential-bridge-remote-${target}";
              cargoExtraArgs = "--locked -p credential-bridge-remote";
              CARGO_BUILD_TARGET = target;
              "CARGO_TARGET_${envTarget target}_LINKER" = linker;
              "CARGO_TARGET_${envTarget target}_RUSTFLAGS" = "-C target-feature=+crt-static ${rustflags}";
              doCheck = false;
            }
          );
        remotes = lib.mapAttrs' (
          target: args: lib.nameValuePair "credential-bridge-remote-${target}" (mkRemote target args)
        ) remoteTargets;

        # Directory layout `credential-bridge-ctl server add` searches
        # (`$CREDENTIAL_BRIDGE_HELPER_DIR` or `<prefix>/share/credential-bridge/helpers`).
        helperDir = pkgs.runCommand "credential-bridge-remotes" { } (
          ''
            mkdir -p $out/share/credential-bridge/helpers
          ''
          + lib.concatStrings (
            lib.mapAttrsToList (name: drv: ''
              ln -s ${drv}/bin/credential-bridge-remote $out/share/credential-bridge/helpers/${name}
            '') remotes
          )
        );

        # Local programs plus the static remote binaries.
        bundle = pkgs.symlinkJoin {
          name = "credential-bridge-${version}";
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

        # Release packages for installing without Nix: both local programs statically
        # linked (musl), every remote binary, man pages, completions and install.sh.
        # Built on Linux for Linux machines. The HTTP client's TLS library (aws-lc) is
        # C, so these need the musl cross compilers from nixpkgs.
        releaseTargets = lib.optionalAttrs isLinux {
          "x86_64-linux" = {
            target = "x86_64-unknown-linux-musl";
            cc = pkgs.pkgsCross.musl64.stdenv.cc;
          };
          "aarch64-linux" = {
            target = "aarch64-unknown-linux-musl";
            cc = pkgs.pkgsCross.aarch64-multiplatform-musl.stdenv.cc;
          };
        };
        mkStaticTools =
          platform:
          { target, cc }:
          let
            prefix = cc.targetPrefix;
          in
          craneLib.buildPackage (
            commonArgs
            // {
              pname = "credential-bridge-static-${platform}";
              cargoExtraArgs = "--locked -p credential-bridged -p credential-bridge-ctl";
              CARGO_BUILD_TARGET = target;
              "CC_${ccTarget target}" = "${cc}/bin/${prefix}cc";
              "AR_${ccTarget target}" = "${cc.bintools}/bin/${prefix}ar";
              "CARGO_TARGET_${envTarget target}_LINKER" = "${cc}/bin/${prefix}cc";
              "CARGO_TARGET_${envTarget target}_RUSTFLAGS" = "-C target-feature=+crt-static";
              doCheck = false;
            }
          );
        mkRelease =
          platform: args:
          let
            tools = mkStaticTools platform args;
            name = "credential-bridge-${version}-${platform}";
          in
          pkgs.runCommand name { } ''
            mkdir -p ${name}/bin ${name}/share/credential-bridge/helpers
            cp ${tools}/bin/credential-bridge-ctl ${tools}/bin/credential-bridged ${name}/bin/
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
        releases = lib.mapAttrs mkRelease releaseTargets;
        release = pkgs.runCommand "credential-bridge-${version}-release" { } ''
          mkdir -p $out
          ${lib.concatMapStrings (r: "cp ${r}/*.tar.gz $out/\n") (builtins.attrValues releases)}
          cd $out && sha256sum *.tar.gz > SHA256SUMS
        '';

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

        # Fuzzing (fuzz/): a nightly toolchain and cargo-fuzz, for CI and by hand. Not
        # part of the dev shell.
        fuzzToolchain = pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.minimal);
        fuzzCraneLib = (crane.mkLib pkgs).overrideToolchain (_: fuzzToolchain);
        fuzzTargets = [
          "agent_frame"
          "session_bind"
          "extension_payload"
          "git_credential"
          "ipc_frame"
          "assuan_filter"
        ];
        # Builds every fuzz target with coverage instrumentation and runs each for
        # `seconds`. Offline, with the dependencies of fuzz/Cargo.lock vendored.
        mkFuzz =
          seconds:
          fuzzCraneLib.mkCargoDerivation {
            pname = "credential-bridge-fuzz";
            inherit version;
            src = lib.fileset.toSource {
              root = ./.;
              fileset = lib.fileset.unions [
                ./Cargo.toml
                ./crates
                ./fuzz/Cargo.toml
                ./fuzz/Cargo.lock
                ./fuzz/fuzz_targets
              ];
            };
            cargoArtifacts = null;
            doInstallCargoArtifacts = false;
            cargoVendorDir = fuzzCraneLib.vendorCargoDeps { cargoLock = ./fuzz/Cargo.lock; };
            nativeBuildInputs = [ pkgs.cargo-fuzz ];
            buildPhaseCargoCommand = ''
              cd fuzz
              cargo fuzz build --release
              for target in ${lib.concatStringsSep " " fuzzTargets}; do
                echo "== $target"
                mkdir -p corpus/$target
                cargo fuzz run --release $target corpus/$target -- -max_total_time=${toString seconds}
              done
            '';
            installPhaseCommand = "touch $out";
          };
        fuzz = pkgs.writeShellApplication {
          name = "credential-bridge-fuzz";
          runtimeInputs = [
            fuzzToolchain
            pkgs.cargo-fuzz
            pkgs.stdenv.cc
          ];
          text = ''
            # Usage, from the repository root:
            #   nix run .#fuzz -- [SECONDS] [TARGET...]   run each target (all by default)
            #                                             for SECONDS (default 60); fails
            #                                             at the end if any target crashed
            #   nix run .#fuzz -- reproduce TARGET FILE   run TARGET once on FILE
            if [ "''${1:-}" = reproduce ]; then
              [ $# -eq 3 ] || { echo "usage: reproduce TARGET FILE" >&2; exit 2; }
              file=$(realpath -- "$3")
              cd fuzz
              exec cargo fuzz run --release "$2" "$file"
            fi
            seconds=''${1:-60}
            case "$seconds" in
              ""|*[!0-9]*) echo "SECONDS must be a whole number, not '$seconds'" >&2; exit 2 ;;
            esac
            shift || true
            targets=("$@")
            [ ''${#targets[@]} -gt 0 ] || targets=(${lib.concatStringsSep " " fuzzTargets})
            cd fuzz
            failed=()
            for target in "''${targets[@]}"; do
              echo "== $target ($seconds s)"
              mkdir -p "corpus/$target"
              if ! cargo fuzz run --release "$target" "corpus/$target" -- -max_total_time="$seconds"; then
                failed+=("$target")
              fi
            done
            if [ ''${#failed[@]} -gt 0 ]; then
              echo "failed: ''${failed[*]} (crash inputs in fuzz/artifacts/)" >&2
              exit 1
            fi
            echo "all targets ran without a crash"
          '';
        };

        # Link check of the Markdown files with lychee.toml, from the repository root:
        #   nix run .#links                 everything, with network
        #   nix run .#links -- --offline    only local files and anchors (checks.links)
        # Further arguments go to lychee. Links to this repository's main branch are
        # checked against the working tree, so they may point to what a change adds.
        links = pkgs.writeShellApplication {
          name = "credential-bridge-links";
          runtimeInputs = [ pkgs.lychee ];
          text = ''
            if [ ! -f lychee.toml ]; then
              echo "run this from the repository root (no lychee.toml here)" >&2
              exit 2
            fi
            exec lychee --config lychee.toml \
              --remap "^https://github\.com/XeS0r/ssh-credential-bridge/blob/main/(.*)\$ file://$PWD/\$1" \
              "$@" '**/*.md'
          '';
        };

        # Throwaway NixOS guest for manual tests (`nix run .#vm`); Linux hosts only.
        testbox = lib.optionalAttrs isLinux {
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
          remotes = helperDir;
        }
        // lib.optionalAttrs isLinux { inherit release; }
        // remotes
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
          fuzz = flake-utils.lib.mkApp { drv = fuzz; };
          links = flake-utils.lib.mkApp { drv = links; };
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
              cargoClippyExtraArgs = "--workspace --all-targets -- --deny warnings";
            }
          );
          fmt = craneLib.cargoFmt commonArgs;
          tests = craneLib.cargoNextest (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoNextestExtraArgs = "--workspace";
              # The daemon's OpenSSH test drives the real ssh-agent and ssh-add; the
              # remote's setup tests drive git.
              nativeCheckInputs = [
                pkgs.git
                pkgs.openssh
              ];
              # The forge tests build the HTTP client, which loads the system CAs.
              SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
            }
          );
        }
        // remotes
        # macOS code paths are cfg'd out on Linux; type-check and lint them for
        # aarch64-apple-darwin without a Mac. The daemon, ctl and forge need the C
        # library aws-lc (TLS), which cannot be compiled for macOS without Apple's SDK,
        # so only the crates without it are checked.
        // lib.optionalAttrs isLinux {
          macos = craneLib.mkCargoDerivation (
            commonArgs
            // {
              pname = "credential-bridge-macos-check";
              cargoArtifacts = null;
              doInstallCargoArtifacts = false;
              buildPhaseCargoCommand = ''
                cargo clippy --locked --target aarch64-apple-darwin --all-targets --all-features \
                  -p credential-bridge-platform -p credential-bridge-config -p credential-bridge-proto \
                  -p credential-bridge-vault -p credential-bridge-gpg -p credential-bridge-remote \
                  -- --deny warnings
              '';
              installPhaseCommand = "touch $out";
            }
          );
        }
        // lib.optionalAttrs isLinux {
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
          # release-notes-test.sh also tests the script on a fixture and rejects
          # relative links in the notes (dead on the release page).
          changelog =
            pkgs.runCommand "credential-bridge-changelog"
              {
                src = lib.fileset.toSource {
                  root = ./.;
                  fileset = lib.fileset.unions [
                    ./CHANGELOG.md
                    ./packaging/release-notes.sh
                    ./packaging/release-notes-test.sh
                  ];
                };
              }
              ''
                cd $src
                sh packaging/release-notes.sh ${version} CHANGELOG.md > /dev/null
                sh packaging/release-notes-test.sh ${version} CHANGELOG.md
                touch $out
              '';
          # Local links and anchors only: `--offline` blocks every network request,
          # so this is deterministic (the links workflow checks the rest).
          links =
            pkgs.runCommand "credential-bridge-links"
              {
                src = lib.fileset.toSource {
                  root = ./.;
                  fileset = lib.fileset.unions [
                    (lib.fileset.fileFilter (file: file.hasExt "md") ./.)
                    ./lychee.toml
                    # Every other file the Markdown links to.
                    ./LICENSE
                  ];
                };
              }
              ''
                cd $src
                # lychee builds its HTTP client even offline, and that wants CAs.
                HOME=$TMPDIR SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt \
                  ${lib.getExe links} --offline
                touch $out
              '';
          # A short run of every fuzz target (the scheduled CI job runs longer).
          fuzz = mkFuzz 20;
          release = import ./nix/release-test.nix {
            inherit pkgs;
            tarball = releases.${system};
          };
          remotes = import ./nix/remotes-test.nix {
            inherit pkgs;
            package = bundle;
          };
          # Several VMs, real ssh and git: needs KVM (`just e2e`).
          e2e = import ./nix/e2e.nix {
            inherit pkgs;
            package = bundle;
            skDummy = pkgs.callPackage ./nix/sk-dummy.nix { };
            sshNobind = pkgs.callPackage ./nix/ssh-nobind.nix { };
          };
        };

        formatter = pkgs.nixfmt;

        devShells.default = craneLib.devShell {
          # Not `fuzz` (nightly toolchain) and not `tests` (its check inputs): the dev
          # shell stays what it was.
          checks = removeAttrs self.checks.${system} [
            "fuzz"
            "tests"
          ];
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
