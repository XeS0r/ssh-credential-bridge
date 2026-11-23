# List the recipes.
default:
    @just --list

# Build and link the tools into ~/.local (bin, man pages, completions); updates a running service.
install:
    nix run .#install

# Remove the links, the GC root and the service; the configuration is kept.
uninstall:
    nix run .#uninstall

# Build the bundle: credential-bridged, credential-bridge-ctl and the static remote binaries.
build:
    nix build

# Build the release packages for installing without Nix (into ./result).
release:
    nix build .#release

# Format Rust, Nix and Markdown.
fmt:
    cargo fmt --all
    nix fmt -- flake.nix nix/*.nix
    prettier --write '**/*.md'

# Lint Rust and Markdown.
lint:
    cargo clippy --workspace --all-targets -- --deny warnings
    prettier --check '**/*.md'
    markdownlint-cli2

# Everything: build, tests, clippy (Linux + macOS), rustfmt, Markdown, local links, remote binaries, fuzz smoke run, VM test.
check: kvm-check
    nix flake check -L

# Unit and integration tests (fast, no VMs).
test:
    cargo nextest run --workspace

# End-to-end test: four VMs with real ssh agent forwarding and git over HTTPS (needs KVM).
e2e: kvm-check
    nix build -L --no-link .#checks.$(nix eval --raw --impure --expr builtins.currentSystem).e2e

# Warns if Nix builds cannot use /dev/kvm. They do not get the kvm group, so only the
# mode counts (README.md, Development); a remote builder may still have KVM.
[private]
kvm-check:
    #!/bin/sh
    [ -e /dev/kvm ] || exit 0
    mode=$(stat -c %a /dev/kvm 2>/dev/null) || exit 0
    case $mode in
      *[67]) ;;
      *) cat >&2 <<EOF
    warning: /dev/kvm has mode $mode, not readable and writable for everyone: Nix builds
    cannot use it, and the VMs fall back to slow emulation. To fix it, create
    /etc/udev/rules.d/99-kvm.rules with
      KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"
    then run
      sudo udevadm control --reload-rules && sudo udevadm trigger --name-match=kvm
    EOF
      ;;
    esac

# Open a Python shell in the end-to-end test to poke around (`start_all()`, `client.succeed(...)`).
e2e-interactive:
    nix run .#checks.$(nix eval --raw --impure --expr builtins.currentSystem).e2e.driverInteractive

# Check the links in every Markdown file with lychee (pass --offline for local links only).
links *args:
    nix run .#links -- {{args}}

# Run the fuzz targets (all if none are named) for SECONDS each; fails if any crashed.
fuzz seconds="60" *targets:
    nix run .#fuzz -- {{seconds}} {{targets}}

# Start the throwaway test guest (sshd on 127.0.0.1:2222, user/password test); quit with Ctrl-A X.
vm:
    nix run .#vm
