# List the recipes.
default:
    @just --list

# Build and link the tools into ~/.local (bin, man pages, completions); updates a running service.
install:
    nix run .#install

# Remove the links, the GC root and the service; the configuration is kept.
uninstall:
    nix run .#uninstall

# Build the bundle: tools + static helpers for the remotes.
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

# Everything: build, unit and integration tests, clippy, rustfmt, static helpers, end-to-end test.
check:
    nix flake check -L

# Unit and integration tests (fast, no VMs).
test:
    cargo nextest run --workspace

# End-to-end test: two VMs with real ssh and git run every feature (needs KVM).
e2e:
    nix build -L --no-link .#checks.$(nix eval --raw --impure --expr builtins.currentSystem).e2e

# Open a Python shell in the end-to-end test to poke around (`start_all()`, `client.succeed(...)`).
e2e-interactive:
    nix run .#checks.$(nix eval --raw --impure --expr builtins.currentSystem).e2e.driverInteractive

# Start the throwaway test guest (sshd on 127.0.0.1:2222, user/password test); quit with Ctrl-A X.
vm:
    nix run .#vm
