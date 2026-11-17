//! Wire formats shared by the credential-bridge tools.
//!
//! * [`Credential`] implements git's credential helper format (`key=value` lines).
//! * [`Request`] and [`Response`] frame a credential for the trip between
//!   `git-credential-bridge` (remote) and `credential-bridged` (local).
//! * [`client::exchange`] performs one request/response round trip over a unix socket.
//!
//! Frame layout (all lines end with `\n`):
//!
//! ```text
//! request:   credential-bridge/1 <get|store|erase|ping>
//!            <key>=<value>          (zero or more)
//!            <empty line>
//!
//! response:  credential-bridge/1 <ok|denied|error>[ <message>]
//!            <key>=<value>          (zero or more)
//!            <empty line>
//! ```

#[cfg(unix)]
pub mod client;
mod credential;
mod frame;
mod pattern;
mod shell;

pub use credential::{Credential, MAX_CREDENTIAL_BYTES, ParseError, Redacted, UrlError, is_secret};
pub use frame::{FrameError, MAX_MESSAGE_BYTES, Operation, PROTOCOL, Request, Response, Status};
pub use pattern::{MAX_PATH_BYTES, PatternError, UrlPattern, git_sections};
pub use shell::{HELPER_BINARY, REMOTE_HELPER_RELATIVE, REMOTE_SOCKET_RELATIVE, sh_quote};

/// Separates a response message from the step that fixes it: `problem → fix`.
pub const FIX_SEPARATOR: &str = " → ";

/// Joins a problem and its fix with [`FIX_SEPARATOR`], within
/// [`MAX_MESSAGE_BYTES`]: a long problem is shortened so the fix stays whole,
/// and a fix that cannot fit is left out rather than cut mid-command.
pub fn with_fix(problem: &str, fix: &str) -> String {
    const ELLIPSIS: &str = "…";
    const MIN_PROBLEM: usize = 40;
    let full = format!("{problem}{FIX_SEPARATOR}{fix}");
    if full.len() <= MAX_MESSAGE_BYTES {
        return full;
    }
    let room = MAX_MESSAGE_BYTES.saturating_sub(FIX_SEPARATOR.len() + fix.len() + ELLIPSIS.len());
    if room >= MIN_PROBLEM {
        return format!("{}{ELLIPSIS}{FIX_SEPARATOR}{fix}", truncate(problem, room));
    }
    if problem.len() <= MAX_MESSAGE_BYTES {
        problem.to_owned()
    } else {
        format!("{}{ELLIPSIS}", truncate(problem, MAX_MESSAGE_BYTES - ELLIPSIS.len()))
    }
}

/// The longest prefix of `s` of at most `max` bytes that ends on a char boundary.
pub fn truncate(s: &str, max: usize) -> &str {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Short, stable fingerprint of a configuration file's text (FNV-1a, 64 bit).
/// The daemon writes the one it has loaded to a local file
/// (`credential_bridge_core::paths::loaded_config_file`), so ctl can tell when
/// a reload has taken effect. It is never sent over a socket.
pub fn fingerprint(text: &str) -> String {
    let hash = text.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    format!("{hash:016x}")
}

/// Splits a response message into problem and fix.
pub fn split_fix(message: &str) -> (&str, Option<&str>) {
    match message.split_once(FIX_SEPARATOR) {
        Some((problem, fix)) => (problem, Some(fix)),
        None => (message, None),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn long_messages_keep_their_fix_and_fit() {
        let fix = "locally: credential-bridge-ctl remote edit r --add-allow 'https://github.com/x/*'";
        let message = super::with_fix(&"ä".repeat(800), fix);
        assert!(message.len() <= super::MAX_MESSAGE_BYTES);
        assert_eq!(super::split_fix(&message).1, Some(fix), "fix kept whole");
        let huge_fix = "x".repeat(600);
        assert_eq!(
            super::with_fix("problem", &huge_fix),
            "problem",
            "a fix that cannot fit is dropped, not cut"
        );
        assert_eq!(super::truncate("aä", 2), "a");
    }

    #[test]
    fn fingerprints_differ_and_are_stable() {
        assert_eq!(super::fingerprint(""), "cbf29ce484222325");
        assert_ne!(super::fingerprint("a = 1"), super::fingerprint("a = 2"));
        assert_eq!(super::fingerprint("x"), super::fingerprint("x"));
    }

    #[test]
    fn fix_round_trip() {
        let message = super::with_fix("no credential for github.com", "locally: gh auth login");
        assert_eq!(
            super::split_fix(&message),
            ("no credential for github.com", Some("locally: gh auth login"))
        );
        assert_eq!(super::split_fix("plain"), ("plain", None));
    }
}
