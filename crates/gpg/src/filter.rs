//! The command allowlist (`docs/architecture.md`, section "gpg").
//!
//! Housekeeping commands are always allowed; `PKSIGN` needs `sign`, `PKDECRYPT` needs
//! `decrypt`; [`ALWAYS_BLOCKED`] and every command not listed are denied. Verbs compare
//! case-insensitively. `OPTION`s are filtered by name: the ones that describe the
//! server's terminal and display ([`LOCAL_OPTIONS`]) are answered locally and never reach
//! the local gpg-agent (a pinentry must not open on a display the server names), the
//! ones in [`FORWARDED_OPTIONS`] are forwarded, `pinentry-mode` only with a value in
//! [`PINENTRY_MODES`], and every other `OPTION` is denied.

use crate::GpgPolicy;

/// Allowed regardless of policy.
pub const HOUSEKEEPING: &[&str] = &[
    "OPTION",
    "GETINFO",
    "HAVEKEY",
    "KEYINFO",
    "RESET",
    "SIGKEY",
    "SETKEY",
    "SETKEYDESC",
    "SETHASH",
    "NOP",
    "BYE",
];

/// Allowed with `gpg = ["sign"]`.
pub const SIGN_COMMANDS: &[&str] = &["PKSIGN"];

/// Allowed with `gpg = ["sign", "decrypt"]`.
pub const DECRYPT_COMMANDS: &[&str] = &["PKDECRYPT"];

/// Never allowed, listed for clear log messages. Unlisted commands are denied too.
pub const ALWAYS_BLOCKED: &[&str] = &[
    "SCD",
    "KEYTOCARD",
    "EXPORT_KEY",
    "IMPORT_KEY",
    "DELETE_KEY",
    "PRESET_PASSPHRASE",
    "CLEAR_PASSPHRASE",
    "GET_PASSPHRASE",
    "GENKEY",
    "PASSWD",
    "LEARN",
    "KILLAGENT",
    "RELOADAGENT",
];

/// `OPTION` names answered locally with `OK` and not forwarded.
pub const LOCAL_OPTIONS: &[&str] = &[
    "display",
    "ttyname",
    "ttytype",
    "lc-ctype",
    "lc-messages",
    "xauthority",
    "putenv",
    "pinentry-user-data",
];

/// `OPTION` names forwarded to gpg-agent with any value. They change how gpg-agent talks
/// to this client, never where a pinentry appears or who answers it:
///
/// - `agent-awareness`, `allow-pinentry-notify`: what the client is told.
/// - `pretend-request-origin`: gpg-agent honours it only on an unrestricted socket, where
///   `remote` or `browser` restrict the connection and `local` leaves it as it is; on
///   the restricted extra socket (the default `[gpg] socket`) gpg-agent rejects it. It
///   can only add restrictions.
pub const FORWARDED_OPTIONS: &[&str] =
    &["agent-awareness", "allow-pinentry-notify", "pretend-request-origin"];

/// The `pinentry-mode` values forwarded. `ask` and `default` are gpg-agent's default (the
/// pinentry on your machine); `cancel` and `error` make it ask no one, which only takes
/// away. `loopback` is denied: it would let the server answer `INQUIRE PASSPHRASE`
/// itself, and gpg-agent refuses it only on its restricted extra socket, while
/// `[gpg] socket` may name any socket. gpg-agent compares the value case-sensitively, so
/// does the filter.
pub const PINENTRY_MODES: &[&str] = &["ask", "default", "cancel", "error"];

/// Why a command was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// In [`ALWAYS_BLOCKED`].
    Blocked,
    /// `PKSIGN` / `PKDECRYPT` not allowed by the profile.
    NotPermitted,
    /// Not on any list.
    Unknown,
}

/// The decision for one command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Forward to gpg-agent.
    Allow,
    /// Answer `OK` locally without forwarding ([`LOCAL_OPTIONS`]).
    AnswerOk,
    /// Answer `ERR` [`crate::assuan::ERR_FORBIDDEN`] locally.
    Deny(DenyReason),
}

impl DenyReason {
    /// A short text for the `ERR` description and the log.
    pub fn describe(self) -> &'static str {
        match self {
            DenyReason::Blocked => "always blocked",
            DenyReason::NotPermitted => "not allowed by the profile",
            DenyReason::Unknown => "not on the allowlist",
        }
    }
}

/// Whether `verb` is in `list`, ignoring ASCII case.
fn listed(list: &[&str], verb: &str) -> bool {
    list.iter().any(|v| v.eq_ignore_ascii_case(verb))
}

/// The name of an `OPTION`, parsed as libassuan does: leading spaces and tabs are
/// skipped, the name ends at a space, tab or `=`, and a leading `--` is dropped.
fn option_name(args: &[u8]) -> &[u8] {
    let start = args.iter().position(|&b| b != b' ' && b != b'\t').unwrap_or(args.len());
    let args = &args[start..];
    let end = args.iter().position(|&b| b == b'=' || b == b' ' || b == b'\t').unwrap_or(args.len());
    let name = &args[..end];
    match name.strip_prefix(b"--") {
        Some(rest) if !rest.is_empty() => rest,
        _ => name,
    }
}

/// The value of an `OPTION`, parsed as libassuan does: after the name, blanks, an
/// optional `=` and blanks are skipped, and trailing blanks are dropped. Empty if there
/// is none.
fn option_value(args: &[u8]) -> &[u8] {
    let blank = |b: &u8| *b == b' ' || *b == b'\t';
    let start = args.iter().position(|b| !blank(b)).unwrap_or(args.len());
    let rest = &args[start..];
    let end = rest.iter().position(|&b| b == b'=' || blank(&b)).unwrap_or(rest.len());
    let mut value = &rest[end..];
    value = &value[value.iter().position(|b| !blank(b)).unwrap_or(value.len())..];
    if let Some(after) = value.strip_prefix(b"=") {
        value = &after[after.iter().position(|b| !blank(b)).unwrap_or(after.len())..];
    }
    let trimmed = value.iter().rposition(|b| !blank(b)).map_or(0, |last| last + 1);
    &value[..trimmed]
}

/// Decides on a command line's verb and arguments.
pub fn check_command(policy: &GpgPolicy, verb: &str, args: &[u8]) -> Verdict {
    if listed(ALWAYS_BLOCKED, verb) {
        return Verdict::Deny(DenyReason::Blocked);
    }
    if verb.eq_ignore_ascii_case("OPTION") {
        let name = option_name(args);
        if LOCAL_OPTIONS.iter().any(|o| o.as_bytes().eq_ignore_ascii_case(name)) {
            return Verdict::AnswerOk;
        }
        if FORWARDED_OPTIONS.iter().any(|o| o.as_bytes().eq_ignore_ascii_case(name)) {
            return Verdict::Allow;
        }
        if name.eq_ignore_ascii_case(b"pinentry-mode") {
            let value = option_value(args);
            return if PINENTRY_MODES.iter().any(|mode| mode.as_bytes() == value) {
                Verdict::Allow
            } else {
                Verdict::Deny(DenyReason::Unknown)
            };
        }
        return Verdict::Deny(DenyReason::Unknown);
    }
    if listed(HOUSEKEEPING, verb) {
        return Verdict::Allow;
    }
    if listed(SIGN_COMMANDS, verb) {
        return if policy.sign { Verdict::Allow } else { Verdict::Deny(DenyReason::NotPermitted) };
    }
    if listed(DECRYPT_COMMANDS, verb) {
        return if policy.decrypt { Verdict::Allow } else { Verdict::Deny(DenyReason::NotPermitted) };
    }
    Verdict::Deny(DenyReason::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: GpgPolicy = GpgPolicy { sign: false, decrypt: false };
    const SIGN: GpgPolicy = GpgPolicy { sign: true, decrypt: false };
    const BOTH: GpgPolicy = GpgPolicy { sign: true, decrypt: true };

    #[test]
    fn housekeeping_always_allowed() {
        for verb in HOUSEKEEPING {
            // OPTION is decided by the option's name (see below).
            let args: &[u8] = if *verb == "OPTION" { b"allow-pinentry-notify" } else { b"" };
            assert_eq!(check_command(&NONE, verb, args), Verdict::Allow, "{verb}");
            assert_eq!(check_command(&NONE, &verb.to_ascii_lowercase(), args), Verdict::Allow);
        }
    }

    #[test]
    fn sign_and_decrypt_follow_policy() {
        assert_eq!(check_command(&NONE, "PKSIGN", b""), Verdict::Deny(DenyReason::NotPermitted));
        assert_eq!(check_command(&SIGN, "PKSIGN", b""), Verdict::Allow);
        assert_eq!(check_command(&SIGN, "pksign", b"--hash=sha256"), Verdict::Allow);
        assert_eq!(check_command(&SIGN, "PKDECRYPT", b""), Verdict::Deny(DenyReason::NotPermitted));
        assert_eq!(check_command(&BOTH, "PKDECRYPT", b""), Verdict::Allow);
        let decrypt_only = GpgPolicy { sign: false, decrypt: true };
        assert_eq!(check_command(&decrypt_only, "PKDECRYPT", b""), Verdict::Allow);
        assert_eq!(check_command(&decrypt_only, "PKSIGN", b""), Verdict::Deny(DenyReason::NotPermitted));
    }

    #[test]
    fn blocked_even_with_full_policy() {
        for verb in ALWAYS_BLOCKED {
            assert_eq!(check_command(&BOTH, verb, b""), Verdict::Deny(DenyReason::Blocked), "{verb}");
            assert_eq!(
                check_command(&BOTH, &verb.to_ascii_lowercase(), b""),
                Verdict::Deny(DenyReason::Blocked)
            );
        }
        // The lists must not overlap.
        for verb in ALWAYS_BLOCKED {
            assert!(!listed(HOUSEKEEPING, verb) && !listed(SIGN_COMMANDS, verb));
            assert!(!listed(DECRYPT_COMMANDS, verb));
        }
    }

    #[test]
    fn unknown_denied() {
        for verb in ["READKEY", "INPUT", "OUTPUT", "GET_CONFIRMATION", "PKSIGNX", "END", "X"] {
            assert_eq!(check_command(&BOTH, verb, b""), Verdict::Deny(DenyReason::Unknown), "{verb}");
        }
    }

    #[test]
    fn local_options_answered_locally() {
        for args in [
            b"display=:0".as_slice(),
            b"ttyname=/dev/pts/3",
            b"ttyname /dev/pts/3",
            b"--ttytype=xterm",
            b"DISPLAY=:1",
            b"lc-ctype=C.UTF-8",
            b"lc-messages=C",
            b"xauthority=/home/u/.Xauthority",
            b"putenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/x",
            b"pinentry-user-data=x",
            // libassuan also separates with tabs and skips leading blanks.
            b"display\t:0",
            b"\tdisplay=:0",
            b" \t--putenv\tDISPLAY=:0",
            b"xauthority\t/tmp/x",
        ] {
            assert_eq!(check_command(&NONE, "OPTION", args), Verdict::AnswerOk, "{args:?}");
        }
        for args in [
            b"agent-awareness=2.1.0".as_slice(),
            b"allow-pinentry-notify",
            b"--pinentry-mode=ask",
            b"pinentry-mode=default",
            b"pinentry-mode cancel",
            b" pinentry-mode = error \t",
            b"pretend-request-origin\tremote",
            b"pretend-request-origin=local",
        ] {
            assert_eq!(check_command(&NONE, "option", args), Verdict::Allow, "{args:?}");
        }
    }

    /// `pinentry-mode=loopback` would let the server answer passphrase inquiries; every
    /// spelling gpg-agent would accept is denied, and so are values it does not know.
    #[test]
    fn loopback_pinentry_is_denied() {
        for args in [
            b"pinentry-mode=loopback".as_slice(),
            b"--pinentry-mode=loopback",
            b"pinentry-mode loopback",
            b"PINENTRY-MODE=loopback",
            b"\tpinentry-mode\t=\tloopback  ",
            b"pinentry-mode=LOOPBACK",
            b"pinentry-mode=Ask",
            b"pinentry-mode",
            b"pinentry-mode=",
            b"pinentry-mode=ask loopback",
        ] {
            assert_eq!(check_command(&BOTH, "OPTION", args), Verdict::Deny(DenyReason::Unknown), "{args:?}");
        }
    }

    #[test]
    fn option_values_are_parsed_like_libassuan() {
        assert_eq!(option_value(b"pinentry-mode=ask"), b"ask");
        assert_eq!(option_value(b"pinentry-mode ask"), b"ask");
        assert_eq!(option_value(b" --pinentry-mode \t= \task \t"), b"ask");
        assert_eq!(option_value(b"putenv=A=B"), b"A=B");
        assert_eq!(option_value(b"allow-pinentry-notify"), b"");
        assert_eq!(option_value(b"x = "), b"");
    }

    #[test]
    fn other_options_denied() {
        for args in [b"displayx=1".as_slice(), b"", b"--", b"=x", b"no-grab", b"s2k-count=1"] {
            assert_eq!(check_command(&NONE, "OPTION", args), Verdict::Deny(DenyReason::Unknown), "{args:?}");
        }
    }
}
