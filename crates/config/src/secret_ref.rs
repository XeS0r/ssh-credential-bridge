//! Secret references: where a secret lives, never the secret itself.
//!
//! | Vault             | Syntax                         | Variant                   |
//! | ----------------- | ------------------------------ | ------------------------- |
//! | 1Password         | `op://Vault/Item/field`        | [`SecretRef::OnePassword`] |
//! | Bitwarden         | `bw://Item/field`              | [`SecretRef::Bitwarden`]  |
//! | KeePassXC         | `keepassxc://Group/Item/field` | [`SecretRef::KeePassXc`]  |
//! | macOS Keychain    | `keychain://service/account`   | [`SecretRef::Keychain`]   |
//! | Secret Service    | `secret-service://attr=value`  | [`SecretRef::SecretService`] |
//! | pass / gopass     | `pass://path/entry`            | [`SecretRef::Pass`]       |
//! | Command           | `cmd:my-script --arg`          | [`SecretRef::Command`]    |
//! | HashiCorp Vault   | `vault://kv/path#field`        | [`SecretRef::HashiVault`] |
//!
//! Path segments are taken literally (no percent-decoding) except that empty segments
//! are invalid. `Display` writes the canonical form, and
//! `s.parse::<SecretRef>()?.to_string() == s` for every canonical `s`.

use std::fmt;
use std::str::FromStr;

/// A parsed secret reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SecretRef {
    /// `op://<vault>/<item>/<field>`; also `op://<vault>/<item>/<section>/<field>`,
    /// kept verbatim as `op read` accepts it.
    OnePassword {
        /// The full `op://` URI, passed to `op read` unchanged.
        uri: String,
    },
    /// `bw://<item>/<field>`; `field` is `password`, `username`, `notes`, `totp` or a
    /// custom field name.
    Bitwarden {
        /// Item name or id.
        item: String,
        /// Field.
        field: String,
    },
    /// `keepassxc://<group>/…/<item>/<field>`; `field` is `password`, `username` or an
    /// attribute name.
    KeePassXc {
        /// Group path, possibly empty (root group).
        group: Vec<String>,
        /// Entry title.
        item: String,
        /// Attribute.
        field: String,
    },
    /// `keychain://<service>/<account>`: a generic password item (macOS only).
    Keychain {
        /// Service.
        service: String,
        /// Account.
        account: String,
    },
    /// `secret-service://<attr>=<value>[&<attr>=<value>…]`: the first item matching all
    /// attributes (Linux only).
    SecretService {
        /// Attribute pairs, in the given order, non-empty.
        attributes: Vec<(String, String)>,
    },
    /// `pass://<path>`: the first line of `pass show <path>` (or `gopass`).
    Pass {
        /// Entry path.
        path: String,
    },
    /// `cmd:<command line>`: run through `sh -c`, the secret is stdout with one trailing
    /// newline removed. Read-only.
    Command {
        /// The command line.
        command: String,
    },
    /// `vault://<mount>/<path>#<field>` (HashiCorp Vault / OpenBao; later).
    HashiVault {
        /// Mount and path.
        path: String,
        /// Field.
        field: String,
    },
}

impl SecretRef {
    /// The vault this reference belongs to.
    pub fn vault(&self) -> VaultKind {
        match self {
            SecretRef::OnePassword { .. } => VaultKind::OnePassword,
            SecretRef::Bitwarden { .. } => VaultKind::Bitwarden,
            SecretRef::KeePassXc { .. } => VaultKind::KeePassXc,
            SecretRef::Keychain { .. } => VaultKind::Keychain,
            SecretRef::SecretService { .. } => VaultKind::SecretService,
            SecretRef::Pass { .. } => VaultKind::Pass,
            SecretRef::Command { .. } => VaultKind::Command,
            SecretRef::HashiVault { .. } => VaultKind::HashiVault,
        }
    }

    /// Whether secrets can be written to this reference (all but `cmd:`).
    pub fn writable(&self) -> bool {
        !matches!(self, SecretRef::Command { .. })
    }
}

/// Error of parsing a [`SecretRef`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid secret reference {reference:?}: {reason}")]
pub struct SecretRefError {
    /// The input.
    pub reference: String,
    /// Why it is invalid.
    pub reason: &'static str,
}

impl FromStr for SecretRef {
    type Err = SecretRefError;

    /// Parses the syntax in the module table. Errors on an unknown scheme, a wrong
    /// number of segments, empty segments, or an empty command.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let error = |reason: &'static str| SecretRefError { reference: s.to_owned(), reason };
        if s.chars().any(char::is_control) {
            return Err(error("control characters are not allowed"));
        }
        if let Some(command) = s.strip_prefix("cmd:") {
            if command.trim().is_empty() {
                return Err(error("the command after cmd: is empty"));
            }
            return Ok(SecretRef::Command { command: command.to_owned() });
        }
        let Some((scheme, rest)) = s.split_once("://") else {
            return Err(error(
                "expected <scheme>://…: op://, bw://, keepassxc://, keychain://, \
                 secret-service://, pass://, vault:// or cmd:",
            ));
        };
        match scheme {
            "op" => {
                let segments = segments(rest).map_err(error)?;
                if !(3..=4).contains(&segments.len()) {
                    return Err(error("expected op://<vault>/<item>/[<section>/]<field>"));
                }
                Ok(SecretRef::OnePassword { uri: s.to_owned() })
            }
            "bw" => match segments(rest).map_err(error)?.as_slice() {
                [item, field] => {
                    Ok(SecretRef::Bitwarden { item: (*item).to_owned(), field: (*field).to_owned() })
                }
                _ => Err(error("expected bw://<item>/<field>")),
            },
            "keepassxc" => match segments(rest).map_err(error)?.as_slice() {
                [group @ .., item, field] => Ok(SecretRef::KeePassXc {
                    group: group.iter().map(|g| (*g).to_owned()).collect(),
                    item: (*item).to_owned(),
                    field: (*field).to_owned(),
                }),
                _ => Err(error("expected keepassxc://[<group>/…/]<item>/<field>")),
            },
            "keychain" => match segments(rest).map_err(error)?.as_slice() {
                [service, account] => {
                    Ok(SecretRef::Keychain { service: (*service).to_owned(), account: (*account).to_owned() })
                }
                _ => Err(error("expected keychain://<service>/<account>")),
            },
            "secret-service" => {
                if rest.is_empty() {
                    return Err(error("expected secret-service://<attribute>=<value>[&…]"));
                }
                let attributes = rest
                    .split('&')
                    .map(|pair| match pair.split_once('=') {
                        Some((key, value))
                            if !key.is_empty() && !value.is_empty() && !value.contains('=') =>
                        {
                            Ok((key.to_owned(), value.to_owned()))
                        }
                        _ => Err(error("expected secret-service://<attribute>=<value>[&…]")),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(SecretRef::SecretService { attributes })
            }
            "pass" => {
                segments(rest).map_err(error)?;
                Ok(SecretRef::Pass { path: rest.to_owned() })
            }
            "vault" => {
                let Some((path, field)) = rest.split_once('#') else {
                    return Err(error("expected vault://<mount>/<path>#<field>"));
                };
                if field.is_empty() || field.contains('#') {
                    return Err(error("expected vault://<mount>/<path>#<field>"));
                }
                if segments(path).map_err(error)?.len() < 2 {
                    return Err(error("expected vault://<mount>/<path>#<field>"));
                }
                Ok(SecretRef::HashiVault { path: path.to_owned(), field: field.to_owned() })
            }
            _ => Err(error(
                "unknown scheme; expected op://, bw://, keepassxc://, keychain://, \
                 secret-service://, pass://, vault:// or cmd:",
            )),
        }
    }
}

/// Splits a reference path at `/`; every segment must be non-empty.
fn segments(rest: &str) -> Result<Vec<&str>, &'static str> {
    if rest.is_empty() {
        return Err("the path after the scheme is empty");
    }
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.iter().any(|part| part.is_empty()) {
        return Err("empty path segment (leading, trailing or double /)");
    }
    Ok(parts)
}

impl fmt::Display for SecretRef {
    /// Writes the canonical form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretRef::OnePassword { uri } => f.write_str(uri),
            SecretRef::Bitwarden { item, field } => write!(f, "bw://{item}/{field}"),
            SecretRef::KeePassXc { group, item, field } => {
                f.write_str("keepassxc://")?;
                for g in group {
                    write!(f, "{g}/")?;
                }
                write!(f, "{item}/{field}")
            }
            SecretRef::Keychain { service, account } => write!(f, "keychain://{service}/{account}"),
            SecretRef::SecretService { attributes } => {
                f.write_str("secret-service://")?;
                for (i, (key, value)) in attributes.iter().enumerate() {
                    if i > 0 {
                        f.write_str("&")?;
                    }
                    write!(f, "{key}={value}")?;
                }
                Ok(())
            }
            SecretRef::Pass { path } => write!(f, "pass://{path}"),
            SecretRef::Command { command } => write!(f, "cmd:{command}"),
            SecretRef::HashiVault { path, field } => write!(f, "vault://{path}#{field}"),
        }
    }
}

/// The vault kinds. The names are used by `ctl vault unlock <vault>` and in messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VaultKind {
    /// `1password`
    OnePassword,
    /// `bitwarden`
    Bitwarden,
    /// `keepassxc`
    KeePassXc,
    /// `keychain`
    Keychain,
    /// `secret-service`
    SecretService,
    /// `pass`
    Pass,
    /// `cmd`
    Command,
    /// `vault`
    HashiVault,
}

impl VaultKind {
    /// Every kind, in display order.
    pub const ALL: [VaultKind; 8] = [
        VaultKind::OnePassword,
        VaultKind::Bitwarden,
        VaultKind::KeePassXc,
        VaultKind::Keychain,
        VaultKind::SecretService,
        VaultKind::Pass,
        VaultKind::Command,
        VaultKind::HashiVault,
    ];

    /// The name used on the command line.
    pub fn name(self) -> &'static str {
        match self {
            VaultKind::OnePassword => "1password",
            VaultKind::Bitwarden => "bitwarden",
            VaultKind::KeePassXc => "keepassxc",
            VaultKind::Keychain => "keychain",
            VaultKind::SecretService => "secret-service",
            VaultKind::Pass => "pass",
            VaultKind::Command => "cmd",
            VaultKind::HashiVault => "vault",
        }
    }

    /// Whether `ctl vault unlock` applies (Bitwarden; KeePassXC on macOS; Vault later).
    pub fn has_unlock_session(self) -> bool {
        matches!(self, VaultKind::Bitwarden | VaultKind::KeePassXc | VaultKind::HashiVault)
    }
}

impl fmt::Display for VaultKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for VaultKind {
    type Err = SecretRefError;

    /// Parses [`VaultKind::name`]; `op` is accepted for `1password`, `bw` for
    /// `bitwarden`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let alias = match s {
            "op" => "1password",
            "bw" => "bitwarden",
            other => other,
        };
        VaultKind::ALL
            .into_iter()
            .find(|kind| kind.name() == alias)
            .ok_or_else(|| SecretRefError { reference: s.to_owned(), reason: "unknown vault" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> SecretRef {
        s.parse().unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn parses_every_scheme() {
        assert_eq!(
            parse("op://Dev/bridge-app/private-key"),
            SecretRef::OnePassword { uri: "op://Dev/bridge-app/private-key".into() }
        );
        assert_eq!(
            parse("op://Dev/item/section/field"),
            SecretRef::OnePassword { uri: "op://Dev/item/section/field".into() }
        );
        assert_eq!(
            parse("bw://gitlab-team/token"),
            SecretRef::Bitwarden { item: "gitlab-team".into(), field: "token".into() }
        );
        assert_eq!(
            parse("keepassxc://Group/Sub/Item/password"),
            SecretRef::KeePassXc {
                group: vec!["Group".into(), "Sub".into()],
                item: "Item".into(),
                field: "password".into()
            }
        );
        assert_eq!(
            parse("keepassxc://Item/password"),
            SecretRef::KeePassXc { group: vec![], item: "Item".into(), field: "password".into() }
        );
        assert_eq!(
            parse("keychain://github/me"),
            SecretRef::Keychain { service: "github".into(), account: "me".into() }
        );
        assert_eq!(
            parse("secret-service://service=github&user=me"),
            SecretRef::SecretService {
                attributes: vec![("service".into(), "github".into()), ("user".into(), "me".into())]
            }
        );
        assert_eq!(parse("pass://work/github/token"), SecretRef::Pass { path: "work/github/token".into() });
        assert_eq!(parse("pass://token"), SecretRef::Pass { path: "token".into() });
        assert_eq!(
            parse("cmd:my-script --arg 'a b'"),
            SecretRef::Command { command: "my-script --arg 'a b'".into() }
        );
        assert_eq!(
            parse("vault://kv/ci/github#token"),
            SecretRef::HashiVault { path: "kv/ci/github".into(), field: "token".into() }
        );
    }

    #[test]
    fn canonical_forms_round_trip() {
        for s in [
            "op://Dev/bridge-app/private-key",
            "op://V/I/S/F",
            "bw://Item/field",
            "keepassxc://Root/Item/field",
            "keepassxc://Item/field",
            "keychain://svc/acct",
            "secret-service://a=b",
            "secret-service://a=b&c=d",
            "pass://a/b/c",
            "cmd:echo hi",
            "vault://kv/path#field",
        ] {
            assert_eq!(parse(s).to_string(), s);
        }
    }

    #[test]
    fn rejects_invalid_references() {
        for (s, hint) in [
            ("", "expected <scheme>://"),
            ("plain-token", "expected <scheme>://"),
            ("ftp://x/y", "unknown scheme"),
            ("op://Vault/Item", "op://<vault>"),
            ("op://V/I/S/F/X", "op://<vault>"),
            ("op://V//F", "empty path segment"),
            ("op://", "empty"),
            ("bw://item", "bw://<item>/<field>"),
            ("bw://a/b/c", "bw://<item>/<field>"),
            ("bw://item/", "empty path segment"),
            ("keepassxc://item", "keepassxc://"),
            ("keychain://svc", "keychain://"),
            ("secret-service://", "secret-service://"),
            ("secret-service://novalue", "secret-service://"),
            ("secret-service://a=", "secret-service://"),
            ("secret-service://=b", "secret-service://"),
            ("secret-service://a=b&", "secret-service://"),
            ("pass://", "empty"),
            ("pass://a//b", "empty path segment"),
            ("cmd:", "command"),
            ("cmd:   ", "command"),
            ("vault://kv/path", "vault://"),
            ("vault://kv#field", "vault://"),
            ("vault://kv/path#", "vault://"),
            ("vault://kv/path#a#b", "vault://"),
            ("bw://item/field\n", "control characters"),
        ] {
            let err = s.parse::<SecretRef>().expect_err(s);
            assert_eq!(err.reference, s);
            assert!(err.reason.contains(hint), "{s:?}: {} does not mention {hint:?}", err.reason);
        }
    }

    #[test]
    fn vault_and_writability() {
        assert_eq!(parse("op://a/b/c").vault(), VaultKind::OnePassword);
        assert_eq!(parse("bw://a/b").vault(), VaultKind::Bitwarden);
        assert_eq!(parse("keepassxc://a/b").vault(), VaultKind::KeePassXc);
        assert_eq!(parse("keychain://a/b").vault(), VaultKind::Keychain);
        assert_eq!(parse("secret-service://a=b").vault(), VaultKind::SecretService);
        assert_eq!(parse("pass://a").vault(), VaultKind::Pass);
        assert_eq!(parse("cmd:x").vault(), VaultKind::Command);
        assert_eq!(parse("vault://a/b#c").vault(), VaultKind::HashiVault);
        assert!(parse("op://a/b/c").writable());
        assert!(!parse("cmd:x").writable());
    }

    #[test]
    fn vault_names_round_trip() {
        for kind in VaultKind::ALL {
            assert_eq!(kind.name().parse::<VaultKind>(), Ok(kind));
        }
        assert_eq!("bw".parse::<VaultKind>(), Ok(VaultKind::Bitwarden));
        assert!("nope".parse::<VaultKind>().is_err());
    }
}
