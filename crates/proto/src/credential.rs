//! The git credential attribute format (`git help credential`, "INPUT/OUTPUT FORMAT").
//!
//! A credential is a sequence of `key=value` lines terminated by a blank line or end of
//! input. Values may contain `=` but neither NUL nor newline. Keys ending in `[]` are
//! multi-valued; an empty `key[]=` resets the list. Unknown keys are ignored when parsing
//! and never written, so the format can grow without breaking either side.

use std::io::{self, Write};

use zeroize::Zeroizing;

use crate::secret::Secret;

/// Largest accepted credential text in bytes.
pub const MAX_CREDENTIAL_LEN: usize = 64 * 1024;

/// Errors of parsing credential text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    /// A non-empty line without `=`.
    #[error("credential line {line} has no '='")]
    MissingEquals {
        /// 1-based line number.
        line: usize,
    },
    /// The input contains a NUL byte.
    #[error("credential contains a NUL byte")]
    Nul,
    /// The input is not UTF-8.
    #[error("credential is not valid UTF-8")]
    InvalidUtf8,
    /// The input exceeds [`MAX_CREDENTIAL_LEN`].
    #[error("credential exceeds {MAX_CREDENTIAL_LEN} bytes")]
    TooLong,
    /// A value to be written contains a newline or NUL, or ends with a carriage return
    /// (git strips one from the end of every line, so it would not arrive).
    #[error("credential value for {key} contains a newline or NUL, or ends with a carriage return")]
    InvalidValue {
        /// The attribute whose value is invalid.
        key: &'static str,
    },
}

/// The git credential attributes credential-bridge understands.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Credential {
    /// `protocol`, e.g. `https`.
    pub protocol: Option<String>,
    /// `host`, including a `:port` if git sent one.
    pub host: Option<String>,
    /// `path`, sent only with `credential.useHttpPath`.
    pub path: Option<String>,
    /// `username`.
    pub username: Option<String>,
    /// `password` (the token).
    pub password: Option<Secret>,
    /// `password_expiry_utc`, seconds since the epoch.
    pub password_expiry_utc: Option<u64>,
    /// `oauth_refresh_token`.
    pub oauth_refresh_token: Option<Secret>,
    /// `wwwauth[]`, in order.
    pub wwwauth: Vec<String>,
}

impl Credential {
    /// Parses credential text, stopping at the first blank line or the end of `input`.
    ///
    /// A trailing `\r` is removed from each line, as git does. A key given twice keeps
    /// the last value; `wwwauth[]` accumulates, and an empty `wwwauth[]=` clears it. An
    /// unparsable `password_expiry_utc` is ignored.
    ///
    /// Errors: see [`CredentialError`]. Unknown keys are skipped.
    pub fn parse(input: &[u8]) -> Result<Credential, CredentialError> {
        if input.len() > MAX_CREDENTIAL_LEN {
            return Err(CredentialError::TooLong);
        }
        if input.contains(&0) {
            return Err(CredentialError::Nul);
        }
        let text = std::str::from_utf8(input).map_err(|_| CredentialError::InvalidUtf8)?;
        let mut credential = Credential::default();
        for (index, line) in text.split('\n').enumerate() {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.is_empty() {
                break;
            }
            let (key, value) =
                line.split_once('=').ok_or(CredentialError::MissingEquals { line: index + 1 })?;
            credential.set(key, value);
        }
        Ok(credential)
    }

    /// Applies one `key=value` attribute.
    fn set(&mut self, key: &str, value: &str) {
        match key {
            "protocol" => self.protocol = Some(value.to_owned()),
            "host" => self.host = Some(value.to_owned()),
            "path" => self.path = Some(value.to_owned()),
            "username" => self.username = Some(value.to_owned()),
            "password" => self.password = Some(Secret::new(value.to_owned())),
            "password_expiry_utc" => self.password_expiry_utc = value.parse().ok(),
            "oauth_refresh_token" => self.oauth_refresh_token = Some(Secret::new(value.to_owned())),
            "wwwauth[]" if value.is_empty() => self.wwwauth.clear(),
            "wwwauth[]" => self.wwwauth.push(value.to_owned()),
            _ => {}
        }
    }

    /// The set attributes in output order, values borrowed.
    fn attributes(&self) -> Vec<(&'static str, std::borrow::Cow<'_, str>)> {
        use std::borrow::Cow;
        let mut out: Vec<(&'static str, Cow<'_, str>)> = Vec::new();
        let plain = [
            ("protocol", self.protocol.as_deref()),
            ("host", self.host.as_deref()),
            ("path", self.path.as_deref()),
            ("username", self.username.as_deref()),
            ("password", self.password.as_ref().map(Secret::expose)),
        ];
        for (key, value) in plain {
            if let Some(value) = value {
                out.push((key, Cow::Borrowed(value)));
            }
        }
        if let Some(expiry) = self.password_expiry_utc {
            out.push(("password_expiry_utc", Cow::Owned(expiry.to_string())));
        }
        if let Some(token) = &self.oauth_refresh_token {
            out.push(("oauth_refresh_token", Cow::Borrowed(token.expose())));
        }
        for value in &self.wwwauth {
            out.push(("wwwauth[]", Cow::Borrowed(value)));
        }
        out
    }

    /// Writes the set attributes as `key=value` lines (no terminating blank line).
    ///
    /// Errors: [`io::ErrorKind::InvalidInput`] wrapping [`CredentialError::InvalidValue`]
    /// if a value contains a newline or NUL or ends with a carriage return; nothing is
    /// written in that case.
    pub fn write_to<W: Write>(&self, out: &mut W) -> io::Result<()> {
        let bytes = self.to_bytes().map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        let bytes = Zeroizing::new(bytes);
        out.write_all(&bytes)
    }

    /// Checks that every set value can be written: no newline or NUL, no trailing carriage
    /// return. [`Credential::parse`] accepts such values (as git does), so callers that
    /// must re-encode what they received check here first.
    ///
    /// Errors: [`CredentialError::InvalidValue`] naming the first offending key.
    pub fn check_writable(&self) -> Result<(), CredentialError> {
        for (key, value) in self.attributes() {
            if value.contains(['\n', '\0']) || value.ends_with('\r') {
                return Err(CredentialError::InvalidValue { key });
            }
        }
        Ok(())
    }

    /// [`Credential::write_to`] into a new buffer.
    ///
    /// The buffer contains the password; callers should zeroize it after use.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CredentialError> {
        // `wwwauth[]=` with an empty value would clear the list on the other side.
        let attributes: Vec<_> = self
            .attributes()
            .into_iter()
            .filter(|(key, value)| !(*key == "wwwauth[]" && value.is_empty()))
            .collect();
        let mut capacity = 0;
        for (key, value) in &attributes {
            if value.contains(['\n', '\0']) || value.ends_with('\r') {
                return Err(CredentialError::InvalidValue { key });
            }
            capacity += key.len() + value.len() + 2;
        }
        // Allocated once, so no reallocation leaves copies of the password behind.
        let mut out = Vec::with_capacity(capacity);
        for (key, value) in &attributes {
            out.extend_from_slice(key.as_bytes());
            out.push(b'=');
            out.extend_from_slice(value.as_bytes());
            out.push(b'\n');
        }
        Ok(out)
    }

    /// `protocol://host/path` if protocol and host are set (path only if present).
    pub fn url(&self) -> Option<String> {
        let protocol = self.protocol.as_deref()?;
        let host = self.host.as_deref()?;
        Some(match self.path.as_deref() {
            Some(path) => format!("{protocol}://{host}/{}", path.trim_start_matches('/')),
            None => format!("{protocol}://{host}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_git_input() {
        let input = b"protocol=https\nhost=example.com:8443\npath=a/b.git\nusername=me\npassword=p=w\n\
password_expiry_utc=1700000000\noauth_refresh_token=r\nwwwauth[]=Basic realm=\"x\"\nwwwauth[]=Bearer\n\
capability[]=authtype\nunknown=1\n\nhost=ignored\n";
        let c = Credential::parse(input).unwrap();
        assert_eq!(c.protocol.as_deref(), Some("https"));
        assert_eq!(c.host.as_deref(), Some("example.com:8443"));
        assert_eq!(c.path.as_deref(), Some("a/b.git"));
        assert_eq!(c.username.as_deref(), Some("me"));
        assert_eq!(c.password.as_ref().map(Secret::expose), Some("p=w"));
        assert_eq!(c.password_expiry_utc, Some(1_700_000_000));
        assert_eq!(c.oauth_refresh_token.as_ref().map(Secret::expose), Some("r"));
        assert_eq!(c.wwwauth, ["Basic realm=\"x\"", "Bearer"]);
        assert_eq!(c.url().as_deref(), Some("https://example.com:8443/a/b.git"));
    }

    #[test]
    fn parse_details() {
        let c = Credential::parse(b"host=a\r\nhost=b\r\nwwwauth[]=x\nwwwauth[]=\nwwwauth[]=y").unwrap();
        assert_eq!(c.host.as_deref(), Some("b"));
        assert_eq!(c.wwwauth, ["y"]);
        assert_eq!(Credential::parse(b"").unwrap(), Credential::default());
        assert_eq!(Credential::parse(b"password_expiry_utc=soon\n").unwrap().password_expiry_utc, None);
    }

    #[test]
    fn parse_errors() {
        assert_eq!(Credential::parse(b"host=a\nnoequals\n"), Err(CredentialError::MissingEquals { line: 2 }));
        assert_eq!(Credential::parse(b"host=a\0\n"), Err(CredentialError::Nul));
        assert_eq!(Credential::parse(b"host=\xff\n"), Err(CredentialError::InvalidUtf8));
        let long = vec![b'a'; MAX_CREDENTIAL_LEN + 1];
        assert_eq!(Credential::parse(&long), Err(CredentialError::TooLong));
    }

    #[test]
    fn writes_in_fixed_order() {
        let c = Credential {
            protocol: Some("https".into()),
            host: Some("github.com".into()),
            username: Some("x-access-token".into()),
            password: Some(Secret::new("ghs_x".into())),
            password_expiry_utc: Some(5),
            wwwauth: vec!["Basic".into(), String::new()],
            ..Credential::default()
        };
        let mut out = Vec::new();
        c.write_to(&mut out).unwrap();
        assert_eq!(
            out,
            b"protocol=https\nhost=github.com\nusername=x-access-token\npassword=ghs_x\npassword_expiry_utc=5\nwwwauth[]=Basic\n"
        );
        assert_eq!(c.to_bytes().unwrap(), out);
        assert_eq!(c.url().as_deref(), Some("https://github.com"));
        assert_eq!(Credential::default().url(), None);
    }

    #[test]
    fn refuses_values_that_would_inject_lines() {
        let c = Credential { password: Some(Secret::new("a\nhost=evil".into())), ..Credential::default() };
        assert_eq!(c.to_bytes(), Err(CredentialError::InvalidValue { key: "password" }));
        let mut out = Vec::new();
        let err = c.write_to(&mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(out.is_empty());
        assert!(!err.to_string().contains("evil"));
        let c = Credential { path: Some("a\0b".into()), ..Credential::default() };
        assert_eq!(c.to_bytes(), Err(CredentialError::InvalidValue { key: "path" }));
    }

    #[test]
    fn refuses_a_trailing_carriage_return_that_git_would_strip() {
        // git strips one `\r` per line, as `parse` does, so `a\r` cannot be written.
        let c = Credential::parse(b"password=a\r\r\n").unwrap();
        assert_eq!(c.password.as_ref().map(Secret::expose), Some("a\r"));
        assert_eq!(c.to_bytes(), Err(CredentialError::InvalidValue { key: "password" }));
        let c = Credential::parse(b"password=a\rb\r\n").unwrap();
        assert_eq!(Credential::parse(&c.to_bytes().unwrap()), Ok(c));
    }
}
