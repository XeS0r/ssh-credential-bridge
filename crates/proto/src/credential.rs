//! The git credential helper attribute format.
//!
//! See `git help credential` ("INPUT/OUTPUT FORMAT"): a block of `key=value`
//! lines terminated by an empty line or end of input. Keys ending in `[]` may
//! repeat; for all other keys the last value wins.

use std::fmt;
use std::io::{self, BufRead, Read, Write};

/// Maximum size of a single credential block in bytes.
pub const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;

/// Attributes whose values must never be logged or displayed.
const SECRET_KEYS: &[&str] = &["password", "oauth_refresh_token", "credential"];

/// Returns `true` if the attribute carries a secret value.
pub fn is_secret(key: &str) -> bool {
    SECRET_KEYS.contains(&key)
}

/// Errors while parsing a credential block.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// The line is not `key=value`. The content is deliberately not included,
    /// because it may contain a secret.
    #[error("malformed attribute on line {0} (expected key=value)")]
    Malformed(usize),
    #[error("credential block exceeds {MAX_CREDENTIAL_BYTES} bytes")]
    TooLarge,
}

/// Errors while turning a URL into credential attributes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UrlError {
    #[error("URL has no scheme (expected something like https://github.com/org/repo)")]
    MissingScheme,
    #[error("URL has no host")]
    MissingHost,
}

/// An ordered list of credential attributes.
///
/// `Debug` output redacts secret values.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Credential {
    attrs: Vec<(String, String)>,
}

impl Credential {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds `protocol`, `host`, `path` and `username` attributes from a URL
    /// such as `https://user@github.com/org/repo.git`.
    pub fn from_url(url: &str) -> Result<Self, UrlError> {
        let (scheme, rest) = url.split_once("://").ok_or(UrlError::MissingScheme)?;
        if scheme.is_empty() {
            return Err(UrlError::MissingScheme);
        }
        let rest = rest.split(['?', '#']).next().unwrap_or_default();
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let (user, host) = match authority.rsplit_once('@') {
            Some((user, host)) => (Some(user), host),
            None => (None, authority),
        };
        if host.is_empty() {
            return Err(UrlError::MissingHost);
        }

        let mut cred = Self::new();
        cred.push("protocol", scheme.to_ascii_lowercase());
        cred.push("host", host.to_ascii_lowercase());
        if !path.is_empty() {
            cred.push("path", path);
        }
        if let Some(name) = user.and_then(|u| u.split(':').next()).filter(|n| !n.is_empty()) {
            cred.push("username", name);
        }
        Ok(cred)
    }

    /// Last value of `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.attrs.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// All values of `key`, in order.
    pub fn get_all<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.attrs.iter().filter(move |(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// Replaces all values of `key` with `value`.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        self.attrs.retain(|(k, _)| *k != key);
        self.attrs.push((key, value.into()));
    }

    /// Appends a value (for multi-valued `key[]` attributes).
    pub fn push(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attrs.push((key.into(), value.into()));
    }

    pub fn remove(&mut self, key: &str) {
        self.attrs.retain(|(k, _)| k != key);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.attrs.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn is_empty(&self) -> bool {
        self.attrs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.attrs.len()
    }

    pub fn protocol(&self) -> Option<&str> {
        self.get("protocol")
    }

    pub fn host(&self) -> Option<&str> {
        self.get("host")
    }

    pub fn path(&self) -> Option<&str> {
        self.get("path")
    }

    /// Returns `true` if the block carries a password or a pre-encoded credential.
    pub fn has_secret(&self) -> bool {
        self.get("password").is_some() || self.get("credential").is_some()
    }

    /// Expands a `url` attribute into its components. Attributes that are
    /// already present take precedence. The `url` attribute is removed.
    pub fn expand_url(&mut self) -> Result<(), UrlError> {
        let Some(url) = self.get("url").map(str::to_owned) else {
            return Ok(());
        };
        let parsed = Self::from_url(&url)?;
        self.remove("url");
        for (key, value) in parsed.attrs {
            if self.get(&key).is_none() {
                self.push(key, value);
            }
        }
        Ok(())
    }

    /// Display adapter that hides secret values.
    pub fn redacted(&self) -> Redacted<'_> {
        Redacted(self)
    }

    /// Reads one block, up to an empty line or end of input.
    pub fn read_from<R: BufRead>(reader: &mut R) -> Result<Self, ParseError> {
        let mut cred = Self::new();
        let mut total = 0usize;
        let mut line = Vec::new();
        for lineno in 1.. {
            line.clear();
            let budget = (MAX_CREDENTIAL_BYTES - total) as u64 + 1;
            let read = reader.by_ref().take(budget).read_until(b'\n', &mut line)?;
            if read == 0 {
                break;
            }
            total += read;
            if total > MAX_CREDENTIAL_BYTES {
                return Err(ParseError::TooLarge);
            }
            let text = strip_eol(&line);
            if text.is_empty() {
                break;
            }
            let text = std::str::from_utf8(text).map_err(|_| ParseError::Malformed(lineno))?;
            match text.split_once('=') {
                Some((key, value)) if !key.is_empty() && !text.contains('\0') => {
                    cred.attrs.push((key.to_owned(), value.to_owned()));
                }
                _ => return Err(ParseError::Malformed(lineno)),
            }
        }
        Ok(cred)
    }

    /// Writes the attributes as `key=value` lines, without the terminating empty line.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        for (key, value) in &self.attrs {
            if key.is_empty() || key.contains(['=', '\n', '\0']) || value.contains(['\n', '\0']) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("attribute {key:?} cannot be encoded"),
                ));
            }
            writeln!(writer, "{key}={value}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Credential {{ {} }}", self.redacted())
    }
}

/// Display adapter returned by [`Credential::redacted`].
#[derive(Debug, Clone, Copy)]
pub struct Redacted<'a>(&'a Credential);

impl fmt::Display for Redacted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (key, value)) in self.0.attrs.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            if is_secret(key) {
                write!(f, "{key}=<redacted>")?;
            } else {
                write!(f, "{key}={value}")?;
            }
        }
        Ok(())
    }
}

pub(crate) fn strip_eol(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> Result<Credential, ParseError> {
        Credential::read_from(&mut input.as_bytes())
    }

    #[test]
    fn parses_until_blank_line() {
        let cred = parse("protocol=https\nhost=github.com\n\nignored=1\n").unwrap();
        assert_eq!(cred.protocol(), Some("https"));
        assert_eq!(cred.host(), Some("github.com"));
        assert_eq!(cred.get("ignored"), None);
    }

    #[test]
    fn parses_until_eof_and_keeps_equals_in_value() {
        let cred = parse("password=a=b").unwrap();
        assert_eq!(cred.get("password"), Some("a=b"));
    }

    #[test]
    fn last_value_wins_and_multi_values_are_kept() {
        let cred = parse("host=a\nhost=b\nwwwauth[]=x\nwwwauth[]=y\n").unwrap();
        assert_eq!(cred.host(), Some("b"));
        assert_eq!(cred.get_all("wwwauth[]").collect::<Vec<_>>(), ["x", "y"]);
    }

    #[test]
    fn rejects_malformed_lines_without_echoing_them() {
        let err = parse("protocol=https\nsecret-without-equals\n").unwrap_err();
        assert!(matches!(err, ParseError::Malformed(2)));
        assert!(!err.to_string().contains("secret"));
        assert!(matches!(parse("=value\n"), Err(ParseError::Malformed(1))));
    }

    #[test]
    fn rejects_oversized_blocks() {
        let input = format!("password={}\n", "x".repeat(MAX_CREDENTIAL_BYTES));
        assert!(matches!(parse(&input), Err(ParseError::TooLarge)));
    }

    #[test]
    fn round_trips() {
        let cred = parse("protocol=https\nhost=github.com\nusername=u\npassword=p\n").unwrap();
        let mut out = Vec::new();
        cred.write_to(&mut out).unwrap();
        assert_eq!(parse(std::str::from_utf8(&out).unwrap()).unwrap(), cred);
    }

    #[test]
    fn refuses_to_encode_newlines() {
        let mut cred = Credential::new();
        cred.set("password", "a\nhost=evil");
        assert!(cred.write_to(&mut Vec::new()).is_err());
    }

    #[test]
    fn redacts_secrets() {
        let cred = parse("host=github.com\npassword=hunter2\noauth_refresh_token=t\n").unwrap();
        let shown = format!("{} {:?}", cred.redacted(), cred);
        assert!(shown.contains("host=github.com"));
        assert!(!shown.contains("hunter2"));
        assert!(!shown.contains("=t"));
    }

    #[test]
    fn parses_urls() {
        let cred = Credential::from_url("HTTPS://me:pw@GitHub.com/Org/Repo.git?x=1").unwrap();
        assert_eq!(cred.protocol(), Some("https"));
        assert_eq!(cred.host(), Some("github.com"));
        assert_eq!(cred.path(), Some("Org/Repo.git"));
        assert_eq!(cred.get("username"), Some("me"));
        assert_eq!(cred.get("password"), None);

        let cred = Credential::from_url("https://example.com:8443").unwrap();
        assert_eq!(cred.host(), Some("example.com:8443"));
        assert_eq!(cred.path(), None);

        assert_eq!(Credential::from_url("github.com").unwrap_err(), UrlError::MissingScheme);
        assert_eq!(Credential::from_url("https:///x").unwrap_err(), UrlError::MissingHost);
    }

    #[test]
    fn expands_url_attribute() {
        let mut cred = parse("url=https://github.com/org/repo\nhost=override.example\n").unwrap();
        cred.expand_url().unwrap();
        assert_eq!(cred.get("url"), None);
        assert_eq!(cred.protocol(), Some("https"));
        assert_eq!(cred.host(), Some("override.example"));
        assert_eq!(cred.path(), Some("org/repo"));
    }
}
