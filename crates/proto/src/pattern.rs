//! URL patterns of a remote's allow list, shared by the daemon (matching),
//! ctl and the helper (deriving git's `credential.<url>` sections).

use std::fmt;
use std::str::FromStr;

use crate::Credential;

/// An allow-list entry such as `https://github.com` or `https://github.com/my-org/*`.
///
/// * `protocol` must match exactly (case-insensitive).
/// * In the host, `*` matches within one DNS label (`*.example.com` matches
///   `git.example.com`, not `a.b.example.com`). A port is part of the host.
/// * Without a path, every path on the host matches. With a path, the request
///   must carry one (remote git needs `credential.<url>.useHttpPath = true`,
///   which `credential-bridge-ctl remote install` sets). `*` matches any
///   characters including `/`, and a trailing `.git` on the request is optional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlPattern {
    protocol: String,
    host: String,
    path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid URL pattern {0:?}: expected <protocol>://<host>[/<path>], e.g. https://github.com or https://github.com/my-org/*"
)]
pub struct PatternError(String);

impl FromStr for UrlPattern {
    type Err = PatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || PatternError(s.to_owned());
        let (protocol, rest) = s.split_once("://").ok_or_else(err)?;
        if protocol.is_empty() || !protocol.bytes().all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
        {
            return Err(err());
        }
        let (host, path) = match rest.split_once('/') {
            Some((host, path)) => (host, Some(path)),
            None => (rest, None),
        };
        if host.is_empty() || host.contains(['@', '/', '?', '#']) || host.contains(char::is_whitespace) {
            return Err(err());
        }
        let path = path.map(|p| p.trim_matches('/')).filter(|p| !p.is_empty()).map(str::to_owned);
        Ok(Self {
            protocol: protocol.to_ascii_lowercase(),
            host: collapse_stars(&host.to_ascii_lowercase()),
            path: path.map(|p| collapse_stars(&p)),
        })
    }
}

impl fmt::Display for UrlPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.protocol, self.host)?;
        if let Some(path) = &self.path {
            write!(f, "/{path}")?;
        }
        Ok(())
    }
}

impl UrlPattern {
    /// `protocol://host`, as used for git's `credential.<url>.*` settings.
    pub fn origin(&self) -> String {
        format!("{}://{}", self.protocol, self.host)
    }

    pub fn has_path(&self) -> bool {
        self.path.is_some()
    }

    pub fn matches(&self, cred: &Credential) -> bool {
        let (Some(protocol), Some(host)) = (cred.protocol(), cred.host()) else {
            return false;
        };
        // A `*` must never stretch over URL syntax: a host such as
        // `intranet#.example.com` would pass `*.example.com`, and a backend
        // that builds a URL from it could answer for `intranet` instead.
        if !is_plain_host(host) {
            return false;
        }
        if !protocol.eq_ignore_ascii_case(&self.protocol) {
            return false;
        }
        if !glob(self.host.as_bytes(), host.to_ascii_lowercase().as_bytes(), b".:") {
            return false;
        }
        let Some(pattern) = &self.path else {
            return true;
        };
        let Some(path) = cred.path() else {
            return false;
        };
        let path = path.trim_matches('/');
        if path.len() > MAX_PATH_BYTES {
            return false;
        }
        // Encoded or URL-syntax characters could hide `..` or another
        // repository behind what the pattern sees.
        if path.contains(['%', '?', '#', '\\']) {
            return false;
        }
        if path.split('/').any(|segment| segment == "." || segment == "..") {
            return false;
        }
        glob(pattern.as_bytes(), path.as_bytes(), b"")
            || path.strip_suffix(".git").is_some_and(|p| glob(pattern.as_bytes(), p.as_bytes(), b""))
    }
}

fn collapse_stars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if !(c == '*' && out.ends_with('*')) {
            out.push(c);
        }
    }
    out
}

/// Whether `host` is a plain `name.domain[:port]` (or `[v6]:port`): only
/// letters, digits, `-`, `_`, `.`, `:` and brackets, and no empty labels.
fn is_plain_host(host: &str) -> bool {
    if host.is_empty() || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.:[]".contains(&b)) {
        return false;
    }
    if host.starts_with('[') {
        return true;
    }
    let name = host.split(':').next().unwrap_or_default();
    !name.split('.').any(str::is_empty)
}

/// git's `credential.<url>` sections for an allow list: each origin, with
/// whether the request path is needed (`useHttpPath`) because a pattern for
/// it names one. Used by ctl and by the helper's `setup`.
pub fn git_sections<'a>(
    patterns: impl IntoIterator<Item = &'a UrlPattern>,
) -> std::collections::BTreeMap<String, bool> {
    let mut sections = std::collections::BTreeMap::new();
    for pattern in patterns {
        *sections.entry(pattern.origin()).or_insert(false) |= pattern.has_path();
    }
    sections
}

/// Longest request path the patterns are matched against; longer requests
/// are refused instead of spending time on them.
pub const MAX_PATH_BYTES: usize = 4096;

/// Glob match where `*` matches any run of bytes, including none.
///
/// Iterative with a single backtrack point, so it runs in
/// O(len(pattern) x len(text)) even for patterns with many stars on long,
/// remote-controlled input.
fn glob_bytes(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, t));
            p += 1;
        } else if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some((star_p, star_t)) = star {
            // Let the last star swallow one more byte and retry from there.
            p = star_p + 1;
            t = star_t + 1;
            star = Some((star_p, star_t + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&b| b == b'*')
}

/// Like [`glob_bytes`], but `*` never matches one of `stops`: pattern and
/// text are cut at their stop bytes, which must line up one to one.
fn glob(pattern: &[u8], text: &[u8], stops: &[u8]) -> bool {
    if stops.is_empty() {
        return glob_bytes(pattern, text);
    }
    let separators = |s: &[u8]| s.iter().copied().filter(|b| stops.contains(b)).collect::<Vec<u8>>();
    if separators(pattern) != separators(text) {
        return false;
    }
    pattern.split(|b| stops.contains(b)).zip(text.split(|b| stops.contains(b))).all(|(p, t)| glob_bytes(p, t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches_like_before() {
        for (p, t, ok) in [
            ("*", "", true),
            ("a*c", "abbbc", true),
            ("a*c", "abbb", false),
            ("*-team/*", "core-team/repo", true),
            ("*-team/*", "core/repo", false),
            ("my-org/*", "my-org/a/b", true),
            ("x*y*z", "xaaybbz", true),
            ("x*y*z", "xaaybb", false),
            ("a*b*c", "aXbYbZc", true),
        ] {
            assert_eq!(glob_bytes(p.as_bytes(), t.as_bytes()), ok, "{p} vs {t}");
        }
        assert!(glob(b"*.example.com", b"git.example.com", b".:"));
        assert!(!glob(b"*.example.com", b"a.b.example.com", b".:"));
        assert!(!glob(b"*.example.com", b"git.example.com:22", b".:"));
        assert!(glob(b"host:*", b"host:8443", b".:"));
    }

    #[test]
    fn glob_stays_fast_on_hostile_input() {
        // The old recursive version needed billions of steps for this.
        let text = "a".repeat(60_000);
        let started = std::time::Instant::now();
        assert!(!glob_bytes(b"*-team/*-x/*-y/*z", text.as_bytes()));
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "took {:?}", started.elapsed());
    }

    #[test]
    fn wildcards_do_not_stretch_over_url_syntax() {
        let pattern: UrlPattern = "https://*.example.com".parse().unwrap();
        let mut cred = Credential::new();
        cred.set("protocol", "https");
        for (host, ok) in [
            ("git.example.com", true),
            ("intranet#.example.com", false),
            ("intranet/x.example.com", false),
            ("me@x.example.com", false),
            (".example.com", false),
            ("a..example.com", false),
            ("$(curl evil).example.com", false),
        ] {
            cred.set("host", host);
            assert_eq!(pattern.matches(&cred), ok, "{host}");
        }
        let pattern: UrlPattern = "https://github.com/org/*".parse().unwrap();
        for (path, ok) in
            [("org/repo", true), ("org/%2e%2e/other/repo", false), ("org/a?x", false), ("org/a#b", false)]
        {
            let mut cred = Credential::from_url("https://github.com").unwrap();
            cred.set("path", path);
            assert_eq!(pattern.matches(&cred), ok, "{path}");
        }
    }

    #[test]
    fn git_sections_merge_origins() {
        let patterns: Vec<UrlPattern> =
            ["https://github.com", "https://github.com/org/*", "https://**.example.org"]
                .iter()
                .map(|p| p.parse().unwrap())
                .collect();
        assert_eq!(
            git_sections(&patterns).into_iter().collect::<Vec<_>>(),
            [("https://*.example.org".to_owned(), false), ("https://github.com".to_owned(), true)]
        );
    }

    #[test]
    fn overlong_paths_never_match() {
        let pattern: UrlPattern = "https://github.com/*".parse().unwrap();
        let ok = Credential::from_url(&format!("https://github.com/{}", "a".repeat(100))).unwrap();
        let long =
            Credential::from_url(&format!("https://github.com/{}", "a".repeat(MAX_PATH_BYTES + 1))).unwrap();
        assert!(pattern.matches(&ok));
        assert!(!pattern.matches(&long));
    }
}
