//! URL patterns of git rules and the targets they match.
//!
//! A pattern is `<scheme>://<host>[:<port>][/<path>]`:
//!
//! - scheme and host compare case-insensitively and exactly (no host wildcards);
//! - without a path the pattern matches every path on the host, also none;
//! - with a path, it is split at `/` and compared segment by segment: a `*` segment
//!   matches exactly one segment, except as the last segment, where it matches one or
//!   more; other segments compare exactly (case-sensitive);
//! - a pattern with a path never matches a target without a path;
//! - a target path's trailing `/` and `.git` suffix are removed before matching;
//! - a target path with an empty, `.` or `..` segment, a `%` or a `\` is rejected
//!   ([`GitTarget::parse_credential`], [`GitTarget::parse_url`]) and never matches, so
//!   `team-a/../team-b/repo` cannot pass for `team-a/*`.
//!
//! git percent-decodes the URL path before it asks a credential helper (checked with git
//! 2.56): `team-a/%2e%2e/team-b` arrives as `team-a/../team-b` and is rejected for its
//! `..` segment, `My%20Project` arrives as `My Project`. Patterns are compared with this
//! decoded path. A pattern may contain neither whitespace nor `%`, so a path with a space
//! (Azure DevOps projects, for example) can only be matched by a host-only pattern or by
//! `*` segments. [`GitTarget::parse_url`] (`ctl server token`) decodes the path of its URL
//! once in the same way, so it tests the path git would send.
//!
//! Examples: `https://github.com/my-org/*` matches `my-org/app.git` and
//! `my-org/group/sub`, not `my-org` or `other/app`.

use std::fmt;

use credential_bridge_proto::credential::Credential;

/// Error of parsing a pattern or URL.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid URL pattern {input:?}: {reason}")]
pub struct PatternError {
    /// The input.
    pub input: String,
    /// Why it is invalid.
    pub reason: &'static str,
}

/// What git asks a credential for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GitTarget {
    /// Scheme, lower case (`https`).
    pub protocol: String,
    /// Host, lower case, with `:port` if given.
    pub host: String,
    /// Path without leading `/`, trailing `/` and `.git`, and without empty, `.` or
    /// `..` segments, `%` or `\`; `None` if git sent none. [`GitTarget::parse_credential`]
    /// and [`GitTarget::parse_url`] normalise it once; [`UrlPattern::matches`] compares it
    /// as it is.
    pub path: Option<String>,
}

impl GitTarget {
    /// Builds a target from git's attributes (sent by the server, so untrusted).
    ///
    /// Errors: `protocol` or `host` is missing or empty, or the path has an empty, `.` or
    /// `..` segment, a `%` or a `\` (see the module documentation). The error's `input`
    /// is the offending attribute.
    pub fn parse_credential(credential: &Credential) -> Result<GitTarget, PatternError> {
        let error = |input: Option<&str>, reason| PatternError {
            input: input.unwrap_or_default().to_owned(),
            reason,
        };
        let protocol = credential
            .protocol
            .as_deref()
            .filter(|p| !p.is_empty())
            .ok_or_else(|| error(None, "missing protocol"))?;
        let host = credential
            .host
            .as_deref()
            .filter(|h| !h.is_empty())
            .ok_or_else(|| error(None, "missing host"))?;
        let path = match credential.path.as_deref() {
            Some(path) => check_target_path(path).map_err(|reason| error(Some(path), reason))?,
            None => None,
        };
        Ok(GitTarget { protocol: protocol.to_ascii_lowercase(), host: host.to_ascii_lowercase(), path })
    }

    /// Parses `scheme://host[:port][/path]` (as `ctl server token` takes it) into the
    /// target git would ask for: the path is percent-decoded once, as git does before it
    /// asks a credential helper, and then checked as [`GitTarget::parse_credential`]
    /// checks git's path. `https://dev.azure.com/org/My%20Project/_git/repo` has the path
    /// `org/My Project/_git/repo`; `a/%2e%2e/b` is refused for its `..` segment.
    ///
    /// Errors on a missing scheme or host, userinfo, query or fragment, whitespace or
    /// control characters in scheme and host, control characters in the path (also
    /// decoded ones), and on a decoded path that [`GitTarget::parse_credential`] rejects.
    pub fn parse_url(url: &str) -> Result<GitTarget, PatternError> {
        let error = |reason| PatternError { input: url.to_owned(), reason };
        let (head, path) = split_off_path(url);
        let parts = split_url(head).map_err(error)?;
        if path.contains('?') {
            return Err(error("a query (?) is not allowed"));
        }
        if path.contains('#') {
            return Err(error("a fragment (#) is not allowed"));
        }
        let decoded = percent_decode(path).map_err(error)?;
        if path.chars().chain(decoded.chars()).any(char::is_control) {
            return Err(error("control characters are not allowed in the path"));
        }
        let path = check_target_path(&decoded).map_err(error)?;
        Ok(GitTarget { protocol: parts.scheme, host: parts.host, path })
    }

    /// First path segment (the owner on GitHub), if there is a path.
    pub fn owner(&self) -> Option<&str> {
        self.path.as_deref().and_then(|path| path.split('/').next())
    }

    /// Last path segment (the repository name), if the path has at least two segments.
    pub fn repo(&self) -> Option<&str> {
        let path = self.path.as_deref()?;
        path.rsplit_once('/').map(|(_, repo)| repo)
    }
}

/// A parsed URL pattern; see the module documentation for the matching rules.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UrlPattern {
    /// The pattern as written.
    raw: String,
    /// Scheme, lower case.
    scheme: String,
    /// Host, lower case, with `:port` if given.
    host: String,
    /// Path segments (`.git` removed from the last one); `None` without a path.
    path: Option<Vec<Segment>>,
}

/// One segment of a pattern path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Segment {
    /// `*`.
    Wildcard,
    /// A literal segment, compared exactly.
    Literal(String),
}

impl UrlPattern {
    /// Parses a pattern.
    ///
    /// Errors: missing scheme or host, userinfo, query or fragment, empty path segments,
    /// `*` mixed with other characters in a segment, `*` in the host.
    ///
    /// A trailing `/` is ignored, as is a `.git` suffix of the last segment, so that
    /// patterns compare like the targets they are matched against.
    pub fn parse(input: &str) -> Result<UrlPattern, PatternError> {
        let error = |reason| PatternError { input: input.to_owned(), reason };
        let parts = split_url(input).map_err(error)?;
        let path = parts.path.strip_suffix('/').unwrap_or(parts.path);
        let path = if path.is_empty() {
            None
        } else {
            let raw_segments: Vec<&str> = path.split('/').collect();
            let last = raw_segments.len() - 1;
            let mut segments = Vec::with_capacity(raw_segments.len());
            for (i, segment) in raw_segments.into_iter().enumerate() {
                if segment.is_empty() {
                    return Err(error("empty path segment (double /)"));
                }
                if segment == "." || segment == ".." {
                    return Err(error("`.` and `..` path segments are not allowed"));
                }
                if segment.contains(['%', '\\']) {
                    return Err(error("`%` and `\\` are not allowed in the path"));
                }
                if segment == "*" {
                    segments.push(Segment::Wildcard);
                } else if segment.contains('*') {
                    return Err(error("`*` must be a whole path segment"));
                } else {
                    let segment =
                        if i == last { segment.strip_suffix(".git").unwrap_or(segment) } else { segment };
                    if segment.is_empty() {
                        return Err(error("empty repository name before .git"));
                    }
                    segments.push(Segment::Literal(segment.to_owned()));
                }
            }
            Some(segments)
        };
        Ok(UrlPattern { raw: input.to_owned(), scheme: parts.scheme, host: parts.host, path })
    }

    /// A pattern that matches nothing, standing in for one that failed to parse while
    /// the remaining configuration is checked. Never part of a returned `Config`.
    pub(crate) fn unparsed(raw: &str) -> UrlPattern {
        UrlPattern { raw: raw.to_owned(), scheme: String::new(), host: String::new(), path: None }
    }

    /// Whether the pattern matches `target`.
    pub fn matches(&self, target: &GitTarget) -> bool {
        if self.host.is_empty()
            || !self.scheme.eq_ignore_ascii_case(&target.protocol)
            || !self.host.eq_ignore_ascii_case(&target.host)
        {
            return false;
        }
        let Some(pattern) = &self.path else { return true };
        // Already normalised when the target was parsed: normalising again would strip
        // a second `.git` (`org/a.git.git` arrives as `org/a.git`). Only checked, so that
        // a target built by hand with a `..` segment never matches.
        let Some(path) = target.path.as_deref().filter(|path| path_problem(path).is_none()) else {
            return false;
        };
        let target: Vec<&str> = path.split('/').collect();
        let last = pattern.len() - 1;
        for (i, segment) in pattern.iter().enumerate() {
            match segment {
                Segment::Wildcard if i == last => {
                    let rest = target.get(i..).unwrap_or_default();
                    return !rest.is_empty() && rest.iter().all(|s| !s.is_empty());
                }
                Segment::Wildcard => {
                    if target.get(i).is_none_or(|s| s.is_empty()) {
                        return false;
                    }
                }
                Segment::Literal(literal) => {
                    if target.get(i) != Some(&literal.as_str()) {
                        return false;
                    }
                }
            }
        }
        target.len() == pattern.len()
    }

    /// The pattern's host (lower case, with port).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The pattern's scheme (lower case).
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// `Some(owner)` if the pattern has exactly the form `<scheme>://<host>/<owner>/*`;
    /// only such rules may use `per = "owner"`.
    pub fn owner_wildcard(&self) -> Option<&str> {
        match self.path.as_deref()? {
            [Segment::Literal(owner), Segment::Wildcard] => Some(owner),
            _ => None,
        }
    }

    /// Whether the pattern has a path, so matching needs git's `useHttpPath`.
    pub fn has_path(&self) -> bool {
        self.path.is_some()
    }

    /// The pattern as written.
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl fmt::Display for UrlPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

/// A URL split into its parts; scheme and host lower case, path without leading `/`.
struct UrlParts<'a> {
    scheme: String,
    host: String,
    path: &'a str,
}

/// Splits `scheme://host[:port][/path]`, rejecting what neither patterns nor targets
/// may contain.
fn split_url(input: &str) -> Result<UrlParts<'_>, &'static str> {
    if input.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("whitespace and control characters are not allowed");
    }
    let (scheme, rest) = input.split_once("://").ok_or("missing scheme, expected e.g. https://host/path")?;
    if !valid_scheme(scheme) {
        return Err("invalid scheme");
    }
    if rest.contains('?') {
        return Err("a query (?) is not allowed");
    }
    if rest.contains('#') {
        return Err("a fragment (#) is not allowed");
    }
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() {
        return Err("missing host");
    }
    if authority.contains('@') {
        return Err("user information (user@) is not allowed");
    }
    if authority.contains('*') {
        return Err("wildcards are not allowed in the host");
    }
    if !valid_host(authority) {
        return Err("invalid host");
    }
    Ok(UrlParts { scheme: scheme.to_ascii_lowercase(), host: authority.to_ascii_lowercase(), path })
}

/// Splits `scheme://host[:port]/path` before the `/` that starts the path; the path
/// part is empty without one.
fn split_off_path(input: &str) -> (&str, &str) {
    let Some(scheme_end) = input.find("://").map(|at| at + 3) else { return (input, "") };
    match input[scheme_end..].find('/') {
        Some(at) => input.split_at(scheme_end + at),
        None => (input, ""),
    }
}

/// Decodes every `%XX` (two hex digits) once, as git does with a URL path; a `%` not
/// followed by two hex digits stays as it is
/// ([`credential_bridge_proto::text::percent_decode_bytes`]).
///
/// Errors if the decoded bytes are not UTF-8.
fn percent_decode(path: &str) -> Result<String, &'static str> {
    String::from_utf8(credential_bridge_proto::text::percent_decode_bytes(path))
        .map_err(|_| "the decoded path is not UTF-8")
}

/// `[A-Za-z][A-Za-z0-9+.-]*`.
fn valid_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Whether `host` is `name[:port]` or `[ipv6][:port]`, with a DNS-like name of
/// non-empty dot-separated labels of `[A-Za-z0-9_-]` and a port in 1..=65535.
pub(crate) fn valid_host(host: &str) -> bool {
    let (name, port) = if let Some(rest) = host.strip_prefix('[') {
        let Some((addr, after)) = rest.split_once(']') else { return false };
        if addr.is_empty() || !addr.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.') {
            return false;
        }
        match after {
            "" => return true,
            _ => match after.strip_prefix(':') {
                Some(port) => return valid_port(port),
                None => return false,
            },
        }
    } else {
        match host.split_once(':') {
            Some((name, port)) => (name, Some(port)),
            None => (host, None),
        }
    };
    let name_ok = !name.is_empty()
        && name.split('.').all(|label| {
            !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        });
    name_ok && port.is_none_or(valid_port)
}

fn valid_port(port: &str) -> bool {
    !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) && port.parse::<u16>().is_ok_and(|p| p != 0)
}

/// Removes a leading `/`, trailing `/` and a `.git` suffix; `Ok(None)` if nothing is
/// left. Errors if what is left has an empty, `.` or `..` segment, a `%` or a `\`.
///
/// git has already percent-decoded the path (`%2e%2e` arrives as `..` and fails the
/// segment check; [`GitTarget::parse_url`] decodes it the same way), so a `%` here is a
/// literal one, from `%25` in the URL. It is refused
/// so that no component that decodes once more could turn `%252e%252e` into `..`.
fn check_target_path(path: &str) -> Result<Option<String>, &'static str> {
    if path.contains(['%', '\\']) {
        return Err(ESCAPES_IN_PATH);
    }
    let path = path.trim_start_matches('/').trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path).trim_end_matches('/');
    if path.is_empty() {
        return Ok(None);
    }
    match path_problem(path) {
        Some(problem) => Err(problem),
        None => Ok(Some(path.to_owned())),
    }
}

const ESCAPES_IN_PATH: &str = "`%` and `\\` are not allowed in the path";

/// What is wrong with a normalised target path: a `%` or `\`, or an empty, `.` or `..`
/// segment (which a leading or trailing `/` makes). `None` if nothing.
fn path_problem(path: &str) -> Option<&'static str> {
    if path.contains(['%', '\\']) {
        return Some(ESCAPES_IN_PATH);
    }
    path.split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        .then_some("the path has an empty, `.` or `..` segment")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(url: &str) -> GitTarget {
        GitTarget::parse_url(url).unwrap_or_else(|e| panic!("{e}"))
    }

    fn pattern(p: &str) -> UrlPattern {
        UrlPattern::parse(p).unwrap_or_else(|e| panic!("{e}"))
    }

    /// The target path is normalised once, when it is parsed: a repository named
    /// `a.git` (URL `org/a.git.git`) is `org/a.git` and matches only a pattern for it.
    #[test]
    fn target_paths_are_normalised_once() {
        let doubled = target("https://github.com/org/a.git.git");
        assert_eq!(doubled.path.as_deref(), Some("org/a.git"));
        assert!(pattern("https://github.com/org/a.git.git").matches(&doubled));
        assert!(!pattern("https://github.com/org/a").matches(&doubled));
        assert!(!pattern("https://github.com/org/a.git").matches(&doubled));
        assert!(pattern("https://github.com/org/*").matches(&doubled));

        let credential = Credential {
            protocol: Some("https".into()),
            host: Some("github.com".into()),
            path: Some("org/a.git.git/".into()),
            ..Credential::default()
        };
        let from_git = GitTarget::parse_credential(&credential).unwrap();
        assert_eq!(from_git, doubled);
        assert!(!pattern("https://github.com/org/a").matches(&from_git));

        let plain = target("https://github.com/org/a.git");
        assert!(pattern("https://github.com/org/a").matches(&plain));
        assert!(pattern("https://github.com/org/a.git").matches(&plain));
        assert!(!pattern("https://github.com/org/a.git.git").matches(&plain));
    }

    /// The path is decoded once, strictly: invalid UTF-8 is an error, not replaced.
    #[test]
    fn url_paths_are_decoded_once_and_strictly() {
        assert_eq!(percent_decode("a%20b%2fc"), Ok("a b/c".to_owned()));
        assert_eq!(percent_decode("100%"), Ok("100%".to_owned()));
        assert_eq!(percent_decode("%c3%a4"), Ok("ä".to_owned()));
        assert_eq!(percent_decode("%ff"), Err("the decoded path is not UTF-8"));
        assert_eq!(percent_decode("a+b"), Ok("a+b".to_owned()));
    }

    #[test]
    fn module_examples() {
        let p = pattern("https://github.com/my-org/*");
        assert!(p.matches(&target("https://github.com/my-org/app.git")));
        assert!(p.matches(&target("https://github.com/my-org/group/sub")));
        assert!(!p.matches(&target("https://github.com/my-org")));
        assert!(!p.matches(&target("https://github.com/other/app")));
    }

    #[test]
    fn host_only_pattern_matches_any_path_and_none() {
        let p = pattern("https://github.com");
        assert!(!p.has_path());
        assert!(p.matches(&target("https://github.com")));
        assert!(p.matches(&target("https://github.com/a/b")));
        assert!(!p.matches(&target("https://gitlab.com/a/b")));
        assert!(!p.matches(&target("http://github.com/a/b")));
        assert!(pattern("https://github.com/").matches(&target("https://github.com/x")));
    }

    #[test]
    fn scheme_and_host_are_case_insensitive_and_exact() {
        let p = pattern("HTTPS://GitHub.com/Org/*");
        assert_eq!(p.host(), "github.com");
        assert_eq!(p.scheme(), "https");
        assert!(p.matches(&target("https://github.com/Org/x")));
        assert!(!p.matches(&target("https://github.com/org/x")), "path is case-sensitive");
        assert!(!p.matches(&target("https://api.github.com/Org/x")));
        assert!(!p.matches(&target("https://github.com:8443/Org/x")));
        let with_port = pattern("https://git.example.com:8443/team/*");
        assert_eq!(with_port.host(), "git.example.com:8443");
        assert!(with_port.matches(&target("https://git.example.com:8443/team/x")));
        assert!(!with_port.matches(&target("https://git.example.com/team/x")));
    }

    #[test]
    fn path_pattern_needs_target_path() {
        let p = pattern("https://github.com/my-org/*");
        let no_path = GitTarget { protocol: "https".into(), host: "github.com".into(), path: None };
        assert!(!p.matches(&no_path));
    }

    #[test]
    fn inner_wildcard_matches_exactly_one_segment() {
        let p = pattern("https://gitlab.example.com/*/infra");
        assert!(p.matches(&target("https://gitlab.example.com/team/infra.git")));
        assert!(!p.matches(&target("https://gitlab.example.com/team/sub/infra")));
        assert!(!p.matches(&target("https://gitlab.example.com/infra")));
        assert!(!p.matches(&target("https://gitlab.example.com/team/infra/x")));
    }

    #[test]
    fn exact_path_pattern() {
        let p = pattern("https://github.com/my-org/app.git");
        assert!(p.matches(&target("https://github.com/my-org/app")));
        assert!(p.matches(&target("https://github.com/my-org/app.git/")));
        assert!(!p.matches(&target("https://github.com/my-org/app2")));
        assert!(!p.matches(&target("https://github.com/my-org/app/x")));
        assert_eq!(p.owner_wildcard(), None);
    }

    /// Matching takes the path as parsing normalised it; a target built by hand with a
    /// path that was not normalised does not match.
    #[test]
    fn target_path_is_normalized_when_parsed() {
        let p = pattern("https://github.com/o/r");
        assert!(p.matches(&target("https://github.com/o/r.git/")));
        let t =
            GitTarget { protocol: "https".into(), host: "github.com".into(), path: Some("/o/r.git/".into()) };
        assert!(!p.matches(&t));
        let t = GitTarget { path: Some("o/r".into()), ..t };
        assert!(p.matches(&t));
    }

    #[test]
    fn owner_wildcard() {
        assert_eq!(pattern("https://github.com/my-org/*").owner_wildcard(), Some("my-org"));
        assert_eq!(pattern("https://github.com/my-org/*/").owner_wildcard(), Some("my-org"));
        assert_eq!(pattern("https://github.com/*").owner_wildcard(), None);
        assert_eq!(pattern("https://github.com/*/*").owner_wildcard(), None);
        assert_eq!(pattern("https://github.com/a/b/*").owner_wildcard(), None);
        assert_eq!(pattern("https://github.com").owner_wildcard(), None);
    }

    #[test]
    fn rejects_invalid_patterns() {
        for (input, hint) in [
            ("github.com/x", "missing scheme"),
            ("://github.com", "invalid scheme"),
            ("1https://github.com", "invalid scheme"),
            ("https://", "missing host"),
            ("https:///x", "missing host"),
            ("https://user@github.com/x", "user information"),
            ("https://github.com/x?y=1", "query"),
            ("https://github.com/x#frag", "fragment"),
            ("https://*.github.com/x", "wildcards"),
            ("https://github.com//x", "empty path segment"),
            ("https://github.com/a//b", "empty path segment"),
            ("https://github.com/my-*", "whole path segment"),
            ("https://github.com/.git", "empty repository name"),
            ("https://github.com:0/x", "invalid host"),
            ("https://github.com:99999/x", "invalid host"),
            ("https://git hub.com/x", "whitespace"),
            ("https://github..com/x", "invalid host"),
        ] {
            let err = UrlPattern::parse(input).expect_err(input);
            assert!(err.reason.contains(hint), "{input:?}: {} does not mention {hint:?}", err.reason);
            assert!(err.to_string().contains(input));
        }
    }

    #[test]
    fn ipv6_hosts() {
        let p = pattern("https://[::1]:8443/x/*");
        assert_eq!(p.host(), "[::1]:8443");
        assert!(p.matches(&target("https://[::1]:8443/x/y")));
        assert!(UrlPattern::parse("https://[::1/x").is_err());
        assert!(UrlPattern::parse("https://[::1]x/x").is_err());
    }

    #[test]
    fn parse_url() {
        let t = target("HTTPS://GitHub.com/my-org/app.git");
        assert_eq!(t.protocol, "https");
        assert_eq!(t.host, "github.com");
        assert_eq!(t.path.as_deref(), Some("my-org/app"));
        assert_eq!(t.owner(), Some("my-org"));
        assert_eq!(t.repo(), Some("app"));

        let t = target("https://github.com");
        assert_eq!(t.path, None);
        assert_eq!(t.owner(), None);
        assert_eq!(t.repo(), None);

        let t = target("https://github.com/only-owner");
        assert_eq!(t.owner(), Some("only-owner"));
        assert_eq!(t.repo(), None);

        let t = target("https://gitlab.com/group/sub/project");
        assert_eq!(t.owner(), Some("group"));
        assert_eq!(t.repo(), Some("project"));

        assert!(GitTarget::parse_url("https://token@github.com/x").is_err());
        assert!(GitTarget::parse_url("github.com/x").is_err());
        assert!(GitTarget::parse_url("https://github.com/x?a").is_err());
    }

    #[test]
    fn parse_credential() {
        let credential = Credential {
            protocol: Some("HTTPS".into()),
            host: Some("GitHub.com".into()),
            path: Some("my-org/app.git".into()),
            ..Credential::default()
        };
        let t = GitTarget::parse_credential(&credential).unwrap();
        assert_eq!(t, target("https://github.com/my-org/app"));

        let no_path = Credential { path: None, ..credential.clone() };
        assert_eq!(GitTarget::parse_credential(&no_path).unwrap().path, None);
        let no_host = Credential { host: None, ..credential.clone() };
        assert_eq!(GitTarget::parse_credential(&no_host).unwrap_err().reason, "missing host");
        let no_protocol = Credential { protocol: None, ..credential };
        assert_eq!(GitTarget::parse_credential(&no_protocol).unwrap_err().reason, "missing protocol");
    }

    #[test]
    fn parse_credential_names_what_is_missing() {
        let credential = Credential {
            protocol: Some("https".into()),
            host: Some("github.com".into()),
            ..Credential::default()
        };
        assert!(GitTarget::parse_credential(&credential).is_ok());
        let err =
            GitTarget::parse_credential(&Credential { host: Some(String::new()), ..credential.clone() })
                .unwrap_err();
        assert_eq!(err.reason, "missing host");
        let err = GitTarget::parse_credential(&Credential { protocol: None, ..credential }).unwrap_err();
        assert_eq!(err.reason, "missing protocol");
    }

    /// Paths git could send that are refused. As URL paths for
    /// [`GitTarget::parse_url`] they are refused too, after decoding, except
    /// `team-a%2fteam-b/repo`, which git decodes to the valid `team-a/team-b/repo`.
    const BAD_TARGET_PATHS: [&str; 12] = [
        "team-a/../team-b/repo",
        "team-a/%2e%2e/team-b/repo",
        "team-a/%2E%2E/team-b/repo",
        "team-a%2fteam-b/repo",
        "team-a/./repo",
        "team-a//repo",
        "team-a/..",
        "../team-a/repo",
        "team-a/..git",
        "team-a\\..\\team-b",
        "team-a/re%po",
        "./team-a/repo",
    ];

    #[test]
    fn target_paths_with_dot_segments_or_escapes_are_rejected() {
        let rule = pattern("https://git.example.com/team-a/*");
        for path in BAD_TARGET_PATHS {
            let credential = Credential {
                protocol: Some("https".into()),
                host: Some("git.example.com".into()),
                path: Some(path.into()),
                ..Credential::default()
            };
            let err = GitTarget::parse_credential(&credential).expect_err(path);
            assert_eq!(err.input, path);
            let url = GitTarget::parse_url(&format!("https://git.example.com/{path}"));
            if path == "team-a%2fteam-b/repo" {
                assert_eq!(url.unwrap().path.as_deref(), Some("team-a/team-b/repo"));
            } else {
                assert!(url.is_err(), "{path}");
            }
            // A target built by hand never matches with a path that is bad as it stands
            // (matching does not normalise again; `team-a/..git` is only bad after the
            // `.git` that parsing removes).
            let target = GitTarget {
                protocol: "https".into(),
                host: "git.example.com".into(),
                path: Some(path.into()),
            };
            if path_problem(path).is_some() {
                assert!(!rule.matches(&target), "{path}");
            }
        }
        assert!(rule.matches(&target("https://git.example.com/team-a/repo.git/")));
        assert!(rule.matches(&target("https://git.example.com/team-a/.hidden/x..y")));
    }

    /// git sends the decoded path: a space arrives as a space. Only host-only and
    /// wildcard patterns can match it, since patterns allow neither spaces nor `%`.
    #[test]
    fn decoded_paths_with_spaces_need_wildcards() {
        let credential = Credential {
            protocol: Some("https".into()),
            host: Some("dev.azure.com".into()),
            path: Some("org/My Project/_git/repo".into()),
            ..Credential::default()
        };
        let target = GitTarget::parse_credential(&credential).unwrap();
        assert_eq!(target.path.as_deref(), Some("org/My Project/_git/repo"));
        assert!(pattern("https://dev.azure.com").matches(&target));
        assert!(pattern("https://dev.azure.com/org/*").matches(&target));
        assert!(pattern("https://dev.azure.com/org/*/_git/repo").matches(&target));
        assert!(UrlPattern::parse("https://dev.azure.com/org/My Project/_git/repo").is_err());
        assert!(UrlPattern::parse("https://dev.azure.com/org/My%20Project/_git/repo").is_err());
    }

    /// `ctl server token` takes a URL as git sees it: the path is decoded once and then
    /// checked as git's path, so it matches what git would send.
    #[test]
    fn parse_url_decodes_the_path_once_like_git() {
        let t = target("https://dev.azure.com/org/My%20Project/_git/repo");
        assert_eq!(t.path.as_deref(), Some("org/My Project/_git/repo"));
        assert!(pattern("https://dev.azure.com/org/*/_git/repo").matches(&t));
        // A literal space is what git would send for it as well.
        assert_eq!(target("https://dev.azure.com/org/My Project/_git/repo"), t);
        assert_eq!(target("https://h.com/a%2Fb").path.as_deref(), Some("a/b"));
        assert_eq!(target("https://h.com/%41pp").path.as_deref(), Some("App"));
        assert_eq!(target("https://h.com/r%C3%A9po").path.as_deref(), Some("répo"));

        for (url, reason) in [
            ("https://h.com/a/%2e%2e/b", "segment"),
            ("https://h.com/a/%2E%2e", "segment"),
            ("https://h.com/a/%2e/b", "segment"),
            ("https://h.com/a%2f%2e%2e%2fb", "segment"),
            ("https://h.com/a/%2f/b", "segment"),
            ("https://h.com/a/%5c..%5cb", "`\\`"),
            // Decoded once only: `%252e%252e` becomes `%2e%2e`, a literal `%`.
            ("https://h.com/a/%252e%252e/b", "`%`"),
            ("https://h.com/a/%25", "`%`"),
            ("https://h.com/a/%zz", "`%`"),
            ("https://h.com/a/%2", "`%`"),
            ("https://h.com/a/%0a/b", "control"),
            ("https://h.com/a/\tb", "control"),
            ("https://h.com/a/%ff", "UTF-8"),
            ("https://h.com/a?x", "query"),
            ("https://h.com/a#x", "fragment"),
            // Scheme and host keep the strict checks.
            ("https://h%2ecom/a", "invalid host"),
            ("https://h .com/a", "whitespace"),
            ("https ://h.com/a", "whitespace"),
        ] {
            let error = GitTarget::parse_url(url).expect_err(url);
            assert!(error.reason.contains(reason), "{url}: {}", error.reason);
        }
    }

    #[test]
    fn patterns_with_dot_segments_or_escapes_are_rejected() {
        for input in [
            "https://github.com/a/../b",
            "https://github.com/./b",
            "https://github.com/a/%2e%2e",
            "https://github.com/a\\b",
        ] {
            assert!(UrlPattern::parse(input).is_err(), "{input}");
        }
    }

    #[test]
    fn unparsed_matches_nothing() {
        let p = UrlPattern::unparsed("garbage");
        assert!(!p.matches(&target("https://github.com/a/b")));
        assert_eq!(p.as_str(), "garbage");
    }
}
