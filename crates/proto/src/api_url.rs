//! The one check of GitHub API base URLs (`api_url` of an App source), used by config
//! validation and by the forge client before every request.
//!
//! The git worker's sandbox lets it connect to TCP port 443 only, so the URL must be
//! `https` on port 443: any other port, and plain `http` (port 80), could never be
//! reached. The URL is parsed with the `url` crate as `reqwest` parses it, so both agree
//! on scheme, host and port.

use url::{Host, ParseError, Url};

/// Checks a GitHub REST API base URL: `https://<host>[:443][/path]`, without user
/// information, query or fragment. The host is an IP address or a DNS name of letters,
/// digits and hyphens without a trailing dot.
///
/// The URL must be used exactly as given: the `url` crate drops whitespace at either end
/// and tabs and line breaks anywhere, but the forge client builds its request URLs from
/// the string itself, so such characters are refused here.
///
/// Errors: a short reason, to be shown after the URL.
pub fn check(api_url: &str) -> Result<(), &'static str> {
    const HTTPS: &str = "must use https:// (the git worker's sandbox only allows port 443)";
    if api_url.trim() != api_url || api_url.chars().any(char::is_control) {
        return Err("must not have whitespace at either end or contain control characters");
    }
    let url = Url::parse(api_url).map_err(|error| match error {
        ParseError::RelativeUrlWithoutBase => HTTPS,
        ParseError::EmptyHost
        | ParseError::IdnaError
        | ParseError::InvalidDomainCharacter
        | ParseError::InvalidIpv4Address
        | ParseError::InvalidIpv6Address => "has an invalid host",
        ParseError::InvalidPort => "has an invalid port",
        _ => "is not a valid URL",
    })?;
    if url.scheme() != "https" {
        return Err(HTTPS);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("must not contain user information, a query or a fragment");
    }
    match url.host() {
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => {}
        Some(Host::Domain(domain)) if valid_dns_name(domain) => {}
        _ => return Err("has an invalid host"),
    }
    if url.port_or_known_default() != Some(443) {
        return Err("must use port 443: the git worker's sandbox only allows connections to TCP port 443");
    }
    Ok(())
}

/// A DNS name as the `url` crate normalises it (lower case, IDNA applied): labels of
/// letters, digits and inner hyphens, at most 63 bytes each, no empty label (so no
/// trailing dot).
fn valid_dns_name(domain: &str) -> bool {
    domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_on_port_443() {
        for good in [
            "https://api.github.com",
            "https://ghe.example.com/api/v3",
            "https://ghe.example.com:443/api/v3",
            "https://[::1]",
            "https://[::1]:443/api",
            "https://127.0.0.1",
            "https://xn--bcher-kva.example",
            // The url crate (and reqwest) read these as https on port 443.
            "HTTPS://h.com",
            "https://h.com:",
            "https://h.com:0443",
        ] {
            assert_eq!(check(good), Ok(()), "{good}");
        }
    }

    #[test]
    fn rejects_everything_else_with_a_reason() {
        for (bad, hint) in [
            ("https://ghe.example.com:8443/api/v3", "port 443"),
            ("https://[::1]:8080", "port 443"),
            ("https://h.com:0", "port 443"),
            ("https://h.com:99999", "invalid port"),
            ("http://127.0.0.1:8080", "https://"),
            ("http://localhost:1234/api", "https://"),
            ("http://[::1]:8080", "https://"),
            ("http://api.github.com", "https://"),
            ("ftp://api.github.com", "https://"),
            ("api.github.com", "https://"),
            ("https://", "invalid host"),
            ("https://bad host", "invalid host"),
            ("https://h.com.", "invalid host"),
            ("https://a..b", "invalid host"),
            ("https://-a.com", "invalid host"),
            ("https://under_score.com", "invalid host"),
            ("https://[1::2::3]", "invalid host"),
            ("https://999.1.1.1", "invalid host"),
            ("https://user@api.github.com", "user information"),
            ("https://user:pw@api.github.com", "user information"),
            ("https://api.github.com/?x=1", "query"),
            ("https://api.github.com?x=1", "query"),
            ("https://api.github.com#top", "fragment"),
            ("not a url", "https://"),
            (" https://api.github.com", "whitespace"),
            ("https://api.github.com ", "whitespace"),
            ("https://api.github.com\t", "whitespace"),
            ("\thttps://api.github.com", "whitespace"),
            ("https://api.github.com\n", "whitespace"),
            ("https://api.git\thub.com", "control characters"),
            ("https://ghe.example.com/api\n/v3", "control characters"),
            ("https://api.github.com\u{7f}", "control characters"),
        ] {
            let why = check(bad).expect_err(bad);
            assert!(why.contains(hint), "{bad}: {why}");
        }
    }
}
