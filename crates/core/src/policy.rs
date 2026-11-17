//! Per-remote access policy.

use credential_bridge_proto::{Credential, Operation};
pub use credential_bridge_proto::{PatternError, UrlPattern};

/// What a remote may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub allow: Vec<UrlPattern>,
    pub operations: Vec<Operation>,
}

/// Result of [`Policy::check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
}

impl Policy {
    pub fn check(&self, operation: Operation, cred: &Credential) -> Decision {
        if !self.operations.contains(&operation) {
            return Decision::Deny(format!("operation '{operation}' is not permitted for this remote"));
        }
        if cred.protocol().is_none() || cred.host().is_none() {
            return Decision::Deny("request carries no protocol or host".to_owned());
        }
        if self.allow.iter().any(|pattern| pattern.matches(cred)) {
            Decision::Allow
        } else {
            Decision::Deny(format!("{} is not in this remote's allow list", describe(cred)))
        }
    }
}

/// `protocol://host/path` of a request, for log and error messages.
pub fn describe(cred: &Credential) -> String {
    let mut out = format!("{}://{}", cred.protocol().unwrap_or("?"), cred.host().unwrap_or("?"));
    if let Some(path) = cred.path() {
        out.push('/');
        out.push_str(path);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(u: &str) -> Credential {
        Credential::from_url(u).unwrap()
    }

    fn pattern(p: &str) -> UrlPattern {
        p.parse().unwrap()
    }

    #[test]
    fn parses_patterns() {
        assert_eq!(pattern("HTTPS://GitHub.com/").to_string(), "https://github.com");
        assert_eq!(pattern("https://github.com/org/**").to_string(), "https://github.com/org/*");
        assert_eq!(pattern("https://github.com/org/*").origin(), "https://github.com");
        for bad in ["github.com", "://github.com", "https://", "https://user@github.com", "ht tp://x"] {
            assert!(bad.parse::<UrlPattern>().is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn host_matching() {
        let p = pattern("https://github.com");
        assert!(p.matches(&url("https://github.com/any/repo")));
        assert!(p.matches(&url("https://GITHUB.com")));
        assert!(!p.matches(&url("http://github.com")));
        assert!(!p.matches(&url("https://github.com.evil.com")));
        assert!(!p.matches(&url("https://github.com:8443")));

        let p = pattern("https://*.example.com");
        assert!(p.matches(&url("https://git.example.com")));
        assert!(!p.matches(&url("https://a.b.example.com")));
        assert!(!p.matches(&url("https://example.com")));
        assert!(!p.matches(&url("https://git.example.com:22")));
    }

    #[test]
    fn path_matching() {
        let p = pattern("https://github.com/my-org/*");
        assert!(p.matches(&url("https://github.com/my-org/repo.git")));
        assert!(p.matches(&url("https://github.com/my-org/sub/repo")));
        assert!(!p.matches(&url("https://github.com/other-org/repo")));
        assert!(!p.matches(&url("https://github.com/my-org/../other/repo")));
        assert!(!p.matches(&url("https://github.com")), "path required when the pattern has one");

        let p = pattern("https://github.com/my-org/repo");
        assert!(p.matches(&url("https://github.com/my-org/repo.git")));
        assert!(!p.matches(&url("https://github.com/my-org/repo2")));
    }

    #[test]
    fn policy_checks_operation_and_allow_list() {
        let policy = Policy { allow: vec![pattern("https://github.com")], operations: vec![Operation::Get] };
        assert_eq!(policy.check(Operation::Get, &url("https://github.com/x/y")), Decision::Allow);
        assert!(matches!(policy.check(Operation::Store, &url("https://github.com")), Decision::Deny(_)));
        assert!(matches!(policy.check(Operation::Get, &url("https://gitlab.com")), Decision::Deny(_)));
        assert!(matches!(policy.check(Operation::Get, &Credential::new()), Decision::Deny(_)));
    }
}
