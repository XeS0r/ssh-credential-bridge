//! Errors of loading and validating the configuration.

use std::path::PathBuf;

/// Loading the configuration failed.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file exists but could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The cause.
        source: std::io::Error,
    },
    /// The text is not valid TOML or does not match the schema (unknown keys, wrong
    /// types). `message` is the TOML parser's message including line and column.
    #[error("{path}: {message}")]
    Syntax {
        /// The file, or `<string>` for [`crate::Config::parse`].
        path: PathBuf,
        /// The parser's message.
        message: String,
    },
    /// A configuration from credential-bridge 0.1 (no `version` key, `[[remote]]`
    /// tables). There is no migration; the message points to the documentation.
    #[error(
        "{path} is a credential-bridge 0.1 configuration; the agent proxy uses a new \
         format (version = 2) and does not migrate it, see docs/architecture.md"
    )]
    Legacy {
        /// The file.
        path: PathBuf,
    },
    /// `version` is present but not [`crate::CONFIG_VERSION`].
    #[error("{path}: unsupported configuration version {version}")]
    Version {
        /// The file.
        path: PathBuf,
        /// The version found.
        version: i64,
    },
    /// The file parses but violates rules; every problem found is listed.
    #[error("{path}: {} problem(s): {}", problems.len(), problems.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))]
    Invalid {
        /// The file.
        path: PathBuf,
        /// All problems, in file order where possible.
        problems: Vec<Problem>,
    },
}

/// One validation problem. `location` is a dotted TOML path such as
/// `profile.build.git[0].permissions`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{location}: {message}")]
pub struct Problem {
    /// Where the problem is.
    pub location: String,
    /// What is wrong, as a sentence for `ctl check`.
    pub message: String,
}

impl Problem {
    /// Builds a problem.
    pub fn new(location: impl Into<String>, message: impl Into<String>) -> Self {
        Self { location: location.into(), message: message.into() }
    }
}
