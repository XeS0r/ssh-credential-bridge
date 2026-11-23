//! Errors of the git worker.

use credential_bridge_proto::ipc::{WorkerError, WorkerErrorKind};

/// Making a token failed. `Display` is safe to show on the server.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ForgeError {
    /// Getting a secret failed (from the vault worker, passed on unchanged).
    #[error("{}", .0.message)]
    Secret(WorkerError),
    /// The request cannot be served, e.g. an App rule with `per = "repo"` and no path
    /// (git config lacks `useHttpPath`).
    #[error("{0}")]
    Invalid(String),
    /// The private key is not a valid RSA PEM key, or signing the JWT failed.
    #[error("GitHub App private key: {0}")]
    Jwt(String),
    /// The App has no installation for the owner.
    #[error("GitHub App {app_id} is not installed for {owner}")]
    NotInstalled {
        /// The App ID.
        app_id: u64,
        /// The owner from the path.
        owner: String,
    },
    /// The API answered with an error status; `message` is GitHub's `message` field.
    #[error("{api} answered {status}: {message}")]
    Api {
        /// The API base URL.
        api: String,
        /// HTTP status.
        status: u16,
        /// The error message from the response body.
        message: String,
    },
    /// Connecting, TLS or reading the response failed.
    #[error("cannot reach {api}: {message}")]
    Network {
        /// The API base URL.
        api: String,
        /// What failed.
        message: String,
    },
}

impl From<ForgeError> for WorkerError {
    fn from(error: ForgeError) -> Self {
        let kind = match &error {
            ForgeError::Secret(inner) => return inner.clone(),
            ForgeError::Invalid(_) | ForgeError::Jwt(_) => WorkerErrorKind::Invalid,
            ForgeError::NotInstalled { .. } => WorkerErrorKind::NotFound,
            ForgeError::Api { status: 401 | 403 | 422, .. } => WorkerErrorKind::Denied,
            ForgeError::Api { status: 404, .. } => WorkerErrorKind::NotFound,
            ForgeError::Api { .. } => WorkerErrorKind::Upstream,
            ForgeError::Network { .. } => WorkerErrorKind::Unavailable,
        };
        WorkerError::new(kind, error.to_string())
    }
}
