//! The GitHub App manifest flow for `credential-bridge-ctl source add github --auth app --create`.
//!
//! ctl serves a local page that POSTs [`AppManifest`] to GitHub's "new app" form; GitHub
//! redirects back with a temporary `code`, which [`GithubClient::convert_manifest`]
//! exchanges for the App's id and private key. ctl stores the key straight in the vault
//! (via the daemon) and adds the `[source.*]` table; the key never touches the disk.

use credential_bridge_proto::ipc::git::Permissions;
use credential_bridge_proto::secret::Secret;
use serde::Deserialize;

use super::{GithubClient, api_base, check_name};
use crate::ForgeError;

/// The manifest sent to GitHub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppManifest {
    /// App name (must be unique on GitHub).
    pub name: String,
    /// Homepage URL.
    pub url: String,
    /// Where GitHub redirects with the code (ctl's loopback listener).
    pub redirect_url: String,
    /// Whether other accounts may install it.
    pub public: bool,
    /// Requested permissions (become the source's `max_permissions`).
    pub default_permissions: Permissions,
}

impl AppManifest {
    /// The manifest JSON as GitHub expects it (`hook_attributes.active = false`, no
    /// events).
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "name": self.name,
            "url": self.url,
            "redirect_url": self.redirect_url,
            "public": self.public,
            "default_permissions": self.default_permissions,
            "default_events": [],
            "hook_attributes": { "url": self.url, "active": false },
        })
        .to_string()
    }
}

/// Where to POST the manifest: `<web_url>/settings/apps/new` or, for an organisation,
/// `<web_url>/organizations/<org>/settings/apps/new`.
pub fn new_app_url(web_url: &str, organization: Option<&str>) -> String {
    let web = web_url.trim_end_matches('/');
    match organization {
        Some(org) => format!("{web}/organizations/{org}/settings/apps/new"),
        None => format!("{web}/settings/apps/new"),
    }
}

/// What the conversion returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppCredentials {
    /// The App ID.
    pub id: u64,
    /// The App slug.
    pub slug: String,
    /// The account that owns it.
    pub owner: String,
    /// The App's page.
    pub html_url: String,
    /// The PEM private key.
    pub pem: Secret,
}

impl GithubClient {
    /// `POST /app-manifests/{code}/conversions` (unauthenticated).
    ///
    /// Errors: [`ForgeError::Api`] (e.g. an expired code, 404), [`ForgeError::Network`],
    /// [`ForgeError::Invalid`] for a code that is not a plain token.
    pub async fn convert_manifest(&self, api_url: &str, code: &str) -> Result<AppCredentials, ForgeError> {
        #[derive(Deserialize)]
        struct Owner {
            login: String,
        }
        #[derive(Deserialize)]
        struct Conversion {
            id: u64,
            slug: String,
            owner: Owner,
            html_url: String,
            pem: Secret,
        }

        let api = api_base(api_url)?;
        check_name("manifest code", code)?;
        let url = self.endpoint(api, &format!("/app-manifests/{code}/conversions"));
        let response = self.send(api, self.http()?.post(url)).await?;
        if response.status != 201 {
            return Err(response.error(api));
        }
        let conversion: Conversion = response.json(api)?;
        Ok(AppCredentials {
            id: conversion.id,
            slug: conversion.slug,
            owner: conversion.owner.login,
            html_url: conversion.html_url,
            pem: conversion.pem,
        })
    }
}

#[cfg(test)]
mod tests {
    use credential_bridge_proto::ipc::git::Access;

    use super::*;
    use crate::github::mock::{MockServer, Reply};

    #[test]
    fn manifest_json_has_no_active_webhook() {
        let manifest = AppManifest {
            name: "bridge".into(),
            url: "https://github.com/XeS0r/ssh-credential-bridge".into(),
            redirect_url: "http://127.0.0.1:4567/callback".into(),
            public: false,
            default_permissions: Permissions::from([
                ("contents".to_owned(), Access::Write),
                ("metadata".to_owned(), Access::Read),
            ]),
        };
        let json: serde_json::Value = serde_json::from_str(&manifest.to_json()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "name": "bridge",
                "url": "https://github.com/XeS0r/ssh-credential-bridge",
                "redirect_url": "http://127.0.0.1:4567/callback",
                "public": false,
                "default_permissions": {"contents": "write", "metadata": "read"},
                "default_events": [],
                "hook_attributes": {"url": "https://github.com/XeS0r/ssh-credential-bridge", "active": false},
            })
        );
    }

    #[test]
    fn new_app_urls() {
        assert_eq!(new_app_url("https://github.com/", None), "https://github.com/settings/apps/new");
        assert_eq!(
            new_app_url("https://github.com", Some("my-org")),
            "https://github.com/organizations/my-org/settings/apps/new"
        );
    }

    #[tokio::test]
    async fn converts_the_code() {
        let server = MockServer::start(|request| match request.path.as_str() {
            "/app-manifests/abc123/conversions" => Reply::json(
                201,
                r#"{"id":99,"slug":"bridge","owner":{"login":"my-org","id":1},
                    "html_url":"https://github.com/apps/bridge","pem":"-----BEGIN RSA PRIVATE KEY-----\nX\n",
                    "webhook_secret":null,"client_id":"Iv1","client_secret":"s"}"#,
            ),
            _ => Reply::json(404, r#"{"message":"Not Found"}"#),
        })
        .await;
        let client = server.client();
        let credentials = client.convert_manifest(MockServer::API, "abc123").await.unwrap();
        assert_eq!(credentials.id, 99);
        assert_eq!(credentials.slug, "bridge");
        assert_eq!(credentials.owner, "my-org");
        assert_eq!(credentials.html_url, "https://github.com/apps/bridge");
        assert_eq!(credentials.pem.expose(), "-----BEGIN RSA PRIVATE KEY-----\nX\n");
        let request = &server.requests()[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.header("authorization"), None);

        let error = client.convert_manifest(MockServer::API, "expired").await.unwrap_err();
        assert_eq!(
            error,
            ForgeError::Api { api: MockServer::API.into(), status: 404, message: "Not Found".into() }
        );
        let error = client.convert_manifest(MockServer::API, "../x").await.unwrap_err();
        assert!(matches!(error, ForgeError::Invalid(_)));
    }
}
