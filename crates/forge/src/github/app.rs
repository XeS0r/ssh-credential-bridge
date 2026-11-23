//! GitHub App JWTs (RS256).

use std::time::{Duration, SystemTime};

use credential_bridge_proto::secret::Secret;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

use crate::ForgeError;

/// The JWT is dated back by this much to allow for clock skew (GitHub's recommendation).
const BACKDATE: Duration = Duration::from_secs(60);

/// Lifetime of the JWT after `now`; GitHub allows at most 10 minutes.
const LIFETIME: Duration = Duration::from_secs(9 * 60);

/// The claims GitHub expects.
#[derive(Serialize)]
struct Claims {
    iat: u64,
    exp: u64,
    iss: u64,
}

/// Signs the JWT that authenticates as the App: `iss = app_id`, `iat = now - 60s`
/// (clock skew), `exp = now + 9 min` (GitHub allows at most 10), RS256 with the PEM
/// private key (PKCS#1 or PKCS#8).
///
/// Errors: [`ForgeError::Jwt`] for an invalid key.
pub fn app_jwt(app_id: u64, private_key_pem: &Secret, now: SystemTime) -> Result<Secret, ForgeError> {
    let key = EncodingKey::from_rsa_pem(private_key_pem.expose().trim().as_bytes())
        .map_err(|_| ForgeError::Jwt("not an RSA private key in PEM format (PKCS#1 or PKCS#8)".to_owned()))?;
    let now = now.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let claims =
        Claims { iat: now.saturating_sub(BACKDATE).as_secs(), exp: (now + LIFETIME).as_secs(), iss: app_id };
    jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &key)
        .map(Secret::new)
        .map_err(|error| ForgeError::Jwt(format!("signing failed: {error}")))
}

#[cfg(test)]
pub(crate) mod test_key {
    //! An RSA key generated once per test run.

    use std::sync::OnceLock;

    use rsa::RsaPrivateKey;
    use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

    struct Keys {
        pkcs1: String,
        pkcs8: String,
        public: String,
    }

    fn keys() -> &'static Keys {
        static KEYS: OnceLock<Keys> = OnceLock::new();
        KEYS.get_or_init(|| {
            let key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("generate RSA key");
            Keys {
                pkcs1: key.to_pkcs1_pem(LineEnding::LF).unwrap().to_string(),
                pkcs8: key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(),
                public: key.to_public_key().to_public_key_pem(LineEnding::LF).unwrap(),
            }
        })
    }

    /// The private key as PKCS#1 PEM (`BEGIN RSA PRIVATE KEY`, as GitHub hands it out).
    pub fn pkcs1_pem() -> String {
        keys().pkcs1.clone()
    }

    /// The private key as PKCS#8 PEM (`BEGIN PRIVATE KEY`).
    pub fn pkcs8_pem() -> String {
        keys().pkcs8.clone()
    }

    /// The public key as SPKI PEM.
    pub fn public_pem() -> String {
        keys().public.clone()
    }

    /// Verifies an App JWT and returns `(iss, iat, exp)`.
    pub fn verify(jwt: &str) -> (u64, u64, u64) {
        #[derive(serde::Deserialize)]
        struct Claims {
            iss: u64,
            iat: u64,
            exp: u64,
        }
        let key = jsonwebtoken::DecodingKey::from_rsa_pem(public_pem().as_bytes()).unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        let claims = jsonwebtoken::decode::<Claims>(jwt, &key, &validation).expect("valid JWT").claims;
        (claims.iss, claims.iat, claims.exp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_with_pkcs1_and_pkcs8_keys() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        for pem in [test_key::pkcs1_pem(), test_key::pkcs8_pem()] {
            let jwt = app_jwt(123_456, &Secret::new(pem), now).unwrap();
            let (iss, iat, exp) = test_key::verify(jwt.expose());
            assert_eq!(iss, 123_456);
            assert_eq!(iat, 1_700_000_000 - 60);
            assert_eq!(exp, 1_700_000_000 + 9 * 60);
        }
    }

    #[test]
    fn rejects_keys_that_are_not_rsa_pem() {
        for pem in ["", "not a key", "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"]
        {
            let error = app_jwt(1, &Secret::new(pem.to_owned()), SystemTime::now()).unwrap_err();
            assert!(matches!(error, ForgeError::Jwt(_)), "{error:?}");
        }
    }
}
