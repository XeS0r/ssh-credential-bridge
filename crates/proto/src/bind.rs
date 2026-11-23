//! `session-bind@openssh.com` (OpenSSH `PROTOCOL.agent`, section 1).
//!
//! The extension contents are `string hostkey`, `string session_identifier`,
//! `string signature`, `boolean is_forwarding`. The signature is the server's signature
//! over the session identifier from the key exchange, made with `hostkey`. Supported host
//! key algorithms: `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521` and `ssh-rsa` with
//! `rsa-sha2-256`/`rsa-sha2-512` signatures (plain `ssh-rsa` SHA-1 signatures are
//! rejected, as in OpenSSH).
//!
//! The host key may also be an OpenSSH host certificate (`*-cert-v01@openssh.com`): the
//! client sends the key the key exchange used, which is the certificate whenever a
//! certificate host key algorithm was negotiated. Only the key embedded in the
//! certificate counts. Its CA, signature, principals and validity are not checked (the
//! identity is the embedded key, as in OpenSSH's fallback to the plain key when no CA
//! matches); the signature is verified with the embedded key, and the embedded key is
//! [`SessionBind::host_key`]. The original blob is kept for the replay upstream.
//!
//! Connection-level rules (only a verified forwarding bind as the first message of a
//! connection selects the server, no bind after an `is_forwarding = 0` bind, at most
//! [`MAX_SESSION_IDS`] binds) are enforced by the daemon's bind tracker, not here.

use signature::Verifier;
use ssh_key::{Algorithm, PublicKey, Signature};

use crate::wire::Reader;

/// The extension name.
pub const SESSION_BIND: &str = crate::ext::SESSION_BIND;

/// At most this many session IDs per connection (OpenSSH `AGENT_MAX_SESSION_IDS`).
pub const MAX_SESSION_IDS: usize = 16;

/// Longest accepted session identifier in bytes (OpenSSH `AGENT_MAX_SID_LEN`).
pub const MAX_SESSION_ID_LEN: usize = 128;

/// Errors of parsing or verifying a bind.
#[derive(Debug, thiserror::Error)]
pub enum BindError {
    /// The contents do not match the layout above.
    #[error("malformed session-bind: {0}")]
    Malformed(#[from] crate::wire::WireError),
    /// The host key blob could not be parsed or uses an unsupported algorithm.
    #[error("unsupported or invalid host key: {0}")]
    HostKey(String),
    /// The session identifier is empty or longer than [`MAX_SESSION_ID_LEN`].
    #[error("invalid session identifier length {0}")]
    SessionIdLength(usize),
    /// The signature blob is malformed, uses an algorithm that does not fit the host key,
    /// or does not verify.
    #[error("session-bind signature does not verify")]
    BadSignature,
}

/// A parsed `session-bind@openssh.com` request. Parsing does not verify; call
/// [`SessionBind::verify`] before trusting any field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBind {
    /// The server's host key; for a host certificate the plain key embedded in it.
    /// Used for server lookup and fingerprints.
    pub host_key: ssh_key::PublicKey,
    /// The host key blob exactly as received, certificate included.
    pub host_key_blob: Vec<u8>,
    /// The session identifier (exchange hash) of the ssh connection.
    pub session_id: Vec<u8>,
    /// The signature blob in SSH wire format (`string algorithm`, `string sig`).
    pub signature: Vec<u8>,
    /// `true` when the agent connection is forwarded to the server, `false` for an
    /// authentication bind of the local login.
    pub is_forwarding: bool,
}

impl SessionBind {
    /// Parses the extension contents (everything after the name).
    ///
    /// Errors: [`BindError::Malformed`] (including trailing bytes),
    /// [`BindError::HostKey`], [`BindError::SessionIdLength`].
    pub fn parse(contents: &[u8]) -> Result<SessionBind, BindError> {
        let mut r = Reader::new(contents);
        let host_key_blob = r.read_string()?;
        let session_id = r.read_string()?;
        let signature = r.read_string()?;
        let is_forwarding = r.read_bool()?;
        r.finish()?;

        let host_key = parse_host_key(host_key_blob)?;
        match host_key.algorithm() {
            Algorithm::Ed25519 | Algorithm::Ecdsa { .. } | Algorithm::Rsa { .. } => {}
            other => {
                return Err(BindError::HostKey(format!(
                    "algorithm {} is not a supported host key",
                    other.as_str()
                )));
            }
        }
        if session_id.is_empty() || session_id.len() > MAX_SESSION_ID_LEN {
            return Err(BindError::SessionIdLength(session_id.len()));
        }
        Ok(SessionBind {
            host_key,
            host_key_blob: host_key_blob.to_vec(),
            session_id: session_id.to_vec(),
            signature: signature.to_vec(),
            is_forwarding,
        })
    }

    /// Verifies that `signature` is a valid signature of `session_id` by `host_key`.
    ///
    /// Errors: [`BindError::BadSignature`] for any mismatch.
    pub fn verify(&self) -> Result<(), BindError> {
        let signature = self.decode_signature().ok_or(BindError::BadSignature)?;
        let fits = match (self.host_key.algorithm(), signature.algorithm()) {
            (Algorithm::Ed25519, Algorithm::Ed25519) => true,
            (Algorithm::Ecdsa { curve: key }, Algorithm::Ecdsa { curve: sig }) => key == sig,
            // SHA-1 (`ssh-rsa`) signatures never get here: `Signature::new` rejects them.
            (Algorithm::Rsa { .. }, Algorithm::Rsa { hash: Some(_) }) => true,
            _ => false,
        };
        if !fits {
            return Err(BindError::BadSignature);
        }
        Verifier::verify(&self.host_key, &self.session_id, &signature).map_err(|_| BindError::BadSignature)
    }

    /// Decodes the signature blob (`string algorithm`, `string signature`), rejecting
    /// trailing bytes, unknown algorithms and malformed signature data.
    fn decode_signature(&self) -> Option<Signature> {
        let mut r = Reader::new(&self.signature);
        let algorithm = r.read_string().ok()?;
        let data = r.read_string().ok()?;
        r.finish().ok()?;
        let algorithm = Algorithm::new(std::str::from_utf8(algorithm).ok()?).ok()?;
        Signature::new(algorithm, data).ok()
    }

    /// The host key's SHA-256 fingerprint as `ssh-keygen -l` prints it (`SHA256:…`), for
    /// logs and dialogs.
    pub fn host_key_fingerprint(&self) -> String {
        self.host_key.fingerprint(ssh_key::HashAlg::Sha256).to_string()
    }
}

/// The suffix of OpenSSH certificate key types (`PROTOCOL.certkeys`).
const CERT_SUFFIX: &str = "-cert-v01@openssh.com";

/// Parses a host key blob: a plain public key, or a certificate whose embedded key is
/// returned.
fn parse_host_key(blob: &[u8]) -> Result<PublicKey, BindError> {
    let invalid = |err: &dyn std::fmt::Display| BindError::HostKey(err.to_string());
    let mut r = Reader::new(blob);
    let name = r.read_string().map_err(|err| invalid(&err))?;
    let name = std::str::from_utf8(name).map_err(|err| invalid(&err))?;
    match name.strip_suffix(CERT_SUFFIX) {
        None => PublicKey::from_bytes(blob).map_err(|err| invalid(&err)),
        Some(plain) => {
            let key = certificate_key(plain, blob, r).map_err(|err| invalid(&err))?;
            PublicKey::from_bytes(&key).map_err(|err| invalid(&err))
        }
    }
}

/// The plain public key blob embedded in a certificate of type `plain` + [`CERT_SUFFIX`]
/// (`r` is positioned after the type). The remaining certificate fields are checked for
/// their layout only.
fn certificate_key(plain: &str, blob: &[u8], mut r: Reader<'_>) -> Result<Vec<u8>, String> {
    // Number of `string`/`mpint` fields of the public key, which follow the nonce.
    let key_fields = match plain {
        "ssh-ed25519" => 1,
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" | "ssh-rsa" => 2,
        other => return Err(format!("certificate type {other}{CERT_SUFFIX} is not a supported host key")),
    };
    let layout = |err: crate::wire::WireError| format!("malformed host certificate: {err}");
    let offset = |r: &Reader<'_>| blob.len() - r.remaining();
    r.read_string().map_err(layout)?; // nonce
    let start = offset(&r);
    for _ in 0..key_fields {
        r.read_string().map_err(layout)?;
    }
    let end = offset(&r);
    // serial (uint64), type (uint32), key id, principals, valid after and before
    // (uint64 each), critical options, extensions, reserved, signature key, signature.
    for _ in 0..3 {
        r.read_u32().map_err(layout)?;
    }
    for _ in 0..2 {
        r.read_string().map_err(layout)?;
    }
    for _ in 0..4 {
        r.read_u32().map_err(layout)?;
    }
    for _ in 0..5 {
        r.read_string().map_err(layout)?;
    }
    r.finish().map_err(layout)?;
    let mut w = crate::wire::Writer::new();
    w.put_string(plain.as_bytes()).put_raw(&blob[start..end]);
    Ok(w.into_bytes())
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use signature::Signer;
    use ssh_key::private::{Ed25519Keypair, KeypairData, RsaKeypair};
    use ssh_key::public::KeyData;
    use ssh_key::rand_core::OsRng;
    use ssh_key::sha2::{Sha256, Sha512};
    use ssh_key::{EcdsaCurve, HashAlg, PrivateKey};

    use super::*;
    use crate::wire::Writer;

    const SESSION_ID: &[u8] = &[0x5a; 32];

    /// A host key generated for the test.
    #[derive(Clone)]
    enum Host {
        /// Ed25519 and ECDSA, signed through ssh-key.
        Ssh(PrivateKey),
        /// RSA, signed with the `rsa` crate: ssh-key 0.6.7 converts RSA keypairs to
        /// `rsa::RsaPrivateKey` with `p` twice, so it cannot sign with RSA.
        Rsa(rsa::RsaPrivateKey),
    }

    impl Host {
        fn public_key(&self) -> PublicKey {
            match self {
                Host::Ssh(key) => key.public_key().clone(),
                Host::Rsa(key) => {
                    let keypair = RsaKeypair::try_from(key).unwrap();
                    PublicKey::from(KeyData::Rsa(keypair.public))
                }
            }
        }
    }

    fn ed25519() -> Host {
        Host::Ssh(PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap())
    }

    fn ecdsa(curve: EcdsaCurve) -> Host {
        Host::Ssh(PrivateKey::random(&mut OsRng, Algorithm::Ecdsa { curve }).unwrap())
    }

    /// RSA key generation is slow in debug builds; one key serves all tests.
    fn rsa_key() -> &'static Host {
        static KEY: OnceLock<Host> = OnceLock::new();
        KEY.get_or_init(|| Host::Rsa(rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap()))
    }

    fn blob(key: &Host) -> Vec<u8> {
        key.public_key().to_bytes().unwrap()
    }

    /// The wire signature blob (RSA: `rsa-sha2-512`).
    fn sign(key: &Host, data: &[u8]) -> Vec<u8> {
        match key {
            Host::Ssh(key) => {
                let signature: Signature = key.try_sign(data).unwrap();
                Vec::<u8>::try_from(signature).unwrap()
            }
            Host::Rsa(_) => sign_rsa(key, data, "rsa-sha2-512"),
        }
    }

    /// A PKCS#1 v1.5 signature blob labelled `label`; SHA-256 for `rsa-sha2-256` and
    /// `ssh-rsa`, SHA-512 otherwise.
    fn sign_rsa(key: &Host, data: &[u8], label: &str) -> Vec<u8> {
        let Host::Rsa(private) = key else { panic!("not RSA") };
        let raw: Box<[u8]> = if label == "rsa-sha2-512" {
            rsa::pkcs1v15::SigningKey::<Sha512>::new(private.clone()).sign(data).into()
        } else {
            rsa::pkcs1v15::SigningKey::<Sha256>::new(private.clone()).sign(data).into()
        };
        let mut w = Writer::new();
        w.put_string(label.as_bytes()).put_string(&raw);
        w.into_bytes()
    }

    fn contents(host_key: &[u8], session_id: &[u8], signature: &[u8], is_forwarding: bool) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_string(host_key).put_string(session_id).put_string(signature).put_bool(is_forwarding);
        w.into_bytes()
    }

    fn bind_for(key: &Host, is_forwarding: bool) -> Vec<u8> {
        contents(&blob(key), SESSION_ID, &sign(key, SESSION_ID), is_forwarding)
    }

    fn parse_and_verify(contents: &[u8]) -> Result<SessionBind, BindError> {
        let bind = SessionBind::parse(contents)?;
        bind.verify()?;
        Ok(bind)
    }

    #[test]
    fn verifies_genuine_binds_of_every_host_key_type() {
        let keys = [
            ed25519(),
            ecdsa(EcdsaCurve::NistP256),
            ecdsa(EcdsaCurve::NistP384),
            ecdsa(EcdsaCurve::NistP521),
            rsa_key().clone(),
        ];
        for key in &keys {
            for is_forwarding in [true, false] {
                let bind = parse_and_verify(&bind_for(key, is_forwarding)).unwrap();
                assert_eq!(bind.is_forwarding, is_forwarding);
                assert_eq!(bind.host_key_blob, blob(key));
                assert_eq!(bind.session_id, SESSION_ID);
                assert_eq!(bind.host_key, key.public_key());
                assert_eq!(
                    bind.host_key_fingerprint(),
                    key.public_key().fingerprint(HashAlg::Sha256).to_string()
                );
                assert!(bind.host_key_fingerprint().starts_with("SHA256:"));
            }
        }
    }

    #[test]
    fn verifies_rsa_sha2_256() {
        let key = rsa_key();
        let signature = sign_rsa(key, SESSION_ID, "rsa-sha2-256");
        parse_and_verify(&contents(&blob(key), SESSION_ID, &signature, true)).unwrap();
    }

    #[test]
    fn rejects_sha1_rsa_signatures() {
        let key = rsa_key();
        // A valid PKCS#1 signature relabelled as `ssh-rsa` (SHA-1) must not pass.
        let signature = sign_rsa(key, SESSION_ID, "ssh-rsa");
        let bind = SessionBind::parse(&contents(&blob(key), SESSION_ID, &signature, true)).unwrap();
        assert!(matches!(bind.verify(), Err(BindError::BadSignature)));
        // Relabelling the SHA-256 signature as SHA-512 fails too.
        let mut signature = sign_rsa(key, SESSION_ID, "rsa-sha2-256");
        assert_eq!(&signature[4..16], b"rsa-sha2-256");
        signature[13..16].copy_from_slice(b"512");
        let bind = SessionBind::parse(&contents(&blob(key), SESSION_ID, &signature, true)).unwrap();
        assert!(matches!(bind.verify(), Err(BindError::BadSignature)));
    }

    #[test]
    fn rejects_forged_and_mismatched_signatures() {
        let host = ed25519();
        let other = ed25519();
        let bad = |c: Vec<u8>| matches!(parse_and_verify(&c), Err(BindError::BadSignature));

        // Signature over another session id.
        assert!(bad(contents(&blob(&host), SESSION_ID, &sign(&host, b"other session"), true)));
        // Genuine signature of another host, presented with this host key.
        assert!(bad(contents(&blob(&host), SESSION_ID, &sign(&other, SESSION_ID), true)));
        // A flipped bit in the signature.
        let mut tampered = sign(&host, SESSION_ID);
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(bad(contents(&blob(&host), SESSION_ID, &tampered, true)));
        // Trailing bytes after the signature blob.
        let mut trailing = sign(&host, SESSION_ID);
        trailing.push(0);
        assert!(bad(contents(&blob(&host), SESSION_ID, &trailing, true)));
        // Empty and garbage signature blobs.
        assert!(bad(contents(&blob(&host), SESSION_ID, &[], true)));
        assert!(bad(contents(&blob(&host), SESSION_ID, b"\x00\x00\x00\x03abc\x00\x00\x00\x00", true)));

        // Algorithm mismatches: ECDSA curve, key type.
        let p256 = ecdsa(EcdsaCurve::NistP256);
        let p384 = ecdsa(EcdsaCurve::NistP384);
        assert!(bad(contents(&blob(&p256), SESSION_ID, &sign(&p384, SESSION_ID), true)));
        assert!(bad(contents(&blob(&host), SESSION_ID, &sign(rsa_key(), SESSION_ID), true)));
        assert!(bad(contents(&blob(rsa_key()), SESSION_ID, &sign(&host, SESSION_ID), true)));
        assert!(bad(contents(&blob(&p256), SESSION_ID, &sign(&host, SESSION_ID), true)));
    }

    #[test]
    fn is_forwarding_is_not_covered_by_the_signature() {
        // The flag is the client's statement; both values verify with the same signature,
        // so connection rules (only a first-message forwarding bind counts) must live in
        // the tracker.
        let host = ed25519();
        let signature = sign(&host, SESSION_ID);
        for is_forwarding in [false, true] {
            let bind =
                parse_and_verify(&contents(&blob(&host), SESSION_ID, &signature, is_forwarding)).unwrap();
            assert_eq!(bind.is_forwarding, is_forwarding);
        }
    }

    #[test]
    fn rejects_malformed_contents() {
        let host = Ed25519Keypair::from_seed(&[7; 32]);
        let key = Host::Ssh(PrivateKey::try_from(KeypairData::Ed25519(host)).unwrap());
        let good = bind_for(&key, true);
        assert!(SessionBind::parse(&good).is_ok());

        let mut trailing = good.clone();
        trailing.push(0);
        assert!(matches!(SessionBind::parse(&trailing), Err(BindError::Malformed(_))));
        let mut bad_bool = good.clone();
        *bad_bool.last_mut().unwrap() = 2;
        assert!(matches!(SessionBind::parse(&bad_bool), Err(BindError::Malformed(_))));
        for len in 0..good.len() {
            assert!(matches!(SessionBind::parse(&good[..len]), Err(BindError::Malformed(_))), "{len}");
        }

        let signature = sign(&key, SESSION_ID);
        let empty_sid = contents(&blob(&key), &[], &signature, true);
        assert!(matches!(SessionBind::parse(&empty_sid), Err(BindError::SessionIdLength(0))));
        let long_sid = contents(&blob(&key), &[1; MAX_SESSION_ID_LEN + 1], &signature, true);
        assert!(matches!(SessionBind::parse(&long_sid), Err(BindError::SessionIdLength(129))));
        let max_sid = vec![1; MAX_SESSION_ID_LEN];
        parse_and_verify(&contents(&blob(&key), &max_sid, &sign(&key, &max_sid), true)).unwrap();

        let garbage_key = contents(b"\x00\x00\x00\x07ssh-foo", SESSION_ID, &signature, true);
        assert!(matches!(SessionBind::parse(&garbage_key), Err(BindError::HostKey(_))));
        let mut key_trailing = blob(&key);
        key_trailing.push(0);
        let key_trailing = contents(&key_trailing, SESSION_ID, &signature, true);
        assert!(matches!(SessionBind::parse(&key_trailing), Err(BindError::HostKey(_))));
    }

    /// A host certificate for `key`, signed by a fresh ed25519 CA, expired in 2004.
    fn certificate(key: &Host) -> Vec<u8> {
        let ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
            &mut OsRng,
            key.public_key().key_data().clone(),
            1_000_000_000,
            1_100_000_000,
        )
        .unwrap();
        builder.cert_type(ssh_key::certificate::CertType::Host).unwrap();
        builder.valid_principal("server.example").unwrap();
        builder.sign(&ca).unwrap().to_bytes().unwrap()
    }

    #[test]
    fn accepts_host_certificates_with_the_embedded_key() {
        let keys = [
            ed25519(),
            ecdsa(EcdsaCurve::NistP256),
            ecdsa(EcdsaCurve::NistP384),
            ecdsa(EcdsaCurve::NistP521),
            rsa_key().clone(),
        ];
        for key in &keys {
            let cert = certificate(key);
            assert!(cert.windows(CERT_SUFFIX.len()).any(|w| w == CERT_SUFFIX.as_bytes()));
            let bind = parse_and_verify(&contents(&cert, SESSION_ID, &sign(key, SESSION_ID), true)).unwrap();
            // The identity is the plain key; the blob stays the certificate for the replay.
            assert_eq!(bind.host_key, key.public_key());
            assert_eq!(bind.host_key_blob, cert);
            assert_eq!(
                bind.host_key_fingerprint(),
                key.public_key().fingerprint(HashAlg::Sha256).to_string()
            );
            // A signature by another key does not verify against the embedded key.
            let other = contents(&cert, SESSION_ID, &sign(&ed25519(), SESSION_ID), true);
            assert!(matches!(parse_and_verify(&other), Err(BindError::BadSignature)));
        }
        let plain = parse_and_verify(&bind_for(&ed25519(), true)).unwrap();
        assert_eq!(plain.host_key_blob, plain.host_key.to_bytes().unwrap());
    }

    #[test]
    fn certificate_ca_and_validity_are_not_checked() {
        // A broken CA signature (last byte flipped) of an expired certificate: the
        // identity is the embedded key, as in OpenSSH's fallback to the plain key.
        let key = ed25519();
        let mut cert = certificate(&key);
        let last = cert.len() - 1;
        cert[last] ^= 1;
        let bind = parse_and_verify(&contents(&cert, SESSION_ID, &sign(&key, SESSION_ID), true)).unwrap();
        assert_eq!(bind.host_key, key.public_key());
    }

    #[test]
    fn rejects_malformed_and_unsupported_certificates() {
        let key = ed25519();
        let signature = sign(&key, SESSION_ID);
        let cert = certificate(&key);
        let host_key_error = |blob: &[u8]| {
            matches!(
                SessionBind::parse(&contents(blob, SESSION_ID, &signature, true)),
                Err(BindError::HostKey(_))
            )
        };
        for len in 0..cert.len() {
            assert!(host_key_error(&cert[..len]), "{len}");
        }
        let mut trailing = cert.clone();
        trailing.push(0);
        assert!(host_key_error(&trailing));

        // Certificate types that are no supported host key: security keys, unknown types.
        for name in ["sk-ssh-ed25519-cert-v01@openssh.com", "ssh-mldsa44-ed25519-cert-v01@openssh.com"] {
            let mut w = Writer::new();
            w.put_string(name.as_bytes()).put_raw(&cert[4 + 32..]);
            assert!(host_key_error(&w.into_bytes()), "{name}");
        }
        // A certificate type whose embedded key does not fit the type.
        let mut w = Writer::new();
        w.put_string(b"ecdsa-sha2-nistp256-cert-v01@openssh.com").put_raw(&cert[4 + 32..]);
        assert!(host_key_error(&w.into_bytes()));
    }

    #[test]
    fn rejects_security_key_host_keys() {
        let mut w = Writer::new();
        w.put_string(b"sk-ssh-ed25519@openssh.com").put_string(&[9; 32]).put_string(b"ssh:");
        let sk_blob = w.into_bytes();
        let c = contents(&sk_blob, SESSION_ID, &sign(&ed25519(), SESSION_ID), true);
        assert!(matches!(SessionBind::parse(&c), Err(BindError::HostKey(_))));
    }
}
