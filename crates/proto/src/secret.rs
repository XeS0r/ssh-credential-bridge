//! Containers for secret values.
//!
//! Both types overwrite their memory on drop (`zeroize`), never print their contents in
//! `Debug`, and serialize transparently (a string, or a byte array) so they can travel in
//! [`crate::ipc`] frames. Equality is not constant-time; do not use it for
//! authentication decisions.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secret text value: a token, a password, a PEM private key.
#[derive(Clone, Default, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Secret(String);

impl Secret {
    /// Wraps `value`. The string's buffer is zeroized when the `Secret` is dropped.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Returns the secret text. Callers must not log or persist it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret is the empty string.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

/// Secret binary data: key material inside agent messages, lock passphrases.
#[derive(Clone, Default, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wraps `value`. The buffer is zeroized when the `SecretBytes` is dropped.
    pub fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    /// Returns the secret bytes. Callers must not log or persist them.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Takes over the buffer of `value` without copying it.
    pub fn from_zeroizing(mut value: zeroize::Zeroizing<Vec<u8>>) -> Self {
        Self(std::mem::take(&mut *value))
    }

    /// Hands the buffer over without copying it; it stays wiped on drop.
    pub fn into_zeroizing(mut self) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(std::mem::take(&mut self.0))
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(<{} bytes redacted>)", self.0.len())
    }
}

impl Serialize for SecretBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    /// A byte array (JSON: an array of numbers) or a byte string. The buffer never
    /// reallocates in place: it grows into a new buffer and the old one is wiped, so no
    /// copy of the bytes is left behind in freed memory.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(SecretBytesVisitor)
    }
}

/// Reads [`SecretBytes`] without leaving copies behind.
struct SecretBytesVisitor;

impl<'de> serde::de::Visitor<'de> for SecretBytesVisitor {
    type Value = SecretBytes;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a byte array")
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<SecretBytes, A::Error> {
        // The hint comes from the peer: bounded, so a lying length cannot reserve much.
        let mut bytes = SecretBytes(Vec::with_capacity(seq.size_hint().unwrap_or(0).min(64 * 1024)));
        while let Some(byte) = seq.next_element::<u8>()? {
            if bytes.0.len() == bytes.0.capacity() {
                let mut larger = Vec::with_capacity((bytes.0.capacity() * 2).max(64));
                larger.extend_from_slice(&bytes.0);
                // The old buffer is wiped when `bytes` is replaced and dropped.
                bytes = SecretBytes(larger);
            }
            bytes.0.push(byte);
        }
        Ok(bytes)
    }

    fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<SecretBytes, E> {
        Ok(SecretBytes(value.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let secret = Secret::new("ghp_token".to_owned());
        assert!(!format!("{secret:?}").contains("ghp_token"));
        let bytes = SecretBytes::new(b"passphrase".to_vec());
        assert!(!format!("{bytes:?}").contains("passphrase"));
    }

    #[test]
    fn secret_bytes_serialize_as_a_byte_array() {
        let bytes = SecretBytes::new((0..=255).collect());
        let json = serde_json::to_string(&bytes).unwrap();
        assert_eq!(json, serde_json::to_string(&(0..=255u8).collect::<Vec<u8>>()).unwrap());
        let back: SecretBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(back, bytes);
        assert_eq!(serde_json::from_str::<SecretBytes>("[]").unwrap(), SecretBytes::default());
        assert!(serde_json::from_str::<SecretBytes>("[256]").is_err());
        assert!(serde_json::from_str::<SecretBytes>("\"text\"").is_err());
    }

    #[test]
    fn serializes_transparently() {
        let secret = Secret::new("value".to_owned());
        let json = serde_json::to_string(&secret).unwrap();
        assert_eq!(json, "\"value\"");
        let back: Secret = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expose(), "value");
    }
}
