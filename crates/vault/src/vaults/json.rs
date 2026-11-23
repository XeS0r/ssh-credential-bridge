//! JSON items of vault CLIs (`op`, `bw`), which carry secrets: parsed into a wrapper that
//! wipes every string on drop, and serialized into a [`Secret`].

use std::ops::{Deref, DerefMut};

use credential_bridge_proto::secret::Secret;
use serde_json::Value;
use zeroize::Zeroize;

/// A JSON value whose strings are zeroized on drop. Object keys are not secret and stay
/// as they are.
#[derive(Debug, Default)]
pub(crate) struct WipedJson(pub Value);

impl WipedJson {
    /// Parses `text`; `None` if it is not JSON.
    pub(crate) fn parse(text: &Secret) -> Option<Self> {
        serde_json::from_str(text.expose()).ok().map(Self)
    }

    /// Serializes into a secret.
    pub(crate) fn to_secret(&self) -> Secret {
        Secret::new(self.0.to_string())
    }
}

impl Deref for WipedJson {
    type Target = Value;

    fn deref(&self) -> &Value {
        &self.0
    }
}

impl DerefMut for WipedJson {
    fn deref_mut(&mut self) -> &mut Value {
        &mut self.0
    }
}

impl Drop for WipedJson {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Zeroizes every string in `value`.
fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(map) => map.values_mut().for_each(wipe),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Standard base64 with padding (what `bw create`/`bw edit` expect on stdin).
pub(crate) fn base64(input: &[u8]) -> Secret {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> shift) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    Secret::new(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        let cases = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (input, expected) in cases {
            assert_eq!(base64(input.as_bytes()).expose(), expected);
        }
    }

    #[test]
    fn parses_and_serializes() {
        let json = WipedJson::parse(&Secret::new(r#"{"a":["x",1]}"#.to_owned())).unwrap();
        assert_eq!(json["a"][0], "x");
        assert_eq!(json.to_secret().expose(), r#"{"a":["x",1]}"#);
        assert!(WipedJson::parse(&Secret::new("nope".to_owned())).is_none());
    }
}
