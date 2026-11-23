//! SSH wire encoding primitives (RFC 4251 section 5): `byte`, `boolean`, `uint32` and
//! `string`, all big-endian. Used by [`crate::agent`], [`crate::ext`] and `bind`.

/// Errors while reading SSH wire data.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The input ended before the announced field was complete.
    #[error("truncated input")]
    Truncated,
    /// A `boolean` byte was neither 0 nor 1.
    #[error("invalid boolean")]
    InvalidBool,
    /// Bytes were left over after the last expected field.
    #[error("{0} trailing bytes")]
    TrailingBytes(usize),
}

/// A cursor over SSH wire data. Never panics and never allocates beyond the input size:
/// every length is checked against the remaining input before use.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    /// The bytes not consumed yet.
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Starts reading at the beginning of `input`.
    pub fn new(input: &'a [u8]) -> Self {
        Self { rest: input }
    }

    /// Reads one byte.
    pub fn read_u8(&mut self) -> Result<u8, WireError> {
        let (&first, rest) = self.rest.split_first().ok_or(WireError::Truncated)?;
        self.rest = rest;
        Ok(first)
    }

    /// Reads a `boolean` (0 or 1; anything else is [`WireError::InvalidBool`]).
    pub fn read_bool(&mut self) -> Result<bool, WireError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError::InvalidBool),
        }
    }

    /// Reads a big-endian `uint32`.
    pub fn read_u32(&mut self) -> Result<u32, WireError> {
        let (head, rest) = self.rest.split_first_chunk::<4>().ok_or(WireError::Truncated)?;
        self.rest = rest;
        Ok(u32::from_be_bytes(*head))
    }

    /// Reads a `string`: a `uint32` length followed by that many bytes, borrowed from the
    /// input.
    pub fn read_string(&mut self) -> Result<&'a [u8], WireError> {
        let len = usize::try_from(self.read_u32()?).map_err(|_| WireError::Truncated)?;
        if len > self.rest.len() {
            return Err(WireError::Truncated);
        }
        let (value, rest) = self.rest.split_at(len);
        self.rest = rest;
        Ok(value)
    }

    /// Returns the unread remainder and consumes it.
    pub fn read_rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.rest)
    }

    /// Number of unread bytes.
    pub fn remaining(&self) -> usize {
        self.rest.len()
    }

    /// Succeeds only if all input was consumed; otherwise [`WireError::TrailingBytes`].
    pub fn finish(self) -> Result<(), WireError> {
        match self.rest.len() {
            0 => Ok(()),
            n => Err(WireError::TrailingBytes(n)),
        }
    }
}

/// Appends SSH wire fields to a byte vector.
#[derive(Debug, Clone, Default)]
pub struct Writer {
    /// The encoded bytes so far.
    buf: Vec<u8>,
}

impl Writer {
    /// An empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty writer with room for `capacity` bytes, so encoding up to that size never
    /// reallocates (and leaves no copies in freed memory).
    pub fn with_capacity(capacity: usize) -> Self {
        Self { buf: Vec::with_capacity(capacity) }
    }

    /// Appends one byte.
    pub fn put_u8(&mut self, value: u8) -> &mut Self {
        self.buf.push(value);
        self
    }

    /// Appends a `boolean` (1 or 0).
    pub fn put_bool(&mut self, value: bool) -> &mut Self {
        self.put_u8(u8::from(value))
    }

    /// Appends a big-endian `uint32`.
    pub fn put_u32(&mut self, value: u32) -> &mut Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Appends a `string`. Panics if `value` is longer than `u32::MAX` bytes, which the
    /// size limits of every caller rule out.
    pub fn put_string(&mut self, value: &[u8]) -> &mut Self {
        let len = u32::try_from(value.len()).expect("string longer than u32::MAX");
        self.put_u32(len).put_raw(value)
    }

    /// Appends `value` without a length prefix.
    pub fn put_raw(&mut self, value: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(value);
        self
    }

    /// Returns the encoded bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut w = Writer::new();
        w.put_u8(7).put_bool(true).put_u32(0x0102_0304).put_string(b"abc");
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_u8(), Ok(7));
        assert_eq!(r.read_bool(), Ok(true));
        assert_eq!(r.read_u32(), Ok(0x0102_0304));
        assert_eq!(r.read_string(), Ok(&b"abc"[..]));
        assert_eq!(r.finish(), Ok(()));
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(Reader::new(&[0, 0, 0, 5, 1]).read_string(), Err(WireError::Truncated));
        assert_eq!(Reader::new(&[2]).read_bool(), Err(WireError::InvalidBool));
        assert_eq!(Reader::new(&[1, 2]).finish(), Err(WireError::TrailingBytes(2)));
    }
}
