//! How Assuan traffic is cut into `gpg-agent@credential-bridge` messages.
//!
//! Assuan is strictly turn-based, so each extension request carries one client **unit**
//! and its reply carries one server **turn**:
//!
//! - a unit is one command line, or one inquiry answer (all `D` lines up to and including
//!   `END` or `CAN`), each including LFs;
//! - a turn is every server line up to and including the next terminator (`OK`, `ERR`,
//!   `INQUIRE`); after `INQUIRE` the next unit must be an inquiry answer.
//!
//! The shim uses [`ClientFramer`] to cut what gpg writes into units; the worker uses
//! [`TurnCollector`] to gather gpg-agent's output into turns. Units and turns larger
//! than [`credential_bridge_proto::ext::MAX_GPG_CHUNK`] are errors.
//!
//! # The tunnel
//!
//! One ssh-agent connection carries at most one tunnel, which is tied to exactly one
//! gpg-agent connection on the local side (so `INQUIRE` round trips stay on one
//! connection). The messages are those of [`credential_bridge_proto::ext`]:
//!
//! | Shim sends (`GpgRequest`) | Proxy answers (`GpgReply`)                              |
//! | ------------------------- | ------------------------------------------------------- |
//! | `Open`                    | `Opened(greeting)`: gpg-agent's first turn (`OK …`)     |
//! | `Input(unit)`             | `Output(turn)`: gpg-agent's turn, or a local `OK`/`ERR` |
//! | `Close`                   | `Closed`                                                |
//!
//! A failure at any point (protocol violation, gpg-agent gone) is answered `Failed` and
//! ends the tunnel. Comment lines and empty lines from gpg are dropped by the shim:
//! gpg-agent answers neither, so forwarding them would break the one-unit-one-turn rule.
//!
//! A signature with a pinentry notification and a decryption look like this (`→` is one
//! `Input`, `←` the `Output` that answers it):
//!
//! ```text
//! Open                              ← OK Pleased to meet you
//! → SIGKEY 0123…\n                  ← OK
//! → SETHASH 8 ABCD…\n               ← OK
//! → PKSIGN\n                        ← INQUIRE PINENTRY_LAUNCHED 4711 gtk2 1.2.1 - - -\n
//! → END\n                           ← D (7:sig-val…)\nOK\n
//! → SETKEY 0123…\n                  ← OK
//! → PKDECRYPT\n                     ← S INQUIRE_MAXLEN 4096\nINQUIRE CIPHERTEXT\n
//! → D (7:enc-val…)\nEND\n           ← S PADDING 0\nD (5:value…)\nOK\n
//! Close                             ← Closed
//! ```

use credential_bridge_proto::ext::MAX_GPG_CHUNK;
use zeroize::Zeroizing;

use crate::GpgError;
use crate::assuan::{ClientLine, MAX_LINE_LEN, ServerLine, parse_client_line, parse_server_line};

/// Finds the next LF at or after `from` and returns the line (without LF) and the
/// offset just past the LF. If there is none, checks that the unfinished line can still
/// become a valid one.
fn next_line(buf: &[u8], from: usize) -> Result<Option<(&[u8], usize)>, GpgError> {
    match buf[from..].iter().position(|&b| b == b'\n') {
        Some(i) => Ok(Some((&buf[from..from + i], from + i + 1))),
        None if buf.len() - from >= MAX_LINE_LEN => Err(GpgError::LineTooLong),
        None => Ok(None),
    }
}

/// Shim side: accumulates bytes from gpg and yields complete units.
///
/// After a unit is returned, the framer yields nothing until [`ClientFramer::turn_ended`]
/// reports the turn that answered it, because the kind of the next unit (command or
/// inquiry answer) depends on that turn.
///
/// Inquiry answers may carry passphrases, so the buffer is a [`Zeroizing`] one that holds
/// [`MAX_GPG_CHUNK`] bytes from the first push on and never reallocates (no stale copy is
/// left behind in freed memory); consumed bytes are overwritten at once. Lines are checked
/// once, as they complete, and a unit is copied out only when it is complete.
#[derive(Debug, Default)]
pub struct ClientFramer {
    /// Bytes received but not yet returned as a unit.
    pending: Zeroizing<Vec<u8>>,
    /// Offset in `pending` up to which complete lines were already checked; they belong
    /// to the inquiry answer being received (comments and empty lines before a unit are
    /// dropped as soon as they are seen).
    scanned: usize,
    /// Whether the last turn ended with `INQUIRE`.
    inquiring: bool,
    /// Whether a unit was returned whose turn has not been reported yet.
    awaiting: bool,
}

impl ClientFramer {
    /// A framer expecting a command first.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends bytes read from gpg.
    /// Errors: [`GpgError::TooLarge`] if the pending unit grows beyond the limit.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), GpgError> {
        if self.pending.len() + bytes.len() > MAX_GPG_CHUNK {
            return Err(GpgError::TooLarge);
        }
        if self.pending.capacity() < MAX_GPG_CHUNK {
            // Once, while the buffer is still empty or small: what moves now was never a
            // secret worth keeping, and afterwards nothing moves again.
            let missing = MAX_GPG_CHUNK - self.pending.len();
            self.pending.reserve_exact(missing);
        }
        self.pending.extend_from_slice(bytes);
        Ok(())
    }

    /// Takes the next complete unit, if any.
    ///
    /// Errors: [`GpgError::Protocol`] for `D` lines outside an inquiry or a command
    /// inside one, [`GpgError::LineTooLong`] / [`GpgError::Malformed`] for bad lines,
    /// [`GpgError::TooLarge`] for an inquiry answer beyond the limit.
    pub fn next_unit(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, GpgError> {
        if self.awaiting {
            return Ok(None);
        }
        while let Some((line, next)) = next_line(&self.pending, self.scanned)? {
            let parsed = if line.is_empty() { ClientLine::Comment } else { parse_client_line(line)? };
            match (self.inquiring, parsed) {
                // Before a unit: dropped now. Inside an inquiry answer: dropped when the
                // unit is copied out.
                (_, ClientLine::Comment) if self.scanned == 0 => {
                    self.consume(next);
                    continue;
                }
                (_, ClientLine::Comment) => {}
                (false, ClientLine::Command { .. }) => {
                    let unit = Zeroizing::new(self.pending[..next].to_vec());
                    return Ok(Some(self.finish(unit, next)));
                }
                (false, _) => return Err(GpgError::Protocol("inquiry data without INQUIRE")),
                (true, ClientLine::Command { .. }) => {
                    return Err(GpgError::Protocol("command while answering an INQUIRE"));
                }
                (true, ClientLine::Data(_)) => {}
                (true, ClientLine::End | ClientLine::Cancel) => {
                    let unit = self.inquiry_answer(next)?;
                    return Ok(Some(self.finish(unit, next)));
                }
            }
            if next > MAX_GPG_CHUNK {
                return Err(GpgError::TooLarge);
            }
            self.scanned = next;
        }
        Ok(None)
    }

    /// The inquiry answer in `pending[..end]` (already checked) without its comment and
    /// empty lines.
    fn inquiry_answer(&self, end: usize) -> Result<Zeroizing<Vec<u8>>, GpgError> {
        let mut unit = Zeroizing::new(Vec::with_capacity(end));
        for line in self.pending[..end].split_inclusive(|&b| b == b'\n') {
            let text = &line[..line.len() - 1];
            if !text.is_empty() && !matches!(parse_client_line(text)?, ClientLine::Comment) {
                unit.extend_from_slice(line);
            }
        }
        if unit.len() > MAX_GPG_CHUNK {
            return Err(GpgError::TooLarge);
        }
        Ok(unit)
    }

    /// Drops the first `count` bytes of `pending` and overwrites the bytes that moving
    /// the rest left behind.
    fn consume(&mut self, count: usize) {
        self.pending.drain(..count);
        for byte in self.pending.spare_capacity_mut() {
            byte.write(0);
        }
        self.scanned = 0;
    }

    /// Drops the consumed bytes and waits for the turn.
    fn finish(&mut self, unit: Zeroizing<Vec<u8>>, consumed: usize) -> Zeroizing<Vec<u8>> {
        self.consume(consumed);
        self.awaiting = true;
        unit
    }

    /// Tells the framer how the last turn ended, so it knows whether the next unit is
    /// an inquiry answer.
    pub fn turn_ended(&mut self, inquire: bool) {
        self.inquiring = inquire;
        self.awaiting = false;
    }

    /// Whether bytes are buffered that do not form a complete unit yet.
    pub fn has_partial(&self) -> bool {
        !self.pending.is_empty()
    }
}

/// How a server turn ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnEnd {
    /// `OK`.
    Ok,
    /// `ERR`.
    Err,
    /// `INQUIRE`: the next unit must be an inquiry answer.
    Inquire,
}

/// A complete server turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Turn {
    /// All bytes of the turn, including the terminator line; wiped when dropped (a turn
    /// may carry a signature or a decrypted session key).
    pub bytes: Zeroizing<Vec<u8>>,
    /// The terminator.
    pub end: TurnEnd,
}

impl Turn {
    /// Parses a complete turn as it travels in a `GpgReply::Opened` or `Output` (shim
    /// side): every line valid, the last and only the last one a terminator.
    ///
    /// Errors: [`GpgError::Malformed`] / [`GpgError::LineTooLong`] for bad lines,
    /// [`GpgError::Protocol`] for a missing or early terminator, [`GpgError::TooLarge`].
    pub fn parse(bytes: &[u8]) -> Result<Turn, GpgError> {
        if bytes.len() > MAX_GPG_CHUNK {
            return Err(GpgError::TooLarge);
        }
        let mut collector = TurnCollector::new();
        match collector.push(bytes)? {
            Some(turn) if !collector.has_partial() => Ok(turn),
            Some(_) => Err(GpgError::Protocol("data after the end of a turn")),
            None => Err(GpgError::Protocol("turn without OK, ERR or INQUIRE")),
        }
    }
}

/// Worker side: accumulates gpg-agent output and yields complete turns.
///
/// Turns may carry signatures and decrypted session keys, so the buffer is a
/// [`Zeroizing`] one that grows only into a new buffer (the old one is wiped, no copy is
/// left behind in freed memory); consumed bytes are overwritten at once.
#[derive(Debug, Clone, Default)]
pub struct TurnCollector {
    /// Bytes received but not yet returned as a turn.
    pending: Zeroizing<Vec<u8>>,
    /// Offset in `pending` up to which complete lines were already checked.
    scanned: usize,
}

impl TurnCollector {
    /// An empty collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends bytes read from gpg-agent and returns a turn once its terminator arrived.
    /// Bytes after the terminator stay buffered (gpg-agent never sends them unasked; if
    /// it does, the next call returns them).
    ///
    /// Errors: [`GpgError::TooLarge`], [`GpgError::LineTooLong`], [`GpgError::Malformed`].
    pub fn push(&mut self, bytes: &[u8]) -> Result<Option<Turn>, GpgError> {
        append_zeroizing(&mut self.pending, bytes);
        while let Some((line, next)) = next_line(&self.pending, self.scanned)? {
            if next > MAX_GPG_CHUNK {
                return Err(GpgError::TooLarge);
            }
            let end = match parse_server_line(line)? {
                ServerLine::Ok(_) => Some(TurnEnd::Ok),
                ServerLine::Err { .. } => Some(TurnEnd::Err),
                ServerLine::Inquire { .. } => Some(TurnEnd::Inquire),
                _ => None,
            };
            self.scanned = next;
            if let Some(end) = end {
                let bytes = Zeroizing::new(self.pending[..next].to_vec());
                consume_zeroizing(&mut self.pending, next);
                self.scanned = 0;
                return Ok(Some(Turn { bytes, end }));
            }
        }
        if self.pending.len() > MAX_GPG_CHUNK {
            return Err(GpgError::TooLarge);
        }
        Ok(None)
    }

    /// Whether bytes are buffered.
    pub fn has_partial(&self) -> bool {
        !self.pending.is_empty()
    }
}

/// Appends `bytes` to `buffer` without reallocating in place: a buffer that is too
/// small is replaced by a larger one and wiped as it is dropped.
pub fn append_zeroizing(buffer: &mut Zeroizing<Vec<u8>>, bytes: &[u8]) {
    let needed = buffer.len() + bytes.len();
    if needed > buffer.capacity() {
        let mut larger = Zeroizing::new(Vec::with_capacity(needed.max(buffer.capacity() * 2)));
        larger.extend_from_slice(buffer);
        *buffer = larger;
    }
    buffer.extend_from_slice(bytes);
}

/// Drops the first `count` bytes of `buffer` and overwrites the bytes that moving the
/// rest left behind.
pub fn consume_zeroizing(buffer: &mut Zeroizing<Vec<u8>>, count: usize) {
    buffer.drain(..count);
    for byte in buffer.spare_capacity_mut() {
        byte.write(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds `input` in chunks of `chunk` bytes and collects units, answering each with
    /// the matching entry of `turns` (whether it ends with INQUIRE).
    fn units(input: &[u8], chunk: usize, inquires: &[bool]) -> Vec<Vec<u8>> {
        let mut framer = ClientFramer::new();
        let mut out = Vec::new();
        let mut inquires = inquires.iter();
        for piece in input.chunks(chunk) {
            framer.push(piece).unwrap();
            while let Some(unit) = framer.next_unit().unwrap() {
                out.push(unit.to_vec());
                framer.turn_ended(*inquires.next().unwrap_or(&false));
            }
        }
        assert!(!framer.has_partial());
        out
    }

    #[test]
    fn commands_one_per_unit() {
        let input = b"RESET\nOPTION ttyname=/dev/pts/1\nHAVEKEY ABC\n";
        for chunk in [1, 3, 7, input.len()] {
            assert_eq!(
                units(input, chunk, &[]),
                vec![b"RESET\n".to_vec(), b"OPTION ttyname=/dev/pts/1\n".to_vec(), b"HAVEKEY ABC\n".to_vec()]
            );
        }
    }

    #[test]
    fn inquiry_answer_is_one_unit() {
        let input = b"PKDECRYPT\nD (7:enc-val\nD %25more\nEND\nBYE\n";
        for chunk in [1, 2, 5, input.len()] {
            assert_eq!(
                units(input, chunk, &[true, false, false]),
                vec![b"PKDECRYPT\n".to_vec(), b"D (7:enc-val\nD %25more\nEND\n".to_vec(), b"BYE\n".to_vec()]
            );
        }
        let cancelled = b"PKSIGN\nCAN\n";
        assert_eq!(units(cancelled, 1, &[true]), vec![b"PKSIGN\n".to_vec(), b"CAN\n".to_vec()]);
    }

    #[test]
    fn comments_and_empty_lines_dropped() {
        let input = b"# hello\n\nRESET\nD x\n# inside\nEND\n";
        assert_eq!(units(input, 4, &[true]), vec![b"RESET\n".to_vec(), b"D x\nEND\n".to_vec()]);
    }

    #[test]
    fn waits_for_turn() {
        let mut framer = ClientFramer::new();
        framer.push(b"RESET\nNOP\n").unwrap();
        assert_eq!(framer.next_unit().unwrap().unwrap().as_slice(), b"RESET\n");
        assert_eq!(framer.next_unit().unwrap(), None);
        assert!(framer.has_partial());
        framer.turn_ended(false);
        assert_eq!(framer.next_unit().unwrap().unwrap().as_slice(), b"NOP\n");
    }

    #[test]
    fn framer_protocol_errors() {
        let mut framer = ClientFramer::new();
        framer.push(b"D data\n").unwrap();
        assert!(matches!(framer.next_unit(), Err(GpgError::Protocol(_))));

        let mut framer = ClientFramer::new();
        framer.push(b"END\n").unwrap();
        assert!(matches!(framer.next_unit(), Err(GpgError::Protocol(_))));

        let mut framer = ClientFramer::new();
        framer.turn_ended(true);
        framer.push(b"D x\nPKSIGN\n").unwrap();
        assert!(matches!(framer.next_unit(), Err(GpgError::Protocol(_))));
    }

    #[test]
    fn framer_limits() {
        let mut framer = ClientFramer::new();
        framer.push(&vec![b'A'; MAX_LINE_LEN]).unwrap();
        assert_eq!(framer.next_unit(), Err(GpgError::LineTooLong));

        let mut framer = ClientFramer::new();
        assert_eq!(framer.push(&vec![b'A'; MAX_GPG_CHUNK + 1]), Err(GpgError::TooLarge));

        // A long inquiry answer, fed line by line, stays within the limit or fails.
        let mut framer = ClientFramer::new();
        framer.turn_ended(true);
        let line = [b"D ".as_slice(), &[b'x'; 900], b"\n"].concat();
        let mut result = Ok(None);
        for _ in 0..(MAX_GPG_CHUNK / line.len() + 2) {
            if framer.push(&line).is_err() {
                result = Err(GpgError::TooLarge);
                break;
            }
            result = framer.next_unit();
        }
        assert_eq!(result, Err(GpgError::TooLarge));
    }

    #[test]
    fn zeroizing_buffers_grow_into_new_buffers_and_wipe_what_moves() {
        let mut buffer = Zeroizing::new(Vec::with_capacity(4));
        append_zeroizing(&mut buffer, b"abc");
        let first = buffer.as_ptr();
        append_zeroizing(&mut buffer, b"d");
        assert_eq!(buffer.as_ptr(), first, "fits: no new buffer");
        append_zeroizing(&mut buffer, b"efgh");
        assert_eq!(buffer.as_slice(), b"abcdefgh");
        assert!(buffer.capacity() >= 8);
        consume_zeroizing(&mut buffer, 3);
        assert_eq!(buffer.as_slice(), b"defgh");
        consume_zeroizing(&mut buffer, 5);
        assert!(buffer.is_empty());
    }

    /// A turn (which may hold a signature or a session key) is handed out in a wiped
    /// buffer of its own, and what stays behind in the collector moves without leaving a
    /// copy.
    #[test]
    fn collector_hands_out_turns_and_wipes_behind_them() {
        let mut collector = TurnCollector::new();
        assert_eq!(collector.push(b"D (7:sig-val)\n").unwrap(), None);
        let turn = collector.push(b"OK\nS LEFT").unwrap().unwrap();
        let buffer = collector.pending.as_ptr();
        assert_eq!(turn.bytes.as_slice(), b"D (7:sig-val)\nOK\n");
        assert_eq!(turn.bytes.capacity(), turn.bytes.len());
        assert_eq!(collector.pending.as_slice(), b"S LEFT");
        assert_eq!(collector.push(b" MORE").unwrap(), None);
        assert_eq!(collector.pending.as_ptr(), buffer, "fits: no new buffer");
    }

    /// An inquiry answer (which may hold a passphrase) arriving in many pieces: the
    /// buffer never moves, so no partial copy is left behind, and the unit comes out
    /// whole once `END` arrives.
    #[test]
    fn framer_buffer_never_moves() {
        let mut framer = ClientFramer::new();
        framer.turn_ended(true);
        framer.push(b"D ").unwrap();
        let buffer = framer.pending.as_ptr();
        assert!(framer.pending.capacity() >= MAX_GPG_CHUNK);
        let line = [&[b's'; 900][..], b"\nD "].concat();
        for _ in 0..40 {
            for piece in line.chunks(7) {
                framer.push(piece).unwrap();
                assert_eq!(framer.next_unit().unwrap(), None);
            }
        }
        framer.push(b"x\n# comment\nEND\n").unwrap();
        let unit = framer.next_unit().unwrap().unwrap();
        assert_eq!(framer.pending.as_ptr(), buffer);
        assert!(
            unit.starts_with(b"D sss") && unit.ends_with(b"\nD x\nEND\n"),
            "{:?}",
            &unit[unit.len() - 20..]
        );
        assert!(!unit.windows(9).any(|w| w == b"# comment"));
        assert_eq!(unit.len(), 2 + 40 * line.len() + 2 + 4);
        assert!(!framer.has_partial());
        assert!(framer.pending.is_empty());
    }

    #[test]
    fn collector_turns() {
        let output = b"OK Pleased to meet you\nS PROGRESS x\nD (7:sig-val)\nOK\nINQUIRE CIPHERTEXT\nERR 67109115 Forbidden\n";
        for chunk in [1, 4, output.len()] {
            let mut collector = TurnCollector::new();
            let mut turns = Vec::new();
            for piece in output.chunks(chunk) {
                let mut piece = piece;
                while let Some(turn) = collector.push(piece).unwrap() {
                    turns.push(turn);
                    piece = b"";
                }
            }
            assert!(!collector.has_partial());
            assert_eq!(
                turns,
                vec![
                    Turn { bytes: b"OK Pleased to meet you\n".to_vec().into(), end: TurnEnd::Ok },
                    Turn { bytes: b"S PROGRESS x\nD (7:sig-val)\nOK\n".to_vec().into(), end: TurnEnd::Ok },
                    Turn { bytes: b"INQUIRE CIPHERTEXT\n".to_vec().into(), end: TurnEnd::Inquire },
                    Turn { bytes: b"ERR 67109115 Forbidden\n".to_vec().into(), end: TurnEnd::Err },
                ]
            );
        }
    }

    #[test]
    fn collector_errors() {
        let mut collector = TurnCollector::new();
        assert!(matches!(collector.push(b"BOGUS\n"), Err(GpgError::Malformed(_))));

        let mut collector = TurnCollector::new();
        assert_eq!(collector.push(&vec![b'D'; MAX_LINE_LEN]), Err(GpgError::LineTooLong));

        let mut collector = TurnCollector::new();
        let line = [b"D ".as_slice(), &[b'x'; 900], b"\n"].concat();
        let mut result = Ok(None);
        for _ in 0..(MAX_GPG_CHUNK / line.len() + 2) {
            result = collector.push(&line);
            if result.is_err() {
                break;
            }
        }
        assert_eq!(result, Err(GpgError::TooLarge));
    }

    #[test]
    fn turn_parse() {
        assert_eq!(Turn::parse(b"D x\nOK\n").unwrap().end, TurnEnd::Ok);
        assert_eq!(Turn::parse(b"INQUIRE X\n").unwrap().end, TurnEnd::Inquire);
        assert!(matches!(Turn::parse(b"D x\n"), Err(GpgError::Protocol(_))));
        assert!(matches!(Turn::parse(b"OK\nOK\n"), Err(GpgError::Protocol(_))));
        assert!(matches!(Turn::parse(b"OK"), Err(GpgError::Protocol(_))));
        assert!(matches!(Turn::parse(b"NOPE\n"), Err(GpgError::Malformed(_))));
    }
}
