//! Assuan lines (libassuan, "Client requests" / "Server responses").
//!
//! A line ends with LF and is at most [`MAX_LINE_LEN`] bytes including the LF. In `D`
//! lines `%`, CR and LF are percent-escaped. Parsers take one line **without** its LF.
//!
//! Like libassuan, the parsers compare `D`, `END`, `CAN`, `OK`, `ERR`, `S` and
//! `INQUIRE` case-sensitively; command verbs are returned as sent and compared
//! case-insensitively by the [`crate::filter`]. Arguments are returned raw, without
//! the spaces that separate them from the verb or keyword.

use crate::GpgError;

/// `ASSUAN_LINELENGTH`: longest line including LF.
pub const MAX_LINE_LEN: usize = 1000;

/// `GPG_ERR_FORBIDDEN` with source gpg-agent, as gpg-agent itself reports it
/// (`ERR 67109115 Forbidden`).
pub const ERR_FORBIDDEN: u32 = (4 << 24) | 251;

/// `GPG_ERR_ASS_UNKNOWN_CMD` with source gpg-agent.
pub const ERR_UNKNOWN_COMMAND: u32 = (4 << 24) | 275;

/// Longest command verb the parser accepts (libassuan's own limit is lower in practice).
const MAX_VERB_LEN: usize = 64;

/// A line from the client (gpg on the server).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientLine<'a> {
    /// A command: verb (as sent; compare case-insensitively) and raw arguments.
    Command {
        /// e.g. `PKSIGN`.
        verb: &'a str,
        /// Everything after the first space, unparsed.
        args: &'a [u8],
    },
    /// `D <escaped data>` (only valid while answering an `INQUIRE`).
    Data(&'a [u8]),
    /// `END` (ends an inquiry answer).
    End,
    /// `CAN` (cancels an inquiry).
    Cancel,
    /// `# comment`.
    Comment,
}

/// A line from the server (gpg-agent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerLine<'a> {
    /// `OK [text]`: the command finished.
    Ok(&'a [u8]),
    /// `ERR <code> [description]`: the command failed.
    Err {
        /// The gpg-error code.
        code: u32,
        /// Description.
        description: &'a [u8],
    },
    /// `S <keyword> [args]`: status.
    Status {
        /// Keyword.
        keyword: &'a str,
        /// Arguments.
        args: &'a [u8],
    },
    /// `D <escaped data>`.
    Data(&'a [u8]),
    /// `INQUIRE <keyword> [args]`: the server waits for `D`… `END` or `CAN`.
    Inquire {
        /// Keyword.
        keyword: &'a str,
        /// Arguments.
        args: &'a [u8],
    },
    /// `END` after data.
    End,
    /// `# comment`.
    Comment,
}

impl ServerLine<'_> {
    /// Whether this line ends a server turn (`OK`, `ERR`, `INQUIRE`).
    pub fn is_terminator(&self) -> bool {
        matches!(self, ServerLine::Ok(_) | ServerLine::Err { .. } | ServerLine::Inquire { .. })
    }
}

/// Splits `line` into the leading word and the rest after the separating spaces.
/// Returns `None` if `line` does not start with `word` followed by a space or the end.
fn strip_word<'a>(line: &'a [u8], word: &[u8]) -> Option<&'a [u8]> {
    let rest = line.strip_prefix(word)?;
    match rest.first() {
        None => Some(rest),
        Some(b' ') => Some(skip_spaces(rest)),
        Some(_) => None,
    }
}

/// Whether `byte` separates words. libassuan splits a command line at spaces and tabs.
fn is_blank(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

/// Drops leading spaces and tabs.
fn skip_spaces(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| !is_blank(b)).unwrap_or(bytes.len());
    &bytes[start..]
}

/// Splits off the first word (ended by a space or tab) and the rest (leading blanks
/// dropped), as libassuan does for a command's verb and its arguments.
fn split_word(bytes: &[u8]) -> (&[u8], &[u8]) {
    match bytes.iter().position(|&b| is_blank(b)) {
        Some(i) => (&bytes[..i], skip_spaces(&bytes[i..])),
        None => (bytes, &[]),
    }
}

/// Whether `word` is a plausible verb or keyword: ASCII letters, digits, `_` and `-`.
fn valid_word(word: &[u8]) -> bool {
    !word.is_empty()
        && word.len() <= MAX_VERB_LEN
        && word.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Checks the length limit for a line without its LF.
fn check_len(line: &[u8]) -> Result<(), GpgError> {
    if line.len() + 1 > MAX_LINE_LEN { Err(GpgError::LineTooLong) } else { Ok(()) }
}

/// Parses a word already checked by [`valid_word`] as `&str`.
fn word_str(word: &[u8]) -> &str {
    // valid_word only admits ASCII, so this cannot fail.
    std::str::from_utf8(word).unwrap_or_default()
}

/// Parses one client line (without LF).
/// Errors: [`GpgError::LineTooLong`], [`GpgError::Malformed`] (empty, non-UTF-8 verb).
pub fn parse_client_line(line: &[u8]) -> Result<ClientLine<'_>, GpgError> {
    check_len(line)?;
    if line.contains(&b'\n') {
        return Err(GpgError::Malformed("line contains LF"));
    }
    if line.is_empty() {
        return Err(GpgError::Malformed("empty line"));
    }
    if line[0] == b'#' {
        return Ok(ClientLine::Comment);
    }
    if line == b"D" {
        return Ok(ClientLine::Data(&[]));
    }
    if let Some(data) = line.strip_prefix(b"D ") {
        return Ok(ClientLine::Data(data));
    }
    if line == b"END" {
        return Ok(ClientLine::End);
    }
    if line == b"CAN" {
        return Ok(ClientLine::Cancel);
    }
    let (verb, args) = split_word(line);
    if !valid_word(verb) {
        return Err(GpgError::Malformed("invalid command verb"));
    }
    Ok(ClientLine::Command { verb: word_str(verb), args })
}

/// Parses one server line (without LF).
/// Errors: [`GpgError::LineTooLong`], [`GpgError::Malformed`].
pub fn parse_server_line(line: &[u8]) -> Result<ServerLine<'_>, GpgError> {
    check_len(line)?;
    if line.contains(&b'\n') {
        return Err(GpgError::Malformed("line contains LF"));
    }
    if line.first() == Some(&b'#') {
        return Ok(ServerLine::Comment);
    }
    if line == b"END" {
        return Ok(ServerLine::End);
    }
    if line == b"D" {
        return Ok(ServerLine::Data(&[]));
    }
    if let Some(data) = line.strip_prefix(b"D ") {
        return Ok(ServerLine::Data(data));
    }
    if let Some(text) = strip_word(line, b"OK") {
        return Ok(ServerLine::Ok(text));
    }
    if let Some(rest) = strip_word(line, b"ERR") {
        let (code, description) = split_word(rest);
        if code.is_empty() || !code.iter().all(u8::is_ascii_digit) {
            return Err(GpgError::Malformed("ERR without numeric code"));
        }
        let code = word_str(code).parse().map_err(|_| GpgError::Malformed("ERR code out of range"))?;
        return Ok(ServerLine::Err { code, description });
    }
    if let Some(rest) = strip_word(line, b"S") {
        let (keyword, args) = split_word(rest);
        if !valid_word(keyword) {
            return Err(GpgError::Malformed("invalid status keyword"));
        }
        return Ok(ServerLine::Status { keyword: word_str(keyword), args });
    }
    if let Some(rest) = strip_word(line, b"INQUIRE") {
        let (keyword, args) = split_word(rest);
        if !valid_word(keyword) {
            return Err(GpgError::Malformed("invalid inquire keyword"));
        }
        return Ok(ServerLine::Inquire { keyword: word_str(keyword), args });
    }
    Err(GpgError::Malformed("unknown server line"))
}

/// Formats `ERR <code> <description>\n`; the description is truncated so the line fits
/// [`MAX_LINE_LEN`] and has CR/LF replaced.
pub fn err_line(code: u32, description: &str) -> Vec<u8> {
    let mut line = format!("ERR {code}").into_bytes();
    let description: String =
        description.chars().map(|c| if c == '\r' || c == '\n' { ' ' } else { c }).collect();
    if !description.is_empty() {
        line.push(b' ');
        // Room for the description: everything but the prefix, the space and the LF.
        let room = MAX_LINE_LEN - 1 - line.len();
        let mut end = description.len().min(room);
        while !description.is_char_boundary(end) {
            end -= 1;
        }
        line.extend_from_slice(&description.as_bytes()[..end]);
    }
    line.push(b'\n');
    line
}

/// Formats `OK\n`.
pub fn ok_line() -> Vec<u8> {
    b"OK\n".to_vec()
}

/// Percent-escapes data for a `D` line: `%`, CR and LF become `%25`, `%0D`, `%0A`.
pub fn escape_data(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        match b {
            b'%' | b'\r' | b'\n' => out.extend_from_slice(format!("%{b:02X}").as_bytes()),
            _ => out.push(b),
        }
    }
    out
}

/// Reverses percent-escaping of `D` line data (any `%XX`, upper or lower case hex).
/// Errors: [`GpgError::Malformed`] for a `%` not followed by two hex digits.
pub fn unescape_data(escaped: &[u8]) -> Result<Vec<u8>, GpgError> {
    let mut out = Vec::with_capacity(escaped.len());
    let mut i = 0;
    while i < escaped.len() {
        if escaped[i] == b'%' {
            let hex = escaped.get(i + 1..i + 3).ok_or(GpgError::Malformed("truncated escape"))?;
            let value = std::str::from_utf8(hex)
                .ok()
                .filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or(GpgError::Malformed("invalid escape"))?;
            out.push(value);
            i += 3;
        } else {
            out.push(escaped[i]);
            i += 1;
        }
    }
    Ok(out)
}

/// Formats `data` as `D` lines (escaped, each within [`MAX_LINE_LEN`]), without a
/// trailing `END`. Empty data yields no lines.
pub fn data_lines(data: &[u8]) -> Vec<u8> {
    // "D " + payload + LF; an escape takes three bytes and is never split.
    let room = MAX_LINE_LEN - 3;
    let mut out = Vec::new();
    let mut line = Vec::with_capacity(room);
    for &b in data {
        let escaped: &[u8] = match b {
            b'%' => b"%25",
            b'\r' => b"%0D",
            b'\n' => b"%0A",
            _ => std::slice::from_ref(&b),
        };
        if line.len() + escaped.len() > room {
            out.extend_from_slice(b"D ");
            out.append(&mut line);
            out.push(b'\n');
        }
        line.extend_from_slice(escaped);
    }
    if !line.is_empty() {
        out.extend_from_slice(b"D ");
        out.append(&mut line);
        out.push(b'\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_commands() {
        assert_eq!(parse_client_line(b"PKSIGN").unwrap(), ClientLine::Command { verb: "PKSIGN", args: b"" });
        assert_eq!(
            parse_client_line(b"sethash  --hash=sha256 ABCD").unwrap(),
            ClientLine::Command { verb: "sethash", args: b"--hash=sha256 ABCD" }
        );
        assert_eq!(
            parse_client_line(b"OPTION display=:0").unwrap(),
            ClientLine::Command { verb: "OPTION", args: b"display=:0" }
        );
        assert_eq!(
            parse_client_line(b"EXPORT_KEY x").unwrap(),
            ClientLine::Command { verb: "EXPORT_KEY", args: b"x" }
        );
    }

    #[test]
    fn client_inquiry_lines() {
        assert_eq!(parse_client_line(b"D abc%25").unwrap(), ClientLine::Data(b"abc%25"));
        assert_eq!(parse_client_line(b"D").unwrap(), ClientLine::Data(b""));
        assert_eq!(parse_client_line(b"END").unwrap(), ClientLine::End);
        assert_eq!(parse_client_line(b"CAN").unwrap(), ClientLine::Cancel);
        assert_eq!(parse_client_line(b"# hello").unwrap(), ClientLine::Comment);
        // Lower case is a command, as in libassuan's inquiry handling.
        assert_eq!(parse_client_line(b"end").unwrap(), ClientLine::Command { verb: "end", args: b"" });
        // "DATA" is a command, not a D line.
        assert_eq!(parse_client_line(b"DATA x").unwrap(), ClientLine::Command { verb: "DATA", args: b"x" });
    }

    #[test]
    fn client_malformed() {
        assert_eq!(parse_client_line(b""), Err(GpgError::Malformed("empty line")));
        assert!(matches!(parse_client_line(b" PKSIGN"), Err(GpgError::Malformed(_))));
        assert!(matches!(parse_client_line(b"PK\xffSIGN"), Err(GpgError::Malformed(_))));
        assert!(matches!(parse_client_line(b"PKSIGN\r"), Err(GpgError::Malformed(_))));
        assert!(matches!(parse_client_line(b"A\nB"), Err(GpgError::Malformed(_))));
        let long = vec![b'A'; MAX_LINE_LEN];
        assert_eq!(parse_client_line(&long), Err(GpgError::LineTooLong));
        let fits = [b"D ".as_slice(), &vec![b'x'; MAX_LINE_LEN - 3]].concat();
        assert!(parse_client_line(&fits).is_ok());
    }

    #[test]
    fn server_lines() {
        assert_eq!(parse_server_line(b"OK").unwrap(), ServerLine::Ok(b""));
        assert_eq!(
            parse_server_line(b"OK Pleased to meet you").unwrap(),
            ServerLine::Ok(b"Pleased to meet you")
        );
        assert_eq!(
            parse_server_line(b"ERR 67109115 Forbidden <GPG Agent>").unwrap(),
            ServerLine::Err { code: ERR_FORBIDDEN, description: b"Forbidden <GPG Agent>" }
        );
        assert_eq!(parse_server_line(b"ERR 1").unwrap(), ServerLine::Err { code: 1, description: b"" });
        assert_eq!(
            parse_server_line(b"S INQUIRE_MAXLEN 4096").unwrap(),
            ServerLine::Status { keyword: "INQUIRE_MAXLEN", args: b"4096" }
        );
        assert_eq!(
            parse_server_line(b"INQUIRE CIPHERTEXT").unwrap(),
            ServerLine::Inquire { keyword: "CIPHERTEXT", args: b"" }
        );
        assert_eq!(
            parse_server_line(b"INQUIRE PINENTRY_LAUNCHED 1234 curses 1.2.1 - - -").unwrap(),
            ServerLine::Inquire { keyword: "PINENTRY_LAUNCHED", args: b"1234 curses 1.2.1 - - -" }
        );
        assert_eq!(parse_server_line(b"D (7:sig-val)").unwrap(), ServerLine::Data(b"(7:sig-val)"));
        assert_eq!(parse_server_line(b"END").unwrap(), ServerLine::End);
        assert_eq!(parse_server_line(b"# debug").unwrap(), ServerLine::Comment);
        assert!(parse_server_line(b"OK").unwrap().is_terminator());
        assert!(parse_server_line(b"INQUIRE X").unwrap().is_terminator());
        assert!(!parse_server_line(b"S PROGRESS").unwrap().is_terminator());
        assert!(!parse_server_line(b"D x").unwrap().is_terminator());
    }

    #[test]
    fn server_malformed() {
        for line in [
            b"".as_slice(),
            b"OKAY",
            b"ERR",
            b"ERR abc",
            b"ERR 99999999999",
            b"S",
            b"INQUIRE",
            b"INQUIRE \xff",
            b"ok",
            b"HELLO",
        ] {
            assert!(matches!(parse_server_line(line), Err(GpgError::Malformed(_))), "{line:?}");
        }
        assert_eq!(parse_server_line(&vec![b'#'; MAX_LINE_LEN]), Err(GpgError::LineTooLong));
    }

    #[test]
    fn err_line_format() {
        assert_eq!(err_line(ERR_FORBIDDEN, "Forbidden"), b"ERR 67109115 Forbidden\n");
        assert_eq!(err_line(5, ""), b"ERR 5\n");
        assert_eq!(err_line(5, "a\r\nb"), b"ERR 5 a  b\n");
        let long = "\u{e4}".repeat(MAX_LINE_LEN);
        let line = err_line(ERR_FORBIDDEN, &long);
        assert!(line.len() <= MAX_LINE_LEN);
        assert_eq!(line.last(), Some(&b'\n'));
        let text = std::str::from_utf8(&line).unwrap();
        assert!(text.starts_with("ERR 67109115 \u{e4}"));
        assert!(matches!(parse_server_line(&line[..line.len() - 1]), Ok(ServerLine::Err { .. })));
    }

    #[test]
    fn escaping_round_trip() {
        let data = b"100%\r\nbinary\x00\xff";
        let escaped = escape_data(data);
        assert_eq!(escaped, b"100%25%0D%0Abinary\x00\xff");
        assert_eq!(unescape_data(&escaped).unwrap(), data);
        assert_eq!(unescape_data(b"%0a%2b").unwrap(), b"\n+");
        assert!(unescape_data(b"%").is_err());
        assert!(unescape_data(b"%4").is_err());
        assert!(unescape_data(b"%zz").is_err());
        assert!(unescape_data(b"%+1").is_err());
    }

    #[test]
    fn data_lines_split() {
        assert!(data_lines(b"").is_empty());
        assert_eq!(data_lines(b"a%b"), b"D a%25b\n");
        let data: Vec<u8> = (0..5000u32).map(|i| if i % 7 == 0 { b'\n' } else { b'x' }).collect();
        let lines = data_lines(&data);
        let mut decoded = Vec::new();
        for line in lines.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
            assert!(line.len() < MAX_LINE_LEN);
            let ClientLine::Data(escaped) = parse_client_line(line).unwrap() else { panic!("not D") };
            decoded.extend(unescape_data(escaped).unwrap());
        }
        assert_eq!(decoded, data);
    }
}
