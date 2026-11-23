//! Parsing of the RFC 3339 timestamps GitHub sends (`2016-07-11T22:14:10Z`).

use std::time::{Duration, SystemTime};

/// Parses `YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)` into a point in time. Fractions of
/// a second are dropped. Times before 1970 are rejected.
pub(crate) fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let num = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = text.get(range)?;
        part.bytes().all(|b| b.is_ascii_digit()).then(|| part.parse().ok())?
    };
    let separators = [(4, b'-'), (7, b'-'), (13, b':'), (16, b':')];
    if separators.iter().any(|&(at, sep)| bytes[at] != sep) || !matches!(bytes[10], b'T' | b't' | b' ') {
        return None;
    }
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&month) || !(1..=days_in_month(year, month)).contains(&day) {
        return None;
    }
    // 60 allows a leap second; it is counted as the next second.
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let mut rest = &text[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        rest = &fraction[digits..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            if rest.len() != 6 || rest.as_bytes()[3] != b':' {
                return None;
            }
            let (h, m) = (rest[1..3].parse::<i64>().ok()?, rest[4..6].parse::<i64>().ok()?);
            if h > 23 || m > 59 {
                return None;
            }
            sign * (h * 3600 + m * 60)
        }
    };

    let secs = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset;
    u64::try_from(secs).ok().map(|secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(text: &str) -> Option<u64> {
        parse_rfc3339(text).map(|t| t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs())
    }

    #[test]
    fn parses_github_timestamps() {
        assert_eq!(secs("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(secs("2016-07-11T22:14:10Z"), Some(1_468_275_250));
        assert_eq!(secs("2024-02-29T12:00:00Z"), Some(1_709_208_000));
        assert_eq!(secs("2016-07-11T22:14:10.123Z"), Some(1_468_275_250));
        assert_eq!(secs("2016-07-12T00:14:10+02:00"), Some(1_468_275_250));
        assert_eq!(secs("2016-07-11T21:14:10-01:00"), Some(1_468_275_250));
    }

    #[test]
    fn rejects_malformed_timestamps() {
        for text in [
            "",
            "2016-07-11",
            "2016-07-11T22:14:10",
            "2016-13-11T22:14:10Z",
            "2023-02-29T22:14:10Z",
            "2016-07-11T24:14:10Z",
            "2016-07-11T22:14:10.Z",
            "2016-07-11T22:14:10+0200",
            "1969-12-31T23:59:59Z",
            "+016-07-11T22:14:10Z",
        ] {
            assert_eq!(secs(text), None, "{text}");
        }
    }
}
