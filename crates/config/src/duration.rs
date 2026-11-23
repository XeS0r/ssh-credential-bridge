//! Durations in the configuration, e.g. `confirm = "8h"`.
//!
//! Syntax: one or more `<number><unit>` groups without spaces, units `s`, `m`, `h`, `d`
//! (`"90m"`, `"1h30m"`, `"7d"`). Zero and values above 365 days are invalid.

use std::time::Duration;

/// The longest accepted duration: 365 days.
pub const MAX_DURATION: Duration = Duration::from_secs(365 * DAY);

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

/// Error of parsing a duration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid duration {input:?}: expected e.g. \"30m\", \"8h\" or \"1h30m\"")]
pub struct DurationError {
    /// The input.
    pub input: String,
}

/// Parses a duration as described in the module documentation.
pub fn parse_duration(input: &str) -> Result<Duration, DurationError> {
    let error = || DurationError { input: input.to_owned() };
    if input.is_empty() {
        return Err(error());
    }
    let mut total: u64 = 0;
    let mut number: Option<u64> = None;
    for c in input.chars() {
        if let Some(digit) = c.to_digit(10) {
            let value = number.unwrap_or(0).checked_mul(10).and_then(|n| n.checked_add(u64::from(digit)));
            number = Some(value.ok_or_else(error)?);
            continue;
        }
        let unit = match c {
            's' => 1,
            'm' => MINUTE,
            'h' => HOUR,
            'd' => DAY,
            _ => return Err(error()),
        };
        let value = number.take().ok_or_else(error)?;
        let seconds = value.checked_mul(unit).ok_or_else(error)?;
        total = total.checked_add(seconds).ok_or_else(error)?;
    }
    // A trailing number without unit ("8") is ambiguous.
    if number.is_some() {
        return Err(error());
    }
    let duration = Duration::from_secs(total);
    if duration.is_zero() || duration > MAX_DURATION {
        return Err(error());
    }
    Ok(duration)
}

/// Formats a duration in the same syntax, largest units first (`5400s` → `"1h30m"`).
/// Sub-second parts are dropped; zero is `"0s"`.
pub fn format_duration(duration: Duration) -> String {
    let mut rest = duration.as_secs();
    if rest == 0 {
        return "0s".to_owned();
    }
    let mut out = String::new();
    for (unit, suffix) in [(DAY, 'd'), (HOUR, 'h'), (MINUTE, 'm'), (1, 's')] {
        let count = rest / unit;
        if count > 0 {
            out.push_str(&count.to_string());
            out.push(suffix);
            rest %= unit;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_and_combined_units() {
        assert_eq!(parse_duration("8h"), Ok(Duration::from_secs(8 * 3600)));
        assert_eq!(parse_duration("90m"), Ok(Duration::from_secs(5400)));
        assert_eq!(parse_duration("1h30m"), Ok(Duration::from_secs(5400)));
        assert_eq!(parse_duration("7d"), Ok(Duration::from_secs(7 * 86400)));
        assert_eq!(parse_duration("45s"), Ok(Duration::from_secs(45)));
        assert_eq!(parse_duration("1d2h3m4s"), Ok(Duration::from_secs(86400 + 7200 + 180 + 4)));
        assert_eq!(parse_duration("365d"), Ok(MAX_DURATION));
    }

    #[test]
    fn rejects_bad_input() {
        for input in [
            "",
            "8",
            "h",
            "8x",
            "8 h",
            " 8h",
            "8h ",
            "-1h",
            "0s",
            "0h0m",
            "366d",
            "1.5h",
            "8H",
            "99999999999999999999s",
            "18446744073709551615d",
        ] {
            assert!(parse_duration(input).is_err(), "{input:?} should be rejected");
        }
    }

    #[test]
    fn error_message_names_input() {
        let err = parse_duration("soon").unwrap_err();
        assert!(err.to_string().contains("\"soon\""));
    }

    #[test]
    fn formats_largest_units_first() {
        assert_eq!(format_duration(Duration::from_secs(5400)), "1h30m");
        assert_eq!(format_duration(Duration::from_secs(8 * 3600)), "8h");
        assert_eq!(format_duration(Duration::from_secs(86400 + 1)), "1d1s");
        assert_eq!(format_duration(Duration::ZERO), "0s");
        assert_eq!(format_duration(Duration::from_millis(1500)), "1s");
    }

    #[test]
    fn format_round_trips() {
        for secs in [1, 59, 60, 61, 3599, 3600, 5400, 86399, 86400, 90061, 365 * 86400] {
            let d = Duration::from_secs(secs);
            assert_eq!(parse_duration(&format_duration(d)), Ok(d));
        }
    }
}
