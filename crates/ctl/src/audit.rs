//! Reading the daemon's audit log (JSON lines, `crates/daemon/src/audit.rs`): its end for
//! `check`'s recent requests, and the lines appended after a [`Mark`] for the probe.

use std::fs::File;
use std::io::{self, Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

/// One audit event: the JSON object of a line.
pub type Event = serde_json::Map<String, serde_json::Value>;

/// The events in `text`, skipping lines that are not JSON objects.
pub fn events(text: &str) -> Vec<Event> {
    text.lines()
        .filter_map(|line| match serde_json::from_str::<serde_json::Value>(line) {
            Ok(serde_json::Value::Object(event)) => Some(event),
            _ => None,
        })
        .collect()
}

/// A string field of an event.
pub fn text<'a>(event: &'a Event, key: &str) -> Option<&'a str> {
    event.get(key).and_then(serde_json::Value::as_str)
}

/// At most the last `max` bytes of the log, from the first complete line.
pub fn tail(path: &Path, max: u64) -> io::Result<String> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let start = len.saturating_sub(max);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(max).read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    Ok(if start > 0 {
        text.split_once('\n').map_or(String::new(), |(_, rest)| rest.to_owned())
    } else {
        text
    })
}

/// Where the log ended at one moment: lines written later are read with
/// [`Mark::since`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mark {
    /// Device and inode of the file then; `None` if it did not exist.
    file: Option<(u64, u64)>,
    /// Its length then.
    len: u64,
}

impl Mark {
    /// The end of the log at `path` now.
    pub fn of(path: &Path) -> Mark {
        match std::fs::metadata(path) {
            Ok(meta) => Mark { file: Some((meta.dev(), meta.ino())), len: meta.len() },
            Err(_) => Mark { file: None, len: 0 },
        }
    }

    /// The complete lines written after the mark. A log that was replaced (rotation)
    /// or truncated since is read from its start. Empty if the file does not exist.
    pub fn since(&self, path: &Path) -> io::Result<String> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(String::new()),
            Err(error) => return Err(error),
        };
        let meta = file.metadata()?;
        let start =
            if self.file == Some((meta.dev(), meta.ino())) && meta.len() >= self.len { self.len } else { 0 };
        file.seek(SeekFrom::Start(start))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        // An incomplete last line is still being written.
        let complete = bytes.iter().rposition(|byte| *byte == b'\n').map_or(0, |end| end + 1);
        Ok(String::from_utf8_lossy(&bytes[..complete]).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    #[test]
    fn parses_events_and_skips_garbage() {
        let events =
            events("{\"event\":\"connect\",\"connection\":1}\nnot json\n[1]\n{\"event\":\"sign\"}\n");
        assert_eq!(events.len(), 2);
        assert_eq!(text(&events[0], "event"), Some("connect"));
        assert_eq!(text(&events[0], "connection"), None);
    }

    #[test]
    fn tail_starts_at_a_complete_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "first line\nsecond\nthird\n").unwrap();
        assert_eq!(tail(&path, 1024).unwrap(), "first line\nsecond\nthird\n");
        assert_eq!(tail(&path, 10).unwrap(), "third\n");
        assert!(tail(&dir.path().join("missing"), 10).is_err());
    }

    #[test]
    fn reads_what_was_written_after_the_mark() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let missing = Mark::of(&path);
        assert_eq!(missing.since(&path).unwrap(), "");
        std::fs::write(&path, "old\n").unwrap();
        // The file appeared after the mark: everything is new.
        assert_eq!(missing.since(&path).unwrap(), "old\n");

        let mark = Mark::of(&path);
        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"new\npartial").unwrap();
        assert_eq!(mark.since(&path).unwrap(), "new\n");

        // Rotated: the new file is read from its start.
        std::fs::rename(&path, dir.path().join("audit.log.1")).unwrap();
        std::fs::write(&path, "after rotation\n").unwrap();
        assert_eq!(mark.since(&path).unwrap(), "after rotation\n");
    }
}
