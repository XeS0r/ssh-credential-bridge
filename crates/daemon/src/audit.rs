//! The audit log: one JSON object per line, append-only, mode 0600. Never contains
//! message contents, tokens or secrets (security rule 9). `credential-bridge-ctl log`
//! reads it.
//!
//! [`AuditLog::record`] never blocks a request: it renders the line and queues it for a
//! dedicated writer thread (bounded queue of [`QUEUE_LEN`] lines). The thread keeps the
//! file open and reopens it when it was moved or deleted (log rotation). Lines that do
//! not fit into a full queue are counted; the count is written as a `dropped` event as
//! soon as there is room again, and logged. At shutdown [`AuditLog::close`] writes what
//! is queued and joins the thread.

use std::fs::File;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::sync::lock;

/// Lines that may wait for the writer thread.
const QUEUE_LEN: usize = 4096;

/// One audit event. Serialized with `"event": "<variant in snake_case>"` plus the
/// fields and a `time` (RFC 3339, UTC) added by [`AuditLog::record`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    /// A connection was accepted.
    Connect {
        /// The connection's number, shared by its `client` and `server` events.
        connection: u64,
        /// `local` or `forward`.
        socket: &'static str,
        /// Peer process id and name.
        peer: Option<String>,
    },
    /// The local ssh client of a connection on `agent-forward.sock`, checked before its
    /// first message: only OpenSSH 8.9 or later lets a bind select the server.
    Client {
        /// The connection's number.
        connection: u64,
        /// `OpenSSH 10.2`, or why the client is not verified.
        client: String,
        /// Whether a session-bind as the first message may select the server.
        server_recognition: bool,
    },
    /// The server bind (a verified forwarding bind that is the connection's first
    /// message) selected a server (or none for an unregistered host key).
    Server {
        /// The connection's number.
        connection: u64,
        /// `[server.*]` name, `None` for an unregistered host key (profile `unregistered`).
        server: Option<String>,
        /// Host key fingerprint.
        host_key: String,
        /// Profile in force.
        profile: Option<String>,
        /// Where the matching key came from: `pinned` (`host_keys`) or `known_hosts`;
        /// `None` without a server.
        #[serde(skip_serializing_if = "Option::is_none")]
        source: Option<&'static str>,
        /// The servers that all have this host key (it then selects none of them).
        #[serde(skip_serializing_if = "Vec::is_empty")]
        ambiguous: Vec<String>,
    },
    /// A further forwarding bind (hop); host key only logged.
    Hop {
        /// Host key fingerprint.
        host_key: String,
    },
    /// A signature was requested.
    Sign {
        /// The server label (see [`crate::connection::server_label`]): the
        /// `[server.*]` name, `local`, `unregistered host SHA256:…`, or `unrecognised host (…)`.
        server: String,
        /// Key fingerprint.
        key: String,
        /// Upstream used.
        upstream: Option<String>,
        /// `ok`, `refused`, `denied` (approval), `failed`.
        outcome: &'static str,
    },
    /// A git credential was requested.
    Git {
        /// The server label (see [`crate::connection::server_label`]): the
        /// `[server.*]` name, `local`, `unregistered host SHA256:…`, or `unrecognised host (…)`.
        server: String,
        /// Host and path.
        target: String,
        /// Matching rule pattern.
        rule: Option<String>,
        /// Outcome or error message.
        outcome: String,
    },
    /// A gpg tunnel opened or a command was filtered.
    Gpg {
        /// The server label (see [`crate::connection::server_label`]): the
        /// `[server.*]` name, `local`, `unregistered host SHA256:…`, or `unrecognised host (…)`.
        server: String,
        /// The Assuan verb (only the verb).
        command: String,
        /// `allowed` or `denied`.
        outcome: &'static str,
    },
    /// A request was refused by policy.
    Refused {
        /// The server label (see [`crate::connection::server_label`]): the
        /// `[server.*]` name, `local`, `unregistered host SHA256:…`, or `unrecognised host (…)`.
        server: String,
        /// The reason from [`crate::policy::Decision::Refuse`].
        reason: &'static str,
    },
    /// A worker started, exited or ran without a sandbox layer.
    Worker {
        /// `git`, `vault`, `gpg`.
        kind: &'static str,
        /// What happened.
        message: String,
    },
    /// Events were lost because the writer fell behind (written by the log itself).
    Dropped {
        /// How many events are missing before this line.
        count: u64,
    },
}

/// A message to the writer thread.
enum Queued {
    /// A rendered line.
    Line(String),
    /// Answer once everything queued before has been written.
    Flush(std::sync::mpsc::Sender<()>),
}

/// The audit log writer.
#[derive(Debug)]
pub struct AuditLog {
    /// The file path.
    path: PathBuf,
    /// Lines to the writer thread; `None` if the thread could not be started or the log
    /// was closed (lines are then counted as dropped). The lock is held only to use or
    /// take the sender, never while waiting.
    queue: Mutex<Option<SyncSender<Queued>>>,
    /// The writer thread, joined by [`AuditLog::close`].
    writer: Mutex<Option<JoinHandle<()>>>,
    /// Lines that did not fit into the queue and are not yet reported.
    dropped: Arc<AtomicU64>,
}

impl AuditLog {
    /// A log writing to `path` (created with mode 0600 on first write).
    pub fn new(path: PathBuf) -> Self {
        Self::with_queue(path, QUEUE_LEN)
    }

    /// As [`AuditLog::new`] with a queue of `len` lines.
    fn with_queue(path: PathBuf, len: usize) -> Self {
        let (queue, lines) = std::sync::mpsc::sync_channel(len);
        let dropped = Arc::new(AtomicU64::new(0));
        let writer = Writer { path: path.clone(), file: None, dropped: Arc::clone(&dropped) };
        let started = std::thread::Builder::new()
            .name("credential-bridged-audit".to_owned())
            .spawn(move || writer.run(lines));
        let (queue, writer) = match started {
            Ok(thread) => (Some(queue), Some(thread)),
            Err(error) => {
                tracing::error!("cannot start the audit log writer: {error}");
                (None, None)
            }
        };
        Self { path, queue: Mutex::new(queue), writer: Mutex::new(writer), dropped }
    }

    /// The file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Queues one event for writing; never blocks. Encoding and write errors are reported
    /// through `tracing`; an event that does not fit into a full queue is counted and
    /// reported as a `dropped` event.
    pub fn record(&self, event: &AuditEvent) {
        let line = match render(event, SystemTime::now()) {
            Ok(line) => line,
            Err(error) => {
                tracing::warn!("audit event could not be encoded: {error}");
                return;
            }
        };
        let sent = match &*lock(&self.queue) {
            Some(queue) => match queue.try_send(Queued::Line(line)) {
                Ok(()) => true,
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
            },
            None => false,
        };
        if !sent && self.dropped.fetch_add(1, Ordering::Relaxed) == 0 {
            tracing::warn!("the audit log writer falls behind: events are dropped");
        }
    }

    /// Waits until every event recorded so far has been written (shutdown, tests).
    /// Blocking.
    pub fn flush(&self) {
        let Some(queue) = lock(&self.queue).clone() else { return };
        let (done, wait) = std::sync::mpsc::channel();
        if queue.send(Queued::Flush(done)).is_ok() {
            let _ = wait.recv();
        }
    }

    /// Writes every event recorded so far, stops the writer thread and waits for it
    /// (shutdown). Events recorded afterwards are counted as dropped. Blocking.
    pub fn close(&self) {
        // The writer drains the queue and ends once its only sender is gone.
        drop(lock(&self.queue).take());
        let writer = lock(&self.writer).take();
        if let Some(writer) = writer
            && writer.join().is_err()
        {
            tracing::error!("the audit log writer panicked");
        }
    }
}

/// The writer thread's state.
struct Writer {
    /// The file path.
    path: PathBuf,
    /// The open file with its device and inode at opening.
    file: Option<(File, (u64, u64))>,
    /// Shared with [`AuditLog`].
    dropped: Arc<AtomicU64>,
}

impl Writer {
    /// Writes queued lines until the [`AuditLog`] is dropped. Lines that are already
    /// waiting are written together, with one rotation check per batch.
    fn run(mut self, lines: Receiver<Queued>) {
        while let Ok(first) = lines.recv() {
            let mut batch = String::new();
            let mut flushes = Vec::new();
            let mut take = |queued: Queued| match queued {
                Queued::Line(line) => batch.push_str(&line),
                Queued::Flush(done) => flushes.push(done),
            };
            take(first);
            while let Ok(queued) = lines.try_recv() {
                take(queued);
            }
            let dropped = self.dropped.swap(0, Ordering::Relaxed);
            if dropped > 0 {
                tracing::warn!("{dropped} audit events were dropped");
                if let Ok(line) = render(&AuditEvent::Dropped { count: dropped }, SystemTime::now()) {
                    batch.push_str(&line);
                }
            }
            if !batch.is_empty()
                && let Err(error) = self.append(batch.as_bytes())
            {
                tracing::warn!("cannot write the audit log {}: {error}", self.path.display());
                self.file = None;
            }
            for done in flushes {
                let _ = done.send(());
            }
        }
    }

    /// Appends `lines`, (re)opening the file if it is not open or no longer at the path.
    fn append(&mut self, lines: &[u8]) -> std::io::Result<()> {
        let current = std::fs::metadata(&self.path).ok().map(|meta| (meta.dev(), meta.ino()));
        let file = match &mut self.file {
            Some((file, id)) if Some(*id) == current => file,
            _ => {
                let file = open(&self.path)?;
                let meta = file.metadata()?;
                &mut self.file.insert((file, (meta.dev(), meta.ino()))).0
            }
        };
        file.write_all(lines)
    }
}

/// Opens `path` for appending, creating file and directory privately if needed.
fn open(path: &Path) -> std::io::Result<File> {
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty())
        && !parent.exists()
    {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)?;
    }
    std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(path)
}

/// One log line: the event's JSON object with `time` added, and a newline.
fn render(event: &AuditEvent, now: SystemTime) -> Result<String, serde_json::Error> {
    let mut value = serde_json::to_value(event)?;
    if let serde_json::Value::Object(map) = &mut value {
        map.insert("time".to_owned(), serde_json::Value::String(rfc3339(now)));
    }
    let mut line = serde_json::to_string(&value)?;
    line.push('\n');
    Ok(line)
}

/// `YYYY-MM-DDTHH:MM:SSZ` in UTC. Times before the epoch print as the epoch.
pub(crate) fn rfc3339(time: SystemTime) -> String {
    let secs = time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX);
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem / 60 % 60, rem % 60)
}

/// Converts days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, u32::try_from(month).unwrap_or(1), u32::try_from(day).unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    use super::*;

    #[test]
    fn formats_times() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(UNIX_EPOCH + Duration::from_secs(951_782_400)), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(UNIX_EPOCH + Duration::from_secs(1_795_181_045)), "2026-11-20T13:24:05Z");
    }

    #[test]
    fn writes_json_lines_privately() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs").join("audit.log");
        let log = AuditLog::new(path.clone());
        log.record(&AuditEvent::Connect { connection: 7, socket: "forward", peer: Some("123 ssh".into()) });
        log.record(&AuditEvent::Server {
            connection: 7,
            server: Some("box".into()),
            host_key: "SHA256:k".into(),
            profile: Some("dev".into()),
            source: Some("known_hosts"),
            ambiguous: Vec::new(),
        });
        log.record(&AuditEvent::Server {
            connection: 8,
            server: None,
            host_key: "SHA256:k".into(),
            profile: Some("unregistered".into()),
            source: None,
            ambiguous: vec!["a".into(), "b".into()],
        });
        log.record(&AuditEvent::Refused {
            server: "unrecognised host (no session-bind)".to_owned(),
            reason: "write command on the forward socket",
        });
        log.flush();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0]["event"], "connect");
        assert_eq!(lines[0]["socket"], "forward");
        assert_eq!(lines[0]["connection"], 7);
        assert_eq!(lines[1]["source"], "known_hosts");
        assert!(lines[1].get("ambiguous").is_none(), "{}", lines[1]);
        assert!(lines[2].get("source").is_none(), "{}", lines[2]);
        assert_eq!(lines[2]["ambiguous"], serde_json::json!(["a", "b"]));
        assert!(lines[0]["time"].as_str().unwrap().ends_with('Z'));
        assert_eq!(lines[3]["event"], "refused");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn write_errors_are_ignored() {
        let log = AuditLog::new(PathBuf::from("/proc/credential-bridge-test/audit.log"));
        log.record(&AuditEvent::Hop { host_key: "SHA256:x".into() });
        log.flush();
    }

    fn events(path: &Path) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(path).unwrap();
        text.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    #[test]
    fn reopens_a_rotated_or_deleted_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let log = AuditLog::new(path.clone());
        log.record(&AuditEvent::Hop { host_key: "one".into() });
        log.flush();
        // logrotate: move the file away; the next event starts a new file.
        let rotated = dir.path().join("audit.log.1");
        std::fs::rename(&path, &rotated).unwrap();
        log.record(&AuditEvent::Hop { host_key: "two".into() });
        log.flush();
        assert_eq!(events(&rotated).len(), 1);
        assert_eq!(events(&path)[0]["host_key"], "two");
        // Deleted: recreated.
        std::fs::remove_file(&path).unwrap();
        log.record(&AuditEvent::Hop { host_key: "three".into() });
        log.flush();
        assert_eq!(events(&path)[0]["host_key"], "three");
    }

    #[test]
    fn close_writes_the_queue_and_joins_the_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let log = AuditLog::new(path.clone());
        for n in 0..100 {
            log.record(&AuditEvent::Hop { host_key: format!("k{n}") });
        }
        log.close();
        assert!(lock(&log.writer).is_none());
        let lines = events(&path);
        assert_eq!(lines.len(), 100);
        assert_eq!(lines[99]["host_key"], "k99");
        // Closed: later events are counted, not written; flush and close return.
        log.record(&AuditEvent::Hop { host_key: "late".into() });
        log.flush();
        log.close();
        assert_eq!(log.dropped.load(Ordering::Relaxed), 1);
        assert_eq!(events(&path).len(), 100);
    }

    #[test]
    fn counts_and_reports_dropped_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        // No writer thread: everything is dropped and counted.
        let log = AuditLog {
            path: path.clone(),
            queue: Mutex::new(None),
            writer: Mutex::new(None),
            dropped: Arc::default(),
        };
        for _ in 0..3 {
            log.record(&AuditEvent::Hop { host_key: "x".into() });
        }
        assert_eq!(log.dropped.load(Ordering::Relaxed), 3);

        // The writer reports a pending count with its next batch.
        let log = AuditLog::with_queue(path.clone(), 1);
        log.dropped.store(5, Ordering::Relaxed);
        log.record(&AuditEvent::Hop { host_key: "kept".into() });
        log.flush();
        let lines = events(&path);
        assert_eq!(lines.last().unwrap()["event"], "dropped");
        assert_eq!(lines.last().unwrap()["count"], 5);
        assert!(lines.iter().any(|line| line["host_key"] == "kept"));
        assert_eq!(log.dropped.load(Ordering::Relaxed), 0);
    }
}
