//! Which local ssh client is behind a connection on `agent-forward.sock`
//! (`docs/architecture.md`, "Recognising the server").
//!
//! OpenSSH 8.2 to 8.8 support `ForwardAgent <path>` but send no `session-bind`; on their
//! connections the first message comes from the server, which could replay a genuine
//! bind of another configured server. So a first-message bind may select the server only
//! if the peer process runs OpenSSH 8.9 or later. The check runs once per connection,
//! before its first message, and fails closed: no process id, an executable that cannot
//! be read, no or several OpenSSH versions in it, or an older release all leave the
//! connection without a server.
//!
//! The version comes from the executable's contents
//! ([`credential_bridge_platform::ssh_client`]), read on a blocking thread and cached
//! per file (device, inode, modification time, size).

use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use credential_bridge_platform::ssh_client::{self, OpenSshVersion, SESSION_BIND_SINCE};

use crate::sync::lock;

/// How long the check of one connection may take.
const CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Executables remembered; the cache starts over when it is full.
const CACHE_LEN: usize = 64;

/// The outcome for one connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientCheck {
    /// OpenSSH 8.9 or later: a first-message bind may select the server.
    Verified(OpenSshVersion),
    /// Anything else, with the reason; the connection never gets a server.
    NotVerified(String),
}

impl ClientCheck {
    /// Whether a first-message bind may select the server.
    pub fn may_select_server(&self) -> bool {
        matches!(self, ClientCheck::Verified(_))
    }

    /// For logs: `OpenSSH 10.2`, or why the client is not verified.
    pub fn describe(&self) -> String {
        match self {
            ClientCheck::Verified(version) => format!("OpenSSH {version}"),
            ClientCheck::NotVerified(reason) => {
                format!("not verified as OpenSSH {SESSION_BIND_SINCE} or later: {reason}")
            }
        }
    }

    /// The outcome for a version read from an executable.
    fn from_version(result: &Result<OpenSshVersion, String>) -> ClientCheck {
        match result {
            Ok(version) if version.sends_session_bind() => ClientCheck::Verified(*version),
            Ok(version) => ClientCheck::NotVerified(format!("OpenSSH {version} sends no session-bind")),
            Err(reason) => ClientCheck::NotVerified(reason.clone()),
        }
    }
}

/// Identifies an executable file's contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FileId {
    dev: u64,
    ino: u64,
    mtime: i64,
    mtime_nsec: i64,
    size: u64,
}

/// OpenSSH versions of executables already read.
#[derive(Debug, Default)]
pub struct ClientCache {
    entries: Mutex<HashMap<FileId, Result<OpenSshVersion, String>>>,
}

impl ClientCache {
    /// Checks the peer process `pid` (`None` if the platform did not report it). Never
    /// blocks the runtime; gives up after [`CHECK_TIMEOUT`].
    pub async fn check(self: &Arc<Self>, pid: Option<u32>) -> ClientCheck {
        let Some(pid) = pid else {
            return ClientCheck::NotVerified(
                "the process id of the local ssh client is not known".to_owned(),
            );
        };
        let cache = Arc::clone(self);
        let task = tokio::task::spawn_blocking(move || cache.check_blocking(pid));
        match tokio::time::timeout(CHECK_TIMEOUT, task).await {
            Ok(Ok(check)) => check,
            Ok(Err(error)) => ClientCheck::NotVerified(format!("the check failed: {error}")),
            Err(_) => ClientCheck::NotVerified("reading its executable timed out".to_owned()),
        }
    }

    /// [`ClientCache::check`] on the current thread.
    fn check_blocking(&self, pid: u32) -> ClientCheck {
        match ssh_client::open_executable(pid) {
            Ok(file) => self.check_file(&file),
            Err(error) => {
                ClientCheck::NotVerified(format!("cannot open the executable of process {pid}: {error}"))
            }
        }
    }

    /// The outcome for an opened executable, from the cache if its file is known.
    fn check_file(&self, file: &File) -> ClientCheck {
        let meta = match file.metadata() {
            Ok(meta) => meta,
            Err(error) => return ClientCheck::NotVerified(format!("cannot read its executable: {error}")),
        };
        let id = FileId {
            dev: meta.dev(),
            ino: meta.ino(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            size: meta.size(),
        };
        if let Some(known) = lock(&self.entries).get(&id) {
            return ClientCheck::from_version(known);
        }
        let result = ssh_client::executable_version(file).map_err(|error| error.to_string());
        let mut entries = lock(&self.entries);
        if entries.len() >= CACHE_LEN {
            entries.clear();
        }
        entries.insert(id, result.clone());
        ClientCheck::from_version(&result)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn executable(contents: &[u8]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents).unwrap();
        file
    }

    #[test]
    fn decides_by_version() {
        let check = |contents: &[u8]| {
            let file = executable(contents);
            ClientCache::default().check_file(&File::open(file.path()).unwrap())
        };
        let ok = check(b"\0OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\0");
        assert_eq!(ok, ClientCheck::Verified(OpenSshVersion { major: 8, minor: 9 }));
        assert!(ok.may_select_server());
        assert_eq!(ok.describe(), "OpenSSH 8.9");
        assert!(check(b"\0OpenSSH_10.0\0").may_select_server());

        let old = check(b"\0OpenSSH_8.8p1\0");
        assert!(!old.may_select_server());
        assert_eq!(old.describe(), "not verified as OpenSSH 8.9 or later: OpenSSH 8.8 sends no session-bind");
        let unknown = check(b"#!/bin/sh\nexec socat ...\n");
        assert!(!unknown.may_select_server());
        assert!(unknown.describe().ends_with("no OpenSSH version in the executable"));
        assert!(!check(b"\0OpenSSH_8.8p1\0OpenSSH_9.0p1\0").may_select_server());
    }

    #[test]
    fn caches_per_file_and_notices_changes() {
        let mut file = executable(b"\0OpenSSH_9.9p1\0");
        let cache = ClientCache::default();
        assert!(cache.check_file(&File::open(file.path()).unwrap()).may_select_server());
        assert_eq!(lock(&cache.entries).len(), 1);
        assert!(cache.check_file(&File::open(file.path()).unwrap()).may_select_server());
        assert_eq!(lock(&cache.entries).len(), 1);
        // Changed contents (another size) are read again.
        file.as_file_mut().set_len(0).unwrap();
        file.write_all(b"\0OpenSSH_8.2p1\0 and more").unwrap();
        assert!(!cache.check_file(&File::open(file.path()).unwrap()).may_select_server());
        assert_eq!(lock(&cache.entries).len(), 2);
    }

    #[tokio::test]
    async fn fails_closed_without_a_readable_peer() {
        let cache = Arc::new(ClientCache::default());
        assert!(
            matches!(cache.check(None).await, ClientCheck::NotVerified(reason) if reason.contains("process id"))
        );
        assert!(!cache.check(Some(u32::MAX - 1)).await.may_select_server());
        // The test binary itself is no OpenSSH client.
        assert!(!cache.check(Some(std::process::id())).await.may_select_server());
    }
}
