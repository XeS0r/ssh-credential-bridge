//! Writing files that may hold private data (the configuration, its backups and edit
//! copies).

use std::io::Write as _;
use std::path::Path;

/// Creates `path` readable and writable only by the owner (mode 0600), writes
/// `contents` and syncs it to disk.
///
/// Never replaces anything: an existing file (or link) at `path` is an error of kind
/// [`std::io::ErrorKind::AlreadyExists`]. Callers that replace a stale file remove it
/// first.
pub fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_a_new_private_file_and_never_replaces_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private");
        write_private(&path, b"one").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let error = write_private(&path, b"two").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
    }
}
