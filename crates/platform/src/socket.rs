//! Local listening sockets (unix sockets on Linux and macOS).

use std::fs;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::io::Errno;
use rustix::net::{AddressFamily, SocketAddrUnix, SocketType};

use crate::channel::{SOCKET_CLOEXEC, ensure_cloexec};

/// Creates `dir` (and parents) with mode 0700 if missing, then checks that it is a
/// directory owned by this user and not accessible by group or others.
///
/// Errors: creation fails, or the existing directory has the wrong owner or mode
/// ([`io::ErrorKind::PermissionDenied`]).
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    // `symlink_metadata`: a symlink planted in place of the directory is refused.
    let meta = fs::symlink_metadata(dir)?;
    let denied =
        |why: String| io::Error::new(io::ErrorKind::PermissionDenied, format!("{}: {why}", dir.display()));
    if !meta.file_type().is_dir() {
        return Err(denied("not a directory".to_owned()));
    }
    let own_uid = rustix::process::geteuid().as_raw();
    if meta.uid() != own_uid {
        return Err(denied(format!("owned by uid {}, expected {own_uid}", meta.uid())));
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(denied(format!("mode {mode:03o} is accessible by group or others (expected 700)")));
    }
    Ok(())
}

/// Binds a listening socket at `path` with mode 0600 (non-blocking, `O_CLOEXEC`).
///
/// A file already at `path` is removed only if it is a socket nobody accepts on (a
/// stale socket); a live socket yields [`io::ErrorKind::AddrInUse`], anything else
/// [`io::ErrorKind::AlreadyExists`]. The parent must pass [`ensure_private_dir`].
pub fn bind_private(path: &Path) -> io::Result<UnixListener> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => match UnixStream::connect(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("{}: another process is listening", path.display()),
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => match fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        },
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{}: exists and is not a socket", path.display()),
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    // The private parent directory keeps others out until the mode is set.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Whether something accepts connections at `path` within `timeout`. Used by
/// `credential-bridge-ctl daemon alive`, which runs on every ssh call, so it must not block
/// longer than `timeout` (a stale socket file fails fast with `ECONNREFUSED`).
pub fn is_listening(path: &Path, timeout: Duration) -> bool {
    probe(path, timeout).unwrap_or(false)
}

fn probe(path: &Path, timeout: Duration) -> io::Result<bool> {
    let addr = SocketAddrUnix::new(path)?;
    let socket = rustix::net::socket_with(AddressFamily::UNIX, SocketType::STREAM, SOCKET_CLOEXEC, None)?;
    ensure_cloexec(socket.as_fd())?;
    rustix::io::ioctl_fionbio(&socket, true)?;
    match rustix::net::connect(&socket, &addr) {
        Ok(()) => return Ok(true),
        // Linux: a listener whose backlog is full. Someone is there.
        Err(Errno::AGAIN) => return Ok(true),
        Err(Errno::INPROGRESS | Errno::INTR) => {}
        Err(_) => return Ok(false),
    }
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let ts = Timespec::try_from(left).unwrap_or(Timespec { tv_sec: i64::MAX, tv_nsec: 0 });
        let mut fds = [PollFd::new(&socket, PollFlags::OUT)];
        match rustix::event::poll(&mut fds, Some(&ts)) {
            Ok(0) => return Ok(false),
            Ok(_) => break,
            Err(Errno::INTR) if !left.is_zero() => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(rustix::net::sockopt::socket_error(socket.as_fd())?.is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_tempdir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn creates_private_directories() {
        let base = private_tempdir();
        let dir = base.path().join("a/b");
        ensure_private_dir(&dir).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        // Idempotent.
        ensure_private_dir(&dir).unwrap();
    }

    #[test]
    fn refuses_open_directories_and_symlinks() {
        let base = private_tempdir();
        let open = base.path().join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(ensure_private_dir(&open).unwrap_err().kind(), io::ErrorKind::PermissionDenied);

        let target = base.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(ensure_private_dir(&link).unwrap_err().kind(), io::ErrorKind::PermissionDenied);

        let file = base.path().join("file");
        fs::write(&file, b"").unwrap();
        assert!(ensure_private_dir(&file).is_err());
    }

    #[test]
    fn binds_with_mode_0600_and_detects_listeners() {
        let dir = private_tempdir();
        let path = dir.path().join("agent.sock");
        let listener = bind_private(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(fs::metadata(&path).unwrap().file_type().is_socket());
        assert!(is_listening(&path, Duration::from_secs(1)));

        // A second bind finds the live socket.
        assert_eq!(bind_private(&path).unwrap_err().kind(), io::ErrorKind::AddrInUse);

        // After the listener is gone the socket file is stale and replaced. A child that
        // another test thread forks may hold a copy of the listener until it execs, so
        // wait for that (bounded) instead of expecting it gone at once.
        drop(listener);
        let deadline = Instant::now() + Duration::from_secs(10);
        while is_listening(&path, Duration::from_secs(1)) {
            assert!(Instant::now() < deadline, "the socket still listens after its listener was dropped");
            std::thread::sleep(Duration::from_millis(20));
        }
        let _again = bind_private(&path).unwrap();
        assert!(is_listening(&path, Duration::from_secs(1)));
    }

    #[test]
    fn leaves_other_files_alone() {
        let dir = private_tempdir();
        let path = dir.path().join("agent.sock");
        fs::write(&path, b"keep me").unwrap();
        assert_eq!(bind_private(&path).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"keep me");
    }

    #[test]
    fn missing_socket_is_not_listening() {
        let dir = private_tempdir();
        let started = Instant::now();
        assert!(!is_listening(&dir.path().join("none.sock"), Duration::from_secs(5)));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn listener_is_nonblocking() {
        let dir = private_tempdir();
        let listener = bind_private(&dir.path().join("s")).unwrap();
        assert_eq!(listener.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }
}
