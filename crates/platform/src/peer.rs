//! Credentials of the process on the other end of a local stream socket
//! (`SO_PEERCRED` on Linux, `getpeereid` + `LOCAL_PEERPID` on macOS).

use std::io;
use std::os::fd::AsFd;

/// Who is connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    /// Effective user id at `connect` time.
    pub uid: u32,
    /// Process id, if the platform reports it. For forwarded requests this is the local
    /// `ssh` client, never the process on the server.
    pub pid: Option<u32>,
}

/// Reads the peer credentials of a connected unix stream socket.
///
/// Errors: the socket is not a connected unix stream socket, or the system call fails.
pub fn peer_credentials<Fd: AsFd>(socket: Fd) -> io::Result<PeerCredentials> {
    imp::peer_credentials(socket.as_fd())
}

#[cfg(target_os = "linux")]
mod imp {
    use super::PeerCredentials;
    use std::io;
    use std::os::fd::BorrowedFd;

    pub(super) fn peer_credentials(socket: BorrowedFd<'_>) -> io::Result<PeerCredentials> {
        let cred = rustix::net::sockopt::socket_peercred(socket)?;
        // The kernel reports pid 0 for a peer whose PID namespace is not visible here.
        let pid = u32::try_from(cred.pid.as_raw_pid()).ok().filter(|&p| p > 0);
        Ok(PeerCredentials { uid: cred.uid.as_raw(), pid })
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::PeerCredentials;
    use std::io;
    use std::os::fd::BorrowedFd;

    pub(super) fn peer_credentials(socket: BorrowedFd<'_>) -> io::Result<PeerCredentials> {
        let uid = crate::macos::peer_euid(socket)?;
        // `LOCAL_PEERPID` is best effort: the uid is what the peer check needs.
        let pid = crate::macos::peer_pid(socket).ok().filter(|&p| p > 0);
        Ok(PeerCredentials { uid, pid })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    use super::PeerCredentials;
    use std::io;
    use std::os::fd::BorrowedFd;

    pub(super) fn peer_credentials(_socket: BorrowedFd<'_>) -> io::Result<PeerCredentials> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "peer credentials are not supported on this platform"))
    }
}

/// The real user id of this process.
pub fn current_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// Security rule 6: sockets accept only the own user or root.
pub fn is_trusted(peer: &PeerCredentials, own_uid: u32) -> bool {
    peer.uid == own_uid || peer.uid == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusts_own_user_and_root_only() {
        let peer = |uid| PeerCredentials { uid, pid: None };
        assert!(is_trusted(&peer(1000), 1000));
        assert!(is_trusted(&peer(0), 1000));
        assert!(!is_trusted(&peer(1001), 1000));
    }

    #[test]
    fn reads_own_credentials_from_a_socketpair() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let cred = peer_credentials(&a).unwrap();
        assert_eq!(cred.uid, rustix::process::geteuid().as_raw());
        assert_eq!(cred.pid, Some(std::process::id()));
    }

    #[test]
    fn rejects_non_socket() {
        let file = tempfile::tempfile().unwrap();
        assert!(peer_credentials(&file).is_err());
    }
}
