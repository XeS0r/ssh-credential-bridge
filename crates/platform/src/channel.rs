//! Worker channels and descriptor passing.
//!
//! The core creates a stream socketpair per worker and starts the worker
//! (`credential-bridged worker <kind>`) with the worker end as **stdin**; std's
//! `Command` closes every other descriptor (all are `O_CLOEXEC`). The worker takes the
//! channel with [`inherited_channel`] before anything else reads stdin.

use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, SocketFlags, SocketType,
};

/// Most descriptors accepted in one message; more are closed and reported as an error.
pub const MAX_FDS_PER_MESSAGE: usize = 4;

/// Control buffer size for [`MAX_FDS_PER_MESSAGE`] descriptors.
const CMSG_SPACE: usize = rustix::cmsg_space!(ScmRights(MAX_FDS_PER_MESSAGE));

/// Creates a connected unix stream socketpair, both ends `O_CLOEXEC`:
/// `(core_end, worker_end)`.
pub fn channel_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let (a, b) = rustix::net::socketpair(AddressFamily::UNIX, SocketType::STREAM, SOCKET_CLOEXEC, None)?;
    for end in [&a, &b] {
        ensure_cloexec(end.as_fd())?;
        no_sigpipe(end.as_fd())?;
    }
    Ok((a, b))
}

/// In a worker: duplicates stdin as the channel, checks that it is a unix stream
/// socket, and replaces stdin with `/dev/null`.
///
/// Errors: stdin is not a unix stream socket (the worker was not started by the core).
pub fn inherited_channel() -> io::Result<OwnedFd> {
    let stdin = io::stdin();
    let fd = stdin.as_fd();
    let is_unix_stream = rustix::net::sockopt::socket_type(fd) == Ok(SocketType::STREAM)
        && rustix::net::getsockname(fd).is_ok_and(|addr| addr.address_family() == AddressFamily::UNIX);
    if !is_unix_stream {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stdin is not a unix stream socket: workers are started by credential-bridged",
        ));
    }
    let channel = rustix::io::fcntl_dupfd_cloexec(fd, 3)?;
    no_sigpipe(channel.as_fd())?;
    let null = rustix::fs::open(
        "/dev/null",
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    rustix::stdio::dup2_stdin(&null)?;
    Ok(channel)
}

/// Sends `data` with `fds` attached (`SCM_RIGHTS`) in one `sendmsg`. Returns the number
/// of bytes sent; the descriptors travel with the first byte. At most
/// [`MAX_FDS_PER_MESSAGE`] descriptors.
pub fn send_with_fds<Fd: AsFd>(socket: Fd, data: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<usize> {
    if fds.len() > MAX_FDS_PER_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("at most {MAX_FDS_PER_MESSAGE} descriptors per message"),
        ));
    }
    if data.is_empty() && !fds.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "descriptors need at least one data byte"));
    }
    let mut space = [MaybeUninit::<u8>::uninit(); CMSG_SPACE];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() && !control.push(SendAncillaryMessage::ScmRights(fds)) {
        return Err(io::Error::other("control buffer too small"));
    }
    let iov = [IoSlice::new(data)];
    loop {
        match rustix::net::sendmsg(socket.as_fd(), &iov, &mut control, send_flags()) {
            Err(rustix::io::Errno::INTR) => continue,
            result => return Ok(result?),
        }
    }
}

/// Receives into `buf` and returns the byte count and any descriptors that arrived
/// (`O_CLOEXEC`). Truncated control data is an error and closes what was received.
pub fn recv_with_fds<Fd: AsFd>(socket: Fd, buf: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
    let mut space = [MaybeUninit::<u8>::uninit(); CMSG_SPACE];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let mut iov = [IoSliceMut::new(buf)];
    let msg = loop {
        match rustix::net::recvmsg(socket.as_fd(), &mut iov, &mut control, recv_flags()) {
            Err(rustix::io::Errno::INTR) => continue,
            result => break result?,
        }
    };
    let mut fds = Vec::new();
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(received) = message {
            fds.extend(received);
        }
    }
    if msg.flags.contains(ReturnFlags::CTRUNC) || fds.len() > MAX_FDS_PER_MESSAGE {
        drop(fds);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("more than {MAX_FDS_PER_MESSAGE} descriptors in one message; closed them"),
        ));
    }
    for fd in &fds {
        set_cloexec(fd.as_fd())?;
    }
    Ok((msg.bytes, fds))
}

/// `SOCK_CLOEXEC` where `socket`/`socketpair` accept it; elsewhere [`ensure_cloexec`]
/// sets it right after creation.
#[cfg(not(target_vendor = "apple"))]
pub(crate) const SOCKET_CLOEXEC: SocketFlags = SocketFlags::CLOEXEC;
#[cfg(target_vendor = "apple")]
pub(crate) const SOCKET_CLOEXEC: SocketFlags = SocketFlags::empty();

/// Sets `FD_CLOEXEC` on a new socket where [`SOCKET_CLOEXEC`] is not available.
#[cfg(not(target_vendor = "apple"))]
pub(crate) fn ensure_cloexec(_fd: BorrowedFd<'_>) -> io::Result<()> {
    Ok(())
}

#[cfg(target_vendor = "apple")]
pub(crate) fn ensure_cloexec(fd: BorrowedFd<'_>) -> io::Result<()> {
    Ok(rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::CLOEXEC)?)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn send_flags() -> SendFlags {
    SendFlags::NOSIGNAL
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn send_flags() -> SendFlags {
    SendFlags::empty()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn recv_flags() -> RecvFlags {
    RecvFlags::CMSG_CLOEXEC
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn recv_flags() -> RecvFlags {
    RecvFlags::empty()
}

/// Received descriptors are `O_CLOEXEC` already where `MSG_CMSG_CLOEXEC` exists; elsewhere
/// there is a short window in which a concurrent `exec` could inherit them.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_cloexec(_fd: BorrowedFd<'_>) -> io::Result<()> {
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn set_cloexec(fd: BorrowedFd<'_>) -> io::Result<()> {
    Ok(rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::CLOEXEC)?)
}

/// Writes to a closed channel return `EPIPE` instead of raising `SIGPIPE` (macOS has no
/// `MSG_NOSIGNAL`).
#[cfg(target_os = "macos")]
fn no_sigpipe(fd: BorrowedFd<'_>) -> io::Result<()> {
    Ok(rustix::net::sockopt::set_socket_nosigpipe(fd, true)?)
}

#[cfg(not(target_os = "macos"))]
fn no_sigpipe(_fd: BorrowedFd<'_>) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, Write};

    #[test]
    fn pair_is_connected_and_cloexec() {
        let (a, b) = channel_pair().unwrap();
        for end in [&a, &b] {
            let flags = rustix::io::fcntl_getfd(end).unwrap();
            assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
        }
        let mut a = std::os::unix::net::UnixStream::from(a);
        let mut b = std::os::unix::net::UnixStream::from(b);
        a.write_all(b"ping").unwrap();
        let mut buf = [0; 4];
        b.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[test]
    fn passes_descriptors() {
        let (a, b) = channel_pair().unwrap();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"secret-free test data").unwrap();
        let (r, mut w) = std::io::pipe().unwrap();

        let sent = send_with_fds(&a, b"open", &[file.as_fd(), r.as_fd()]).unwrap();
        assert_eq!(sent, 4);
        drop(r);

        let mut buf = [0u8; 16];
        let (n, fds) = recv_with_fds(&b, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"open");
        assert_eq!(fds.len(), 2);
        for fd in &fds {
            assert!(rustix::io::fcntl_getfd(fd).unwrap().contains(rustix::io::FdFlags::CLOEXEC));
        }
        let mut fds = fds.into_iter();
        let mut received_file = std::fs::File::from(fds.next().unwrap());
        received_file.rewind().unwrap();
        let mut text = String::new();
        received_file.read_to_string(&mut text).unwrap();
        assert_eq!(text, "secret-free test data");

        let mut received_pipe = std::io::PipeReader::from(fds.next().unwrap());
        w.write_all(b"x").unwrap();
        drop(w);
        let mut rest = Vec::new();
        received_pipe.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"x");
    }

    #[test]
    fn plain_data_without_descriptors() {
        let (a, b) = channel_pair().unwrap();
        assert_eq!(send_with_fds(&a, b"hello", &[]).unwrap(), 5);
        let mut buf = [0u8; 8];
        let (n, fds) = recv_with_fds(&b, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert!(fds.is_empty());
    }

    #[test]
    fn rejects_too_many_or_dataless_descriptors() {
        let (a, _b) = channel_pair().unwrap();
        let file = tempfile::tempfile().unwrap();
        let many = vec![file.as_fd(); MAX_FDS_PER_MESSAGE + 1];
        assert_eq!(send_with_fds(&a, b"x", &many).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(send_with_fds(&a, b"", &[file.as_fd()]).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn excess_descriptors_are_closed_and_reported() {
        let (a, b) = channel_pair().unwrap();
        let file = tempfile::tempfile().unwrap();
        // Bypass the sender's limit with rustix directly.
        let many = vec![file.as_fd(); MAX_FDS_PER_MESSAGE + 4];
        let mut space =
            [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS_PER_MESSAGE + 4))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        assert!(control.push(SendAncillaryMessage::ScmRights(&many)));
        rustix::net::sendmsg(&a, &[IoSlice::new(b"x")], &mut control, SendFlags::empty()).unwrap();
        let mut buf = [0u8; 4];
        let err = recv_with_fds(&b, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn inherited_channel_rejects_a_non_socket_stdin() {
        // The test harness's stdin is a terminal, a pipe or /dev/null, never a unix
        // stream socket.
        if rustix::net::sockopt::socket_type(io::stdin().as_fd()).is_ok() {
            return;
        }
        assert_eq!(inherited_channel().unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn worker_takes_its_channel_from_stdin() {
        const NAME: &str = "channel::tests::worker_takes_its_channel_from_stdin";
        let (core_end, worker_end) = channel_pair().unwrap();
        let mut core_end = Some(core_end);
        let mut answerer = None;
        let parent = crate::testutil::run_in_child_with(NAME, |command| {
            command.stdin(std::process::Stdio::from(worker_end));
            let core_end = core_end.take().unwrap();
            // The child answers while the parent waits for its output.
            answerer = Some(std::thread::spawn(move || {
                let mut stream = std::os::unix::net::UnixStream::from(core_end);
                stream.write_all(b"ping").unwrap();
                let mut answer = [0u8; 4];
                stream.read_exact(&mut answer).unwrap();
                assert_eq!(&answer, b"pong");
            }));
        });
        if parent {
            answerer.unwrap().join().expect("core end saw the right answer");
            return;
        }
        let channel = inherited_channel().unwrap();
        assert!(channel.as_fd().try_clone_to_owned().is_ok());
        assert!(rustix::io::fcntl_getfd(&channel).unwrap().contains(rustix::io::FdFlags::CLOEXEC));
        // stdin is /dev/null now.
        let mut rest = Vec::new();
        assert_eq!(io::stdin().read_to_end(&mut rest).unwrap(), 0);
        let mut stream = std::os::unix::net::UnixStream::from(channel);
        let mut ping = [0u8; 4];
        stream.read_exact(&mut ping).unwrap();
        assert_eq!(&ping, b"ping");
        stream.write_all(b"pong").unwrap();
    }
}
