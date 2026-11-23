//! The only `unsafe` code of credential-bridge: thin macOS FFI wrappers for calls that
//! neither `std` nor `rustix` offer. Each wrapper is a safe function around exactly one
//! foreign call with fully initialised, correctly sized buffers.

use std::ffi::{CStr, CString, OsString};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStringExt;

/// `getpeereid`: the effective uid of the peer of a unix stream socket.
#[allow(unsafe_code)]
pub(crate) fn peer_euid(socket: BorrowedFd<'_>) -> io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `socket` is a valid open descriptor for the duration of the call and both
    // out pointers point to live, writable integers of the declared types.
    let rc = unsafe { libc::getpeereid(socket.as_raw_fd(), &mut uid, &mut gid) };
    if rc == 0 { Ok(uid) } else { Err(io::Error::last_os_error()) }
}

/// `getsockopt(SOL_LOCAL, LOCAL_PEERPID)`: the pid of the peer at `connect` time.
#[allow(unsafe_code)]
pub(crate) fn peer_pid(socket: BorrowedFd<'_>) -> io::Result<u32> {
    let mut pid: libc::pid_t = 0;
    let mut len = libc::socklen_t::try_from(size_of::<libc::pid_t>()).expect("pid_t fits socklen_t");
    // SAFETY: `socket` is a valid descriptor; `pid` and `len` are live and writable, and
    // `len` holds the exact size of `pid`, so the kernel writes at most that many bytes.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    u32::try_from(pid).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative peer pid"))
}

/// `proc_pidpath`: the executable path of process `pid`.
#[allow(unsafe_code)]
pub(crate) fn pid_path(pid: u32) -> io::Result<OsString> {
    let pid = libc::c_int::try_from(pid).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let size = u32::try_from(buf.len()).expect("buffer size fits u32");
    // SAFETY: `buf` is a live, writable allocation of exactly `size` bytes; the call
    // writes at most `size` bytes and returns how many it wrote.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast::<libc::c_void>(), size) };
    if n <= 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(usize::try_from(n).unwrap_or(0));
    Ok(OsString::from_vec(buf))
}

/// `ptrace(PT_DENY_ATTACH)`: no debugger may attach to this process from now on.
#[allow(unsafe_code)]
pub(crate) fn deny_attach() -> io::Result<()> {
    // SAFETY: `PT_DENY_ATTACH` takes no address or data; it only sets a flag on the
    // calling process.
    let rc = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    if rc == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

#[allow(unsafe_code)]
unsafe extern "C" {
    // libsandbox (part of libSystem); declared in `<sandbox.h>`.
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: u64,
        errorbuf: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn sandbox_free_error(errorbuf: *mut libc::c_char);
}

/// `sandbox_init` with an SBPL profile text (flags 0). Irreversible.
#[allow(unsafe_code)]
pub(crate) fn apply_sandbox_profile(profile: &str) -> Result<(), String> {
    let profile = CString::new(profile).map_err(|_| "sandbox profile contains a NUL byte".to_owned())?;
    let mut error: *mut libc::c_char = std::ptr::null_mut();
    // SAFETY: `profile` is a NUL-terminated string that outlives the call; `error` is a
    // live out pointer that the call sets to NULL or to a C string it allocated.
    let rc = unsafe { sandbox_init(profile.as_ptr(), 0, &mut error) };
    if rc == 0 {
        return Ok(());
    }
    if error.is_null() {
        return Err(format!("sandbox_init returned {rc}"));
    }
    // SAFETY: on failure `error` points to a NUL-terminated string owned by libsandbox
    // until `sandbox_free_error`; it is copied before being freed exactly once.
    let message = unsafe {
        let message = CStr::from_ptr(error).to_string_lossy().into_owned();
        sandbox_free_error(error);
        message
    };
    Err(message)
}
