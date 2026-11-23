//! The OpenSSH version of the local ssh client.
//!
//! OpenSSH clients from 8.9 on send `session-bind@openssh.com` as the first message of
//! every forwarded agent connection; 8.2 to 8.8 support `ForwardAgent <path>` but send
//! no bind, so on their connections the first message comes from the server. The daemon
//! therefore lets a first-message bind select a server only if the process at the other
//! end of `agent-forward.sock` runs OpenSSH 8.9 or later ([`executable_version`]); ctl
//! warns about an older `ssh` ([`parse_version_output`] on `ssh -V`).
//!
//! The version of a running process is read from its executable, not by running it:
//! every OpenSSH client binary holds its release string (`SSH_RELEASE`, for example
//! `OpenSSH_10.2p1` or `OpenSSH_9.6p1 Ubuntu-3ubuntu13`) as a NUL-terminated C string,
//! which [`scan_executable`] finds. Running `<exe> -V` would execute whatever binary
//! connected, need `exec` and a timeout, and tell nothing more.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};

/// The first OpenSSH release whose client sends `session-bind@openssh.com`.
pub const SESSION_BIND_SINCE: OpenSshVersion = OpenSshVersion { major: 8, minor: 9 };

/// Largest executable [`executable_version`] reads. OpenSSH clients are a few MiB at
/// most, even statically linked.
pub const MAX_EXECUTABLE_LEN: u64 = 64 * 1024 * 1024;

/// The marker in front of an OpenSSH release.
const MARKER: &[u8] = b"OpenSSH_";

/// An OpenSSH release, major and minor (the portable suffix `p1` is ignored).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpenSshVersion {
    /// For example 9 in 9.6p1.
    pub major: u32,
    /// For example 6 in 9.6p1.
    pub minor: u32,
}

impl OpenSshVersion {
    /// Whether a client of this release sends `session-bind@openssh.com`.
    pub fn sends_session_bind(self) -> bool {
        self >= SESSION_BIND_SINCE
    }
}

impl fmt::Display for OpenSshVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Why the OpenSSH version of an executable is not known.
#[derive(Debug, thiserror::Error)]
pub enum VersionError {
    /// The executable could not be opened or read.
    #[error("cannot read the executable: {0}")]
    Io(#[from] io::Error),
    /// Larger than [`MAX_EXECUTABLE_LEN`].
    #[error("the executable is larger than {} MiB", MAX_EXECUTABLE_LEN / 1024 / 1024)]
    TooLarge,
    /// No OpenSSH release string: not an OpenSSH client.
    #[error("no OpenSSH version in the executable")]
    NotFound,
    /// Release strings of different versions.
    #[error("the executable names several OpenSSH versions ({})", list(.0))]
    Ambiguous(Vec<OpenSshVersion>),
}

fn list(versions: &[OpenSshVersion]) -> String {
    versions.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

/// Parses `major.minor` with an optional portable suffix (`p1`) at the start of `bytes`;
/// returns the version and the number of bytes it took. Each number has 1 to 4 digits.
fn parse_release(bytes: &[u8]) -> Option<(OpenSshVersion, usize)> {
    fn number(bytes: &[u8], at: usize) -> Option<(u32, usize)> {
        let digits = bytes.get(at..)?.iter().take(5).take_while(|b| b.is_ascii_digit()).count();
        if digits == 0 || digits > 4 {
            return None;
        }
        let text = std::str::from_utf8(&bytes[at..at + digits]).ok()?;
        Some((text.parse().ok()?, at + digits))
    }
    let (major, end) = number(bytes, 0)?;
    if bytes.get(end) != Some(&b'.') {
        return None;
    }
    let (minor, mut end) = number(bytes, end + 1)?;
    if bytes.get(end) == Some(&b'p')
        && let Some((_, after)) = number(bytes, end + 1)
    {
        end = after;
    }
    Some((OpenSshVersion { major, minor }, end))
}

/// The version in the output of `ssh -V`, for example
/// `OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024`: the first word that
/// is `OpenSSH_<major>.<minor>[p<n>]`. `None` for anything else.
pub fn parse_version_output(text: &str) -> Option<OpenSshVersion> {
    text.split(|c: char| c.is_whitespace() || c == ',').find_map(|word| {
        let release = word.strip_prefix("OpenSSH_")?.as_bytes();
        parse_release(release).filter(|&(_, len)| len == release.len()).map(|(version, _)| version)
    })
}

/// The OpenSSH version an executable's contents name: every `OpenSSH_<major>.<minor>`
/// with an optional `p<n>`, followed by a NUL byte (`SSH_VERSION`, `SSH_RELEASE`) or a
/// space (a vendor suffix, `SSH_RELEASE` with `SSH_EXTRAVERSION`). Compatibility
/// patterns such as `OpenSSH_7.4*` or `OpenSSH_6.6.1*` do not match. All matches must
/// agree on major and minor.
pub fn scan_executable(contents: &[u8]) -> Result<OpenSshVersion, VersionError> {
    let mut found = BTreeSet::new();
    let mut rest = contents;
    while let Some(at) = rest.windows(MARKER.len()).position(|window| window == MARKER) {
        let release = &rest[at + MARKER.len()..];
        if let Some((version, len)) = parse_release(release)
            && matches!(release.get(len), Some(0 | b' '))
        {
            found.insert(version);
        }
        rest = release;
    }
    let mut versions = found.into_iter();
    match (versions.next(), versions.next()) {
        (None, _) => Err(VersionError::NotFound),
        (Some(version), None) => Ok(version),
        (Some(first), Some(second)) => {
            Err(VersionError::Ambiguous([first, second].into_iter().chain(versions).collect()))
        }
    }
}

/// Opens the executable of process `pid` (Linux: `/proc/<pid>/exe`, which stays the
/// file the process runs even if its path was replaced or deleted; macOS: the path from
/// `proc_pidpath`).
///
/// Errors: the process is gone, belongs to someone else, or
/// [`io::ErrorKind::Unsupported`] elsewhere.
pub fn open_executable(pid: u32) -> io::Result<File> {
    imp::open_executable(pid)
}

/// Reads an opened executable (at most [`MAX_EXECUTABLE_LEN`]) and scans it with
/// [`scan_executable`]. Blocking: call it off the async runtime.
pub fn executable_version(file: &File) -> Result<OpenSshVersion, VersionError> {
    let mut contents = Vec::new();
    let reader: &File = file;
    reader.take(MAX_EXECUTABLE_LEN + 1).read_to_end(&mut contents)?;
    if contents.len() as u64 > MAX_EXECUTABLE_LEN {
        return Err(VersionError::TooLarge);
    }
    scan_executable(&contents)
}

#[cfg(target_os = "linux")]
mod imp {
    use std::fs::File;
    use std::io;

    pub(super) fn open_executable(pid: u32) -> io::Result<File> {
        File::open(format!("/proc/{pid}/exe"))
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::fs::File;
    use std::io;

    pub(super) fn open_executable(pid: u32) -> io::Result<File> {
        File::open(crate::macos::pid_path(pid)?)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    use std::fs::File;
    use std::io;

    pub(super) fn open_executable(_pid: u32) -> io::Result<File> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process executables are not supported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(major: u32, minor: u32) -> OpenSshVersion {
        OpenSshVersion { major, minor }
    }

    #[test]
    fn parses_ssh_v_output() {
        let cases = [
            ("OpenSSH_8.9p1 Ubuntu-3ubuntu0.1, OpenSSL 3.0.2 15 Mar 2022", Some(v(8, 9))),
            ("OpenSSH_10.0p2, OpenSSL 3.5.0 8 Apr 2025", Some(v(10, 0))),
            ("OpenSSH_10.0", Some(v(10, 0))),
            ("OpenSSH_8.8p1, OpenSSL 1.1.1l  24 Aug 2021\n", Some(v(8, 8))),
            ("OpenSSH_9.8p1, LibreSSL 3.3.6", Some(v(9, 8))),
            ("OpenSSH_7.4p1 Debian-10+deb9u7, OpenSSL 1.0.2u  20 Dec 2019", Some(v(7, 4))),
            ("OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5 27 Jan 2026", Some(v(10, 2))),
            ("ssh: unknown option -- V", None),
            ("Dropbear v2022.83", None),
            ("OpenSSH_", None),
            ("OpenSSH_8", None),
            ("OpenSSH_8.", None),
            ("OpenSSH_8.9x", None),
            ("OpenSSH_8.9p1x", None),
            ("OpenSSH_12345.1", None),
            ("NotOpenSSH_9.9", None),
            ("", None),
        ];
        for (text, expected) in cases {
            assert_eq!(parse_version_output(text), expected, "{text:?}");
        }
    }

    #[test]
    fn compares_with_8_9() {
        assert!(!v(8, 8).sends_session_bind());
        assert!(!v(7, 9).sends_session_bind());
        assert!(v(8, 9).sends_session_bind());
        assert!(v(9, 0).sends_session_bind());
        assert!(v(10, 0).sends_session_bind());
        assert_eq!(v(10, 2).to_string(), "10.2");
    }

    #[test]
    fn scans_executables() {
        // An upstream build: SSH_VERSION and SSH_RELEASE, plus compatibility patterns.
        let nix =
            b"\x7fELF..\0OpenSSH_10.6\0OpenSSH_10.6p1\0OpenSSH_2*,OpenSSH_3*\0OpenSSH_7.4*\0OpenSSH_6.6.1*\0";
        assert_eq!(scan_executable(nix).unwrap(), v(10, 6));
        // A vendor build.
        let ubuntu = b"x\0OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\0OpenSSH_7.0*,OpenSSH_7.1*\0";
        assert_eq!(scan_executable(ubuntu).unwrap(), v(8, 9));
        assert_eq!(scan_executable(b"\0OpenSSH_8.8p1\0").unwrap(), v(8, 8));
        // Merged with a longer string (linker tail merging).
        assert_eq!(scan_executable(b"\0SSH-2.0-OpenSSH_9.9p1\0").unwrap(), v(9, 9));

        assert!(matches!(scan_executable(b"\x7fELF no version here"), Err(VersionError::NotFound)));
        assert!(matches!(scan_executable(b"OpenSSH_7.4*,OpenSSH_6.6.1*"), Err(VersionError::NotFound)));
        // Not terminated: a prefix of some other text, or cut off at the end.
        assert!(matches!(scan_executable(b"OpenSSH_9.9,x\0OpenSSH_9.9"), Err(VersionError::NotFound)));
        let both = scan_executable(b"\0OpenSSH_8.8p1\0OpenSSH_9.0p1\0").unwrap_err();
        assert!(matches!(&both, VersionError::Ambiguous(versions) if *versions == [v(8, 8), v(9, 0)]));
        assert_eq!(both.to_string(), "the executable names several OpenSSH versions (8.8, 9.0)");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_the_executable_of_a_process() {
        let mut child = std::process::Command::new("sleep").arg("30").spawn().expect("spawn sleep");
        let pid = child.id();
        // Until `exec`, the child runs this test binary.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while crate::process::process_name(pid).ok().as_deref() != Some("sleep")
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let file = open_executable(pid);
        child.kill().ok();
        child.wait().ok();
        // `sleep` is no OpenSSH client.
        assert!(matches!(executable_version(&file.unwrap()), Err(VersionError::NotFound)));
        assert!(open_executable(u32::MAX - 1).is_err());
    }
}
