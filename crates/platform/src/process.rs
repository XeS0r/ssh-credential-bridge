//! Information about other processes of the same user.

use std::ffi::OsString;
use std::io;

/// The short name of process `pid` for approval dialogs and the audit log
/// (Linux: `/proc/<pid>/comm`; macOS: the file name of `proc_pidpath`).
///
/// Errors: the process is gone or not accessible.
pub fn process_name(pid: u32) -> io::Result<String> {
    imp::process_name(pid)
}

/// One variable from the environment of process `pid` (Linux: `/proc/<pid>/environ`).
/// The gpg shim uses it to find the caller's `SSH_AUTH_SOCK`.
///
/// Returns `Ok(None)` if the variable is not set. Errors: the process is gone, not
/// readable (not dumpable, other user), or [`io::ErrorKind::Unsupported`] on macOS.
pub fn environ_var(pid: u32, name: &str) -> io::Result<Option<OsString>> {
    imp::environ_var(pid, name)
}

/// Finds `name` in an environment block of `NAME=value` entries separated by NUL bytes,
/// as in `/proc/<pid>/environ`. The first entry wins, like `getenv`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn find_in_environ(block: &[u8], name: &str) -> Option<OsString> {
    use std::os::unix::ffi::OsStringExt;

    if name.is_empty() || name.contains('=') {
        return None;
    }
    block.split(|&b| b == 0).find_map(|entry| {
        let rest = entry.strip_prefix(name.as_bytes())?;
        let value = rest.strip_prefix(b"=")?;
        Some(OsString::from_vec(value.to_vec()))
    })
}

/// Turns a process name into one printable line: control characters become `?`.
fn printable(name: &str) -> String {
    name.chars().map(|c| if c.is_control() { '?' } else { c }).collect()
}

#[cfg(target_os = "linux")]
mod imp {
    use std::ffi::OsString;
    use std::io;

    pub(super) fn process_name(pid: u32) -> io::Result<String> {
        let comm = std::fs::read(format!("/proc/{pid}/comm"))?;
        let comm = String::from_utf8_lossy(&comm);
        Ok(super::printable(comm.strip_suffix('\n').unwrap_or(&comm)))
    }

    pub(super) fn environ_var(pid: u32, name: &str) -> io::Result<Option<OsString>> {
        let block = std::fs::read(format!("/proc/{pid}/environ"))?;
        Ok(super::find_in_environ(&block, name))
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::OsString;
    use std::io;
    use std::path::Path;

    pub(super) fn process_name(pid: u32) -> io::Result<String> {
        let path = crate::macos::pid_path(pid)?;
        let name = Path::new(&path).file_name().unwrap_or(path.as_os_str());
        Ok(super::printable(&name.to_string_lossy()))
    }

    pub(super) fn environ_var(_pid: u32, _name: &str) -> io::Result<Option<OsString>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "reading another process's environment is not supported on macOS",
        ))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    use std::ffi::OsString;
    use std::io;

    pub(super) fn process_name(_pid: u32) -> io::Result<String> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "process names are not supported on this platform"))
    }

    pub(super) fn environ_var(_pid: u32, _name: &str) -> io::Result<Option<OsString>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process environments are not supported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_variables_in_an_environ_block() {
        let block = b"HOME=/home/u\0SSH_AUTH_SOCK=/tmp/a\0SSH_AUTH_SOCK=/tmp/b\0EMPTY=\0FOO_BAR=x\0";
        assert_eq!(find_in_environ(block, "SSH_AUTH_SOCK"), Some("/tmp/a".into()));
        assert_eq!(find_in_environ(block, "EMPTY"), Some("".into()));
        assert_eq!(find_in_environ(block, "FOO"), None);
        assert_eq!(find_in_environ(block, "MISSING"), None);
        assert_eq!(find_in_environ(block, ""), None);
        assert_eq!(find_in_environ(block, "HOME=/home"), None);
        assert_eq!(find_in_environ(b"", "HOME"), None);
    }

    #[test]
    fn printable_replaces_control_characters() {
        assert_eq!(printable("ssh\n\u{1b}[31m"), "ssh??[31m");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_name_and_environment_of_a_child() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .env("CB_PLATFORM_TEST_VAR", "value 1")
            .env_remove("CB_PLATFORM_TEST_UNSET")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        // Until `exec`, the child still shows this process's name and environment; the
        // kernel sets the new name before the new environment, so wait for both.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let ready = || {
            process_name(pid).is_ok_and(|n| n == "sleep")
                && environ_var(pid, "CB_PLATFORM_TEST_VAR").is_ok_and(|v| v.is_some())
        };
        while !ready() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let name = process_name(pid);
        let var = environ_var(pid, "CB_PLATFORM_TEST_VAR");
        let unset = environ_var(pid, "CB_PLATFORM_TEST_UNSET");
        child.kill().ok();
        child.wait().ok();
        assert_eq!(name.unwrap(), "sleep");
        assert_eq!(var.unwrap(), Some("value 1".into()));
        assert_eq!(unset.unwrap(), None);
    }

    #[test]
    fn missing_process_is_an_error() {
        // PIDs are below 2^22 on Linux and 99999 on macOS.
        assert!(process_name(u32::MAX - 1).is_err());
    }
}
