//! Reading a password from the terminal without echo.

use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Write as _};

use credential_bridge_proto::secret::Secret;
use rustix::termios::{LocalModes, OptionalActions, Termios, tcgetattr, tcsetattr};
use zeroize::Zeroizing;

/// Longest accepted password in bytes.
const MAX_PASSWORD: usize = 64 * 1024;

/// Restores the terminal settings when dropped, also on early return.
struct EchoGuard<'a> {
    tty: &'a File,
    original: Termios,
}

impl Drop for EchoGuard<'_> {
    fn drop(&mut self) {
        let _ = tcsetattr(self.tty, OptionalActions::Flush, &self.original);
    }
}

/// Prints `prompt` on the controlling terminal and reads one line with echo switched
/// off. The input is wiped from ctl's buffers after use.
pub fn read_password(prompt: &str) -> io::Result<Secret> {
    let tty = OpenOptions::new().read(true).write(true).open("/dev/tty").map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("no terminal to ask for the password ({error}); use --password-stdin"),
        )
    })?;
    let original = tcgetattr(&tty)?;
    let mut silent = original.clone();
    silent.local_modes.remove(LocalModes::ECHO);
    silent.local_modes.insert(LocalModes::ECHONL);
    (&tty).write_all(prompt.as_bytes())?;
    (&tty).flush()?;
    let guard = EchoGuard { tty: &tty, original };
    tcsetattr(&tty, OptionalActions::Flush, &silent)?;

    let mut bytes = Zeroizing::new(Vec::new());
    let mut byte = [0u8; 1];
    loop {
        if (&tty).read(&mut byte)? == 0 || byte[0] == b'\n' {
            break;
        }
        if bytes.len() >= MAX_PASSWORD {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "the password is too long"));
        }
        bytes.push(byte[0]);
    }
    zeroize::Zeroize::zeroize(&mut byte);
    drop(guard);
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the password is not valid UTF-8"))?;
    Ok(Secret::new(text.to_owned()))
}
