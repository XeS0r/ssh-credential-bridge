//! Pure helpers for the remote gpg shim (`credential-bridge-remote gpg`): the arguments
//! gpg passes to an `agent-program`.
//!
//! # Arguments on autostart
//!
//! When no agent listens on its socket, gpg (GnuPG 2.1 and later, `start_new_gpg_agent`
//! in `common/asshelp.c`) runs the `agent-program` as
//!
//! ```text
//! <program> --homedir <dir> --use-standard-socket [<arg>] --daemon
//! ```
//!
//! where `<arg>` is present only if `gpg.conf` says `agent-program <program>|<arg>`. gpg
//! then polls the socket until the agent accepts connections. Other GnuPG versions and
//! wrappers may pass more options (`--supervised`, `--options <file>`, `-v`, …);
//! [`AgentProgramArgs::parse`] accepts any of them and keeps everything in
//! [`AgentProgramArgs::raw`] so the shim can start a real gpg-agent with the same
//! arguments.

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// The arguments gpg passes to an `agent-program`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentProgramArgs {
    /// `--homedir <dir>` or `--homedir=<dir>` (the last one wins).
    pub homedir: Option<PathBuf>,
    /// `--daemon`: gpg asks for a background agent.
    pub daemon: bool,
    /// `--supervised`: the agent was started by a service manager with sockets.
    pub supervised: bool,
    /// `--use-standard-socket` (a no-op since GnuPG 2.1, still passed).
    pub use_standard_socket: bool,
    /// Options this parser does not know, and positional arguments (such as the
    /// `agent-program <program>|<arg>` argument), in order.
    pub unknown: Vec<OsString>,
    /// All arguments as given.
    pub raw: Vec<OsString>,
}

impl AgentProgramArgs {
    /// Parses the arguments after the program name. Never fails: unknown options and a
    /// `--homedir` without a value are kept in [`AgentProgramArgs::unknown`]. After `--`
    /// everything is positional.
    pub fn parse<I, A>(args: I) -> AgentProgramArgs
    where
        I: IntoIterator<Item = A>,
        A: Into<OsString>,
    {
        let raw: Vec<OsString> = args.into_iter().map(Into::into).collect();
        let mut parsed = AgentProgramArgs::default();
        let mut iter = raw.iter();
        let mut options_done = false;
        while let Some(arg) = iter.next() {
            let bytes = arg.as_bytes();
            if options_done {
                parsed.unknown.push(arg.clone());
                continue;
            }
            match bytes {
                b"--" => options_done = true,
                b"--daemon" => parsed.daemon = true,
                b"--supervised" => parsed.supervised = true,
                b"--use-standard-socket" => parsed.use_standard_socket = true,
                b"--homedir" => match iter.next() {
                    Some(dir) => parsed.homedir = Some(PathBuf::from(dir)),
                    None => parsed.unknown.push(arg.clone()),
                },
                _ => match bytes.strip_prefix(b"--homedir=") {
                    Some(dir) => parsed.homedir = Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir))),
                    None => parsed.unknown.push(arg.clone()),
                },
            }
        }
        parsed.raw = raw;
        parsed
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStringExt;
    use std::path::Path;

    use super::*;

    #[test]
    fn gpg_autostart_arguments() {
        let args =
            AgentProgramArgs::parse(["--homedir", "/home/u/.gnupg", "--use-standard-socket", "--daemon"]);
        assert_eq!(args.homedir.as_deref(), Some(Path::new("/home/u/.gnupg")));
        assert!(args.daemon && args.use_standard_socket && !args.supervised);
        assert!(args.unknown.is_empty());
        assert_eq!(args.raw.len(), 4);
    }

    #[test]
    fn program_arg_and_unknown_options() {
        let args = AgentProgramArgs::parse([
            "--homedir=/a",
            "--use-standard-socket",
            "gpg",
            "-v",
            "--options",
            "/x.conf",
            "--homedir",
            "/b",
            "--daemon",
        ]);
        assert_eq!(args.homedir.as_deref(), Some(Path::new("/b")));
        assert!(args.daemon);
        assert_eq!(args.unknown, ["gpg", "-v", "--options", "/x.conf"].map(OsString::from));
        assert_eq!(args.raw.len(), 9);
    }

    #[test]
    fn odd_arguments() {
        assert_eq!(AgentProgramArgs::parse(Vec::<OsString>::new()), AgentProgramArgs::default());
        let args = AgentProgramArgs::parse(["--homedir"]);
        assert_eq!(args.homedir, None);
        assert_eq!(args.unknown, [OsString::from("--homedir")]);
        let args = AgentProgramArgs::parse(["--", "--daemon"]);
        assert!(!args.daemon);
        assert_eq!(args.unknown, [OsString::from("--daemon")]);
        let args = AgentProgramArgs::parse([OsString::from_vec(b"--homedir=/\xff".to_vec())]);
        assert_eq!(args.homedir.unwrap().as_os_str().as_bytes(), b"/\xff");
    }
}
