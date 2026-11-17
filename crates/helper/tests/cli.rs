//! The helper as git and users run it, including the documented environment.

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn helper(args: &[&str], env: &[(&str, &str)], stdin: &str) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_git-credential-bridge"));
    cmd.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for name in ["CREDENTIAL_BRIDGE_VERBOSE", "CREDENTIAL_BRIDGE_QUIET", "CREDENTIAL_BRIDGE_SOCK", "NO_COLOR"]
    {
        cmd.env_remove(name);
    }
    cmd.envs(env.iter().copied());
    let mut child = cmd.spawn().unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

const NO_SOCKET: &str = "/nonexistent/credential-bridge.sock";

#[test]
fn verbose_and_quiet_accept_the_documented_values() {
    for value in ["1", "true", "yes", "on"] {
        let out = helper(&["--socket", NO_SOCKET, "ping"], &[("CREDENTIAL_BRIDGE_VERBOSE", value)], "");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "VERBOSE={value}: {stderr}");
        assert!(stderr.contains("not connected to your local machine"), "{stderr}");
        assert!(stderr.contains(NO_SOCKET), "verbose adds the socket path: {stderr}");
    }

    let request = "protocol=https\nhost=github.com\n\n";
    let out = helper(&["--socket", NO_SOCKET, "get"], &[("CREDENTIAL_BRIDGE_QUIET", "1")], request);
    assert!(out.status.success(), "QUIET=1 must not break git: {:?}", out);
    assert!(out.stderr.is_empty(), "QUIET=1 must silence warnings: {}", String::from_utf8_lossy(&out.stderr));

    let out = helper(&["--socket", NO_SOCKET, "get"], &[("CREDENTIAL_BRIDGE_QUIET", "0")], request);
    assert!(out.status.success());
    assert!(!out.stderr.is_empty(), "QUIET=0 means not quiet");
}
