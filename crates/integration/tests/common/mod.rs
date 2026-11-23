//! Helpers for the cross-crate tests.

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use credential_bridge_testutil::{Daemon, FAKE_SSH, send_bind, ssh_client, workspace_binary};

/// The `credential-bridged` binary. `cargo test`/`nextest run --workspace` build it
/// fresh because the daemon package has integration tests of its own.
pub fn daemon_binary() -> PathBuf {
    workspace_binary("credential-bridged")
}

/// A socket that plays the ssh client: each connection to it is relayed to
/// `agent-forward.sock` after sending `bind` as the first message. The connection to the
/// daemon goes through `fake-ssh`, which the daemon verifies as OpenSSH 8.9 or later.
pub fn binding_relay(dir: &Path, daemon: &Daemon, bind: Vec<u8>) -> PathBuf {
    let path = dir.join("relay.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let forward = daemon.forward_path().to_owned();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut inner) = incoming else { return };
            let mut upstream = ssh_client(FAKE_SSH, &forward);
            assert!(send_bind(&mut upstream, bind.clone()));
            let mut outer = upstream.into_inner();
            let (mut inner2, mut outer2) = (inner.try_clone().unwrap(), outer.try_clone().unwrap());
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut inner2, &mut outer2);
                let _ = outer2.shutdown(std::net::Shutdown::Write);
            });
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut outer, &mut inner);
                let _ = inner.shutdown(std::net::Shutdown::Write);
            });
        }
    });
    path
}

/// Runs the server-side git helper (`git get`) against `auth_sock` with `input` and
/// returns the error it would print; asserts that it prints nothing on stdout.
///
/// Calls `credential_bridge_remote::git_helper::run` in-process rather than running the
/// binary: cargo builds a package's binaries only for that package's own tests, so
/// `credential-bridge-remote` may be missing or stale (crane's dummy from the
/// dependency-only build) when these tests run.
pub fn remote_helper_error(auth_sock: &Path, input: &str) -> String {
    let mut stdout = Vec::new();
    let result =
        credential_bridge_remote::git_helper::run("get", Some(auth_sock), input.as_bytes(), &mut stdout);
    assert!(stdout.is_empty(), "{}", String::from_utf8_lossy(&stdout));
    result.expect_err("the helper should fail").to_string()
}

/// Runs the server-side git helper (`git get`) against `auth_sock` with `input` and
/// returns what it printed; asserts that it does not fail (it steps aside silently when
/// there is no bridge to be seen).
pub fn remote_helper_output(auth_sock: &Path, input: &str) -> String {
    let mut stdout = Vec::new();
    credential_bridge_remote::git_helper::run("get", Some(auth_sock), input.as_bytes(), &mut stdout)
        .expect("the helper should step aside without an error");
    String::from_utf8(stdout).unwrap()
}
