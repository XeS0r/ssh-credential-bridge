//! The `fake-ssh` relays. Besides testing them, this integration test makes cargo build
//! the binaries of this package whenever the workspace's tests are built (cargo builds a
//! package's binaries only for that package's own integration tests), so the daemon's
//! and the integration crate's tests never find a stale or dummy `fake-ssh`.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::process::Command;

use credential_bridge_testutil::{FAKE_SSH, FAKE_SSH_OLD, short_tempdir, ssh_client};

#[test]
fn prints_its_release() {
    for (binary, release) in [
        (env!("CARGO_BIN_EXE_fake-ssh"), "OpenSSH_9.9p1"),
        (env!("CARGO_BIN_EXE_fake-ssh-old"), "OpenSSH_8.8p1"),
    ] {
        let output = Command::new(binary).arg("-V").output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).starts_with(release), "{binary}");
    }
}

#[test]
fn relays_both_ways_until_closed() {
    let dir = short_tempdir();
    let path = dir.path().join("echo.sock");
    let listener = UnixListener::bind(&path).unwrap();
    for program in [FAKE_SSH, FAKE_SSH_OLD] {
        let client = ssh_client(program, &path);
        let (mut server, _) = listener.accept().unwrap();
        let mut stream = client.into_inner();
        stream.write_all(b"ping").unwrap();
        let mut buf = [0; 4];
        server.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        server.write_all(b"pong").unwrap();
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        // Closing our end reaches the server as end of file, and back.
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(server.read(&mut buf).unwrap(), 0);
        drop(server);
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }
}
