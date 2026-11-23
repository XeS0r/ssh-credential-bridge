//! Plays a local OpenSSH 9.9 client for the daemon's ssh client check; see
//! [`credential_bridge_testutil::fake_ssh_main`].

fn main() {
    credential_bridge_testutil::fake_ssh_main(b"\0OpenSSH_9.9p1 credential-bridge-testutil\0");
}
