//! Plays a local OpenSSH 8.8 client (no session-bind support) for the daemon's ssh
//! client check; see [`credential_bridge_testutil::fake_ssh_main`].

fn main() {
    credential_bridge_testutil::fake_ssh_main(b"\0OpenSSH_8.8p1 credential-bridge-testutil\0");
}
