//! The daemon as a process: signals during startup and readiness notification.

use std::io::Write;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn daemon(config: &Path, notify: Option<&Path>) -> Child {
    daemon_with_state(config, notify, &config.parent().unwrap().join("state"))
}

fn daemon_with_state(config: &Path, notify: Option<&Path>, state: &Path) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_credential-bridged"));
    cmd.env("XDG_STATE_HOME", state);
    cmd.args(["run", "--config"]).arg(config).stdout(Stdio::null()).stderr(Stdio::null());
    cmd.env_remove("NOTIFY_SOCKET");
    if let Some(socket) = notify {
        cmd.env("NOTIFY_SOCKET", socket);
    }
    cmd.spawn().unwrap()
}

fn hangup(child: &Child) {
    let pid = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::HUP).unwrap();
}

fn config_text(sockets: &Path) -> String {
    format!(
        "backend = \"!true\"\nsocket_dir = \"{}\"\n[[remote]]\nname = \"r\"\nallow = [\"https://github.com\"]\n",
        sockets.display()
    )
}

#[test]
fn survives_sighup_while_loading_the_config() {
    let dir = tempfile::tempdir().unwrap();
    // A FIFO as config: the daemon blocks in Config::load until we write it,
    // which is exactly the window in which a SIGHUP used to kill it.
    let config = dir.path().join("config.toml");
    assert!(Command::new("mkfifo").arg(&config).status().unwrap().success());
    let mut child = daemon(&config, None);
    std::thread::sleep(Duration::from_millis(300));

    hangup(&child);
    std::thread::sleep(Duration::from_millis(200));
    assert!(child.try_wait().unwrap().is_none(), "SIGHUP during startup killed the daemon");

    // Let it finish loading; it must come up and serve.
    std::fs::OpenOptions::new()
        .write(true)
        .open(&config)
        .unwrap()
        .write_all(config_text(&dir.path().join("s")).as_bytes())
        .unwrap();
    let socket = dir.path().join("s/r.sock");
    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(socket.exists(), "daemon did not come up after the SIGHUP");
    assert!(child.try_wait().unwrap().is_none());
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn notifies_systemd_once_the_sockets_are_bound() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, config_text(&dir.path().join("s"))).unwrap();
    let notify_path = dir.path().join("notify");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    notify.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

    let mut child = daemon(&config, Some(&notify_path));
    let mut buf = [0u8; 64];
    let len = notify.recv(&mut buf).expect("no READY=1 from the daemon");
    assert_eq!(&buf[..len], b"READY=1");
    assert!(dir.path().join("s/r.sock").exists(), "READY=1 came before the socket was bound");
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn records_the_applied_config_locally_and_updates_it_on_reload() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let first = config_text(&dir.path().join("s"));
    std::fs::write(&config, &first).unwrap();
    let loaded = dir.path().join("state/credential-bridge/loaded-config");
    let mut child = daemon_with_state(&config, None, &dir.path().join("state"));

    let read = |want: &str| {
        for _ in 0..100 {
            if std::fs::read_to_string(&loaded).is_ok_and(|t| t.trim() == want) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    };
    assert!(read(&credential_bridge_proto::fingerprint(&first)), "not recorded after start");

    let second = format!("{first}\n# changed\n");
    std::fs::write(&config, &second).unwrap();
    hangup(&child);
    assert!(read(&credential_bridge_proto::fingerprint(&second)), "not updated after SIGHUP");

    hangup_term(&child);
    child.wait().unwrap();
    assert!(!loaded.exists(), "left behind after stopping");
}

fn hangup_term(child: &Child) {
    let pid = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
}
