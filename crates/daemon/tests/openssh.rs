//! The daemon in front of a real OpenSSH `ssh-agent`, driven by the real `ssh-add`.
//! Skipped when `ssh-agent`, `ssh-add` or `ssh-keygen` are not on PATH.

use std::path::Path;
use std::process::{Child, Command, Stdio};

use common::{Daemon, Host, eventually, list, script, send_bind, short_tempdir};
use credential_bridge_proto::agent::Message;
use credential_bridge_proto::wire::{Reader, Writer};
use credential_bridge_testutil as common;
use signature::Verifier;

/// The daemon binary under test.
const DAEMON: &str = env!("CARGO_BIN_EXE_credential-bridged");

/// A running `ssh-agent -D`; killed on drop.
struct SshAgent(Child);

impl Drop for SshAgent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn ssh_add(socket: &Path, args: &[&str], askpass: Option<&Path>) -> std::process::Output {
    let mut command = Command::new("ssh-add");
    command.args(args).env("SSH_AUTH_SOCK", socket).stdin(Stdio::null());
    if let Some(askpass) = askpass {
        command.env("SSH_ASKPASS", askpass).env("SSH_ASKPASS_REQUIRE", "force").env("DISPLAY", ":0");
    }
    command.output().unwrap()
}

/// Whether the OpenSSH tools are available; prints why a test is skipped if not.
fn have_openssh() -> bool {
    let have = ["ssh-agent", "ssh-add", "ssh-keygen"].iter().all(|program| common::have(program));
    if !have {
        eprintln!("skipped: OpenSSH tools not on PATH");
    }
    have
}

/// Starts `ssh-agent -D` at `socket`.
fn start_ssh_agent(socket: &Path) -> SshAgent {
    let agent = SshAgent(
        Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    assert!(eventually(|| socket.exists()), "ssh-agent did not start");
    agent
}

/// Runs `ssh-keygen -q -N ""` with `args`.
fn keygen(args: &[&str]) {
    let output = Command::new("ssh-keygen").args(["-q", "-N", ""]).args(args).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}

/// A daemon config with the upstream `openssh` (also `add_to`) at `{dir}/openssh.sock`
/// and the server `srv` with `host_keys` pinned and profile `srv`.
fn config(host_keys: &[String]) -> String {
    let host_keys = host_keys.iter().map(|key| format!("{key:?}")).collect::<Vec<_>>().join(", ");
    format!(
        r#"
version = 2
[daemon]
socket = "{{dir}}/s/agent.sock"
forward_socket = "{{dir}}/s/agent-forward.sock"
control_socket = "{{dir}}/s/control.sock"
audit_log = "{{dir}}/audit.log"

[agent]
add_to = "openssh"

[[agent.upstream]]
name = "openssh"
socket = "{{dir}}/openssh.sock"

[profile.srv]
ssh = {{ keys = ["openssh"] }}

[server.srv]
host_keys = [{}]
profile = "srv"
"#,
        host_keys
    )
}

/// Decodes standard base64 with padding (an OpenSSH public key line's blob).
fn base64_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for byte in text.bytes().take_while(|&b| b != b'=') {
        let value = ALPHABET.iter().position(|&c| c == byte).expect("base64");
        acc = (acc << 6) | u32::try_from(value).unwrap();
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).unwrap());
        }
    }
    out
}

#[test]
fn real_ssh_agent_behind_the_proxy() {
    if !have_openssh() {
        return;
    }
    let dir = short_tempdir();
    let path = dir.path();
    let agent_socket = path.join("openssh.sock");
    let _agent = start_ssh_agent(&agent_socket);
    let key_file = path.join("id");
    keygen(&["-t", "ed25519", "-C", "proxy-test-key", "-f", key_file.to_str().unwrap()]);
    let public = ssh_key::PublicKey::read_openssh_file(&path.join("id.pub")).unwrap();

    let host = Host::new();
    let daemon = Daemon::start(DAEMON.as_ref(), path, &config(&[host.openssh()]), &[]);

    // ssh-add through agent.sock lands in ssh-agent (add_to).
    let added = ssh_add(&daemon.local, &[key_file.to_str().unwrap()], None);
    assert!(added.status.success(), "{}", String::from_utf8_lossy(&added.stderr));
    let listed = ssh_add(&daemon.local, &["-l"], None);
    assert!(String::from_utf8_lossy(&listed.stdout).contains("proxy-test-key"));
    let direct = ssh_add(&agent_socket, &["-l"], None);
    assert!(String::from_utf8_lossy(&direct.stdout).contains("proxy-test-key"));

    // Write commands from the forward socket are refused.
    let refused = ssh_add(&daemon.forward, &["-D"], None);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&ssh_add(&agent_socket, &["-l"], None).stdout).contains("proxy-test-key")
    );

    // A server signs through the forward socket; the bind is replayed to ssh-agent,
    // which verifies it itself, and the signature verifies with the key.
    let mut forward = daemon.forward_client();
    assert!(send_bind(&mut forward, host.bind(b"real-session", true)));
    let keys = list(&mut forward).unwrap();
    assert_eq!(keys.len(), 1);
    let data = b"git commit to sign".to_vec();
    let reply = forward
        .request(&Message::SignRequest { key_blob: keys[0].key_blob.clone(), data: data.clone(), flags: 0 })
        .unwrap();
    let Message::SignResponse { signature } = reply else {
        panic!("no signature: {reply:?}\n{}", daemon.log_text())
    };
    let signature = ssh_key::Signature::try_from(signature.as_slice()).unwrap();
    Verifier::verify(&public, &data, &signature).expect("the upstream's signature passes unchanged");

    // ssh-add -x / -X lock the proxy.
    let askpass = path.join("askpass");
    script(&askpass, "echo lock-pass");
    assert!(ssh_add(&daemon.local, &["-x"], Some(&askpass)).status.success());
    assert!(
        !String::from_utf8_lossy(&ssh_add(&daemon.local, &["-l"], None).stdout).contains("proxy-test-key")
    );
    assert_eq!(list(&mut daemon.forward_client()).unwrap(), vec![]);
    assert!(ssh_add(&daemon.local, &["-X"], Some(&askpass)).status.success());
    assert!(
        String::from_utf8_lossy(&ssh_add(&daemon.local, &["-l"], None).stdout).contains("proxy-test-key")
    );

    // ssh-add -d through the proxy removes the key from ssh-agent.
    let removed = ssh_add(&daemon.local, &["-d", path.join("id.pub").to_str().unwrap()], None);
    assert!(removed.status.success(), "{}", String::from_utf8_lossy(&removed.stderr));
    assert!(
        !String::from_utf8_lossy(&ssh_add(&agent_socket, &["-l"], None).stdout).contains("proxy-test-key")
    );
}

#[test]
fn refused_binds_reach_ssh_agent_for_destination_constraints() {
    if !have_openssh() {
        return;
    }
    let dir = short_tempdir();
    let path = dir.path();
    let agent_socket = path.join("openssh.sock");
    let _agent = start_ssh_agent(&agent_socket);
    let host = Host::new();
    let daemon = Daemon::start(DAEMON.as_ref(), path, &config(&[host.openssh()]), &[]);

    // A key that may only be used towards dest.example (ssh-add -h).
    let key_file = path.join("id");
    keygen(&["-t", "ed25519", "-C", "constrained-key", "-f", key_file.to_str().unwrap()]);
    let known_hosts = path.join("known_hosts");
    std::fs::write(&known_hosts, format!("dest.example {}\n", host.openssh())).unwrap();
    let added = ssh_add(
        &daemon.local,
        &["-H", known_hosts.to_str().unwrap(), "-h", "dest.example", key_file.to_str().unwrap()],
        None,
    );
    assert!(added.status.success(), "{}", String::from_utf8_lossy(&added.stderr));

    // Without any bind, ssh-agent treats the connection as local and lists the key.
    assert_eq!(list(&mut daemon.local_client()).unwrap().len(), 1);
    // After a bind the proxy refused, ssh-agent must know that a bind was attempted:
    // it then hides destination-constrained keys, as it would without the proxy.
    for bind in [b"garbage".to_vec(), host.forged_bind(b"session")] {
        let mut local = daemon.local_client();
        assert!(!send_bind(&mut local, bind));
        assert_eq!(list(&mut local).unwrap(), vec![], "{}", daemon.log_text());
    }
}

#[test]
fn host_certificates_from_ssh_keygen_select_the_server() {
    if !have_openssh() {
        return;
    }
    let dir = short_tempdir();
    let path = dir.path();
    let agent_socket = path.join("openssh.sock");
    let _agent = start_ssh_agent(&agent_socket);
    let ca = path.join("ca");
    keygen(&["-t", "ed25519", "-f", ca.to_str().unwrap()]);
    // ssh-key cannot sign with RSA (see the proto tests), so RSA certificates are covered
    // by the proto unit tests only.
    let mut hosts = Vec::new();
    for (kind, bits) in [("ed25519", "256"), ("ecdsa", "256"), ("ecdsa", "384")] {
        let host_file = path.join(format!("host_{kind}_{bits}"));
        keygen(&["-t", kind, "-b", bits, "-f", host_file.to_str().unwrap()]);
        let host_pub = format!("{}.pub", host_file.display());
        keygen(&["-s", ca.to_str().unwrap(), "-h", "-I", "srv", "-n", "srv.example", &host_pub]);
        let cert_text = std::fs::read_to_string(format!("{}-cert.pub", host_file.display())).unwrap();
        // ssh-key cannot parse the default "forever" validity, so decode the blob here.
        let cert = base64_decode(cert_text.split_whitespace().nth(1).unwrap());
        let host = Host { key: ssh_key::PrivateKey::read_openssh_file(&host_file).unwrap() };
        hosts.push((format!("{kind}-{bits}"), host, cert));
    }
    let pinned: Vec<String> = hosts.iter().map(|(_, host, _)| host.openssh()).collect();
    let daemon = Daemon::start(DAEMON.as_ref(), path, &config(&pinned), &[]);

    for (kind, host, cert) in &hosts {
        // The bind ssh sends after negotiating a certificate host key algorithm: the
        // certificate as host key, signed with the plain key.
        let plain_bind = host.bind(kind.as_bytes(), true);
        let mut reader = Reader::new(&plain_bind);
        reader.read_string().unwrap();
        let mut contents = Writer::new();
        contents.put_string(cert).put_raw(reader.read_rest());
        let mut forward = daemon.forward_client();
        assert!(send_bind(&mut forward, contents.into_bytes()), "{kind}: {}", daemon.log_text());
        // An empty list either way (profile srv and profile.unregistered show no keys);
        // the audit log below shows that the pinned plain key was recognised.
        assert_eq!(list(&mut forward), Some(vec![]), "{kind}: {}", daemon.log_text());
    }
    assert!(
        eventually(|| daemon.audit_text().matches(r#""server":"srv""#).count() == hosts.len()),
        "{}",
        daemon.audit_text()
    );
}
