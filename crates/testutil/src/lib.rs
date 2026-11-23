//! Test harness shared by the daemon's tests and `credential-bridge-integration`: runs
//! `credential-bridged` in a temporary home with fake upstream agents, fake server host
//! keys and agent clients. No network, no real keys.
//!
//! The daemon lets a bind select a server only for a local ssh client it verified as
//! OpenSSH 8.9 or later, by the release string in the client's executable. So clients
//! on `agent-forward.sock` connect through the `fake-ssh` binary of this crate, which
//! carries such a string and relays its stdin to the socket ([`ssh_client`]);
//! `fake-ssh-old` carries an OpenSSH 8.8 string, and a test process that connects
//! itself ([`client`]) is no OpenSSH client at all.
//!
//! This package's own integration test (`tests/fake_ssh.rs`) makes cargo build both
//! binaries whenever the workspace's tests are built (`--workspace`).

use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use credential_bridge_proto::agent::{
    AgentClient, ExtensionReply, Identity, Message, read_frame, write_frame,
};
use credential_bridge_proto::ext;
use credential_bridge_proto::wire::Writer;
use signature::Signer;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};

/// A temporary directory with a short path (unix socket paths are limited).
pub fn short_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new().prefix("cbd").tempdir_in("/tmp").expect("temp dir in /tmp")
}

/// The path of the workspace binary `name`, for tests of a package that does not build
/// it (`CARGO_BIN_EXE_*` only covers the test's own package). Binaries land in the
/// profile directory (`<target>/debug`); the test executable lies below it, in `deps/`
/// or, with cargo's newer build-dir layout, in `build/<crate>/<hash>/out/`. So the
/// nearest ancestor of the test executable that holds `name` is the answer.
/// `cargo test --workspace` and `cargo nextest run --workspace` build every binary
/// before running tests.
pub fn workspace_binary(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("path of the test executable");
    exe.ancestors()
        .skip(1)
        .take(6)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| {
            panic!(
                "no {name} binary in the directories above {}: build the workspace binaries first \
                 (cargo build --workspace, or run the tests with --workspace)",
                exe.display()
            )
        })
}

/// A running daemon; terminated (SIGTERM) on drop.
#[derive(Debug)]
pub struct Daemon {
    /// The process.
    child: Child,
    /// `agent.sock`.
    pub local: PathBuf,
    /// `agent-forward.sock`.
    pub forward: PathBuf,
    /// `control.sock`.
    pub control: PathBuf,
    /// The audit log.
    pub audit: PathBuf,
    /// The configuration file.
    pub config: PathBuf,
    /// The daemon's stderr.
    pub log: PathBuf,
    /// Receives sd_notify messages.
    notify: UnixDatagram,
}

impl Daemon {
    /// Writes `config` (with `{dir}` replaced) and starts the daemon `binary`; waits for
    /// `READY=1`. `env` adds variables to the daemon's otherwise minimal environment.
    pub fn start(binary: &Path, dir: &Path, config: &str, env: &[(&str, &str)]) -> Daemon {
        let config_path = dir.join("config.toml");
        std::fs::write(&config_path, config.replace("{dir}", dir.to_str().unwrap())).unwrap();
        let notify_path = dir.join("notify");
        let _ = std::fs::remove_file(&notify_path);
        let notify = UnixDatagram::bind(&notify_path).unwrap();
        notify.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let log = dir.join("daemon.log");
        let stderr = std::fs::File::create(&log).unwrap();
        let mut command = Command::new(binary);
        command
            .arg("--config")
            .arg(&config_path)
            .env_clear()
            .env("HOME", dir)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("XDG_STATE_HOME", dir.join("state"))
            .env("XDG_CONFIG_HOME", dir.join("xdg-config"))
            .env("NOTIFY_SOCKET", &notify_path)
            .env("RUST_LOG", "debug")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr);
        for (name, value) in env {
            command.env(name, value);
        }
        let child = command.spawn().expect("daemon starts");
        let mut daemon = Daemon {
            child,
            local: dir.join("s/agent.sock"),
            forward: dir.join("s/agent-forward.sock"),
            control: dir.join("s/control.sock"),
            audit: dir.join("audit.log"),
            config: config_path,
            log,
            notify,
        };
        daemon.wait_for_notify("READY=1");
        daemon
    }

    /// Waits for an sd_notify message starting with `prefix`.
    pub fn wait_for_notify(&mut self, prefix: &str) {
        let mut buf = [0u8; 256];
        loop {
            match self.notify.recv(&mut buf) {
                Ok(n) if buf[..n].starts_with(prefix.as_bytes()) => return,
                Ok(_) => {}
                Err(error) => {
                    let status = self.child.try_wait().unwrap();
                    panic!("no {prefix} from the daemon ({error}, exit {status:?}):\n{}", self.log_text());
                }
            }
        }
    }

    /// The daemon's log so far.
    pub fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The audit log so far. The daemon writes it from a writer thread, so a line for a
    /// request may appear only after the reply: use [`Daemon::wait_for_audit`] to read
    /// it after a request.
    pub fn audit_text(&self) -> String {
        std::fs::read_to_string(&self.audit).unwrap_or_default()
    }

    /// Polls the audit log (up to 10 s) until it contains every one of `needles` and
    /// returns it; panics with the log if they do not appear.
    pub fn wait_for_audit_all(&self, needles: &[&str]) -> String {
        let mut text = String::new();
        if eventually(|| {
            text = self.audit_text();
            needles.iter().all(|needle| text.contains(needle))
        }) {
            return text;
        }
        panic!("audit log lacks {needles:?}:\n{text}\ndaemon log:\n{}", self.log_text());
    }

    /// [`Daemon::wait_for_audit_all`] for one needle.
    pub fn wait_for_audit(&self, needle: &str) -> String {
        self.wait_for_audit_all(&[needle])
    }

    /// The path of `agent-forward.sock`.
    pub fn forward_path(&self) -> &Path {
        &self.forward
    }

    /// The daemon's pid.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Sends a signal.
    pub fn signal(&self, signal: rustix::process::Signal) {
        let pid = rustix::process::Pid::from_raw(i32::try_from(self.child.id()).unwrap()).unwrap();
        rustix::process::kill_process(pid, signal).unwrap();
    }

    /// Terminates the daemon and waits for it; returns its exit status.
    pub fn stop(&mut self) -> std::process::ExitStatus {
        if self.child.try_wait().unwrap().is_none() {
            self.signal(rustix::process::Signal::TERM);
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                return self.child.wait().unwrap();
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// An agent client on `agent.sock`.
    pub fn local_client(&self) -> AgentClient<UnixStream> {
        client(&self.local)
    }

    /// An agent client on `agent-forward.sock` through [`FAKE_SSH`], a verified local
    /// OpenSSH client.
    pub fn forward_client(&self) -> AgentClient<UnixStream> {
        ssh_client(FAKE_SSH, &self.forward)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop();
        if std::thread::panicking() {
            eprintln!("--- daemon log ---\n{}", self.log_text());
        }
    }
}

/// The relay binary that plays a local OpenSSH 9.9 client.
pub const FAKE_SSH: &str = "fake-ssh";

/// The relay binary that plays a local OpenSSH 8.8 client (no session-bind support).
pub const FAKE_SSH_OLD: &str = "fake-ssh-old";

/// An agent client on `path` whose peer is the workspace binary `program`
/// ([`FAKE_SSH`], [`FAKE_SSH_OLD`]): it connects to `path` and relays one end of a
/// socket pair to it, so the daemon sees that program as the local ssh client. The
/// relay ends when either side closes; its process is reaped by a thread.
pub fn ssh_client(program: &str, path: &Path) -> AgentClient<UnixStream> {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let mut child = Command::new(workspace_binary(program))
        .arg(path)
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(theirs)))
        .stdout(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("start {program}: {e}"));
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    ours.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    AgentClient::new(ours)
}

/// The main function of the `fake-ssh` binaries: `fake-ssh SOCKET` connects to
/// `SOCKET` and relays between it and stdin (a unix stream socket, see [`ssh_client`]);
/// `fake-ssh -V` prints the release. `release` is the NUL-framed OpenSSH release string
/// the daemon finds in the executable; it must be a literal in the binary's `main`.
pub fn fake_ssh_main(release: &'static [u8]) {
    let release = std::hint::black_box(release);
    let Some(socket) = std::env::args_os().nth(1) else {
        eprintln!("usage: fake-ssh SOCKET | -V");
        std::process::exit(2);
    };
    if socket == "-V" {
        eprintln!("{}", String::from_utf8_lossy(release).trim_matches('\0'));
        return;
    }
    let local = std::io::stdin().as_fd().try_clone_to_owned().map(UnixStream::from).expect("stdin");
    let upstream = UnixStream::connect(&socket).unwrap_or_else(|e| {
        eprintln!("fake-ssh: connect {}: {e}", socket.to_string_lossy());
        std::process::exit(1);
    });
    let (mut local_in, mut upstream_out) = (local.try_clone().unwrap(), upstream.try_clone().unwrap());
    let outbound = std::thread::spawn(move || {
        let _ = std::io::copy(&mut local_in, &mut upstream_out);
        let _ = upstream_out.shutdown(std::net::Shutdown::Write);
    });
    let (mut upstream_in, mut local_out) = (upstream, local);
    let _ = std::io::copy(&mut upstream_in, &mut local_out);
    let _ = local_out.shutdown(std::net::Shutdown::Write);
    let _ = outbound.join();
}

/// An agent client with a read timeout. On `agent-forward.sock` the test process itself
/// is the peer, which the daemon does not verify as an OpenSSH client.
pub fn client(path: &Path) -> AgentClient<UnixStream> {
    let stream = UnixStream::connect(path).unwrap_or_else(|e| panic!("connect {}: {e}", path.display()));
    stream.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    AgentClient::new(stream)
}

/// A fake upstream agent: one key, a fixed signature, records every request.
#[derive(Clone, Debug)]
pub struct FakeAgent {
    /// The socket.
    pub socket: PathBuf,
    /// The key it lists.
    pub key: Identity,
    /// The signature blob it answers every sign request with.
    pub signature: Vec<u8>,
    /// Requests seen (raw payloads), across connections.
    pub seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl FakeAgent {
    /// Starts serving at `socket` on background threads.
    pub fn spawn(socket: PathBuf, name: &str) -> FakeAgent {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let identity = Identity {
            key_blob: key.public_key().to_bytes().unwrap(),
            comment: format!("{name}-key").into_bytes(),
        };
        let agent = FakeAgent {
            socket: socket.clone(),
            key: identity,
            signature: format!("signature-from-{name}").into_bytes(),
            seen: Arc::default(),
        };
        let listener = UnixListener::bind(&socket).unwrap();
        let serving = agent.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let agent = serving.clone();
                std::thread::spawn(move || {
                    while let Ok(Some(payload)) = read_frame(&mut stream) {
                        agent.seen.lock().unwrap().push(payload.clone());
                        let reply = match Message::decode(&payload) {
                            Ok(Message::RequestIdentities) => {
                                Message::IdentitiesAnswer(vec![agent.key.clone()])
                            }
                            Ok(Message::SignRequest { .. }) => {
                                Message::SignResponse { signature: agent.signature.clone() }
                            }
                            Ok(Message::Extension { .. } | Message::RemoveAllIdentities) => {
                                Message::Success { contents: vec![] }
                            }
                            _ => Message::Failure,
                        };
                        if write_frame(&mut stream, &reply.encode()).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        agent
    }

    /// The decoded requests seen so far.
    pub fn messages(&self) -> Vec<Message> {
        self.seen.lock().unwrap().iter().map(|payload| Message::decode(payload).unwrap()).collect()
    }

    /// Forgets the recorded requests.
    pub fn clear(&self) {
        self.seen.lock().unwrap().clear();
    }
}

/// A fake ssh server host key.
#[derive(Debug)]
pub struct Host {
    /// The private key (generated for the test).
    pub key: PrivateKey,
}

impl Default for Host {
    fn default() -> Host {
        Host::new()
    }
}

impl Host {
    /// A new ed25519 host key.
    pub fn new() -> Host {
        Host { key: PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap() }
    }

    /// The public key in OpenSSH format, for `host_keys`.
    pub fn openssh(&self) -> String {
        self.key.public_key().to_openssh().unwrap()
    }

    /// The `SHA256:…` fingerprint of the host key, as the audit log shows it.
    pub fn fingerprint(&self) -> String {
        self.key.public_key().fingerprint(ssh_key::HashAlg::Sha256).to_string()
    }

    /// `session-bind@openssh.com` contents for `session_id`, correctly signed.
    pub fn bind(&self, session_id: &[u8], is_forwarding: bool) -> Vec<u8> {
        let signature: ssh_key::Signature = self.key.try_sign(session_id).unwrap();
        let signature = Vec::<u8>::try_from(signature).unwrap();
        bind_contents(&self.key.public_key().to_bytes().unwrap(), session_id, &signature, is_forwarding)
    }

    /// A bind like [`Host::bind`] with a host certificate for the key (signed by a fresh
    /// CA) as host key, as ssh sends it after negotiating a `*-cert-v01` algorithm.
    pub fn cert_bind(&self, session_id: &[u8], is_forwarding: bool) -> Vec<u8> {
        let ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
            &mut OsRng,
            self.key.public_key().key_data().clone(),
            1_000_000_000,
            4_000_000_000,
        )
        .unwrap();
        builder.cert_type(ssh_key::certificate::CertType::Host).unwrap();
        builder.valid_principal("server.example").unwrap();
        let cert = builder.sign(&ca).unwrap().to_bytes().unwrap();
        let signature: ssh_key::Signature = self.key.try_sign(session_id).unwrap();
        let signature = Vec::<u8>::try_from(signature).unwrap();
        bind_contents(&cert, session_id, &signature, is_forwarding)
    }

    /// A bind whose signature covers another session id.
    pub fn forged_bind(&self, session_id: &[u8]) -> Vec<u8> {
        let signature: ssh_key::Signature = self.key.try_sign(b"another session").unwrap();
        let signature = Vec::<u8>::try_from(signature).unwrap();
        bind_contents(&self.key.public_key().to_bytes().unwrap(), session_id, &signature, true)
    }
}

/// Builds bind contents.
pub fn bind_contents(host_key: &[u8], session_id: &[u8], signature: &[u8], is_forwarding: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_string(host_key).put_string(session_id).put_string(signature).put_bool(is_forwarding);
    w.into_bytes()
}

/// The extension message for a bind.
pub fn bind_message(contents: Vec<u8>) -> Message {
    Message::Extension { name: ext::SESSION_BIND.to_owned(), contents }
}

/// Sends a bind and returns whether it was accepted.
pub fn send_bind(client: &mut AgentClient<UnixStream>, contents: Vec<u8>) -> bool {
    match client.request(&bind_message(contents)).unwrap() {
        Message::Success { .. } => true,
        Message::Failure => false,
        other => panic!("unexpected bind reply {other:?}"),
    }
}

/// Lists identities; `None` if the request failed.
pub fn list(client: &mut AgentClient<UnixStream>) -> Option<Vec<Identity>> {
    match client.request(&Message::RequestIdentities).unwrap() {
        Message::IdentitiesAnswer(list) => Some(list),
        Message::Failure => None,
        other => panic!("unexpected list reply {other:?}"),
    }
}

/// Sends an extension and returns the reply.
pub fn extension(client: &mut AgentClient<UnixStream>, name: &str, contents: &[u8]) -> ExtensionReply {
    client.extension(name, contents).unwrap()
}

/// Writes an executable shell script.
pub fn script(path: &Path, body: &str) {
    write_script(path, body);
}

/// Writes `#!/bin/sh` and `body` to `path` and makes it executable. Written by a child `sh`, so this process never holds the file open for writing: a
/// test thread that forks meanwhile would inherit such a descriptor until its child
/// execs, and running the script in that window fails with ETXTBSY ("Text file busy").
fn write_script(path: &std::path::Path, body: &str) {
    use std::io::Write as _;
    let mut child = std::process::Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(path)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(format!("#!/bin/sh\n{body}\n").as_bytes()).unwrap();
    assert!(child.wait().unwrap().success(), "writing {} failed", path.display());
}

/// Whether `program` can be run from PATH.
pub fn have(program: &str) -> bool {
    Command::new(program)
        .arg("-?")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Polls `condition` for up to 10 s.
pub fn eventually(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Reads all of a stream until EOF (for fake servers).
pub fn read_all(stream: &mut UnixStream) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    out
}
