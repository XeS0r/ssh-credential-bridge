//! End-to-end tests: the real daemon binary against fake upstream agents, fake server
//! host keys, a fake git credential helper and a fake gpg-agent.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use common::{Daemon, FakeAgent, Host, eventually, extension, list, script, send_bind, short_tempdir};
use credential_bridge_proto::agent::{ExtensionReply, Message};
use credential_bridge_proto::credential::Credential;
use credential_bridge_proto::ext::{self, GitAction, GitReply, GitRequest, GpgReply, GpgRequest};
use credential_bridge_proto::ipc::control;
use credential_bridge_proto::secret::SecretBytes;
use credential_bridge_testutil as common;

/// The daemon binary under test.
const DAEMON: &str = env!("CARGO_BIN_EXE_credential-bridged");

/// Two fake upstreams (`a`, `b`), a pinned server `buildserver` with profile `build`
/// (keys of `b`, git rules, gpg sign, no hops), and the built-in `profile.unregistered`
/// (no keys, no tokens, no gpg) for every other host.
const CONFIG: &str = r#"
version = 2

[daemon]
socket = "{dir}/s/agent.sock"
forward_socket = "{dir}/s/agent-forward.sock"
control_socket = "{dir}/s/control.sock"
audit_log = "{dir}/audit.log"

[agent]
add_to = "a"

[[agent.upstream]]
name = "a"
socket = "{dir}/a.sock"

[[agent.upstream]]
name = "b"
socket = "{dir}/b.sock"

[gpg]
socket = "{dir}/gpg-agent.sock"

[source.helper]
type = "helper"
helper = "{dir}/helper.sh"

[source.forgejo]
type = "forgejo"
host = "git.example.org"
token = "cmd:printf forgejo-token"

[profile.build]
ssh = { keys = ["b"] }
gpg = ["sign"]
hops = { ssh = false, git = false, gpg = false }

[[profile.build.git]]
url = "https://git.example.com/*"
source = "helper"

[[profile.build.git]]
url = "https://git.example.org/*"
source = "forgejo"

[server.buildserver]
host_keys = ["HOST_KEY"]
profile = "build"
"#;

/// The scenario: directory, fake agents, host key, daemon.
struct Setup {
    dir: tempfile::TempDir,
    a: FakeAgent,
    b: FakeAgent,
    host: Host,
    daemon: Daemon,
}

fn setup_with(config: &str, env: &[(&str, &str)]) -> Setup {
    let dir = short_tempdir();
    let a = FakeAgent::spawn(dir.path().join("a.sock"), "a");
    let b = FakeAgent::spawn(dir.path().join("b.sock"), "b");
    let host = Host::new();
    script(
        &dir.path().join("helper.sh"),
        "cat >/dev/null\nif [ \"$1\" = get ]; then printf 'username=helper-user\\npassword=helper-pass\\n'; fi",
    );
    let config = config.replace("HOST_KEY", &host.openssh());
    let daemon = Daemon::start(DAEMON.as_ref(), dir.path(), &config, env);
    Setup { dir, a, b, host, daemon }
}

fn setup() -> Setup {
    setup_with(CONFIG, &[])
}

/// A connection on `agent-forward.sock` whose first message is the pinned server's bind.
fn server_client(s: &Setup, session: &[u8]) -> credential_bridge_proto::agent::AgentClient<UnixStream> {
    let mut forward = s.daemon.forward_client();
    assert!(send_bind(&mut forward, s.host.bind(session, true)));
    forward
}

/// The `refused` audit events with this server label, as their reasons.
fn refusals(daemon: &Daemon, label: &str) -> Vec<String> {
    daemon
        .audit_text()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|event| event["event"] == "refused" && event["server"] == label)
        .map(|event| event["reason"].as_str().unwrap().to_owned())
        .collect()
}

fn sign_request(key_blob: &[u8]) -> Message {
    Message::SignRequest { key_blob: key_blob.to_vec(), data: b"data to sign".to_vec(), flags: 0 }
}

fn git_get(url_host: &str, path: &str) -> Vec<u8> {
    let credential = Credential {
        protocol: Some("https".into()),
        host: Some(url_host.into()),
        path: Some(path.into()),
        ..Credential::default()
    };
    GitRequest { action: GitAction::Get, credential }.encode().unwrap()
}

fn git_reply(reply: ExtensionReply) -> GitReply {
    match reply {
        ExtensionReply::Success(contents) => GitReply::decode(&contents).unwrap(),
        other => panic!("git extension failed: {other:?}"),
    }
}

#[test]
fn two_sockets_mux_and_write_commands() {
    let s = setup();

    // agent.sock: all keys in upstream order; signatures routed and passed unchanged.
    let mut local = s.daemon.local_client();
    assert_eq!(list(&mut local).unwrap(), vec![s.a.key.clone(), s.b.key.clone()]);
    let request = sign_request(&s.b.key.key_blob);
    let reply = local.request(&request).unwrap();
    assert_eq!(reply, Message::SignResponse { signature: s.b.signature.clone() });
    assert!(s.b.seen.lock().unwrap().contains(&request.encode()), "the sign request reached b unchanged");
    assert!(!s.a.messages().contains(&request));

    // A key nobody listed is never signed with.
    assert_eq!(local.request(&sign_request(b"unknown key")).unwrap(), Message::Failure);

    // agent-forward.sock without bind: nothing at all, not even public keys.
    let mut forward = s.daemon.forward_client();
    assert_eq!(list(&mut forward).unwrap(), vec![]);
    assert_eq!(forward.request(&sign_request(&s.b.key.key_blob)).unwrap(), Message::Failure);
    assert_eq!(forward.request(&sign_request(&s.a.key.key_blob)).unwrap(), Message::Failure);

    // Write commands: refused on the forward socket, sent to add_to locally.
    s.a.clear();
    assert_eq!(forward.request(&Message::RemoveAllIdentities).unwrap(), Message::Failure);
    let add = Message::AddIdentity { constrained: false, body: SecretBytes::new(b"not a key".to_vec()) };
    assert_eq!(forward.request(&add).unwrap(), Message::Failure);
    assert!(s.a.messages().is_empty(), "nothing from the forward socket reached a");
    assert_eq!(local.request(&Message::RemoveAllIdentities).unwrap(), Message::Success { contents: vec![] });
    assert_eq!(s.a.messages(), vec![Message::RemoveAllIdentities]);
    assert!(!s.b.messages().contains(&Message::RemoveAllIdentities));

    // Extensions: never on agent.sock, and answered as by OpenSSH's ssh-agent
    // (SSH_AGENT_FAILURE); query on the forward socket for a registered server only.
    assert_eq!(extension(&mut local, ext::QUERY, &[]), ExtensionReply::Failure);
    assert_eq!(
        extension(&mut local, ext::GIT_CREDENTIAL, &git_get("git.example.com", "x/y")),
        ExtensionReply::Failure
    );
    assert_eq!(extension(&mut forward, ext::QUERY, &[]), ExtensionReply::Failure, "hidden without bind");
    let mut server = server_client(&s, b"session-query");
    let names = server.query_extensions().unwrap();
    assert!(names.contains(&ext::GIT_CREDENTIAL.to_owned()));
    assert!(names.contains(&ext::GPG_AGENT.to_owned()));
    assert_eq!(extension(&mut server, "unknown@example.org", &[]), ExtensionReply::Failure);

    // Garbage gets FAILURE and the connection keeps working.
    assert_eq!(local.request(&Message::Other { msg_type: 200, body: vec![1] }).unwrap(), Message::Failure);
    assert!(list(&mut local).is_some());

    let audit = s.daemon.wait_for_audit_all(&[r#""event":"refused""#, r#""event":"sign""#]);
    assert!(!audit.contains("data to sign"));
    drop(s.dir);
}

#[test]
fn binds_select_the_server_and_follow_the_rules() {
    let s = setup();

    // A verified forwarding bind with the pinned host key as the first message selects
    // profile build.
    let mut forward = s.daemon.forward_client();
    let bind = s.host.bind(b"session-1", true);
    assert!(send_bind(&mut forward, bind.clone()));
    assert_eq!(list(&mut forward).unwrap(), vec![s.b.key.clone()]);
    // The bind was replayed to b before the list, byte for byte.
    let seen = s.b.messages();
    let bind_at = seen.iter().position(|m| *m == common::bind_message(bind.clone())).expect("bind replayed");
    let list_at = seen.iter().position(|m| *m == Message::RequestIdentities).unwrap();
    assert!(bind_at < list_at);
    assert_eq!(
        forward.request(&sign_request(&s.b.key.key_blob)).unwrap(),
        Message::SignResponse { signature: s.b.signature.clone() }
    );
    // The same bind again is fine (as ssh-agent).
    assert!(send_bind(&mut forward, bind));

    // A later forwarding bind (hop): build has hops.ssh = false, so an empty list.
    let other = Host::new();
    assert!(send_bind(&mut forward, other.bind(b"session-2", true)));
    assert_eq!(list(&mut forward).unwrap(), vec![]);
    assert_eq!(forward.request(&sign_request(&s.b.key.key_blob)).unwrap(), Message::Failure);

    // Bad signatures are refused and change nothing: no server, no keys.
    let mut forward = s.daemon.forward_client();
    assert!(!send_bind(&mut forward, s.host.forged_bind(b"session-3")));
    assert!(!send_bind(&mut forward, b"garbage".to_vec()));
    assert_eq!(list(&mut forward).unwrap(), vec![], "not recognised");

    // Unregistered host keys get the built-in profile.unregistered: no keys.
    let mut forward = s.daemon.forward_client();
    assert!(send_bind(&mut forward, other.bind(b"session-4", true)));
    assert_eq!(list(&mut forward).unwrap(), vec![]);

    // No bind after an authentication bind.
    let mut forward = s.daemon.forward_client();
    assert!(send_bind(&mut forward, s.host.bind(b"session-5", false)));
    assert!(!send_bind(&mut forward, s.host.bind(b"session-6", true)));

    // At most 16 session ids per connection.
    let mut local = s.daemon.local_client();
    for i in 0..16u8 {
        assert!(send_bind(&mut local, other.bind(&[b's', i], true)), "bind {i}");
    }
    assert!(!send_bind(&mut local, other.bind(b"one too many", true)));
    // Local binds never select a server: all keys stay visible.
    assert_eq!(list(&mut local).unwrap().len(), 2);

    s.daemon.wait_for_audit_all(&[r#""server":"buildserver""#, r#""event":"hop""#]);
}

/// A host with a valid server bind but no `[server.*]` entry gets the built-in
/// `profile.unregistered` and does not see the bridge: `query` and our extensions are
/// answered like unknown extensions by an agent without the bridge. Every audit event
/// names it the same way, with its host key.
#[test]
fn unregistered_hosts_get_nothing_and_do_not_see_the_bridge() {
    let s = setup();
    fake_gpg_agent(&s.dir.path().join("gpg-agent.sock"));
    let other = Host::new();
    let mut forward = s.daemon.forward_client();
    assert!(send_bind(&mut forward, other.bind(b"session-unpinned", true)));
    // No keys, not even public ones.
    assert_eq!(list(&mut forward).unwrap(), vec![]);
    assert_eq!(forward.request(&sign_request(&s.a.key.key_blob)).unwrap(), Message::Failure);
    // The same answers as OpenSSH's ssh-agent gives for extensions it does not know.
    assert_eq!(extension(&mut forward, ext::QUERY, &[]), ExtensionReply::Failure);
    assert!(forward.query_extensions().unwrap().is_empty());
    assert_eq!(
        extension(&mut forward, ext::GIT_CREDENTIAL, &git_get("git.example.com", "x/y")),
        ExtensionReply::Failure
    );
    assert_eq!(
        extension(&mut forward, ext::GPG_AGENT, &GpgRequest::Open.encode().unwrap()),
        ExtensionReply::Failure
    );
    assert_eq!(extension(&mut forward, "unknown@example.org", &[]), ExtensionReply::Failure);
    assert!(!s.b.messages().iter().any(|m| matches!(m, Message::SignRequest { .. })));
    assert!(!s.a.messages().iter().any(|m| matches!(m, Message::SignRequest { .. })));

    // Locally, the audit log says who and why.
    let fingerprint = other.fingerprint();
    let label = format!("unregistered host {fingerprint}");
    s.daemon
        .wait_for_audit_all(&[r#""event":"sign""#, r#""reason":"unknown extension on the forward socket""#]);
    let events: Vec<serde_json::Value> =
        s.daemon.audit_text().lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert!(
        events.iter().any(|e| e["event"] == "server"
            && e["server"].is_null()
            && e["host_key"] == fingerprint.as_str()
            && e["profile"] == "unregistered"),
        "{events:#?}"
    );
    let labelled: Vec<_> = events
        .iter()
        .filter(|e| ["sign", "git", "gpg", "refused"].contains(&e["event"].as_str().unwrap()))
        .collect();
    assert!(labelled.len() >= 6, "{events:#?}");
    for event in labelled {
        assert_eq!(event["server"], label.as_str(), "{event}");
    }
    let reasons = refusals(&s.daemon, &label);
    let hidden = "the host is not registered (no [server.*] entry for its host key)";
    assert_eq!(reasons.iter().filter(|reason| *reason == hidden).count(), 4, "{reasons:?}");
    assert!(!events.iter().any(|e| e["event"] == "git" || e["event"] == "gpg"), "never reached");
}

/// `[profile.unregistered]` overrides single fields: keys may be shown, `confirm`
/// stays "always" (a dialog for every signature) unless set, and a duration remembers
/// the answer per host key. Tokens and gpg stay hidden.
#[test]
fn unregistered_profile_overrides_ask_per_host_key() {
    let dir_for_script = short_tempdir();
    let prompts = dir_for_script.path().join("prompts");
    let askpass = dir_for_script.path().join("askpass");
    script(&askpass, &format!("printf '%s\\n--\\n' \"$1\" >> {}\nexit 0", prompts.display()));
    let env = [("DISPLAY", ":0"), ("SSH_ASKPASS", askpass.to_str().unwrap())];
    let dialogs = || std::fs::read_to_string(&prompts).unwrap_or_default().matches("\n--\n").count();
    let signed = |forward: &mut credential_bridge_proto::agent::AgentClient<UnixStream>,
                  agent: &FakeAgent| {
        forward.request(&sign_request(&agent.key.key_blob)).unwrap()
            == Message::SignResponse { signature: agent.signature.clone() }
    };

    // keys written, confirm not: a dialog for every signature, nothing remembered.
    let config = CONFIG.replace(
        "[server.buildserver]",
        "[profile.unregistered]\nssh = { keys = [\"a\"] }\n\n[server.buildserver]",
    );
    let s = setup_with(&config, &env);
    let host = Host::new();
    let mut forward = s.daemon.forward_client();
    assert!(send_bind(&mut forward, host.bind(b"session-1", true)));
    assert_eq!(list(&mut forward).unwrap(), vec![s.a.key.clone()]);
    assert!(signed(&mut forward, &s.a), "{}", s.daemon.log_text());
    assert!(signed(&mut forward, &s.a));
    assert_eq!(dialogs(), 2);
    assert!(std::fs::read_to_string(&prompts).unwrap().contains("This answer is not remembered."));
    assert_eq!(extension(&mut forward, ext::QUERY, &[]), ExtensionReply::Failure, "still hidden");
    drop(s);
    std::fs::remove_file(&prompts).unwrap();

    // confirm = "8h": remembered per host key.
    let config = CONFIG.replace(
        "[server.buildserver]",
        "[profile.unregistered]\nssh = { keys = [\"a\"], confirm = \"8h\" }\n\n[server.buildserver]",
    );
    let s = setup_with(&config, &env);
    for session in [b"session-a".as_slice(), b"session-b"] {
        let mut forward = s.daemon.forward_client();
        assert!(send_bind(&mut forward, host.bind(session, true)));
        assert!(signed(&mut forward, &s.a), "{}", s.daemon.log_text());
    }
    assert_eq!(dialogs(), 1, "the same host key: asked once");
    let mut forward = s.daemon.forward_client();
    assert!(send_bind(&mut forward, Host::new().bind(b"session-c", true)));
    assert!(signed(&mut forward, &s.a));
    assert_eq!(dialogs(), 2, "another host key: asked again");
}

#[test]
fn only_a_valid_first_bind_selects_the_server() {
    let s = setup();
    let pinned = |forward: &mut credential_bridge_proto::agent::AgentClient<UnixStream>| {
        list(forward).unwrap() == vec![s.b.key.clone()]
    };

    // A refused bind first (here: forged), then the pinned server's genuine bind, as a
    // server would replay it after making the client's own bind fail: still no server.
    let mut forward = s.daemon.forward_client();
    assert!(!send_bind(&mut forward, s.host.forged_bind(b"session-a")));
    assert!(send_bind(&mut forward, s.host.bind(b"session-b", true)), "accepted as a hop");
    assert_eq!(list(&mut forward).unwrap(), vec![], "not recognised: nothing");
    // The server sees no bridge; the reason is only in the local audit log.
    assert_eq!(
        extension(&mut forward, ext::GIT_CREDENTIAL, &git_get("git.example.com", "x/y")),
        ExtensionReply::Failure
    );
    let label = "unrecognised host (session-bind refused or not first)";
    // The forged bind's refusal carries the label as well; wait for the git refusal.
    s.daemon.wait_for_audit_all(&[label, "the session-bind was refused or not the first message"]);
    let reasons = refusals(&s.daemon, label);
    assert!(
        reasons
            .iter()
            .any(|reason| reason.contains("refused or not the first message")
                && !reason.contains("OpenSSH 8.9")),
        "{reasons:?}"
    );

    // Undecodable binds and other messages first: the same.
    for first in [
        Message::Extension { name: ext::SESSION_BIND.into(), contents: b"garbage".to_vec() },
        Message::RequestIdentities,
        Message::Extension { name: ext::QUERY.into(), contents: vec![] },
        Message::Other { msg_type: 200, body: vec![] },
        // A truncated sign request: undecodable.
        Message::Other { msg_type: 13, body: vec![1] },
    ] {
        let mut forward = s.daemon.forward_client();
        forward.request(&first).unwrap();
        assert!(send_bind(&mut forward, s.host.bind(b"session-c", true)));
        assert!(!pinned(&mut forward), "{first:?} came first");
    }

    // A host certificate of the pinned key selects the server (fix for servers with
    // host certificates); the certificate is replayed unchanged.
    let mut forward = s.daemon.forward_client();
    let cert_bind = s.host.cert_bind(b"session-cert", true);
    assert!(send_bind(&mut forward, cert_bind.clone()));
    assert!(pinned(&mut forward));
    assert!(s.b.messages().contains(&common::bind_message(cert_bind)));
}

/// The `server` audit events, in order.
fn server_events(daemon: &Daemon) -> Vec<serde_json::Value> {
    daemon
        .audit_text()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|event| event["event"] == "server")
        .collect()
}

/// Writes a known_hosts file by renaming a new one into place, as ssh and
/// `ssh-keygen -R` replace it.
fn write_known_hosts(path: &Path, text: &str) {
    let temp = path.with_extension("new");
    std::fs::write(&temp, text).unwrap();
    std::fs::rename(&temp, path).unwrap();
}

/// A server with `known_host` follows the known_hosts file: its keys select it (also
/// inside a host certificate), a rotated key is picked up without a reload, and a key
/// that two servers have selects neither.
#[test]
fn known_hosts_servers_follow_the_file() {
    let config = CONFIG.replace(
        "[server.buildserver]\nhost_keys = [\"HOST_KEY\"]\n",
        "[server.buildserver]\nknown_host = \"[build.example]:2222\"\nknown_hosts_files = [\"{dir}/known_hosts\"]\n\
         profile = \"build\"\n[server.alias]\nknown_host = \"10.0.0.7\"\nknown_hosts_files = [\"{dir}/known_hosts\"]\nprofile = \"build\"\n\
         [server.pinned]\nhost_keys = [\"HOST_KEY\"]\n",
    );
    let s = setup_with(&config, &[]);
    let known_hosts = s.dir.path().join("known_hosts");
    let (rotated, shared) = (Host::new(), Host::new());
    let connect = |host: &Host, session: &[u8], cert: bool| {
        let mut forward = s.daemon.forward_client();
        let bind = if cert { host.cert_bind(session, true) } else { host.bind(session, true) };
        assert!(send_bind(&mut forward, bind));
        let keys = list(&mut forward).unwrap();
        keys == vec![s.b.key.clone()]
    };
    let last_server = |count: usize| {
        assert!(eventually(|| server_events(&s.daemon).len() >= count), "{}", s.daemon.audit_text());
        server_events(&s.daemon)[count - 1].clone()
    };

    // Pinned keys keep working next to followed ones.
    assert!(connect(&s.host, b"session-pinned", false));
    let event = last_server(1);
    assert_eq!((event["server"].as_str(), event["source"].as_str()), (Some("pinned"), Some("pinned")));

    // Not yet in known_hosts: unregistered. Once ssh has stored it: recognised, no reload.
    assert!(!connect(&rotated, b"session-1", false));
    assert!(last_server(2)["server"].is_null());
    write_known_hosts(&known_hosts, &format!("[build.example]:2222 {}\n", rotated.openssh()));
    assert!(connect(&rotated, b"session-2", false));
    let event = last_server(3);
    assert_eq!(
        (event["server"].as_str(), event["source"].as_str()),
        (Some("buildserver"), Some("known_hosts"))
    );
    assert_eq!(event["host_key"], rotated.fingerprint().as_str());
    // A host certificate counts by its embedded key.
    assert!(connect(&rotated, b"session-3", true));
    assert_eq!(last_server(4)["server"], "buildserver");

    // One key under both servers' names: neither gets anything.
    write_known_hosts(
        &known_hosts,
        &format!(
            "[build.example]:2222 {}\n[build.example]:2222,10.0.0.7 {}\n",
            rotated.openssh(),
            shared.openssh()
        ),
    );
    assert!(!connect(&shared, b"session-4", false));
    let event = last_server(5);
    assert!(event["server"].is_null(), "{event}");
    assert_eq!(event["ambiguous"], serde_json::json!(["alias", "buildserver"]));
    assert_eq!(event["profile"], "unregistered");
    assert!(
        s.daemon.log_text().contains("belongs to servers alias and buildserver"),
        "{}",
        s.daemon.log_text()
    );

    // The server replaced its key (known_hosts no longer lists the old one): the old key
    // is an unregistered host from the next miss on.
    write_known_hosts(&known_hosts, &format!("[build.example]:2222 {}\n", shared.openssh()));
    assert!(connect(&shared, b"session-5", false));
    assert_eq!(last_server(6)["server"], "buildserver");
    assert!(!connect(&rotated, b"session-6", false));
    assert!(last_server(7)["server"].is_null());
}

/// OpenSSH 8.2 to 8.8 forward the agent but send no session-bind, so the first message
/// on such a connection comes from the server, which could replay a genuine bind of
/// another configured server. A bind selects the server only for a local ssh client
/// verified as OpenSSH 8.9 or later.
#[test]
fn only_a_verified_local_client_lets_a_bind_select_the_server() {
    let s = setup();
    for (who, mut forward) in [
        ("the test process (not OpenSSH)", common::client(&s.daemon.forward)),
        ("OpenSSH 8.8", common::ssh_client(common::FAKE_SSH_OLD, &s.daemon.forward)),
    ] {
        // The pinned server's genuine forwarding bind as the first message: accepted,
        // replayed upstream, but only a hop.
        assert!(send_bind(&mut forward, s.host.bind(b"session-old", true)), "{who}");
        assert_eq!(list(&mut forward).unwrap(), vec![], "{who}: nothing");
        assert_eq!(forward.request(&sign_request(&s.b.key.key_blob)).unwrap(), Message::Failure, "{who}");
        // No bridge to be seen; the reason is in the local audit log.
        assert_eq!(extension(&mut forward, ext::QUERY, &[]), ExtensionReply::Failure, "{who}");
        assert_eq!(
            extension(&mut forward, ext::GIT_CREDENTIAL, &git_get("git.example.com", "x/y")),
            ExtensionReply::Failure,
            "{who}"
        );
        assert_eq!(
            extension(&mut forward, ext::GPG_AGENT, &GpgRequest::Open.encode().unwrap()),
            ExtensionReply::Failure,
            "{who}"
        );
    }
    let label = "unrecognised host (local ssh client not verified as OpenSSH 8.9 or later)";
    let reason = "the local ssh client is not OpenSSH 8.9 or later, so the server is not recognised";
    // The audit log is written on a thread of its own: wait for every refusal, not the
    // first line with the label.
    let mut reasons = Vec::new();
    let all = eventually(|| {
        reasons = refusals(&s.daemon, label);
        reasons.iter().filter(|r| *r == reason).count() >= 6
    });
    assert!(all, "{reasons:?}");
    // The same bind through a verified client selects the server.
    let mut forward = s.daemon.forward_client();
    assert!(send_bind(&mut forward, s.host.bind(b"session-new", true)));
    assert_eq!(list(&mut forward).unwrap(), vec![s.b.key.clone()]);

    let audit = s.daemon.wait_for_audit_all(&[
        r#""client":"not verified as OpenSSH 8.9 or later: OpenSSH 8.8 sends no session-bind""#,
        r#""client":"OpenSSH 9.9""#,
        r#""server":"buildserver""#,
    ]);
    assert_eq!(audit.matches(r#""server_recognition":false"#).count(), 2, "{audit}");
}

#[test]
fn refused_binds_reach_the_upstreams() {
    let s = setup();
    for role in ["local", "forward"] {
        s.a.clear();
        // On the forward socket the pinned server, so that the key list reaches upstreams.
        let mut client =
            if role == "local" { s.daemon.local_client() } else { server_client(&s, b"session-r") };
        // Refused before any upstream connection exists: replayed when one is opened.
        assert!(!send_bind(&mut client, b"garbage".to_vec()));
        assert!(list(&mut client).is_some());
        let garbage = common::bind_message(b"garbage".to_vec());
        let seen = s.a.messages();
        let bind_at = seen.iter().position(|m| *m == garbage).unwrap_or_else(|| panic!("{role}: {seen:?}"));
        assert!(bind_at < seen.iter().position(|m| *m == Message::RequestIdentities).unwrap());
        // Refused with an open upstream connection: replayed now. The upstream accepts it
        // (the fake agent answers SUCCESS) but the proxy still refuses it.
        let forged = s.host.forged_bind(b"session-x");
        assert!(!send_bind(&mut client, forged.clone()));
        assert!(s.a.messages().contains(&common::bind_message(forged)), "{role}");
    }
    // Only session-binds: nothing else was sent but identity lists.
    assert!(s.a.messages().iter().all(|m| match m {
        Message::RequestIdentities => true,
        Message::Extension { name, .. } => name == ext::SESSION_BIND,
        _ => false,
    }));
}

#[test]
fn git_extension_end_to_end() {
    let s = setup();

    // No bind: no tokens, and no sign of the bridge.
    let mut forward = s.daemon.forward_client();
    assert_eq!(
        extension(&mut forward, ext::GIT_CREDENTIAL, &git_get("git.example.com", "x/y.git")),
        ExtensionReply::Failure
    );

    // Pinned server: helper source through the vault worker.
    let mut forward = s.daemon.forward_client();
    assert!(send_bind(&mut forward, s.host.bind(b"session-git", true)));
    let GitReply::Credential(credential) =
        git_reply(extension(&mut forward, ext::GIT_CREDENTIAL, &git_get("git.example.com", "x/y.git")))
    else {
        panic!("no credential from the helper:\n{}", s.daemon.log_text())
    };
    assert_eq!(credential.username.as_deref(), Some("helper-user"));
    assert_eq!(credential.password.as_ref().map(|p| p.expose().to_owned()).as_deref(), Some("helper-pass"));

    // Forgejo token through the sandboxed git worker, secret via the vault worker.
    let reply = git_reply(extension(&mut forward, ext::GIT_CREDENTIAL, &git_get("git.example.org", "o/r")));
    let GitReply::Credential(credential) = reply else {
        panic!("no forgejo token: {reply:?}\n{}", s.daemon.log_text())
    };
    assert_eq!(credential.username.as_deref(), Some("token"));
    assert_eq!(credential.password.as_ref().map(|p| p.expose().to_owned()).as_deref(), Some("forgejo-token"));

    // No rule: no match; erase: erased.
    assert_eq!(
        git_reply(extension(&mut forward, ext::GIT_CREDENTIAL, &git_get("other.example.net", "a/b"))),
        GitReply::NoMatch
    );
    let erase = GitRequest {
        action: GitAction::Erase,
        credential: Credential {
            protocol: Some("https".into()),
            host: Some("git.example.org".into()),
            path: Some("o/r".into()),
            ..Credential::default()
        },
    };
    assert_eq!(
        git_reply(extension(&mut forward, ext::GIT_CREDENTIAL, &erase.encode().unwrap())),
        GitReply::Erased
    );

    // Unknown extension versions are refused as unknown extensions.
    assert_eq!(
        extension(&mut forward, ext::GIT_CREDENTIAL, &[9, 0, 0, 0, 0, 0]),
        ExtensionReply::ExtensionFailure
    );

    // A hop does not get tokens (hops.git = false); a registered server is told why.
    assert!(send_bind(&mut forward, Host::new().bind(b"hop", true)));
    assert_eq!(
        git_reply(extension(&mut forward, ext::GIT_CREDENTIAL, &git_get("git.example.com", "x/y"))),
        GitReply::Denied("git from a hop is not allowed (hops.git)".to_owned())
    );

    // The last request (the hop) is audited last; wait for it.
    let audit = s.daemon.wait_for_audit(r#""outcome":"denied: git from a hop is not allowed (hops.git)""#);
    assert!(audit.contains(r#""event":"git""#));
    assert!(!audit.contains("forgejo-token") && !audit.contains("helper-pass"), "{audit}");
    assert!(!s.daemon.log_text().contains("forgejo-token"));
}

/// A reload reaches open forwarded connections: a changed source applies to the next
/// request; a changed profile refuses it and ends the connection.
#[test]
fn open_connections_follow_a_reload_or_end() {
    let s = setup();
    let mut forward = server_client(&s, b"session-reload");
    let token = |forward: &mut credential_bridge_proto::agent::AgentClient<UnixStream>| match git_reply(
        extension(forward, ext::GIT_CREDENTIAL, &git_get("git.example.org", "o/r")),
    ) {
        GitReply::Credential(credential) => credential.password.map(|p| p.expose().to_owned()),
        other => panic!("no token: {other:?}\n{}", s.daemon.log_text()),
    };
    assert_eq!(token(&mut forward).as_deref(), Some("forgejo-token"));

    let text = std::fs::read_to_string(&s.daemon.config).unwrap();
    std::fs::write(&s.daemon.config, text.replace("printf forgejo-token", "printf rotated-token")).unwrap();
    assert!(matches!(control(&s.daemon, &control::Request::Reload), control::Response::Reloaded));
    assert_eq!(token(&mut forward).as_deref(), Some("rotated-token"));

    std::fs::write(&s.daemon.config, text.replace("keys = [\"b\"]", "keys = [\"a\"]")).unwrap();
    assert!(matches!(control(&s.daemon, &control::Request::Reload), control::Response::Reloaded));
    assert_eq!(
        extension(&mut forward, ext::GIT_CREDENTIAL, &git_get("git.example.org", "o/r")),
        ExtensionReply::Failure
    );
    assert!(forward.request(&Message::RequestIdentities).is_err(), "the connection stays open");
    assert!(eventually(|| refusals(&s.daemon, "buildserver")
        .contains(&"the server's configuration changed; reconnect".to_owned())));
    // A new connection gets the new profile.
    let mut forward = server_client(&s, b"session-reload-2");
    assert_eq!(list(&mut forward).unwrap(), vec![s.a.key.clone()]);
}

#[test]
fn lock_and_unlock_the_proxy() {
    let s = setup();
    let mut local = s.daemon.local_client();
    let mut forward = s.daemon.forward_client();
    let lock = Message::Lock { passphrase: SecretBytes::new(b"pw".to_vec()) };
    assert_eq!(forward.request(&lock).unwrap(), Message::Failure, "not from servers");
    assert_eq!(local.request(&lock).unwrap(), Message::Success { contents: vec![] });
    assert_eq!(local.request(&lock).unwrap(), Message::Failure, "already locked");
    assert_eq!(list(&mut local).unwrap(), vec![]);
    assert_eq!(list(&mut forward).unwrap(), vec![]);
    assert_eq!(local.request(&sign_request(&s.a.key.key_blob)).unwrap(), Message::Failure);
    let wrong = Message::Unlock { passphrase: SecretBytes::new(b"nope".to_vec()) };
    assert_eq!(local.request(&wrong).unwrap(), Message::Failure);
    let unlock = Message::Unlock { passphrase: SecretBytes::new(b"pw".to_vec()) };
    assert_eq!(local.request(&unlock).unwrap(), Message::Success { contents: vec![] });
    assert_eq!(list(&mut local).unwrap().len(), 2);
}

/// Tokens cached in the git worker go with the lock of their vault (only those), with
/// `vault lock --all` and with the proxy lock; the next request reads the vault again.
#[test]
fn locks_drop_the_cached_tokens() {
    let config = CONFIG.replace("cmd:printf forgejo-token", "cmd:cat {dir}/forgejo-token").replace(
        "[profile.build]",
        "[source.gitlab]\ntype = \"gitlab\"\nhost = \"gitlab.example.net\"\ntoken = \"pass://gitlab\"\n\n\
         [[profile.build.git]]\nurl = \"https://gitlab.example.net/*\"\nsource = \"gitlab\"\n\n[profile.build]",
    );
    let bin = short_tempdir();
    let gitlab_token = bin.path().join("gitlab-token");
    script(&bin.path().join("pass"), &format!("cat {}", gitlab_token.display()));
    let path = format!("{}:{}", bin.path().display(), std::env::var("PATH").unwrap_or_default());
    let s = setup_with(&config, &[("PATH", &path)]);
    let forgejo_token = s.dir.path().join("forgejo-token");
    let write = |n: u32| {
        std::fs::write(&forgejo_token, format!("forgejo-{n}")).unwrap();
        std::fs::write(&gitlab_token, format!("gitlab-{n}\n")).unwrap();
    };
    let mut forward = server_client(&s, b"session-tokens");
    let tokens = |forward: &mut credential_bridge_proto::agent::AgentClient<UnixStream>| {
        ["git.example.org", "gitlab.example.net"].map(|host| {
            match git_reply(extension(forward, ext::GIT_CREDENTIAL, &git_get(host, "o/r"))) {
                GitReply::Credential(credential) => credential.password.unwrap().expose().to_owned(),
                other => panic!("no token from {host}: {other:?}\n{}", s.daemon.log_text()),
            }
        })
    };
    let lock = |vault: Option<&str>| {
        let request = control::Request::Lock { vault: vault.map(str::to_owned) };
        assert_eq!(control(&s.daemon, &request), control::Response::Locked);
    };

    // Nothing cached yet: the lock does not start the git worker.
    lock(None);
    let git_pid = || {
        let control::Response::Status(status) = control(&s.daemon, &control::Request::Status) else {
            panic!()
        };
        status.workers.iter().find(|w| w.kind == credential_bridge_proto::ipc::WorkerKind::Git).unwrap().pid
    };
    assert_eq!(git_pid(), None);

    write(1);
    assert_eq!(tokens(&mut forward), ["forgejo-1", "gitlab-1"]);
    write(2);
    assert_eq!(tokens(&mut forward), ["forgejo-1", "gitlab-1"], "cached");

    // One vault: only the tokens of its sources.
    lock(Some("pass"));
    assert_eq!(tokens(&mut forward), ["forgejo-1", "gitlab-2"]);
    lock(Some("cmd"));
    assert_eq!(tokens(&mut forward), ["forgejo-2", "gitlab-2"]);

    // All vaults.
    write(3);
    lock(None);
    assert_eq!(tokens(&mut forward), ["forgejo-3", "gitlab-3"]);

    // The proxy lock (ssh-add -x): no tokens while locked, read again after unlock.
    write(4);
    let mut local = s.daemon.local_client();
    let passphrase = SecretBytes::new(b"pw".to_vec());
    let locked = Message::Lock { passphrase: passphrase.clone() };
    assert_eq!(local.request(&locked).unwrap(), Message::Success { contents: vec![] });
    assert_eq!(
        extension(&mut forward, ext::GIT_CREDENTIAL, &git_get("git.example.org", "o/r")),
        ExtensionReply::Failure
    );
    let unlock = Message::Unlock { passphrase };
    assert_eq!(local.request(&unlock).unwrap(), Message::Success { contents: vec![] });
    assert_eq!(tokens(&mut forward), ["forgejo-4", "gitlab-4"]);
}

/// A token whose making overlaps a lock is never cached: with `ssh-add -x` it is not
/// handed out either, with `vault lock` it is. The vault (`cmd:` reading a FIFO) answers
/// only once the test writes to it, so the lock happens while the token is being made.
#[test]
fn tokens_made_during_a_lock_are_not_kept() {
    let config = CONFIG.replace("cmd:printf forgejo-token", "cmd:cat {dir}/forgejo-token");
    let s = setup_with(&config, &[]);
    let fifo = s.dir.path().join("forgejo-token");
    let status = std::process::Command::new("mkfifo").arg(&fifo).status().unwrap();
    assert!(status.success());
    // Opening the FIFO waits for the vault's `cat`: the request is being served.
    let open_vault = || std::fs::OpenOptions::new().write(true).open(&fifo).unwrap();
    let answer_vault = |token: &str| open_vault().write_all(token.as_bytes()).unwrap();
    let mut forward = server_client(&s, b"session-lock-in-flight");
    let mut local = s.daemon.local_client();
    let passphrase = SecretBytes::new(b"pw".to_vec());
    let get = |forward: &mut credential_bridge_proto::agent::AgentClient<UnixStream>| {
        git_reply(extension(forward, ext::GIT_CREDENTIAL, &git_get("git.example.org", "o/r")))
    };
    let token = |reply: GitReply| match reply {
        GitReply::Credential(credential) => credential.password.unwrap().expose().to_owned(),
        other => panic!("no token: {other:?}\n{}", s.daemon.log_text()),
    };

    // ssh-add -x while the token is being made: refused, and the vault is read again.
    let reply = std::thread::scope(|scope| {
        let request = scope.spawn(|| get(&mut forward));
        let mut vault = open_vault();
        let locked = Message::Lock { passphrase: passphrase.clone() };
        assert_eq!(local.request(&locked).unwrap(), Message::Success { contents: vec![] });
        vault.write_all(b"forgejo-1").unwrap();
        drop(vault);
        request.join().unwrap()
    });
    assert_eq!(reply, GitReply::Denied("proxy is locked".to_owned()));
    let unlock = Message::Unlock { passphrase };
    assert_eq!(local.request(&unlock).unwrap(), Message::Success { contents: vec![] });
    let reply = std::thread::scope(|scope| {
        let request = scope.spawn(|| get(&mut forward));
        answer_vault("forgejo-2");
        request.join().unwrap()
    });
    assert_eq!(token(reply), "forgejo-2", "not cached");

    // vault lock while the token is being made: handed out, not cached.
    let lock = control::Request::Lock { vault: Some("cmd".to_owned()) };
    assert_eq!(control(&s.daemon, &lock), control::Response::Locked);
    let reply = std::thread::scope(|scope| {
        let request = scope.spawn(|| get(&mut forward));
        let mut vault = open_vault();
        assert_eq!(control(&s.daemon, &lock), control::Response::Locked);
        vault.write_all(b"forgejo-3").unwrap();
        drop(vault);
        request.join().unwrap()
    });
    assert_eq!(token(reply), "forgejo-3");
    let reply = std::thread::scope(|scope| {
        let request = scope.spawn(|| get(&mut forward));
        answer_vault("forgejo-4");
        request.join().unwrap()
    });
    assert_eq!(token(reply), "forgejo-4", "not cached");
}

/// A reload drops the cached tokens of every source it removed or changed (renamed, moved
/// to another vault); unchanged sources keep theirs. Renaming or moving back would
/// otherwise find the old token again.
#[test]
fn reloads_drop_the_tokens_of_changed_sources() {
    let config = CONFIG.replace("cmd:printf forgejo-token", "cmd:cat {dir}/forgejo-token").replace(
        "[profile.build]",
        "[source.gitlab]\ntype = \"gitlab\"\nhost = \"gitlab.example.net\"\ntoken = \"pass://gitlab\"\n\n\
         [[profile.build.git]]\nurl = \"https://gitlab.example.net/*\"\nsource = \"gitlab\"\n\n[profile.build]",
    );
    let bin = short_tempdir();
    // `pass show [--noparsing] NAME` prints the file NAME.
    script(&bin.path().join("pass"), &format!("for a; do name=$a; done\ncat {}/$name", bin.path().display()));
    let path = format!("{}:{}", bin.path().display(), std::env::var("PATH").unwrap_or_default());
    let s = setup_with(&config, &[("PATH", &path)]);
    let write = |n: u32| {
        std::fs::write(s.dir.path().join("forgejo-token"), format!("forgejo-{n}")).unwrap();
        std::fs::write(bin.path().join("forgejo"), format!("pass-forgejo-{n}\n")).unwrap();
        std::fs::write(bin.path().join("gitlab"), format!("gitlab-{n}\n")).unwrap();
    };
    let mut forward = server_client(&s, b"session-reload-tokens");
    let mut token =
        |host: &str| match git_reply(extension(&mut forward, ext::GIT_CREDENTIAL, &git_get(host, "o/r"))) {
            GitReply::Credential(credential) => Some(credential.password.unwrap().expose().to_owned()),
            GitReply::NoMatch => None,
            other => panic!("no token from {host}: {other:?}\n{}", s.daemon.log_text()),
        };
    let mut tokens = || ["git.example.org", "gitlab.example.net"].map(&mut token);
    let original = std::fs::read_to_string(&s.daemon.config).unwrap();
    let reload = |text: &str| {
        std::fs::write(&s.daemon.config, text).unwrap();
        assert_eq!(control(&s.daemon, &control::Request::Reload), control::Response::Reloaded);
    };
    let lock = |vault: &str| {
        let request = control::Request::Lock { vault: Some(vault.to_owned()) };
        assert_eq!(control(&s.daemon, &request), control::Response::Locked);
    };
    let some = |forgejo: &str, gitlab: &str| [Some(forgejo.to_owned()), Some(gitlab.to_owned())];

    write(1);
    assert_eq!(tokens(), some("forgejo-1", "gitlab-1"));
    write(2);

    // Unchanged sources keep their tokens, also when other parts change.
    reload(&format!(
        "{original}\n[source.unused]\ntype = \"gitlab\"\nhost = \"x.example\"\ntoken = \"pass://unused\"\n"
    ));
    reload(&original);
    assert_eq!(tokens(), some("forgejo-1", "gitlab-1"), "still cached");

    // A rename drops the old name's tokens: renaming back reads the vault again.
    let renamed = original
        .replace("[source.gitlab]", "[source.lab]")
        .replace("source = \"gitlab\"", "source = \"lab\"");
    reload(&renamed);
    assert_eq!(tokens(), some("forgejo-1", "gitlab-2"));
    write(3);
    reload(&original);
    assert_eq!(tokens(), some("forgejo-1", "gitlab-3"), "the old name's token is gone");

    // A move to another vault drops the old tokens; locks follow the new vault.
    let moved =
        original.replace(&format!("cmd:cat {}/forgejo-token", s.dir.path().display()), "pass://forgejo");
    assert_ne!(moved, original);
    reload(&moved);
    assert_eq!(tokens(), some("pass-forgejo-3", "gitlab-3"));
    write(4);
    lock("cmd");
    assert_eq!(tokens(), some("pass-forgejo-3", "gitlab-3"), "no source in cmd any more");
    lock("pass");
    assert_eq!(tokens(), some("pass-forgejo-4", "gitlab-4"));
    write(5);
    reload(&original);
    assert_eq!(tokens(), some("forgejo-5", "gitlab-4"), "the old cmd token is gone");
    lock("pass");
    assert_eq!(tokens(), some("forgejo-5", "gitlab-5"), "the cmd token stays on a pass lock");

    // A removed source (through SIGHUP): adding it back reads the vault again.
    write(6);
    let removed = original
        .replace("[source.gitlab]\ntype = \"gitlab\"\nhost = \"gitlab.example.net\"\ntoken = \"pass://gitlab\"\n\n", "")
        .replace("[[profile.build.git]]\nurl = \"https://gitlab.example.net/*\"\nsource = \"gitlab\"\n\n", "");
    assert!(!removed.contains("gitlab"));
    let dropped = || {
        s.daemon
            .log_text()
            .matches("dropped cached tokens of the removed or changed sources gitlab\n")
            .count()
    };
    let before = dropped();
    std::fs::write(&s.daemon.config, &removed).unwrap();
    s.daemon.signal(rustix::process::Signal::HUP);
    assert!(eventually(|| dropped() > before), "{}", s.daemon.log_text());
    assert_eq!(tokens(), [Some("forgejo-5".to_owned()), None]);
    reload(&original);
    assert_eq!(tokens(), some("forgejo-5", "gitlab-6"));
}

/// A source with `cache = false` reads its vault for every request while a cached one
/// does not; switching `cache` by reload drops what was cached.
#[test]
fn sources_without_cache_read_the_vault_every_time() {
    let config = CONFIG
        .replace("cmd:printf forgejo-token\"", "cmd:cat {dir}/forgejo-token\"\ncache = false")
        .replace(
            "[profile.build]",
            "[source.gitlab]\ntype = \"gitlab\"\nhost = \"gitlab.example.net\"\n\
             token = \"cmd:cat {dir}/gitlab-token\"\n\n\
             [[profile.build.git]]\nurl = \"https://gitlab.example.net/*\"\nsource = \"gitlab\"\n\n[profile.build]",
        );
    let s = setup_with(&config, &[]);
    let write = |n: u32| {
        std::fs::write(s.dir.path().join("forgejo-token"), format!("forgejo-{n}")).unwrap();
        std::fs::write(s.dir.path().join("gitlab-token"), format!("gitlab-{n}")).unwrap();
    };
    let mut forward = server_client(&s, b"session-no-cache");
    let mut tokens = || {
        ["git.example.org", "gitlab.example.net"].map(|host| {
            match git_reply(extension(&mut forward, ext::GIT_CREDENTIAL, &git_get(host, "o/r"))) {
                GitReply::Credential(credential) => credential.password.unwrap().expose().to_owned(),
                other => panic!("no token from {host}: {other:?}\n{}", s.daemon.log_text()),
            }
        })
    };
    let original = std::fs::read_to_string(&s.daemon.config).unwrap();
    let reload = |text: &str| {
        std::fs::write(&s.daemon.config, text).unwrap();
        assert_eq!(control(&s.daemon, &control::Request::Reload), control::Response::Reloaded);
    };

    write(1);
    assert_eq!(tokens(), ["forgejo-1", "gitlab-1"]);
    write(2);
    assert_eq!(tokens(), ["forgejo-2", "gitlab-1"], "only gitlab is cached");
    write(3);
    assert_eq!(tokens(), ["forgejo-3", "gitlab-1"]);

    // cache = true for forgejo, false for gitlab: gitlab's cached token goes.
    let gitlab_ref = format!("token = \"cmd:cat {}/gitlab-token\"", s.dir.path().display());
    let swapped =
        original.replace("cache = false\n", "").replace(&gitlab_ref, &format!("{gitlab_ref}\ncache = false"));
    assert_ne!(swapped, original);
    reload(&swapped);
    assert_eq!(tokens(), ["forgejo-3", "gitlab-3"]);
    write(4);
    assert_eq!(tokens(), ["forgejo-3", "gitlab-4"], "now forgejo is cached");

    // And back: forgejo's cached token goes too.
    write(5);
    reload(&original);
    assert_eq!(tokens(), ["forgejo-5", "gitlab-5"]);
    write(6);
    assert_eq!(tokens(), ["forgejo-6", "gitlab-5"]);
}

/// Sends one control request.
fn control(daemon: &Daemon, request: &control::Request) -> control::Response {
    let mut stream = UnixStream::connect(&daemon.control).unwrap();
    credential_bridge_proto::ipc::write_frame(&mut stream, request).unwrap();
    credential_bridge_proto::ipc::read_frame(&mut stream).unwrap().unwrap()
}

#[test]
fn control_socket_and_reload() {
    let s = setup();
    assert!(matches!(control(&s.daemon, &control::Request::Ping), control::Response::Pong { .. }));
    let control::Response::Status(status) = control(&s.daemon, &control::Request::Status) else { panic!() };
    assert_eq!(status.upstreams.len(), 2);
    assert!(status.upstreams.iter().all(|u| u.reachable && u.keys == Some(1)));
    assert!(!status.locked);

    let control::Response::Keys(keys) =
        control(&s.daemon, &control::Request::Keys { server: Some("buildserver".into()) })
    else {
        panic!()
    };
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].upstream, "b");
    assert!(keys[0].fingerprint.starts_with("ssh-ed25519 SHA256:"));
    assert!(matches!(
        control(&s.daemon, &control::Request::Keys { server: Some("nope".into()) }),
        control::Response::Error(_)
    ));

    let control::Response::Token(result) = control(
        &s.daemon,
        &control::Request::TokenTest {
            server: "buildserver".into(),
            url: "https://git.example.org/o/r".into(),
        },
    ) else {
        panic!("{}", s.daemon.log_text())
    };
    assert_eq!(result.profile, "build");
    assert_eq!(result.source.as_deref(), Some("forgejo"));
    assert_eq!(result.username.as_deref(), Some("token"));
    let control::Response::Status(status) = control(&s.daemon, &control::Request::Status) else { panic!() };
    let git =
        status.workers.iter().find(|w| w.kind == credential_bridge_proto::ipc::WorkerKind::Git).unwrap();
    assert!(git.pid.is_some(), "the git worker runs");
    eprintln!("git worker sandbox layers missing: {:?}", git.degraded);

    // Reload through ctl: an invalid file keeps the old configuration.
    let text = std::fs::read_to_string(&s.daemon.config).unwrap();
    // `None` when the connection ended: a reload that lands between the bind and the
    // list changes profile.unregistered for an already bound connection, which then
    // closes instead of answering.
    let unregistered = |s: &Setup| {
        let mut forward = s.daemon.forward_client();
        assert!(send_bind(&mut forward, Host::new().bind(b"session-reload", true)));
        list(&mut forward)
    };
    for (invalid, hint) in [
        ("version = 2\n[profile.unregistered]\nssh = { keys = [\"nope\"] }\n", "\"nope\""),
        ("version = 2\n[profile.default]\nssh = { keys = \"all\" }\n", "profile.unregistered"),
    ] {
        std::fs::write(&s.daemon.config, invalid).unwrap();
        let control::Response::Error(error) = control(&s.daemon, &control::Request::Reload) else {
            panic!("{invalid} was accepted")
        };
        assert!(error.message.contains(hint), "{}", error.message);
        assert_eq!(unregistered(&s), Some(vec![]));
    }

    // SIGHUP: profile.unregistered now shows b.
    let changed = text.replace(
        "[server.buildserver]",
        "[profile.unregistered]\nssh = { keys = [\"b\"], confirm = \"never\" }\n\n[server.buildserver]",
    );
    std::fs::write(&s.daemon.config, changed).unwrap();
    s.daemon.signal(rustix::process::Signal::HUP);
    assert!(eventually(|| unregistered(&s) == Some(vec![s.b.key.clone()])));
}

/// `SourceTest` resolves a source's references in the daemon and answers with the
/// outcome only: neither a working nor a failing secret reaches the control socket.
#[test]
fn source_test_never_returns_the_secret() {
    let config = CONFIG.replace(
        "[profile.build]",
        "[source.broken]\ntype = \"gitlab\"\nhost = \"gitlab.example.org\"\n\
         token = \"cmd:printf broken-secret; exit 3\"\n\n[profile.build]",
    );
    let s = setup_with(&config, &[]);
    let raw = |source: &str| {
        let mut stream = UnixStream::connect(&s.daemon.control).unwrap();
        let request = control::Request::SourceTest { source: source.into() };
        credential_bridge_proto::ipc::write_frame(&mut stream, &request).unwrap();
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).unwrap();
        let mut body = vec![0u8; credential_bridge_proto::ipc::frame_len(header).unwrap()];
        stream.read_exact(&mut body).unwrap();
        let text = String::from_utf8_lossy(&body).into_owned();
        let response: control::Response = credential_bridge_proto::ipc::decode_body(&body).unwrap();
        (text, response)
    };

    let (text, response) = raw("forgejo");
    let control::Response::SourceTested(checks) = response else { panic!("{text}\n{}", s.daemon.log_text()) };
    assert_eq!(checks, vec![control::SourceCheck { what: "cmd:printf forgejo-token".into(), error: None }]);
    assert!(!text.replace("printf forgejo-token", "").contains("forgejo-token"), "{text}");

    let (text, response) = raw("broken");
    let control::Response::SourceTested(checks) = response else { panic!("{text}") };
    let error = checks[0].error.as_ref().expect("a failing command fails the check");
    assert_eq!(error.kind, credential_bridge_proto::ipc::WorkerErrorKind::Upstream, "{error:?}");
    assert!(!text.replace("printf broken-secret", "").contains("broken-secret"), "{text}");

    // A helper is asked per repository: nothing to resolve ahead of a request.
    let (_, response) = raw("helper");
    assert_eq!(response, control::Response::SourceTested(vec![]));
    let (_, response) = raw("nope");
    let control::Response::Error(error) = response else { panic!("{response:?}") };
    assert!(error.message.contains("no source nope"), "{}", error.message);
}

/// Ping and Status name the sockets, the audit log and the KeePassXC files the daemon
/// uses, which stay those it started with when `[daemon]` or `[vault]` changes and the
/// configuration is reloaded.
#[test]
fn control_names_the_paths_in_use() {
    let s = setup_with(&format!("{CONFIG}\n[vault.keepassxc]\ndatabase = \"{{dir}}/db.kdbx\"\n"), &[]);
    let paths = |s: &Setup| {
        let control::Response::Pong { paths, .. } = control(&s.daemon, &control::Request::Ping) else {
            panic!()
        };
        let control::Response::Status(status) = control(&s.daemon, &control::Request::Status) else {
            panic!()
        };
        assert_eq!(status.paths, paths);
        paths
    };
    let expected = control::DaemonPaths {
        socket: s.daemon.local.display().to_string(),
        forward_socket: s.daemon.forward.display().to_string(),
        control_socket: s.daemon.control.display().to_string(),
        audit_log: s.daemon.audit.display().to_string(),
        keepassxc_database: Some(s.dir.path().join("db.kdbx").display().to_string()),
        keepassxc_key_file: None,
    };
    assert_eq!(paths(&s), expected);
    let text = std::fs::read_to_string(&s.daemon.config).unwrap();
    let moved = text.replace("/audit.log\"", "/elsewhere.log\"").replace("/db.kdbx", "/other.kdbx");
    assert_ne!(moved, text);
    std::fs::write(&s.daemon.config, moved).unwrap();
    assert_eq!(control(&s.daemon, &control::Request::Reload), control::Response::Reloaded);
    assert_eq!(paths(&s), expected, "the audit log and the database change on a restart only");
}

/// A fake gpg-agent on `path`: greeting, then fixed answers.
fn fake_gpg_agent(path: &Path) {
    let listener = UnixListener::bind(path).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            std::thread::spawn(move || {
                stream.write_all(b"OK Pleased to meet you\n").unwrap();
                let mut pending = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    let n = match stream.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    pending.extend_from_slice(&buf[..n]);
                    while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
                        let line: Vec<u8> = pending.drain(..=pos).collect();
                        let reply: &[u8] = match line.as_slice() {
                            b"GETINFO version\n" => b"D 2.4.7\nOK\n",
                            _ => b"ERR 1 unexpected\n",
                        };
                        stream.write_all(reply).unwrap();
                    }
                }
            });
        }
    });
}

fn gpg(
    client: &mut credential_bridge_proto::agent::AgentClient<UnixStream>,
    request: GpgRequest,
) -> GpgReply {
    match extension(client, ext::GPG_AGENT, &request.encode().unwrap()) {
        ExtensionReply::Success(contents) => GpgReply::decode(&contents).unwrap(),
        other => panic!("gpg extension failed: {other:?}"),
    }
}

#[test]
fn gpg_tunnel_through_the_sandboxed_worker() {
    let s = setup();
    fake_gpg_agent(&s.dir.path().join("gpg-agent.sock"));

    let mut forward = s.daemon.forward_client();
    assert_eq!(
        extension(&mut forward, ext::GPG_AGENT, &GpgRequest::Open.encode().unwrap()),
        ExtensionReply::Failure,
        "no bind, no gpg, no sign of the bridge"
    );

    let mut forward = s.daemon.forward_client();
    assert!(send_bind(&mut forward, s.host.bind(b"session-gpg", true)));
    let opened = gpg(&mut forward, GpgRequest::Open);
    assert_eq!(
        opened,
        GpgReply::Opened(b"OK Pleased to meet you\n".to_vec().into()),
        "{}",
        s.daemon.log_text()
    );
    assert_eq!(
        gpg(&mut forward, GpgRequest::Input(b"GETINFO version\n".to_vec().into())),
        GpgReply::Output(b"D 2.4.7\nOK\n".to_vec().into())
    );
    let GpgReply::Output(denied) = gpg(&mut forward, GpgRequest::Input(b"PKDECRYPT\n".to_vec().into()))
    else {
        panic!()
    };
    assert!(denied.starts_with(b"ERR 67109115"), "{}", String::from_utf8_lossy(&denied));
    assert_eq!(gpg(&mut forward, GpgRequest::Close), GpgReply::Closed);
    assert!(matches!(
        gpg(&mut forward, GpgRequest::Input(b"GETINFO version\n".to_vec().into())),
        GpgReply::Failed(_)
    ));

    s.daemon.wait_for_audit_all(&[r#""command":"PKDECRYPT""#, r#""outcome":"denied""#]);
}

#[test]
fn confirm_asks_once_and_remembers() {
    let dir_for_script = short_tempdir();
    let calls = dir_for_script.path().join("calls");
    let askpass = dir_for_script.path().join("askpass");
    script(&askpass, &format!("echo \"$SSH_ASKPASS_PROMPT\" >> {}\nexit 0", calls.display()));
    let config = CONFIG.replace("ssh = { keys = [\"b\"] }", "ssh = { keys = [\"b\"], confirm = \"1h\" }");
    let s = setup_with(&config, &[("DISPLAY", ":0"), ("SSH_ASKPASS", askpass.to_str().unwrap())]);
    let mut forward = s.daemon.forward_client();
    assert!(send_bind(&mut forward, s.host.bind(b"session-confirm", true)));
    for _ in 0..2 {
        assert_eq!(
            forward.request(&sign_request(&s.b.key.key_blob)).unwrap(),
            Message::SignResponse { signature: s.b.signature.clone() },
            "{}",
            s.daemon.log_text()
        );
    }
    assert_eq!(std::fs::read_to_string(&calls).unwrap(), "confirm\n", "one dialog, then remembered");

    // A denying helper: the signature fails and nothing reaches the upstream.
    script(&askpass, "exit 1");
    let config = CONFIG.replace("ssh = { keys = [\"b\"] }", "ssh = { keys = [\"b\"], confirm = \"1h\" }");
    let denied = setup_with(&config, &[("DISPLAY", ":0"), ("SSH_ASKPASS", askpass.to_str().unwrap())]);
    let mut forward = denied.daemon.forward_client();
    assert!(send_bind(&mut forward, denied.host.bind(b"session-deny", true)));
    assert_eq!(forward.request(&sign_request(&denied.b.key.key_blob)).unwrap(), Message::Failure);
    assert!(!denied.b.messages().iter().any(|m| matches!(m, Message::SignRequest { .. })));
    denied.daemon.wait_for_audit(r#""outcome":"denied""#);
}

/// `ssh-add -x` while the dialog is open: the allowed signature is not passed on, and the
/// approval is not remembered.
#[test]
fn a_lock_during_the_dialog_wins() {
    let dir_for_script = short_tempdir();
    let started = dir_for_script.path().join("started");
    let go = dir_for_script.path().join("go");
    let askpass = dir_for_script.path().join("askpass");
    script(
        &askpass,
        &format!(
            "echo x >> {started}\nn=0\nwhile [ ! -e {go} ] && [ $n -lt 300 ]; do sleep 0.1; n=$((n+1)); done\nrm -f {go}\nexit 0",
            started = started.display(),
            go = go.display()
        ),
    );
    let config = CONFIG.replace("ssh = { keys = [\"b\"] }", "ssh = { keys = [\"b\"], confirm = \"1h\" }");
    let s = setup_with(&config, &[("DISPLAY", ":0"), ("SSH_ASKPASS", askpass.to_str().unwrap())]);
    let mut forward = s.daemon.forward_client();
    assert!(send_bind(&mut forward, s.host.bind(b"session-lock", true)));
    let request = sign_request(&s.b.key.key_blob);
    let signing = {
        let request = request.clone();
        std::thread::spawn(move || {
            let reply = forward.request(&request).unwrap();
            (forward, reply)
        })
    };
    assert!(eventually(|| started.exists()), "no dialog: {}", s.daemon.log_text());
    let mut local = s.daemon.local_client();
    let lock = Message::Lock { passphrase: SecretBytes::new(b"pw".to_vec()) };
    assert_eq!(local.request(&lock).unwrap(), Message::Success { contents: Vec::new() });
    std::fs::write(&go, b"").unwrap();
    let (mut forward, reply) = signing.join().unwrap();
    assert_eq!(reply, Message::Failure);
    assert!(!s.b.messages().iter().any(|m| matches!(m, Message::SignRequest { .. })));

    // Unlocked again, the approval given during the lock was not remembered: a new dialog.
    let unlock = Message::Unlock { passphrase: SecretBytes::new(b"pw".to_vec()) };
    assert_eq!(local.request(&unlock).unwrap(), Message::Success { contents: Vec::new() });
    std::fs::write(&go, b"").unwrap();
    assert_eq!(
        forward.request(&request).unwrap(),
        Message::SignResponse { signature: s.b.signature.clone() }
    );
    assert_eq!(std::fs::read_to_string(&started).unwrap(), "x\nx\n", "asked again");
}

#[test]
fn confirm_separates_hops() {
    let dir_for_script = short_tempdir();
    let prompts = dir_for_script.path().join("prompts");
    let askpass = dir_for_script.path().join("askpass");
    script(&askpass, &format!("printf '%s\\n--\\n' \"$1\" >> {}\nexit 0", prompts.display()));
    let config = CONFIG
        .replace("ssh = { keys = [\"b\"] }", "ssh = { keys = [\"b\"], confirm = \"1h\" }")
        .replace("hops = { ssh = false,", "hops = { ssh = true,");
    let s = setup_with(&config, &[("DISPLAY", ":0"), ("SSH_ASKPASS", askpass.to_str().unwrap())]);
    let dialogs = || std::fs::read_to_string(&prompts).unwrap_or_default().matches("\n--\n").count();
    let signed = |forward: &mut credential_bridge_proto::agent::AgentClient<UnixStream>,
                  agent: &FakeAgent| {
        forward.request(&sign_request(&agent.key.key_blob)).unwrap()
            == Message::SignResponse { signature: agent.signature.clone() }
    };

    // The server: asked once, then remembered.
    let mut forward = s.daemon.forward_client();
    assert!(send_bind(&mut forward, s.host.bind(b"session-server", true)));
    assert!(signed(&mut forward, &s.b), "{}", s.daemon.log_text());
    assert!(signed(&mut forward, &s.b));
    assert_eq!(dialogs(), 1);
    // A hop behind it is asked about separately, and the dialog says so.
    assert!(send_bind(&mut forward, Host::new().bind(b"session-hop", true)));
    assert!(signed(&mut forward, &s.b));
    assert_eq!(dialogs(), 2);
    let text = std::fs::read_to_string(&prompts).unwrap();
    let last = text.split("\n--\n").nth(1).unwrap();
    assert!(last.contains("From: a host behind this server (hop)"), "{last}");
}

#[test]
fn token_only_mode_and_clean_exit() {
    let dir = short_tempdir();
    let config = r#"
version = 2
[daemon]
socket = "{dir}/s/agent.sock"
forward_socket = "{dir}/s/agent-forward.sock"
control_socket = "{dir}/s/control.sock"
audit_log = "{dir}/audit.log"
"#;
    let mut daemon = Daemon::start(DAEMON.as_ref(), dir.path(), config, &[]);
    assert_eq!(list(&mut daemon.local_client()).unwrap(), vec![]);
    assert_eq!(daemon.local_client().request(&sign_request(b"k")).unwrap(), Message::Failure);
    // Without [agent] nobody gets keys; a server sees an empty list.
    assert_eq!(list(&mut daemon.forward_client()).unwrap(), vec![]);
    let status = daemon.stop();
    assert!(status.success(), "{status}");
    assert!(!daemon.local.exists() && !daemon.forward.exists() && !daemon.control.exists());

    // A second daemon on the same sockets is refused while the first runs.
    let first = Daemon::start(DAEMON.as_ref(), dir.path(), config, &[]);
    let second = std::process::Command::new(env!("CARGO_BIN_EXE_credential-bridged"))
        .arg("--config")
        .arg(&first.config)
        .env("HOME", dir.path())
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("cannot listen"));
}
