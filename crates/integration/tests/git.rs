//! The server-side git helper (`credential_bridge_remote`, in-process) against the
//! real daemon (`credential-bridged`, run as a process), through a relay that plays the ssh
//! client and sends a verified forwarding session-bind first.

mod common;

use common::{binding_relay, daemon_binary, remote_helper_error, remote_helper_output};
use credential_bridge_testutil::{Daemon, FakeAgent, Host, script, short_tempdir};

/// One fake upstream, a pinned server with a git rule backed by a helper source.
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

[source.helper]
type = "helper"
helper = "{dir}/helper.sh"

[profile.build]
ssh = { keys = ["a"] }

[[profile.build.git]]
url = "https://git.example.com/*"
source = "helper"

[server.buildserver]
host_keys = ["HOST_KEY"]
profile = "build"
"#;

#[test]
fn git_invalid_requests_are_denied_with_the_reason() {
    let dir = short_tempdir();
    let _upstream = FakeAgent::spawn(dir.path().join("a.sock"), "a");
    let host = Host::new();
    script(
        &dir.path().join("helper.sh"),
        "cat >/dev/null\nif [ \"$1\" = get ]; then printf 'username=helper-user\\npassword=helper-pass\\n'; fi",
    );
    let config = CONFIG.replace("HOST_KEY", &host.openssh());
    let daemon = Daemon::start(&daemon_binary(), dir.path(), &config, &[]);
    let relay_dir = short_tempdir();
    let relay = binding_relay(relay_dir.path(), &daemon, host.bind(b"session-invalid", true));

    let message =
        remote_helper_error(&relay, "protocol=https\nhost=git.example.com\npath=team-a/../team-b/repo\n\n");
    assert_eq!(message, "credential-bridge: invalid request: the path has an empty, `.` or `..` segment");

    let message = remote_helper_error(&relay, "protocol=https\npath=team-a/repo\n\n");
    assert_eq!(message, "credential-bridge: invalid request: missing host");

    let audit = daemon.wait_for_audit(r#""outcome":"denied: missing host""#);
    assert!(audit.contains(r#""outcome":"denied: "#), "{audit}");
    assert!(!audit.contains("team-b"), "the raw path is not logged: {audit}");
}

/// A host without `[server.*]` entry does not see the bridge: the git helper and the gpg
/// shim find no extension and step aside silently (git goes on with its other helpers);
/// only the local audit log says what happened.
#[test]
fn unregistered_hosts_make_the_remote_side_step_aside() {
    let dir = short_tempdir();
    let _upstream = FakeAgent::spawn(dir.path().join("a.sock"), "a");
    let pinned = Host::new();
    let unregistered = Host::new();
    script(&dir.path().join("helper.sh"), "cat >/dev/null\nprintf 'username=u\\npassword=p\\n'");
    let config = CONFIG.replace("HOST_KEY", &pinned.openssh());
    let daemon = Daemon::start(&daemon_binary(), dir.path(), &config, &[]);
    let relay_dir = short_tempdir();
    let relay = binding_relay(relay_dir.path(), &daemon, unregistered.bind(b"session-unregistered", true));

    let output = remote_helper_output(&relay, "protocol=https\nhost=git.example.com\npath=team/repo\n\n");
    assert_eq!(output, "", "no credential, no message");
    assert!(!credential_bridge_remote::agent::supports(&relay, credential_bridge_proto::ext::GPG_AGENT));
    assert!(!credential_bridge_remote::agent::supports(&relay, credential_bridge_proto::ext::GIT_CREDENTIAL));

    let label = format!("unregistered host {}", unregistered.fingerprint());
    let audit = daemon.wait_for_audit(&label);
    assert!(audit.contains("the host is not registered"), "{audit}");
    assert!(!audit.contains(r#""event":"git""#), "the request never reached the git rules: {audit}");
}
