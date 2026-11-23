//! One client connection on `agent.sock` or `agent-forward.sock` (`docs/architecture.md`,
//! "Agent proxy and key mux"):
//!
//! peer check (done by the accept loop) → local ssh client check ([`crate::client`],
//! forward socket only) → binds ([`BindTracker`]) → [`policy::decide`]
//! → identities (merged and filtered), signatures (routed unchanged, optional approval),
//! write commands (to `agent.add_to`), extensions (forward socket only). Every refusal is
//! `SSH_AGENT_FAILURE`, as OpenSSH's ssh-agent answers an unknown extension (an empty
//! key list for `REQUEST_IDENTITIES`, as an agent without keys), and an
//! [`AuditEvent::Refused`]. `SSH_AGENT_EXTENSION_FAILURE` only answers an extension
//! payload this version does not understand.

use std::sync::Arc;
use std::time::Duration;

use credential_bridge_config::Profile;
use credential_bridge_config::host_keys::Recognition;
use credential_bridge_platform::peer::PeerCredentials;
use credential_bridge_proto::agent::{MAX_MESSAGE_LEN, Message};
use credential_bridge_proto::bind::SessionBind;
use credential_bridge_proto::ext::{self, GitRequest, GpgRequest};
use tokio::net::UnixStream;
use tokio::sync::watch;

use crate::approvals::{self, ApprovalKey};
use crate::audit::AuditEvent;
use crate::bind::{BindEvent, BindRejected, BindTracker, ServerBind};
use crate::core::{Core, Resolved};
use crate::extensions::{self, GpgTunnel};
use crate::frame::{read_agent_frame_within, write_agent_frame};
use crate::keymux::KeyMap;
use crate::policy::{self, Decision, RequestContext, SocketRole};
use crate::slots::ServerSlot;
use crate::upstream::UpstreamSet;

/// How long writing a reply may take.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the rest of a request may take once its first byte has arrived.
const FRAME_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a connection on `agent-forward.sock` may stay idle between requests.
/// Programs on a server open one agent connection per use, so an idle one is closed.
const FORWARD_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// The state of one client connection.
struct Connection {
    /// Shared state.
    core: Arc<Core>,
    /// The configuration in force: the one the connection started with, replaced by the
    /// current one on each request of a bound forwarded connection while the server's
    /// identity, profile and upstreams stay the same ([`Connection::follow_reload`]).
    snapshot: Arc<Resolved>,
    /// The socket.
    role: SocketRole,
    /// Binds seen.
    tracker: BindTracker,
    /// The `[server.*]` name the server bind (the verified first message) matched.
    server: Option<String>,
    /// Upstream connections.
    upstreams: UpstreamSet,
    /// The last identity answer.
    keys: KeyMap,
    /// The local process at the other end (`ssh`), for approvals.
    process: Option<String>,
    /// The gpg tunnel, if open.
    gpg: GpgTunnel,
    /// The connection budget this forward connection counts against.
    slot: Option<ServerSlot>,
    /// Set when the connection must end after the current reply.
    closing: bool,
    /// The connection's number in the audit log.
    number: u64,
}

/// Serves one connection until the client closes it or `stop` turns true (or its sender
/// is gone). A stop ends the wait for the next request at once; a request being handled
/// is answered first.
pub async fn serve(
    core: Arc<Core>,
    mut stream: UnixStream,
    role: SocketRole,
    peer: PeerCredentials,
    mut stop: watch::Receiver<bool>,
) {
    let process = peer.pid.and_then(|pid| credential_bridge_platform::process::process_name(pid).ok());
    let peer_text = peer.pid.map(|pid| format!("{pid} {}", process.as_deref().unwrap_or("?")));
    let number = core.next_connection();
    core.audit.record(&AuditEvent::Connect { connection: number, socket: role.as_str(), peer: peer_text });
    let slot = match role {
        SocketRole::Local => None,
        SocketRole::Forward => match core.forward_slots.acquire("") {
            Some(slot) => Some(slot),
            None => {
                tracing::warn!("too many forwarded connections without a session-bind; closing one");
                return;
            }
        },
    };
    // Fixed before the first message: only a verified OpenSSH 8.9 or later sends the
    // session-bind first; with any other client the first message may be the server's.
    let client_verified = match role {
        SocketRole::Local => false,
        SocketRole::Forward => {
            let check = core.clients.check(peer.pid).await;
            let client = check.describe();
            if check.may_select_server() {
                tracing::debug!("forwarded connection from {client}");
            } else {
                tracing::info!(
                    "forwarded connection: the local ssh client is {client}; no server recognition"
                );
            }
            let server_recognition = check.may_select_server();
            core.audit.record(&AuditEvent::Client { connection: number, client, server_recognition });
            server_recognition
        }
    };
    let snapshot = core.snapshot();
    let mut connection = Connection {
        upstreams: UpstreamSet::new(snapshot.upstreams.clone()),
        core,
        snapshot,
        role,
        tracker: BindTracker::new(role, client_verified),
        server: None,
        keys: KeyMap::default(),
        process,
        gpg: GpgTunnel::default(),
        slot,
        closing: false,
        number,
    };
    let idle = match role {
        SocketRole::Local => None,
        SocketRole::Forward => Some(FORWARD_IDLE_TIMEOUT),
    };
    loop {
        let stopped = async {
            let _ = stop.wait_for(|stop| *stop).await;
        };
        let payload = match read_agent_frame_within(&mut stream, idle, FRAME_TIMEOUT, stopped).await {
            Ok(Some(payload)) => payload,
            Ok(None) => break,
            Err(error) => {
                tracing::debug!("{} connection: {error}", role.as_str());
                break;
            }
        };
        let mut reply = match Message::decode(&payload) {
            Ok(message) => connection.handle(message).await,
            Err(error) => {
                tracing::debug!("undecodable message: {error}");
                Message::Failure
            }
        };
        // Whatever the frame was, it was a message: only the first one can select the
        // server.
        connection.tracker.note_message();
        drop(payload);
        // Extension replies may carry tokens and gpg-agent output: encoded into a wiped
        // buffer, and the reply's own copy wiped as well.
        let mut encoded = reply.encode_zeroizing();
        if let Message::Success { contents } = &mut reply {
            zeroize::Zeroize::zeroize(contents);
        }
        if encoded.len() > MAX_MESSAGE_LEN {
            // A merged key list from several upstreams can exceed the limit.
            tracing::warn!(
                "reply of {} bytes exceeds the agent message limit; answering FAILURE",
                encoded.len()
            );
            encoded = Message::Failure.encode_zeroizing();
        }
        let written = tokio::time::timeout(WRITE_TIMEOUT, write_agent_frame(&mut stream, &encoded)).await;
        if !matches!(written, Ok(Ok(()))) || connection.closing {
            break;
        }
    }
    let core = Arc::clone(&connection.core);
    connection.gpg.close(&core).await;
}

/// The server label of a forwarded connection without a server bind.
fn unbound_label(state: ServerBind) -> &'static str {
    match state {
        ServerBind::Unrecognised => "unrecognised host (session-bind refused or not first)",
        ServerBind::ClientNotVerified => {
            "unrecognised host (local ssh client not verified as OpenSSH 8.9 or later)"
        }
        ServerBind::Missing | ServerBind::Verified => "unrecognised host (no session-bind)",
    }
}

/// The server as dialogs and every audit event (`sign`, `git`, `gpg`, `refused`) name it:
/// `local` on `agent.sock`; on `agent-forward.sock` the `[server.*]` name, else
/// `unregistered host SHA256:…` for a server bind with an unpinned host key
/// (`fingerprint`), else `unrecognised host (…)` with the reason there is no server bind.
pub(crate) fn server_label(
    role: SocketRole,
    server: Option<&str>,
    fingerprint: Option<&str>,
    state: ServerBind,
) -> String {
    match (role, server, fingerprint) {
        (SocketRole::Local, _, _) => "local".to_owned(),
        (SocketRole::Forward, Some(name), _) => name.to_owned(),
        (SocketRole::Forward, None, Some(fingerprint)) => format!("unregistered host {fingerprint}"),
        (SocketRole::Forward, None, None) => unbound_label(state).to_owned(),
    }
}

/// The SSH fingerprint of a key blob (`SHA256:…`), or a placeholder.
pub(crate) fn fingerprint(key_blob: &[u8]) -> String {
    ssh_key::PublicKey::from_bytes(key_blob)
        .map(|key| key.fingerprint(ssh_key::HashAlg::Sha256).to_string())
        .unwrap_or_else(|_| "unknown key type".to_owned())
}

impl Connection {
    /// The profile in force: the registered server's, else `profile.unregistered` for a
    /// server bind with an unpinned host key; nothing without a server bind (hard-coded,
    /// not configurable) and nothing on `agent.sock`.
    fn profile<'a>(&self, snapshot: &'a Resolved) -> Option<&'a Profile> {
        match self.role {
            SocketRole::Local => None,
            SocketRole::Forward if self.tracker.server_bind().is_none() => None,
            SocketRole::Forward => {
                let server = self.server.as_deref().and_then(|name| snapshot.config.servers.get(name));
                snapshot.config.profile_for(server)
            }
        }
    }

    /// The decision context for a request now.
    fn context<'a>(
        &self,
        snapshot: &'a Resolved,
        server: Option<&'a str>,
        label: &'a str,
    ) -> RequestContext<'a> {
        // Before the lock: a lock between the two is seen by one or the other.
        let forgets = self.core.forget_count();
        RequestContext {
            config: &snapshot.config,
            role: self.role,
            server,
            profile: self.profile(snapshot),
            server_bind: self.tracker.server_bind_state(),
            hop: self.tracker.is_hop(),
            forgets,
            locked: self.core.lock.is_locked(),
            label,
        }
    }

    /// The server as shown in dialogs and every audit event ([`server_label`]).
    fn server_label(&self) -> String {
        let fingerprint = self.tracker.server_bind().map(|bind| bind.host_key_fingerprint());
        server_label(
            self.role,
            self.server.as_deref(),
            fingerprint.as_deref(),
            self.tracker.server_bind_state(),
        )
    }

    /// Records a refusal and answers `SSH_AGENT_FAILURE`, which is also how an agent
    /// without the bridge answers an extension it does not know.
    fn refuse(&self, reason: &'static str) -> Message {
        tracing::debug!("refused on {}: {reason}", self.role.as_str());
        self.core.audit.record(&AuditEvent::Refused { server: self.server_label(), reason });
        Message::Failure
    }

    /// Answers one message.
    async fn handle(&mut self, message: Message) -> Message {
        if let Message::Extension { name, contents } = &message
            && name == ext::SESSION_BIND
        {
            return self.bind(contents).await;
        }
        if let Err(refusal) = self.follow_reload().await {
            return refusal;
        }
        let snapshot = Arc::clone(&self.snapshot);
        let server = self.server.clone();
        let label = self.server_label();
        let ctx = self.context(&snapshot, server.as_deref(), &label);
        if let Decision::Refuse(reason) = policy::decide(&ctx, &message) {
            let failure = self.refuse(reason);
            // ssh-agent answers an empty list while locked, and so does an agent without
            // keys: no key, not even a public one, is shown.
            if matches!(message, Message::RequestIdentities) {
                return Message::IdentitiesAnswer(Vec::new());
            }
            return failure;
        }
        match message {
            Message::RequestIdentities => Message::IdentitiesAnswer(self.identities(&ctx).await),
            Message::SignRequest { .. } => self.sign(&ctx, message).await,
            Message::Lock { passphrase } => {
                if self.core.lock.lock(passphrase) {
                    self.core.approvals.clear();
                    tracing::info!("proxy locked");
                    crate::extensions::forget_tokens(&self.core, None).await;
                    Message::Success { contents: Vec::new() }
                } else {
                    Message::Failure
                }
            }
            Message::Unlock { passphrase } => {
                if self.core.lock.attempt_unlock(&passphrase).await {
                    tracing::info!("proxy unlocked");
                    Message::Success { contents: Vec::new() }
                } else {
                    Message::Failure
                }
            }
            // The policy refuses every extension on agent.sock but session-bind.
            Message::Extension { name, mut contents } => {
                let reply = match self.role {
                    SocketRole::Local => self.refuse("extension on the local socket"),
                    SocketRole::Forward => self.extension(&ctx, &name, &contents).await,
                };
                // Inquiry answers and git requests: wiped once handled.
                zeroize::Zeroize::zeroize(&mut contents);
                reply
            }
            write if write.is_write_command() => self.write_command(&ctx, write).await,
            _ => Message::Failure,
        }
    }

    /// On a forwarded connection with a server bind: recognises the bound host key again
    /// under the current configuration (and known_hosts as it is now). If that selects the
    /// same server with the same profile (apart from its git rules, which are looked up
    /// per request, and `signing`, which only ctl uses) and the upstreams are the same,
    /// the connection continues under the current configuration, so changed sources and
    /// rules apply at once (an open gpg tunnel also needs the same gpg-agent socket).
    /// Otherwise the request is refused and the connection ends: keys listed, approvals
    /// given and a gpg tunnel opened under the old profile must not outlive it.
    async fn follow_reload(&mut self) -> Result<(), Message> {
        let Some(bind) = self.tracker.server_bind().filter(|_| self.role == SocketRole::Forward) else {
            return Ok(());
        };
        let current = self.core.snapshot();
        let recognition = Arc::clone(&self.core.recognition);
        let (config, key) = (Arc::clone(&current.config), bind.host_key.clone());
        // Cheap unless a known_hosts file changed: then it reads the files again.
        let found = tokio::task::spawn_blocking(move || recognition.recognise(&config, &key))
            .await
            .unwrap_or(Recognition::Unregistered);
        let server = match found {
            Recognition::Server { name, .. } => Some(name),
            Recognition::Unregistered | Recognition::Ambiguous(_) => None,
        };
        let profile =
            current.config.profile_for(server.as_deref().and_then(|name| current.config.servers.get(name)));
        // An open gpg tunnel is connected to the old socket.
        let unchanged = server == self.server
            && same_profile(self.profile(&self.snapshot), profile)
            && current.upstreams == self.snapshot.upstreams
            && (!self.gpg.is_open() || current.gpg_socket == self.snapshot.gpg_socket);
        if unchanged {
            self.snapshot = current;
            return Ok(());
        }
        tracing::info!("{}: the server's configuration changed; closing the connection", self.server_label());
        self.closing = true;
        Err(self.refuse("the server's configuration changed; reconnect"))
    }

    /// `session-bind@openssh.com`: verify, apply the connection rules, replay. A refused
    /// bind is replayed as well (within the tracker's limits), so upstream ssh-agents see
    /// the attempt; their answer does not change the decision.
    async fn bind(&mut self, contents: &[u8]) -> Message {
        let bind = match SessionBind::parse(contents).and_then(|bind| bind.verify().map(|()| bind)) {
            Ok(bind) => Some(bind),
            Err(error) => {
                tracing::info!("{}: refused a session-bind: {error}", self.role.as_str());
                None
            }
        };
        let recorded = self.tracker.record(bind, contents);
        if let Some(new) = recorded.queued {
            self.upstreams.replay_bind(new).await;
        }
        let (event, bind) = match recorded.result {
            Ok(accepted) => accepted,
            Err(rejected) => {
                let reason = match rejected {
                    BindRejected::Invalid => "invalid session-bind",
                    BindRejected::TooMany => "too many session binds",
                    BindRejected::AfterAuthBind => "bind after an authentication bind",
                    BindRejected::Conflict => "conflicting session-bind",
                };
                return self.refuse(reason);
            }
        };
        match event {
            BindEvent::SelectsServer => {
                let host_key = bind.host_key_fingerprint();
                let config = Arc::clone(&self.snapshot.config);
                let recognition = Arc::clone(&self.core.recognition);
                let key = bind.host_key.clone();
                let lookup = config.clone();
                // May read the known_hosts files again (if they changed).
                let found = tokio::task::spawn_blocking(move || recognition.recognise(&lookup, &key))
                    .await
                    .unwrap_or(Recognition::Unregistered);
                if let Some(slot) = self.slot.as_mut()
                    && !slot.move_to(&host_key)
                {
                    tracing::warn!("too many forwarded connections from host key {host_key}; closing one");
                    self.closing = true;
                    return self.refuse("too many connections from this server");
                }
                let (source, ambiguous) = match found {
                    // A server of this very snapshot: the map is built from it.
                    Recognition::Server { name, source } => {
                        self.server = Some(name);
                        (Some(source.as_str()), Vec::new())
                    }
                    Recognition::Unregistered => (None, Vec::new()),
                    Recognition::Ambiguous(names) => (None, names),
                };
                let server = self.server.as_deref().and_then(|name| config.servers.get(name));
                let profile = config.profile_for(server).map(|profile| profile.name.clone());
                match (&self.server, ambiguous.as_slice()) {
                    (Some(name), _) => tracing::info!(
                        "forwarded connection from {name} (profile {}, host key {})",
                        profile.as_deref().unwrap_or("none"),
                        source.unwrap_or("?")
                    ),
                    (None, []) => tracing::info!(
                        "forwarded connection from unregistered host {host_key} (profile unregistered); \
                         to register it: credential-bridge-ctl server add NAME --profile PROFILE"
                    ),
                    (None, names) => tracing::warn!(
                        "forwarded connection with host key {host_key}, which belongs to servers {}: \
                         treated as unregistered (credential-bridge-ctl check)",
                        names.join(" and ")
                    ),
                }
                self.core.audit.record(&AuditEvent::Server {
                    connection: self.number,
                    server: self.server.clone(),
                    host_key,
                    profile,
                    source,
                    ambiguous,
                });
                self.keys = KeyMap::default();
            }
            BindEvent::Hop => {
                self.core.audit.record(&AuditEvent::Hop { host_key: bind.host_key_fingerprint() });
                self.keys = KeyMap::default();
            }
            BindEvent::Recorded | BindEvent::Duplicate => {}
        }
        Message::Success { contents: Vec::new() }
    }

    /// Merged and filtered identities; also remembered for routing.
    async fn identities(
        &mut self,
        ctx: &RequestContext<'_>,
    ) -> Vec<credential_bridge_proto::agent::Identity> {
        if ctx.config.agent.is_none() || ctx.locked {
            self.keys = KeyMap::default();
            return Vec::new();
        }
        let lists = self.upstreams.all_identities(self.tracker.replay()).await;
        let targets = self.upstreams.targets();
        let visible = |index: usize| match ctx.role {
            SocketRole::Local => true,
            SocketRole::Forward => ctx
                .profile
                .zip(targets.get(index))
                .is_some_and(|(profile, target)| profile.shows_upstream(&target.name)),
        };
        self.keys = KeyMap::merge(lists, visible);
        self.keys.identities()
    }

    /// A sign request: route, maybe ask, pass through unchanged.
    async fn sign(&mut self, ctx: &RequestContext<'_>, message: Message) -> Message {
        let Message::SignRequest { key_blob, .. } = &message else { return Message::Failure };
        let key = fingerprint(key_blob);
        let server = self.server_label();
        let audit = |core: &Core, upstream: Option<String>, outcome: &'static str| {
            core.audit.record(&AuditEvent::Sign {
                server: server.clone(),
                key: key.clone(),
                upstream,
                outcome,
            });
        };
        let mut route = self.keys.route(key_blob);
        if route.is_none() {
            // No list on this connection yet (or the key list changed): list once.
            self.identities(ctx).await;
            route = self.keys.route(key_blob);
        }
        let Some(index) = route else {
            audit(&self.core, None, "refused");
            return self.refuse("key is not available to this connection");
        };
        let upstream_name = self.upstreams.targets().get(index).map(|target| target.name.clone());
        let dialog = match ctx.role {
            SocketRole::Forward => {
                ctx.profile.and_then(|profile| profile.ssh.as_ref()).and_then(|ssh| ssh.confirm.dialog())
            }
            SocketRole::Local => None,
        };
        if let Some(remember) = dialog {
            // Without a server bind every such connection has the same label: ask each time.
            // (Such connections get no keys today; the rule stays for safety.)
            let remember = remember.filter(|_| self.tracker.server_bind().is_some());
            let allowed = match self.core.approval_dialog() {
                Ok(dialog) => {
                    let approval = ApprovalKey {
                        server: server.clone(),
                        key: key.clone(),
                        process: self.process.clone(),
                        hop: ctx.hop,
                    };
                    approvals::confirm(&self.core.approvals, dialog, approval, remember).await
                }
                Err(error) => {
                    tracing::warn!("approval needed but no dialog: {error}");
                    false
                }
            };
            if !allowed {
                audit(&self.core, upstream_name, "denied");
                return Message::Failure;
            }
            // The dialog may have been open for a minute: `ssh-add -x` meanwhile wins, for
            // the request that asked as for every request that waited for its answer.
            if self.core.lock.is_locked() {
                audit(&self.core, upstream_name, "refused");
                return self.refuse("proxy is locked");
            }
        }
        match self.upstreams.request(index, &message, self.tracker.replay()).await {
            Ok(reply) => {
                let outcome = if matches!(reply, Message::SignResponse { .. }) { "ok" } else { "failed" };
                audit(&self.core, upstream_name, outcome);
                reply
            }
            Err(error) => {
                tracing::warn!("{error}");
                audit(&self.core, upstream_name, "failed");
                Message::Failure
            }
        }
    }

    /// `ssh-add`, `-d`, `-D`, `-s`, `-e` on `agent.sock`: to `agent.add_to`.
    async fn write_command(&mut self, ctx: &RequestContext<'_>, message: Message) -> Message {
        let Some(index) = self.add_to_index(ctx) else {
            return self.refuse("no agent.add_to upstream for write commands");
        };
        match self.upstreams.request(index, &message, self.tracker.replay()).await {
            Ok(reply) => {
                self.keys = KeyMap::default();
                reply
            }
            Err(error) => {
                tracing::warn!("{error}");
                Message::Failure
            }
        }
    }

    /// The upstream index of `agent.add_to`.
    fn add_to_index(&self, ctx: &RequestContext<'_>) -> Option<usize> {
        let name = ctx.config.agent.as_ref()?.add_to.as_deref()?;
        self.upstreams.targets().iter().position(|target| target.name == name)
    }

    /// `query`, git and gpg on `agent-forward.sock`, for a registered server (the policy
    /// hides them from everyone else). A payload this version cannot decode gets
    /// `SSH_AGENT_EXTENSION_FAILURE`: the extension exists, the request does not fit.
    async fn extension(&mut self, ctx: &RequestContext<'_>, name: &str, contents: &[u8]) -> Message {
        match name {
            ext::QUERY => ext::query_response(extensions::SUPPORTED),
            ext::GIT_CREDENTIAL => {
                let Ok(request) = GitRequest::decode(contents) else { return Message::ExtensionFailure };
                let reply = extensions::git_credential(&self.core, ctx, request).await;
                encode_reply(reply.encode())
            }
            ext::GPG_AGENT => {
                let Ok(request) = GpgRequest::decode(contents) else { return Message::ExtensionFailure };
                let core = Arc::clone(&self.core);
                let reply = self.gpg.handle(&core, ctx, request).await;
                // Moved into the reply, not copied; `serve` wipes it after writing.
                encode_reply(reply.encode().map(|mut encoded| std::mem::take(&mut *encoded)))
            }
            _ => self.refuse("unknown extension"),
        }
    }
}

/// Whether two profiles are the same but for their git rules, which a connection looks
/// up per request, and `signing`, which only `ctl` uses (git setup on the server).
fn same_profile(old: Option<&Profile>, new: Option<&Profile>) -> bool {
    match (old, new) {
        (None, None) => true,
        (Some(old), Some(new)) => {
            let Profile { name, ssh, gpg, hops, signing: _, git: _ } = old;
            let Profile { name: new_name, ssh: new_ssh, gpg: new_gpg, hops: new_hops, signing: _, git: _ } =
                new;
            name == new_name && ssh == new_ssh && gpg == new_gpg && hops == new_hops
        }
        _ => false,
    }
}

/// `SSH_AGENT_SUCCESS` with the encoded reply, or `SSH_AGENT_FAILURE`.
fn encode_reply(encoded: Result<Vec<u8>, ext::ExtError>) -> Message {
    match encoded {
        Ok(contents) => Message::Success { contents },
        Err(error) => {
            tracing::warn!("cannot encode an extension reply: {error}");
            Message::Failure
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_labels() {
        let label = |role, server, fingerprint, state| server_label(role, server, fingerprint, state);
        assert_eq!(label(SocketRole::Local, Some("x"), Some("SHA256:k"), ServerBind::Verified), "local");
        assert_eq!(
            label(SocketRole::Forward, Some("build"), Some("SHA256:k"), ServerBind::Verified),
            "build"
        );
        assert_eq!(
            label(SocketRole::Forward, None, Some("SHA256:k"), ServerBind::Verified),
            "unregistered host SHA256:k"
        );
        assert_eq!(
            label(SocketRole::Forward, None, None, ServerBind::Missing),
            "unrecognised host (no session-bind)"
        );
        assert_eq!(
            label(SocketRole::Forward, None, None, ServerBind::Unrecognised),
            "unrecognised host (session-bind refused or not first)"
        );
    }

    #[test]
    fn fingerprints() {
        let key = ssh_key::PublicKey::new(
            ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey([7; 32])),
            "",
        );
        assert!(fingerprint(&key.to_bytes().unwrap()).starts_with("SHA256:"));
        assert_eq!(fingerprint(&[1, 2, 3]), "unknown key type");
    }

    /// Server `box` follows `{dir}/known_hosts`; its profile shows every key without a
    /// dialog. `{extra}` goes at the end.
    fn reload_config(dir: &std::path::Path, extra: &str) -> String {
        let dir = dir.display();
        format!(
            "version = 2\n[daemon]\naudit_log = \"{dir}/audit.log\"\n\
             [source.helper]\ntype = \"helper\"\nhelper = \"{dir}/helper.sh\"\n\
             [profile.build]\nssh = {{ keys = \"all\" }}\n\
             [server.box]\nknown_host = \"box\"\nknown_hosts_files = [\"{dir}/known_hosts\"]\nprofile = \"build\"\n{extra}"
        )
    }

    /// A core for `text` (written as `{dir}/config.toml`) without workers.
    fn reload_core(dir: &std::path::Path, text: &str) -> Arc<Core> {
        let vars = credential_bridge_config::paths::PathVars {
            home: Some(dir.as_os_str().to_owned()),
            ..Default::default()
        };
        let paths = credential_bridge_config::paths::Paths::from_vars(
            &vars,
            credential_bridge_config::paths::TargetOs::current(),
        )
        .unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, text).unwrap();
        let config = credential_bridge_config::Config::load(&path, &paths).unwrap();
        Arc::new(Core::new(paths, path, config, crate::supervisor::Workers::none()))
    }

    /// A forwarded connection from a verified client whose first message was `host`'s
    /// bind, which selected server `box`.
    async fn bound(core: &Arc<Core>, host: &credential_bridge_testutil::Host) -> Connection {
        let connection = bound_as(core, host).await;
        assert_eq!(connection.server.as_deref(), Some("box"));
        connection
    }

    /// A forwarded connection from a verified client whose first message was `host`'s
    /// bind.
    async fn bound_as(core: &Arc<Core>, host: &credential_bridge_testutil::Host) -> Connection {
        let snapshot = core.snapshot();
        let mut connection = Connection {
            upstreams: UpstreamSet::new(snapshot.upstreams.clone()),
            core: Arc::clone(core),
            snapshot,
            role: SocketRole::Forward,
            tracker: BindTracker::new(SocketRole::Forward, true),
            server: None,
            keys: KeyMap::default(),
            process: None,
            gpg: GpgTunnel::default(),
            slot: None,
            closing: false,
            number: 1,
        };
        let bind = credential_bridge_testutil::bind_message(host.bind(b"session", true));
        assert!(matches!(connection.handle(bind).await, Message::Success { .. }));
        connection.tracker.note_message();
        connection
    }

    fn query() -> Message {
        Message::Extension { name: ext::QUERY.to_owned(), contents: Vec::new() }
    }

    /// A reload reaches open connections: a change that leaves the server, its profile
    /// (but for git rules) and the upstreams alone applies to the next request; any other
    /// change, and a host key known_hosts no longer vouches for, refuses the next request
    /// and ends the connection.
    #[tokio::test]
    async fn open_connections_follow_or_end_on_reload() {
        let dir = tempfile::tempdir().unwrap();
        let host = credential_bridge_testutil::Host::new();
        let known_hosts = dir.path().join("known_hosts");
        std::fs::write(&known_hosts, format!("box {}\n", host.openssh())).unwrap();
        let core = reload_core(dir.path(), &reload_config(dir.path(), ""));
        let reload = |extra: &str, profile: Option<&str>| {
            let mut text = reload_config(dir.path(), extra);
            if let Some(profile) = profile {
                text = text.replace("ssh = { keys = \"all\" }", profile);
            }
            std::fs::write(dir.path().join("config.toml"), text).unwrap();
            core.reload().unwrap();
        };

        // A new rule and a new source: served under the new configuration.
        let mut connection = bound(&core, &host).await;
        assert!(matches!(connection.handle(query()).await, Message::Other { .. }));
        reload(
            "[source.other]\ntype = \"helper\"\nhelper = \"h\"\n\
             [[profile.build.git]]\nurl = \"https://git.example.com/*\"\nsource = \"other\"\n",
            None,
        );
        assert!(matches!(connection.handle(query()).await, Message::Other { .. }));
        assert!(!connection.closing);
        assert!(Arc::ptr_eq(&connection.snapshot, &core.snapshot()));
        assert_eq!(connection.snapshot.config.profiles["build"].git.len(), 1);

        // A stricter profile: refused, and the connection ends.
        reload("", Some("ssh = { keys = \"all\", confirm = \"always\" }"));
        assert!(matches!(connection.handle(query()).await, Message::Failure));
        assert!(connection.closing);

        // The server removed from the configuration.
        reload("", None);
        let mut connection = bound(&core, &host).await;
        std::fs::write(
            dir.path().join("config.toml"),
            reload_config(dir.path(), "").replace("[server.box]", "[server.gone]"),
        )
        .unwrap();
        core.reload().unwrap();
        assert!(matches!(connection.handle(query()).await, Message::Failure));
        assert!(connection.closing);

        // The host key revoked in known_hosts, without a reload.
        reload("", None);
        let mut connection = bound(&core, &host).await;
        let temp = dir.path().join("known_hosts.new");
        std::fs::write(&temp, format!("@revoked box {}\nbox {}\n", host.openssh(), host.openssh())).unwrap();
        std::fs::rename(&temp, &known_hosts).unwrap();
        assert!(matches!(connection.handle(query()).await, Message::Failure));
        assert!(connection.closing);
    }

    /// Whether the next request of `connection` goes on (under the current snapshot) or
    /// ends the connection.
    async fn follows(connection: &mut Connection) -> bool {
        connection.handle(Message::RequestIdentities).await;
        assert!(connection.closing || Arc::ptr_eq(&connection.snapshot, &connection.core.snapshot()));
        !connection.closing
    }

    /// What may change under an open connection: `signing` (ctl only) and other parts
    /// of the configuration; what ends it: changed upstreams, a looser profile as well as
    /// a stricter one, and with a gpg tunnel open a changed gpg-agent socket.
    #[tokio::test]
    async fn reloads_end_connections_whose_server_setup_changed() {
        let dir = tempfile::tempdir().unwrap();
        let host = credential_bridge_testutil::Host::new();
        std::fs::write(dir.path().join("known_hosts"), format!("box {}\n", host.openssh())).unwrap();
        let strict = "ssh = { keys = \"all\", confirm = \"always\" }";
        let text = |extra: &str, profile: &str| {
            reload_config(dir.path(), extra).replace("ssh = { keys = \"all\" }", profile)
        };
        let core = reload_core(dir.path(), &text("", strict));
        let reload = |extra: &str, profile: &str| {
            std::fs::write(dir.path().join("config.toml"), text(extra, profile)).unwrap();
            core.reload().unwrap();
        };

        // signing is only for ctl: the connection goes on.
        let mut connection = bound(&core, &host).await;
        reload("", &format!("{strict}\nsigning = \"ssh\""));
        assert!(follows(&mut connection).await);
        assert_eq!(
            connection.snapshot.config.profiles["build"].signing,
            Some(credential_bridge_config::Signing::Ssh)
        );

        // A looser profile ends it as well: the connection was set up under the old one.
        reload("", strict);
        let mut connection = bound(&core, &host).await;
        reload("", "ssh = { keys = \"all\" }");
        assert!(!follows(&mut connection).await);

        // Another upstream.
        reload("", strict);
        let mut connection = bound(&core, &host).await;
        let agent = format!(
            "[agent]\n[[agent.upstream]]\nname = \"a\"\nsocket = \"{}/a.sock\"\n",
            dir.path().display()
        );
        reload(&agent, strict);
        assert!(!follows(&mut connection).await);

        // Another gpg-agent socket: only a connection with an open tunnel ends.
        let gpg = |name: &str| format!("[gpg]\nsocket = \"{}/{name}\"\n", dir.path().display());
        reload(&gpg("gpg-a"), strict);
        let mut idle = bound(&core, &host).await;
        let mut tunnel = bound(&core, &host).await;
        tunnel.gpg = GpgTunnel::opened_for_test();
        reload(&gpg("gpg-a"), strict);
        assert!(follows(&mut tunnel).await, "the same socket");
        reload(&gpg("gpg-b"), strict);
        assert!(follows(&mut idle).await);
        assert!(!follows(&mut tunnel).await);
    }

    /// A host without `[server.*]` entry is recognised again on each request as well: it
    /// goes on while `profile.unregistered` stays as it was, and ends when it changes,
    /// looser or stricter, or when the host becomes a registered server.
    #[tokio::test]
    async fn reloads_end_unregistered_connections_whose_profile_changed() {
        let dir = tempfile::tempdir().unwrap();
        let (host, other) =
            (credential_bridge_testutil::Host::new(), credential_bridge_testutil::Host::new());
        std::fs::write(dir.path().join("known_hosts"), format!("box {}\n", host.openssh())).unwrap();
        let unregistered = |ssh: &str| format!("[profile.unregistered]\nssh = {{ {ssh} }}\n");
        let core = reload_core(
            dir.path(),
            &reload_config(dir.path(), &unregistered("keys = \"all\", confirm = \"8h\"")),
        );
        let reload = |extra: &str| {
            std::fs::write(dir.path().join("config.toml"), reload_config(dir.path(), extra)).unwrap();
            core.reload().unwrap();
        };

        // Other changes: it goes on.
        let mut connection = bound_as(&core, &other).await;
        assert_eq!(connection.server, None);
        reload(&format!(
            "{}[source.other]\ntype = \"helper\"\nhelper = \"h\"\n",
            unregistered("keys = \"all\", confirm = \"8h\"")
        ));
        assert!(follows(&mut connection).await);

        // Looser.
        reload(&unregistered("keys = \"all\", confirm = \"8h\""));
        let mut connection = bound_as(&core, &other).await;
        reload(&unregistered("keys = \"all\", confirm = \"never\""));
        assert!(!follows(&mut connection).await);

        // Stricter.
        let mut connection = bound_as(&core, &other).await;
        reload(&unregistered("keys = \"all\", confirm = \"always\""));
        assert!(!follows(&mut connection).await);

        // Registered meanwhile.
        let mut connection = bound_as(&core, &other).await;
        std::fs::write(
            dir.path().join("known_hosts"),
            format!("box {}\nbox {}\n", host.openssh(), other.openssh()),
        )
        .unwrap();
        reload(&unregistered("keys = \"all\", confirm = \"always\""));
        assert!(!follows(&mut connection).await);
    }

    #[test]
    fn labels_tell_a_missing_bind_from_a_refused_one() {
        assert_eq!(unbound_label(ServerBind::Missing), "unrecognised host (no session-bind)");
        assert_eq!(
            unbound_label(ServerBind::Unrecognised),
            "unrecognised host (session-bind refused or not first)"
        );
        assert_eq!(
            unbound_label(ServerBind::ClientNotVerified),
            "unrecognised host (local ssh client not verified as OpenSSH 8.9 or later)"
        );
    }
}
