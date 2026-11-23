//! Per-connection bind tracking (`docs/architecture.md`: "Recognising the server", "Hops").
//!
//! Rules:
//!
//! - on `agent-forward.sock` only the **first message** of a connection can select the
//!   server, and only if it is a `session-bind` that parses, verifies
//!   ([`credential_bridge_proto::bind::SessionBind::verify`]) and has
//!   `is_forwarding = 1`, and only if the local ssh client was verified as OpenSSH 8.9
//!   or later ([`crate::client`]; older clients send no bind, so their first message
//!   comes from the server). If the first message is anything else, or a bind that
//!   fails, or the client is not verified, the connection never gets a server. Every
//!   other accepted forwarding bind marks the connection as a hop (its host key is only
//!   logged);
//! - on `agent.sock` binds are recorded and replayed to upstreams, never select a
//!   server;
//! - at most [`MAX_SESSION_IDS`] accepted binds per connection, the limit of ssh-agent,
//!   which also counts accepted binds only;
//! - no bind after an `is_forwarding = 0` bind;
//! - a session id bound again with the same host key blob and direction is accepted
//!   without being recorded twice; with anything else it is a conflict (as ssh-agent).
//!
//! Every accepted bind and every refused one is queued for the replay to the upstream
//! agents ([`BindTracker::replay`]), in arrival order: an upstream ssh-agent that sees a
//! bind attempt treats the connection as remote and applies its own rules to
//! destination-constrained keys (`ssh-add -h`). Its answer to a replayed bind never
//! changes the proxy's decision. Refused binds do not count against ssh-agent's limit
//! (it only notes that an attempt failed), so the proxy bounds them itself: at most
//! [`MAX_SESSION_IDS`] of them are queued, each at most [`MAX_REPLAYED_REFUSED_LEN`]
//! bytes; a longer one is replaced by an empty `session-bind`, which ssh-agent treats as
//! a failed attempt as well.
//!
//! The replay list is shared ([`Replay`]): the upstream connections of a request take a
//! reference, not a copy.

use std::sync::Arc;

use credential_bridge_proto::bind::{MAX_SESSION_IDS, SessionBind};

use crate::policy::SocketRole;

/// Longest refused bind (extension contents) replayed as received.
pub const MAX_REPLAYED_REFUSED_LEN: usize = 16 * 1024;

/// Why a bind was refused (answered with `SSH_AGENT_FAILURE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BindRejected {
    /// The bind did not parse or its signature did not verify.
    #[error("invalid session-bind")]
    Invalid,
    /// More than [`MAX_SESSION_IDS`] binds.
    #[error("too many session binds")]
    TooMany,
    /// A bind after an authentication (`is_forwarding = 0`) bind.
    #[error("bind after an authentication bind")]
    AfterAuthBind,
    /// The same session id was bound twice with a different host key.
    #[error("conflicting session-bind")]
    Conflict,
}

/// What an accepted bind meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindEvent {
    /// A verified forwarding bind as the first message on `agent-forward.sock` from a
    /// verified ssh client: look up the server.
    SelectsServer,
    /// Any other forwarding bind on `agent-forward.sock`: the connection now serves a
    /// hop.
    Hop,
    /// An authentication bind, or any bind on `agent.sock`: replay only.
    Recorded,
    /// The same bind was already recorded; nothing changed and nothing is replayed.
    Duplicate,
}

/// The `session-bind` contents to replay on every upstream connection, in order; shared
/// so that concurrent upstream requests need no copy.
pub type Replay = Arc<Vec<Vec<u8>>>;

/// What [`BindTracker::record`] did with a bind.
#[derive(Debug)]
pub struct Recorded<'a> {
    /// The accepted bind (for a duplicate the one recorded before) with what it meant,
    /// or why it was refused.
    pub result: Result<(BindEvent, &'a SessionBind), BindRejected>,
    /// The contents just queued for the replay, to send to the upstream connections
    /// already open; `None` for a duplicate or a refused bind beyond the limit.
    pub queued: Option<&'a [u8]>,
}

/// Whether a connection on `agent-forward.sock` identified its server, and if not, why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerBind {
    /// The first message was a verified forwarding bind (the server bind).
    Verified,
    /// The local ssh client was verified as OpenSSH 8.9 or later, but no forwarding
    /// `session-bind` arrived and no bind was refused (a client built without binds).
    /// Accepted authentication binds may have arrived: an ssh 8.9 or later on the server
    /// that logs in to a further host sends one, even as the first message.
    Missing,
    /// A bind was refused, or a forwarding bind arrived but not as the first message: the
    /// server is not recognised.
    Unrecognised,
    /// The local ssh client is not verified as OpenSSH 8.9 or later (an older release,
    /// another program, or a check that failed), so no bind can select the server.
    ClientNotVerified,
}

/// Bind state of one client connection.
#[derive(Debug, Clone)]
pub struct BindTracker {
    /// The socket the connection came in on.
    role: SocketRole,
    /// Whether a first-message bind may select the server: `agent-forward.sock` with a
    /// verified local ssh client.
    may_select: bool,
    /// Whether a message was handled already (only the first one can select a server).
    started: bool,
    /// Whether the first message was a verified forwarding bind that selected the
    /// server (the server bind).
    selected: bool,
    /// Whether a `session-bind` was refused.
    bind_refused: bool,
    /// Accepted binds, in order.
    binds: Vec<SessionBind>,
    /// Contents of the binds to replay upstream, accepted and refused, in order.
    replay: Replay,
    /// Refused binds queued in `replay`.
    refused: usize,
}

impl BindTracker {
    /// A connection that has not sent anything yet. `client_verified`: the local ssh
    /// client is OpenSSH 8.9 or later ([`crate::client`]); without it no bind selects
    /// the server. Ignored on `agent.sock`.
    pub fn new(role: SocketRole, client_verified: bool) -> Self {
        Self {
            role,
            may_select: role == SocketRole::Forward && client_verified,
            started: false,
            selected: false,
            bind_refused: false,
            binds: Vec::new(),
            replay: Replay::default(),
            refused: 0,
        }
    }

    /// Notes that a message was handled: from now on no bind can select the server. The
    /// connection's serve loop calls it once per frame after handling it, whatever the
    /// frame was (an undecodable one too); [`BindTracker::record`] marks it as well.
    pub fn note_message(&mut self) {
        self.started = true;
    }

    /// Records a `session-bind` whose extension contents were `contents`: `bind` is the
    /// parsed and verified bind, or `None` if parsing or verification failed.
    pub fn record(&mut self, bind: Option<SessionBind>, contents: &[u8]) -> Recorded<'_> {
        let first = !std::mem::replace(&mut self.started, true);
        let result = match bind {
            Some(bind) => self.accept(bind, first),
            None => Err(BindRejected::Invalid),
        };
        let queued = match result {
            Ok((BindEvent::Duplicate, _)) => false,
            Ok(_) => {
                Arc::make_mut(&mut self.replay).push(contents.to_vec());
                true
            }
            Err(_) => {
                self.bind_refused = true;
                self.queue_refused(contents)
            }
        };
        Recorded {
            result: result.map(|(event, index)| (event, &self.binds[index])),
            queued: queued.then(|| self.replay.last().map(Vec::as_slice)).flatten(),
        }
    }

    /// Applies the connection rules to a verified bind; returns the event and the index
    /// of the bind in `binds`.
    fn accept(&mut self, bind: SessionBind, first: bool) -> Result<(BindEvent, usize), BindRejected> {
        for (index, known) in self.binds.iter().enumerate() {
            if !known.is_forwarding {
                return Err(BindRejected::AfterAuthBind);
            }
            if known.session_id == bind.session_id {
                let same =
                    known.host_key_blob == bind.host_key_blob && known.is_forwarding == bind.is_forwarding;
                return if same { Ok((BindEvent::Duplicate, index)) } else { Err(BindRejected::Conflict) };
            }
        }
        if self.binds.len() >= MAX_SESSION_IDS {
            return Err(BindRejected::TooMany);
        }
        let event = match (self.role, bind.is_forwarding) {
            (SocketRole::Forward, true) if first && self.may_select => {
                self.selected = true;
                BindEvent::SelectsServer
            }
            (SocketRole::Forward, true) => BindEvent::Hop,
            _ => BindEvent::Recorded,
        };
        self.binds.push(bind);
        Ok((event, self.binds.len() - 1))
    }

    /// Queues a refused bind for the replay, within the limits in the module docs;
    /// returns whether it was queued.
    fn queue_refused(&mut self, contents: &[u8]) -> bool {
        if self.refused >= MAX_SESSION_IDS {
            // Every upstream has seen an attempt already (new connections get the queue).
            return false;
        }
        self.refused += 1;
        let contents =
            if contents.len() <= MAX_REPLAYED_REFUSED_LEN { contents.to_vec() } else { Vec::new() };
        Arc::make_mut(&mut self.replay).push(contents);
        true
    }

    /// The bind that selected the server: a verified forwarding bind that was the first
    /// message on `agent-forward.sock`.
    pub fn server_bind(&self) -> Option<&SessionBind> {
        self.binds.first().filter(|_| self.selected)
    }

    /// Whether the server was identified, and if not, why (see [`ServerBind`]).
    pub fn server_bind_state(&self) -> ServerBind {
        if self.selected {
            ServerBind::Verified
        } else if self.role == SocketRole::Forward && !self.may_select {
            ServerBind::ClientNotVerified
        } else if self.bind_refused || self.binds.iter().any(|bind| bind.is_forwarding) {
            ServerBind::Unrecognised
        } else {
            ServerBind::Missing
        }
    }

    /// Whether an accepted forwarding bind on `agent-forward.sock` did not select the
    /// server (a hop request; also on a connection without a server).
    pub fn is_hop(&self) -> bool {
        let skip = usize::from(self.selected);
        self.role == SocketRole::Forward && self.binds.iter().skip(skip).any(|bind| bind.is_forwarding)
    }

    /// All accepted binds, in order.
    #[cfg(test)]
    pub fn binds(&self) -> &[SessionBind] {
        &self.binds
    }

    /// The `session-bind` contents to replay on every upstream connection, in order.
    pub fn replay(&self) -> &Replay {
        &self.replay
    }

    /// The socket role.
    pub fn role(&self) -> SocketRole {
        self.role
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use credential_bridge_proto::wire::Writer;
    use ssh_key::public::{Ed25519PublicKey, KeyData};

    use super::*;

    /// A bind with a fake host key (seeded) and session id; not verifiable, which the
    /// tracker does not need.
    pub(crate) fn fake_bind(host: u8, session: u8, is_forwarding: bool) -> SessionBind {
        let host_key = ssh_key::PublicKey::new(KeyData::Ed25519(Ed25519PublicKey([host; 32])), "");
        SessionBind {
            host_key_blob: host_key.to_bytes().unwrap(),
            host_key,
            session_id: vec![session; 32],
            signature: vec![],
            is_forwarding,
        }
    }

    /// The extension contents of `bind`.
    pub(crate) fn contents(bind: &SessionBind) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_string(&bind.host_key_blob)
            .put_string(&bind.session_id)
            .put_string(&bind.signature)
            .put_bool(bind.is_forwarding);
        w.into_bytes()
    }

    /// Records `bind` as verified.
    fn record(tracker: &mut BindTracker, bind: SessionBind) -> Result<BindEvent, BindRejected> {
        let contents = contents(&bind);
        tracker.record(Some(bind), &contents).result.map(|(event, _)| event)
    }

    /// Records a bind that failed to parse or verify.
    fn refuse(tracker: &mut BindTracker, contents: &[u8]) -> Result<BindEvent, BindRejected> {
        tracker.record(None, contents).result.map(|(event, _)| event)
    }

    #[test]
    fn first_forwarding_bind_selects_the_server() {
        let mut tracker = BindTracker::new(SocketRole::Forward, true);
        assert!(tracker.server_bind().is_none());
        assert_eq!(record(&mut tracker, fake_bind(1, 1, true)), Ok(BindEvent::SelectsServer));
        assert!(!tracker.is_hop());
        assert_eq!(record(&mut tracker, fake_bind(2, 2, true)), Ok(BindEvent::Hop));
        assert!(tracker.is_hop());
        assert_eq!(tracker.server_bind().unwrap().host_key_blob, fake_bind(1, 1, true).host_key_blob);
        assert_eq!(tracker.binds().len(), 2);
        // Duplicates are not replayed again.
        assert_eq!(record(&mut tracker, fake_bind(1, 1, true)), Ok(BindEvent::Duplicate));
        assert_eq!(**tracker.replay(), [contents(&fake_bind(1, 1, true)), contents(&fake_bind(2, 2, true))]);
    }

    #[test]
    fn only_the_first_message_can_select_the_server() {
        // A refused bind first: a later valid bind (a replayed bind of another server)
        // is only a hop.
        let mut tracker = BindTracker::new(SocketRole::Forward, true);
        assert_eq!(refuse(&mut tracker, b"invalid"), Err(BindRejected::Invalid));
        assert_eq!(record(&mut tracker, fake_bind(1, 1, true)), Ok(BindEvent::Hop));
        assert!(tracker.server_bind().is_none());
        assert!(tracker.is_hop());

        // Another message first.
        let mut tracker = BindTracker::new(SocketRole::Forward, true);
        tracker.note_message();
        assert_eq!(record(&mut tracker, fake_bind(1, 1, true)), Ok(BindEvent::Hop));
        assert!(tracker.server_bind().is_none());

        // Noting the server bind itself as handled changes nothing.
        let mut tracker = BindTracker::new(SocketRole::Forward, true);
        assert_eq!(record(&mut tracker, fake_bind(1, 1, true)), Ok(BindEvent::SelectsServer));
        tracker.note_message();
        assert!(tracker.server_bind().is_some());
        assert_eq!(record(&mut tracker, fake_bind(2, 2, true)), Ok(BindEvent::Hop));

        // A failed first bind never turns into a server later, not even a duplicate.
        let mut tracker = BindTracker::new(SocketRole::Forward, true);
        assert_eq!(refuse(&mut tracker, b"x"), Err(BindRejected::Invalid));
        assert_eq!(record(&mut tracker, fake_bind(1, 1, true)), Ok(BindEvent::Hop));
        assert_eq!(record(&mut tracker, fake_bind(1, 1, true)), Ok(BindEvent::Duplicate));
        assert!(tracker.server_bind().is_none());
    }

    #[test]
    fn record_returns_the_bind_and_the_queued_contents() {
        let mut tracker = BindTracker::new(SocketRole::Forward, true);
        let bind = fake_bind(1, 1, true);
        let first = contents(&bind);
        let recorded = tracker.record(Some(bind.clone()), &first);
        assert_eq!(recorded.result, Ok((BindEvent::SelectsServer, &bind)));
        assert_eq!(recorded.queued, Some(first.as_slice()));
        // A duplicate names the bind recorded before and queues nothing.
        let recorded = tracker.record(Some(bind.clone()), &first);
        assert_eq!(recorded.result, Ok((BindEvent::Duplicate, &bind)));
        assert_eq!(recorded.queued, None);
        // A refused bind is queued, up to the limit.
        let recorded = tracker.record(None, b"bad");
        assert_eq!((recorded.result, recorded.queued), (Err(BindRejected::Invalid), Some(&b"bad"[..])));
        for _ in 1..MAX_SESSION_IDS {
            tracker.record(None, b"bad");
        }
        let recorded = tracker.record(None, b"bad");
        assert_eq!((recorded.result, recorded.queued), (Err(BindRejected::Invalid), None));
        // The replay list is shared, and a change after sharing does not alter the copy
        // already handed out.
        let shared = Arc::clone(tracker.replay());
        let hop = fake_bind(2, 2, true);
        tracker.record(Some(hop.clone()), &contents(&hop));
        assert_eq!(shared.len() + 1, tracker.replay().len());
    }

    #[test]
    fn server_bind_state_tells_missing_from_unrecognised() {
        let mut tracker = BindTracker::new(SocketRole::Forward, true);
        tracker.note_message();
        assert_eq!(tracker.server_bind_state(), ServerBind::Missing);
        record(&mut tracker, fake_bind(1, 1, true)).unwrap();
        assert_eq!(tracker.server_bind_state(), ServerBind::Unrecognised, "bind not first");

        let mut tracker = BindTracker::new(SocketRole::Forward, true);
        refuse(&mut tracker, b"bad").unwrap_err();
        assert_eq!(tracker.server_bind_state(), ServerBind::Unrecognised, "first bind refused");

        let mut tracker = BindTracker::new(SocketRole::Forward, true);
        record(&mut tracker, fake_bind(1, 1, true)).unwrap();
        assert_eq!(tracker.server_bind_state(), ServerBind::Verified);
    }

    /// A local OpenSSH before 8.9 sends no forwarding bind; an ssh 8.9 or later on the
    /// server that logs in to a further host sends an authentication bind, which may be
    /// the first message. That is still a missing server bind, not an unrecognised one.
    #[test]
    fn accepted_auth_binds_leave_the_server_bind_missing() {
        let mut tracker = BindTracker::new(SocketRole::Forward, true);
        assert_eq!(record(&mut tracker, fake_bind(1, 1, false)), Ok(BindEvent::Recorded));
        assert_eq!(tracker.server_bind_state(), ServerBind::Missing, "auth bind first");

        let mut tracker = BindTracker::new(SocketRole::Forward, true);
        tracker.note_message();
        assert_eq!(record(&mut tracker, fake_bind(1, 1, false)), Ok(BindEvent::Recorded));
        assert_eq!(tracker.server_bind_state(), ServerBind::Missing, "auth bind later");

        // A refused bind after the authentication bind makes it unrecognised.
        assert_eq!(record(&mut tracker, fake_bind(2, 2, true)), Err(BindRejected::AfterAuthBind));
        assert_eq!(tracker.server_bind_state(), ServerBind::Unrecognised, "bind refused");
    }

    /// A server behind an ssh client before OpenSSH 8.9 speaks first: a genuine bind of
    /// another server, replayed as the first message, must not select that server.
    #[test]
    fn an_unverified_client_never_selects_a_server() {
        let mut tracker = BindTracker::new(SocketRole::Forward, false);
        assert_eq!(tracker.server_bind_state(), ServerBind::ClientNotVerified);
        assert_eq!(record(&mut tracker, fake_bind(1, 1, true)), Ok(BindEvent::Hop));
        assert!(tracker.server_bind().is_none());
        assert!(tracker.is_hop());
        assert_eq!(record(&mut tracker, fake_bind(2, 2, true)), Ok(BindEvent::Hop));
        assert_eq!(tracker.server_bind_state(), ServerBind::ClientNotVerified);
        // A refused bind does not change the reason.
        refuse(&mut tracker, b"bad").unwrap_err();
        assert_eq!(tracker.server_bind_state(), ServerBind::ClientNotVerified);
        // Authentication binds are recorded as before.
        let mut tracker = BindTracker::new(SocketRole::Forward, false);
        assert_eq!(record(&mut tracker, fake_bind(1, 1, false)), Ok(BindEvent::Recorded));
        assert!(!tracker.is_hop());
        // On agent.sock the flag changes nothing.
        let tracker = BindTracker::new(SocketRole::Local, false);
        assert_eq!(tracker.server_bind_state(), ServerBind::Missing);
    }

    #[test]
    fn login_from_the_server_is_not_a_hop() {
        let mut tracker = BindTracker::new(SocketRole::Forward, true);
        record(&mut tracker, fake_bind(1, 1, true)).unwrap();
        assert_eq!(record(&mut tracker, fake_bind(2, 2, false)), Ok(BindEvent::Recorded));
        assert!(!tracker.is_hop());
        assert_eq!(record(&mut tracker, fake_bind(3, 3, true)), Err(BindRejected::AfterAuthBind));
        assert_eq!(record(&mut tracker, fake_bind(3, 3, false)), Err(BindRejected::AfterAuthBind));
    }

    #[test]
    fn auth_bind_first_never_selects_a_server() {
        let mut tracker = BindTracker::new(SocketRole::Forward, true);
        assert_eq!(record(&mut tracker, fake_bind(1, 1, false)), Ok(BindEvent::Recorded));
        assert!(tracker.server_bind().is_none());
        assert_eq!(record(&mut tracker, fake_bind(2, 2, true)), Err(BindRejected::AfterAuthBind));
    }

    #[test]
    fn local_binds_are_only_recorded() {
        let mut tracker = BindTracker::new(SocketRole::Local, true);
        assert_eq!(record(&mut tracker, fake_bind(1, 1, true)), Ok(BindEvent::Recorded));
        assert_eq!(record(&mut tracker, fake_bind(2, 2, true)), Ok(BindEvent::Recorded));
        assert!(tracker.server_bind().is_none());
        assert!(!tracker.is_hop());
        assert_eq!(tracker.role(), SocketRole::Local);
    }

    #[test]
    fn limits_and_conflicts() {
        let mut tracker = BindTracker::new(SocketRole::Forward, true);
        for i in 0..MAX_SESSION_IDS {
            record(&mut tracker, fake_bind(u8::try_from(i).unwrap(), u8::try_from(i).unwrap(), true))
                .unwrap();
        }
        assert_eq!(record(&mut tracker, fake_bind(200, 200, true)), Err(BindRejected::TooMany));
        // A repeated identical bind is fine even at the limit, a changed one is not.
        assert_eq!(record(&mut tracker, fake_bind(3, 3, true)), Ok(BindEvent::Duplicate));
        assert_eq!(record(&mut tracker, fake_bind(4, 3, true)), Err(BindRejected::Conflict));
        assert_eq!(tracker.binds().len(), MAX_SESSION_IDS);
    }

    #[test]
    fn refused_binds_are_replayed_within_limits() {
        for role in [SocketRole::Local, SocketRole::Forward] {
            let mut tracker = BindTracker::new(role, true);
            // Refused binds are queued as received, in order with accepted ones.
            assert_eq!(refuse(&mut tracker, b"bad bind"), Err(BindRejected::Invalid));
            record(&mut tracker, fake_bind(1, 1, false)).unwrap();
            assert_eq!(record(&mut tracker, fake_bind(2, 2, true)), Err(BindRejected::AfterAuthBind));
            assert_eq!(record(&mut tracker, fake_bind(1, 1, false)), Err(BindRejected::AfterAuthBind));
            assert_eq!(
                **tracker.replay(),
                [
                    b"bad bind".to_vec(),
                    contents(&fake_bind(1, 1, false)),
                    contents(&fake_bind(2, 2, true)),
                    contents(&fake_bind(1, 1, false)),
                ]
            );

            // A long refused bind is replaced by an empty one.
            let mut tracker = BindTracker::new(role, true);
            let long = vec![7; MAX_REPLAYED_REFUSED_LEN + 1];
            refuse(&mut tracker, &long).unwrap_err();
            refuse(&mut tracker, &long[1..]).unwrap_err();
            assert_eq!(**tracker.replay(), [Vec::new(), long[1..].to_vec()]);

            // At most MAX_SESSION_IDS refused binds are queued; accepted ones still are.
            let mut tracker = BindTracker::new(role, true);
            for _ in 0..3 * MAX_SESSION_IDS {
                refuse(&mut tracker, b"bad").unwrap_err();
            }
            assert_eq!(tracker.replay().len(), MAX_SESSION_IDS);
            record(&mut tracker, fake_bind(1, 1, true)).unwrap();
            assert_eq!(tracker.replay().len(), MAX_SESSION_IDS + 1);
            assert!(tracker.server_bind().is_none());
        }
    }
}
