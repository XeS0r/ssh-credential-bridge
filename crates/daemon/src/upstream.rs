//! Connections to upstream agents. For every client connection the proxy opens its own
//! connection to each upstream (lazily, on first need) and replays every bind on it, so
//! destination constraints keep working. Binds are replayed as the client sent them, the
//! ones the proxy refused included ([`crate::bind::BindTracker::replay`]). An upstream
//! that rejects a bind is not an error, and its answer changes nothing in the proxy.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use credential_bridge_proto::agent::{AgentError, Identity, Message};
use credential_bridge_proto::ext;
use tokio::net::UnixStream;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::bind::Replay;
use crate::frame::{read_agent_frame, write_agent_frame};

/// Timeout for one upstream request. Leaves room for touch, PIN and approval prompts.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(120);

/// Timeout for connecting to an upstream.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for a bind replay or an identity list: neither involves the user.
const QUICK_TIMEOUT: Duration = Duration::from_secs(15);

/// One upstream as resolved at start (`gpgconf:` already turned into a path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamTarget {
    /// `[[agent.upstream]]` name.
    pub name: String,
    /// The socket path.
    pub socket: PathBuf,
}

/// Errors talking to an upstream. The client always gets `SSH_AGENT_FAILURE`.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// Connecting failed (agent not running).
    #[error("upstream {name} unreachable: {source}")]
    Connect {
        /// Upstream name.
        name: String,
        /// The cause.
        source: std::io::Error,
    },
    /// The exchange failed.
    #[error("upstream {name}: {source}")]
    Protocol {
        /// Upstream name.
        name: String,
        /// The cause.
        source: AgentError,
    },
    /// No answer within [`UPSTREAM_TIMEOUT`].
    #[error("upstream {name} timed out")]
    Timeout {
        /// Upstream name.
        name: String,
    },
}

/// The upstream connections of one client connection.
#[derive(Debug)]
pub struct UpstreamSet {
    /// The targets, in configuration order.
    targets: Vec<UpstreamTarget>,
    /// The open connection per target (same index), if any.
    conns: Vec<Option<UnixStream>>,
}

impl UpstreamSet {
    /// A set that has not connected anywhere yet.
    pub fn new(targets: Vec<UpstreamTarget>) -> Self {
        let conns = targets.iter().map(|_| None).collect();
        Self { targets, conns }
    }

    /// The targets.
    pub fn targets(&self) -> &[UpstreamTarget] {
        &self.targets
    }

    /// Sends `message` to upstream `index` (connecting and replaying `binds` first if
    /// needed) and returns the raw reply unchanged.
    pub async fn request(
        &mut self,
        index: usize,
        message: &Message,
        binds: &[Vec<u8>],
    ) -> Result<Message, UpstreamError> {
        let target = self.targets.get(index).cloned().ok_or_else(|| UpstreamError::Connect {
            name: format!("#{index}"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "no such upstream"),
        })?;
        let mut conn = match self.conns[index].take() {
            Some(conn) => conn,
            None => connect(&target, binds).await?,
        };
        let payload = message.encode_zeroizing();
        let reply = exchange_timed(&target, &mut conn, &payload, UPSTREAM_TIMEOUT).await?;
        self.conns[index] = Some(conn);
        Ok(reply)
    }

    /// Replays new bind contents on every upstream already connected; rejections are
    /// ignored. A connection that fails is dropped (the next request reconnects and
    /// replays all binds).
    pub async fn replay_bind(&mut self, contents: &[u8]) {
        let payload = bind_message(contents).encode();
        for (target, slot) in self.targets.iter().zip(&mut self.conns) {
            let Some(conn) = slot.as_mut() else { continue };
            if let Err(error) = exchange_timed(target, conn, &payload, QUICK_TIMEOUT).await {
                tracing::debug!("dropping the connection: {error}");
                *slot = None;
            }
        }
    }

    /// Asks every upstream for its identities concurrently; unreachable upstreams
    /// contribute nothing (logged).
    /// The replay list is shared with the tasks, not copied.
    pub async fn all_identities(&mut self, binds: &Replay) -> Vec<(usize, Vec<Identity>)> {
        let mut tasks = JoinSet::new();
        for (index, target) in self.targets.iter().enumerate() {
            let conn = self.conns[index].take();
            let target = target.clone();
            let binds = Arc::clone(binds);
            tasks.spawn(async move {
                let result = identities(&target, conn, &binds).await;
                (index, target, result)
            });
        }
        let mut lists = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            let Ok((index, target, result)) = joined else { continue };
            match result {
                Ok((conn, list)) => {
                    self.conns[index] = Some(conn);
                    lists.push((index, list));
                }
                Err(error) => tracing::warn!("upstream {}: {error}", target.name),
            }
        }
        lists.sort_by_key(|(index, _)| *index);
        lists
    }

    /// The identities of one upstream, with the error if it cannot be asked (for
    /// `ctl check`).
    pub async fn identities_of(
        &mut self,
        index: usize,
        binds: &[Vec<u8>],
    ) -> Result<Vec<Identity>, UpstreamError> {
        let name = self.targets.get(index).map(|t| t.name.clone()).unwrap_or_default();
        match self.request(index, &Message::RequestIdentities, binds).await? {
            Message::IdentitiesAnswer(list) => Ok(list),
            other => Err(UpstreamError::Protocol {
                name,
                source: AgentError::UnexpectedReply { msg_type: other.msg_type() },
            }),
        }
    }
}

/// Connects (if `conn` is `None`) and lists identities; returns the connection for
/// reuse.
async fn identities(
    target: &UpstreamTarget,
    conn: Option<UnixStream>,
    binds: &[Vec<u8>],
) -> Result<(UnixStream, Vec<Identity>), UpstreamError> {
    let mut conn = match conn {
        Some(conn) => conn,
        None => connect(target, binds).await?,
    };
    let payload = Message::RequestIdentities.encode();
    match exchange_timed(target, &mut conn, &payload, QUICK_TIMEOUT).await? {
        Message::IdentitiesAnswer(list) => Ok((conn, list)),
        other => Err(UpstreamError::Protocol {
            name: target.name.clone(),
            source: AgentError::UnexpectedReply { msg_type: other.msg_type() },
        }),
    }
}

/// Opens a connection and replays the bind contents `binds` on it; rejected binds are
/// ignored.
async fn connect(target: &UpstreamTarget, binds: &[Vec<u8>]) -> Result<UnixStream, UpstreamError> {
    let name = || target.name.clone();
    let mut conn = match timeout(CONNECT_TIMEOUT, UnixStream::connect(&target.socket)).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(source)) => return Err(UpstreamError::Connect { name: name(), source }),
        Err(_) => return Err(UpstreamError::Timeout { name: name() }),
    };
    for contents in binds {
        let reply =
            exchange_timed(target, &mut conn, &bind_message(contents).encode(), QUICK_TIMEOUT).await?;
        if !matches!(reply, Message::Success { .. }) {
            tracing::debug!("upstream {} did not accept a session-bind", target.name);
        }
    }
    Ok(conn)
}

/// One request/response exchange with a deadline.
async fn exchange_timed(
    target: &UpstreamTarget,
    conn: &mut UnixStream,
    payload: &[u8],
    deadline: Duration,
) -> Result<Message, UpstreamError> {
    match timeout(deadline, exchange(conn, payload)).await {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(source)) => Err(UpstreamError::Protocol { name: target.name.clone(), source }),
        Err(_) => Err(UpstreamError::Timeout { name: target.name.clone() }),
    }
}

/// Writes `payload` as one frame and reads the reply.
async fn exchange(conn: &mut UnixStream, payload: &[u8]) -> Result<Message, AgentError> {
    write_agent_frame(conn, payload).await?;
    let reply = read_agent_frame(conn).await?.ok_or(AgentError::Truncated)?;
    Message::decode(&reply)
}

/// The `session-bind@openssh.com` request with `contents` byte for byte as the client
/// sent them. Only ever a `session-bind`: the name is fixed here.
pub fn bind_message(contents: &[u8]) -> Message {
    Message::Extension { name: ext::SESSION_BIND.to_owned(), contents: contents.to_vec() }
}

#[cfg(test)]
mod tests {
    use tokio::net::UnixListener;

    use super::*;
    use crate::bind::tests::{contents, fake_bind};

    /// A fake agent answering each request with the list it was given (identities), a
    /// SUCCESS for extensions and FAILURE otherwise; it reports every request type.
    async fn fake_agent(
        listener: UnixListener,
        keys: Vec<Identity>,
        seen: tokio::sync::mpsc::UnboundedSender<Message>,
    ) {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else { return };
            let keys = keys.clone();
            let seen = seen.clone();
            tokio::spawn(async move {
                while let Ok(Some(payload)) = read_agent_frame(&mut conn).await {
                    let message = Message::decode(&payload).unwrap();
                    let reply = match &message {
                        Message::RequestIdentities => Message::IdentitiesAnswer(keys.clone()),
                        Message::Extension { .. } => Message::Success { contents: vec![] },
                        _ => Message::Failure,
                    };
                    let _ = seen.send(message);
                    write_agent_frame(&mut conn, &reply.encode()).await.unwrap();
                }
            });
        }
    }

    #[tokio::test]
    async fn lists_replays_binds_and_survives_dead_upstreams() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("a.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let key = Identity { key_blob: vec![1, 2], comment: b"k".to_vec() };
        tokio::spawn(fake_agent(listener, vec![key.clone()], tx));

        let targets = vec![
            UpstreamTarget { name: "dead".into(), socket: dir.path().join("missing.sock") },
            UpstreamTarget { name: "fake".into(), socket },
        ];
        let mut set = UpstreamSet::new(targets);
        let first = contents(&fake_bind(1, 1, true));
        let lists = set.all_identities(&Arc::new(vec![first.clone()])).await;
        assert_eq!(lists, vec![(1, vec![key])]);
        // The bind was replayed before the list.
        assert_eq!(rx.recv().await.unwrap(), bind_message(&first));
        assert_eq!(rx.recv().await.unwrap(), Message::RequestIdentities);

        // A new bind goes to the open connection.
        let second = contents(&fake_bind(2, 2, true));
        set.replay_bind(&second).await;
        assert_eq!(rx.recv().await.unwrap(), bind_message(&second));

        let sign = Message::SignRequest { key_blob: vec![1, 2], data: vec![3], flags: 0 };
        assert_eq!(set.request(1, &sign, &[]).await.unwrap(), Message::Failure);
        assert_eq!(rx.recv().await.unwrap(), sign);
        assert!(matches!(set.request(0, &sign, &[]).await, Err(UpstreamError::Connect { .. })));
        assert!(set.request(7, &sign, &[]).await.is_err());
    }

    #[test]
    fn bind_message_is_a_session_bind_with_the_contents() {
        let contents = contents(&fake_bind(1, 1, false));
        assert_eq!(
            bind_message(&contents),
            Message::Extension { name: ext::SESSION_BIND.to_owned(), contents: contents.clone() }
        );
    }
}
