//! The gpg worker's loop: receives gpg-agent descriptors with `gpg::Request::Open`
//! (`SCM_RIGHTS`), runs one [`credential_bridge_gpg::session::FilterSession`] per tunnel
//! and relays filtered traffic.
//!
//! The worker never opens files or sockets (its sandbox forbids it); every gpg-agent
//! connection arrives as a descriptor attached to the first byte of its `Open` frame.
//! Tunnels are served concurrently; requests of one tunnel one after another.

use std::collections::{HashMap, VecDeque};
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use credential_bridge_gpg::framing::{Turn, TurnCollector, append_zeroizing, consume_zeroizing};
use credential_bridge_gpg::session::{FilterSession, SessionState, UnitAction};
use credential_bridge_proto::ipc::gpg::{ConnId, GpgPolicy, Request, Response};
use credential_bridge_proto::ipc::{
    FromWorker, IpcError, ToWorker, WorkerError, WorkerErrorKind, decode_body, frame_len,
};
use credential_bridge_proto::secret::SecretBytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedReadHalf;
use tokio::task::JoinSet;
use zeroize::Zeroizing;

use super::{FrameWriter, send_frame};

/// How long gpg-agent may take for its greeting.
const GREETING_TIMEOUT: Duration = Duration::from_secs(30);

/// How long gpg-agent may take for a turn: pinentry and card PINs happen inside it, and
/// the core's own deadline is a little longer.
const TURN_TIMEOUT: Duration = Duration::from_secs(110);

/// One tunnel: filter state, the gpg-agent connection and its turn buffer.
#[derive(Debug)]
pub struct Tunnel {
    /// The filter.
    session: FilterSession,
    /// The gpg-agent connection.
    agent: UnixStream,
    /// Output of gpg-agent not yet returned.
    collector: TurnCollector,
}

/// Open tunnels by id.
pub type Tunnels = HashMap<ConnId, Arc<tokio::sync::Mutex<Tunnel>>>;

/// Shared tunnel table.
type SharedTunnels = Arc<Mutex<Tunnels>>;

/// A descriptor and the stream bytes of the `recvmsg` that delivered it.
///
/// On Linux a unix stream `recvmsg` may return data sent before the descriptor's
/// message, but it stops after the message that carries descriptors. The core attaches
/// each descriptor to the first byte of its `Open` frame, so that frame starts inside
/// `start..end`.
#[derive(Debug)]
struct ReceivedFd {
    /// Stream offset of the first byte of that `recvmsg`.
    start: u64,
    /// Stream offset just past its last byte.
    end: u64,
    /// The descriptor.
    fd: OwnedFd,
}

/// Reads IPC frames together with the descriptors that arrive with them.
struct FdReader {
    /// The channel.
    reader: OwnedReadHalf,
    /// Bytes received but not yet returned as frames. Grown only by
    /// [`append_zeroizing`], so no stale copy stays behind in freed memory.
    buffer: Zeroizing<Vec<u8>>,
    /// The one buffer `recvmsg` reads into, reused for every read.
    chunk: Zeroizing<Vec<u8>>,
    /// Stream offset of `buffer[0]`.
    offset: u64,
    /// Descriptors received and not yet handed to a frame, in order.
    fds: VecDeque<ReceivedFd>,
}

impl FdReader {
    /// A reader for `reader`.
    fn new(reader: OwnedReadHalf) -> Self {
        Self {
            reader,
            buffer: Zeroizing::new(Vec::new()),
            chunk: Zeroizing::new(vec![0u8; READ_CHUNK]),
            offset: 0,
            fds: VecDeque::new(),
        }
    }

    /// The next frame body and the stream offset where its frame starts; `Ok(None)` at a
    /// clean end of the channel.
    async fn next_frame(&mut self) -> Result<Option<(u64, Zeroizing<Vec<u8>>)>, IpcError> {
        loop {
            if self.buffer.len() >= 4 {
                let header: [u8; 4] = self.buffer[..4].try_into().expect("four bytes");
                let len = frame_len(header)?;
                if self.buffer.len() >= 4 + len {
                    let start = self.offset;
                    let body = Zeroizing::new(self.buffer[4..4 + len].to_vec());
                    consume_zeroizing(&mut self.buffer, 4 + len);
                    self.offset += (4 + len) as u64;
                    return Ok(Some((start, body)));
                }
            }
            let chunk = &mut self.chunk;
            let stream: &UnixStream = self.reader.as_ref();
            let (n, fds) = loop {
                stream.readable().await?;
                match stream.try_io(Interest::READABLE, || {
                    credential_bridge_platform::channel::recv_with_fds(stream, &mut chunk[..])
                }) {
                    Ok(received) => break received,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(error) => return Err(IpcError::Io(error)),
                }
            };
            let start = self.offset + self.buffer.len() as u64;
            let end = start + n as u64;
            self.fds.extend(fds.into_iter().map(|fd| ReceivedFd { start, end, fd }));
            if n == 0 {
                return if self.buffer.is_empty() { Ok(None) } else { Err(IpcError::Truncated) };
            }
            append_zeroizing(&mut self.buffer, &self.chunk[..n]);
            // What was read is in `buffer` now; the read buffer keeps no copy.
            self.chunk[..n].fill(0);
        }
    }

    /// The descriptor that belongs to the frame starting at `frame_start`, if one came
    /// with it. Descriptors that arrived only before `frame_start` belong to frames
    /// already handled and are closed.
    fn take_fd(&mut self, frame_start: u64) -> Option<OwnedFd> {
        self.drop_fds_before(frame_start);
        let index = self.fds.iter().position(|fd| fd.start <= frame_start && frame_start < fd.end)?;
        self.fds.remove(index).map(|fd| fd.fd)
    }

    /// Closes descriptors whose bytes all lie before `offset`: no frame that starts at
    /// or after `offset` can own them.
    fn drop_fds_before(&mut self, offset: u64) {
        self.fds.retain(|fd| fd.end > offset);
    }
}

/// Size of [`FdReader`]'s read buffer.
const READ_CHUNK: usize = 64 * 1024;

/// Serves the channel (a raw descriptor, because descriptors arrive with `recvmsg`)
/// until `Shutdown` or end of channel.
pub async fn serve(channel: OwnedFd) -> anyhow::Result<()> {
    let stream = std::os::unix::net::UnixStream::from(channel);
    stream.set_nonblocking(true)?;
    let (reader, writer) = UnixStream::from_std(stream)?.into_split();
    let writer: FrameWriter = Arc::new(tokio::sync::Mutex::new(writer));
    let mut reader = FdReader::new(reader);
    let tunnels: SharedTunnels = Arc::default();
    let mut tasks = JoinSet::new();
    loop {
        let body = tokio::select! {
            body = reader.next_frame() => body?,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
        };
        let Some((frame_start, body)) = body else { break };
        match decode_body::<ToWorker<Request>>(&body)? {
            ToWorker::Request { id, body } => {
                // Only an Open frame carries a descriptor, attached to its first byte.
                let fd = matches!(body, Request::Open { .. }).then(|| reader.take_fd(frame_start)).flatten();
                let tunnels = Arc::clone(&tunnels);
                let writer = Arc::clone(&writer);
                tasks.spawn(async move {
                    let result = handle(&tunnels, body, fd).await;
                    send_frame(&writer, &FromWorker::Response { id, result }).await;
                });
            }
            ToWorker::CallbackReply { .. } => tracing::debug!("the gpg worker sends no callbacks"),
            ToWorker::Shutdown => break,
        }
        // Descriptors that came only with frames handled by now are not ours to keep;
        // one that came with a frame still in the buffer stays.
        reader.drop_fds_before(reader.offset);
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// Locks the tunnel table, ignoring poisoning.
fn table(tunnels: &SharedTunnels) -> std::sync::MutexGuard<'_, Tunnels> {
    crate::sync::lock(tunnels)
}

/// Serves one request.
async fn handle(
    tunnels: &SharedTunnels,
    request: Request,
    fd: Option<OwnedFd>,
) -> Result<Response, WorkerError> {
    match request {
        Request::Open { conn, policy } => {
            let fd = fd.ok_or_else(|| invalid("Open without a gpg-agent descriptor"))?;
            open(tunnels, conn, policy, fd).await
        }
        Request::Input { conn, data } => {
            let tunnel = table(tunnels).get(&conn).cloned().ok_or_else(|| invalid("unknown gpg tunnel"))?;
            let mut tunnel = tunnel.lock().await;
            let result = input(&mut tunnel, data.expose()).await;
            if result.is_err() || tunnel.session.state() == SessionState::Closed {
                table(tunnels).remove(&conn);
            }
            result
        }
        Request::Close { conn } => {
            table(tunnels).remove(&conn);
            Ok(Response::Closed)
        }
    }
}

/// Takes over the gpg-agent connection and returns its greeting.
async fn open(
    tunnels: &SharedTunnels,
    conn: ConnId,
    policy: GpgPolicy,
    fd: OwnedFd,
) -> Result<Response, WorkerError> {
    let stream = std::os::unix::net::UnixStream::from(fd);
    let agent =
        stream.set_nonblocking(true).and_then(|()| UnixStream::from_std(stream)).map_err(|error| {
            WorkerError::new(WorkerErrorKind::Internal, format!("gpg-agent descriptor: {error}"))
        })?;
    let mut tunnel = Tunnel { session: FilterSession::new(policy), agent, collector: TurnCollector::new() };
    let greeting = read_turn(&mut tunnel, GREETING_TIMEOUT).await?;
    tunnel.session.server_turn(&greeting).map_err(|error| upstream(&error.to_string()))?;
    if tunnel.session.state() != SessionState::Idle {
        return Err(upstream("gpg-agent refused the connection"));
    }
    let mut table = table(tunnels);
    if table.contains_key(&conn) {
        return Err(invalid("gpg tunnel id in use"));
    }
    table.insert(conn, Arc::new(tokio::sync::Mutex::new(tunnel)));
    // Moved, not copied: the buffer stays wiped on drop.
    Ok(Response::Opened(SecretBytes::from_zeroizing(greeting.bytes)))
}

/// Filters one client unit and returns gpg-agent's turn or the local answer, with the
/// command's verb and the filter's decision.
async fn input(tunnel: &mut Tunnel, data: &[u8]) -> Result<Response, WorkerError> {
    let command = credential_bridge_gpg::session::command_verb(data);
    let output = |data: SecretBytes, denied| Response::Output { data, command: command.clone(), denied };
    match tunnel.session.client_unit(data).map_err(|error| invalid(&error.to_string()))? {
        UnitAction::Reply(bytes) => Ok(output(bytes.into(), false)),
        UnitAction::Deny(bytes) => Ok(output(bytes.into(), true)),
        UnitAction::Forward(bytes) => {
            tunnel
                .agent
                .write_all(&bytes)
                .await
                .map_err(|error| upstream(&format!("writing to gpg-agent: {error}")))?;
            drop(bytes);
            let turn = read_turn(tunnel, TURN_TIMEOUT).await?;
            tunnel.session.server_turn(&turn).map_err(|error| upstream(&error.to_string()))?;
            Ok(output(SecretBytes::from_zeroizing(turn.bytes), false))
        }
    }
}

/// Reads gpg-agent output until a turn is complete.
async fn read_turn(tunnel: &mut Tunnel, deadline: Duration) -> Result<Turn, WorkerError> {
    let collect = async {
        if let Some(turn) = tunnel.collector.push(&[]).map_err(|error| upstream(&error.to_string()))? {
            return Ok(turn);
        }
        // gpg-agent output may hold a signature or a session key: wiped when dropped.
        let mut chunk = Zeroizing::new(vec![0u8; 8192]);
        loop {
            let n = tunnel
                .agent
                .read(&mut chunk)
                .await
                .map_err(|error| upstream(&format!("reading from gpg-agent: {error}")))?;
            if n == 0 {
                return Err(upstream("gpg-agent closed the connection"));
            }
            if let Some(turn) =
                tunnel.collector.push(&chunk[..n]).map_err(|error| upstream(&error.to_string()))?
            {
                return Ok(turn);
            }
        }
    };
    tokio::time::timeout(deadline, collect).await.unwrap_or_else(|_| {
        Err(WorkerError::new(WorkerErrorKind::Timeout, "gpg-agent did not answer in time"))
    })
}

/// An `Invalid` error.
fn invalid(message: &str) -> WorkerError {
    WorkerError::new(WorkerErrorKind::Invalid, message)
}

/// An `Upstream` error (gpg-agent misbehaved or went away).
fn upstream(message: &str) -> WorkerError {
    WorkerError::new(WorkerErrorKind::Upstream, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake gpg-agent on one end of a socketpair, answering by a script.
    async fn fake_agent(mut stream: UnixStream) {
        stream.write_all(b"OK Pleased to meet you\n").await.unwrap();
        let mut buf = vec![0u8; 1024];
        let mut pending = Vec::new();
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                return;
            }
            pending.extend_from_slice(&buf[..n]);
            while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = pending.drain(..=pos).collect();
                let reply: &[u8] = match line.as_slice() {
                    b"GETINFO version\n" => b"D 2.4.7\nOK\n",
                    b"PKSIGN\n" => b"INQUIRE PINENTRY_LAUNCHED 1234\n",
                    b"END\n" => b"D (7:sig-val)\nOK\n",
                    b"BYE\n" => b"OK closing connection\n",
                    _ => b"ERR 1 unexpected\n",
                };
                stream.write_all(reply).await.unwrap();
            }
        }
    }

    /// Frames split over many reads and several frames in one read come out whole, with
    /// one read buffer for all reads.
    #[tokio::test]
    async fn fd_reader_reassembles_frames() {
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        ours.set_nonblocking(true).unwrap();
        let (reader, _writer) = UnixStream::from_std(ours).unwrap().into_split();
        let mut reader = FdReader::new(reader);
        let chunk = reader.chunk.as_ptr();
        let mut theirs = theirs;
        let big = vec![7u8; 3 * READ_CHUNK];
        let mut bytes = Vec::new();
        for body in [b"one".as_slice(), &big, b"three"] {
            bytes.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(body);
        }
        let writer = std::thread::spawn(move || {
            use std::io::Write as _;
            theirs.write_all(&bytes).unwrap();
        });
        let (start, one) = reader.next_frame().await.unwrap().unwrap();
        assert_eq!((start, one.as_slice()), (0, b"one".as_slice()));
        let (_, two) = reader.next_frame().await.unwrap().unwrap();
        assert_eq!(two.as_slice(), big.as_slice());
        let (_, three) = reader.next_frame().await.unwrap().unwrap();
        assert_eq!(three.as_slice(), b"three");
        writer.join().unwrap();
        assert_eq!(reader.next_frame().await.unwrap(), None);
        assert_eq!(reader.chunk.as_ptr(), chunk, "the read buffer is reused");
    }

    fn output(data: &[u8], command: Option<&str>, denied: bool) -> Response {
        Response::Output { data: data.to_vec().into(), command: command.map(str::to_owned), denied }
    }

    fn pair() -> (OwnedFd, UnixStream) {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        b.set_nonblocking(true).unwrap();
        (OwnedFd::from(a), UnixStream::from_std(b).unwrap())
    }

    #[tokio::test]
    async fn filters_and_relays() {
        let tunnels: SharedTunnels = Arc::default();
        let (fd, agent) = pair();
        tokio::spawn(fake_agent(agent));
        let policy = GpgPolicy { sign: true, decrypt: false };
        let opened = handle(&tunnels, Request::Open { conn: 1, policy }, Some(fd)).await.unwrap();
        assert_eq!(opened, Response::Opened(b"OK Pleased to meet you\n".to_vec().into()));

        let input = |data: &[u8]| Request::Input { conn: 1, data: data.to_vec().into() };
        assert_eq!(
            handle(&tunnels, input(b"GETINFO version\n"), None).await.unwrap(),
            output(b"D 2.4.7\nOK\n", Some("GETINFO"), false)
        );
        let Response::Output { data, command, denied } =
            handle(&tunnels, input(b"PKDECRYPT\n"), None).await.unwrap()
        else {
            panic!()
        };
        assert!(data.expose().starts_with(b"ERR 67109115 "), "{}", String::from_utf8_lossy(data.expose()));
        assert_eq!((command.as_deref(), denied), (Some("PKDECRYPT"), true));
        // Answered locally, not denied.
        assert_eq!(
            handle(&tunnels, input(b"OPTION display=:0\n"), None).await.unwrap(),
            output(b"OK\n", Some("OPTION"), false)
        );
        // gpg-agent's own ERR is not a filter denial.
        assert_eq!(
            handle(&tunnels, input(b"HAVEKEY x\n"), None).await.unwrap(),
            output(b"ERR 1 unexpected\n", Some("HAVEKEY"), false)
        );
        assert_eq!(
            handle(&tunnels, input(b"PKSIGN\n"), None).await.unwrap(),
            output(b"INQUIRE PINENTRY_LAUNCHED 1234\n", Some("PKSIGN"), false)
        );
        assert_eq!(
            handle(&tunnels, input(b"END\n"), None).await.unwrap(),
            output(b"D (7:sig-val)\nOK\n", None, false)
        );
        // Out of order input closes the tunnel.
        assert!(handle(&tunnels, input(b"D x\nEND\n"), None).await.is_err());
        assert!(handle(&tunnels, input(b"GETINFO version\n"), None).await.is_err());
        assert_eq!(handle(&tunnels, Request::Close { conn: 1 }, None).await.unwrap(), Response::Closed);
    }

    /// An Input frame and an Open frame with its descriptor, queued back to back before
    /// the worker reads: one `recvmsg` returns both, and the descriptor must still reach
    /// the Open.
    #[tokio::test]
    async fn descriptor_follows_its_open_frame() {
        use credential_bridge_proto::ipc::encode_frame;
        use std::io::Write as _;
        use std::os::fd::AsFd as _;

        let (core, worker) = std::os::unix::net::UnixStream::pair().unwrap();
        let input =
            ToWorker::Request { id: 1, body: Request::Input { conn: 9, data: b"NOP\n".to_vec().into() } };
        let policy = GpgPolicy::default();
        let open = ToWorker::Request { id: 2, body: Request::Open { conn: 1, policy } };
        let (agent_fd, agent) = pair();
        tokio::spawn(fake_agent(agent));
        (&core).write_all(&encode_frame(&input).unwrap()).unwrap();
        let open_frame = encode_frame(&open).unwrap();
        let sent =
            credential_bridge_platform::channel::send_with_fds(&core, &open_frame, &[agent_fd.as_fd()])
                .unwrap();
        (&core).write_all(&open_frame[sent..]).unwrap();
        drop(agent_fd);
        (&core).write_all(&encode_frame(&ToWorker::<Request>::Shutdown).unwrap()).unwrap();

        serve(OwnedFd::from(worker)).await.unwrap();
        core.set_nonblocking(true).unwrap();
        let mut core = tokio::net::UnixStream::from_std(core).unwrap();
        let mut results = HashMap::new();
        for _ in 0..2 {
            let body = crate::frame::read_ipc_body(&mut core).await.unwrap().unwrap();
            let FromWorker::Response { id, result } = decode_body::<FromWorker<Response>>(&body).unwrap()
            else {
                panic!("not a response")
            };
            results.insert(id, result);
        }
        assert!(results[&1].is_err(), "Input for an unknown tunnel fails");
        assert_eq!(results[&2], Ok(Response::Opened(b"OK Pleased to meet you\n".to_vec().into())));
    }

    #[tokio::test]
    async fn bye_closes_and_open_needs_a_descriptor() {
        let tunnels: SharedTunnels = Arc::default();
        let policy = GpgPolicy::default();
        assert!(handle(&tunnels, Request::Open { conn: 1, policy }, None).await.is_err());
        let (fd, agent) = pair();
        tokio::spawn(fake_agent(agent));
        handle(&tunnels, Request::Open { conn: 2, policy }, Some(fd)).await.unwrap();
        let bye = Request::Input { conn: 2, data: b"BYE\n".to_vec().into() };
        assert_eq!(
            handle(&tunnels, bye, None).await.unwrap(),
            output(b"OK closing connection\n", Some("BYE"), false)
        );
        assert!(table(&tunnels).is_empty());
    }
}
