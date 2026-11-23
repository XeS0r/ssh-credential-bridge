//! Async reading and writing of agent frames and IPC frames on tokio streams. The
//! layouts and limits come from `credential_bridge_proto` (`agent::frame_len`,
//! `ipc::frame_len`).

use std::time::Duration;

use credential_bridge_proto::agent::{self, AgentError};
use credential_bridge_proto::ipc::{self, IpcError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

/// Reads the 4-byte header; `Ok(None)` on a clean end of stream before it.
async fn read_header<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Option<[u8; 4]>> {
    let mut header = [0u8; 4];
    let mut filled = 0;
    while filled < header.len() {
        match reader.read(&mut header[filled..]).await? {
            0 if filled == 0 => return Ok(None),
            0 => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            n => filled += n,
        }
    }
    Ok(Some(header))
}

/// Maps an unexpected end of stream inside a frame to `Truncated`.
fn agent_io(error: std::io::Error) -> AgentError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        AgentError::Truncated
    } else {
        AgentError::Io(error)
    }
}

/// Reads one agent frame and returns its payload. `Ok(None)` on a clean end of stream.
/// Oversized lengths are rejected before anything is allocated. The payload is wiped
/// when dropped (it may carry private keys or passphrases).
pub(crate) async fn read_agent_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Zeroizing<Vec<u8>>>, AgentError> {
    let Some(header) = read_header(reader).await.map_err(agent_io)? else { return Ok(None) };
    let len = agent::frame_len(header)?;
    let mut payload = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut payload).await.map_err(agent_io)?;
    Ok(Some(payload))
}

/// Reads one agent frame like [`read_agent_frame`], with deadlines: the first byte must
/// arrive within `idle` (if set), the rest of the frame within `rest` of it. A missed
/// deadline is an [`std::io::ErrorKind::TimedOut`] error. If `stopped` completes before
/// the first byte arrives, the result is `Ok(None)` as at the end of the stream; once a
/// frame has begun, it is read to its end.
pub(crate) async fn read_agent_frame_within<R: AsyncRead + Unpin>(
    reader: &mut R,
    idle: Option<Duration>,
    rest: Duration,
    stopped: impl Future<Output = ()>,
) -> Result<Option<Zeroizing<Vec<u8>>>, AgentError> {
    let timed_out = || AgentError::Io(std::io::ErrorKind::TimedOut.into());
    let mut first = [0u8; 1];
    let read = async {
        let read = reader.read(&mut first);
        match idle {
            Some(idle) => tokio::time::timeout(idle, read).await.map_err(|_| timed_out()),
            None => Ok(read.await),
        }
    };
    // Reading into `first` is cancel-safe: nothing has been read when `stopped` wins.
    let read = tokio::select! {
        biased;
        read = read => read?,
        () = stopped => return Ok(None),
    };
    if read.map_err(agent_io)? == 0 {
        return Ok(None);
    }
    let frame = async {
        let mut header = [first[0], 0, 0, 0];
        reader.read_exact(&mut header[1..]).await.map_err(agent_io)?;
        let len = agent::frame_len(header)?;
        let mut payload = Zeroizing::new(vec![0u8; len]);
        reader.read_exact(&mut payload).await.map_err(agent_io)?;
        Ok(Some(payload))
    };
    tokio::time::timeout(rest, frame).await.map_err(|_| timed_out())?
}

/// Writes one agent frame (length prefix and payload in one write).
pub(crate) async fn write_agent_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> std::io::Result<()> {
    if payload.is_empty() || payload.len() > agent::MAX_MESSAGE_LEN {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "agent message size out of range"));
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(payload.len() + 4));
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap_or(u32::MAX).to_be_bytes());
    frame.extend_from_slice(payload);
    writer.write_all(&frame).await?;
    writer.flush().await
}

/// Reads one IPC frame body (version byte and JSON). `Ok(None)` on a clean end of
/// stream.
pub(crate) async fn read_ipc_body<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Zeroizing<Vec<u8>>>, IpcError> {
    let header = match read_header(reader).await {
        Ok(Some(header)) => header,
        Ok(None) => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Err(IpcError::Truncated),
        Err(error) => return Err(IpcError::Io(error)),
    };
    let len = ipc::frame_len(header)?;
    let mut body = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut body).await.map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            IpcError::Truncated
        } else {
            IpcError::Io(error)
        }
    })?;
    Ok(Some(body))
}

/// A cancel-safe reader of IPC frame bodies: partial progress is kept in the reader
/// across calls, so a [`IpcReader::next_body`] future dropped inside `tokio::select!`
/// loses nothing and the next call continues the same frame (unlike [`read_ipc_body`],
/// whose partly read header and body live in the dropped future).
///
/// Bytes are read straight into their final place: the header into a fixed 4-byte
/// array, the body into a buffer of exactly the frame's size, allocated once per frame.
/// Secret-holding memory is therefore never reallocated (which would free the old block
/// unwiped) and never keeps bytes of earlier frames.
pub(crate) struct IpcReader<R> {
    /// The stream.
    reader: R,
    /// The header of the current frame, filled up to `header_filled`.
    header: [u8; 4],
    /// How many header bytes have arrived.
    header_filled: usize,
    /// The body of the current frame once its header is complete, filled up to
    /// `body_filled` (wiped on drop).
    body: Option<Zeroizing<Vec<u8>>>,
    /// How many body bytes have arrived.
    body_filled: usize,
}

impl<R: AsyncRead + Unpin> IpcReader<R> {
    /// A reader for `reader`.
    pub(crate) fn new(reader: R) -> Self {
        Self { reader, header: [0; 4], header_filled: 0, body: None, body_filled: 0 }
    }

    /// Whether no part of a frame has arrived since the last complete one.
    pub(crate) fn between_frames(&self) -> bool {
        self.header_filled == 0 && self.body.is_none()
    }

    /// The next frame body (version byte and JSON); `Ok(None)` at a clean end of stream
    /// between frames. Cancel-safe: the only await point is a single `read` into the
    /// header or body, whose progress is recorded before the next await.
    pub(crate) async fn next_body(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, IpcError> {
        loop {
            let n = match &mut self.body {
                Some(body) if self.body_filled == body.len() => {
                    self.header_filled = 0;
                    self.body_filled = 0;
                    return Ok(self.body.take());
                }
                Some(body) => self.reader.read(&mut body[self.body_filled..]).await?,
                None if self.header_filled == self.header.len() => {
                    let len = ipc::frame_len(self.header)?;
                    self.body = Some(Zeroizing::new(vec![0u8; len]));
                    continue;
                }
                None => self.reader.read(&mut self.header[self.header_filled..]).await?,
            };
            if n == 0 {
                return if self.between_frames() { Ok(None) } else { Err(IpcError::Truncated) };
            }
            if self.body.is_some() {
                self.body_filled += n;
            } else {
                self.header_filled += n;
            }
        }
    }
}

/// Encodes and writes one IPC frame.
pub(crate) async fn write_ipc<W: AsyncWrite + Unpin, T: serde::Serialize>(
    writer: &mut W,
    message: &T,
) -> Result<(), IpcError> {
    let frame = Zeroizing::new(ipc::encode_frame(message)?);
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn agent_frames_round_trip_and_limits() {
        let mut buf = Vec::new();
        write_agent_frame(&mut buf, &[11]).await.unwrap();
        let mut reader = buf.as_slice();
        assert_eq!(read_agent_frame(&mut reader).await.unwrap().unwrap().as_slice(), &[11]);
        assert!(read_agent_frame(&mut reader).await.unwrap().is_none());

        let too_big = (u32::try_from(agent::MAX_MESSAGE_LEN).unwrap() + 1).to_be_bytes();
        assert!(matches!(read_agent_frame(&mut too_big.as_slice()).await, Err(AgentError::TooLarge { .. })));
        let truncated = [0, 0, 0, 5, 11];
        assert!(matches!(read_agent_frame(&mut truncated.as_slice()).await, Err(AgentError::Truncated)));
        assert!(matches!(read_agent_frame(&mut [0u8, 0].as_slice()).await, Err(AgentError::Truncated)));
        assert!(write_agent_frame(&mut Vec::new(), &[]).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn agent_frame_deadlines() {
        let short = Duration::from_secs(1);
        let mut buf = Vec::new();
        write_agent_frame(&mut buf, &[11, 12]).await.unwrap();
        let mut reader = buf.as_slice();
        let running = std::future::pending;
        let payload =
            read_agent_frame_within(&mut reader, Some(short), short, running()).await.unwrap().unwrap();
        assert_eq!(payload.as_slice(), &[11, 12]);
        assert!(read_agent_frame_within(&mut reader, Some(short), short, running()).await.unwrap().is_none());

        let timed_out = |result: Result<_, AgentError>| matches!(result, Err(AgentError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut);
        // Nothing arrives: the idle deadline ends it.
        let (_client, mut server) = tokio::io::duplex(64);
        assert!(timed_out(read_agent_frame_within(&mut server, Some(short), short, running()).await));
        // Half a frame arrives and then nothing: the frame deadline ends it, also
        // without an idle deadline.
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut client, &[0, 0, 0, 5, 11]).await.unwrap();
        assert!(timed_out(read_agent_frame_within(&mut server, None, short, running()).await));
    }

    /// A stop ends the wait for the next frame at once, but not a frame that has begun.
    #[tokio::test(start_paused = true)]
    async fn agent_frame_wait_ends_on_stop() {
        let long = Duration::from_secs(60);
        let (_client, mut server) = tokio::io::duplex(64);
        let begun = tokio::time::Instant::now();
        let stopped = tokio::time::sleep(Duration::from_millis(10));
        assert!(read_agent_frame_within(&mut server, Some(long), long, stopped).await.unwrap().is_none());
        assert!(begun.elapsed() < Duration::from_secs(1));

        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut client, &[0, 0, 0, 2, 11]).await.unwrap();
        let finish = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            tokio::io::AsyncWriteExt::write_all(&mut client, &[12]).await.unwrap();
        };
        let (read, ()) =
            tokio::join!(read_agent_frame_within(&mut server, None, long, std::future::ready(())), finish);
        assert_eq!(read.unwrap().unwrap().as_slice(), &[11, 12]);
    }

    #[tokio::test]
    async fn ipc_frames_round_trip() {
        let mut buf = Vec::new();
        write_ipc(&mut buf, &vec!["a".to_owned()]).await.unwrap();
        let body = read_ipc_body(&mut buf.as_slice()).await.unwrap().unwrap();
        let back: Vec<String> = ipc::decode_body(&body).unwrap();
        assert_eq!(back, ["a"]);
        assert!(read_ipc_body(&mut [0u8, 0, 0, 0].as_slice()).await.is_err());
    }

    #[tokio::test]
    async fn ipc_reader_survives_cancellation() {
        let mut frames = Vec::new();
        write_ipc(&mut frames, &vec!["first".to_owned()]).await.unwrap();
        write_ipc(&mut frames, &vec!["second".to_owned()]).await.unwrap();
        let (mut client, server) = tokio::io::duplex(1024);
        let mut reader = IpcReader::new(server);
        // Half of the first frame arrives; the read is cancelled meanwhile.
        client.write_all(&frames[..7]).await.unwrap();
        let cancelled = tokio::time::timeout(Duration::from_millis(20), reader.next_body()).await;
        assert!(cancelled.is_err());
        // The rest arrives: the frame is complete, nothing was lost.
        client.write_all(&frames[7..]).await.unwrap();
        for expected in ["first", "second"] {
            let body = reader.next_body().await.unwrap().unwrap();
            assert_eq!(ipc::decode_body::<Vec<String>>(&body).unwrap(), [expected]);
        }
        drop(client);
        assert!(reader.next_body().await.unwrap().is_none());

        // An end of stream inside a frame is `Truncated`.
        let (mut client, server) = tokio::io::duplex(64);
        client.write_all(&[0, 0, 0, 5, 1]).await.unwrap();
        drop(client);
        assert!(matches!(IpcReader::new(server).next_body().await, Err(IpcError::Truncated)));
    }

    /// Frames that arrive a few bytes at a time, with the header split and two frames in
    /// one write, come out whole and in order.
    #[tokio::test]
    async fn ipc_reader_assembles_frames_from_pieces() {
        let mut frames = Vec::new();
        write_ipc(&mut frames, &vec!["first".to_owned()]).await.unwrap();
        let first_len = frames.len();
        write_ipc(&mut frames, &vec!["x".repeat(300)]).await.unwrap();
        write_ipc(&mut frames, &vec!["third".to_owned()]).await.unwrap();
        let (mut client, server) = tokio::io::duplex(4096);
        let writer = tokio::spawn(async move {
            // Two header bytes, then the rest of the first frame and the start of the
            // second in one write, then the remainder in 7-byte pieces.
            let split = first_len + 9;
            for piece in [&frames[..2], &frames[2..split]].into_iter().chain(frames[split..].chunks(7)) {
                client.write_all(piece).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let mut reader = IpcReader::new(server);
        let expected = ["first".to_owned(), "x".repeat(300), "third".to_owned()];
        for expected in &expected {
            let body = reader.next_body().await.unwrap().unwrap();
            assert_eq!(body.capacity(), body.len(), "the body is allocated at its exact size");
            assert_eq!(&ipc::decode_body::<Vec<String>>(&body).unwrap(), std::slice::from_ref(expected));
        }
        writer.await.unwrap();
        assert!(reader.next_body().await.unwrap().is_none());
    }
}
