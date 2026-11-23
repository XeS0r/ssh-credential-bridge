//! The git worker's loop: serves `git::Request`s with
//! [`credential_bridge_forge::GitWorker`] concurrently and implements
//! [`credential_bridge_forge::SecretProvider`] with `Callback::Secret` round trips.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use credential_bridge_forge::github::GithubClient;
use credential_bridge_forge::{ForgeError, SecretProvider};
use credential_bridge_proto::ipc::{
    Callback, CallbackReply, FromWorker, RequestId, ToWorker, WorkerError, WorkerErrorKind, decode_body, git,
};
use credential_bridge_proto::secret::Secret;
use tokio::sync::oneshot;
use tokio::task::JoinSet;

use super::{FrameWriter, send_frame};
use crate::frame::IpcReader;
use crate::sync::lock;

tokio::task_local! {
    /// The core's id of the request a task serves (for `Callback::for_request`).
    static CURRENT_REQUEST: RequestId;
}

/// Answers to callbacks, by callback id.
type Waiting = Arc<Mutex<HashMap<RequestId, oneshot::Sender<Result<CallbackReply, WorkerError>>>>>;

/// [`SecretProvider`] that asks the core.
#[derive(Debug)]
pub struct CallbackSecrets {
    /// Frames to the core.
    writer: FrameWriter,
    /// Callbacks waiting for their reply.
    waiting: Waiting,
    /// Callback ids.
    next_id: AtomicU64,
}

impl SecretProvider for CallbackSecrets {
    async fn secret(&self, reference: &str) -> Result<Secret, ForgeError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let for_request = CURRENT_REQUEST.try_with(|id| *id).unwrap_or_default();
        let (tx, rx) = oneshot::channel();
        lock(&self.waiting).insert(id, tx);
        let frame: FromWorker<()> = FromWorker::Callback {
            id,
            for_request,
            body: Callback::Secret { reference: reference.to_owned() },
        };
        send_frame(&self.writer, &frame).await;
        let reply = rx.await.unwrap_or_else(|_| {
            Err(WorkerError::new(WorkerErrorKind::Internal, "the core closed the channel"))
        });
        match reply {
            Ok(CallbackReply::Secret(secret)) => Ok(secret),
            Err(error) => Err(ForgeError::Secret(error)),
        }
    }
}

/// Serves the channel until `Shutdown` or end of channel.
pub async fn serve(channel: tokio::net::UnixStream) -> anyhow::Result<()> {
    let (reader, writer) = channel.into_split();
    // Cancel-safe: the read below races `join_next` in a `select!`.
    let mut reader = IpcReader::new(reader);
    let writer: FrameWriter = Arc::new(tokio::sync::Mutex::new(writer));
    let waiting: Waiting = Arc::default();
    let secrets = CallbackSecrets {
        writer: Arc::clone(&writer),
        waiting: Arc::clone(&waiting),
        next_id: AtomicU64::new(1),
    };
    let github = GithubClient::new().map_err(|error| anyhow::anyhow!("{error}"))?;
    let worker: Arc<Worker<CallbackSecrets>> = Arc::new(credential_bridge_forge::GitWorker::new(
        secrets,
        credential_bridge_forge::SystemClock,
        github,
    ));
    let mut tasks = JoinSet::new();
    loop {
        let body = tokio::select! {
            body = reader.next_body() => body?,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
        };
        let Some(body) = body else { break };
        match decode_body::<ToWorker<git::Request>>(&body)? {
            ToWorker::Request { id, body } => {
                let worker = Arc::clone(&worker);
                let writer = Arc::clone(&writer);
                tasks.spawn(CURRENT_REQUEST.scope(id, async move {
                    let result = worker.handle(body).await;
                    send_frame(&writer, &FromWorker::Response { id, result }).await;
                }));
            }
            ToWorker::CallbackReply { id, result } => match lock(&waiting).remove(&id) {
                Some(waiter) => {
                    let _ = waiter.send(result);
                }
                None => tracing::debug!("reply to unknown callback {id}"),
            },
            ToWorker::Shutdown => break,
        }
    }
    // Finish what is in flight; callbacks fail once the reader is gone.
    lock(&waiting).clear();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// The request handler this loop drives; `S` is the loop's callback-based
/// [`credential_bridge_forge::SecretProvider`].
pub type Worker<S> = credential_bridge_forge::GitWorker<S, credential_bridge_forge::SystemClock>;
