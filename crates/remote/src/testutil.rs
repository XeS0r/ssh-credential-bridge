//! Test helpers: a fake ssh-agent on a unix socket in a temporary directory.

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use credential_bridge_proto::agent::{Message, read_frame, write_frame};
use credential_bridge_proto::ext::{QUERY, encode_query_reply};

/// Answers one agent request.
pub(crate) type Handler = dyn Fn(&Message) -> Message + Send + Sync;

/// A fake agent: every connection is served in its own thread by the handler; all
/// requests are recorded.
pub(crate) struct FakeAgent {
    _dir: tempfile::TempDir,
    path: PathBuf,
    requests: Arc<Mutex<Vec<Message>>>,
    connections: Arc<Mutex<usize>>,
}

impl FakeAgent {
    /// Starts a fake agent with `handler`.
    pub(crate) fn start(handler: impl Fn(&Message) -> Message + Send + Sync + 'static) -> FakeAgent {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(Mutex::new(0));
        let handler: Arc<Handler> = Arc::new(handler);
        {
            let requests = Arc::clone(&requests);
            let connections = Arc::clone(&connections);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { return };
                    *connections.lock().unwrap() += 1;
                    let handler = Arc::clone(&handler);
                    let requests = Arc::clone(&requests);
                    std::thread::spawn(move || serve(stream, &*handler, &requests));
                }
            });
        }
        FakeAgent { _dir: dir, path, requests, connections }
    }

    /// The socket path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// All requests received so far, in order.
    pub(crate) fn requests(&self) -> Vec<Message> {
        self.requests.lock().unwrap().clone()
    }

    /// How many connections were accepted.
    pub(crate) fn connections(&self) -> usize {
        *self.connections.lock().unwrap()
    }
}

fn serve(mut stream: UnixStream, handler: &Handler, requests: &Mutex<Vec<Message>>) {
    while let Ok(Some(frame)) = read_frame(&mut stream) {
        let request = Message::decode(&frame).unwrap();
        requests.lock().unwrap().push(request.clone());
        let reply = handler(&request);
        if write_frame(&mut stream, &reply.encode()).is_err() {
            return;
        }
    }
}

/// The reply to `query` listing `names`, or `None` if `request` is not `query`.
pub(crate) fn query_reply(request: &Message, names: &[&str]) -> Option<Message> {
    match request {
        Message::Extension { name, .. } if name == QUERY => {
            Some(Message::Success { contents: encode_query_reply(names) })
        }
        _ => None,
    }
}

/// A handler that answers `query` with `names` and everything else with failure.
pub(crate) fn query_only(names: &[&str]) -> impl Fn(&Message) -> Message + Send + Sync + 'static {
    let names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
    move |request| {
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        query_reply(request, &names).unwrap_or(Message::Failure)
    }
}

/// Contents of the extension request `name`, if `request` is one.
pub(crate) fn extension_contents<'a>(request: &'a Message, name: &str) -> Option<&'a [u8]> {
    match request {
        Message::Extension { name: n, contents } if n == name => Some(contents),
        _ => None,
    }
}
