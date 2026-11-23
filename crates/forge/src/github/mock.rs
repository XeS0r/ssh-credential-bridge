//! A minimal HTTP/1.1 server on a loopback port for tests: one request per connection,
//! answers from a closure, records every request.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// A request the server received.
#[derive(Debug, Clone)]
pub(crate) struct Recorded {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Recorded {
    /// A header by lower-case name.
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name).cloned()
    }

    /// The body as JSON.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("JSON body")
    }

    /// The bearer token of the `Authorization` header.
    pub fn bearer(&self) -> Option<String> {
        self.header("authorization")?.strip_prefix("Bearer ").map(str::to_owned)
    }
}

/// The answer to a request.
#[derive(Debug, Clone)]
pub(crate) struct Reply {
    status: u16,
    body: String,
}

impl Reply {
    /// A JSON answer.
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Self { status, body: body.into() }
    }
}

type Handler = dyn Fn(&Recorded) -> Reply + Send + Sync;

/// The running server; stops when dropped.
#[derive(Debug)]
pub(crate) struct MockServer {
    port: u16,
    requests: Arc<Mutex<Vec<Recorded>>>,
    task: JoinHandle<()>,
}

impl MockServer {
    /// Starts a server answering with `handler`.
    pub async fn start(handler: impl Fn(&Recorded) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("address").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let handler: Arc<Handler> = Arc::new(handler);
        let recorded = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let handler = Arc::clone(&handler);
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let _ = serve(stream, &*handler, &recorded).await;
                });
            }
        });
        Self { port, requests, task }
    }

    /// The API base URL tests pass to the client: a production-valid `https` URL that
    /// a client from [`MockServer::client`] maps to this server.
    pub const API: &str = "https://github.mock.invalid/api/v3";

    /// The plain-HTTP base URL, e.g. `http://127.0.0.1:41234`.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// A client that sends every request to this server.
    pub fn client(&self) -> super::GithubClient {
        super::GithubClient::with_mock(self.url())
    }

    /// All requests so far, in order of arrival.
    pub fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }

    /// The paths of all requests so far.
    pub fn paths(&self) -> Vec<String> {
        self.requests().into_iter().map(|r| format!("{} {}", r.method, r.path)).collect()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    mut stream: TcpStream,
    handler: &Handler,
    recorded: &Mutex<Vec<Recorded>>,
) -> std::io::Result<()> {
    let mut buffer = Vec::new();
    let header_end = loop {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..n]);
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default().to_owned();
    let path = request_line.next().unwrap_or_default().to_owned();
    let headers: HashMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut body = buffer[header_end..].to_vec();
    while body.len() < length {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }

    let request = Recorded { method, path, headers, body };
    let reply = handler(&request);
    recorded.lock().unwrap().push(request);
    let response = format!(
        "HTTP/1.1 {} Mock\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        reply.status,
        reply.body.len(),
        reply.body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}
