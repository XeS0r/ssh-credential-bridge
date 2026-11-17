//! End-to-end tests: real sockets, a fake backend, the blocking client.

use std::path::{Path, PathBuf};
use std::time::Duration;

use credential_bridge_core::config::Config;
use credential_bridge_proto::client::exchange;
use credential_bridge_proto::{Credential, Operation, Request, Response, Status};
use credential_bridged::server::Server;

struct Fixture {
    _dir: tempfile::TempDir,
    sockets: PathBuf,
    log: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let sockets = dir.path().join("s");
        let log = dir.path().join("backend.log");
        Self { _dir: dir, sockets, log }
    }

    /// Two remotes; the fake backend records each operation and answers `get`
    /// with fixed credentials (including a host it must not be able to change).
    fn config(&self) -> Config {
        let backend = format!(
            r#"!f() {{ cat >/dev/null; echo "$1" >> '{}'; test "$1" = get && printf 'protocol=https\nhost=evil.example\nusername=me\npassword=secret\n'; true; }}; f"#,
            self.log.display()
        );
        let text = format!(
            r#"
            backend = '''{backend}'''
            socket_dir = "{}"

            [[remote]]
            name = "build"
            allow = ["https://github.com"]

            [[remote]]
            name = "dev"
            allow = ["https://github.com/my-org/*"]
            operations = ["get", "erase"]
            "#,
            self.sockets.display()
        );
        Config::parse(&text, Path::new("test.toml")).unwrap()
    }

    fn socket(&self, name: &str) -> PathBuf {
        self.sockets.join(format!("{name}.sock"))
    }

    fn backend_calls(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log).unwrap_or_default().lines().map(str::to_owned).collect()
    }
}

async fn ask(socket: PathBuf, operation: Operation, url: &str) -> Response {
    let request = Request::new(operation, Credential::from_url(url).unwrap());
    tokio::task::spawn_blocking(move || exchange(&socket, &request, Some(Duration::from_secs(5))))
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn serves_per_remote_policies() {
    let fx = Fixture::new();
    let server = Server::start(&fx.config()).unwrap();

    // Allowed: the answer comes back, without attributes that could redirect it.
    let response = ask(fx.socket("build"), Operation::Get, "https://github.com/any/repo").await;
    assert_eq!(response.status, Status::Ok);
    assert_eq!(response.credential.get("password"), Some("secret"));
    assert_eq!(response.credential.host(), None);

    // Host not allowed.
    let response = ask(fx.socket("build"), Operation::Get, "https://gitlab.com/x").await;
    assert_eq!(response.status, Status::Denied);
    assert!(response.credential.is_empty());

    // Operation not allowed on build, allowed on dev.
    let response = ask(fx.socket("build"), Operation::Erase, "https://github.com/x").await;
    assert_eq!(response.status, Status::Denied);
    let response = ask(fx.socket("dev"), Operation::Erase, "https://github.com/my-org/x").await;
    assert_eq!(response.status, Status::Ok);

    // Path policy on dev.
    let response = ask(fx.socket("dev"), Operation::Get, "https://github.com/other/x").await;
    assert_eq!(response.status, Status::Denied);
    let response = ask(fx.socket("dev"), Operation::Get, "https://github.com/my-org/x.git").await;
    assert_eq!(response.status, Status::Ok);

    // Ping names the remote and never reaches the backend.
    let response = ask(fx.socket("dev"), Operation::Ping, "https://ignored").await;
    assert_eq!(response.message.as_deref(), Some("remote dev"));

    assert_eq!(fx.backend_calls(), ["get", "erase", "get"]);

    drop(server);
    assert!(!fx.socket("build").exists(), "sockets are removed on shutdown");
    assert!(!fx.socket("dev").exists(), "sockets are removed on shutdown");
}

#[tokio::test]
async fn never_steals_a_live_socket_but_replaces_a_stale_one() {
    let fx = Fixture::new();
    let first = Server::start(&fx.config()).unwrap();
    assert!(Server::start(&fx.config()).is_err());
    drop(first);

    let stale = std::os::unix::net::UnixListener::bind(fx.socket("build")).unwrap();
    drop(stale);
    assert!(fx.socket("build").exists());
    let _server = Server::start(&fx.config()).unwrap();
}

#[tokio::test]
async fn answers_garbage_with_an_error() {
    use std::io::{Read, Write};

    let fx = Fixture::new();
    let _server = Server::start(&fx.config()).unwrap();
    let socket = fx.socket("build");
    let reply = tokio::task::spawn_blocking(move || {
        let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
        stream.write_all(b"GET / HTTP/1.1\n\n").unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();
        reply
    })
    .await
    .unwrap();
    assert!(reply.starts_with("credential-bridge/1 error"), "{reply}");
    assert!(fx.backend_calls().is_empty());
}

#[tokio::test]
async fn explains_a_backend_without_credential() {
    let fx = Fixture::new();
    let text = format!(
        r#"
        backend = "!gh auth git-credential >/dev/null 2>&1 </dev/null; f() {{ exit 1; }}; f"
        socket_dir = "{}"

        [[remote]]
        name = "build"
        allow = ["https://github.com"]
        "#,
        fx.sockets.display()
    );
    // `gh` is probably not installed here; a silent `exit 1` behaves the same.
    let config = Config::parse(&text, Path::new("test.toml")).unwrap();
    let _server = Server::start(&config).unwrap();

    let response = ask(fx.socket("build"), Operation::Get, "https://github.com/org/repo").await;
    assert_eq!(response.status, Status::Ok);
    assert!(response.credential.is_empty());
    let message = response.message.unwrap();
    assert_eq!(
        credential_bridge_proto::split_fix(&message),
        (
            "no credential for github.com on your local machine",
            Some("locally: gh auth login --hostname github.com")
        )
    );
}

#[tokio::test]
async fn denial_names_the_fix() {
    let fx = Fixture::new();
    let _server = Server::start(&fx.config()).unwrap();
    let response = ask(fx.socket("build"), Operation::Get, "https://gitlab.com/x").await;
    assert_eq!(response.status, Status::Denied);
    assert_eq!(
        credential_bridge_proto::split_fix(response.message.as_deref().unwrap()),
        (
            "gitlab.com/x is not allowed for this remote",
            Some("locally: credential-bridge-ctl remote edit build --add-allow https://gitlab.com/x")
        )
    );
}

#[tokio::test]
async fn never_forwards_long_lived_tokens() {
    let fx = Fixture::new();
    let text = format!(
        r#"
        backend = "!f() {{ cat >/dev/null; printf 'username=me\npassword=short\noauth_refresh_token=long-lived\nprotocol=https\nhost=evil.example\n'; }}; f"
        socket_dir = "{}"

        [[remote]]
        name = "build"
        allow = ["https://github.com"]
        "#,
        fx.sockets.display()
    );
    let config = Config::parse(&text, Path::new("test.toml")).unwrap();
    let _server = Server::start(&config).unwrap();
    let response = ask(fx.socket("build"), Operation::Get, "https://github.com/org/repo").await;
    assert_eq!(response.status, Status::Ok);
    assert_eq!(response.credential.get("password"), Some("short"));
    assert_eq!(response.credential.get("oauth_refresh_token"), None);
    assert_eq!(response.credential.host(), None);
}

fn config_with(sockets: &Path, backend: &str, remotes: &str) -> Config {
    let text = format!("backend = '''{backend}'''\nsocket_dir = \"{}\"\n{remotes}", sockets.display());
    Config::parse(&text, Path::new("test.toml")).unwrap()
}

#[tokio::test]
async fn reload_keeps_unchanged_sockets_and_swaps_the_policy() {
    use std::os::unix::fs::MetadataExt;

    let fx = Fixture::new();
    let backend =
        "!f() { cat >/dev/null; test \"$1\" = get && printf 'username=u\\npassword=p\\n'; true; }; f";
    let one = "[[remote]]\nname = \"build\"\nallow = [\"https://github.com\"]\n";
    let mut server = Server::start(&config_with(&fx.sockets, backend, one)).unwrap();
    let inode = std::fs::metadata(fx.socket("build")).unwrap().ino();
    // Ping answers carry nothing about the local configuration.
    let ping = ask(fx.socket("build"), Operation::Ping, "https://x").await;
    assert_eq!(ping.status, Status::Ok);
    assert!(ping.credential.is_empty(), "ping must not reveal anything: {:?}", ping.credential);

    let two = "[[remote]]\nname = \"build\"\nallow = [\"https://gitlab.com\"]\n\
               [[remote]]\nname = \"dev\"\nallow = [\"https://github.com\"]\n";
    server.reload(&config_with(&fx.sockets, backend, two)).unwrap();
    assert_eq!(std::fs::metadata(fx.socket("build")).unwrap().ino(), inode, "unchanged socket was rebound");
    assert_eq!(ask(fx.socket("build"), Operation::Get, "https://github.com/x").await.status, Status::Denied);
    assert_eq!(ask(fx.socket("build"), Operation::Get, "https://gitlab.com/x").await.status, Status::Ok);
    assert_eq!(ask(fx.socket("dev"), Operation::Get, "https://github.com/x").await.status, Status::Ok);

    // A failing reload (the new socket path is taken) changes nothing.
    std::fs::write(fx.sockets.join("blocked.sock"), "not a socket").unwrap();
    let blocked = format!("{two}[[remote]]\nname = \"blocked\"\nallow = [\"https://github.com\"]\n");
    assert!(server.reload(&config_with(&fx.sockets, backend, &blocked)).is_err());
    assert_eq!(ask(fx.socket("dev"), Operation::Get, "https://github.com/x").await.status, Status::Ok);
    {
        use std::os::unix::fs::FileTypeExt;
        let kind = std::fs::symlink_metadata(fx.socket("blocked")).unwrap().file_type();
        assert!(!kind.is_socket(), "a failed reload replaced the file with a socket");
    }

    server.reload(&config_with(&fx.sockets, backend, one)).unwrap();
    assert!(!fx.socket("dev").exists(), "removed remote's socket stays");
    assert_eq!(std::fs::metadata(fx.socket("build")).unwrap().ino(), inode);
}

#[tokio::test]
async fn limits_requests_in_flight_per_remote() {
    let fx = Fixture::new();
    let backend = format!(
        "!f() {{ cat >/dev/null; echo \"$1\" >> '{}'; sleep 2; printf 'username=u\\npassword=p\\n'; }}; f",
        fx.log.display()
    );
    let one = "[[remote]]\nname = \"build\"\nallow = [\"https://github.com\"]\n";
    let _server = Server::start(&config_with(&fx.sockets, &backend, one)).unwrap();

    let asks: Vec<_> = (0..20)
        .map(|_| tokio::spawn(ask(fx.socket("build"), Operation::Get, "https://github.com/x")))
        .collect();
    let mut busy = 0;
    for task in asks {
        let response = task.await.unwrap();
        if response.status == Status::Error {
            assert!(response.message.unwrap().contains("too many requests"));
            busy += 1;
        }
    }
    assert!(busy >= 12, "only {busy} of 20 refused");
    assert!(fx.backend_calls().len() <= 8, "{} backends ran at once", fx.backend_calls().len());
}
