//! `source add github --auth app --create`: GitHub's App manifest flow through a
//! loopback listener and the browser. The private key goes from GitHub's answer
//! straight to the vault (through the daemon) and never touches the disk.

use std::io::{self, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use credential_bridge_config::DaemonConfig;
use credential_bridge_config::edit::ConfigDocument;
use credential_bridge_config::secret_ref::SecretRef;
use credential_bridge_forge::github::manifest::{AppManifest, new_app_url};
use credential_bridge_forge::github::{GITHUB_API, GithubClient};
use credential_bridge_proto::ipc::control::{Request, Response};
use credential_bridge_proto::ipc::git::{Access, Permissions};

use super::change::reload_failed_line;
use super::source::test_after_add;
use super::{CONTROL_TIMEOUT, Context, SLOW_CONTROL_TIMEOUT, connect, load_config, printable, reload_daemon};
use crate::cli::GithubSourceArgs;
use crate::control::ControlError;
use crate::report::{Line, Report};

/// The GitHub host when `--host` is not given.
const GITHUB_HOST: &str = "github.com";

/// How long the flow waits for GitHub's redirect.
const FLOW_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Longest HTTP request head the loopback listener reads.
const MAX_REQUEST_HEAD: usize = 8 * 1024;

/// Longest App name GitHub accepts.
const MAX_APP_NAME: usize = 34;

/// `source add github NAME --auth app --create`: manifest flow with a loopback listener
/// and the browser, `GithubClient::convert_manifest`, control request `StoreSecret` for
/// the key at `--private-key`, then `ConfigDocument::add_github_app_source`, a reload and
/// the test every `source add` runs. The key never touches the disk.
pub fn github_app_create(ctx: &Context, args: &GithubSourceArgs, report: &mut Report) -> anyhow::Result<()> {
    let reference = args.private_key.as_deref().context("--create needs --private-key REFERENCE")?;
    let key: SecretRef = reference.parse().map_err(|error: credential_bridge_config::SecretRefError| {
        anyhow::anyhow!("--private-key {}: {}", error.reference, error.reason)
    })?;
    if !key.writable() {
        bail!("--private-key {key}: this vault reference cannot be written");
    }
    let host = args.host.as_deref().unwrap_or(GITHUB_HOST);
    check_host(host)?;
    if let Some(org) = &args.org {
        check_name("--org", org)?;
    }
    let name = args.name.as_str();
    check_name("the source name", name)?;
    let config = load_config(ctx)?;
    if config.sources.contains_key(name) {
        bail!("[source.{name}] already exists; choose another name");
    }
    // The daemon stores the key; find out now rather than after the App exists.
    let mut client = connect(&config.daemon, CONTROL_TIMEOUT)?;
    client.request(&Request::Ping)?;
    drop(client);

    let listener = TcpListener::bind(("127.0.0.1", 0)).context("cannot open a local port for the browser")?;
    let port = listener.local_addr()?.port();
    let manifest = app_manifest(args, &format!("http://127.0.0.1:{port}/callback"))?;
    let state = random_state()?;
    let action = format!("{}?state={state}", new_app_url(&format!("https://{host}"), args.org.as_deref()));
    let page = manifest_page(&action, &manifest.to_json());
    let start = format!("http://127.0.0.1:{port}/");
    report.show(&format!("Open {start} in your browser to create the App on {host} (opening it now).\n"));
    open_browser(&start);
    let code = wait_for_code(&listener, &page, &state, Instant::now() + FLOW_TIMEOUT)?;

    let api_url = if host == GITHUB_HOST { GITHUB_API.to_owned() } else { format!("https://{host}/api/v3") };
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let app = runtime
        .block_on(async { GithubClient::new()?.convert_manifest(&api_url, &code).await })
        .context("GitHub did not hand out the new App")?;
    report.push(Line::ok("app created", format!("{} ({})", printable(&app.slug), printable(&app.html_url))));

    let mut client = connect(&config.daemon, SLOW_CONTROL_TIMEOUT)?;
    match client.request(&Request::StoreSecret { reference: key.to_string(), value: app.pem }) {
        Ok(Response::Stored) => report.push(Line::ok("private key stored", key.to_string())),
        Ok(_) => return Err(lost_key(&app.html_url, ControlError::Unexpected.into())),
        Err(error) => return Err(lost_key(&app.html_url, error.into())),
    }

    let new = NewApp {
        name,
        host,
        app_id: app.id,
        key: &key.to_string(),
        permissions: &manifest.default_permissions,
        cache: !args.no_cache,
    };
    add_app_source(ctx, &config.daemon, &new, report)?;
    report
        .show(&format!("\n{}\n", next_steps(name, &printable(&app.owner), &printable(&app.html_url), host)));
    Ok(())
}

/// The `[source.*]` entry of a new App.
struct NewApp<'a> {
    name: &'a str,
    host: &'a str,
    app_id: u64,
    /// The reference the private key was stored at.
    key: &'a str,
    permissions: &'a Permissions,
    /// `cache`; `false` is written as `cache = false`.
    cache: bool,
}

/// Writes `[source.NAME]` for the new App, reloads the daemon (`daemon`) and tests the
/// source as every `source add` does (a failure is a warning; the entry stays).
fn add_app_source(
    ctx: &Context,
    daemon: &DaemonConfig,
    new: &NewApp<'_>,
    report: &mut Report,
) -> anyhow::Result<()> {
    let name = new.name;
    let mut doc = ConfigDocument::open(&ctx.config_path)?;
    let saved = doc
        .add_github_app_source(name, new.host, new.app_id, new.key, new.permissions)
        .and_then(|()| if new.cache { Ok(()) } else { doc.set_source_cache(name, false) })
        .and_then(|()| doc.save(&ctx.paths));
    if let Err(error) = saved {
        bail!(
            "cannot add [source.{name}] ({error}); add it to {} yourself:\n\n{}",
            ctx.config_path.display(),
            source_snippet(new)
        );
    }
    report.push(Line::ok("source added", format!("[source.{name}] in {}", ctx.config_path.display())));
    match reload_daemon(daemon) {
        Ok(true) => report.push(Line::ok("daemon", "reloaded the configuration")),
        // The test below says that the daemon is not running.
        Ok(false) => {}
        Err(error) => report.push(reload_failed_line(&error)),
    }
    let config = load_config(ctx)?;
    test_after_add(ctx, &config, name, report);
    Ok(())
}

/// The error when the App exists but its key could not be stored.
fn lost_key(html_url: &str, error: anyhow::Error) -> anyhow::Error {
    error.context(format!(
        "the App was created ({}), but its private key could not be stored; generate a new key on \
         the App's settings page and store it in the vault yourself",
        printable(html_url)
    ))
}

/// The manifest `--create` sends: name, homepage, loopback `redirect_url`, and the
/// requested permissions parsed from `--max-permission`.
pub fn app_manifest(args: &GithubSourceArgs, redirect_url: &str) -> anyhow::Result<AppManifest> {
    let name = match &args.app_name {
        Some(name) => name.clone(),
        None => default_app_name(std::env::var("USER").ok().as_deref()),
    };
    if name.is_empty() || name.chars().count() > MAX_APP_NAME {
        bail!("the App name must have 1 to {MAX_APP_NAME} characters");
    }
    Ok(AppManifest {
        name,
        url: env!("CARGO_PKG_REPOSITORY").to_owned(),
        redirect_url: redirect_url.to_owned(),
        public: args.public,
        default_permissions: parse_permissions(&args.max_permissions)?,
    })
}

/// `credential-bridge-<user>`, cut to GitHub's length limit.
fn default_app_name(user: Option<&str>) -> String {
    let user: String = user
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let user = if user.is_empty() { "app".to_owned() } else { user };
    format!("credential-bridge-{user}").chars().take(MAX_APP_NAME).collect()
}

/// `name=access` pairs; default `contents=write`, `metadata=read`.
fn parse_permissions(values: &[String]) -> anyhow::Result<Permissions> {
    if values.is_empty() {
        return Ok(Permissions::from([
            ("contents".to_owned(), Access::Write),
            ("metadata".to_owned(), Access::Read),
        ]));
    }
    parse_permission_list("--max-permission", values)
}

/// `name=access` values given for `flag` (`--max-permission contents=write`).
pub(crate) fn parse_permission_list(flag: &str, values: &[String]) -> anyhow::Result<Permissions> {
    let mut permissions = Permissions::new();
    for value in values {
        let Some((name, access)) = value.split_once('=') else {
            bail!("{flag} {value:?}: expected NAME=ACCESS, e.g. contents=write");
        };
        let access: Access = match access.parse() {
            Ok(access) => access,
            Err(error) => bail!("{flag} {value:?}: access {error}"),
        };
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            bail!("{flag} {value:?}: {name:?} is not a GitHub permission name");
        }
        permissions.insert(name.to_owned(), access);
    }
    Ok(permissions)
}

/// Names of tables and organisations: `[A-Za-z0-9._-]+`.
fn check_name(what: &str, name: &str) -> anyhow::Result<()> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
        bail!("{what} {name:?} may only contain letters, digits, '.', '_' and '-'");
    }
    Ok(())
}

/// A host name, optionally with a port.
fn check_host(host: &str) -> anyhow::Result<()> {
    if host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || ".-:".contains(c)) {
        bail!("--host {host:?} is not a host name");
    }
    Ok(())
}

/// The `[source.*]` table, for adding it by hand if saving fails.
fn source_snippet(new: &NewApp<'_>) -> String {
    let NewApp { name, host, app_id, key, permissions, cache } = new;
    let permissions: Vec<String> =
        permissions.iter().map(|(name, access)| format!("{name} = \"{}\"", access.as_str())).collect();
    let host = if *host == "github.com" { String::new() } else { format!("host            = \"{host}\"\n") };
    let cache = if *cache { "" } else { "cache           = false\n" };
    format!(
        "[source.{name}]\ntype            = \"github\"\nauth            = \"app\"\n{host}app_id          = {app_id}\n\
         private_key     = \"{key}\"\nmax_permissions = {{ {} }}\n{cache}",
        permissions.join(", ")
    )
}

/// What to do after the App exists.
fn next_steps(source: &str, owner: &str, html_url: &str, host: &str) -> String {
    format!(
        "Next:\n  1. Install the App on the accounts and repositories it may serve:\n       {html_url}/installations/new\n  \
         2. Point a git rule of a profile to it, e.g.\n\n       [[profile.build.git]]\n       \
         url         = \"https://{host}/{owner}/*\"\n       source      = \"{source}\"\n       \
         permissions = {{ contents = \"write\" }}\n\n  \
         3. Run credential-bridge-ctl server add for the servers using that profile (it sets useHttpPath).\n"
    )
}

/// 128 random bits as hex, for the `state` parameter.
fn random_state() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Opens `url` in the default browser; failures only mean the user opens it by hand.
fn open_browser(url: &str) {
    let opener = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
    let url = url.to_owned();
    std::thread::spawn(move || {
        let _ = std::process::Command::new(opener)
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    });
}

/// Escapes text for HTML attribute values and content.
fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The local start page: a form that POSTs the manifest to GitHub, submitted at once
/// (with a button for browsers without JavaScript).
fn manifest_page(action: &str, manifest_json: &str) -> String {
    format!(
        "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>Create GitHub App</title></head><body>\n\
         <p>Sending the App manifest to GitHub&hellip;</p>\n\
         <form id=\"manifest\" method=\"post\" action=\"{}\">\n\
         <input type=\"hidden\" name=\"manifest\" value=\"{}\">\n\
         <button type=\"submit\">Continue to GitHub</button>\n</form>\n\
         <script>document.getElementById(\"manifest\").submit();</script>\n</body></html>\n",
        html_escape(action),
        html_escape(manifest_json)
    )
}

/// The answer to one request on the loopback listener.
#[derive(Debug, PartialEq, Eq)]
struct Routed {
    status: &'static str,
    body: String,
    /// The manifest code, once GitHub redirected back with the right state.
    code: Option<String>,
}

/// Routes one request head: `GET /` is the start page, `GET /callback?code=…&state=…`
/// ends the flow; everything else is 404.
fn route(head: &str, page: &str, state: &str) -> Routed {
    let message = |status, text: &str| Routed {
        status,
        body: format!("<!doctype html><meta charset=\"utf-8\"><p>{}</p>\n", html_escape(text)),
        code: None,
    };
    let mut parts = head.lines().next().unwrap_or_default().split(' ');
    let (method, target) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
    if method != "GET" {
        return message("405 Method Not Allowed", "Only GET is supported.");
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    match path {
        "/" => Routed { status: "200 OK", body: page.to_owned(), code: None },
        "/callback" => {
            if query_param(query, "state").as_deref() != Some(state) {
                return message("400 Bad Request", "This answer does not belong to the running setup.");
            }
            match query_param(query, "code").filter(|code| !code.is_empty()) {
                Some(code) => Routed {
                    code: Some(code),
                    ..message(
                        "200 OK",
                        "GitHub created the App. credential-bridge-ctl finishes the setup in your terminal; you can close this window.",
                    )
                },
                None => message("400 Bad Request", "GitHub sent no code."),
            }
        }
        _ => message("404 Not Found", "Not found."),
    }
}

/// The decoded value of `name` in a query string.
fn query_param(query: &str, name: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, v)| percent_decode(v))
}

/// Decodes a query-string value: `+` is a space, then `%XX` escapes
/// ([`credential_bridge_proto::text::percent_decode_bytes`]; `%2B` stays a `+`); invalid
/// escapes stay as they are, invalid UTF-8 becomes U+FFFD.
fn percent_decode(value: &str) -> String {
    let bytes = credential_bridge_proto::text::percent_decode_bytes(&value.replace('+', " "));
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Serves the start page until GitHub redirects back with a code, or `deadline`.
fn wait_for_code(
    listener: &TcpListener,
    page: &str,
    state: &str,
    deadline: Instant,
) -> anyhow::Result<String> {
    listener.set_nonblocking(true)?;
    loop {
        if Instant::now() > deadline {
            bail!("gave up waiting for GitHub after {} minutes", FLOW_TIMEOUT.as_secs() / 60);
        }
        match listener.accept() {
            Ok((stream, _)) => {
                if let Ok(Some(code)) = answer(stream, page, state) {
                    return Ok(code);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// Reads one request, answers it and closes the connection.
fn answer(mut stream: TcpStream, page: &str, state: &str) -> io::Result<Option<String>> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < MAX_REQUEST_HEAD {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&buf[..n]);
    }
    let routed = route(&String::from_utf8_lossy(&head), page, state);
    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n{}",
        routed.status,
        routed.body.len(),
        routed.body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(routed.code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{GithubAuth, WriteArgs};
    use crate::commands::test_support::{context, recording_daemon, write_config};

    fn args() -> GithubSourceArgs {
        GithubSourceArgs {
            name: "my-org".into(),
            auth: GithubAuth::App,
            host: None,
            token: None,
            create: true,
            app_id: None,
            private_key: Some("op://Dev/bridge-app/private-key".into()),
            max_permissions: vec![],
            api_url: None,
            no_cache: false,
            org: None,
            app_name: None,
            public: false,
            write: WriteArgs::default(),
        }
    }

    #[test]
    fn builds_the_manifest() {
        let mut args = args();
        args.app_name = Some("bridge".into());
        let manifest = app_manifest(&args, "http://127.0.0.1:1234/callback").unwrap();
        assert_eq!(manifest.name, "bridge");
        assert_eq!(manifest.redirect_url, "http://127.0.0.1:1234/callback");
        assert!(!manifest.public);
        assert_eq!(manifest.default_permissions.get("contents"), Some(&Access::Write));
        assert_eq!(manifest.default_permissions.get("metadata"), Some(&Access::Read));

        args.max_permissions = vec!["pull_requests=write".into(), "issues=read".into()];
        args.public = true;
        let manifest = app_manifest(&args, "x").unwrap();
        assert!(manifest.public);
        assert_eq!(manifest.default_permissions.len(), 2);

        for bad in ["contents", "contents=all", "Contents=read", "=read"] {
            args.max_permissions = vec![bad.into()];
            assert!(app_manifest(&args, "x").is_err(), "{bad}");
        }
        args.max_permissions.clear();
        args.app_name = Some("x".repeat(35));
        assert!(app_manifest(&args, "x").is_err());
    }

    #[test]
    fn default_names() {
        assert_eq!(default_app_name(Some("André.W")), "credential-bridge-andrw");
        assert_eq!(default_app_name(None), "credential-bridge-app");
        assert_eq!(default_app_name(Some(&"a".repeat(40))).len(), MAX_APP_NAME);
    }

    #[test]
    fn page_escapes_the_manifest() {
        let page = manifest_page("https://github.com/settings/apps/new?state=ab", r#"{"name":"<x>&'"}"#);
        assert!(page.contains("action=\"https://github.com/settings/apps/new?state=ab\""));
        assert!(page.contains("value=\"{&quot;name&quot;:&quot;&lt;x&gt;&amp;&#39;&quot;}\""));
    }

    #[test]
    fn routes_requests() {
        let page = "PAGE";
        assert_eq!(route("GET / HTTP/1.1\r\nHost: x\r\n\r\n", page, "s1").body, "PAGE");
        let done = route("GET /callback?code=abc123&state=s1 HTTP/1.1\r\n\r\n", page, "s1");
        assert_eq!(done.code.as_deref(), Some("abc123"));
        let wrong = route("GET /callback?code=abc123&state=s2 HTTP/1.1\r\n\r\n", page, "s1");
        assert_eq!((wrong.status, wrong.code), ("400 Bad Request", None));
        assert_eq!(route("GET /callback?state=s1 HTTP/1.1\r\n\r\n", page, "s1").code, None);
        assert_eq!(route("POST / HTTP/1.1\r\n\r\n", page, "s1").status, "405 Method Not Allowed");
        assert_eq!(route("GET /favicon.ico HTTP/1.1\r\n\r\n", page, "s1").status, "404 Not Found");
        assert_eq!(route("", page, "s1").status, "405 Method Not Allowed");
    }

    #[test]
    fn decodes_query_values() {
        assert_eq!(percent_decode("a%20b+c"), "a b c");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
        // `+` is a space, an escaped `+` stays one; invalid UTF-8 is replaced.
        assert_eq!(percent_decode("a%2Bb+c%2b"), "a+b c+");
        assert_eq!(percent_decode("%ff"), "\u{fffd}");
        assert_eq!(percent_decode("x%4"), "x%4");
        assert_eq!(query_param("a=1&b=x%2Fy", "b").as_deref(), Some("x/y"));
        assert_eq!(query_param("a=1", "b"), None);
    }

    #[test]
    fn serves_the_flow_over_loopback() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = std::thread::spawn(move || {
            let get = |target: &str| {
                let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
                write!(stream, "GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
                let mut response = String::new();
                stream.read_to_string(&mut response).unwrap();
                response
            };
            let start = get("/");
            let wrong = get("/callback?code=c&state=other");
            let done = get("/callback?code=the-code&state=st");
            (start, wrong, done)
        });
        let code = wait_for_code(&listener, "PAGE", "st", Instant::now() + Duration::from_secs(20)).unwrap();
        assert_eq!(code, "the-code");
        let (start, wrong, done) = client.join().unwrap();
        assert!(start.starts_with("HTTP/1.1 200 OK\r\n") && start.ends_with("PAGE"));
        assert!(wrong.starts_with("HTTP/1.1 400"));
        assert!(done.contains("you can close this window"));
    }

    #[test]
    fn snippet_and_next_steps() {
        let permissions = Permissions::from([("contents".to_owned(), Access::Write)]);
        let mut new = NewApp {
            name: "my-org",
            host: "ghe.example.com",
            app_id: 42,
            key: "op://Dev/app/key",
            permissions: &permissions,
            cache: true,
        };
        let snippet = source_snippet(&new);
        assert!(snippet.contains("host            = \"ghe.example.com\"\napp_id          = 42\n"));
        assert!(snippet.ends_with("max_permissions = { contents = \"write\" }\n"), "{snippet}");
        new.cache = false;
        assert!(source_snippet(&new).ends_with("}\ncache           = false\n"));
        let steps = next_steps("my-org", "my-org", "https://github.com/apps/bridge", "github.com");
        assert!(steps.contains("https://github.com/apps/bridge/installations/new"));
        assert!(steps.contains("url         = \"https://github.com/my-org/*\""));
    }

    /// After the App exists: the source is written, the daemon reloaded and the source
    /// tested like every `source add`; a failing test is a warning.
    #[test]
    fn adds_reloads_and_tests_the_new_source() {
        use credential_bridge_proto::ipc::control::SourceCheck;
        use credential_bridge_proto::ipc::{WorkerError, WorkerErrorKind};

        let (_dir, ctx) = context();
        write_config(&ctx, "version = 2\n");
        let locked = WorkerError::new(WorkerErrorKind::Locked, "vault 1password is locked");
        let tested = Response::SourceTested(vec![SourceCheck {
            what: "op://Dev/app/key".into(),
            error: Some(locked),
        }]);
        let requests = recording_daemon(&ctx.paths.control_socket, tested);
        let permissions = Permissions::from([("contents".to_owned(), Access::Write)]);
        let new = NewApp {
            name: "my-org",
            host: "github.com",
            app_id: 42,
            key: "op://Dev/app/key",
            permissions: &permissions,
            cache: false,
        };
        let mut report = Report::default();
        let daemon = load_config(&ctx).unwrap().daemon;
        add_app_source(&ctx, &daemon, &new, &mut report).unwrap();
        let text = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(text.contains("[source.my-org]\ntype = \"github\"\nauth = \"app\"\napp_id = 42\n"), "{text}");
        assert!(text.ends_with("\ncache = false\n"), "{text}");
        assert_eq!(
            *requests.lock().unwrap(),
            vec![Request::Reload, Request::SourceTest { source: "my-org".into() }]
        );
        assert!(
            report.text.contains("✓ daemon               reloaded the configuration\n"),
            "{}",
            report.text
        );
        assert!(
            report.text.contains("⚠ private_key          op://Dev/app/key: vault 1password is locked"),
            "{}",
            report.text
        );
        assert!(!report.failed());
    }

    #[test]
    fn rejects_bad_arguments_before_any_network() {
        let (_dir, ctx) = context();
        let mut bad = args();
        bad.private_key = Some("cmd:print-key".into());
        assert!(
            github_app_create(&ctx, &bad, &mut Report::default())
                .unwrap_err()
                .to_string()
                .contains("cannot be written")
        );
        let mut bad = args();
        bad.host = Some("evil.example/x".into());
        assert!(github_app_create(&ctx, &bad, &mut Report::default()).is_err());
        let mut bad = args();
        bad.org = Some("../x".into());
        assert!(github_app_create(&ctx, &bad, &mut Report::default()).is_err());
        write_config(&ctx, "version = 2\n[source.my-org]\ntype = \"github\"\nauth = \"gh\"\n");
        assert!(
            github_app_create(&ctx, &args(), &mut Report::default())
                .unwrap_err()
                .to_string()
                .contains("already exists")
        );
        std::fs::remove_file(&ctx.config_path).unwrap();
        // The daemon is not running in tests.
        let error = github_app_create(&ctx, &args(), &mut Report::default()).unwrap_err();
        assert!(
            error.downcast_ref::<ControlError>().is_some_and(|e| matches!(e, ControlError::NotRunning(_)))
        );
    }
}
