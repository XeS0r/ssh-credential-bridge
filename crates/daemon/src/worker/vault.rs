//! The vault worker's loop: serves `vault::Request`s with
//! [`credential_bridge_vault::VaultWorker`].
//!
//! Every request runs in its own task, concurrently with the others: `Resolve` (the
//! common and potentially slow case: a 1Password approval), `Store`, `Status`, the `gh`
//! and `helper` git sources and `Unlock` (for example `bw unlock`) run external programs
//! for up to 100 s. The unlock sessions sit behind a short lock inside
//! [`credential_bridge_vault::Vaults`] that is never held while a program runs, so no
//! request waits for another request's program. Only a second `Unlock` of a vault whose
//! unlock is running is refused at once.
//!
//! The `[vault.keepassxc]` settings arrive in the environment ([`keepassxc_env`]), set by
//! the core when it starts the worker; they are not passed on to vault programs.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use credential_bridge_config::KeepassxcConfig;

use credential_bridge_proto::ipc::vault::Request;
use credential_bridge_proto::ipc::{FromWorker, ToWorker, decode_body};
use credential_bridge_vault::runner::SystemRunner;
use credential_bridge_vault::{SystemClock, VaultWorker, Vaults};
use tokio::task::JoinSet;

use super::{FrameWriter, send_frame};
use crate::frame::IpcReader;

/// Serves the channel until `Shutdown` or end of channel.
pub async fn serve(channel: tokio::net::UnixStream) -> anyhow::Result<()> {
    let (reader, writer) = channel.into_split();
    // Cancel-safe: the read below races `join_next` in a `select!`.
    let mut reader = IpcReader::new(reader);
    let writer: FrameWriter = Arc::new(tokio::sync::Mutex::new(writer));
    let env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let keepassxc = keepassxc_from_env(&env);
    let runner = SystemRunner::new(program_env(env));
    let worker = Arc::new(Worker::new(Vaults::new(runner, SystemClock).with_keepassxc(keepassxc)));
    let mut tasks = JoinSet::new();
    loop {
        let body = tokio::select! {
            body = reader.next_body() => body?,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
        };
        let Some(body) = body else { break };
        match decode_body::<ToWorker<Request>>(&body)? {
            ToWorker::Request { id, body } => {
                let worker = Arc::clone(&worker);
                let writer = Arc::clone(&writer);
                tasks.spawn(async move {
                    let result = worker.handle(body).await;
                    send_frame(&writer, &FromWorker::Response { id, result }).await;
                });
            }
            ToWorker::CallbackReply { .. } => tracing::debug!("the vault worker sends no callbacks"),
            ToWorker::Shutdown => break,
        }
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// The request handler this loop drives.
pub type Worker = VaultWorker<SystemRunner, SystemClock>;

/// `[vault.keepassxc] database` for the worker.
pub const KEEPASSXC_DATABASE_ENV: &str = "CREDENTIAL_BRIDGE_KEEPASSXC_DATABASE";
/// `[vault.keepassxc] key_file` for the worker.
pub const KEEPASSXC_KEY_FILE_ENV: &str = "CREDENTIAL_BRIDGE_KEEPASSXC_KEY_FILE";

/// The environment that hands `config` to the vault worker (added by the core to the
/// worker's allowlisted environment).
pub fn keepassxc_env(config: &KeepassxcConfig) -> Vec<(OsString, OsString)> {
    [(KEEPASSXC_DATABASE_ENV, &config.database), (KEEPASSXC_KEY_FILE_ENV, &config.key_file)]
        .into_iter()
        .filter_map(|(name, path)| Some((OsString::from(name), path.as_ref()?.clone().into_os_string())))
        .collect()
}

/// The settings [`keepassxc_env`] put into `env`.
fn keepassxc_from_env(env: &[(OsString, OsString)]) -> KeepassxcConfig {
    let get = |wanted: &str| {
        env.iter().find(|(name, _)| name == wanted).map(|(_, value)| PathBuf::from(value.clone()))
    };
    KeepassxcConfig { database: get(KEEPASSXC_DATABASE_ENV), key_file: get(KEEPASSXC_KEY_FILE_ENV) }
}

/// The environment of vault programs: the worker's own (already reduced to the allowlist
/// by the core), without the settings of [`keepassxc_env`] and without variables that are
/// not UTF-8.
fn program_env(env: Vec<(OsString, OsString)>) -> Vec<(String, String)> {
    env.into_iter()
        .filter(|(name, _)| name != KEEPASSXC_DATABASE_ENV && name != KEEPASSXC_KEY_FILE_ENV)
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use credential_bridge_proto::ipc::git::TokenTarget;
    use credential_bridge_proto::ipc::vault::{CredentialAction, Response};
    use credential_bridge_proto::secret::Secret;

    use super::*;

    /// Writes an executable `sh` script.
    fn script(path: &Path, body: &str) {
        write_script(path, body);
    }

    /// Writes `#!/bin/sh` and `body` to `path` and makes it executable. Written by a child `sh`, so this process never holds the file open for writing: a
    /// test thread that forks meanwhile would inherit such a descriptor until its child
    /// execs, and running the script in that window fails with ETXTBSY ("Text file busy").
    fn write_script(path: &std::path::Path, body: &str) {
        use std::io::Write as _;
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
            .arg(path)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(format!("#!/bin/sh\n{body}\n").as_bytes()).unwrap();
        assert!(child.wait().unwrap().success(), "writing {} failed", path.display());
    }

    /// A worker whose `PATH` starts with `dir`.
    fn worker(dir: &Path) -> Arc<Worker> {
        let path = format!("{}:{}", dir.display(), std::env::var("PATH").unwrap_or_default());
        let runner = SystemRunner::new(vec![("PATH".into(), path)]);
        Arc::new(VaultWorker::new(Vaults::new(runner, SystemClock)))
    }

    #[test]
    fn keepassxc_settings_travel_in_the_environment() {
        let config = KeepassxcConfig {
            database: Some("/home/u/db.kdbx".into()),
            key_file: Some("/home/u/db.keyx".into()),
        };
        let mut env = keepassxc_env(&config);
        assert_eq!(keepassxc_from_env(&env), config);
        env.push(("PATH".into(), "/bin".into()));
        assert_eq!(program_env(env), vec![("PATH".to_owned(), "/bin".to_owned())]);

        let database_only = KeepassxcConfig { database: Some("/db.kdbx".into()), key_file: None };
        assert_eq!(keepassxc_env(&database_only).len(), 1);
        assert_eq!(keepassxc_from_env(&keepassxc_env(&database_only)), database_only);
        assert!(keepassxc_env(&KeepassxcConfig::default()).is_empty());
    }

    fn unlock() -> Request {
        Request::Unlock { vault: "bw".into(), password: Secret::new("pw".into()), ttl_secs: Some(60) }
    }

    /// A slow credential helper (or `Status`) must not hold up a `Resolve`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_helper_does_not_block_resolve() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("git-credential-slow");
        script(&helper, "sleep 5");
        let worker = worker(dir.path());

        let slow = {
            let worker = Arc::clone(&worker);
            let request = Request::HelperCredential {
                helper: helper.display().to_string(),
                target: TokenTarget { protocol: "https".into(), host: "example.org".into(), path: None },
                action: CredentialAction::Get,
            };
            tokio::spawn(async move { worker.handle(request).await })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!slow.is_finished());
        let resolve = worker.handle(Request::Resolve { reference: "cmd:printf tok".into() });
        let response = tokio::time::timeout(Duration::from_secs(3), resolve).await.expect("resolve waited");
        let Ok(Response::Secret(secret)) = response else { panic!("no secret: {response:?}") };
        assert_eq!(secret.expose(), "tok");
        slow.abort();
    }

    /// A slow unlock program does not hold up a `Resolve`, and the session it opens is
    /// used afterwards.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_unlock_does_not_block_resolve() {
        let dir = tempfile::tempdir().unwrap();
        script(&dir.path().join("bw"), "sleep 2; printf session-key");
        let worker = worker(dir.path());

        let slow = {
            let worker = Arc::clone(&worker);
            tokio::spawn(async move { worker.handle(unlock()).await })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!slow.is_finished());
        let resolve = worker.handle(Request::Resolve { reference: "cmd:printf tok".into() });
        let response = tokio::time::timeout(Duration::from_secs(1), resolve).await.expect("resolve waited");
        assert!(matches!(response, Ok(Response::Secret(_))), "{response:?}");
        assert!(!slow.is_finished(), "the test needs the unlock to be still running");

        let unlocked = slow.await.unwrap();
        assert!(matches!(unlocked, Ok(Response::Unlocked { .. })), "{unlocked:?}");
        assert!(worker.keep_alive());
    }

    /// A slow `Resolve` does not delay an `Unlock`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_resolve_does_not_delay_unlock() {
        let dir = tempfile::tempdir().unwrap();
        script(&dir.path().join("bw"), "printf session-key");
        let worker = worker(dir.path());

        let slow = {
            let worker = Arc::clone(&worker);
            let request = Request::Resolve { reference: "cmd:sleep 5; printf tok".into() };
            tokio::spawn(async move { worker.handle(request).await })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!slow.is_finished());
        let response = tokio::time::timeout(Duration::from_secs(3), worker.handle(unlock()))
            .await
            .expect("unlock waited");
        assert!(matches!(response, Ok(Response::Unlocked { .. })), "{response:?}");
        let lock = worker.handle(Request::Lock { vault: None });
        let response = tokio::time::timeout(Duration::from_secs(1), lock).await.expect("lock waited");
        assert_eq!(response.unwrap(), Response::Locked);
        assert!(!slow.is_finished());
        slow.abort();
    }
}
