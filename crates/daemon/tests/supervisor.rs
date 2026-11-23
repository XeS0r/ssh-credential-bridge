//! The worker supervisor against the real worker binary: start on demand, crash and
//! restart with back-off, idle exit, shutdown.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use credential_bridge_proto::ipc::vault::{Request, Response};
use credential_bridge_proto::ipc::{WorkerErrorKind, WorkerKind};
use credential_bridged::supervisor::{WorkerConfig, WorkerHandle, worker_env};

fn vault_handle(idle: Duration) -> WorkerHandle<Request, Response> {
    let env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let mut config = WorkerConfig::new(
        WorkerKind::Vault,
        PathBuf::from(env!("CARGO_BIN_EXE_credential-bridged")),
        worker_env(WorkerKind::Vault, env),
    );
    config.idle_timeout = idle;
    config.request_timeout = Duration::from_secs(20);
    WorkerHandle::new(config, None)
}

async fn resolve(
    handle: &WorkerHandle<Request, Response>,
    reference: &str,
) -> Result<Response, credential_bridge_proto::ipc::WorkerError> {
    handle.request(Request::Resolve { reference: reference.to_owned() }).await
}

#[tokio::test(flavor = "multi_thread")]
async fn starts_on_demand_restarts_after_a_crash_and_stops() {
    let handle = vault_handle(Duration::from_secs(600));
    assert!(!handle.is_running());
    let Response::Secret(secret) = resolve(&handle, "cmd:printf hello").await.unwrap() else { panic!() };
    assert_eq!(secret.expose(), "hello");
    let pid = handle.status().pid.expect("running");

    // Requests run concurrently in the worker.
    let (a, b) = tokio::join!(
        resolve(&handle, "cmd:sleep 0.3; printf a"),
        resolve(&handle, "cmd:sleep 0.3; printf b")
    );
    assert!(a.is_ok() && b.is_ok());

    // Errors cross the channel with their kind.
    let error = resolve(&handle, "not a reference").await.unwrap_err();
    assert_eq!(error.kind, WorkerErrorKind::Invalid);

    // Kill it: the next request restarts it after the back-off.
    let target = rustix::process::Pid::from_raw(i32::try_from(pid).unwrap()).unwrap();
    rustix::process::kill_process(target, rustix::process::Signal::KILL).unwrap();
    let mut waited = Duration::ZERO;
    while handle.is_running() && waited < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(20)).await;
        waited += Duration::from_millis(20);
    }
    assert!(!handle.is_running());
    let Response::Secret(secret) = resolve(&handle, "cmd:printf again").await.unwrap() else { panic!() };
    assert_eq!(secret.expose(), "again");
    let status = handle.status();
    assert_eq!(status.restarts, 1);
    assert_ne!(status.pid, Some(pid));

    handle.shutdown().await;
    assert!(!handle.is_running());
    assert_eq!(handle.status().pid, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn exits_when_idle_unless_kept_alive() {
    let handle = vault_handle(Duration::from_millis(300));
    resolve(&handle, "cmd:printf x").await.unwrap();
    assert!(handle.is_running());
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(!handle.is_running(), "idle worker exits");
    assert_eq!(handle.status().restarts, 0, "an idle exit is no crash");

    // Kept alive (an unlock session) it stays.
    handle.extend_keep_alive(std::time::SystemTime::now() + Duration::from_secs(60));
    resolve(&handle, "cmd:printf y").await.unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(handle.is_running());
    handle.keep_alive_until(None);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(!handle.is_running());
}

/// Requests bound to a worker generation (gpg `Input`/`Close`) never start a worker and
/// never reach a later process.
#[tokio::test(flavor = "multi_thread")]
async fn generation_bound_requests_never_start_a_worker() {
    let handle = vault_handle(Duration::from_secs(600));
    let fd = std::os::fd::OwnedFd::from(std::fs::File::open("/dev/null").unwrap());
    let (response, generation) = handle
        .request_with_fd_tracked(Request::Resolve { reference: "cmd:printf a".into() }, fd)
        .await
        .unwrap();
    assert!(matches!(response, Response::Secret(_)));
    let bound =
        || handle.request_if_running(generation, Request::Resolve { reference: "cmd:printf b".into() });
    assert!(bound().await.is_ok(), "the same process answers");

    // Kill it: a bound request fails and starts nothing.
    let pid = handle.status().pid.expect("running");
    let target = rustix::process::Pid::from_raw(i32::try_from(pid).unwrap()).unwrap();
    rustix::process::kill_process(target, rustix::process::Signal::KILL).unwrap();
    let mut waited = Duration::ZERO;
    while handle.is_running() && waited < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(20)).await;
        waited += Duration::from_millis(20);
    }
    assert_eq!(bound().await.unwrap_err().kind, WorkerErrorKind::Unavailable);
    assert!(!handle.is_running(), "no worker was started");

    // A new process (another generation) does not take the old one's requests.
    resolve(&handle, "cmd:printf c").await.unwrap();
    assert!(handle.is_running());
    assert_eq!(bound().await.unwrap_err().kind, WorkerErrorKind::Unavailable);
    handle.shutdown().await;
}
