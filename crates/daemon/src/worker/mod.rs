//! The worker processes (`credential-bridged worker <kind>`).
//!
//! Start-up order: [`credential_bridge_platform::harden::harden_process`], take the
//! channel from stdin ([`credential_bridge_platform::channel::inherited_channel`]), build
//! a single-threaded tokio runtime, apply the sandbox (git, gpg), send
//! `FromWorker::Ready`, then serve `ToWorker` frames until `Shutdown` or end of channel.
//!
//! The runtime is built before the sandbox because building it creates a socketpair
//! for tokio's signal handling, which the sandbox forbids. A current-thread runtime
//! starts no threads, so the sandbox still covers every thread (Landlock applies to
//! threads started later, seccomp to all).

pub mod git;
pub mod gpg;
pub mod vault;

use std::os::fd::OwnedFd;
use std::process::ExitCode;

use credential_bridge_platform::sandbox::{self, SandboxSpec};
use credential_bridge_proto::ipc::{FromWorker, WorkerKind};

/// Runs the worker `kind` to completion. Exit code 0 after `Shutdown` or end of
/// channel, 1 on set-up errors (no channel, sandbox failure), which the core logs.
pub fn run(kind: WorkerKind) -> ExitCode {
    let hardening = credential_bridge_platform::harden::harden_process();
    for failure in &hardening.failures {
        tracing::warn!("worker {kind}: {failure}");
    }
    let channel = match credential_bridge_platform::channel::inherited_channel() {
        Ok(channel) => channel,
        Err(error) => {
            eprintln!("credential-bridged worker {kind}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!("worker {kind}: cannot start the runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let spec = match kind {
        WorkerKind::Git => Some(SandboxSpec::git_worker()),
        WorkerKind::Gpg => Some(SandboxSpec::gpg_worker()),
        WorkerKind::Vault => None,
    };
    let mut degraded = Vec::new();
    if let Some(spec) = spec {
        match sandbox::apply(&spec) {
            Ok(report) => {
                degraded = report.missing.iter().map(|(layer, why)| format!("{layer:?}: {why}")).collect();
            }
            Err(error) => {
                tracing::error!("worker {kind}: {error}");
                return ExitCode::FAILURE;
            }
        }
    }
    let channel = match send_ready(channel, degraded) {
        Ok(channel) => channel,
        Err(error) => {
            tracing::error!("worker {kind}: cannot send Ready: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async move {
        match kind {
            WorkerKind::Gpg => gpg::serve(channel).await,
            WorkerKind::Git => git::serve(async_stream(channel)?).await,
            WorkerKind::Vault => vault::serve(async_stream(channel)?).await,
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("worker {kind}: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Writes `Ready` with blocking I/O, before the runtime exists.
fn send_ready(
    channel: OwnedFd,
    degraded: Vec<String>,
) -> Result<OwnedFd, credential_bridge_proto::ipc::IpcError> {
    let mut stream = std::os::unix::net::UnixStream::from(channel);
    credential_bridge_proto::ipc::write_frame(&mut stream, &FromWorker::<()>::Ready { degraded })?;
    Ok(OwnedFd::from(stream))
}

/// The channel as a tokio stream (inside the runtime).
fn async_stream(channel: OwnedFd) -> anyhow::Result<tokio::net::UnixStream> {
    let stream = std::os::unix::net::UnixStream::from(channel);
    stream.set_nonblocking(true)?;
    Ok(tokio::net::UnixStream::from_std(stream)?)
}

/// Shared by the worker loops: a writer for frames to the core, usable from many tasks.
pub(crate) type FrameWriter = std::sync::Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>;

/// Encodes and writes one frame to the core; errors are logged (the reader notices a
/// broken channel).
pub(crate) async fn send_frame<T: serde::Serialize>(writer: &FrameWriter, message: &T) {
    let mut writer = writer.lock().await;
    if let Err(error) = crate::frame::write_ipc(&mut *writer, message).await {
        tracing::warn!("writing to the core failed: {error}");
    }
}
