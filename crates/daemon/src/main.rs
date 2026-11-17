use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{CommandFactory, Parser, Subcommand};
use credential_bridge_core::config::Config;
use credential_bridge_core::paths;
use credential_bridged::server::Server;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::registry::LookupSpan;

const LONG_ABOUT: &str = "\
Serves local git credentials to SSH remotes.

credential-bridged listens on one unix socket per configured remote. You forward
a remote's socket with `RemoteForward` in ~/.ssh/config; git on the remote then
asks for credentials through `git-credential-bridge`. Every request is checked
against that remote's policy (allowed URLs and operations) before the local
backend (by default `gh auth git-credential`) is asked.

Usually started by the user service that `credential-bridge-ctl service install`
sets up. Send SIGHUP to reload the configuration.";

/// Serve local git credentials to SSH remotes over per-remote unix sockets.
#[derive(Debug, Parser)]
#[command(name = "credential-bridged", version, long_about = LONG_ABOUT)]
struct Cli {
    /// Configuration file [default: $XDG_CONFIG_HOME/credential-bridge/config.toml]
    #[arg(short, long, global = true, env = "CREDENTIAL_BRIDGE_CONFIG", value_name = "PATH")]
    config: Option<PathBuf>,

    /// Log filter: error, warn, info, debug, trace or a tracing directive
    #[arg(long, global = true, env = "CREDENTIAL_BRIDGE_LOG", default_value = "info", value_name = "FILTER")]
    log: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the daemon in the foreground (used by the service manager)
    Run,
    /// Validate the configuration and print the sockets that would be served
    CheckConfig,
    /// Write man pages to DIR
    #[command(hide = true)]
    GenerateMan { dir: PathBuf },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match real_main(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("credential-bridged: error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn real_main(cli: Cli) -> anyhow::Result<()> {
    let config_path = match cli.config {
        Some(path) => path,
        None => paths::default_config_file()?,
    };
    match cli.command {
        Commands::Run => {
            init_logging(&cli.log);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("cannot start the async runtime")?;
            runtime.block_on(serve(&config_path))
        }
        Commands::CheckConfig => check_config(&config_path),
        Commands::GenerateMan { dir } => {
            std::fs::create_dir_all(&dir)?;
            clap_mangen::generate_to(Cli::command(), &dir)?;
            Ok(())
        }
    }
}

fn init_logging(filter: &str) {
    let filter = EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info"));
    // journald adds its own timestamps.
    let time = std::env::var_os("JOURNAL_STREAM").is_none();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .event_format(PlainFormat { time })
        .init();
}

/// One line per event: `[time ]message`, with `warning: `/`error: ` in front
/// of those levels. Request lines carry their own columns (see `server`).
struct PlainFormat {
    time: bool,
}

impl<S, N> FormatEvent<S, N> for PlainFormat
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        if self.time {
            SystemTime.format_time(&mut writer)?;
            writer.write_char(' ')?;
        }
        match *event.metadata().level() {
            tracing::Level::ERROR => writer.write_str("error: ")?,
            tracing::Level::WARN => writer.write_str("warning: ")?,
            _ => {}
        }
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

/// Records which configuration is in effect, for ctl to wait on after a
/// reload. A local file only: nothing about the configuration goes to remotes.
fn record_loaded(fingerprint: &str) {
    let write = || -> std::io::Result<()> {
        let path = paths::loaded_config_file().map_err(std::io::Error::other)?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, format!("{fingerprint}\n"))?;
        std::fs::rename(&tmp, &path)
    };
    if let Err(err) = write() {
        warn!("cannot record the loaded configuration: {err}");
    }
}

/// Tells systemd (`Type=notify`) that the sockets are bound, so that
/// `systemctl start` and with it `service install` return only then.
fn notify_ready() {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else { return };
    if let Err(err) = send_notify(&path, b"READY=1") {
        warn!("cannot notify the service manager: {err}");
    }
}

fn send_notify(path: &std::ffi::OsStr, message: &[u8]) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixDatagram;
    let socket = UnixDatagram::unbound()?;
    match path.as_bytes().strip_prefix(b"@") {
        #[cfg(target_os = "linux")]
        Some(name) => {
            use std::os::linux::net::SocketAddrExt;
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
            socket.send_to_addr(message, &addr)?;
        }
        #[cfg(not(target_os = "linux"))]
        Some(_) => return Err(std::io::Error::other("abstract sockets need Linux")),
        None => {
            socket.send_to(message, path)?;
        }
    }
    Ok(())
}

fn check_config(path: &Path) -> anyhow::Result<()> {
    let config = Config::load(path)?;
    let remotes = config.resolve()?;
    println!("configuration {} is valid", path.display());
    if remotes.is_empty() {
        println!("no remotes configured");
    }
    for remote in remotes {
        println!();
        println!("remote {}", remote.name);
        println!("  socket:     {}", remote.socket.display());
        let allow: Vec<String> = remote.policy.allow.iter().map(ToString::to_string).collect();
        println!("  allow:      {}", allow.join(", "));
        let ops: Vec<&str> = remote.policy.operations.iter().map(|op| op.as_str()).collect();
        println!("  operations: {}", ops.join(", "));
        println!("  backend:    {}", remote.backend);
    }
    Ok(())
}

fn announce(server: &Server, config_path: &Path) {
    let mut any = false;
    for (name, socket) in server.sockets() {
        info!("listening for {name} on {}", socket.display());
        any = true;
    }
    if !any {
        warn!(
            "no remotes configured in {} → credential-bridge-ctl remote add NAME --allow URL",
            config_path.display()
        );
    }
}

async fn serve(config_path: &Path) -> anyhow::Result<()> {
    // Handlers first: until they exist, SIGHUP (sent by `credential-bridge-ctl`
    // after every config change) would kill the daemon, and systemd counts
    // that as a clean exit and does not restart it. A signal that arrives
    // while the config loads is picked up by the loop below.
    let mut hangup = signal(SignalKind::hangup())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;

    let (config, fingerprint) = Config::load_with_fingerprint(config_path)?;
    let mut server = Server::start(&config)?;
    info!("credential-bridged {} started with {}", env!("CARGO_PKG_VERSION"), config_path.display());
    announce(&server, config_path);
    record_loaded(&fingerprint);
    notify_ready();
    loop {
        tokio::select! {
            _ = hangup.recv() => {
                info!("reloading the configuration (SIGHUP)");
                let (new_config, fingerprint) = match Config::load_with_fingerprint(config_path) {
                    Ok(loaded) => loaded,
                    Err(err) => {
                        error!("keeping the current configuration: {err}");
                        continue;
                    }
                };
                // Unchanged sockets keep listening; on error nothing changes.
                if let Err(err) = server.reload(&new_config) {
                    error!("keeping the current configuration: {err:#}");
                    continue;
                }
                record_loaded(&fingerprint);
                announce(&server, config_path);
            }
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
        }
    }
    drop(server);
    if let Ok(path) = paths::loaded_config_file() {
        let _ = std::fs::remove_file(path);
    }
    info!("credential-bridged stopped");
    Ok(())
}
