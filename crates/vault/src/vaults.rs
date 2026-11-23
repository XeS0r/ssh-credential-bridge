//! Resolving and storing secret references, per vault.
//!
//! | Vault          | Read                                          | Write                       | Session            |
//! | -------------- | --------------------------------------------- | --------------------------- | ------------------ |
//! | 1Password      | `op read <uri>`                               | `op item edit` / `create`   | desktop app        |
//! | Bitwarden      | `bw get item <item>` (JSON) with `BW_SESSION` | `bw edit` / `create`        | `bw unlock --raw`  |
//! | KeePassXC      | `keepassxc-cli show` with `[vault.keepassxc] database`, else Secret Service (Linux) | `keepassxc-cli edit` / Secret Service | database password with `database`, else the app |
//! | Keychain       | `security-framework` generic password         | same                        | login              |
//! | Secret Service | D-Bus `org.freedesktop.secrets`               | same                        | login              |
//! | pass / gopass  | `pass show <path>`, first line                | `pass insert -m`            | gpg-agent          |
//! | Command        | `sh -c <command>`, stdout minus one newline   | –                           | –                  |
//! | Vault (later)  | –                                             | –                           | –                  |
//!
//! Every value written to a program goes through stdin or the environment, never the
//! command line, where other users could read it.

mod bitwarden;
mod command;
mod json;
mod keepassxc;
mod keychain;
mod onepassword;
mod pass;
#[cfg(all(target_os = "linux", feature = "secret-service"))]
mod secret_service;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::future::Future;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use credential_bridge_config::paths::TargetOs;
use credential_bridge_config::{KeepassxcConfig, SecretRef, VaultKind};
use credential_bridge_proto::ipc::vault::VaultStatus;
use credential_bridge_proto::secret::Secret;

use crate::error::VaultError;
use crate::runner::{CommandRunner, CommandSpec, DEFAULT_TIMEOUT, Deadline};
use crate::session::{Session, UnlockSessions};
use crate::tool::{self, Owner};

/// Default unlock session lifetime when `ctl vault unlock` gives none.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(8 * 60 * 60);

/// Deadline of a whole [`Vaults::store`]: waiting for an earlier store of the vault plus
/// every program the store runs. As long as one program may take; the daemon's deadline
/// for a vault request lies above it, so a store has ended, written or not, before the
/// caller is told it failed.
pub const STORE_DEADLINE: Duration = DEFAULT_TIMEOUT;

/// Timeout of the `--version` probes in [`Vaults::status`].
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// A source of the current time (fake in tests).
pub trait Clock: Debug + Send + Sync {
    /// Now.
    fn now(&self) -> SystemTime;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// All vaults with their sessions.
///
/// Every method takes `&self`, so requests run concurrently. The unlock sessions sit
/// behind a [`Mutex`] that is held only to insert, remove or copy a session, never while
/// a program runs: no request waits for another request's program. The exceptions:
/// [`Vaults::store`] runs the writes to one vault one at a time (see there), and [`Vaults::unlock`] refuses
/// a second unlock of a vault while one is running.
#[derive(Debug)]
pub struct Vaults<R: CommandRunner, C: Clock> {
    /// Runs vault programs.
    pub runner: R,
    /// The clock for session expiry.
    pub clock: C,
    /// Open unlock sessions; locked only briefly (see [`Vaults::sessions`]).
    sessions: Mutex<UnlockSessions>,
    /// Vaults whose unlock program is running (see [`Vaults::unlock`]); locked only to
    /// add or remove a vault.
    unlocking: Mutex<BTreeSet<VaultKind>>,
    /// One per vault, held for the whole of a [`Vaults::store`], so the writes to a vault
    /// run one at a time.
    store_locks: BTreeMap<VaultKind, tokio::sync::Mutex<()>>,
    /// Deadline of a whole [`Vaults::store`] ([`STORE_DEADLINE`]; shorter in tests).
    pub store_deadline: Duration,
    /// `[vault.keepassxc]`: with a `database`, KeePassXC is reached through
    /// `keepassxc-cli` on that file; without one through the app's Secret Service (Linux)
    /// or not at all (macOS, [`VaultError::Invalid`]).
    pub keepassxc: KeepassxcConfig,
    /// The system whose KeePassXC access applies ([`TargetOs::current`]; set in tests).
    pub os: TargetOs,
}

/// How KeePassXC is reached, from [`Vaults::keepassxc`] and [`Vaults::os`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeepassxcAccess {
    /// `keepassxc-cli` on the configured database, with the password from
    /// `ctl vault unlock keepassxc`.
    Cli,
    /// The running app's Secret Service (Linux without a database).
    SecretService,
}

/// The error for KeePassXC on macOS without a configured database.
const MACOS_NEEDS_DATABASE: &str = "on macOS keepassxc:// references need [vault.keepassxc] database in \
     the configuration: run credential-bridge-ctl vault setup keepassxc";

impl<R: CommandRunner, C: Clock> Vaults<R, C> {
    /// Vaults without open sessions.
    pub fn new(runner: R, clock: C) -> Self {
        Self {
            runner,
            clock,
            sessions: Mutex::new(UnlockSessions::new()),
            unlocking: Mutex::new(BTreeSet::new()),
            store_locks: VaultKind::ALL
                .into_iter()
                .map(|vault| (vault, tokio::sync::Mutex::new(())))
                .collect(),
            store_deadline: STORE_DEADLINE,
            keepassxc: KeepassxcConfig::default(),
            os: TargetOs::current(),
        }
    }

    /// These vaults with the `[vault.keepassxc]` settings.
    pub fn with_keepassxc(mut self, keepassxc: KeepassxcConfig) -> Self {
        self.keepassxc = keepassxc;
        self
    }

    /// Reads the secret `reference` points to.
    ///
    /// Errors: [`VaultError::Locked`] (no or expired session, or the app refused),
    /// [`VaultError::NotFound`], [`VaultError::ToolMissing`], [`VaultError::ToolFailed`],
    /// [`VaultError::Timeout`], [`VaultError::Unsupported`] (e.g. Keychain on Linux).
    /// An empty secret counts as not found.
    pub async fn resolve(&self, reference: &SecretRef) -> Result<Secret, VaultError> {
        let secret = match reference {
            SecretRef::OnePassword { uri } => onepassword::read(&self.runner, uri).await?,
            SecretRef::Bitwarden { item, field } => {
                bitwarden::read(&self.runner, &self.session_key(VaultKind::Bitwarden)?, item, field).await?
            }
            SecretRef::KeePassXc { group, item, field } => {
                let entry = keepassxc::Entry { group, item, field };
                let password = self.keepassxc_password()?;
                self.keepassxc_backend(&self.runner, password.as_ref())?.read(&entry).await?
            }
            SecretRef::Keychain { service, account } => keychain::read(service, account).await?,
            SecretRef::SecretService { attributes } => secret_service_read(attributes).await?,
            SecretRef::Pass { path } => pass::read(&self.runner, path).await?,
            SecretRef::Command { command } => command::read(&self.runner, command).await?,
            SecretRef::HashiVault { .. } => return Err(hashi_unsupported()),
        };
        match secret {
            Some(secret) if !secret.is_empty() => Ok(secret),
            _ => Err(VaultError::NotFound { reference: reference.to_string() }),
        }
    }

    /// Writes `value` to `reference`, creating the item or field if needed.
    ///
    /// Only one store per vault runs at a time: the vault programs that write (`pass` with
    /// its git auto-commit, `bw` rewriting its `data.json`, `keepassxc-cli` saving the
    /// database) are not safe against a concurrent write. Reads, stores to other vaults
    /// and other requests do not wait.
    ///
    /// The whole store, waiting for an earlier store of the vault included, runs under one
    /// deadline ([`Vaults::store_deadline`]): no program is started after it, and a
    /// program still running then is killed. In-process writes (Keychain, D-Bus) are
    /// abandoned at the deadline.
    ///
    /// Errors: as [`Vaults::resolve`], plus [`VaultError::ReadOnly`] for `cmd:` and
    /// [`VaultError::StoreTimeout`] or [`VaultError::Timeout`] when the deadline passes.
    pub async fn store(&self, reference: &SecretRef, value: &Secret) -> Result<(), VaultError> {
        if !reference.writable() {
            return Err(VaultError::ReadOnly { reference: reference.to_string() });
        }
        let vault = reference.vault();
        let deadline = tokio::time::Instant::now() + self.store_deadline;
        let Some(lock) = self.store_locks.get(&vault) else {
            return Err(VaultError::Invalid(format!("vault {vault} cannot be written")));
        };
        let _one_writer = in_time(vault, deadline, async { Ok(lock.lock().await) }).await?;
        let runner = Deadline { inner: &self.runner, deadline };
        match reference {
            SecretRef::OnePassword { uri } => onepassword::write(&runner, uri, value).await,
            SecretRef::Bitwarden { item, field } => {
                bitwarden::write(&runner, &self.session_key(VaultKind::Bitwarden)?, item, field, value).await
            }
            SecretRef::KeePassXc { group, item, field } => {
                let entry = keepassxc::Entry { group, item, field };
                let password = self.keepassxc_password()?;
                let backend = self.keepassxc_backend(&runner, password.as_ref())?;
                match backend {
                    keepassxc::Backend::Cli(_) => backend.write(&entry, value).await,
                    keepassxc::Backend::SecretService => {
                        in_time(vault, deadline, backend.write(&entry, value)).await
                    }
                }
            }
            SecretRef::Keychain { service, account } => {
                in_time(vault, deadline, keychain::write(service, account, value)).await
            }
            SecretRef::SecretService { attributes } => {
                in_time(vault, deadline, secret_service_write(reference, attributes, value)).await
            }
            SecretRef::Pass { path } => pass::write(&runner, path, value).await,
            SecretRef::HashiVault { .. } => Err(hashi_unsupported()),
            SecretRef::Command { .. } => Err(VaultError::ReadOnly { reference: reference.to_string() }),
        }
    }

    /// Opens an unlock session with the master password and returns its end. The
    /// password is used once and dropped. The unlock program runs without any lock held;
    /// only the finished session is inserted under the short session lock, and not at all
    /// if the vault was locked while the program ran (the lock wins).
    ///
    /// Only one unlock of a vault runs at a time; a second one is refused at once instead
    /// of waiting. Every `bw unlock` creates a new session key and makes the earlier ones
    /// useless, so two overlapping unlocks could leave the newest key with `bw` and an
    /// older one here, and every read would fail as locked. Reads, stores, other vaults
    /// and [`Vaults::status`] do not wait for an unlock.
    ///
    /// Errors: [`VaultError::Invalid`] for a vault without sessions (or a zero `ttl`),
    /// [`VaultError::UnlockRunning`], [`VaultError::LockedDuringUnlock`], tool errors, or [`VaultError::ToolFailed`] for a
    /// wrong password.
    pub async fn unlock(
        &self,
        vault: VaultKind,
        password: Secret,
        ttl: Option<Duration>,
    ) -> Result<SystemTime, VaultError> {
        let ttl = ttl.unwrap_or(DEFAULT_SESSION_TTL);
        if ttl.is_zero() {
            return Err(VaultError::Invalid("the session lifetime must be longer than zero".to_owned()));
        }
        let _one_unlock = UnlockGuard::new(&self.unlocking, vault)?;
        let generation = self.sessions().lock_generation(vault);
        let key = match vault {
            VaultKind::Bitwarden => bitwarden::unlock(&self.runner, password).await?,
            VaultKind::KeePassXc => match self.keepassxc_access()? {
                KeepassxcAccess::Cli => {
                    let cli = self.keepassxc_cli(&self.runner, None)?;
                    cli.verify(&password).await?;
                    password
                }
                KeepassxcAccess::SecretService => {
                    return Err(VaultError::Invalid(
                        "keepassxc needs no unlock without [vault.keepassxc] database: open the \
                         database in the KeePassXC app, or use keepassxc-cli: credential-bridge-ctl \
                         vault setup keepassxc"
                            .to_owned(),
                    ));
                }
            },
            VaultKind::HashiVault => return Err(hashi_unsupported()),
            other => return Err(VaultError::Invalid(format!("vault {other} has no unlock session"))),
        };
        let expires_at = self.clock.now() + ttl;
        if !self.sessions().insert_unless_locked(vault, Session { key, expires_at }, generation) {
            return Err(VaultError::LockedDuringUnlock { vault });
        }
        Ok(expires_at)
    }

    /// Ends the session of `vault`, or all sessions with `None`.
    pub fn lock(&self, vault: Option<VaultKind>) {
        let mut sessions = self.sessions();
        match vault {
            Some(vault) => {
                sessions.remove(vault);
            }
            None => sessions.clear(),
        }
    }

    /// Drops expired unlock sessions (their keys are zeroized on drop).
    pub fn purge_expired(&self) {
        let now = self.clock.now();
        self.sessions().purge_expired(now);
    }

    /// Whether any unlock session is open now.
    pub fn any_session_open(&self) -> bool {
        let now = self.clock.now();
        self.sessions().any_open(now)
    }

    /// The unlock sessions. Callers hold the guard only for a map operation, never
    /// across an `.await`. A panic while holding it cannot leave the map half-changed,
    /// so a poisoned lock is used as it is.
    fn sessions(&self) -> MutexGuard<'_, UnlockSessions> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Availability and session state of every vault kind (for `ctl check`).
    pub async fn status(&self) -> Vec<VaultStatus> {
        let mut report = Vec::with_capacity(VaultKind::ALL.len());
        for vault in VaultKind::ALL {
            let (available, note) = self.availability(vault).await;
            let now = self.clock.now();
            let unlocked_until = self
                .sessions()
                .get(vault, now)
                .and_then(|session| session.expires_at.duration_since(UNIX_EPOCH).ok())
                .map(|end| end.as_secs());
            report.push(VaultStatus { vault: vault.name().to_owned(), available, unlocked_until, note });
        }
        report
    }

    /// Whether `vault` can be used here, with a note for `ctl check`.
    async fn availability(&self, vault: VaultKind) -> (bool, Option<String>) {
        match vault {
            VaultKind::OnePassword => self.probe(vault, "op", &["--version"]).await,
            VaultKind::Bitwarden => self.probe(vault, "bw", &["--version"]).await,
            VaultKind::KeePassXc => match self.keepassxc_access() {
                Ok(KeepassxcAccess::Cli) => self.keepassxc_cli_available().await,
                Ok(KeepassxcAccess::SecretService) => secret_service_available().await,
                Err(error) => (false, Some(error.to_string())),
            },
            VaultKind::SecretService => secret_service_available().await,
            VaultKind::Keychain => keychain::available(),
            VaultKind::Pass => {
                let (available, note) = self.probe(vault, "pass", &["version"]).await;
                if available {
                    return (true, None);
                }
                let (gopass, _) = self.probe(vault, "gopass", &["--version"]).await;
                if gopass { (true, Some("using gopass".to_owned())) } else { (false, note) }
            }
            VaultKind::Command => (true, None),
            VaultKind::HashiVault => (false, Some("not supported yet".to_owned())),
        }
    }

    /// Runs `program args` briefly to see whether it is installed.
    async fn probe(&self, vault: VaultKind, program: &str, args: &[&str]) -> (bool, Option<String>) {
        let spec = CommandSpec::new(program, args.iter().copied()).with_timeout(PROBE_TIMEOUT);
        match tool::run(&self.runner, Owner::Vault(vault), &spec).await {
            Ok(_) => (true, None),
            Err(VaultError::ToolMissing { program, .. }) => {
                (false, Some(format!("{program} not found in PATH")))
            }
            Err(error) => (false, Some(error.to_string())),
        }
    }

    /// A copy of the session key of `vault`, or [`VaultError::Locked`]. The copy lets the
    /// caller run the vault program without holding the session lock.
    fn session_key(&self, vault: VaultKind) -> Result<Secret, VaultError> {
        let now = self.clock.now();
        self.sessions().get(vault, now).map(|session| session.key.clone()).ok_or(VaultError::Locked { vault })
    }

    /// How KeePassXC is reached: `keepassxc-cli` whenever a database is configured (Linux
    /// and macOS), else the app's Secret Service on Linux; on macOS without a database
    /// [`VaultError::Invalid`].
    fn keepassxc_access(&self) -> Result<KeepassxcAccess, VaultError> {
        match (&self.keepassxc.database, self.os) {
            (Some(_), _) => Ok(KeepassxcAccess::Cli),
            (None, TargetOs::Linux) => Ok(KeepassxcAccess::SecretService),
            (None, TargetOs::MacOs) => Err(VaultError::Invalid(MACOS_NEEDS_DATABASE.to_owned())),
        }
    }

    /// The KeePassXC database password where `keepassxc-cli` needs one (from
    /// `ctl vault unlock keepassxc`, else [`VaultError::Locked`]); `None` for the Secret
    /// Service.
    fn keepassxc_password(&self) -> Result<Option<Secret>, VaultError> {
        match self.keepassxc_access()? {
            KeepassxcAccess::Cli => self.session_key(VaultKind::KeePassXc).map(Some),
            KeepassxcAccess::SecretService => Ok(None),
        }
    }

    /// The KeePassXC access, with the password from [`Vaults::keepassxc_password`].
    fn keepassxc_backend<'a, Q: CommandRunner>(
        &'a self,
        runner: &'a Q,
        password: Option<&'a Secret>,
    ) -> Result<keepassxc::Backend<'a, Q>, VaultError> {
        match self.keepassxc_access()? {
            KeepassxcAccess::Cli => Ok(keepassxc::Backend::Cli(self.keepassxc_cli(runner, password)?)),
            KeepassxcAccess::SecretService => Ok(keepassxc::Backend::SecretService),
        }
    }

    /// `keepassxc-cli` on the configured database (and key file), run by `runner`.
    fn keepassxc_cli<'a, Q: CommandRunner>(
        &'a self,
        runner: &'a Q,
        password: Option<&'a Secret>,
    ) -> Result<keepassxc::Cli<'a, Q>, VaultError> {
        let database = self
            .keepassxc
            .database
            .as_deref()
            .ok_or_else(|| VaultError::Invalid(MACOS_NEEDS_DATABASE.to_owned()))?;
        Ok(keepassxc::Cli { runner, database, key_file: self.keepassxc.key_file.as_deref(), password })
    }

    /// Whether `keepassxc-cli` is installed and the configured files exist.
    async fn keepassxc_cli_available(&self) -> (bool, Option<String>) {
        let (available, note) = self.probe(VaultKind::KeePassXc, keepassxc::CLI, &["--version"]).await;
        if !available {
            return (available, note);
        }
        let files = [("database", &self.keepassxc.database), ("key file", &self.keepassxc.key_file)];
        for (what, path) in files {
            if let Some(path) = path
                && !path.is_file()
            {
                return (false, Some(format!("the {what} {} does not exist", path.display())));
            }
        }
        let database =
            self.keepassxc.database.as_deref().map(|d| d.display().to_string()).unwrap_or_default();
        (true, Some(format!("keepassxc-cli on {database}")))
    }
}

/// `work` until `deadline`, else [`VaultError::StoreTimeout`] (`work` is dropped).
async fn in_time<T>(
    vault: VaultKind,
    deadline: tokio::time::Instant,
    work: impl Future<Output = Result<T, VaultError>>,
) -> Result<T, VaultError> {
    tokio::time::timeout_at(deadline, work).await.unwrap_or(Err(VaultError::StoreTimeout { vault }))
}

/// Marks an unlock of one vault as running until it is dropped.
struct UnlockGuard<'a> {
    unlocking: &'a Mutex<BTreeSet<VaultKind>>,
    vault: VaultKind,
}

impl<'a> UnlockGuard<'a> {
    /// Marks `vault` as unlocking, or [`VaultError::UnlockRunning`] if it already is. The
    /// set holds no state a panic could leave half-changed, so a poisoned lock is used as
    /// it is.
    fn new(unlocking: &'a Mutex<BTreeSet<VaultKind>>, vault: VaultKind) -> Result<Self, VaultError> {
        if unlocking.lock().unwrap_or_else(PoisonError::into_inner).insert(vault) {
            Ok(Self { unlocking, vault })
        } else {
            Err(VaultError::UnlockRunning { vault })
        }
    }
}

impl Drop for UnlockGuard<'_> {
    fn drop(&mut self) {
        self.unlocking.lock().unwrap_or_else(PoisonError::into_inner).remove(&self.vault);
    }
}

/// HashiCorp Vault is planned, not implemented.
fn hashi_unsupported() -> VaultError {
    VaultError::Unsupported { vault: VaultKind::HashiVault, reason: "not implemented yet".to_owned() }
}

/// The error for Secret Service references where D-Bus is not available.
#[cfg(not(all(target_os = "linux", feature = "secret-service")))]
fn secret_service_unsupported(vault: VaultKind) -> VaultError {
    let reason = if cfg!(target_os = "linux") {
        "this build has no Secret Service support (feature secret-service)"
    } else {
        "the Secret Service is only available on Linux"
    };
    VaultError::Unsupported { vault, reason: reason.to_owned() }
}

async fn secret_service_read(attributes: &[(String, String)]) -> Result<Option<Secret>, VaultError> {
    #[cfg(all(target_os = "linux", feature = "secret-service"))]
    return secret_service::read(attributes).await;
    #[cfg(not(all(target_os = "linux", feature = "secret-service")))]
    {
        let _ = attributes;
        Err(secret_service_unsupported(VaultKind::SecretService))
    }
}

async fn secret_service_write(
    reference: &SecretRef,
    attributes: &[(String, String)],
    value: &Secret,
) -> Result<(), VaultError> {
    #[cfg(all(target_os = "linux", feature = "secret-service"))]
    return secret_service::write(&reference.to_string(), attributes, value).await;
    #[cfg(not(all(target_os = "linux", feature = "secret-service")))]
    {
        let _ = (reference, attributes, value);
        Err(secret_service_unsupported(VaultKind::SecretService))
    }
}

async fn secret_service_available() -> (bool, Option<String>) {
    #[cfg(all(target_os = "linux", feature = "secret-service"))]
    return secret_service::available().await;
    #[cfg(not(all(target_os = "linux", feature = "secret-service")))]
    (false, Some(secret_service_unsupported(VaultKind::SecretService).to_string()))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use super::*;
    use crate::runner::SystemRunner;

    /// A clock tests can move.
    #[derive(Debug)]
    pub(crate) struct FakeClock(pub Mutex<SystemTime>);

    impl FakeClock {
        pub(crate) fn at(secs: u64) -> Self {
            Self(Mutex::new(UNIX_EPOCH + Duration::from_secs(secs)))
        }

        pub(crate) fn advance(&self, by: Duration) {
            *self.0.lock().unwrap() += by;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> SystemTime {
            *self.0.lock().unwrap()
        }
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

    /// A temporary directory of fake programs, first in `PATH`.
    pub(crate) struct FakeBin {
        pub(crate) dir: tempfile::TempDir,
    }

    impl FakeBin {
        pub(crate) fn new() -> Self {
            Self { dir: tempfile::tempdir().unwrap() }
        }

        /// Writes an executable `sh` script `name`.
        pub(crate) fn script(&self, name: &str, body: &str) -> &Self {
            write_script(&self.dir.path().join(name), body);
            self
        }

        pub(crate) fn path(&self) -> &Path {
            self.dir.path()
        }

        /// A runner whose `PATH` starts with this directory; `HOME` points into it.
        pub(crate) fn runner(&self) -> SystemRunner {
            let path = format!("{}:{}", self.dir.path().display(), std::env::var("PATH").unwrap_or_default());
            SystemRunner::new(vec![
                ("PATH".into(), path),
                ("HOME".into(), self.dir.path().display().to_string()),
            ])
        }

        pub(crate) fn vaults(&self) -> Vaults<SystemRunner, FakeClock> {
            Vaults::new(self.runner(), FakeClock::at(1_000_000))
        }
    }

    fn secret(text: &str) -> Secret {
        Secret::new(text.to_owned())
    }

    #[tokio::test]
    async fn bitwarden_is_locked_without_session_and_unlocks() {
        let bin = FakeBin::new();
        bin.script(
            "bw",
            r#"case "$*" in
  *"unlock --raw --passwordenv BW_PASSWORD"*) [ "$BW_PASSWORD" = right ] && printf 'sess-key' && exit 0; echo "Invalid master password." >&2; exit 1 ;;
  *"get item app"*) [ "$BW_SESSION" = sess-key ] || { echo "Vault is locked." >&2; exit 1; }
     printf '{"id":"1","name":"app","login":{"username":"me","password":"pw"},"fields":[{"name":"token","value":"tok"}]}' ;;
esac"#,
        );
        let vaults = bin.vaults();
        let reference = SecretRef::Bitwarden { item: "app".into(), field: "token".into() };
        let error = vaults.resolve(&reference).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "vault bitwarden is locked: run credential-bridge-ctl vault unlock bitwarden"
        );

        let wrong = vaults.unlock(VaultKind::Bitwarden, secret("wrong"), None).await.unwrap_err();
        assert!(matches!(wrong, VaultError::ToolFailed { .. }), "{wrong:?}");
        assert!(!vaults.any_session_open());

        let end = vaults
            .unlock(VaultKind::Bitwarden, secret("right"), Some(Duration::from_secs(60)))
            .await
            .unwrap();
        assert_eq!(end, vaults.clock.now() + Duration::from_secs(60));
        assert_eq!(vaults.resolve(&reference).await.unwrap().expose(), "tok");
        let password = SecretRef::Bitwarden { item: "app".into(), field: "password".into() };
        assert_eq!(vaults.resolve(&password).await.unwrap().expose(), "pw");
        let missing = SecretRef::Bitwarden { item: "app".into(), field: "nope".into() };
        assert!(matches!(vaults.resolve(&missing).await, Err(VaultError::NotFound { .. })));

        let status = vaults.status().await;
        let bw = status.iter().find(|s| s.vault == "bitwarden").unwrap();
        assert_eq!(bw.unlocked_until, Some(1_000_060));

        vaults.clock.advance(Duration::from_secs(61));
        assert!(matches!(vaults.resolve(&reference).await, Err(VaultError::Locked { .. })));
    }

    #[tokio::test]
    async fn lock_during_unlock_keeps_the_vault_locked() {
        let bin = FakeBin::new();
        bin.script("bw", "sleep 1; printf key");
        let vaults = std::sync::Arc::new(bin.vaults());
        let unlocking = {
            let vaults = vaults.clone();
            tokio::spawn(async move { vaults.unlock(VaultKind::Bitwarden, secret("pw"), None).await })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        vaults.lock(Some(VaultKind::Bitwarden));
        let error = unlocking.await.unwrap().unwrap_err();
        assert_eq!(error, VaultError::LockedDuringUnlock { vault: VaultKind::Bitwarden });
        assert_eq!(
            error.to_string(),
            "vault bitwarden was locked while it was being unlocked; unlock it again"
        );
        assert_eq!(error.kind(), credential_bridge_proto::ipc::WorkerErrorKind::Locked);
        assert!(!vaults.any_session_open());
    }

    /// A second unlock of a vault whose unlock is running is refused at once; the first
    /// one opens the session, and afterwards the vault can be unlocked again.
    #[tokio::test]
    async fn a_second_unlock_of_a_vault_is_refused_at_once() {
        let bin = FakeBin::new();
        bin.script("bw", "sleep 1; printf key");
        let vaults = std::sync::Arc::new(bin.vaults());
        let first = {
            let vaults = vaults.clone();
            tokio::spawn(async move { vaults.unlock(VaultKind::Bitwarden, secret("pw"), None).await })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        let second = tokio::time::timeout(
            Duration::from_millis(300),
            vaults.unlock(VaultKind::Bitwarden, secret("pw"), None),
        )
        .await
        .expect("the second unlock waited");
        let error = second.unwrap_err();
        assert_eq!(error, VaultError::UnlockRunning { vault: VaultKind::Bitwarden });
        assert_eq!(error.to_string(), "an unlock of bitwarden is already running");
        assert!(!first.is_finished(), "the test needs the first unlock to be still running");
        first.await.unwrap().unwrap();
        assert!(vaults.any_session_open());

        vaults.unlock(VaultKind::Bitwarden, secret("pw"), None).await.unwrap();
    }

    /// A failed unlock does not keep the vault marked as unlocking.
    #[tokio::test]
    async fn a_failed_unlock_ends_the_unlock() {
        let bin = FakeBin::new();
        bin.script("bw", "echo 'Invalid master password.' >&2; exit 1");
        let vaults = bin.vaults();
        for _ in 0..2 {
            let error = vaults.unlock(VaultKind::Bitwarden, secret("pw"), None).await.unwrap_err();
            assert!(matches!(error, VaultError::ToolFailed { .. }), "{error:?}");
        }
    }

    /// Unlocks of different vaults do not exclude each other.
    #[test]
    fn unlocks_of_different_vaults_run_concurrently() {
        let unlocking = Mutex::new(BTreeSet::new());
        let bitwarden = UnlockGuard::new(&unlocking, VaultKind::Bitwarden).unwrap();
        let keepassxc = UnlockGuard::new(&unlocking, VaultKind::KeePassXc).unwrap();
        assert!(matches!(
            UnlockGuard::new(&unlocking, VaultKind::Bitwarden),
            Err(VaultError::UnlockRunning { vault: VaultKind::Bitwarden })
        ));
        drop(bitwarden);
        let _bitwarden = UnlockGuard::new(&unlocking, VaultKind::Bitwarden).unwrap();
        drop(keepassxc);
    }

    /// While a Bitwarden unlock runs, an unlock of another vault is not refused for it.
    #[tokio::test]
    async fn a_running_unlock_does_not_hold_up_another_vault() {
        let bin = FakeBin::new();
        bin.script("bw", "sleep 1; printf key");
        let vaults = std::sync::Arc::new(bin.vaults());
        let bitwarden = {
            let vaults = vaults.clone();
            tokio::spawn(async move { vaults.unlock(VaultKind::Bitwarden, secret("pw"), None).await })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        // KeePassXC has no database configured here, so its unlock fails at once, but not
        // because of the Bitwarden unlock.
        let other = tokio::time::timeout(
            Duration::from_millis(300),
            vaults.unlock(VaultKind::KeePassXc, secret("pw"), None),
        )
        .await
        .expect("the other vault's unlock waited");
        assert!(matches!(other, Err(VaultError::Invalid(_))), "{other:?}");
        assert!(!bitwarden.is_finished());
        bitwarden.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn lock_ends_sessions() {
        let bin = FakeBin::new();
        bin.script("bw", "printf key");
        let vaults = bin.vaults();
        vaults.unlock(VaultKind::Bitwarden, secret("pw"), None).await.unwrap();
        assert!(vaults.any_session_open());
        vaults.lock(Some(VaultKind::Bitwarden));
        assert!(!vaults.any_session_open());
    }

    #[tokio::test]
    async fn unlock_rejects_vaults_without_sessions() {
        let bin = FakeBin::new();
        let vaults = bin.vaults();
        for vault in [VaultKind::OnePassword, VaultKind::Pass, VaultKind::Command] {
            let error = vaults.unlock(vault, secret("pw"), None).await.unwrap_err();
            assert!(matches!(error, VaultError::Invalid(_)), "{error:?}");
        }
        let error =
            vaults.unlock(VaultKind::Bitwarden, secret("pw"), Some(Duration::ZERO)).await.unwrap_err();
        assert!(matches!(error, VaultError::Invalid(_)));
        let error = vaults.unlock(VaultKind::KeePassXc, secret("pw"), None).await.unwrap_err();
        assert!(matches!(error, VaultError::Invalid(_)));
    }

    #[tokio::test]
    async fn missing_tools_are_reported() {
        let bin = FakeBin::new();
        // Only the fake directory: no real `op` can be found.
        let runner = SystemRunner::new(vec![("PATH".into(), bin.path().display().to_string())]);
        let vaults = Vaults::new(runner, FakeClock::at(0));
        let error = vaults.resolve(&SecretRef::OnePassword { uri: "op://a/b/c".into() }).await.unwrap_err();
        assert_eq!(error.to_string(), "vault 1password needs op, which is not in PATH");
        let status = vaults.status().await;
        let op = status.iter().find(|s| s.vault == "1password").unwrap();
        assert!(!op.available);
        assert_eq!(op.note.as_deref(), Some("op not found in PATH"));
        assert!(status.iter().find(|s| s.vault == "cmd").unwrap().available);
        assert_eq!(status.len(), VaultKind::ALL.len());
    }

    #[tokio::test]
    async fn command_is_read_only_and_trims_one_newline() {
        let bin = FakeBin::new();
        let vaults = bin.vaults();
        let reference = SecretRef::Command { command: "printf 'abc\\n\\n'".into() };
        assert_eq!(vaults.resolve(&reference).await.unwrap().expose(), "abc\n");
        let error = vaults.store(&reference, &secret("x")).await.unwrap_err();
        assert!(matches!(error, VaultError::ReadOnly { .. }));
        let empty = SecretRef::Command { command: "true".into() };
        assert!(matches!(vaults.resolve(&empty).await, Err(VaultError::NotFound { .. })));
    }

    /// A store waiting behind an earlier store of the same vault gives up at the
    /// deadline and starts no program afterwards.
    #[tokio::test]
    async fn a_store_waiting_past_its_deadline_writes_nothing() {
        let bin = FakeBin::new();
        let log = bin.path().join("log");
        bin.script("pass", &format!("cat >/dev/null; echo \"$1\" >> {}", log.display()));
        let mut vaults = bin.vaults();
        vaults.store_deadline = Duration::from_millis(300);
        let earlier_store = vaults.store_locks[&VaultKind::Pass].lock().await;
        let begin = std::time::Instant::now();
        let result = vaults.store(&SecretRef::Pass { path: "a".into() }, &secret("v")).await;
        assert_eq!(result, Err(VaultError::StoreTimeout { vault: VaultKind::Pass }));
        assert!(begin.elapsed() < Duration::from_secs(1), "{:?}", begin.elapsed());
        drop(earlier_store);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!log.exists(), "a program ran after the deadline");
        assert_eq!(
            VaultError::StoreTimeout { vault: VaultKind::Pass }.to_string(),
            "storing in pass did not finish in time"
        );
    }

    /// A program still running at the deadline is killed.
    #[tokio::test]
    async fn a_store_program_is_killed_at_the_deadline() {
        let bin = FakeBin::new();
        bin.script("pass", "cat >/dev/null; sleep 5");
        let mut vaults = bin.vaults();
        vaults.store_deadline = Duration::from_millis(300);
        let begin = std::time::Instant::now();
        let error = vaults.store(&SecretRef::Pass { path: "a".into() }, &secret("v")).await.unwrap_err();
        assert!(matches!(error, VaultError::Timeout { .. }), "{error:?}");
        assert!(begin.elapsed() < Duration::from_secs(2), "{:?}", begin.elapsed());
    }

    /// The deadline covers all programs of one store: Bitwarden's `bw edit` is not started
    /// when `bw get item` used up the time.
    #[tokio::test]
    async fn one_deadline_covers_every_program_of_a_store() {
        let bin = FakeBin::new();
        let log = bin.path().join("log");
        bin.script(
            "bw",
            &format!(
                r#"echo "$1" >> {log}
case "$1" in
  unlock) printf key ;;
  get) sleep 0.2; printf '{{"id":"1","name":"app","fields":[]}}' ;;
  *) cat >/dev/null ;;
esac"#,
                log = log.display()
            ),
        );
        let mut vaults = bin.vaults();
        vaults.unlock(VaultKind::Bitwarden, secret("pw"), None).await.unwrap();
        fs::remove_file(&log).unwrap();
        vaults.store_deadline = Duration::from_millis(150);
        let reference = SecretRef::Bitwarden { item: "app".into(), field: "token".into() };
        let error = vaults.store(&reference, &secret("v")).await.unwrap_err();
        assert!(matches!(error, VaultError::Timeout { .. }), "{error:?}");
        assert_eq!(fs::read_to_string(&log).unwrap(), "get\n");

        vaults.store_deadline = Duration::from_secs(5);
        vaults.store(&reference, &secret("v")).await.unwrap();
        assert_eq!(fs::read_to_string(&log).unwrap(), "get\nget\nedit\n");
    }

    /// Stores to different vaults do not wait for each other.
    #[tokio::test]
    async fn stores_to_different_vaults_run_concurrently() {
        let bin = FakeBin::new();
        bin.script("pass", "cat >/dev/null; sleep 1");
        bin.script(
            "op",
            r#"case "$1 $2" in
  "item get") printf '{"id":"1","fields":[]}' ;;
  *) cat >/dev/null ;;
esac"#,
        );
        let vaults = std::sync::Arc::new(bin.vaults());
        let slow = {
            let vaults = std::sync::Arc::clone(&vaults);
            tokio::spawn(
                async move { vaults.store(&SecretRef::Pass { path: "a".into() }, &secret("v")).await },
            )
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        let reference = SecretRef::OnePassword { uri: "op://vault/item/field".into() };
        tokio::time::timeout(Duration::from_millis(500), vaults.store(&reference, &secret("v")))
            .await
            .expect("the store waited for another vault's store")
            .unwrap();
        assert!(!slow.is_finished());
        slow.await.unwrap().unwrap();
    }

    /// Two stores never run at the same time; a read meanwhile does not wait.
    #[tokio::test]
    async fn stores_to_one_vault_run_one_at_a_time() {
        let bin = FakeBin::new();
        // `insert` fails if another insert is running, and takes a while.
        let busy = bin.path().join("busy");
        bin.script(
            "pass",
            &format!(
                r#"case "$1" in
  insert) mkdir {busy} 2>/dev/null || {{ echo "concurrent insert" >&2; exit 1; }}
          cat >/dev/null; sleep 0.3; rmdir {busy} ;;
  show) printf 'value\n' ;;
esac"#,
                busy = busy.display()
            ),
        );
        let vaults = std::sync::Arc::new(bin.vaults());
        let stores: Vec<_> = (0..3)
            .map(|n| {
                let vaults = std::sync::Arc::clone(&vaults);
                tokio::spawn(async move {
                    let reference = SecretRef::Pass { path: format!("entry{n}") };
                    vaults.store(&reference, &secret("v")).await
                })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let entry = SecretRef::Pass { path: "entry0".into() };
        let read = tokio::time::timeout(Duration::from_millis(250), vaults.resolve(&entry))
            .await
            .expect("the read waited");
        assert_eq!(read.unwrap().expose(), "value");
        for store in stores {
            store.await.unwrap().unwrap();
        }
    }

    /// A fake `keepassxc-cli` for the database `<bin>/db.kdbx` with password `dbpw`, which
    /// needs the key file `<bin>/db.keyx` if `needs_key_file`. One entry `Dev/app` with
    /// password `s3cret`; `add`/`edit` append the entry and their stdin to `<bin>/writes`.
    fn fake_keepassxc_cli(bin: &FakeBin, needs_key_file: bool) -> (KeepassxcConfig, PathBuf) {
        let database = bin.path().join("db.kdbx");
        let key_file = bin.path().join("db.keyx");
        fs::write(&database, b"kdbx").unwrap();
        fs::write(&key_file, b"key").unwrap();
        let writes = bin.path().join("writes");
        bin.script(
            "keepassxc-cli",
            &format!(
                r#"[ "$1" = --version ] && {{ echo 2.7.10; exit 0; }}
read pw
case " $* " in
  *" --key-file {key} {db} "*) key=1 ;;
  *" --key-file "*) echo "Failed to load key file" >&2; exit 1 ;;
  *" {db} "*) key=0 ;;
  *) echo "Failed to open database: no such file" >&2; exit 1 ;;
esac
[ "$pw" = dbpw ] && [ "$key" = {needs} ] || {{ echo "Error while reading the database: Invalid credentials were provided" >&2; exit 1; }}
for last; do :; done
case "$1" in
  ls) echo "Dev/" ;;
  show) [ "$last" = Dev/app ] || {{ echo "Could not find entry with path $last." >&2; exit 1; }}
        printf 's3cret\n' ;;
  add|edit) echo "$1 $last" >> '{writes}'; cat >> '{writes}' ;;
esac"#,
                key = key_file.display(),
                db = database.display(),
                needs = u8::from(needs_key_file),
                writes = writes.display(),
            ),
        );
        let config =
            KeepassxcConfig { database: Some(database), key_file: needs_key_file.then_some(key_file) };
        (config, writes)
    }

    fn keepassxc_ref(item: &str) -> SecretRef {
        SecretRef::KeePassXc { group: vec!["Dev".into()], item: item.into(), field: "password".into() }
    }

    /// With `[vault.keepassxc] database`, KeePassXC goes through `keepassxc-cli` on that
    /// file on both systems, after `ctl vault unlock keepassxc`, with a session that expires.
    #[tokio::test]
    async fn keepassxc_with_a_database_uses_keepassxc_cli() {
        for os in [TargetOs::Linux, TargetOs::MacOs] {
            let bin = FakeBin::new();
            let (config, writes) = fake_keepassxc_cli(&bin, false);
            let mut vaults = bin.vaults().with_keepassxc(config);
            vaults.os = os;
            let reference = keepassxc_ref("app");
            assert_eq!(
                vaults.resolve(&reference).await.unwrap_err(),
                VaultError::Locked { vault: VaultKind::KeePassXc },
                "{os:?}"
            );
            let wrong = vaults.unlock(VaultKind::KeePassXc, secret("bad"), None).await.unwrap_err();
            assert_eq!(wrong.to_string(), "keepassxc-cli failed: wrong database password");
            let end = vaults
                .unlock(VaultKind::KeePassXc, secret("dbpw"), Some(Duration::from_secs(60)))
                .await
                .unwrap();
            assert_eq!(end, vaults.clock.now() + Duration::from_secs(60));
            assert_eq!(vaults.resolve(&reference).await.unwrap().expose(), "s3cret");
            assert!(matches!(vaults.resolve(&keepassxc_ref("nope")).await, Err(VaultError::NotFound { .. })));

            vaults.store(&reference, &secret("v1")).await.unwrap();
            vaults.store(&keepassxc_ref("new"), &secret("v2")).await.unwrap();
            assert_eq!(fs::read_to_string(&writes).unwrap(), "edit Dev/app\nv1\nv1\nadd Dev/new\nv2\nv2\n");

            let status = vaults.status().await;
            let keepassxc = status.iter().find(|s| s.vault == "keepassxc").unwrap();
            assert!(keepassxc.available, "{keepassxc:?}");
            assert_eq!(keepassxc.unlocked_until, Some(1_000_060));

            vaults.clock.advance(Duration::from_secs(61));
            assert_eq!(
                vaults.resolve(&reference).await.unwrap_err(),
                VaultError::Locked { vault: VaultKind::KeePassXc }
            );
        }
    }

    /// `key_file` is passed as `--key-file`; a database that needs one cannot be opened
    /// without it.
    #[tokio::test]
    async fn keepassxc_key_file_is_passed() {
        let bin = FakeBin::new();
        let (config, _) = fake_keepassxc_cli(&bin, true);
        let without_key_file = KeepassxcConfig { key_file: None, ..config.clone() };
        let vaults = bin.vaults().with_keepassxc(without_key_file);
        let error = vaults.unlock(VaultKind::KeePassXc, secret("dbpw"), None).await.unwrap_err();
        assert_eq!(error.to_string(), "keepassxc-cli failed: wrong database password");
        assert!(!vaults.any_session_open());

        let vaults = bin.vaults().with_keepassxc(config);
        vaults.unlock(VaultKind::KeePassXc, secret("dbpw"), None).await.unwrap();
        assert_eq!(vaults.resolve(&keepassxc_ref("app")).await.unwrap().expose(), "s3cret");
        vaults.store(&keepassxc_ref("app"), &secret("v")).await.unwrap();
    }

    /// A configured file that does not exist makes the vault unavailable in the status.
    #[tokio::test]
    async fn keepassxc_status_reports_missing_files() {
        let bin = FakeBin::new();
        let (mut config, _) = fake_keepassxc_cli(&bin, true);
        config.key_file = Some(bin.path().join("missing.keyx"));
        let vaults = bin.vaults().with_keepassxc(config);
        let status = vaults.status().await;
        let keepassxc = status.iter().find(|s| s.vault == "keepassxc").unwrap();
        assert!(!keepassxc.available);
        let note = keepassxc.note.as_deref().unwrap();
        assert!(note.starts_with("the key file ") && note.ends_with("missing.keyx does not exist"), "{note}");
    }

    /// On macOS without a database, KeePassXC references, unlock and status say that the
    /// database must be configured.
    #[tokio::test]
    async fn keepassxc_on_macos_needs_a_database() {
        let bin = FakeBin::new();
        let mut vaults = bin.vaults();
        vaults.os = TargetOs::MacOs;
        let expected = VaultError::Invalid(MACOS_NEEDS_DATABASE.to_owned());
        assert_eq!(vaults.resolve(&keepassxc_ref("app")).await.unwrap_err(), expected);
        assert_eq!(vaults.store(&keepassxc_ref("app"), &secret("v")).await.unwrap_err(), expected);
        assert_eq!(vaults.unlock(VaultKind::KeePassXc, secret("pw"), None).await.unwrap_err(), expected);
        let status = vaults.status().await;
        let keepassxc = status.iter().find(|s| s.vault == "keepassxc").unwrap();
        assert!(!keepassxc.available);
        assert!(keepassxc.note.as_deref().unwrap().contains("[vault.keepassxc] database"));
    }

    /// On Linux without a database, the running app is used and needs no unlock.
    #[tokio::test]
    async fn keepassxc_on_linux_without_a_database_needs_no_unlock() {
        let bin = FakeBin::new();
        let mut vaults = bin.vaults();
        vaults.os = TargetOs::Linux;
        let error = vaults.unlock(VaultKind::KeePassXc, secret("pw"), None).await.unwrap_err();
        assert!(
            matches!(&error, VaultError::Invalid(m) if m.contains("open the database in the KeePassXC app"))
        );
    }

    #[tokio::test]
    async fn hashicorp_vault_is_not_supported_yet() {
        let bin = FakeBin::new();
        let vaults = bin.vaults();
        let reference = SecretRef::HashiVault { path: "kv/x".into(), field: "f".into() };
        assert!(matches!(vaults.resolve(&reference).await, Err(VaultError::Unsupported { .. })));
    }

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn keychain_is_macos_only() {
        let bin = FakeBin::new();
        let vaults = bin.vaults();
        let reference = SecretRef::Keychain { service: "s".into(), account: "a".into() };
        assert!(matches!(vaults.resolve(&reference).await, Err(VaultError::Unsupported { .. })));
    }
}
