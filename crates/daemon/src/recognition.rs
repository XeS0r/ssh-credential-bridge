//! Which `[server.*]` a verified server bind selects (`docs/architecture.md`,
//! "Recognising the server").
//!
//! The map from host key to server ([`HostKeyMap`]) comes from the pinned `host_keys`
//! and, for servers with `known_host`, from the known_hosts files. It is built when the
//! configuration is loaded or reloaded. Before every lookup the daemon checks whether
//! any of the files changed (modification time, size, inode, or appeared or vanished)
//! since they were read; if so, the map is rebuilt first. A host key that ssh learned,
//! replaced or revoked (`UpdateHostKeys`, `ssh-keygen -R`, `@revoked`) counts from the
//! next connection on, and a removed key stops selecting its server at once. There is no
//! polling.
//!
//! The files are read outside the lock, so other connections keep using the current
//! map meanwhile. Warnings (unreadable files, a followed server without keys, a key of
//! several servers) are logged when they first appear, not on every rebuild.
//!
//! The core is not sandboxed (only the workers are), so it can read the known_hosts
//! files wherever they are.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use credential_bridge_config::Config;
use credential_bridge_config::host_keys::{HostKeyMap, HostKeyWarning, Recognition};
use credential_bridge_config::known_hosts::KnownHosts;

use crate::sync::lock;

/// What identifies a file's contents for the change check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
}

impl Stamp {
    /// The file's stamp; `None` if it cannot be looked at (missing).
    fn of(path: &Path) -> Option<Stamp> {
        let meta = std::fs::metadata(path).ok()?;
        Some(Stamp {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
        })
    }
}

/// A map with the configuration it was built for, the state of the files it read and
/// what is wrong with it.
#[derive(Debug)]
struct Built {
    config: Arc<Config>,
    map: HostKeyMap,
    files: BTreeMap<PathBuf, Option<Stamp>>,
    /// Unreadable files, followed servers without keys, keys of several servers.
    warnings: Vec<String>,
}

impl Built {
    /// Reads the known_hosts files of `config` and builds the map. Files that cannot be
    /// read count as empty and are among the warnings. Logs nothing: see
    /// [`ServerRecognition::install`].
    fn new(config: Arc<Config>) -> Built {
        let mut files = BTreeMap::new();
        let (map, found) = HostKeyMap::build_reporting(&config, |path| {
            // Stamp first: a change while reading makes the next check read again.
            files.insert(path.to_owned(), Stamp::of(path));
            KnownHosts::read(path)
        });
        let warnings = found.iter().map(|warning| describe(&config, warning)).collect();
        Built { config, map, files, warnings }
    }

    /// Whether any file changed since it was read.
    fn stale(&self) -> bool {
        self.files.iter().any(|(path, stamp)| Stamp::of(path) != *stamp)
    }
}

/// The log message for `warning`.
fn describe(config: &Config, warning: &HostKeyWarning) -> String {
    match warning {
        HostKeyWarning::Unreadable { path, error } => {
            format!("cannot read known_hosts file {}: {error}; skipped", path.display())
        }
        HostKeyWarning::NoKeys { server, .. } => {
            let name = match config.servers.get(server).map(|server| &server.keys) {
                Some(credential_bridge_config::ServerKeys::KnownHost(known)) => known.name.as_str(),
                _ => server.as_str(),
            };
            format!(
                "known_hosts lists no host key for {name:?} (server {server}); it is treated as unregistered"
            )
        }
        HostKeyWarning::Ambiguous { key, servers } => format!(
            "host key {} {} belongs to servers {}; connections with it are treated as unregistered \
             until only one server has it (credential-bridge-ctl check)",
            key.algorithm(),
            key.fingerprint(ssh_key::HashAlg::Sha256),
            servers.join(" and ")
        ),
    }
}

/// The host key map of the daemon, shared by all connections.
#[derive(Debug, Default)]
pub struct ServerRecognition {
    built: Mutex<Option<Arc<Built>>>,
    /// The warnings of the installed map, logged once each.
    warned: Mutex<Vec<String>>,
}

impl ServerRecognition {
    /// Builds the map for `config` (at start and on every reload). Blocking: reads files.
    pub fn rebuild(&self, config: &Arc<Config>) {
        let built = Arc::new(Built::new(Arc::clone(config)));
        self.install(built, true);
    }

    /// What `host_key` selects under `config` (the configuration snapshot of the
    /// connection). If a known_hosts file changed since the map was read, or the map is
    /// for another configuration, the map is built again first. A selected server is
    /// always one of `config`. Blocking: may read files.
    pub fn recognise(&self, config: &Arc<Config>, host_key: &ssh_key::PublicKey) -> Recognition {
        let current = lock(&self.built).clone();
        let current = current.filter(|built| Arc::ptr_eq(&built.config, config));
        if let Some(built) = &current {
            if !built.stale() {
                return built.map.recognise(host_key);
            }
            tracing::info!("known_hosts changed; reading it again");
        }
        let fresh = Arc::new(Built::new(Arc::clone(config)));
        let found = fresh.map.recognise(host_key);
        self.install(fresh, false);
        found
    }

    /// Makes `fresh` the map for the next lookups and logs its new warnings. Unless
    /// `always` (a reload), a map for another configuration than the installed one (a
    /// connection that started before a reload) is used for its lookup only.
    fn install(&self, fresh: Arc<Built>, always: bool) {
        let mut built = lock(&self.built);
        if !always && built.as_ref().is_some_and(|built| !Arc::ptr_eq(&built.config, &fresh.config)) {
            return;
        }
        let mut warned = lock(&self.warned);
        for warning in fresh.warnings.iter().filter(|warning| !warned.contains(warning)) {
            tracing::warn!("{warning}");
        }
        warned.clone_from(&fresh.warnings);
        *built = Some(fresh);
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use credential_bridge_config::host_keys::KeySource;
    use credential_bridge_config::paths::{PathVars, Paths, TargetOs};

    use super::*;

    fn key(seed: u8) -> ssh_key::PublicKey {
        let data = ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey([seed; 32]));
        ssh_key::PublicKey::new(data, "")
    }

    fn line(seed: u8) -> String {
        key(seed).to_openssh().unwrap()
    }

    fn config(dir: &Path, servers: &str) -> Arc<Config> {
        let vars = PathVars { home: Some(dir.as_os_str().to_owned()), ..PathVars::default() };
        let paths = Paths::from_vars(&vars, TargetOs::Linux).unwrap();
        let text = format!("version = 2\n[profile.p]\n{servers}");
        Arc::new(Config::parse(&text, &paths).unwrap())
    }

    /// Writes `text` so that the file's stamp surely changes (another size or a new
    /// inode by renaming, as `ssh-keygen -R` and ssh itself replace the file).
    fn write(path: &Path, text: &str) {
        let temp = path.with_extension("tmp");
        std::fs::write(&temp, text).unwrap();
        std::fs::rename(&temp, path).unwrap();
    }

    fn server(name: &str) -> Recognition {
        Recognition::Server { name: name.to_owned(), source: KeySource::KnownHosts }
    }

    /// A key learned after the map was built is found without a reload; a key that was
    /// replaced (host key rotation) stops selecting the server.
    #[test]
    fn follows_known_hosts_changes_without_reload() {
        let dir = tempfile::tempdir().unwrap();
        let known_hosts = dir.path().join("known_hosts");
        let files = format!("known_hosts_files = [\"{}\"]\n", known_hosts.display());
        let config =
            config(dir.path(), &format!("[server.box]\nknown_host = \"box\"\n{files}profile = \"p\"\n"));
        write(&known_hosts, &format!("box {}\n", line(1)));
        let recognition = ServerRecognition::default();
        recognition.rebuild(&config);
        assert_eq!(recognition.recognise(&config, &key(1)), server("box"));
        assert_eq!(recognition.recognise(&config, &key(2)), Recognition::Unregistered);

        // UpdateHostKeys: ssh adds the server's new key, later removes the old one.
        write(&known_hosts, &format!("box {}\nbox {}\n", line(1), line(2)));
        assert_eq!(recognition.recognise(&config, &key(2)), server("box"));
        write(&known_hosts, &format!("box {}\n", line(2)));
        // The removed key stops selecting the server at once.
        assert_eq!(recognition.recognise(&config, &key(1)), Recognition::Unregistered);
        assert_eq!(recognition.recognise(&config, &key(2)), server("box"));
        // A key revoked in the file as well.
        write(&known_hosts, &format!("box {}\n@revoked * {}\n", line(2), line(2)));
        assert_eq!(recognition.recognise(&config, &key(2)), Recognition::Unregistered);
    }

    /// A key that moves to another followed server selects neither of them at once.
    #[test]
    fn a_key_moved_to_another_server_is_ambiguous_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let known_hosts = dir.path().join("known_hosts");
        let files = format!("known_hosts_files = [\"{}\"]\n", known_hosts.display());
        let config = config(
            dir.path(),
            &format!(
                "[server.old]\nknown_host = \"old\"\n{files}profile = \"p\"\n\
                 [server.new]\nknown_host = \"new\"\n{files}profile = \"p\"\n"
            ),
        );
        write(&known_hosts, &format!("old {}\nnew {}\n", line(1), line(2)));
        let recognition = ServerRecognition::default();
        recognition.rebuild(&config);
        assert_eq!(recognition.recognise(&config, &key(1)), server("old"));
        write(&known_hosts, &format!("old {}\nnew {}\nnew {}\n", line(1), line(2), line(1)));
        assert_eq!(
            recognition.recognise(&config, &key(1)),
            Recognition::Ambiguous(vec!["new".into(), "old".into()])
        );
    }

    /// Warnings are kept with the map; a rebuild in the same situation keeps the same
    /// ones (logged once), a change replaces them.
    #[test]
    fn warnings_follow_the_situation() {
        let dir = tempfile::tempdir().unwrap();
        let known_hosts = dir.path().join("known_hosts");
        let files = format!("known_hosts_files = [\"{}\"]\n", known_hosts.display());
        let config =
            config(dir.path(), &format!("[server.box]\nknown_host = \"box\"\n{files}profile = \"p\"\n"));
        let recognition = ServerRecognition::default();
        recognition.rebuild(&config);
        let warned = || lock(&recognition.warned).clone();
        assert_eq!(warned().len(), 1);
        assert!(warned()[0].starts_with("known_hosts lists no host key for \"box\""), "{:?}", warned());
        recognition.rebuild(&config);
        assert_eq!(warned().len(), 1);
        write(&known_hosts, &format!("box {}\n", line(1)));
        assert_eq!(recognition.recognise(&config, &key(1)), server("box"));
        assert!(warned().is_empty());
        // A connection from before a reload does not replace the map of the new one.
        let other = self::config(dir.path(), "");
        assert_eq!(recognition.recognise(&other, &key(1)), Recognition::Unregistered);
        assert!(Arc::ptr_eq(&lock(&recognition.built).as_ref().unwrap().config, &config));
    }

    /// A file that cannot be read is skipped with a warning of its own, before the
    /// server it leaves without keys.
    #[test]
    fn unreadable_files_are_warned_about() {
        let dir = tempfile::tempdir().unwrap();
        let known_hosts = dir.path().join("known_hosts");
        std::fs::create_dir(&known_hosts).unwrap();
        let files = format!("known_hosts_files = [\"{}\"]\n", known_hosts.display());
        let config =
            config(dir.path(), &format!("[server.box]\nknown_host = \"box\"\n{files}profile = \"p\"\n"));
        let recognition = ServerRecognition::default();
        recognition.rebuild(&config);
        assert_eq!(
            *lock(&recognition.warned),
            [
                format!(
                    "cannot read known_hosts file {}: not a regular file; skipped",
                    known_hosts.display()
                ),
                "known_hosts lists no host key for \"box\" (server box); it is treated as unregistered"
                    .to_owned(),
            ]
        );
    }

    /// Without a change no file is read again; a missing file that appears counts as a
    /// change.
    #[test]
    fn reads_again_only_after_a_change() {
        let dir = tempfile::tempdir().unwrap();
        let known_hosts = dir.path().join("known_hosts");
        let files = format!("known_hosts_files = [\"{}\"]\n", known_hosts.display());
        let config =
            config(dir.path(), &format!("[server.box]\nknown_host = \"box\"\n{files}profile = \"p\"\n"));
        let recognition = ServerRecognition::default();
        recognition.rebuild(&config);
        assert!(!lock(&recognition.built).as_ref().unwrap().stale());
        assert_eq!(recognition.recognise(&config, &key(1)), Recognition::Unregistered);
        let before = Arc::clone(lock(&recognition.built).as_ref().unwrap());
        assert_eq!(recognition.recognise(&config, &key(1)), Recognition::Unregistered);
        assert!(Arc::ptr_eq(&before, lock(&recognition.built).as_ref().unwrap()), "read again");

        std::fs::write(&known_hosts, format!("box {}\n", line(1))).unwrap();
        assert_eq!(recognition.recognise(&config, &key(1)), server("box"));
        // Same size, same inode, only a new modification time.
        std::fs::write(&known_hosts, format!("box {}\n", line(2))).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&known_hosts)
            .unwrap()
            .set_modified(SystemTime::now() + Duration::from_secs(2))
            .unwrap();
        assert_eq!(recognition.recognise(&config, &key(2)), server("box"));
    }

    /// Pinned keys select their server as before; a key that two servers have selects
    /// neither.
    #[test]
    fn pinned_keys_and_ambiguity() {
        let dir = tempfile::tempdir().unwrap();
        let known_hosts = dir.path().join("known_hosts");
        let files = format!("known_hosts_files = [\"{}\"]\n", known_hosts.display());
        write(&known_hosts, &format!("box {}\nbox {}\n", line(2), line(3)));
        let config = config(
            dir.path(),
            &format!(
                "[server.pinned]\nhost_keys = [\"{}\", \"{}\"]\nprofile = \"p\"\n\
                 [server.box]\nknown_host = \"box\"\n{files}profile = \"p\"\n",
                line(1),
                line(3)
            ),
        );
        let recognition = ServerRecognition::default();
        recognition.rebuild(&config);
        assert_eq!(
            recognition.recognise(&config, &key(1)),
            Recognition::Server { name: "pinned".into(), source: KeySource::Pinned }
        );
        assert_eq!(recognition.recognise(&config, &key(2)), server("box"));
        assert_eq!(
            recognition.recognise(&config, &key(3)),
            Recognition::Ambiguous(vec!["box".into(), "pinned".into()])
        );
    }

    /// A connection's snapshot from before a reload gets a map for its own configuration.
    #[test]
    fn follows_the_snapshot_of_the_connection() {
        let dir = tempfile::tempdir().unwrap();
        let old =
            config(dir.path(), &format!("[server.a]\nhost_keys = [\"{}\"]\nprofile = \"p\"\n", line(1)));
        let new =
            config(dir.path(), &format!("[server.b]\nhost_keys = [\"{}\"]\nprofile = \"p\"\n", line(1)));
        let recognition = ServerRecognition::default();
        recognition.rebuild(&new);
        assert!(
            matches!(recognition.recognise(&old, &key(1)), Recognition::Server { name, .. } if name == "a")
        );
        assert!(
            matches!(recognition.recognise(&new, &key(1)), Recognition::Server { name, .. } if name == "b")
        );
    }
}
