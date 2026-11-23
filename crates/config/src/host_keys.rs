//! Which `[server.*]` a host key belongs to (`docs/architecture.md`, "Recognising the
//! server"): the pinned `host_keys` of a server, and for a server with `known_host` the
//! keys its known_hosts files list for that name ([`crate::known_hosts`]).
//!
//! A key that belongs to more than one server is **ambiguous**: it selects none of them,
//! so such a host gets `profile.unregistered`. Pinned keys cannot collide with each
//! other (validation refuses that); followed keys can, because known_hosts may list one
//! key under several names (an address and a host name, a moved server).
//!
//! [`HostKeyMap::build_reporting`] is pure apart from the `read` function it is given:
//! the daemon passes one that reads the files and remembers their state, ctl one that
//! only reads. Both get the same [`HostKeyWarning`]s and word them for their output.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::known_hosts::{self, KnownHosts};
use crate::model::{Config, ServerKeys};

/// Where a server's matching key came from (the audit log's `source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeySource {
    /// `host_keys` in the configuration.
    Pinned,
    /// The known_hosts files, for the server's `known_host`.
    KnownHosts,
}

impl KeySource {
    /// `pinned` or `known_hosts`.
    pub fn as_str(self) -> &'static str {
        match self {
            KeySource::Pinned => "pinned",
            KeySource::KnownHosts => "known_hosts",
        }
    }
}

/// What a host key selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recognition {
    /// Exactly one server.
    Server {
        /// Its `[server.*]` name.
        name: String,
        /// Where the key came from.
        source: KeySource,
    },
    /// No server: an unregistered host.
    Unregistered,
    /// Several servers (names sorted): treated as an unregistered host.
    Ambiguous(Vec<String>),
}

/// The host keys of all servers, by key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostKeyMap {
    /// Key blob (without comment) → the servers that have it.
    by_key: BTreeMap<Vec<u8>, Entry>,
    /// The keys each `known_host` server follows right now, in known_hosts order.
    followed: BTreeMap<String, Vec<ssh_key::PublicKey>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    key: ssh_key::PublicKey,
    servers: Vec<(String, KeySource)>,
}

/// What is wrong with the host keys of a configuration, as [`HostKeyMap::build_reporting`]
/// finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyWarning {
    /// A known_hosts file of a followed server exists but cannot be read; it counts as
    /// empty, as ssh skips it too.
    Unreadable {
        /// The file.
        path: PathBuf,
        /// Why it cannot be read.
        error: String,
    },
    /// A server with `known_host` whose known_hosts files list no key for it: it is
    /// treated as unregistered.
    NoKeys {
        /// The `[server.*]` name.
        server: String,
        /// Its files that exist but cannot be read (the key may be in them).
        unreadable: Vec<PathBuf>,
        /// Whether any of its files was read.
        any_read: bool,
    },
    /// A key that belongs to several servers: it selects none of them.
    Ambiguous {
        /// The key.
        key: ssh_key::PublicKey,
        /// The servers (sorted).
        servers: Vec<String>,
    },
}

impl HostKeyWarning {
    /// Whether this warning concerns server `name`; an unreadable file concerns the
    /// servers that follow it (`config`).
    pub fn concerns(&self, config: &Config, name: &str) -> bool {
        match self {
            HostKeyWarning::Unreadable { path, .. } => config.servers.get(name).is_some_and(
                |server| matches!(&server.keys, ServerKeys::KnownHost(known) if known.files.contains(path)),
            ),
            HostKeyWarning::NoKeys { server, .. } => server == name,
            HostKeyWarning::Ambiguous { servers, .. } => servers.iter().any(|server| server == name),
        }
    }
}

impl HostKeyMap {
    /// The map for `config` and what is wrong with it. `read` reads a known_hosts file
    /// ([`KnownHosts::read`]: `Ok(None)` if it does not exist); it is called once per
    /// file. A file that cannot be read counts as empty and is reported, in the order of
    /// [`Config::known_hosts_files`]; then followed servers without keys (by name), then
    /// keys of several servers.
    pub fn build_reporting(
        config: &Config,
        mut read: impl FnMut(&Path) -> std::io::Result<Option<KnownHosts>>,
    ) -> (HostKeyMap, Vec<HostKeyWarning>) {
        let mut warnings = Vec::new();
        let mut files: BTreeMap<&Path, Option<KnownHosts>> = BTreeMap::new();
        let mut unreadable: Vec<&Path> = Vec::new();
        for path in config.known_hosts_files() {
            let known = match read(path) {
                Ok(known) => known,
                Err(error) => {
                    warnings
                        .push(HostKeyWarning::Unreadable { path: path.to_owned(), error: error.to_string() });
                    unreadable.push(path);
                    None
                }
            };
            files.insert(path, known);
        }
        let map = HostKeyMap::from_files(config, &files);
        for server in config.servers.values() {
            if let ServerKeys::KnownHost(known) = &server.keys
                && map.followed(&server.name).is_empty()
            {
                warnings.push(HostKeyWarning::NoKeys {
                    server: server.name.clone(),
                    unreadable: known
                        .files
                        .iter()
                        .filter(|file| unreadable.contains(&file.as_path()))
                        .cloned()
                        .collect(),
                    any_read: known
                        .files
                        .iter()
                        .any(|file| files.get(file.as_path()).is_some_and(Option::is_some)),
                });
            }
        }
        for (key, servers) in map.ambiguous() {
            warnings.push(HostKeyWarning::Ambiguous {
                key: key.clone(),
                servers: servers.into_iter().map(str::to_owned).collect(),
            });
        }
        (map, warnings)
    }

    /// The map for `config` from the contents of its files (`None`: not read).
    fn from_files(config: &Config, files: &BTreeMap<&Path, Option<KnownHosts>>) -> HostKeyMap {
        let mut map = HostKeyMap::default();
        for server in config.servers.values() {
            match &server.keys {
                ServerKeys::Pinned(keys) => {
                    for key in keys {
                        map.insert(key, &server.name, KeySource::Pinned);
                    }
                }
                ServerKeys::KnownHost(known) => {
                    let read = known.files.iter().filter_map(|path| files.get(path.as_path())?.as_ref());
                    let keys = known_hosts::host_keys(read, &known.name);
                    for key in &keys {
                        map.insert(key, &server.name, KeySource::KnownHosts);
                    }
                    map.followed.insert(server.name.clone(), keys);
                }
            }
        }
        map
    }

    fn insert(&mut self, key: &ssh_key::PublicKey, server: &str, source: KeySource) {
        let Ok(blob) = key.to_bytes() else { return };
        let entry = self.by_key.entry(blob).or_insert_with(|| Entry {
            key: ssh_key::PublicKey::new(key.key_data().clone(), ""),
            servers: Vec::new(),
        });
        if !entry.servers.iter().any(|(name, _)| name == server) {
            entry.servers.push((server.to_owned(), source));
        }
    }

    /// What `host_key` selects (compared by key data, ignoring comments; for a host
    /// certificate the caller passes the embedded key).
    pub fn recognise(&self, host_key: &ssh_key::PublicKey) -> Recognition {
        let Some(entry) = host_key.to_bytes().ok().and_then(|blob| self.by_key.get(&blob)) else {
            return Recognition::Unregistered;
        };
        match entry.servers.as_slice() {
            [] => Recognition::Unregistered,
            [(name, source)] => Recognition::Server { name: name.clone(), source: *source },
            several => {
                let mut names: Vec<String> = several.iter().map(|(name, _)| name.clone()).collect();
                names.sort();
                Recognition::Ambiguous(names)
            }
        }
    }

    /// The keys known_hosts lists for a server with `known_host` now; empty for other
    /// servers and when the files list none.
    pub fn followed(&self, server: &str) -> &[ssh_key::PublicKey] {
        self.followed.get(server).map_or(&[], Vec::as_slice)
    }

    /// Keys that belong to more than one server, with the servers (sorted).
    pub fn ambiguous(&self) -> Vec<(&ssh_key::PublicKey, Vec<&str>)> {
        self.by_key
            .values()
            .filter(|entry| entry.servers.len() > 1)
            .map(|entry| {
                let mut names: Vec<&str> = entry.servers.iter().map(|(name, _)| name.as_str()).collect();
                names.sort_unstable();
                (&entry.key, names)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::*;
    use crate::model::{KnownHost, Server};
    use crate::test_support::test_key;

    fn key(seed: u8) -> ssh_key::PublicKey {
        ssh_key::PublicKey::from_openssh(&test_key(seed)).unwrap()
    }

    fn pinned(name: &str, seeds: &[u8]) -> Server {
        Server {
            name: name.to_owned(),
            keys: ServerKeys::Pinned(seeds.iter().map(|seed| key(*seed)).collect()),
            profile: "p".to_owned(),
            git_config: true,
        }
    }

    fn following(name: &str, known_host: &str, files: &[&str]) -> Server {
        Server {
            name: name.to_owned(),
            keys: ServerKeys::KnownHost(KnownHost {
                name: known_host.to_owned(),
                files: files.iter().map(PathBuf::from).collect(),
            }),
            profile: "p".to_owned(),
            git_config: true,
        }
    }

    fn config(servers: Vec<Server>) -> Config {
        let servers = servers.into_iter().map(|server| (server.name.clone(), server)).collect();
        Config { servers, ..Config::default() }
    }

    fn files(contents: &[(&str, String)]) -> BTreeMap<PathBuf, KnownHosts> {
        contents.iter().map(|(path, text)| (PathBuf::from(path), KnownHosts::parse(text))).collect()
    }

    #[test]
    fn pinned_and_followed_keys_select_their_server() {
        let config =
            config(vec![pinned("old", &[1]), following("box", "box.example.com", &["/u/known_hosts"])]);
        let files = files(&[(
            "/u/known_hosts",
            format!("box.example.com {}\nbox.example.com {}\n", test_key(2), test_key(3)),
        )]);
        let mut reads = Vec::new();
        let (map, warnings) = HostKeyMap::build_reporting(&config, |path| {
            reads.push(path.to_owned());
            Ok(files.get(path).cloned())
        });
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(reads, [PathBuf::from("/u/known_hosts")]);
        assert_eq!(
            map.recognise(&key(1)),
            Recognition::Server { name: "old".into(), source: KeySource::Pinned }
        );
        assert_eq!(
            map.recognise(&key(3)),
            Recognition::Server { name: "box".into(), source: KeySource::KnownHosts }
        );
        assert_eq!(map.recognise(&key(4)), Recognition::Unregistered);
        assert_eq!(map.followed("box"), [key(2), key(3)]);
        assert!(map.followed("old").is_empty());
        assert!(map.ambiguous().is_empty());
        // A comment does not matter.
        let commented = ssh_key::PublicKey::from_openssh(&format!("{} root@box", test_key(2))).unwrap();
        assert!(matches!(map.recognise(&commented), Recognition::Server { .. }));
    }

    #[test]
    fn a_key_of_two_servers_selects_none() {
        let config = config(vec![
            pinned("pinned", &[1]),
            following("a", "a", &["/k"]),
            following("b", "10.0.0.2", &["/k"]),
        ]);
        let files = files(&[(
            "/k",
            format!("a {}\n10.0.0.2 {}\na,10.0.0.2 {}\n", test_key(1), test_key(2), test_key(3)),
        )]);
        let (map, warnings) = HostKeyMap::build_reporting(&config, |path| Ok(files.get(path).cloned()));
        assert_eq!(map.recognise(&key(1)), Recognition::Ambiguous(vec!["a".into(), "pinned".into()]));
        assert_eq!(map.recognise(&key(3)), Recognition::Ambiguous(vec!["a".into(), "b".into()]));
        assert_eq!(
            map.recognise(&key(2)),
            Recognition::Server { name: "b".into(), source: KeySource::KnownHosts }
        );
        let ambiguous = map.ambiguous();
        assert_eq!(ambiguous.len(), 2);
        assert!(ambiguous.contains(&(&key(3), vec!["a", "b"])));
        assert_eq!(warnings.len(), 2);
        assert!(
            warnings
                .contains(&HostKeyWarning::Ambiguous { key: key(3), servers: vec!["a".into(), "b".into()] })
        );
        assert!(warnings[0].concerns(&config, "pinned") && !warnings[0].concerns(&config, "b"));
    }

    #[test]
    fn missing_files_give_no_keys() {
        let config = config(vec![following("box", "box", &["/missing", "/k"])]);
        let files = files(&[("/k", format!("box {}\n", test_key(5)))]);
        let (map, warnings) = HostKeyMap::build_reporting(&config, |path| Ok(files.get(path).cloned()));
        assert_eq!(map.followed("box"), [key(5)]);
        assert!(warnings.is_empty(), "{warnings:?}");
        let (map, warnings) = HostKeyMap::build_reporting(&config, |_| Ok(None));
        assert!(map.followed("box").is_empty());
        assert_eq!(map.recognise(&key(5)), Recognition::Unregistered);
        assert_eq!(
            warnings,
            [HostKeyWarning::NoKeys { server: "box".into(), unreadable: Vec::new(), any_read: false }]
        );
    }

    /// A file that cannot be read counts as empty and is reported, once, before the
    /// servers it leaves without keys.
    #[test]
    fn unreadable_files_are_reported() {
        let config = config(vec![
            following("box", "box", &["/locked", "/k"]),
            following("other", "other", &["/locked"]),
            following("fine", "fine", &["/k"]),
        ]);
        let files = files(&[("/k", format!("fine {}\nbox {}\n", test_key(1), test_key(2)))]);
        let mut reads = Vec::new();
        let (map, warnings) = HostKeyMap::build_reporting(&config, |path| {
            reads.push(path.to_owned());
            if path == Path::new("/locked") {
                return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
            }
            Ok(files.get(path).cloned())
        });
        assert_eq!(reads.iter().filter(|path| path.as_path() == Path::new("/locked")).count(), 1);
        assert_eq!(map.followed("box"), [key(2)]);
        let unreadable =
            HostKeyWarning::Unreadable { path: "/locked".into(), error: "permission denied".into() };
        assert_eq!(
            warnings,
            [
                unreadable.clone(),
                HostKeyWarning::NoKeys {
                    server: "other".into(),
                    unreadable: vec!["/locked".into()],
                    any_read: false
                },
            ]
        );
        assert!(unreadable.concerns(&config, "box") && unreadable.concerns(&config, "other"));
        assert!(!unreadable.concerns(&config, "fine") && !unreadable.concerns(&config, "nope"));
    }

    #[test]
    fn sources_print_as_in_the_audit_log() {
        assert_eq!(KeySource::Pinned.as_str(), "pinned");
        assert_eq!(KeySource::KnownHosts.as_str(), "known_hosts");
    }
}
