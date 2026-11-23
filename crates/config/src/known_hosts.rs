//! OpenSSH known_hosts files (`sshd(8)`, "SSH_KNOWN_HOSTS FILE FORMAT"), read for servers
//! that follow known_hosts (`known_host = "…"` in `[server.*]`).
//!
//! Only what identifies one server for certain counts: an entry whose host list names
//! the lookup name **exactly** (plain, compared without regard to ASCII case as OpenSSH
//! does, or hashed as `|1|salt|hash`, HMAC-SHA1 over the name keyed with the salt).
//! Ignored on purpose:
//!
//! - wildcard patterns (`*`, `?`) in host lists: they may cover many hosts, and a key
//!   matched by one would make every such host the same server;
//! - lines with a negated pattern (`!host`): which hosts they exclude depends on pattern
//!   matching the bridge does not repeat, so such a line never counts;
//! - `@cert-authority` lines: a CA key vouches for any host it signed, so it cannot
//!   identify one server;
//! - comments, blank lines and keys that do not parse.
//!
//! A key marked `@revoked` on any line of any file read for a lookup is never returned,
//! whatever the line's host pattern: ssh would refuse it for the host as well.
//!
//! Lookup names are compared as ssh looks them up: lowercase (ssh lowercases the host
//! name and `HostKeyAlias` before it looks them up or hashes them), so callers pass
//! lowercase names; the configuration lowercases `known_host` when it loads.
//!
//! [`key_with_fingerprint`] is the one exception to exact names: `ctl server add --pin`
//! takes the key ssh has just verified for a host from whichever host line lists it,
//! wildcard patterns included.

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use base64ct::{Base64, Encoding as _};
use hmac::{Hmac, Mac as _};
use sha1::Sha1;

/// The files OpenSSH reads when neither `UserKnownHostsFile` nor `GlobalKnownHostsFile`
/// is set, in its order (`~/` is the home directory).
pub const DEFAULT_FILES: [&str; 4] =
    ["~/.ssh/known_hosts", "~/.ssh/known_hosts2", "/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"];

/// [`DEFAULT_FILES`] with `~/` replaced by `home`.
pub fn default_files(home: &Path) -> Vec<PathBuf> {
    DEFAULT_FILES.iter().map(|file| crate::paths::expand_home(home, Path::new(file))).collect()
}

/// The largest known_hosts file that is read (16 MiB); a larger one is a read error.
pub const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024;

/// The parsed contents of one known_hosts file: the usable host entries, the keys of
/// every host line (whatever its host pattern) and the revoked keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownHosts {
    entries: Vec<Entry>,
    host_lines: Vec<ssh_key::PublicKey>,
    revoked: Vec<ssh_key::PublicKey>,
}

/// One host line that can match a name exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    hosts: Hosts,
    key: ssh_key::PublicKey,
}

/// The host part of a line, reduced to what can match exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Hosts {
    /// `|1|salt|hash`.
    Hashed { salt: Vec<u8>, hash: Vec<u8> },
    /// The exact names of a comma-separated list (wildcard patterns left out).
    Plain(Vec<String>),
}

impl Hosts {
    fn parse(field: &str) -> Option<Hosts> {
        if let Some(hashed) = field.strip_prefix("|1|") {
            let (salt, hash) = hashed.split_once('|')?;
            let salt = Base64::decode_vec(salt).ok()?;
            let hash = Base64::decode_vec(hash).ok()?;
            return (hash.len() == 20).then_some(Hosts::Hashed { salt, hash });
        }
        let patterns: Vec<&str> = field.split(',').collect();
        if patterns.iter().any(|pattern| pattern.starts_with('!')) {
            return None;
        }
        let names: Vec<String> = patterns
            .into_iter()
            .filter(|pattern| !pattern.is_empty() && !pattern.contains(['*', '?']))
            .map(str::to_owned)
            .collect();
        (!names.is_empty()).then_some(Hosts::Plain(names))
    }

    fn matches(&self, name: &str) -> bool {
        match self {
            Hosts::Hashed { salt, hash } => {
                let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(salt) else { return false };
                mac.update(name.as_bytes());
                mac.verify_slice(hash).is_ok()
            }
            Hosts::Plain(names) => names.iter().any(|candidate| candidate.eq_ignore_ascii_case(name)),
        }
    }
}

impl KnownHosts {
    /// Parses a known_hosts file. Lines that cannot be used are skipped (see the module
    /// documentation); parsing never fails.
    pub fn parse(text: &str) -> KnownHosts {
        let mut known = KnownHosts::default();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let Some(mut first) = fields.next() else { continue };
            let marker = first.strip_prefix('@');
            if marker.is_some() {
                let Some(hosts) = fields.next() else { continue };
                first = hosts;
            }
            let (Some(kind), Some(data)) = (fields.next(), fields.next()) else { continue };
            let Ok(key) = ssh_key::PublicKey::from_openssh(&format!("{kind} {data}")) else { continue };
            match marker {
                Some("revoked") => known.revoked.push(key),
                // @cert-authority and markers OpenSSH may add later.
                Some(_) => {}
                None => {
                    if let Some(hosts) = Hosts::parse(first) {
                        known.entries.push(Entry { hosts, key: key.clone() });
                    }
                    known.host_lines.push(key);
                }
            }
        }
        known
    }

    /// Reads and parses `path`. `Ok(None)` if it does not exist.
    ///
    /// Errors: it cannot be opened (permissions), it is not a regular file (a directory,
    /// a FIFO, a device) or it is larger than [`MAX_FILE_SIZE`]. It is opened without
    /// blocking, so a FIFO planted at the path is refused at once instead of waiting
    /// for a writer.
    pub fn read(path: &Path) -> std::io::Result<Option<KnownHosts>> {
        let nonblocking = rustix::fs::OFlags::NONBLOCK.bits();
        let file = match File::options()
            .read(true)
            .custom_flags(i32::try_from(nonblocking).unwrap_or_default())
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file"));
        }
        let too_large = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("larger than {} MiB", MAX_FILE_SIZE / 1024 / 1024),
            )
        };
        if meta.len() > MAX_FILE_SIZE {
            return Err(too_large());
        }
        let mut bytes = Vec::new();
        file.take(MAX_FILE_SIZE + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_FILE_SIZE {
            return Err(too_large());
        }
        Ok(Some(KnownHosts::parse(&String::from_utf8_lossy(&bytes))))
    }
}

/// Whether `key` is marked `@revoked` in any of `files`.
fn revoked_in(files: &[&KnownHosts], key: &ssh_key::PublicKey) -> bool {
    files.iter().flat_map(|file| &file.revoked).any(|revoked| revoked.key_data() == key.key_data())
}

/// The host keys `files` list for exactly `name` (lowercase, as ssh looks it up), in
/// file and line order without duplicates, leaving out every key revoked in any of
/// them.
pub fn host_keys<'a>(files: impl IntoIterator<Item = &'a KnownHosts>, name: &str) -> Vec<ssh_key::PublicKey> {
    let files: Vec<&KnownHosts> = files.into_iter().collect();
    let revoked = |key: &ssh_key::PublicKey| revoked_in(&files, key);
    let mut keys: Vec<ssh_key::PublicKey> = Vec::new();
    for entry in files.iter().flat_map(|file| &file.entries) {
        if entry.hosts.matches(name)
            && !revoked(&entry.key)
            && !keys.iter().any(|known| known.key_data() == entry.key.key_data())
        {
            keys.push(ssh_key::PublicKey::new(entry.key.key_data().clone(), ""));
        }
    }
    keys
}

/// The key with the SHA256 fingerprint `fingerprint` (`SHA256:…`) on any host line of
/// `files`, whatever its host pattern (wildcards and negations included), unless it is
/// revoked in any of them; `@cert-authority` lines never count. For a key ssh has just
/// verified for a host: which line made ssh trust it does not matter, only the key.
pub fn key_with_fingerprint<'a>(
    files: impl IntoIterator<Item = &'a KnownHosts>,
    fingerprint: &str,
) -> Option<ssh_key::PublicKey> {
    let files: Vec<&KnownHosts> = files.into_iter().collect();
    files
        .iter()
        .flat_map(|file| &file.host_lines)
        .find(|key| key.fingerprint(ssh_key::HashAlg::Sha256).to_string() == fingerprint)
        .filter(|key| !revoked_in(&files, key))
        .map(|key| ssh_key::PublicKey::new(key.key_data().clone(), ""))
}

/// Why `name` cannot be a `known_host` lookup name, if it cannot: it must be a single
/// host name or address as ssh looks it up (`host`, or `[host]:port` for another port
/// than 22), not a pattern or a list.
pub fn lookup_name_problem(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        return Some("is empty");
    }
    if name.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Some("contains whitespace or control characters");
    }
    if name.contains(['*', '?', '!', ',']) || name.starts_with('|') || name.starts_with('@') {
        return Some("must be one host name, not a pattern, a list or a hashed entry");
    }
    if let Some(rest) = name.strip_prefix('[') {
        let valid = rest.split_once("]:").is_some_and(|(host, port)| {
            !host.is_empty() && !host.contains(['[', ']']) && port.parse::<u16>().is_ok_and(|port| port > 0)
        });
        if !valid {
            return Some("must be host or [host]:port");
        }
    } else if name.contains(['[', ']']) {
        return Some("must be host or [host]:port");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> String {
        crate::test_support::test_key(seed)
    }

    /// `|1|salt|hash` for `name`, as `ssh-keygen -H` writes it.
    fn hashed(name: &str, salt: &[u8]) -> String {
        let mut mac = Hmac::<Sha1>::new_from_slice(salt).unwrap();
        mac.update(name.as_bytes());
        let hash = mac.finalize().into_bytes();
        format!("|1|{}|{}", Base64::encode_string(salt), Base64::encode_string(&hash))
    }

    fn lines(keys: &[ssh_key::PublicKey]) -> Vec<String> {
        keys.iter().map(|key| key.to_openssh().unwrap()).collect()
    }

    #[test]
    fn plain_entries_and_lists_match_exactly() {
        let file = KnownHosts::parse(&format!(
            "# comment\n\n   \nbuild,10.0.0.1 {} a comment\nother {}\nBUILD.example.com {}\n",
            key(1),
            key(2),
            key(3)
        ));
        assert_eq!(lines(&host_keys([&file], "build")), [key(1)]);
        assert_eq!(lines(&host_keys([&file], "10.0.0.1")), [key(1)]);
        // ASCII case does not matter, as in OpenSSH.
        assert_eq!(lines(&host_keys([&file], "build.example.com")), [key(3)]);
        assert!(host_keys([&file], "buil").is_empty());
        assert!(host_keys([&file], "build.example").is_empty());
    }

    #[test]
    fn ports_are_part_of_the_name() {
        let file = KnownHosts::parse(&format!("[build]:2222 {}\nbuild {}\n", key(1), key(2)));
        assert_eq!(lines(&host_keys([&file], "[build]:2222")), [key(1)]);
        assert_eq!(lines(&host_keys([&file], "build")), [key(2)]);
        assert!(host_keys([&file], "[build]:22").is_empty());
    }

    #[test]
    fn hashed_entries() {
        let file = KnownHosts::parse(&format!(
            "{} {}\n{} {}\n|1|broken {}\n|1|AAAA|AAAA {}\n",
            hashed("build", b"0123456789abcdef0123"),
            key(1),
            hashed("[build]:2222", b"another salt"),
            key(2),
            key(3),
            key(4)
        ));
        assert_eq!(lines(&host_keys([&file], "build")), [key(1)]);
        assert_eq!(lines(&host_keys([&file], "[build]:2222")), [key(2)]);
        // Hashes cover the exact bytes: no case folding.
        assert!(host_keys([&file], "BUILD").is_empty());
        assert!(host_keys([&file], "other").is_empty());

        // Written by OpenSSH 10.2's `ssh-keygen -H` for `[build.example]:2222`.
        let openssh = KnownHosts::parse(&format!(
            "|1|TYmslNoqAWw3QHHnN7hzJXDI/Tc=|T7nh1FLc0sF7b77ZLOA2EXCDOsE= {}\n",
            key(1)
        ));
        assert_eq!(lines(&host_keys([&openssh], "[build.example]:2222")), [key(1)]);
        assert!(host_keys([&openssh], "build.example").is_empty());
    }

    #[test]
    fn revoked_keys_are_left_out_in_every_file() {
        let user = KnownHosts::parse(&format!("build {}\nbuild {}\n", key(1), key(2)));
        let global = KnownHosts::parse(&format!("@revoked * {}\n", key(2)));
        assert_eq!(lines(&host_keys([&user], "build")), [key(1), key(2)]);
        assert_eq!(lines(&host_keys([&user, &global], "build")), [key(1)]);
        let same = KnownHosts::parse(&format!("build {}\n@revoked build {}\n", key(1), key(1)));
        assert!(host_keys([&same], "build").is_empty());
    }

    #[test]
    fn authorities_patterns_and_negations_are_not_followed() {
        let file = KnownHosts::parse(&format!(
            "@cert-authority build {}\n*.example.com {}\nbuil? {}\nbuild,!build {}\n!other,build {}\n\
             *,build {}\n@unknown build {}\n",
            key(1),
            key(2),
            key(3),
            key(4),
            key(5),
            key(6),
            key(7)
        ));
        assert!(host_keys([&file], "x.example.com").is_empty());
        // Only the exact name of a list with a wildcard counts.
        assert_eq!(lines(&host_keys([&file], "build")), [key(6)]);
    }

    #[test]
    fn duplicates_and_garbage() {
        let first = KnownHosts::parse(&format!("build {}\nbuild ssh-ed25519 not-base64\nbuild\n", key(1)));
        let second = KnownHosts::parse(&format!("build {} again\nbuild {}\n", key(1), key(2)));
        assert_eq!(lines(&host_keys([&first, &second], "build")), [key(1), key(2)]);
        // Comments of the file are not kept.
        assert!(host_keys([&second], "build")[0].comment().is_empty());
    }

    #[test]
    fn reads_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        assert_eq!(KnownHosts::read(&path).unwrap(), None);
        std::fs::write(&path, format!("build {}\n", key(1))).unwrap();
        let file = KnownHosts::read(&path).unwrap().unwrap();
        assert_eq!(lines(&host_keys([&file], "build")), [key(1)]);
        assert!(KnownHosts::read(dir.path()).is_err());
    }

    /// A FIFO is refused at once (not waited on), a file over the size limit too.
    #[test]
    fn refuses_fifos_and_large_files() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status().unwrap();
        assert!(made.success());
        let started = std::time::Instant::now();
        let error = KnownHosts::read(&fifo).unwrap_err();
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(error.to_string(), "not a regular file");

        let large = dir.path().join("large");
        let file = File::create(&large).unwrap();
        file.set_len(MAX_FILE_SIZE + 1).unwrap();
        assert_eq!(KnownHosts::read(&large).unwrap_err().to_string(), "larger than 16 MiB");
        file.set_len(MAX_FILE_SIZE).unwrap();
        assert!(KnownHosts::read(&large).unwrap().is_some());
    }

    /// `--pin` takes the key ssh verified from any host line, pattern or not, but never
    /// a revoked one or a CA key.
    #[test]
    fn keys_by_fingerprint() {
        let fingerprint = |seed: u8| {
            ssh_key::PublicKey::from_openssh(&key(seed))
                .unwrap()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string()
        };
        let file = KnownHosts::parse(&format!(
            "*.example.com {} comment
build,!evil {}
@cert-authority * {}
other {}
",
            key(1),
            key(2),
            key(3),
            key(4)
        ));
        let found = |seed: u8, files: &[&KnownHosts]| {
            key_with_fingerprint(files.iter().copied(), &fingerprint(seed))
                .map(|key| key.to_openssh().unwrap())
        };
        assert_eq!(found(1, &[&file]), Some(key(1)));
        assert_eq!(found(2, &[&file]), Some(key(2)));
        assert_eq!(found(3, &[&file]), None);
        assert_eq!(found(5, &[&file]), None);
        let revoked = KnownHosts::parse(&format!(
            "@revoked * {}
",
            key(4)
        ));
        assert_eq!(found(4, &[&file]), Some(key(4)));
        assert_eq!(found(4, &[&file, &revoked]), None);
    }

    #[test]
    fn default_files_follow_openssh() {
        assert_eq!(
            default_files(Path::new("/home/me")),
            [
                "/home/me/.ssh/known_hosts",
                "/home/me/.ssh/known_hosts2",
                "/etc/ssh/ssh_known_hosts",
                "/etc/ssh/ssh_known_hosts2"
            ]
            .map(PathBuf::from)
        );
    }

    #[test]
    fn lookup_names() {
        for good in ["build", "build.example.com", "10.0.0.1", "[build]:2222", "[::1]:22", "testbox"] {
            assert_eq!(lookup_name_problem(good), None, "{good}");
        }
        for bad in ["", "a b", "*.example.com", "a,b", "!a", "|1|x|y", "[build]", "[build]:x", "a]", "[]:22"]
        {
            assert!(lookup_name_problem(bad).is_some(), "{bad}");
        }
    }
}
