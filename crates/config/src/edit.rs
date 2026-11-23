//! Format-preserving edits for ctl.
//!
//! ctl can change every section (see [`ConfigDocument`] and the typed operations in
//! this module); the file stays yours to edit by hand. Edits keep comments, order and
//! formatting of untouched parts (`toml_edit`), and nothing is written unless the
//! result validates like a configuration the daemon loads.

use std::path::{Path, PathBuf};

use credential_bridge_proto::ipc::git::Permissions;

use crate::Config;
use crate::error::ConfigError;
use crate::paths::Paths;

mod ops;

pub use ops::{DaemonKey, KeepassxcKey, NewRule, NewSource, ProfileKey, ProfileSetting};

/// The host keys [`ConfigDocument::set_server`] writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeysEntry<'a> {
    /// `known_host = "<name>"`, and `known_hosts_files` unless `None` (OpenSSH's
    /// default files).
    KnownHost {
        /// The name ssh stores the server under in known_hosts.
        name: &'a str,
        /// The known_hosts files, as written (`~/` allowed).
        files: Option<&'a [String]>,
    },
    /// `host_keys = [...]`: pinned keys in OpenSSH format.
    Pinned(&'a [String]),
}

/// Error of editing the configuration file.
#[derive(Debug, thiserror::Error)]
pub enum EditError {
    /// Reading or writing failed.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The cause.
        source: std::io::Error,
    },
    /// The file is not valid TOML.
    #[error("{path}: {message}")]
    Syntax {
        /// The file.
        path: PathBuf,
        /// The parser's message.
        message: String,
    },
    /// A table with this name exists and the edit would replace it.
    #[error("{table} already exists")]
    Exists {
        /// Dotted table name, e.g. `source.my-org`.
        table: String,
    },
    /// A table or entry the edit needs does not exist.
    #[error("no {table}")]
    NotFound {
        /// What is missing, e.g. `source.my-org` or `[[agent.upstream]] "fido"`.
        table: String,
    },
    /// The edit would remove something other parts of the configuration still name.
    #[error(
        "{item} is still used by {}; first run: {}",
        users.join(", "),
        fixes.join("; ")
    )]
    InUse {
        /// What was to be removed, e.g. `profile "build"`.
        item: String,
        /// Where it is used, e.g. `server.buildserver`.
        users: Vec<String>,
        /// Commands that remove the uses.
        fixes: Vec<String>,
    },
    /// A key or value given to an edit is not valid.
    #[error("{key}: {message}")]
    Value {
        /// The key, e.g. `ssh.confirm`.
        key: String,
        /// What is wrong and what is expected.
        message: String,
    },
    /// The part of the file the edit would change is written in a form ctl does not edit
    /// (for example an inline table where ctl expects `[table]` headers).
    #[error(
        "{location} is written in a form credential-bridge-ctl does not edit; change it with \
         credential-bridge-ctl config edit"
    )]
    Unsupported {
        /// Dotted location, e.g. `agent.upstream`.
        location: String,
    },
    /// The edited document no longer validates; nothing was written.
    #[error("the edited configuration is invalid: {0}")]
    Invalid(#[from] ConfigError),
    /// The file (or the file a symbolic link at the path points to) cannot be written;
    /// nothing was changed.
    #[error("{}", not_writable_message(path, target, source))]
    NotWritable {
        /// The configuration path.
        path: PathBuf,
        /// The file that would have to be written: `path`, or the target of the link.
        target: PathBuf,
        /// Why it cannot be written.
        source: std::io::Error,
    },
}

fn not_writable_message(path: &Path, target: &Path, source: &std::io::Error) -> String {
    if path == target {
        format!("{} is not writable: {source}", path.display())
    } else {
        format!(
            "{} is a link to {}, which is not writable ({source}); change the file where it comes \
             from (for example your home-manager configuration), or replace the link with a file",
            path.display(),
            target.display()
        )
    }
}

/// A configuration file opened for editing.
#[derive(Debug, Clone)]
pub struct ConfigDocument {
    /// Where [`ConfigDocument::save`] writes.
    path: PathBuf,
    /// The parsed document.
    doc: toml_edit::DocumentMut,
    /// The text it was opened from; `None` if the file did not exist.
    original: Option<String>,
}

impl ConfigDocument {
    /// Opens `path`; a missing file starts a new document containing `version = 2`.
    /// The file is read once; [`ConfigDocument::original_text`] is that text.
    pub fn open(path: &Path) -> Result<ConfigDocument, EditError> {
        let original = match std::fs::read_to_string(path) {
            Ok(text) => Some(text),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(source) => return Err(EditError::Io { path: path.to_owned(), source }),
        };
        ConfigDocument::from_original(path, original)
    }

    /// A document for `path` from its content `original`, already read by the caller
    /// (`None`: the file does not exist, and the document starts with `version = 2`).
    pub fn from_original(path: &Path, original: Option<String>) -> Result<ConfigDocument, EditError> {
        let text = original
            .as_deref()
            .map_or_else(|| format!("version = {}\n", crate::CONFIG_VERSION), str::to_owned);
        let doc = parse_text(path, &text)?;
        Ok(ConfigDocument { path: path.to_owned(), doc, original })
    }

    /// A document for `path` with the whole new text `text` (`config edit`, `init`).
    /// `original` is the content of the file as the caller read it (`None`: it does not
    /// exist); it is kept for [`ConfigDocument::original_text`] and need not be valid,
    /// so that a broken file can be replaced.
    pub fn replacing(path: &Path, original: Option<String>, text: &str) -> Result<ConfigDocument, EditError> {
        let doc = parse_text(path, text)?;
        Ok(ConfigDocument { path: path.to_owned(), doc, original })
    }

    /// The text of the file when it was opened; `None` if it did not exist.
    pub fn original_text(&self) -> Option<&str> {
        self.original.as_deref()
    }

    /// Validates the edited text exactly as [`Config::load`] would and returns the
    /// configuration it describes. Writes nothing.
    pub fn check(&self, paths: &Paths) -> Result<Config, EditError> {
        Ok(self.validate(paths)?.config)
    }

    /// Validates the edited text like [`ConfigDocument::check`]; the result can be
    /// saved with [`Validated::save`] without validating it again.
    pub fn validate(&self, paths: &Paths) -> Result<Validated<'_>, EditError> {
        let text = self.to_text();
        let config = crate::load::parse_at(&text, paths, &self.path)?;
        Ok(Validated { doc: self, text, config })
    }

    /// The configuration before the edit, from the text the document was opened from
    /// (an empty configuration if the file did not exist). Reads nothing.
    pub fn original_config(&self, paths: &Paths) -> Result<Config, EditError> {
        match &self.original {
            Some(text) => Ok(crate::load::parse_at(text, paths, &self.path)?),
            None => Ok(Config::empty(paths)),
        }
    }

    /// Creates or replaces `[server.<name>]` with its host keys (`known_host` and, if
    /// given, `known_hosts_files`, or pinned `host_keys` in OpenSSH format), `profile`,
    /// and `git_config = false` only if `git_config` is false.
    ///
    /// A replaced table keeps its position and its comments above the header; keys of
    /// the other mode are dropped, so the server switches mode.
    pub fn set_server(
        &mut self,
        name: &str,
        keys: &HostKeysEntry<'_>,
        profile: &str,
        git_config: bool,
    ) -> Result<(), EditError> {
        let servers = self.parent_table("server")?;
        let mut table = toml_edit::Table::new();
        let list = |items: &[String]| {
            let mut array = toml_edit::Array::new();
            for item in items {
                array.push(item.as_str());
            }
            toml_edit::value(array)
        };
        match keys {
            HostKeysEntry::KnownHost { name, files } => {
                table.insert("known_host", toml_edit::value(*name));
                if let Some(files) = files {
                    table.insert("known_hosts_files", list(files));
                }
            }
            HostKeysEntry::Pinned(keys) => {
                table.insert("host_keys", list(keys));
            }
        }
        table.insert("profile", toml_edit::value(profile));
        if !git_config {
            table.insert("git_config", toml_edit::value(false));
        }
        match servers.get_mut(name).and_then(toml_edit::Item::as_table_mut) {
            Some(existing) => {
                // Keep the position and the decoration (comments) of the old table.
                table.set_position(existing.position());
                *table.decor_mut() = existing.decor().clone();
                *existing = table;
            }
            None => {
                servers.insert(name, toml_edit::Item::Table(table));
            }
        }
        Ok(())
    }

    /// Removes `[server.<name>]`. Returns whether it existed.
    pub fn remove_server(&mut self, name: &str) -> bool {
        self.doc
            .get_mut("server")
            .and_then(toml_edit::Item::as_table_like_mut)
            .is_some_and(|servers| servers.remove(name).is_some())
    }

    /// Adds `[source.<name>]` for a GitHub App on `host` (`host` is written only when it
    /// is not `github.com`, the default). Errors with [`EditError::Exists`] if the table
    /// exists.
    pub fn add_github_app_source(
        &mut self,
        name: &str,
        host: &str,
        app_id: u64,
        private_key_ref: &str,
        max_permissions: &Permissions,
    ) -> Result<(), EditError> {
        let private_key = private_key_ref.parse().map_err(|error: crate::SecretRefError| {
            EditError::Value { key: format!("source.{name}.private_key"), message: error.reason.to_owned() }
        })?;
        self.add_source(
            name,
            &NewSource::GithubApp {
                host: Some(host.to_owned()),
                api_url: None,
                app_id,
                private_key,
                max_permissions: max_permissions.clone(),
            },
        )
    }

    /// The document text as it would be saved.
    pub fn to_text(&self) -> String {
        self.doc.to_string()
    }

    /// Validates the edited text exactly as [`ConfigDocument::check`] does and writes it
    /// atomically (temporary file in the same directory, mode 0600, rename). Missing
    /// parent directories are created. Returns the configuration that was written.
    ///
    /// If the opened path is a symbolic link, the file it points to is replaced and the
    /// link stays. A file that cannot be written (for example a home-manager link into the
    /// read-only `/nix/store`) is refused with [`EditError::NotWritable`] instead of being
    /// replaced by a new file.
    pub fn save(&self, paths: &Paths) -> Result<Config, EditError> {
        self.validate(paths)?.save()
    }

    /// Writes `text` as described for [`ConfigDocument::save`]; only through
    /// [`Validated::save`].
    fn write(&self, text: &str) -> Result<(), EditError> {
        let io = |source| EditError::Io { path: self.path.clone(), source };
        let target = self.target().map_err(io)?;
        let not_writable =
            |source| EditError::NotWritable { path: self.path.clone(), target: target.clone(), source };
        if target.exists() {
            // Opening for writing without truncating changes nothing and fails the way the
            // write would (read-only file or file system).
            std::fs::OpenOptions::new().write(true).open(&target).map_err(not_writable)?;
        }
        let dir = match target.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.to_owned(),
            _ => PathBuf::from("."),
        };
        std::fs::create_dir_all(&dir).map_err(io)?;
        let file_name = target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let temp = dir.join(format!(".{file_name}.{}.tmp", std::process::id()));
        // A stale file of an earlier run with the same process ID.
        let _ = std::fs::remove_file(&temp);
        let result =
            crate::file::write_private(&temp, text.as_bytes()).and_then(|()| std::fs::rename(&temp, &target));
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result.map_err(|source| {
            if matches!(
                source.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
            ) {
                not_writable(source)
            } else {
                io(source)
            }
        })
    }

    /// The file [`ConfigDocument::save`] replaces: the opened path, or with all symbolic
    /// links resolved if it exists. A link whose target is missing is an error, so that
    /// the link is never replaced by a file.
    fn target(&self) -> std::io::Result<PathBuf> {
        match std::fs::symlink_metadata(&self.path) {
            Ok(_) => std::fs::canonicalize(&self.path).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("the symbolic link points to a file that cannot be found: {error}"),
                )
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(self.path.clone()),
            Err(error) => Err(error),
        }
    }

    /// The file this document was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The top-level table `key` (`server`, `source`), created as an implicit table
    /// (no `[key]` header) if missing.
    fn parent_table(&mut self, key: &str) -> Result<&mut toml_edit::Table, EditError> {
        let item = self.doc.entry(key).or_insert_with(|| {
            let mut table = toml_edit::Table::new();
            table.set_implicit(true);
            toml_edit::Item::Table(table)
        });
        item.as_table_mut().ok_or_else(|| EditError::Syntax {
            path: self.path.clone(),
            message: format!("{key} must be a table of [{key}.<name>] tables"),
        })
    }
}

/// A [`ConfigDocument`] whose text validated, with the configuration it describes.
#[derive(Debug)]
pub struct Validated<'a> {
    /// The document.
    doc: &'a ConfigDocument,
    /// The text that validated.
    text: String,
    /// The configuration it describes.
    config: Config,
}

impl Validated<'_> {
    /// The configuration the text describes.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Writes the validated text as [`ConfigDocument::save`] does and returns its
    /// configuration.
    pub fn save(self) -> Result<Config, EditError> {
        self.doc.write(&self.text)?;
        Ok(self.config)
    }
}

/// Parses `text` as TOML; errors name `path`.
fn parse_text(path: &Path, text: &str) -> Result<toml_edit::DocumentMut, EditError> {
    text.parse::<toml_edit::DocumentMut>().map_err(|err| EditError::Syntax {
        path: path.to_owned(),
        message: err.to_string().trim_end().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use credential_bridge_proto::ipc::git::Access;

    use super::*;
    use crate::paths::{PathVars, TargetOs};
    use crate::test_support::test_key;

    fn paths(home: &Path) -> Paths {
        let vars = PathVars { home: Some(home.as_os_str().to_owned()), ..PathVars::default() };
        Paths::from_vars(&vars, TargetOs::Linux).unwrap()
    }

    const USER_TEXT: &str = r#"# my configuration
version = 2

# profiles are mine
[profile.build]
ssh = { keys = "all" }   # all keys

[profile.dev]
ssh = { keys = "all" }
"#;

    #[test]
    fn missing_file_starts_versioned_document() {
        let dir = tempfile::tempdir().unwrap();
        let doc = ConfigDocument::open(&dir.path().join("config.toml")).unwrap();
        assert_eq!(doc.to_text(), "version = 2\n");
    }

    /// The original text is what the caller read once, never a second read of the file.
    #[test]
    fn documents_use_the_text_read_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, USER_TEXT).unwrap();
        let doc = ConfigDocument::open(&path).unwrap();
        std::fs::write(&path, "version = 2\n# changed behind our back\n").unwrap();
        assert_eq!(doc.original_text(), Some(USER_TEXT));

        // A broken original can be replaced; the new text must parse.
        let doc = ConfigDocument::replacing(&path, Some("version = \n".into()), "version = 2\n[profile.x]\n")
            .unwrap();
        assert_eq!(doc.original_text(), Some("version = \n"));
        assert_eq!(doc.to_text(), "version = 2\n[profile.x]\n");
        assert!(doc.original_config(&paths(dir.path())).is_err());
        assert!(matches!(
            ConfigDocument::replacing(&path, None, "version = \n"),
            Err(EditError::Syntax { .. })
        ));

        let doc = ConfigDocument::from_original(&path, Some(USER_TEXT.to_owned())).unwrap();
        assert_eq!((doc.original_text(), doc.to_text().as_str()), (Some(USER_TEXT), USER_TEXT));
        let doc = ConfigDocument::from_original(&path, None).unwrap();
        assert_eq!((doc.original_text(), doc.to_text().as_str()), (None, "version = 2\n"));
    }

    #[test]
    fn invalid_toml_is_syntax_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "version = \n").unwrap();
        assert!(matches!(ConfigDocument::open(&path), Err(EditError::Syntax { .. })));
    }

    #[test]
    fn set_server_keeps_user_content() {
        let (key_a, key_b) = (test_key(1), test_key(2));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, USER_TEXT).unwrap();
        let mut doc = ConfigDocument::open(&path).unwrap();
        doc.set_server("buildserver", &HostKeysEntry::Pinned(std::slice::from_ref(&key_a)), "build", true)
            .unwrap();
        doc.set_server("devbox", &HostKeysEntry::Pinned(std::slice::from_ref(&key_b)), "build", false)
            .unwrap();
        let text = doc.to_text();
        assert!(text.starts_with(USER_TEXT), "{text}");
        assert!(
            text.contains(&format!("[server.buildserver]\nhost_keys = [\"{key_a}\"]\nprofile = \"build\"\n"))
        );
        assert!(text.contains("[server.devbox]"));
        assert!(text.contains("git_config = false"));
        assert!(!text.contains("[server]\n"), "parent table must stay implicit: {text}");

        doc.save(&paths(dir.path())).unwrap();
        let config = crate::Config::load(&path, &paths(dir.path())).unwrap();
        assert_eq!(config.servers["buildserver"].profile, "build");
        assert!(config.servers["buildserver"].git_config);
        assert!(!config.servers["devbox"].git_config);
    }

    #[test]
    fn set_server_replaces_in_place() {
        let (key_a, key_b) = (test_key(1), test_key(2));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let text = format!(
            "{USER_TEXT}\n# pinned by ctl\n[server.a]\nhost_keys = [\"{key_a}\"]\nprofile = \"build\"\n\n\
             [server.b]\nhost_keys = [\"{key_b}\"]\nprofile = \"build\"\n"
        );
        std::fs::write(&path, &text).unwrap();
        let mut doc = ConfigDocument::open(&path).unwrap();
        doc.set_server("a", &HostKeysEntry::Pinned(std::slice::from_ref(&key_a)), "dev", false).unwrap();
        let out = doc.to_text();
        let a = out.find("[server.a]").unwrap();
        let b = out.find("[server.b]").unwrap();
        assert!(a < b, "replaced table moved: {out}");
        assert!(out.contains("# pinned by ctl\n[server.a]"), "{out}");
        assert!(out.contains("profile = \"dev\"\ngit_config = false"), "{out}");
        assert_eq!(out.matches("[server.a]").count(), 1);
    }

    /// Running `set_server` again switches between following known_hosts and pinning,
    /// keeping the table's place and comment.
    #[test]
    fn set_server_switches_between_known_hosts_and_pinned() {
        let key_a = test_key(1);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            format!("{USER_TEXT}\n# my box\n[server.a]\nhost_keys = [\"{key_a}\"]\nprofile = \"build\"\n"),
        )
        .unwrap();
        let mut doc = ConfigDocument::open(&path).unwrap();
        doc.set_server(
            "a",
            &HostKeysEntry::KnownHost { name: "[a.example]:2222", files: None },
            "build",
            true,
        )
        .unwrap();
        let out = doc.to_text();
        assert!(
            out.contains("# my box\n[server.a]\nknown_host = \"[a.example]:2222\"\nprofile = \"build\"\n"),
            "{out}"
        );
        assert!(!out.contains("host_keys"), "{out}");
        let config = doc.check(&paths(dir.path())).unwrap();
        match &config.servers["a"].keys {
            crate::ServerKeys::KnownHost(known) => {
                assert_eq!(known.name, "[a.example]:2222");
                assert_eq!(known.files, crate::known_hosts::default_files(dir.path()));
            }
            other => panic!("{other:?}"),
        }

        let files = ["~/.ssh/work_hosts".to_owned()];
        doc.set_server("a", &HostKeysEntry::KnownHost { name: "a", files: Some(&files) }, "build", true)
            .unwrap();
        assert!(doc.to_text().contains("known_host = \"a\"\nknown_hosts_files = [\"~/.ssh/work_hosts\"]\n"));
        let config = doc.check(&paths(dir.path())).unwrap();
        assert!(matches!(&config.servers["a"].keys,
            crate::ServerKeys::KnownHost(known) if known.files == [dir.path().join(".ssh/work_hosts")]));

        doc.set_server("a", &HostKeysEntry::Pinned(std::slice::from_ref(&key_a)), "build", true).unwrap();
        let out = doc.to_text();
        assert!(!out.contains("known_host"), "{out}");
        assert!(out.contains(&format!("[server.a]\nhost_keys = [\"{key_a}\"]\n")), "{out}");
    }

    #[test]
    fn remove_server() {
        let key_a = test_key(1);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, USER_TEXT).unwrap();
        let mut doc = ConfigDocument::open(&path).unwrap();
        assert!(!doc.remove_server("x"));
        doc.set_server("x", &HostKeysEntry::Pinned(std::slice::from_ref(&key_a)), "build", true).unwrap();
        assert!(doc.remove_server("x"));
        assert!(!doc.remove_server("x"));
        assert!(!doc.to_text().contains("server.x"));
    }

    #[test]
    fn add_github_app_source() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, USER_TEXT).unwrap();
        let mut doc = ConfigDocument::open(&path).unwrap();
        let max: Permissions =
            [("contents".to_owned(), Access::Write), ("pull_requests".to_owned(), Access::Read)].into();
        doc.add_github_app_source("my-org", "github.com", 123456, "op://Dev/bridge-app/private-key", &max)
            .unwrap();
        let text = doc.to_text();
        assert!(
            text.contains(
                "[source.my-org]\ntype = \"github\"\nauth = \"app\"\napp_id = 123456\n\
             private_key = \"op://Dev/bridge-app/private-key\"\n\
             max_permissions = { contents = \"write\", pull_requests = \"read\" }\n"
            ),
            "{text}"
        );
        assert!(matches!(
            doc.add_github_app_source("my-org", "github.com", 1, "op://a/b/c", &max),
            Err(EditError::Exists { table }) if table == "source.my-org"
        ));
        doc.save(&paths(dir.path())).unwrap();
        let config = crate::Config::load(&path, &paths(dir.path())).unwrap();
        assert!(matches!(
            &config.sources["my-org"].kind,
            crate::SourceKind::GithubApp { app_id: 123456, max_permissions, .. } if *max_permissions == max
        ));

        // GitHub Enterprise: the host is written, and the API URL follows from it.
        doc.add_github_app_source("ghes", "github.example.com", 2, "op://a/b/c", &max).unwrap();
        assert!(
            doc.to_text().contains(
                "[source.ghes]\ntype = \"github\"\nauth = \"app\"\nhost = \"github.example.com\"\n"
            )
        );
        doc.save(&paths(dir.path())).unwrap();
        let config = crate::Config::load(&path, &paths(dir.path())).unwrap();
        assert!(matches!(
            &config.sources["ghes"].kind,
            crate::SourceKind::GithubApp { host, api_url, .. }
                if host == "github.example.com" && api_url == "https://github.example.com/api/v3"
        ));
    }

    #[test]
    fn save_refuses_invalid_result_and_writes_nothing() {
        let key_a = test_key(1);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, USER_TEXT).unwrap();
        let mut doc = ConfigDocument::open(&path).unwrap();
        doc.set_server("x", &HostKeysEntry::Pinned(std::slice::from_ref(&key_a)), "no-such-profile", true)
            .unwrap();
        let err = doc.save(&paths(dir.path())).unwrap_err();
        assert!(matches!(&err, EditError::Invalid(ConfigError::Invalid { path: p, .. }) if *p == path));
        assert!(err.to_string().contains("no-such-profile"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), USER_TEXT);
        let leftovers: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(leftovers.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn save_creates_private_file_and_directories() {
        let key_a = test_key(1);
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("config.toml");
        let mut doc = ConfigDocument::open(&path).unwrap();
        doc.set_server("x", &HostKeysEntry::Pinned(std::slice::from_ref(&key_a)), "dev", true).unwrap();
        // Unknown profile: invalid until the user adds one.
        assert!(doc.save(&paths(dir.path())).is_err());
        assert!(!path.exists());

        let mut doc = ConfigDocument::open(&path).unwrap();
        doc.add_github_app_source(
            "app",
            "github.com",
            7,
            "op://a/b/c",
            &[("contents".to_owned(), Access::Read)].into(),
        )
        .unwrap();
        doc.save(&paths(dir.path())).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(doc.path(), path);
    }

    fn app_source(doc: &mut ConfigDocument) {
        doc.add_github_app_source(
            "app",
            "github.com",
            7,
            "op://a/b/c",
            &[("contents".to_owned(), Access::Read)].into(),
        )
        .unwrap();
    }

    /// A symbolic link (dotfile managers) stays a link; the file it points to is replaced.
    #[cfg(unix)]
    #[test]
    fn save_keeps_a_symbolic_link() {
        let dir = tempfile::tempdir().unwrap();
        let dotfiles = dir.path().join("dotfiles");
        std::fs::create_dir(&dotfiles).unwrap();
        let real = dotfiles.join("config.toml");
        std::fs::write(&real, "# mine\nversion = 2\n").unwrap();
        let config_dir = dir.path().join("config");
        std::fs::create_dir(&config_dir).unwrap();
        let link = config_dir.join("config.toml");
        std::os::unix::fs::symlink("../dotfiles/config.toml", &link).unwrap();

        let mut doc = ConfigDocument::open(&link).unwrap();
        app_source(&mut doc);
        doc.save(&paths(dir.path())).unwrap();
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        let text = std::fs::read_to_string(&real).unwrap();
        assert!(text.starts_with("# mine\n") && text.contains("[source.app]"), "{text}");
        let leftovers: Vec<_> =
            std::fs::read_dir(&dotfiles).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(leftovers.len(), 1, "{leftovers:?}");
        assert_eq!(std::fs::read_dir(&config_dir).unwrap().count(), 1);
    }

    /// A link into a read-only place (home-manager into `/nix/store`) is refused with a
    /// clear error, and neither the link nor its target changes.
    #[cfg(unix)]
    #[test]
    fn save_refuses_a_link_to_a_read_only_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir(&store).unwrap();
        let real = store.join("config.toml");
        std::fs::write(&real, "version = 2\n").unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o444)).unwrap();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o555)).unwrap();
        let link = dir.path().join("config.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // As root, permissions do not stop writing: nothing to test.
        let root = std::fs::OpenOptions::new().write(true).open(&real).is_ok();
        if !root {
            let mut doc = ConfigDocument::open(&link).unwrap();
            app_source(&mut doc);
            let error = doc.save(&paths(dir.path())).unwrap_err();
            assert!(matches!(&error, EditError::NotWritable { target, .. } if *target == real), "{error:?}");
            let message = error.to_string();
            assert!(message.contains("is a link to") && message.contains("home-manager"), "{message}");
            assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
            assert_eq!(std::fs::read_to_string(&real).unwrap(), "version = 2\n");

            // A read-only file that is not a link is refused too.
            let plain = dir.path().join("plain.toml");
            std::fs::write(&plain, "version = 2\n").unwrap();
            std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o444)).unwrap();
            let mut doc = ConfigDocument::open(&plain).unwrap();
            app_source(&mut doc);
            let error = doc.save(&paths(dir.path())).unwrap_err();
            assert!(
                error.to_string().starts_with(&format!("{} is not writable", plain.display())),
                "{error}"
            );
            assert_eq!(std::fs::read_to_string(&plain).unwrap(), "version = 2\n");
        }
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A link whose target is missing is not replaced by a file.
    #[cfg(unix)]
    #[test]
    fn save_refuses_a_dangling_link() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("config.toml");
        std::os::unix::fs::symlink(dir.path().join("gone.toml"), &link).unwrap();
        let mut doc = ConfigDocument::open(&link).unwrap();
        app_source(&mut doc);
        let error = doc.save(&paths(dir.path())).unwrap_err();
        assert!(error.to_string().contains("cannot be found"), "{error}");
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert!(!dir.path().join("gone.toml").exists());
    }
}
