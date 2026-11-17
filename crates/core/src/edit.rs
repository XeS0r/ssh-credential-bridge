//! Comment-preserving edits of the configuration file.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, value};

use crate::config::{Config, ConfigError, EXAMPLE_CONFIG, RemoteConfig};

/// A configuration file opened for editing.
#[derive(Debug)]
pub struct ConfigDocument {
    path: PathBuf,
    doc: DocumentMut,
}

impl ConfigDocument {
    /// Opens `path`; a missing file starts from [`EXAMPLE_CONFIG`].
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == io::ErrorKind::NotFound => EXAMPLE_CONFIG.to_owned(),
            Err(source) => return Err(ConfigError::Read { path: path.to_owned(), source }),
        };
        let doc = text
            .parse::<DocumentMut>()
            .map_err(|err| ConfigError::Toml { path: path.to_owned(), message: err.message().to_owned() })?;
        Ok(Self { path: path.to_owned(), doc })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn remotes_mut(&mut self) -> Result<&mut ArrayOfTables, ConfigError> {
        self.doc
            .entry("remote")
            .or_insert(Item::ArrayOfTables(ArrayOfTables::new()))
            .as_array_of_tables_mut()
            .ok_or_else(|| ConfigError::Invalid("`remote` must be written as [[remote]] blocks".into()))
    }

    fn position(&mut self, name: &str) -> Result<Option<usize>, ConfigError> {
        Ok(self
            .remotes_mut()?
            .iter()
            .position(|table| table.get("name").and_then(Item::as_str) == Some(name)))
    }

    /// Appends a `[[remote]]` block. Fails if the name is taken.
    pub fn add_remote(&mut self, remote: &RemoteConfig) -> Result<(), ConfigError> {
        if self.position(&remote.name)?.is_some() {
            return Err(ConfigError::Invalid(format!("remote '{}' already exists", remote.name)));
        }
        let mut table = Table::new();
        table["name"] = value(&remote.name);
        if let Some(host) = &remote.ssh_host {
            table["ssh_host"] = value(host);
        }
        table["allow"] = value(remote.allow.iter().collect::<Array>());
        table["operations"] = value(remote.operations.iter().collect::<Array>());
        if let Some(backend) = &remote.backend {
            table["backend"] = value(backend);
        }
        if let Some(socket) = &remote.remote_socket {
            table["remote_socket"] = value(socket);
        }
        // Comments after the last entry are the document's trailing text and
        // would end up *below* the new block, so that a commented-out global
        // option there turns into a key of this remote once uncommented.
        // Keep them above the block instead: append at the very end.
        let trailing = self.doc.trailing().as_str().unwrap_or_default().to_owned();
        if !trailing.trim().is_empty() {
            let separator = if trailing.ends_with("\n\n") { "" } else { "\n" };
            table.decor_mut().set_prefix(format!("{trailing}{separator}"));
            self.doc.set_trailing("");
        }
        self.remotes_mut()?.push(table);
        Ok(())
    }

    /// Removes the block of `name`; returns whether it existed.
    pub fn remove_remote(&mut self, name: &str) -> Result<bool, ConfigError> {
        let Some(index) = self.position(name)? else {
            return Ok(false);
        };
        let remotes = self.remotes_mut()?;
        // Comments above the block (for the first one: the documentation that
        // `add_remote` moved there) belong to the file, not to this remote.
        let comments = remotes
            .get(index)
            .and_then(|table| table.decor().prefix())
            .and_then(|prefix| prefix.as_str())
            .filter(|prefix| prefix.contains('#'))
            .map(str::to_owned);
        remotes.remove(index);
        if let Some(comments) = comments {
            match remotes.get_mut(index) {
                Some(next) => {
                    let rest = next.decor().prefix().and_then(|p| p.as_str()).unwrap_or_default().to_owned();
                    next.decor_mut().set_prefix(format!("{comments}{}", rest.trim_start_matches('\n')));
                }
                None => {
                    let trailing = self.doc.trailing().as_str().unwrap_or_default().to_owned();
                    self.doc.set_trailing(format!("{comments}{trailing}"));
                }
            }
        }
        Ok(true)
    }

    /// Sets a string field of the block of `name`.
    pub fn set_remote_value(&mut self, name: &str, key: &str, val: &str) -> Result<(), ConfigError> {
        self.remote_mut(name)?[key] = value(val);
        Ok(())
    }

    /// Sets a string-list field of the block of `name`.
    pub fn set_remote_list(&mut self, name: &str, key: &str, values: &[String]) -> Result<(), ConfigError> {
        let table = self.remote_mut(name)?;
        table[key] = value(values.iter().collect::<Array>());
        Ok(())
    }

    /// Removes a field of the block of `name`, if present.
    pub fn remove_remote_value(&mut self, name: &str, key: &str) -> Result<(), ConfigError> {
        self.remote_mut(name)?.remove(key);
        Ok(())
    }

    fn remote_mut(&mut self, name: &str) -> Result<&mut Table, ConfigError> {
        let index =
            self.position(name)?.ok_or_else(|| ConfigError::Invalid(format!("no remote named '{name}'")))?;
        Ok(self.remotes_mut()?.get_mut(index).expect("index returned by position"))
    }

    /// Parses and validates the edited document.
    pub fn to_config(&self) -> Result<Config, ConfigError> {
        Config::parse(&self.doc.to_string(), &self.path)
    }

    /// Validates, then atomically replaces the file (mode 0600).
    pub fn save(&self) -> Result<(), ConfigError> {
        self.to_config()?;
        // A symlinked config (dotfiles, home-manager) stays a symlink: write
        // its target instead of replacing the link with a regular file.
        let target = match fs::symlink_metadata(&self.path) {
            Ok(meta) if meta.file_type().is_symlink() => fs::canonicalize(&self.path)
                .map_err(|source| ConfigError::Write { path: self.path.clone(), source })?,
            _ => self.path.clone(),
        };
        let write_err = |source| ConfigError::Write { path: target.clone(), source };
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(write_err)?;
        }
        let tmp = target.with_extension("toml.tmp");
        let result = (|| {
            let mut file =
                fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            file.write_all(self.doc.to_string().as_bytes())?;
            file.sync_all()?;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
            fs::rename(&tmp, &target)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result.map_err(write_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(name: &str) -> RemoteConfig {
        RemoteConfig {
            name: name.into(),
            ssh_host: Some("me@host".into()),
            remote_socket: None,
            allow: vec!["https://github.com".into()],
            operations: vec!["get".into()],
            backend: None,
        }
    }

    #[test]
    fn add_set_remove_round_trip_keeps_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/config.toml");

        let mut doc = ConfigDocument::load(&path).unwrap();
        doc.add_remote(&remote("a")).unwrap();
        doc.add_remote(&remote("b")).unwrap();
        assert!(doc.add_remote(&remote("a")).is_err());
        doc.set_remote_value("a", "remote_socket", "/home/me/x.sock").unwrap();
        doc.save().unwrap();

        let text = fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# credential-bridge configuration"));
        let config = Config::load(&path).unwrap();
        assert_eq!(config.remotes.len(), 2);
        assert_eq!(config.remote("a").unwrap().remote_socket.as_deref(), Some("/home/me/x.sock"));
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

        let mut doc = ConfigDocument::load(&path).unwrap();
        assert!(doc.remove_remote("a").unwrap());
        assert!(!doc.remove_remote("a").unwrap());
        doc.save().unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.remotes.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["b"]);
    }

    #[test]
    fn appends_remotes_after_trailing_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut doc = ConfigDocument::load(&path).unwrap();
        doc.add_remote(&remote("a")).unwrap();
        doc.add_remote(&remote("b")).unwrap();
        doc.save().unwrap();

        let text = fs::read_to_string(&path).unwrap();
        let comment = text.find("# socket_dir =").unwrap();
        let first = text.find("[[remote]]\nname = \"a\"").unwrap();
        let second = text.find("[[remote]]\nname = \"b\"").unwrap();
        assert!(comment < first && first < second, "{text}");
        assert!(text[..first].ends_with("\n\n"), "blank line before the block:\n{text}");
        assert_eq!(Config::load(&path).unwrap().remotes.len(), 2);
    }

    #[test]
    fn edits_lists_and_removes_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut doc = ConfigDocument::load(&path).unwrap();
        let mut r = remote("a");
        r.backend = Some("osxkeychain".into());
        doc.add_remote(&r).unwrap();
        doc.set_remote_list("a", "allow", &["https://github.com".into(), "https://gitlab.com".into()])
            .unwrap();
        doc.remove_remote_value("a", "backend").unwrap();
        assert!(doc.set_remote_list("nope", "allow", &[]).is_err());
        doc.save().unwrap();

        let config = Config::load(&path).unwrap();
        let a = config.remote("a").unwrap();
        assert_eq!(a.allow, ["https://github.com", "https://gitlab.com"]);
        assert_eq!(a.backend, None);
    }

    #[test]
    fn removing_remotes_keeps_the_file_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut doc = ConfigDocument::load(&path).unwrap();
        doc.add_remote(&remote("a")).unwrap();
        doc.add_remote(&remote("b")).unwrap();
        doc.save().unwrap();

        for name in ["a", "b"] {
            let mut doc = ConfigDocument::load(&path).unwrap();
            assert!(doc.remove_remote(name).unwrap());
            doc.save().unwrap();
            let text = fs::read_to_string(&path).unwrap();
            assert!(text.contains("# socket_dir = "), "after removing {name}:\n{text}");
            assert!(text.contains("# One [[remote]] block per SSH host."), "after removing {name}:\n{text}");
        }
        assert!(Config::load(&path).unwrap().remotes.is_empty());

        // And adding again still puts the block below them.
        let mut doc = ConfigDocument::load(&path).unwrap();
        doc.add_remote(&remote("c")).unwrap();
        doc.save().unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.find("# socket_dir = ").unwrap() < text.find("[[remote]]\nname = \"c\"").unwrap());
    }

    #[test]
    fn saving_keeps_a_symlinked_config_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("dotfiles/config.toml");
        fs::create_dir_all(real.parent().unwrap()).unwrap();
        fs::write(&real, crate::config::EXAMPLE_CONFIG).unwrap();
        let link = dir.path().join("config.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let mut doc = ConfigDocument::load(&link).unwrap();
        doc.add_remote(&remote("a")).unwrap();
        doc.save().unwrap();

        assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink(), "link was replaced");
        assert_eq!(Config::load(&real).unwrap().remotes.len(), 1, "target was not updated");
    }

    #[test]
    fn refuses_to_save_invalid_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut doc = ConfigDocument::load(&path).unwrap();
        let mut bad = remote("x");
        bad.allow = vec!["not-a-url".into()];
        doc.add_remote(&bad).unwrap();
        assert!(doc.save().is_err());
        assert!(!path.exists());
    }
}
