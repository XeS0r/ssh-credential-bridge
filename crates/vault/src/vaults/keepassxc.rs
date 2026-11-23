//! KeePassXC. With `[vault.keepassxc] database` (Linux and macOS) through `keepassxc-cli`
//! on exactly that file, with the database password from `ctl vault unlock keepassxc` written
//! to stdin and the optional `key_file` as `--key-file`. Without a database on Linux
//! through the app's Secret Service integration (the database must be open in the app,
//! which exposes it).

use std::path::Path;

use credential_bridge_config::VaultKind;
use credential_bridge_proto::secret::Secret;

use crate::error::VaultError;
use crate::runner::{CommandOutput, CommandRunner, CommandSpec};
use crate::tool::{self, Owner};

/// The CLI program.
pub(super) const CLI: &str = "keepassxc-cli";
const VAULT: VaultKind = VaultKind::KeePassXc;

/// One `keepassxc://group/…/item/field` reference.
#[derive(Debug, Clone, Copy)]
pub(super) struct Entry<'a> {
    /// Groups below the root.
    pub group: &'a [String],
    /// Entry title.
    pub item: &'a str,
    /// Attribute.
    pub field: &'a str,
}

impl Entry<'_> {
    /// `Group/Sub/Title`, as `keepassxc-cli` and KeePassXC's Secret Service `Path` take it.
    pub(super) fn path(&self) -> String {
        let mut parts: Vec<&str> = self.group.iter().map(String::as_str).collect();
        parts.push(self.item);
        parts.join("/")
    }

    /// The KeePassXC attribute of `field`: the standard ones by their lowercase name,
    /// anything else as given (a custom attribute).
    pub(super) fn attribute(&self) -> &str {
        match self.field {
            "password" => "Password",
            "username" => "UserName",
            "url" => "URL",
            "notes" => "Notes",
            "title" => "Title",
            other => other,
        }
    }
}

/// How KeePassXC is reached on this platform.
#[derive(Debug)]
pub(super) enum Backend<'a, R: CommandRunner> {
    /// `keepassxc-cli` on the configured database.
    Cli(Cli<'a, R>),
    /// The app's Secret Service (Linux without a configured database).
    SecretService,
}

impl<R: CommandRunner> Backend<'_, R> {
    pub(super) async fn read(&self, entry: &Entry<'_>) -> Result<Option<Secret>, VaultError> {
        match self {
            Backend::Cli(cli) => cli.read(entry).await,
            Backend::SecretService => secret_service_read(entry).await,
        }
    }

    pub(super) async fn write(&self, entry: &Entry<'_>, value: &Secret) -> Result<(), VaultError> {
        match self {
            Backend::Cli(cli) => cli.write(entry, value).await,
            Backend::SecretService => secret_service_write(entry, value).await,
        }
    }
}

async fn secret_service_read(entry: &Entry<'_>) -> Result<Option<Secret>, VaultError> {
    #[cfg(all(target_os = "linux", feature = "secret-service"))]
    return super::secret_service::keepassxc_read(entry).await;
    #[cfg(not(all(target_os = "linux", feature = "secret-service")))]
    {
        let _ = entry;
        Err(super::secret_service_unsupported(VAULT))
    }
}

async fn secret_service_write(entry: &Entry<'_>, value: &Secret) -> Result<(), VaultError> {
    #[cfg(all(target_os = "linux", feature = "secret-service"))]
    return super::secret_service::keepassxc_write(entry, value).await;
    #[cfg(not(all(target_os = "linux", feature = "secret-service")))]
    {
        let _ = (entry, value);
        Err(super::secret_service_unsupported(VAULT))
    }
}

/// `keepassxc-cli` on one database.
#[derive(Debug)]
pub(super) struct Cli<'a, R: CommandRunner> {
    pub runner: &'a R,
    pub database: &'a Path,
    /// The key file (`--key-file`), if the database needs one besides the password.
    pub key_file: Option<&'a Path>,
    /// The database password; `None` only for [`Cli::verify`], which gets it passed.
    pub password: Option<&'a Secret>,
}

/// stderr phrases for a wrong database password.
const BAD_PASSWORD: &[&str] = &["invalid credentials", "wrong key", "wrong password"];
/// stderr phrases for a missing entry or attribute.
const NOT_FOUND: &[&str] = &["could not find entry", "unknown attribute", "not found"];

impl<R: CommandRunner> Cli<'_, R> {
    /// Opens the database with `password` (`keepassxc-cli ls`) to check it.
    pub(super) async fn verify(&self, password: &Secret) -> Result<(), VaultError> {
        let output = self.run(&["ls", "-q"], &[], password, &[]).await?;
        if output.success() {
            Ok(())
        } else if tool::stderr_mentions(&output, BAD_PASSWORD) {
            Err(VaultError::ToolFailed {
                program: CLI.to_owned(),
                detail: "wrong database password".to_owned(),
            })
        } else {
            Err(tool::failed(CLI, &output))
        }
    }

    /// `keepassxc-cli show -q -s -a <attribute> <db> <entry>`.
    pub(super) async fn read(&self, entry: &Entry<'_>) -> Result<Option<Secret>, VaultError> {
        let path = entry.path();
        let output =
            self.run(&["show", "-q", "-s", "-a", entry.attribute()], &[&path], self.password()?, &[]).await?;
        if !output.success() {
            return self.failure(&output).map(|()| None);
        }
        let text = output.stdout.expose();
        match text.strip_suffix('\n') {
            Some(trimmed) => Ok(Some(Secret::new(trimmed.to_owned()))),
            None => Ok(Some(output.stdout)),
        }
    }

    /// Sets the password of the entry (`edit -p`, or `add -p` for a new entry). Other
    /// attributes and values with line breaks cannot be passed without the command line
    /// and are [`VaultError::Unsupported`].
    pub(super) async fn write(&self, entry: &Entry<'_>, value: &Secret) -> Result<(), VaultError> {
        if entry.attribute() != "Password" {
            return Err(VaultError::Unsupported {
                vault: VAULT,
                reason: "keepassxc-cli can only write the password field".to_owned(),
            });
        }
        if value.expose().contains(['\n', '\r']) {
            return Err(VaultError::Unsupported {
                vault: VAULT,
                reason: "keepassxc-cli cannot store values with line breaks".to_owned(),
            });
        }
        let password = self.password()?;
        let path = entry.path();
        let exists = self.run(&["show", "-q"], &[&path], password, &[]).await?;
        let command = if exists.success() {
            "edit"
        } else {
            self.failure(&exists)?;
            "add"
        };
        // keepassxc-cli asks for the new password once, some versions twice.
        let output = self.run(&[command, "-q", "-p"], &[&path], password, &[value, value]).await?;
        if output.success() {
            Ok(())
        } else {
            Err(self.failure(&output).err().unwrap_or_else(|| tool::failed(CLI, &output)))
        }
    }

    fn password(&self) -> Result<&Secret, VaultError> {
        self.password.ok_or(VaultError::Locked { vault: VAULT })
    }

    /// `Ok(())` for "not found", the error otherwise.
    fn failure(&self, output: &CommandOutput) -> Result<(), VaultError> {
        if tool::stderr_mentions(output, BAD_PASSWORD) {
            Err(VaultError::Locked { vault: VAULT })
        } else if tool::stderr_mentions(output, NOT_FOUND) {
            Ok(())
        } else {
            Err(tool::failed(CLI, output))
        }
    }

    /// `keepassxc-cli <args> [--key-file <file>] <database> <after>` with the database
    /// password and `inputs` as lines on stdin.
    async fn run(
        &self,
        args: &[&str],
        after: &[&str],
        password: &Secret,
        inputs: &[&Secret],
    ) -> Result<CommandOutput, VaultError> {
        let mut stdin =
            String::with_capacity(password.len() + 1 + inputs.iter().map(|i| i.len() + 1).sum::<usize>());
        for line in std::iter::once(password).chain(inputs.iter().copied()) {
            stdin.push_str(line.expose());
            stdin.push('\n');
        }
        let database = self.database.display().to_string();
        let key_file = self.key_file.map(|path| path.display().to_string());
        let key_file_args = key_file.as_deref().map(|path| ["--key-file", path]);
        let args = args
            .iter()
            .copied()
            .chain(key_file_args.into_iter().flatten())
            .chain([database.as_str()])
            .chain(after.iter().copied());
        let spec = CommandSpec::new(CLI, args).with_stdin(Secret::new(stdin));
        tool::run(self.runner, Owner::Vault(VAULT), &spec).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vaults::tests::FakeBin;

    fn secret(text: &str) -> Secret {
        Secret::new(text.to_owned())
    }

    #[test]
    fn paths_and_attributes() {
        let group = vec!["Dev".to_owned(), "Git".to_owned()];
        let entry = Entry { group: &group, item: "app", field: "username" };
        assert_eq!(entry.path(), "Dev/Git/app");
        assert_eq!(entry.attribute(), "UserName");
        let root = Entry { group: &[], item: "app", field: "api-key" };
        assert_eq!(root.path(), "app");
        assert_eq!(root.attribute(), "api-key");
    }

    /// A fake keepassxc-cli: database password `dbpw`, one entry `Dev/app` with
    /// password `s3cret`; `add`/`edit` append their stdin to `log`.
    fn fake(bin: &FakeBin) -> std::path::PathBuf {
        let log = bin.path().join("log");
        bin.script(
            CLI,
            &format!(
                r#"read pw
[ "$pw" = dbpw ] || {{ echo "Error while reading the database: Invalid credentials were provided" >&2; exit 1; }}
case "$1" in
  ls) echo "Dev/" ;;
  show) for last; do :; done
        [ "$last" = Dev/app ] || {{ echo "Could not find entry with path $last." >&2; exit 1; }}
        printf 's3cret\n' ;;
  add|edit) echo "$1 $5" >> '{log}'; cat >> '{log}' ;;
esac"#,
                log = log.display()
            ),
        );
        log
    }

    #[tokio::test]
    async fn verifies_reads_and_writes() {
        let bin = FakeBin::new();
        let log = fake(&bin);
        let runner = bin.runner();
        let database = bin.path().join("db.kdbx");
        let password = secret("dbpw");
        let cli = Cli { runner: &runner, database: &database, key_file: None, password: Some(&password) };
        cli.verify(&password).await.unwrap();
        let error = cli.verify(&secret("bad")).await.unwrap_err();
        assert_eq!(error.to_string(), "keepassxc-cli failed: wrong database password");

        let group = vec!["Dev".to_owned()];
        let entry = Entry { group: &group, item: "app", field: "password" };
        assert_eq!(cli.read(&entry).await.unwrap().unwrap().expose(), "s3cret");
        let missing = Entry { group: &group, item: "nope", field: "password" };
        assert!(cli.read(&missing).await.unwrap().is_none());

        cli.write(&entry, &secret("v1")).await.unwrap();
        cli.write(&missing, &secret("v2")).await.unwrap();
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "edit Dev/app\nv1\nv1\nadd Dev/nope\nv2\nv2\n");

        let username = Entry { group: &group, item: "app", field: "username" };
        assert!(matches!(cli.write(&username, &secret("x")).await, Err(VaultError::Unsupported { .. })));
        assert!(matches!(cli.write(&entry, &secret("a\nb")).await, Err(VaultError::Unsupported { .. })));

        let stale = secret("old");
        let cli = Cli { runner: &runner, database: &database, key_file: None, password: Some(&stale) };
        assert_eq!(cli.read(&entry).await.unwrap_err(), VaultError::Locked { vault: VAULT });
    }
}
