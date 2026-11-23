//! The git sources that run programs: `gh` (`gh auth git-credential`) and `helper` (an
//! existing git credential helper). Both speak the git credential format
//! ([`credential_bridge_proto::credential`]) on stdin/stdout.

use credential_bridge_proto::credential::Credential;
use credential_bridge_proto::ipc::git::{GitToken, TokenTarget};
use credential_bridge_proto::ipc::vault::CredentialAction;
use credential_bridge_proto::secret::Secret;

use crate::error::VaultError;
use crate::runner::{CommandOutput, CommandRunner, CommandSpec};
use crate::tool::{self, Owner};

/// Hint shown when `gh` has no login for the host; the detail of the error appends
/// `--hostname <host>`.
pub const GH_LOGIN_HINT: &str = "not logged in on your local machine: run gh auth login";

/// Runs `gh auth git-credential get` (or `erase`) for `target`.
///
/// `erase` is ignored (gh's tokens are not git's to drop) and returns `Ok(None)` without
/// running gh. Returns `Ok(None)` if gh answers without a password. Errors:
/// [`VaultError::ProgramMissing`] without `gh`; [`VaultError::ToolFailed`] with
/// [`GH_LOGIN_HINT`] and `--hostname <host>` in the detail when gh is not logged in (it
/// then fails without a word).
pub async fn gh_credential<R: CommandRunner>(
    runner: &R,
    target: &TokenTarget,
    action: CredentialAction,
) -> Result<Option<GitToken>, VaultError> {
    if action == CredentialAction::Erase {
        return Ok(None);
    }
    let spec = CommandSpec::new("gh", ["auth", "git-credential", "get"]).with_stdin(request_text(target)?);
    let output = tool::run(runner, Owner::Program, &spec).await?;
    if tool::failed_silently(&output) {
        return Err(VaultError::ToolFailed {
            program: "gh".to_owned(),
            detail: format!("{GH_LOGIN_HINT} --hostname {}", tool::sh_quote(&target.host)),
        });
    }
    if !output.success() {
        return Err(tool::failed("gh", &output));
    }
    token_from(output, "gh")
}

/// Runs a git credential helper for `target`.
///
/// `erase` never runs the helper and returns `Ok(None)`: the request comes from a
/// server and carries only protocol, host and path, so helpers such as `store` or
/// `osxkeychain` would delete every stored credential for that host on this machine.
///
/// Returns `Ok(None)` if the helper has no credential, which includes a `get` that
/// fails without a word (as git treats it). A credential without `username` gets an
/// empty one. Errors as
/// [`gh_credential`], and [`VaultError::Invalid`] for a helper string
/// [`helper_command`] rejects.
pub async fn helper_credential<R: CommandRunner>(
    runner: &R,
    helper: &str,
    target: &TokenTarget,
    action: CredentialAction,
) -> Result<Option<GitToken>, VaultError> {
    if action == CredentialAction::Erase {
        return Ok(None);
    }
    let spec = helper_command(helper, action)?.with_stdin(request_text(target)?);
    let name = helper_name(helper);
    let output = tool::run(runner, Owner::Program, &spec).await?;
    if tool::failed_silently(&output) {
        return Ok(None);
    }
    if !output.success() {
        return Err(tool::failed(&name, &output));
    }
    token_from(output, &name)
}

/// The command for a helper as git interprets `credential.helper`: a name `foo` runs
/// `git credential-foo <action>`, an absolute path runs that program with `<action>`
/// appended, `!cmd` runs `sh -c "cmd <action>"`. Arguments after the first word are
/// split as git does (shell-like quoting).
///
/// Errors: [`VaultError::Invalid`] for an empty helper or unbalanced quotes.
pub fn helper_command(helper: &str, action: CredentialAction) -> Result<CommandSpec, VaultError> {
    let helper = helper.trim();
    let action = action_word(action);
    if let Some(command) = helper.strip_prefix('!') {
        if command.trim().is_empty() {
            return Err(VaultError::Invalid("empty credential helper".to_owned()));
        }
        return Ok(CommandSpec::new("sh", ["-c".to_owned(), format!("{command} {action}")]));
    }
    let mut words = split_words(helper)?;
    if words.is_empty() {
        return Err(VaultError::Invalid("empty credential helper".to_owned()));
    }
    words.push(action.to_owned());
    if std::path::Path::new(&words[0]).is_absolute() {
        let program = words.remove(0);
        Ok(CommandSpec::new(program, words))
    } else {
        words[0] = format!("credential-{}", words[0]);
        Ok(CommandSpec::new("git", words))
    }
}

/// git's word for `action`.
fn action_word(action: CredentialAction) -> &'static str {
    match action {
        CredentialAction::Get => "get",
        CredentialAction::Erase => "erase",
    }
}

/// How a helper is named in messages: `credential helper <first word>`.
fn helper_name(helper: &str) -> String {
    let helper = helper.trim();
    let first = helper.trim_start_matches('!').split_whitespace().next().unwrap_or(helper);
    format!("credential helper {first}")
}

/// Splits like a POSIX shell without expansion: whitespace separates words, `'…'` is
/// literal, `"…"` allows `\"`, `\\`, `\$` and `` \` ``, a backslash outside quotes
/// escapes the next character.
fn split_words(text: &str) -> Result<Vec<String>, VaultError> {
    let unbalanced = || VaultError::Invalid("credential helper has unbalanced quotes".to_owned());
    let mut words = Vec::new();
    let mut word: Option<String> = None;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if let Some(done) = word.take() {
                    words.push(done);
                }
            }
            '\'' => {
                let current = word.get_or_insert_with(String::new);
                loop {
                    match chars.next().ok_or_else(unbalanced)? {
                        '\'' => break,
                        other => current.push(other),
                    }
                }
            }
            '"' => {
                let current = word.get_or_insert_with(String::new);
                loop {
                    match chars.next().ok_or_else(unbalanced)? {
                        '"' => break,
                        '\\' => match chars.next().ok_or_else(unbalanced)? {
                            escaped @ ('"' | '\\' | '$' | '`') => current.push(escaped),
                            '\n' => {}
                            other => {
                                current.push('\\');
                                current.push(other);
                            }
                        },
                        other => current.push(other),
                    }
                }
            }
            '\\' => {
                let escaped = chars.next().ok_or_else(unbalanced)?;
                if escaped != '\n' {
                    word.get_or_insert_with(String::new).push(escaped);
                }
            }
            other => word.get_or_insert_with(String::new).push(other),
        }
    }
    words.extend(word);
    Ok(words)
}

/// The credential request git would send for `target`.
fn request_text(target: &TokenTarget) -> Result<Secret, VaultError> {
    let request = Credential {
        protocol: Some(target.protocol.clone()),
        host: Some(target.host.clone()),
        path: target.path.clone(),
        ..Credential::default()
    };
    let bytes =
        request.to_bytes().map_err(|error| VaultError::Invalid(format!("invalid target: {error}")))?;
    let mut text = String::from_utf8(bytes).map_err(|_| VaultError::Invalid("invalid target".to_owned()))?;
    text.push('\n');
    Ok(Secret::new(text))
}

/// The token in a helper's answer; `None` without password or with `quit=1`.
fn token_from(output: CommandOutput, program: &str) -> Result<Option<GitToken>, VaultError> {
    let mut answer = Credential::parse(output.stdout.expose().as_bytes()).map_err(|error| {
        VaultError::ToolFailed { program: program.to_owned(), detail: format!("unusable answer: {error}") }
    })?;
    let Some(password) = answer.password.take().filter(|password| !password.is_empty()) else {
        return Ok(None);
    };
    Ok(Some(GitToken {
        username: answer.username.take().unwrap_or_default(),
        password,
        expires_at: answer.password_expiry_utc,
    }))
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Mutex;

    use super::*;

    /// Answers every run with a fixed result and records the specs.
    #[derive(Debug)]
    struct Fake {
        answer: Mutex<Option<io::Result<CommandOutput>>>,
        seen: Mutex<Vec<CommandSpec>>,
    }

    impl Fake {
        fn answering(status: i32, stdout: &str, stderr: &str) -> Self {
            let output = CommandOutput {
                status: Some(status),
                stdout: Secret::new(stdout.to_owned()),
                stderr: stderr.to_owned(),
            };
            Self { answer: Mutex::new(Some(Ok(output))), seen: Mutex::new(Vec::new()) }
        }

        fn failing(kind: io::ErrorKind) -> Self {
            Self { answer: Mutex::new(Some(Err(io::Error::from(kind)))), seen: Mutex::new(Vec::new()) }
        }

        fn seen(&self) -> Vec<CommandSpec> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl CommandRunner for Fake {
        async fn run(&self, spec: &CommandSpec) -> io::Result<CommandOutput> {
            self.seen.lock().unwrap().push(spec.clone());
            self.answer.lock().unwrap().take().expect("one run only")
        }
    }

    fn target() -> TokenTarget {
        TokenTarget { protocol: "https".into(), host: "github.com".into(), path: Some("org/app.git".into()) }
    }

    #[test]
    fn helper_command_follows_git() {
        let spec = helper_command("manager", CredentialAction::Get).unwrap();
        assert_eq!(
            (spec.program.as_str(), spec.args.as_slice()),
            ("git", &["credential-manager".into(), "get".into()][..])
        );
        let spec = helper_command("cache --timeout=60", CredentialAction::Erase).unwrap();
        assert_eq!(spec.args, ["credential-cache", "--timeout=60", "erase"]);
        let spec = helper_command("/usr/bin/helper --x 'a b'", CredentialAction::Get).unwrap();
        assert_eq!(spec.program, "/usr/bin/helper");
        assert_eq!(spec.args, ["--x", "a b", "get"]);
        let spec = helper_command("!f() { echo hi; }; f", CredentialAction::Get).unwrap();
        assert_eq!(spec.program, "sh");
        assert_eq!(spec.args, ["-c", "f() { echo hi; }; f get"]);
        let spec = helper_command(r#"store --file "/a dir/\"x\"" b\ c"#, CredentialAction::Get).unwrap();
        assert_eq!(spec.args, ["credential-store", "--file", "/a dir/\"x\"", "b c", "get"]);
    }

    #[test]
    fn helper_command_rejects_bad_input() {
        for helper in ["", "  ", "!", "foo 'bar", "foo \"bar", "foo \\"] {
            assert!(
                matches!(helper_command(helper, CredentialAction::Get), Err(VaultError::Invalid(_))),
                "{helper:?}"
            );
        }
    }

    #[tokio::test]
    async fn gh_returns_the_token_and_sends_the_target() {
        let fake = Fake::answering(0, "protocol=https\nhost=github.com\nusername=octo\npassword=gho_x\n", "");
        let token = gh_credential(&fake, &target(), CredentialAction::Get).await.unwrap().unwrap();
        assert_eq!(token.username, "octo");
        assert_eq!(token.password.expose(), "gho_x");
        let seen = fake.seen();
        assert_eq!(seen[0].program, "gh");
        assert_eq!(seen[0].args, ["auth", "git-credential", "get"]);
        let stdin = seen[0].stdin.as_ref().unwrap().expose().to_owned();
        assert!(stdin.contains("host=github.com\n") && stdin.contains("path=org/app.git\n"), "{stdin}");
    }

    #[tokio::test]
    async fn gh_without_login_hints_at_gh_auth_login() {
        let fake = Fake::answering(1, "", "");
        let error = gh_credential(&fake, &target(), CredentialAction::Get).await.unwrap_err();
        let message = error.to_string();
        assert!(message.contains(GH_LOGIN_HINT), "{message}");
        assert!(message.ends_with("gh auth login --hostname github.com"), "{message}");

        let fake = Fake::answering(1, "", "");
        let evil = TokenTarget { host: "$(x).example".into(), ..target() };
        let message = gh_credential(&fake, &evil, CredentialAction::Get).await.unwrap_err().to_string();
        assert!(message.ends_with("--hostname '$(x).example'"), "{message}");
    }

    #[tokio::test]
    async fn gh_errors_and_erase() {
        let fake = Fake::failing(io::ErrorKind::NotFound);
        let error = gh_credential(&fake, &target(), CredentialAction::Get).await.unwrap_err();
        assert_eq!(error, VaultError::ProgramMissing { program: "gh".into() });

        let fake = Fake::answering(2, "", "boom\n");
        let error = gh_credential(&fake, &target(), CredentialAction::Get).await.unwrap_err();
        assert_eq!(error.to_string(), "gh failed: exit status 2: boom");

        let fake = Fake::answering(0, "protocol=https\nhost=github.com\n", "");
        assert_eq!(gh_credential(&fake, &target(), CredentialAction::Get).await.unwrap(), None);

        let fake = Fake::answering(0, "", "");
        assert_eq!(gh_credential(&fake, &target(), CredentialAction::Erase).await.unwrap(), None);
        assert!(fake.seen().is_empty());
    }

    #[tokio::test]
    async fn helper_get_and_erase() {
        let fake = Fake::answering(0, "username=u\npassword=p\npassword_expiry_utc=1700000000\n", "");
        let token =
            helper_credential(&fake, "manager", &target(), CredentialAction::Get).await.unwrap().unwrap();
        assert_eq!((token.username.as_str(), token.password.expose()), ("u", "p"));
        assert_eq!(token.expires_at, Some(1_700_000_000));

        let fake = Fake::answering(1, "", "");
        assert_eq!(
            helper_credential(&fake, "manager", &target(), CredentialAction::Get).await.unwrap(),
            None
        );

        let fake = Fake::answering(1, "", "fatal: oops");
        let message = helper_credential(&fake, "manager", &target(), CredentialAction::Get)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(message, "credential helper manager failed: exit status 1: fatal: oops");

        let fake = Fake::answering(1, "", "ignored");
        assert_eq!(
            helper_credential(&fake, "manager", &target(), CredentialAction::Erase).await.unwrap(),
            None
        );
        // erase from a server must never reach the local helper.
        assert!(fake.seen().is_empty());
    }
}
