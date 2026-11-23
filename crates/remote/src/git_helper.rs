//! `credential-bridge-remote git <action>`: the git credential helper.

use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;

use credential_bridge_proto::agent::ExtensionReply;
use credential_bridge_proto::credential::{Credential, MAX_CREDENTIAL_LEN};
use credential_bridge_proto::ext::{ExtError, GIT_CREDENTIAL, GitAction, GitReply, GitRequest};
use zeroize::Zeroizing;

use crate::agent;

/// Errors that make the helper print a message on stderr (git shows it). Stepping aside
/// is not an error.
#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    /// git's input is invalid.
    #[error("invalid input from git: {0}")]
    Input(#[from] credential_bridge_proto::credential::CredentialError),
    /// The proxy refused or failed; the message comes from the local daemon (e.g.
    /// `vault bitwarden is locked: run credential-bridge-ctl vault unlock bitwarden`).
    #[error("credential-bridge: {0}")]
    Bridge(String),
    /// Reading stdin or writing stdout failed.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

/// Shown when the proxy answers a git request with `SSH_AGENT_FAILURE`.
const REFUSED: &str = "the local proxy refused the request (see credential-bridge-ctl log on your machine)";
/// Shown when the proxy announced the extension but does not understand the request.
const VERSION_MISMATCH: &str = "the local proxy does not understand this request: \
     credential-bridge-remote and credential-bridged are different versions \
     (run credential-bridge-ctl server add again)";

/// Runs one helper invocation with `SSH_AUTH_SOCK` as `auth_sock`:
///
/// - `store`: reads and ignores stdin, prints nothing;
/// - `get` / `erase`: without `auth_sock`, without agent or without the extension
///   (`query`), prints nothing; otherwise sends the request and prints the credential
///   for `Credential`, nothing for `NoMatch`/`Erased`, and errors for `Denied`/`Failed`;
/// - any other action: prints nothing.
///
/// Only `username`, `password`, `password_expiry_utc` and `oauth_refresh_token` of a
/// returned credential are printed, so the proxy cannot redirect git to another host.
pub fn run<R: Read, W: Write>(
    action: &str,
    auth_sock: Option<&Path>,
    mut stdin: R,
    mut stdout: W,
) -> Result<(), HelperError> {
    let action = match action {
        "get" => GitAction::Get,
        "erase" => GitAction::Erase,
        // `store` and actions added to git later: consume the input, answer nothing.
        _ => {
            drain(&mut stdin)?;
            return Ok(());
        }
    };
    let input = read_input(&mut stdin)?;
    let Some(auth_sock) = auth_sock else {
        return Ok(());
    };
    let credential = Credential::parse(&input)?;
    drop(input);

    // No agent, a dead socket or an agent without our extension: step aside quietly.
    let Ok(mut client) = agent::connect(auth_sock) else {
        return Ok(());
    };
    match agent::extensions(&mut client) {
        Ok(names) if names.iter().any(|name| name == GIT_CREDENTIAL) => {}
        _ => return Ok(()),
    }

    let request = GitRequest { action, credential }
        .encode()
        .map(Zeroizing::new)
        .map_err(|error| HelperError::Bridge(format!("cannot encode the request: {error}")))?;
    let reply = match client.extension(GIT_CREDENTIAL, &request) {
        Ok(ExtensionReply::Success(contents)) => {
            match GitReply::decode(&contents) {
                Ok(reply) => reply,
                // Another protocol version: treat the proxy as absent.
                Err(ExtError::Version(_)) => return Ok(()),
                Err(error) => {
                    return Err(HelperError::Bridge(format!("invalid reply from the local proxy: {error}")));
                }
            }
        }
        Ok(ExtensionReply::Failure) => return Err(HelperError::Bridge(REFUSED.to_owned())),
        Ok(ExtensionReply::ExtensionFailure) => return Err(HelperError::Bridge(VERSION_MISMATCH.to_owned())),
        Err(error) => return Err(HelperError::Bridge(format!("no answer from the local proxy: {error}"))),
    };

    match reply {
        GitReply::Credential(returned) => {
            if action == GitAction::Get && returned.password.is_some() {
                let answer = Credential {
                    username: returned.username,
                    password: returned.password,
                    password_expiry_utc: returned.password_expiry_utc,
                    oauth_refresh_token: returned.oauth_refresh_token,
                    ..Credential::default()
                };
                answer.write_to(&mut stdout)?;
                stdout.flush()?;
            }
            Ok(())
        }
        GitReply::NoMatch | GitReply::Erased => Ok(()),
        GitReply::Denied(message) | GitReply::Failed(message) => {
            Err(HelperError::Bridge(printable(&message)))
        }
    }
}

/// Reads git's input, at most one byte more than a credential may have (so an oversized
/// input is rejected by the parser instead of being read without bound).
fn read_input<R: Read>(stdin: &mut R) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut input = Zeroizing::new(Vec::with_capacity(MAX_CREDENTIAL_LEN + 1));
    stdin.take(MAX_CREDENTIAL_LEN as u64 + 1).read_to_end(&mut input)?;
    Ok(input)
}

/// Reads and discards everything (the input of `store` contains a password).
fn drain<R: Read>(stdin: &mut R) -> io::Result<()> {
    let mut buf = Zeroizing::new([0u8; 4096]);
    loop {
        match stdin.read(&mut buf[..]) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// A message from the proxy as one printable line: control characters become spaces,
/// so a message cannot move the cursor or fake further lines in git's output.
fn printable(message: &str) -> String {
    message.chars().map(|c| if c.is_control() { ' ' } else { c }).collect::<String>().trim().to_owned()
}

/// Entry point: [`run`] with the process's stdin, stdout and `SSH_AUTH_SOCK`. Errors are
/// printed; the exit code is 0 even then, so git continues with other helpers.
pub fn main(action: &str) -> ExitCode {
    let auth_sock = agent::auth_sock_from_env();
    let result = run(action, auth_sock.as_deref(), io::stdin().lock(), io::stdout().lock());
    match result {
        Ok(()) => {}
        Err(error @ HelperError::Bridge(_)) => eprintln!("{error}"),
        Err(error) => eprintln!("credential-bridge-remote: {error}"),
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use credential_bridge_proto::Secret;
    use credential_bridge_proto::agent::Message;
    use credential_bridge_proto::ext::{GPG_AGENT, VERSION};

    use super::*;
    use crate::testutil::{FakeAgent, extension_contents, query_only, query_reply};

    const INPUT: &[u8] = b"protocol=https\nhost=github.com\npath=my-org/app.git\n\n";

    /// A bridge that answers git requests with `reply` (given the decoded request).
    fn bridge(reply: impl Fn(&GitRequest) -> GitReply + Send + Sync + 'static) -> FakeAgent {
        FakeAgent::start(move |request| {
            if let Some(answer) = query_reply(request, &[GIT_CREDENTIAL, GPG_AGENT]) {
                return answer;
            }
            match extension_contents(request, GIT_CREDENTIAL) {
                Some(contents) => {
                    let request = GitRequest::decode(contents).unwrap();
                    Message::Success { contents: reply(&request).encode().unwrap() }
                }
                None => Message::Failure,
            }
        })
    }

    fn token() -> Credential {
        Credential {
            protocol: Some("https".into()),
            host: Some("evil.example.com".into()),
            username: Some("x-access-token".into()),
            password: Some(Secret::new("ghs_token".into())),
            password_expiry_utc: Some(1_900_000_000),
            ..Credential::default()
        }
    }

    fn run_helper(action: &str, agent: Option<&Path>) -> (Result<(), HelperError>, String) {
        let mut out = Vec::new();
        let result = run(action, agent, INPUT, &mut out);
        (result, String::from_utf8(out).unwrap())
    }

    #[test]
    fn get_prints_the_credential() {
        let agent = bridge(|request| {
            assert_eq!(request.action, GitAction::Get);
            assert_eq!(request.credential.host.as_deref(), Some("github.com"));
            assert_eq!(request.credential.path.as_deref(), Some("my-org/app.git"));
            GitReply::Credential(token())
        });
        let (result, out) = run_helper("get", Some(agent.path()));
        result.unwrap();
        // Only the answer attributes; never protocol or host from the proxy.
        assert_eq!(out, "username=x-access-token\npassword=ghs_token\npassword_expiry_utc=1900000000\n");
    }

    #[test]
    fn no_match_prints_nothing() {
        let agent = bridge(|_| GitReply::NoMatch);
        let (result, out) = run_helper("get", Some(agent.path()));
        result.unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn failure_message_reaches_git() {
        let message = "vault bitwarden is locked: run credential-bridge-ctl vault unlock bitwarden";
        let agent = bridge(move |_| GitReply::Failed(message.into()));
        let (result, out) = run_helper("get", Some(agent.path()));
        assert_eq!(out, "");
        let error = result.unwrap_err();
        assert_eq!(error.to_string(), format!("credential-bridge: {message}"));
    }

    #[test]
    fn denied_message_is_one_line() {
        let agent = bridge(|_| GitReply::Denied("no tokens\nfor hops\x1b[2J".into()));
        let (result, _) = run_helper("get", Some(agent.path()));
        assert_eq!(result.unwrap_err().to_string(), "credential-bridge: no tokens for hops [2J");
    }

    #[test]
    fn erase_is_forwarded() {
        let agent = bridge(|request| {
            assert_eq!(request.action, GitAction::Erase);
            GitReply::Erased
        });
        let (result, out) = run_helper("erase", Some(agent.path()));
        result.unwrap();
        assert_eq!(out, "");
        assert_eq!(agent.requests().len(), 2, "query and erase");
    }

    #[test]
    fn store_is_ignored() {
        let agent = bridge(|_| panic!("store must not reach the proxy"));
        let (result, out) = run_helper("store", Some(agent.path()));
        result.unwrap();
        assert_eq!(out, "");
        assert_eq!(agent.connections(), 0);
    }

    #[test]
    fn unknown_action_is_ignored() {
        let (result, out) = run_helper("capabilities", None);
        result.unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn steps_aside_without_agent() {
        let (result, out) = run_helper("get", None);
        result.unwrap();
        assert_eq!(out, "");

        let dir = tempfile::tempdir().unwrap();
        let (result, out) = run_helper("get", Some(&dir.path().join("dead.sock")));
        result.unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn steps_aside_for_a_plain_agent() {
        let agent = FakeAgent::start(query_only(&["session-bind@openssh.com"]));
        let (result, out) = run_helper("get", Some(agent.path()));
        result.unwrap();
        assert_eq!(out, "");
        assert_eq!(agent.requests().len(), 1, "only query");
    }

    /// OpenSSH's ssh-agent answers `query` with `SSH_AGENT_FAILURE`, and so does the
    /// bridge towards a host without `[server.*]` entry: step aside without a word.
    #[test]
    fn steps_aside_when_query_fails() {
        let agent = FakeAgent::start(|_: &Message| Message::Failure);
        let (result, out) = run_helper("get", Some(agent.path()));
        result.unwrap();
        assert_eq!(out, "");
        assert_eq!(agent.requests().len(), 1, "only query");
    }

    #[test]
    fn steps_aside_for_another_version() {
        let agent = FakeAgent::start(|request| {
            query_reply(request, &[GIT_CREDENTIAL])
                .unwrap_or(Message::Success { contents: vec![VERSION + 1, 0, 0, 0, 0, 0] })
        });
        let (result, out) = run_helper("get", Some(agent.path()));
        result.unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn refusal_is_reported() {
        let agent = FakeAgent::start(query_only(&[GIT_CREDENTIAL]));
        let (result, _) = run_helper("get", Some(agent.path()));
        assert!(result.unwrap_err().to_string().contains("refused"));
    }

    #[test]
    fn invalid_input_is_reported() {
        let agent = bridge(|_| GitReply::NoMatch);
        let mut out = Vec::new();
        let error = run("get", Some(agent.path()), &b"no equals sign\n"[..], &mut out).unwrap_err();
        assert!(matches!(error, HelperError::Input(_)));
    }
}
