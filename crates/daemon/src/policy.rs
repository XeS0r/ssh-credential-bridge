//! Policy decisions (security rules 1-3, profiles, hops). Pure functions so they can be
//! tested exhaustively.

use credential_bridge_config::{Config, Profile};
use credential_bridge_proto::agent::{Message, msg_type};
use credential_bridge_proto::ext;

use crate::bind::ServerBind;

/// Which socket a connection came in on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketRole {
    /// `agent.sock`: local; all keys, write commands, never extensions.
    Local,
    /// `agent-forward.sock`: always a server; never write commands.
    Forward,
}

impl SocketRole {
    /// `local` or `forward`, for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            SocketRole::Local => "local",
            SocketRole::Forward => "forward",
        }
    }
}

/// Everything a decision depends on, for one request.
#[derive(Debug, Clone, Copy)]
pub struct RequestContext<'a> {
    /// The configuration snapshot of the connection.
    pub config: &'a Config,
    /// The socket.
    pub role: SocketRole,
    /// The `[server.*]` name if the server bind matched a pinned host key.
    pub server: Option<&'a str>,
    /// The profile in force on the forward socket: the server's, `profile.unregistered`
    /// for a host key without `[server.*]` entry, or `None` (nothing allowed) for a
    /// connection without server bind. Ignored on `agent.sock`.
    pub profile: Option<&'a Profile>,
    /// Whether the connection has a server bind (its first message was a verified
    /// `session-bind` with `is_forwarding = 1` from a local ssh client verified as
    /// OpenSSH 8.9 or later, forward socket only; later binds never make one), and if
    /// not, why.
    pub server_bind: ServerBind,
    /// Whether the connection serves a hop (an accepted forwarding bind that did not
    /// select the server).
    pub hop: bool,
    /// [`crate::core::Core::forget_count`], read before `locked`: a token made for this
    /// request is dropped from the git worker's cache if tokens were forgotten since
    /// ([`crate::extensions::resolve_token`]).
    pub forgets: u64,
    /// Whether the proxy is locked.
    pub locked: bool,
    /// The server as dialogs and every audit event name it
    /// ([`crate::connection::server_label`]).
    pub label: &'a str,
}

impl RequestContext<'_> {
    /// The server label for audit events and dialogs ([`RequestContext::label`]).
    pub fn server_label(&self) -> String {
        self.label.to_owned()
    }

    /// Why the bridge is hidden from this connection, or `None` if it is shown: on the
    /// forward socket, connections without server bind and hosts without `[server.*]`
    /// entry are answered as by an agent without the bridge (`query` and our extensions
    /// as unknown), so the server cannot tell that a bridge is there.
    pub fn hidden_reason(&self) -> Option<&'static str> {
        if self.role != SocketRole::Forward {
            return None;
        }
        unrecognised_reason(self.server_bind).or(self.server.is_none().then_some(UNREGISTERED))
    }
}

/// Why an unregistered host gets no tokens, no gpg and does not see the bridge.
pub const UNREGISTERED: &str = "the host is not registered (no [server.*] entry for its host key)";

/// What may happen with a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Handle it.
    Allow,
    /// Answer `SSH_AGENT_FAILURE` (an empty key list for `REQUEST_IDENTITIES`, as an
    /// agent without keys) and audit the reason.
    Refuse(&'static str),
}

/// Whether `name` is one of ours or the standard `query` (answered only on the forward
/// socket).
pub fn is_own_extension(name: &str) -> bool {
    name == ext::QUERY || name.ends_with("@credential-bridge")
}

/// Decides on an agent message (not on extension payloads):
///
/// - write commands: only on `agent.sock`; lock/unlock always allowed there;
/// - while locked: only `SSH_AGENTC_UNLOCK`;
/// - `session-bind@openssh.com`: always allowed (tracked separately);
/// - `query` and `*@credential-bridge` extensions: only on `agent-forward.sock`, and
///   only for a registered server ([`RequestContext::hidden_reason`]); `agent.sock`
///   answers no extension at all, and other extensions are refused on both;
/// - identities and sign requests: on the forward socket only with a profile that has
///   `ssh`, and from a hop only with `hops.ssh`;
/// - anything else (replies, unknown types): refused.
pub fn decide(ctx: &RequestContext<'_>, message: &Message) -> Decision {
    if let Message::Extension { name, .. } = message
        && name == ext::SESSION_BIND
    {
        return Decision::Allow;
    }
    if message.is_write_command() {
        return match ctx.role {
            SocketRole::Forward => Decision::Refuse("write command on the forward socket"),
            SocketRole::Local if matches!(message, Message::Unlock { .. } | Message::Lock { .. }) => {
                Decision::Allow
            }
            SocketRole::Local if ctx.locked => Decision::Refuse("proxy is locked"),
            SocketRole::Local => match message.msg_type() {
                // Type 24 is unused in the protocol.
                msg_type::ADD_IDENTITY..=msg_type::REMOVE_SMARTCARD_KEY
                | msg_type::ADD_ID_CONSTRAINED
                | msg_type::ADD_SMARTCARD_KEY_CONSTRAINED => Decision::Allow,
                _ => Decision::Refuse("unsupported message"),
            },
        };
    }
    if ctx.locked {
        return Decision::Refuse("proxy is locked");
    }
    match message {
        Message::Extension { name, .. } => match (ctx.role, is_own_extension(name)) {
            (SocketRole::Local, _) => Decision::Refuse("extension on the local socket"),
            (SocketRole::Forward, true) => match ctx.hidden_reason() {
                Some(reason) => Decision::Refuse(reason),
                None => Decision::Allow,
            },
            (SocketRole::Forward, false) => Decision::Refuse("unknown extension on the forward socket"),
        },
        Message::RequestIdentities | Message::SignRequest { .. } => match ctx.role {
            SocketRole::Local => Decision::Allow,
            SocketRole::Forward => ssh_allowed(ctx),
        },
        _ => Decision::Refuse("unsupported message"),
    }
}

/// Identities and signatures on the forward socket.
fn ssh_allowed(ctx: &RequestContext<'_>) -> Decision {
    let Some(profile) = ctx.profile else {
        return Decision::Refuse(
            unrecognised_reason(ctx.server_bind).unwrap_or("no profile for this server"),
        );
    };
    if profile.ssh.is_none() {
        return Decision::Refuse("profile allows no ssh keys");
    }
    if ctx.hop && !profile.hops.ssh {
        return Decision::Refuse("ssh from a hop is not allowed (hops.ssh)");
    }
    Decision::Allow
}

/// The checks git and gpg share: forward socket, a forwarding bind and a registered
/// server (rule 3).
fn extension_base<'a>(ctx: &RequestContext<'a>) -> Result<&'a Profile, &'static str> {
    if ctx.role != SocketRole::Forward {
        return Err("extension on the local socket");
    }
    if ctx.locked {
        return Err("proxy is locked");
    }
    if let Some(reason) = ctx.hidden_reason() {
        return Err(reason);
    }
    ctx.profile.ok_or("no profile for this server")
}

/// Why a connection without a server bind gets no tokens and no gpg; `None` with one.
pub fn unrecognised_reason(server_bind: ServerBind) -> Option<&'static str> {
    match server_bind {
        ServerBind::Verified => None,
        ServerBind::Missing => Some("no session-bind from the ssh client, so the server is not recognised"),
        ServerBind::Unrecognised => {
            Some("the session-bind was refused or not the first message, so the server is not recognised")
        }
        ServerBind::ClientNotVerified => {
            Some("the local ssh client is not OpenSSH 8.9 or later, so the server is not recognised")
        }
    }
}

/// Whether a git credential request may be served: forward socket, a forwarding bind,
/// a profile with git rules, and `hops.git` for hops.
pub fn allows_git(ctx: &RequestContext<'_>) -> Decision {
    let profile = match extension_base(ctx) {
        Ok(profile) => profile,
        Err(reason) => return Decision::Refuse(reason),
    };
    if profile.git.is_empty() {
        return Decision::Refuse("profile has no git rules");
    }
    if ctx.hop && !profile.hops.git {
        return Decision::Refuse("git from a hop is not allowed (hops.git)");
    }
    Decision::Allow
}

/// Whether a gpg tunnel may be opened: forward socket, a forwarding bind, a profile
/// with gpg rights, `[gpg]` configured, and `hops.gpg` for hops.
pub fn allows_gpg(ctx: &RequestContext<'_>) -> Decision {
    let profile = match extension_base(ctx) {
        Ok(profile) => profile,
        Err(reason) => return Decision::Refuse(reason),
    };
    if !profile.gpg.sign && !profile.gpg.decrypt {
        return Decision::Refuse("profile allows no gpg");
    }
    if ctx.config.gpg.is_none() {
        return Decision::Refuse("[gpg] is not configured");
    }
    if ctx.hop && !profile.hops.gpg {
        return Decision::Refuse("gpg from a hop is not allowed (hops.gpg)");
    }
    Decision::Allow
}

#[cfg(test)]
mod tests {
    use credential_bridge_config::{Confirm, GpgConfig, Hops, KeySelection, SocketSpec, SshPolicy};
    use credential_bridge_proto::ipc::gpg::GpgPolicy;
    use credential_bridge_proto::secret::SecretBytes;

    use super::*;

    fn profile(ssh: bool, git: bool, gpg: bool, hops: Hops) -> Profile {
        Profile {
            name: "p".into(),
            ssh: ssh.then_some(SshPolicy { keys: KeySelection::All, confirm: Confirm::Never }),
            gpg: GpgPolicy { sign: gpg, decrypt: false },
            hops,
            signing: None,
            git: if git {
                vec![credential_bridge_config::GitRule {
                    url: credential_bridge_config::UrlPattern::parse("https://github.com/*").unwrap(),
                    source: "github".into(),
                    permissions: Default::default(),
                    per: Default::default(),
                }]
            } else {
                vec![]
            },
        }
    }

    fn config(gpg: bool) -> Config {
        Config {
            gpg: gpg.then(|| GpgConfig { socket: SocketSpec::Gpgconf("agent-extra-socket".into()) }),
            ..Config::default()
        }
    }

    fn ctx<'a>(config: &'a Config, role: SocketRole, profile: Option<&'a Profile>) -> RequestContext<'a> {
        RequestContext {
            config,
            role,
            server: Some("build"),
            profile,
            server_bind: ServerBind::Verified,
            hop: false,
            forgets: 0,
            locked: false,
            label: "build",
        }
    }

    fn ext(name: &str) -> Message {
        Message::Extension { name: name.into(), contents: vec![] }
    }

    fn sign() -> Message {
        Message::SignRequest { key_blob: vec![1], data: vec![2], flags: 0 }
    }

    fn add() -> Message {
        Message::AddIdentity { constrained: false, body: SecretBytes::new(vec![1]) }
    }

    #[test]
    fn write_commands_only_locally() {
        let config = config(false);
        let p = profile(true, false, false, Hops::default());
        let local = ctx(&config, SocketRole::Local, None);
        let forward = ctx(&config, SocketRole::Forward, Some(&p));
        for message in [
            add(),
            Message::RemoveAllIdentities,
            Message::RemoveIdentity { key_blob: vec![1] },
            Message::Lock { passphrase: SecretBytes::new(vec![]) },
            Message::Unlock { passphrase: SecretBytes::new(vec![]) },
        ] {
            assert_eq!(decide(&local, &message), Decision::Allow, "{message:?}");
            assert!(matches!(decide(&forward, &message), Decision::Refuse(_)), "{message:?}");
        }
        let unused = Message::Other { msg_type: 24, body: vec![] };
        assert!(matches!(decide(&local, &unused), Decision::Refuse(_)));
        assert!(matches!(decide(&forward, &unused), Decision::Refuse(_)));
    }

    #[test]
    fn locked_allows_only_unlock() {
        let config = config(false);
        let p = profile(true, false, false, Hops::default());
        for role in [SocketRole::Local, SocketRole::Forward] {
            let mut c = ctx(&config, role, Some(&p));
            c.locked = true;
            for message in [Message::RequestIdentities, sign(), add(), ext("query"), ext("foo@bar")] {
                assert!(matches!(decide(&c, &message), Decision::Refuse(_)), "{role:?} {message:?}");
            }
            assert_eq!(decide(&c, &ext(ext::SESSION_BIND)), Decision::Allow);
            let unlock = Message::Unlock { passphrase: SecretBytes::new(vec![]) };
            let expected = if role == SocketRole::Local { Decision::Allow } else { decide(&c, &unlock) };
            assert_eq!(decide(&c, &unlock), expected);
            assert!(matches!(allows_git(&c), Decision::Refuse(_)));
        }
    }

    #[test]
    fn extensions_by_socket() {
        let config = config(false);
        let p = profile(true, true, false, Hops::default());
        let local = ctx(&config, SocketRole::Local, None);
        let forward = ctx(&config, SocketRole::Forward, Some(&p));
        for name in [ext::QUERY, ext::GIT_CREDENTIAL, ext::GPG_AGENT, "x@credential-bridge"] {
            assert!(matches!(decide(&local, &ext(name)), Decision::Refuse(_)), "{name}");
            assert_eq!(decide(&forward, &ext(name)), Decision::Allow, "{name}");
        }
        assert!(matches!(decide(&local, &ext("restrict-destination-v00@openssh.com")), Decision::Refuse(_)));
        assert!(matches!(
            decide(&forward, &ext("restrict-destination-v00@openssh.com")),
            Decision::Refuse(_)
        ));
        for role in [SocketRole::Local, SocketRole::Forward] {
            assert_eq!(decide(&ctx(&config, role, None), &ext(ext::SESSION_BIND)), Decision::Allow);
        }
    }

    #[test]
    fn the_bridge_is_hidden_from_unregistered_and_unrecognised_connections() {
        let config = config(true);
        let all = profile(true, true, true, Hops { ssh: true, git: true, gpg: true });
        let unregistered = Profile::unregistered();
        let mut c = ctx(&config, SocketRole::Forward, Some(&unregistered));
        c.server = None;
        assert_eq!(c.hidden_reason(), Some(UNREGISTERED));
        for name in [ext::QUERY, ext::GIT_CREDENTIAL, ext::GPG_AGENT] {
            assert_eq!(decide(&c, &ext(name)), Decision::Refuse(UNREGISTERED), "{name}");
        }
        // Even a profile that allowed everything would not help.
        c.profile = Some(&all);
        assert_eq!(allows_git(&c), Decision::Refuse(UNREGISTERED));
        assert_eq!(allows_gpg(&c), Decision::Refuse(UNREGISTERED));
        assert_eq!(decide(&c, &ext(ext::SESSION_BIND)), Decision::Allow);
        for state in [ServerBind::Missing, ServerBind::Unrecognised, ServerBind::ClientNotVerified] {
            let mut c = ctx(&config, SocketRole::Forward, None);
            c.server_bind = state;
            let reason = unrecognised_reason(state).unwrap();
            assert_eq!(c.hidden_reason(), Some(reason));
            assert_eq!(decide(&c, &ext(ext::QUERY)), Decision::Refuse(reason), "{state:?}");
        }
        // A registered server sees the bridge; agent.sock has no extensions anyway.
        assert_eq!(ctx(&config, SocketRole::Forward, Some(&all)).hidden_reason(), None);
        assert_eq!(ctx(&config, SocketRole::Local, None).hidden_reason(), None);
    }

    #[test]
    fn keys_on_the_forward_socket_follow_the_profile() {
        let config = config(false);
        let with_ssh = profile(true, false, false, Hops::default());
        let without_ssh = profile(false, false, false, Hops::default());
        let no_hop_ssh = profile(true, false, false, Hops { ssh: false, git: false, gpg: false });
        for message in [Message::RequestIdentities, sign()] {
            assert_eq!(decide(&ctx(&config, SocketRole::Local, None), &message), Decision::Allow);
            assert_eq!(
                decide(&ctx(&config, SocketRole::Forward, Some(&with_ssh)), &message),
                Decision::Allow
            );
            assert!(matches!(
                decide(&ctx(&config, SocketRole::Forward, None), &message),
                Decision::Refuse(_)
            ));
            assert!(matches!(
                decide(&ctx(&config, SocketRole::Forward, Some(&without_ssh)), &message),
                Decision::Refuse(_)
            ));
            let mut hop = ctx(&config, SocketRole::Forward, Some(&no_hop_ssh));
            assert_eq!(decide(&hop, &message), Decision::Allow);
            hop.hop = true;
            assert!(matches!(decide(&hop, &message), Decision::Refuse(_)));
            hop.profile = Some(&with_ssh);
            assert_eq!(decide(&hop, &message), Decision::Allow);
        }
        let reply = Message::Success { contents: vec![] };
        assert!(matches!(decide(&ctx(&config, SocketRole::Local, None), &reply), Decision::Refuse(_)));
    }

    #[test]
    fn git_needs_bind_profile_rules_and_hop_right() {
        let config = config(false);
        let git = profile(false, true, false, Hops::default());
        let no_git = profile(true, false, false, Hops::default());
        let hop_git = profile(false, true, false, Hops { ssh: true, git: true, gpg: false });
        assert_eq!(allows_git(&ctx(&config, SocketRole::Forward, Some(&git))), Decision::Allow);
        assert!(matches!(allows_git(&ctx(&config, SocketRole::Local, Some(&git))), Decision::Refuse(_)));
        assert!(matches!(allows_git(&ctx(&config, SocketRole::Forward, None)), Decision::Refuse(_)));
        assert!(matches!(allows_git(&ctx(&config, SocketRole::Forward, Some(&no_git))), Decision::Refuse(_)));
        let mut c = ctx(&config, SocketRole::Forward, Some(&git));
        c.server_bind = ServerBind::Missing;
        assert_eq!(
            allows_git(&c),
            Decision::Refuse("no session-bind from the ssh client, so the server is not recognised")
        );
        c.server_bind = ServerBind::Unrecognised;
        assert_eq!(
            allows_git(&c),
            Decision::Refuse(
                "the session-bind was refused or not the first message, so the server is not recognised"
            )
        );
        c.server_bind = ServerBind::ClientNotVerified;
        assert_eq!(
            allows_git(&c),
            Decision::Refuse(
                "the local ssh client is not OpenSSH 8.9 or later, so the server is not recognised"
            )
        );
        c.server_bind = ServerBind::Verified;
        c.hop = true;
        assert!(matches!(allows_git(&c), Decision::Refuse(_)));
        c.profile = Some(&hop_git);
        assert_eq!(allows_git(&c), Decision::Allow);
    }

    #[test]
    fn gpg_needs_rights_section_and_hop_right() {
        let with_gpg = config(true);
        let without_gpg = config(false);
        let gpg = profile(false, false, true, Hops::default());
        let no_gpg = profile(false, false, false, Hops::default());
        assert_eq!(allows_gpg(&ctx(&with_gpg, SocketRole::Forward, Some(&gpg))), Decision::Allow);
        assert!(matches!(
            allows_gpg(&ctx(&without_gpg, SocketRole::Forward, Some(&gpg))),
            Decision::Refuse(_)
        ));
        assert!(matches!(
            allows_gpg(&ctx(&with_gpg, SocketRole::Forward, Some(&no_gpg))),
            Decision::Refuse(_)
        ));
        assert!(matches!(allows_gpg(&ctx(&with_gpg, SocketRole::Local, Some(&gpg))), Decision::Refuse(_)));
        let mut c = ctx(&with_gpg, SocketRole::Forward, Some(&gpg));
        c.hop = true;
        assert!(matches!(allows_gpg(&c), Decision::Refuse(_)));
        c.hop = false;
        c.server_bind = ServerBind::Missing;
        assert_eq!(allows_gpg(&c), Decision::Refuse(unrecognised_reason(ServerBind::Missing).unwrap()));
        c.server_bind = ServerBind::Unrecognised;
        assert_eq!(allows_gpg(&c), Decision::Refuse(unrecognised_reason(ServerBind::Unrecognised).unwrap()));
        c.server_bind = ServerBind::ClientNotVerified;
        assert_eq!(
            allows_gpg(&c),
            Decision::Refuse(unrecognised_reason(ServerBind::ClientNotVerified).unwrap())
        );
    }
}
