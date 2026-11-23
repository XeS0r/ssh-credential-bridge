//! The worker-side state machine for one tunnel: filters client units and pairs them
//! with server turns.

use crate::GpgError;
use crate::GpgPolicy;
use crate::assuan::{ClientLine, ERR_FORBIDDEN, err_line, ok_line, parse_client_line};
use crate::filter::{Verdict, check_command};
use crate::framing::{Turn, TurnEnd};

/// Where the tunnel is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Waiting for gpg-agent's greeting.
    Greeting,
    /// Waiting for a client command.
    Idle,
    /// A command was forwarded; waiting for its turn.
    AwaitingTurn,
    /// The last turn ended with `INQUIRE`; waiting for the inquiry answer.
    Inquiring,
    /// `BYE` was sent or an error ended the tunnel.
    Closed,
}

/// What to do with a client unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitAction {
    /// Write these bytes to gpg-agent, then collect a turn. Wiped when dropped: an
    /// inquiry answer may hold a secret.
    Forward(zeroize::Zeroizing<Vec<u8>>),
    /// Do not contact gpg-agent; send these bytes back as the turn (`OK` for an option
    /// answered locally).
    Reply(Vec<u8>),
    /// The filter denied the command: send these bytes (its `ERR` line) back as the turn.
    Deny(Vec<u8>),
}

/// The verb of a command unit as the audit log shows it, upper case. `None` for an
/// inquiry answer or anything that is not a command line. Parsed with
/// [`parse_client_line`], as the filter parses it, so the verb is a short word of ASCII
/// letters, digits, `_` and `-`.
pub fn command_verb(unit: &[u8]) -> Option<String> {
    let line = unit.split(|&b| b == b'\n').next()?;
    match parse_client_line(line).ok()? {
        ClientLine::Command { verb, .. } => Some(verb.to_ascii_uppercase()),
        _ => None,
    }
}

/// One tunnel's filter state.
#[derive(Debug, Clone)]
pub struct FilterSession {
    /// The profile's rights.
    policy: GpgPolicy,
    /// Current state.
    state: SessionState,
    /// Whether the forwarded command is `BYE`, so its `OK` closes the tunnel.
    bye_pending: bool,
}

impl FilterSession {
    /// A new tunnel in state [`SessionState::Greeting`].
    pub fn new(policy: GpgPolicy) -> Self {
        Self { policy, state: SessionState::Greeting, bye_pending: false }
    }

    /// Decides on a client unit.
    ///
    /// Errors: [`GpgError::Protocol`] if the unit does not fit the state (a command
    /// while inquiring, data while idle, anything while awaiting a turn or closed).
    pub fn client_unit(&mut self, unit: &[u8]) -> Result<UnitAction, GpgError> {
        match self.state {
            SessionState::Idle => self.command_unit(unit),
            SessionState::Inquiring => self.inquiry_unit(unit),
            SessionState::Greeting => Err(GpgError::Protocol("input before the greeting")),
            SessionState::AwaitingTurn => Err(GpgError::Protocol("input while a reply is pending")),
            SessionState::Closed => Err(GpgError::Protocol("input after the tunnel closed")),
        }
    }

    /// A unit in state [`SessionState::Idle`]: exactly one command line.
    fn command_unit(&mut self, unit: &[u8]) -> Result<UnitAction, GpgError> {
        let line = unit.strip_suffix(b"\n").ok_or(GpgError::Malformed("unit without final LF"))?;
        if line.contains(&b'\n') {
            return Err(GpgError::Protocol("more than one command in a unit"));
        }
        let ClientLine::Command { verb, args } = parse_client_line(line)? else {
            return Err(GpgError::Protocol("expected a command"));
        };
        match check_command(&self.policy, verb, args) {
            Verdict::Allow => {
                self.bye_pending = verb.eq_ignore_ascii_case("BYE");
                self.state = SessionState::AwaitingTurn;
                Ok(UnitAction::Forward(zeroize::Zeroizing::new(unit.to_vec())))
            }
            Verdict::AnswerOk => Ok(UnitAction::Reply(ok_line())),
            Verdict::Deny(reason) => {
                let verb = verb.to_ascii_uppercase();
                let text = format!("Forbidden <credential-bridge: {verb} {}>", reason.describe());
                Ok(UnitAction::Deny(err_line(ERR_FORBIDDEN, &text)))
            }
        }
    }

    /// A unit in state [`SessionState::Inquiring`]: `D` lines, then `END` or `CAN` as
    /// the last line.
    fn inquiry_unit(&mut self, unit: &[u8]) -> Result<UnitAction, GpgError> {
        let body = unit.strip_suffix(b"\n").ok_or(GpgError::Malformed("unit without final LF"))?;
        let mut lines = body.split(|&b| b == b'\n').peekable();
        while let Some(line) = lines.next() {
            let last = lines.peek().is_none();
            match (parse_client_line(line)?, last) {
                (ClientLine::Data(_), false) => {}
                (ClientLine::End | ClientLine::Cancel, true) => {}
                _ => return Err(GpgError::Protocol("inquiry answer must be D lines and END or CAN")),
            }
        }
        self.state = SessionState::AwaitingTurn;
        Ok(UnitAction::Forward(zeroize::Zeroizing::new(unit.to_vec())))
    }

    /// Records a server turn (the greeting first) and advances the state.
    ///
    /// Errors: [`GpgError::Protocol`] for a turn nobody waits for, or an `INQUIRE` as
    /// the greeting.
    pub fn server_turn(&mut self, turn: &Turn) -> Result<(), GpgError> {
        self.state = match (self.state, turn.end) {
            (SessionState::Greeting, TurnEnd::Ok) => SessionState::Idle,
            (SessionState::Greeting, TurnEnd::Err) => SessionState::Closed,
            (SessionState::Greeting, TurnEnd::Inquire) => {
                self.state = SessionState::Closed;
                return Err(GpgError::Protocol("INQUIRE as greeting"));
            }
            (SessionState::AwaitingTurn, TurnEnd::Inquire) => SessionState::Inquiring,
            (SessionState::AwaitingTurn, TurnEnd::Ok) if self.bye_pending => SessionState::Closed,
            (SessionState::AwaitingTurn, TurnEnd::Ok | TurnEnd::Err) => SessionState::Idle,
            _ => {
                self.state = SessionState::Closed;
                return Err(GpgError::Protocol("server turn without a pending command"));
            }
        };
        self.bye_pending = false;
        Ok(())
    }

    /// The current state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// The policy in force.
    pub fn policy(&self) -> GpgPolicy {
        self.policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::TurnCollector;

    fn turn(bytes: &[u8]) -> Turn {
        TurnCollector::new().push(bytes).unwrap().unwrap()
    }

    fn open(policy: GpgPolicy) -> FilterSession {
        let mut session = FilterSession::new(policy);
        assert_eq!(session.state(), SessionState::Greeting);
        assert!(session.client_unit(b"NOP\n").is_err());
        session.server_turn(&turn(b"OK Pleased to meet you\n")).unwrap();
        assert_eq!(session.state(), SessionState::Idle);
        session
    }

    const SIGN: GpgPolicy = GpgPolicy { sign: true, decrypt: false };

    #[test]
    fn forwards_allowed_commands() {
        let mut session = open(SIGN);
        assert_eq!(
            session.client_unit(b"SIGKEY ABC\n").unwrap(),
            UnitAction::Forward(b"SIGKEY ABC\n".to_vec().into())
        );
        assert_eq!(session.state(), SessionState::AwaitingTurn);
        assert!(matches!(session.client_unit(b"NOP\n"), Err(GpgError::Protocol(_))));
        session.server_turn(&turn(b"OK\n")).unwrap();
        assert_eq!(session.state(), SessionState::Idle);
        assert_eq!(session.policy(), SIGN);
    }

    #[test]
    fn denies_locally() {
        let mut session = open(SIGN);
        let UnitAction::Deny(reply) = session.client_unit(b"pkdecrypt\n").unwrap() else { panic!() };
        assert!(reply.starts_with(b"ERR 67109115 Forbidden <credential-bridge: PKDECRYPT not allowed"));
        assert_eq!(session.state(), SessionState::Idle);
        let UnitAction::Deny(reply) = session.client_unit(b"SCD SERIALNO\n").unwrap() else { panic!() };
        assert!(reply.starts_with(b"ERR 67109115 "));
        assert_eq!(session.client_unit(b"OPTION display=:0\n").unwrap(), UnitAction::Reply(b"OK\n".to_vec()));
        assert_eq!(session.state(), SessionState::Idle);
    }

    #[test]
    fn verbs_for_the_audit_log() {
        assert_eq!(command_verb(b"PKSIGN\n").as_deref(), Some("PKSIGN"));
        assert_eq!(command_verb(b"getinfo version\n").as_deref(), Some("GETINFO"));
        // libassuan separates the verb with a tab too.
        assert_eq!(command_verb(b"option\tdisplay=:0\n").as_deref(), Some("OPTION"));
        assert_eq!(command_verb(b"D abc\nEND\n"), None);
        assert_eq!(command_verb(b"END\n"), None);
        assert_eq!(command_verb(b"CAN\n"), None);
        assert_eq!(command_verb(b"# comment\n"), None);
        assert_eq!(command_verb(b"\n"), None);
        // Not a valid verb for the filter either.
        let long = format!("{}\n", "X".repeat(100));
        assert_eq!(command_verb(long.as_bytes()), None);
    }

    #[test]
    fn inquiry_round_trip() {
        let mut session = open(GpgPolicy { sign: true, decrypt: true });
        session.client_unit(b"PKDECRYPT\n").unwrap();
        session.server_turn(&turn(b"S INQUIRE_MAXLEN 4096\nINQUIRE CIPHERTEXT\n")).unwrap();
        assert_eq!(session.state(), SessionState::Inquiring);
        assert!(matches!(session.client_unit(b"PKSIGN\n"), Err(GpgError::Protocol(_))));
        assert!(matches!(session.client_unit(b"D x\n"), Err(GpgError::Protocol(_))));
        assert!(matches!(session.client_unit(b"END\nD x\n"), Err(GpgError::Protocol(_))));
        assert!(matches!(session.client_unit(b"D x\nRESET\nEND\n"), Err(GpgError::Protocol(_))));
        let answer = b"D (7:enc-val\nD )\nEND\n";
        assert_eq!(session.client_unit(answer).unwrap(), UnitAction::Forward(answer.to_vec().into()));
        session.server_turn(&turn(b"D (5:value)\nOK\n")).unwrap();
        assert_eq!(session.state(), SessionState::Idle);

        session.client_unit(b"PKSIGN\n").unwrap();
        session.server_turn(&turn(b"INQUIRE PINENTRY_LAUNCHED 1 tty 1.0\n")).unwrap();
        assert_eq!(session.client_unit(b"CAN\n").unwrap(), UnitAction::Forward(b"CAN\n".to_vec().into()));
        session.server_turn(&turn(b"ERR 99 Canceled\n")).unwrap();
        assert_eq!(session.state(), SessionState::Idle);
    }

    #[test]
    fn rejects_bad_units() {
        let mut session = open(SIGN);
        for unit in [b"RESET".as_slice(), b"RESET\nNOP\n", b"D x\n", b"END\n", b"\n", b"# c\n"] {
            assert!(session.client_unit(unit).is_err(), "{unit:?}");
            assert_eq!(session.state(), SessionState::Idle);
        }
    }

    #[test]
    fn bye_closes() {
        let mut session = open(SIGN);
        session.client_unit(b"BYE\n").unwrap();
        session.server_turn(&turn(b"OK closing connection\n")).unwrap();
        assert_eq!(session.state(), SessionState::Closed);
        assert!(session.client_unit(b"NOP\n").is_err());
    }

    #[test]
    fn unexpected_turns() {
        let mut session = open(SIGN);
        assert!(session.server_turn(&turn(b"OK\n")).is_err());
        assert_eq!(session.state(), SessionState::Closed);

        let mut session = FilterSession::new(SIGN);
        session.server_turn(&turn(b"ERR 1 no\n")).unwrap();
        assert_eq!(session.state(), SessionState::Closed);

        let mut session = FilterSession::new(SIGN);
        assert!(session.server_turn(&turn(b"INQUIRE X\n")).is_err());
    }
}
