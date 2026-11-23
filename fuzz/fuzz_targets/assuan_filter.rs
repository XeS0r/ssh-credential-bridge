//! The gpg tunnel as a server drives it: Assuan lines from the shim, the command filter,
//! the shim's framer and the worker's filter session, with gpg-agent's turns mixed in.
//!
//! Input: the first byte selects the policy; the rest is split at `0xFF` into chunks
//! that alternate between bytes from the server (client side of Assuan) and bytes from
//! gpg-agent (server side).
#![no_main]

use credential_bridge_gpg::GpgPolicy;
use credential_bridge_gpg::assuan::{ClientLine, parse_client_line, parse_server_line, unescape_data};
use credential_bridge_gpg::filter::{Verdict, check_command};
use credential_bridge_gpg::framing::{ClientFramer, Turn, TurnCollector, TurnEnd};
use credential_bridge_gpg::session::{FilterSession, SessionState, UnitAction};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else { return };
    let policy = GpgPolicy { sign: first & 1 != 0, decrypt: first & 2 != 0 };

    // The parsers on their own, line by line.
    for line in rest.split(|&b| b == b'\n') {
        if let Ok(ClientLine::Command { verb, args }) = parse_client_line(line) {
            let _ = check_command(&policy, verb, args);
        }
        if let Ok(ClientLine::Data(data)) = parse_client_line(line) {
            let _ = unescape_data(data);
        }
        let _ = parse_server_line(line);
    }
    let _ = Turn::parse(rest);

    // A whole tunnel: framer (shim) → session (worker) ← collector (gpg-agent).
    let mut framer = ClientFramer::new();
    let mut session = FilterSession::new(policy);
    let mut collector = TurnCollector::new();
    for (index, chunk) in rest.split(|&b| b == 0xFF).enumerate() {
        if index % 2 == 1 {
            // gpg-agent's side: the greeting first, then answers.
            let Ok(Some(turn)) = collector.push(chunk) else { continue };
            if session.server_turn(&turn).is_err() {
                return;
            }
            framer.turn_ended(turn.end == TurnEnd::Inquire);
            continue;
        }
        if framer.push(chunk).is_err() {
            return;
        }
        while let Ok(Some(unit)) = framer.next_unit() {
            let before = session.state();
            match session.client_unit(&unit) {
                Ok(UnitAction::Forward(forwarded)) => {
                    assert_eq!(*forwarded, *unit, "units are forwarded unchanged");
                    // Only an allowed command or an inquiry answer reaches gpg-agent.
                    if before == SessionState::Idle {
                        let line = &forwarded[..forwarded.len() - 1];
                        let Ok(ClientLine::Command { verb, args }) = parse_client_line(line) else {
                            panic!("forwarded a unit that is not a command");
                        };
                        assert_eq!(check_command(&policy, verb, args), Verdict::Allow);
                    } else {
                        assert_eq!(before, SessionState::Inquiring);
                    }
                    break;
                }
                Ok(UnitAction::Reply(_) | UnitAction::Deny(_)) => framer.turn_ended(false),
                Err(_) => return,
            }
        }
    }
});
