//! Scripted Assuan conversations through the whole bridge logic: gpg's bytes are cut
//! into units by the shim's `ClientFramer`, filtered by the worker's `FilterSession`,
//! answered by a fake gpg-agent on a real Unix socket, and collected into turns by the
//! `TurnCollector`.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::thread;

use credential_bridge_gpg::GpgPolicy;
use credential_bridge_gpg::framing::{ClientFramer, Turn, TurnCollector, TurnEnd};
use credential_bridge_gpg::session::{FilterSession, SessionState, UnitAction};

/// A fake gpg-agent: sends the greeting, then for every expected line it reads, writes
/// the scripted answer. Returns every line it received.
fn fake_agent(
    stream: UnixStream,
    script: Vec<(&'static str, &'static str)>,
) -> thread::JoinHandle<Vec<String>> {
    thread::spawn(move || {
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        writer.write_all(b"OK Pleased to meet you, process 4711\n").unwrap();
        let mut seen = Vec::new();
        for (expect, answer) in script {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line, expect, "fake agent got an unexpected line");
            seen.push(line);
            writer.write_all(answer.as_bytes()).unwrap();
        }
        // Nothing more may arrive.
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "fake agent got extra bytes: {:?}", String::from_utf8_lossy(&rest));
        seen
    })
}

/// Reads one turn from the agent connection.
fn read_turn(agent: &mut UnixStream, collector: &mut TurnCollector) -> Turn {
    if let Some(turn) = collector.push(b"").unwrap() {
        return turn;
    }
    let mut buf = [0u8; 7]; // small reads exercise reassembly
    loop {
        let n = agent.read(&mut buf).unwrap();
        assert!(n > 0, "agent closed early");
        if let Some(turn) = collector.push(&buf[..n]).unwrap() {
            return turn;
        }
    }
}

/// Runs gpg's input through shim and worker logic against `agent`; returns what gpg
/// would read back.
fn run(policy: GpgPolicy, gpg_input: &[u8], mut agent: UnixStream) -> (Vec<u8>, SessionState) {
    let mut collector = TurnCollector::new();
    let mut session = FilterSession::new(policy);
    let mut framer = ClientFramer::new();
    let greeting = read_turn(&mut agent, &mut collector);
    session.server_turn(&greeting).unwrap();
    let mut to_gpg = greeting.bytes.to_vec();

    for chunk in gpg_input.chunks(5) {
        framer.push(chunk).unwrap();
        while let Some(unit) = framer.next_unit().unwrap() {
            // This is where the shim sends GpgRequest::Input and the worker answers.
            let turn = match session.client_unit(&unit).unwrap() {
                UnitAction::Forward(bytes) => {
                    agent.write_all(&bytes).unwrap();
                    let turn = read_turn(&mut agent, &mut collector);
                    session.server_turn(&turn).unwrap();
                    turn
                }
                UnitAction::Reply(bytes) | UnitAction::Deny(bytes) => Turn::parse(&bytes).unwrap(),
            };
            // Back in the shim: the reply is re-parsed before it goes to gpg.
            let turn = Turn::parse(&turn.bytes).unwrap();
            framer.turn_ended(turn.end == TurnEnd::Inquire);
            to_gpg.extend_from_slice(&turn.bytes);
        }
    }
    assert!(!framer.has_partial());
    assert!(!collector.has_partial());
    (to_gpg, session.state())
}

#[test]
fn sign_with_pinentry_inquiry() {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let agent = fake_agent(
        theirs,
        vec![
            ("RESET\n", "OK\n"),
            ("OPTION agent-awareness=2.1.0\n", "OK\n"),
            ("SIGKEY 0123456789ABCDEF0123456789ABCDEF01234567\n", "OK\n"),
            ("SETKEYDESC Please+enter+the+passphrase\n", "OK\n"),
            ("SETHASH 8 9F86D081884C7D659A2FEAA0C55AD015\n", "OK\n"),
            ("PKSIGN\n", "S PROGRESS x\nINQUIRE PINENTRY_LAUNCHED 4711 gtk2 1.2.1 - - -\n"),
            ("END\n", "D (7:sig-val(3:rsa(1:s4:%25%0A%0D)))\nOK\n"),
            ("BYE\n", "OK closing connection\n"),
        ],
    );
    let gpg = b"RESET\n\
OPTION ttyname=/dev/pts/7\n\
OPTION display=:0\n\
OPTION agent-awareness=2.1.0\n\
# a comment gpg-agent would ignore\n\
SIGKEY 0123456789ABCDEF0123456789ABCDEF01234567\n\
SETKEYDESC Please+enter+the+passphrase\n\
SETHASH 8 9F86D081884C7D659A2FEAA0C55AD015\n\
PKSIGN\n\
END\n\
BYE\n";
    let (to_gpg, state) = run(GpgPolicy { sign: true, decrypt: false }, gpg, ours);
    assert_eq!(state, SessionState::Closed);
    agent.join().unwrap();
    assert_eq!(
        String::from_utf8(to_gpg).unwrap(),
        "OK Pleased to meet you, process 4711\n\
OK\n\
OK\n\
OK\n\
OK\n\
OK\n\
OK\n\
OK\n\
S PROGRESS x\nINQUIRE PINENTRY_LAUNCHED 4711 gtk2 1.2.1 - - -\n\
D (7:sig-val(3:rsa(1:s4:%25%0A%0D)))\nOK\n\
OK closing connection\n"
    );
}

#[test]
fn decrypt_with_ciphertext_inquiry() {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let agent = fake_agent(
        theirs,
        vec![
            ("SETKEY 0123\n", "OK\n"),
            ("PKDECRYPT\n", "S INQUIRE_MAXLEN 4096\nINQUIRE CIPHERTEXT\n"),
            ("D (7:enc-val(3:rsa(1:a3:%25%0A)))\n", ""),
            ("END\n", "S PADDING 0\nD (5:value5:hello)\nOK\n"),
        ],
    );
    let gpg = b"SETKEY 0123\nPKDECRYPT\nD (7:enc-val(3:rsa(1:a3:%25%0A)))\nEND\n";
    let (to_gpg, state) = run(GpgPolicy { sign: true, decrypt: true }, gpg, ours);
    assert_eq!(state, SessionState::Idle);
    let to_gpg = String::from_utf8(to_gpg).unwrap();
    assert!(to_gpg.ends_with("INQUIRE CIPHERTEXT\nS PADDING 0\nD (5:value5:hello)\nOK\n"));
    agent.join().unwrap();
}

#[test]
fn forbidden_commands_never_reach_the_agent() {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let agent = fake_agent(theirs, vec![("HAVEKEY ABC\n", "OK\n"), ("GETINFO version\n", "D 2.4.5\nOK\n")]);
    let gpg = b"HAVEKEY ABC\n\
PKDECRYPT\n\
EXPORT_KEY ABC\n\
SCD SERIALNO\n\
PRESET_PASSPHRASE ABC -1 41\n\
GET_PASSPHRASE --data x\n\
READKEY ABC\n\
GETINFO version\n";
    let (to_gpg, _) = run(GpgPolicy { sign: true, decrypt: false }, gpg, ours);
    agent.join().unwrap();
    let to_gpg = String::from_utf8(to_gpg).unwrap();
    let lines: Vec<&str> = to_gpg.lines().collect();
    assert_eq!(lines[1], "OK");
    for line in &lines[2..8] {
        assert!(line.starts_with("ERR 67109115 Forbidden <credential-bridge: "), "{line}");
    }
    assert!(lines[2].contains("PKDECRYPT not allowed by the profile"));
    assert!(lines[3].contains("EXPORT_KEY always blocked"));
    assert!(lines[7].contains("READKEY not on the allowlist"));
    assert_eq!(&lines[8..], ["D 2.4.5", "OK"]);
}

#[test]
fn malicious_shim_units_are_rejected() {
    // The worker must not trust the shim's framing: units are re-checked.
    let mut session = FilterSession::new(GpgPolicy { sign: true, decrypt: true });
    session.server_turn(&Turn::parse(b"OK hi\n").unwrap()).unwrap();
    for unit in
        [b"NOP\nEXPORT_KEY x\n".as_slice(), b"D smuggled\nEND\n", b"PKSIGN", b"\xff\xfe\n", &[b'A'; 2000]]
    {
        assert!(session.client_unit(unit).is_err(), "{unit:?}");
    }
    assert_eq!(session.state(), SessionState::Idle);
}
