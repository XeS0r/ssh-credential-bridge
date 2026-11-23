//! Property tests: round trips of every codec and robustness against arbitrary input.
//! They run on stable; the fuzz targets in `fuzz/` cover the same decoders with coverage
//! guidance.

use std::io::Cursor;

use credential_bridge_proto::agent::{self, Identity, MAX_MESSAGE_LEN, Message, msg_type};
use credential_bridge_proto::credential::Credential;
use credential_bridge_proto::ext::{
    self, GitAction, GitReply, GitRequest, GpgReply, GpgRequest, MAX_GPG_CHUNK,
};
use credential_bridge_proto::ipc::{self, control};
use credential_bridge_proto::{Secret, SecretBytes};
use proptest::collection::vec;
use proptest::prelude::*;

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..max)
}

/// A payload whose type byte is usually one the codec interprets.
fn agent_payload() -> impl Strategy<Value = Vec<u8>> {
    let msg_type = prop_oneof![5u8..=29, any::<u8>()];
    (msg_type, bytes(512)).prop_map(|(t, body)| [vec![t], body].concat())
}

fn message() -> impl Strategy<Value = Message> {
    let identity = (bytes(64), bytes(32)).prop_map(|(key_blob, comment)| Identity { key_blob, comment });
    prop_oneof![
        Just(Message::RequestIdentities),
        vec(identity, 0..4).prop_map(Message::IdentitiesAnswer),
        (bytes(64), bytes(128), any::<u32>()).prop_map(|(key_blob, data, flags)| Message::SignRequest {
            key_blob,
            data,
            flags
        }),
        bytes(128).prop_map(|signature| Message::SignResponse { signature }),
        (any::<bool>(), bytes(128)).prop_map(|(constrained, body)| Message::AddIdentity {
            constrained,
            body: SecretBytes::new(body)
        }),
        bytes(64).prop_map(|key_blob| Message::RemoveIdentity { key_blob }),
        Just(Message::RemoveAllIdentities),
        (any::<bool>(), bytes(64)).prop_map(|(constrained, body)| Message::AddSmartcardKey {
            constrained,
            body: SecretBytes::new(body)
        }),
        bytes(64).prop_map(|body| Message::RemoveSmartcardKey { body: SecretBytes::new(body) }),
        bytes(32).prop_map(|p| Message::Lock { passphrase: SecretBytes::new(p) }),
        bytes(32).prop_map(|p| Message::Unlock { passphrase: SecretBytes::new(p) }),
        ("[ -~]{0,40}", bytes(128)).prop_map(|(name, contents)| Message::Extension { name, contents }),
        bytes(128).prop_map(|contents| Message::Success { contents }),
        Just(Message::Failure),
        Just(Message::ExtensionFailure),
        (prop_oneof![0u8..5, 29u8..=255, Just(24u8)], bytes(128))
            .prop_map(|(msg_type, body)| Message::Other { msg_type, body }),
    ]
}

/// A credential value git can carry: no newline or NUL, and no trailing `\r` (git strips
/// it when reading).
fn value() -> impl Strategy<Value = String> {
    "[^\n\r\0]{0,20}(\r[^\n\r\0]{1,5})?"
}

fn credential() -> impl Strategy<Value = Credential> {
    (
        (
            proptest::option::of(value()),
            proptest::option::of(value()),
            proptest::option::of(value()),
            proptest::option::of(value()),
        ),
        proptest::option::of(value()),
        proptest::option::of(any::<u64>()),
        proptest::option::of(value()),
        vec("[^\n\r\0]{1,20}", 0..3),
    )
        .prop_map(|((protocol, host, path, username), password, expiry, refresh, wwwauth)| Credential {
            protocol,
            host,
            path,
            username,
            password: password.map(Secret::new),
            password_expiry_utc: expiry,
            oauth_refresh_token: refresh.map(Secret::new),
            wwwauth,
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn accepted_agent_payloads_reencode_exactly(payload in agent_payload()) {
        if let Ok(message) = Message::decode(&payload) {
            prop_assert_eq!(message.encode(), payload);
        }
    }

    #[test]
    fn agent_messages_round_trip(message in message()) {
        let payload = message.encode();
        prop_assert_eq!(payload[0], message.msg_type());
        let decoded = Message::decode(&payload).unwrap();
        prop_assert_eq!(decoded.encode(), payload.clone());
        // Unknown-type and non-interpreted shapes may decode to another variant (e.g.
        // `Other` with a known type byte); the bytes are what must survive.
        if !matches!(message, Message::Other { .. }) {
            prop_assert_eq!(decoded, message);
        }
    }

    #[test]
    fn agent_frames_round_trip(messages in vec(message(), 0..5)) {
        let stream: Vec<u8> = messages.iter().flat_map(Message::to_frame).collect();
        let mut reader = Cursor::new(stream);
        for message in &messages {
            let payload = agent::read_frame(&mut reader).unwrap().unwrap();
            prop_assert_eq!(payload, message.encode());
        }
        prop_assert!(agent::read_frame(&mut reader).unwrap().is_none());
    }

    #[test]
    fn arbitrary_agent_streams_never_panic(stream in bytes(1024)) {
        let mut reader = Cursor::new(stream);
        while let Ok(Some(payload)) = agent::read_frame(&mut reader) {
            prop_assert!(payload.len() <= MAX_MESSAGE_LEN);
            let _ = Message::decode(&payload);
        }
    }

    #[test]
    fn write_commands_follow_the_type_byte(payload in agent_payload()) {
        if let Ok(message) = Message::decode(&payload) {
            prop_assert_eq!(message.is_write_command(), (17..=26).contains(&payload[0]));
        }
    }

    #[test]
    fn credentials_round_trip(credential in credential()) {
        let text = credential.to_bytes().unwrap();
        prop_assert_eq!(Credential::parse(&text).unwrap(), credential);
    }

    #[test]
    fn parsed_credentials_are_stable(input in bytes(256)) {
        if let Ok(credential) = Credential::parse(&input) {
            let text = credential.to_bytes().unwrap();
            prop_assert_eq!(Credential::parse(&text).unwrap(), credential);
        }
    }

    #[test]
    fn git_messages_round_trip(credential in credential(), erase in any::<bool>(), message in "\\PC{0,40}") {
        let action = if erase { GitAction::Erase } else { GitAction::Get };
        let request = GitRequest { action, credential: credential.clone() };
        prop_assert_eq!(GitRequest::decode(&request.encode().unwrap()).unwrap(), request);
        for reply in [
            GitReply::Credential(credential),
            GitReply::NoMatch,
            GitReply::Denied(message.clone()),
            GitReply::Failed(message),
            GitReply::Erased,
        ] {
            prop_assert_eq!(GitReply::decode(&reply.encode().unwrap()).unwrap(), reply);
        }
    }

    #[test]
    fn gpg_messages_round_trip(data in bytes(2048), message in "\\PC{0,40}") {
        for request in [GpgRequest::Open, GpgRequest::Input(data.clone().into()), GpgRequest::Close] {
            prop_assert_eq!(GpgRequest::decode(&request.encode().unwrap()).unwrap(), request);
        }
        for reply in [GpgReply::Opened(data.clone().into()), GpgReply::Output(data.into()), GpgReply::Closed, GpgReply::Failed(message)] {
            prop_assert_eq!(GpgReply::decode(&reply.encode().unwrap()).unwrap(), reply);
        }
    }

    #[test]
    fn extension_decoders_are_consistent(version in prop_oneof![Just(ext::VERSION), any::<u8>()], code in 0u8..6, rest in bytes(256)) {
        let input = [vec![version, code], rest].concat();
        if let Ok(request) = GitRequest::decode(&input) {
            prop_assert_eq!(GitRequest::decode(&request.encode().unwrap()).unwrap(), request);
        }
        if let Ok(reply) = GitReply::decode(&input) {
            prop_assert_eq!(GitReply::decode(&reply.encode().unwrap()).unwrap(), reply);
        }
        // gpg payloads carry no normalised text: accepted input re-encodes exactly.
        if let Ok(request) = GpgRequest::decode(&input) {
            prop_assert_eq!(request.encode().unwrap().to_vec(), input.clone());
        }
        if let Ok(reply) = GpgReply::decode(&input) {
            prop_assert_eq!(reply.encode().unwrap().to_vec(), input.clone());
        }
        if version != ext::VERSION {
            prop_assert_eq!(GitRequest::decode(&input), Err(ext::ExtError::Version(version)));
        }
    }

    #[test]
    fn query_replies_round_trip(names in vec("[!-~]{1,40}", 0..6)) {
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        prop_assert_eq!(ext::decode_query_reply(&ext::encode_query_reply(&names)).unwrap(), names.clone());
        let response = ext::query_response(&names);
        prop_assert_eq!(response.msg_type(), msg_type::EXTENSION_RESPONSE);
    }

    #[test]
    fn query_reply_decoder_never_panics(contents in bytes(256)) {
        let _ = ext::decode_query_reply(&contents);
    }

    #[test]
    fn ipc_frames_round_trip(vault in "\\PC{0,20}", password in "\\PC{0,40}", ttl in proptest::option::of(any::<u64>())) {
        let request = control::Request::Unlock { vault, password: Secret::new(password), ttl_secs: ttl };
        let mut buf = Vec::new();
        ipc::write_frame(&mut buf, &request).unwrap();
        let back: control::Request = ipc::read_frame(&mut Cursor::new(buf)).unwrap().unwrap();
        prop_assert_eq!(back, request);
    }

    #[test]
    fn ipc_decoder_never_panics(body in bytes(256)) {
        let _ = ipc::decode_body::<control::Request>(&body);
        let _ = ipc::read_frame::<_, control::Response>(&mut Cursor::new(body));
    }
}

#[cfg(feature = "bind")]
proptest! {
    #[test]
    fn bind_parser_never_panics(contents in bytes(512)) {
        use credential_bridge_proto::bind::SessionBind;
        if let Ok(bind) = SessionBind::parse(&contents) {
            prop_assert!((1..=credential_bridge_proto::bind::MAX_SESSION_ID_LEN).contains(&bind.session_id.len()));
            let _ = bind.verify();
        }
    }
}

#[test]
fn gpg_chunk_limit_is_exact() {
    assert!(GpgRequest::Input(vec![0; MAX_GPG_CHUNK].into()).encode().is_ok());
    assert!(GpgRequest::Input(vec![0; MAX_GPG_CHUNK + 1].into()).encode().is_err());
}
