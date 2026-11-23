//! Agent frames from a server: framing, decoding and the raw-byte guarantee.
#![no_main]

use std::io::Cursor;

use credential_bridge_proto::agent::{MAX_MESSAGE_LEN, Message, read_frame};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // As a single payload: whatever decodes must re-encode byte for byte.
    if let Ok(message) = Message::decode(data) {
        assert_eq!(message.encode(), data);
        assert_eq!(message.msg_type(), data[0]);
    }
    // As a stream of frames.
    let mut reader = Cursor::new(data);
    while let Ok(Some(payload)) = read_frame(&mut reader) {
        assert!(!payload.is_empty() && payload.len() <= MAX_MESSAGE_LEN);
        if let Ok(message) = Message::decode(&payload) {
            assert_eq!(message.encode(), payload);
        }
    }
});
