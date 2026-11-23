//! `session-bind@openssh.com` contents from a client or a server: parsing and
//! verification must never panic, and nothing random may verify.
#![no_main]

use credential_bridge_proto::bind::{MAX_SESSION_ID_LEN, SessionBind};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(bind) = SessionBind::parse(data) {
        assert!((1..=MAX_SESSION_ID_LEN).contains(&bind.session_id.len()));
        let _ = bind.verify();
        let _ = bind.host_key_fingerprint();
    }
});
