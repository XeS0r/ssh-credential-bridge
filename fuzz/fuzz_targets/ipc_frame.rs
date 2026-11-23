//! IPC frames as read by the core from a (possibly compromised) worker or from ctl.
#![no_main]

use std::io::Cursor;

use credential_bridge_proto::ipc::{FromWorker, control, decode_body, git, gpg, read_frame, vault};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_body::<FromWorker<git::Response>>(data);
    let _ = decode_body::<FromWorker<vault::Response>>(data);
    let _ = decode_body::<FromWorker<gpg::Response>>(data);
    let _ = decode_body::<control::Request>(data);
    let mut reader = Cursor::new(data);
    while let Ok(Some(_)) = read_frame::<_, control::Request>(&mut reader) {}
});
