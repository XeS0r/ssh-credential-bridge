//! Extension payloads (`*@credential-bridge` and `query`), as requests from a server and
//! as replies on the remote side.
#![no_main]

use credential_bridge_proto::ext::{GitReply, GitRequest, GpgReply, GpgRequest, decode_query_reply};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = GitRequest::decode(data) {
        let again = GitRequest::decode(&request.encode().expect("decoded request encodes"));
        assert_eq!(again.as_ref(), Ok(&request));
    }
    if let Ok(reply) = GitReply::decode(data) {
        let again = GitReply::decode(&reply.encode().expect("decoded reply encodes"));
        assert_eq!(again.as_ref(), Ok(&reply));
    }
    if let Ok(request) = GpgRequest::decode(data) {
        assert_eq!(request.encode().as_deref().map(Vec::as_slice), Ok(data));
    }
    if let Ok(reply) = GpgReply::decode(data) {
        assert_eq!(reply.encode().as_deref().map(Vec::as_slice), Ok(data));
    }
    let _ = decode_query_reply(data);
});
