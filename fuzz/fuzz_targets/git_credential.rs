//! git credential text, as embedded in extension payloads.
#![no_main]

use credential_bridge_proto::credential::{Credential, CredentialError};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(credential) = Credential::parse(data) {
        match credential.to_bytes() {
            Ok(text) => assert_eq!(Credential::parse(&text), Ok(credential)),
            // Parsed values hold no newline or NUL, so only a trailing `\r` (which git
            // would strip) can be refused.
            Err(CredentialError::InvalidValue { .. }) => {}
            Err(error) => panic!("unexpected error {error:?}"),
        }
    }
});
