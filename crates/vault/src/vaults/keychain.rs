//! The macOS Keychain: generic password items (`keychain://service/account`) through
//! `security-framework`. The calls block (Keychain may ask the user to allow access), so
//! they run on tokio's blocking pool. Elsewhere every call is
//! [`VaultError::Unsupported`].

use credential_bridge_config::VaultKind;
use credential_bridge_proto::secret::Secret;

use crate::error::VaultError;

const VAULT: VaultKind = VaultKind::Keychain;

/// Whether the Keychain exists here, with a note for `ctl check`.
pub(super) fn available() -> (bool, Option<String>) {
    if cfg!(target_os = "macos") { (true, None) } else { (false, Some("macOS only".to_owned())) }
}

#[cfg(target_os = "macos")]
mod imp {
    use security_framework::passwords;
    use zeroize::Zeroize;

    use super::*;

    /// `errSecItemNotFound`.
    const ITEM_NOT_FOUND: i32 = -25300;
    /// `errSecInteractionNotAllowed`, `errSecAuthFailed`, `userCanceledErr`.
    const LOCKED: [i32; 3] = [-25308, -25293, -128];

    fn error(code: i32) -> VaultError {
        if LOCKED.contains(&code) {
            VaultError::LockedElsewhere {
                vault: VAULT,
                hint: "unlock the login keychain and allow credential-bridged to access the item".to_owned(),
            }
        } else {
            VaultError::ToolFailed { program: "keychain".to_owned(), detail: format!("OSStatus {code}") }
        }
    }

    fn join_error() -> VaultError {
        VaultError::ToolFailed {
            program: "keychain".to_owned(),
            detail: "the keychain call did not finish".to_owned(),
        }
    }

    pub(super) async fn read(service: &str, account: &str) -> Result<Option<Secret>, VaultError> {
        let (service, account) = (service.to_owned(), account.to_owned());
        let result = tokio::task::spawn_blocking(move || passwords::get_generic_password(&service, &account))
            .await
            .map_err(|_| join_error())?;
        match result {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(text) => Ok(Some(Secret::new(text))),
                Err(invalid) => {
                    invalid.into_bytes().zeroize();
                    Err(VaultError::ToolFailed {
                        program: "keychain".to_owned(),
                        detail: "the item is not UTF-8".to_owned(),
                    })
                }
            },
            Err(failure) if failure.code() == ITEM_NOT_FOUND => Ok(None),
            Err(failure) => Err(error(failure.code())),
        }
    }

    pub(super) async fn write(service: &str, account: &str, value: &Secret) -> Result<(), VaultError> {
        let (service, account, value) = (service.to_owned(), account.to_owned(), value.clone());
        let result = tokio::task::spawn_blocking(move || {
            passwords::set_generic_password(&service, &account, value.expose().as_bytes())
        })
        .await
        .map_err(|_| join_error())?;
        result.map_err(|failure| error(failure.code()))
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::*;

    fn unsupported() -> VaultError {
        VaultError::Unsupported { vault: VAULT, reason: "the Keychain exists on macOS only".to_owned() }
    }

    pub(super) async fn read(_service: &str, _account: &str) -> Result<Option<Secret>, VaultError> {
        Err(unsupported())
    }

    pub(super) async fn write(_service: &str, _account: &str, _value: &Secret) -> Result<(), VaultError> {
        Err(unsupported())
    }
}

/// Reads the generic password of `service` and `account`; `Ok(None)` if there is none.
pub(super) async fn read(service: &str, account: &str) -> Result<Option<Secret>, VaultError> {
    imp::read(service, account).await
}

/// Creates or updates the generic password of `service` and `account`.
pub(super) async fn write(service: &str, account: &str, value: &Secret) -> Result<(), VaultError> {
    imp::write(service, account, value).await
}
