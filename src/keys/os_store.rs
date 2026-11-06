//! Thin adapter to maintained OS-store libraries. No fallback store or global
//! backend registration: tests cannot replace a production store accidentally.
use super::DataKey;
use crate::{Error, Result};
use keyring_core::{Entry, Error as StoreError};
use zeroize::Zeroizing;

const SERVICE: &str = "dns-guard.instance-key.v1";

pub(super) fn create() -> Result<String> {
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|_| Error::new("OS identifier generation failed"))?;
    let id = hex::encode(id);
    save_new(&native_entry(&id)?)?;
    Ok(id)
}

pub(super) fn read(id: &str) -> Result<DataKey> {
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::new(
            "keyring identifier must be 32 lowercase hexadecimal characters",
        ));
    }
    read_entry(&native_entry(id)?)
}

fn native_entry(id: &str) -> Result<Entry> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    use keyring_core::api::CredentialStoreApi;
    #[cfg(target_os = "linux")]
    let store = dbus_secret_service_keyring_store::Store::new().map_err(store_error)?;
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new().map_err(store_error)?;
    #[cfg(target_os = "windows")]
    let store = windows_native_keyring_store::Store::new().map_err(store_error)?;
    #[cfg(target_os = "windows")]
    return store
        .build(
            SERVICE,
            id,
            Some(&std::collections::HashMap::from([("persistence", "Local")])),
        )
        .map_err(store_error);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return store.build(SERVICE, id, None).map_err(store_error);
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = id;
        Err(Error::new(
            "no OS credential store backend for this platform",
        ))
    }
}

fn save_new(entry: &Entry) -> Result<()> {
    match entry.get_secret() {
        Err(StoreError::NoEntry) => (),
        Ok(bytes) => {
            drop(Zeroizing::new(bytes));
            return Err(Error::new(
                "credential already exists; refusing to replace its key",
            ));
        }
        Err(e) => return Err(store_error(e)),
    }
    let key = DataKey::generate()?;
    // KDE Wallet requires text. Hex is representation, not encryption; the OS
    // store protects it. The public identifier is independently random.
    let encoded = Zeroizing::new(hex::encode(key.0.as_ref()));
    entry.set_secret(encoded.as_bytes()).map_err(store_error)?;
    if read_entry(entry)?.0.as_ref() != key.0.as_ref() {
        return Err(Error::new(
            "credential read-back failed; existing entry was preserved",
        ));
    }
    Ok(())
}

fn read_entry(entry: &Entry) -> Result<DataKey> {
    let encoded = Zeroizing::new(entry.get_secret().map_err(store_error)?);
    let mut key = Zeroizing::new([0; 32]);
    hex::decode_to_slice(encoded.as_slice(), key.as_mut()).map_err(|_| {
        Error::new(
            "invalid stored instance key; preserve the credential and restore a valid backup",
        )
    })?;
    Ok(DataKey(key))
}

fn store_error(error: StoreError) -> Error {
    // Backend errors can carry secret buffers. Never format them into CLI logs.
    match error {
        StoreError::NoEntry => {
            Error::new("instance key not found in OS credential store; it was not regenerated")
        }
        StoreError::BadEncoding(bytes) | StoreError::BadDataFormat(bytes, _) => {
            drop(Zeroizing::new(bytes));
            Error::new("invalid credential store data; no fallback was attempted")
        }
        _ => Error::new(
            "OS credential store unavailable or access denied; unlock/configure the native store and retry",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyring_core::{api::CredentialStoreApi, mock};

    #[test]
    fn library_store_adapter_preserves_existing_missing_and_malformed_entries() {
        let store = mock::Store::new().unwrap();
        let entry = store.build(SERVICE, "test", None).unwrap();
        assert!(read_entry(&entry).is_err());
        assert!(matches!(entry.get_secret(), Err(StoreError::NoEntry)));
        save_new(&entry).unwrap();
        let before = Zeroizing::new(entry.get_secret().unwrap());
        assert!(save_new(&entry).is_err());
        assert_eq!(entry.get_secret().unwrap(), *before);
        for value in [vec![], vec![b'g'; 64], vec![b'0'; 62], vec![b'0'; 66]] {
            entry.set_secret(&value).unwrap();
            assert!(read_entry(&entry).is_err());
            assert_eq!(entry.get_secret().unwrap(), value);
        }
    }

    #[test]
    fn locked_store_errors_do_not_create_keys_or_expose_backend_details() {
        let store = mock::Store::new().unwrap();
        let entry = store.build(SERVICE, "test", None).unwrap();
        entry
            .as_any()
            .downcast_ref::<mock::Cred>()
            .unwrap()
            .set_error(StoreError::NoStorageAccess(
                "sensitive-backend-detail".into(),
            ));
        let error = save_new(&entry).unwrap_err().to_string();
        assert!(!error.contains("sensitive-backend-detail"));
        assert!(matches!(entry.get_secret(), Err(StoreError::NoEntry)));
    }
}
