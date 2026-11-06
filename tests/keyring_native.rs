//! Opt-in OS-store tests. CI runs these against native stores on all three OSes.
#![cfg(all(
    feature = "os-keyring",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
use dns_guard::{
    config::{ConfigStore, Settings},
    keys::DataKey,
    server::ServerConfig,
};
use keyring_core::{Entry, api::CredentialStoreApi};
use std::{fs, path::PathBuf, process::Command};

const SERVICE: &str = "dns-guard.instance-key.v1";

fn entry(id: &str) -> Entry {
    #[cfg(target_os = "linux")]
    let store = dbus_secret_service_keyring_store::Store::new().unwrap();
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new().unwrap();
    #[cfg(target_os = "windows")]
    let store = windows_native_keyring_store::Store::new().unwrap();
    store.build(SERVICE, id, None).unwrap()
}

struct Fixture {
    ids: Vec<String>,
    root: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for id in &self.ids {
            let _ = entry(id).delete_credential();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
#[ignore = "requires an unlocked OS store; use an isolated test keychain/session"]
fn native_keyring_cli_roundtrip_and_cross_instance_rejection() {
    let first = DataKey::create_in_keyring().unwrap();
    let root = std::env::temp_dir().join(format!("dns-native-keyring-{first}"));
    let mut f = Fixture {
        ids: vec![first.clone()],
        root,
    };
    fs::create_dir(&f.root).unwrap();
    let second = DataKey::create_in_keyring().unwrap();
    f.ids.push(second.clone());
    assert_ne!(first, second);
    assert_eq!(first.len(), 32);
    #[cfg(target_os = "windows")]
    assert_eq!(
        entry(&first).get_attributes().unwrap()["persistence"].to_ascii_lowercase(),
        "local"
    );
    let database = f.root.join("settings.sqlite");
    let settings = Settings {
        index_path: f.root.join("rules.dngi"),
        dns: ServerConfig::default(),
    };
    let key = DataKey::read_keyring(&first).unwrap();
    drop(ConfigStore::create(&database, &settings, &key).unwrap());
    let before = fs::read(&database).unwrap();
    assert!(ConfigStore::open(&database, &DataKey::read_keyring(&second).unwrap()).is_err());
    assert_eq!(fs::read(&database).unwrap(), before);
    let binary = env!("CARGO_BIN_EXE_dns-guard");
    let good = Command::new(binary)
        .args(["config", "show"])
        .arg(&database)
        .args(["--keyring", &first])
        .output()
        .unwrap();
    assert!(
        good.status.success(),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    assert!(String::from_utf8_lossy(&good.stdout).contains("revision=1"));
    let wrong = Command::new(binary)
        .args(["config", "show"])
        .arg(&database)
        .args(["--keyring", &second])
        .output()
        .unwrap();
    assert!(!wrong.status.success());
    entry(&first).delete_credential().unwrap();
    assert!(DataKey::read_keyring(&first).is_err());
    assert!(matches!(
        entry(&first).get_secret(),
        Err(keyring_core::Error::NoEntry)
    ));
    assert_eq!(fs::read(&database).unwrap(), before);
    // Invalid stored data must fail, not be replaced with a newly generated key.
    entry(&second).set_secret(b"invalid-key").unwrap();
    assert!(DataKey::read_keyring(&second).is_err());
    assert_eq!(entry(&second).get_secret().unwrap(), b"invalid-key");
}
