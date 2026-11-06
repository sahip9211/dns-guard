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
    entry_for(SERVICE, id)
}

fn entry_for(service: &str, id: &str) -> Entry {
    #[cfg(target_os = "linux")]
    let store = dbus_secret_service_keyring_store::Store::new().unwrap();
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new().unwrap();
    #[cfg(target_os = "windows")]
    let store = windows_native_keyring_store::Store::new().unwrap();
    store.build(service, id, None).unwrap()
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
fn native_keyring_roundtrip_and_cross_instance_rejection() {
    eprintln!("native API: creating isolated entries");
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
    eprintln!("native API: reading and validating keys");
    let key = DataKey::read_keyring(&first).unwrap();
    drop(ConfigStore::create(&database, &settings, &key).unwrap());
    let before = fs::read(&database).unwrap();
    assert!(ConfigStore::open(&database, &DataKey::read_keyring(&second).unwrap()).is_err());
    assert_eq!(fs::read(&database).unwrap(), before);
    assert_eq!(
        ConfigStore::open(&database, &DataKey::read_keyring(&first).unwrap())
            .unwrap()
            .load()
            .unwrap()
            .settings,
        settings
    );
    eprintln!("native API: deletion and malformed-key checks");
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

#[test]
#[ignore = "requires an unlocked OS store; use an isolated test keychain/session"]
fn native_cli_creates_and_reuses_its_own_credential() {
    // macOS may require user authorization when a different executable reads
    // an entry. Exercise repeated CLI access with the creating executable;
    // the API test above independently exercises the library test executable.
    let binary = env!("CARGO_BIN_EXE_dns-guard");
    eprintln!("native CLI: generating its own key");
    let output = Command::new(binary)
        .args(["config", "keygen", "--keyring"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let id = String::from_utf8(output.stdout).unwrap().trim().to_owned();
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
    let f = Fixture {
        root: std::env::temp_dir().join(format!("dns-keyring-cli-{id}")),
        ids: vec![id.clone()],
    };
    fs::create_dir(&f.root).unwrap();
    let feed = f.root.join("fixture.txt");
    let index = f.root.join("rules.dngi");
    let database = f.root.join("settings.sqlite");
    fs::write(&feed, "blocked.example\n").unwrap();
    let compiled = Command::new(binary)
        .arg("compile")
        .arg(&index)
        .args(["--other-bytes", "1000000", "--feed", "domains", "ads"])
        .arg(&feed)
        .output()
        .unwrap();
    assert!(compiled.status.success());
    eprintln!("native CLI: initializing encrypted configuration");
    let init = Command::new(binary)
        .args(["config", "init"])
        .arg(&database)
        .arg(&index)
        .args(["--keyring", &id, "--upstream", "192.0.2.1:53"])
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let good = Command::new(binary)
        .args(["config", "show"])
        .arg(&database)
        .args(["--keyring", &id])
        .output()
        .unwrap();
    assert!(
        good.status.success(),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    assert!(String::from_utf8_lossy(&good.stdout).contains("revision=1"));
    eprintln!("native CLI: deleting its synthetic fixture");
}

struct ManagementCredential(String);
impl Drop for ManagementCredential {
    fn drop(&mut self) {
        let _ = entry_for("dns-guard.management-token.v1", &self.0).delete_credential();
    }
}

#[test]
#[ignore = "requires an unlocked OS store; use an isolated test keychain/session"]
fn native_management_namespace_and_cli_token_reuse() {
    use dns_guard::keys::ManagementToken;
    let token = ManagementCredential(ManagementToken::create_in_keyring().unwrap());
    assert!(DataKey::read_keyring(&token.0).is_err());
    let first = ManagementToken::read_keyring(&token.0)
        .unwrap()
        .expose_bearer();
    let second = ManagementToken::read_keyring(&token.0)
        .unwrap()
        .expose_bearer();
    assert!(first.as_str() == second.as_str());
    let binary = env!("CARGO_BIN_EXE_dns-guard");
    let created = Command::new(binary)
        .args(["management", "token-create", "--keyring"])
        .output()
        .unwrap();
    assert!(created.status.success());
    let stderr = String::from_utf8(created.stderr).unwrap();
    let id = stderr
        .trim()
        .strip_prefix("management credential ID: ")
        .unwrap();
    let _cleanup = ManagementCredential(id.to_owned());
    let reread = Command::new(binary)
        .args(["management", "token-show", "--token-keyring", id])
        .output()
        .unwrap();
    assert!(reread.status.success());
    assert!(created.stdout == reread.stdout);
    assert_eq!(created.stdout.len(), 65);
}
