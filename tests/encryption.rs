use dns_guard::{
    config::{ConfigStore, Settings},
    keys::DataKey,
    server::ServerConfig,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "dns-encryption-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn settings(&self) -> Settings {
        Settings {
            index_path: self.0.join("confidential-policy-fixture.dngi"),
            dns: ServerConfig::default(),
        }
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn encrypted_database_requires_the_right_instance_key_and_preserves_wrong_key_attempts() {
    let dir = Temp::new();
    let first = DataKey::generate().unwrap();
    let second = DataKey::generate().unwrap();
    let path = dir.0.join("first.sqlite");
    let settings = dir.settings();
    drop(ConfigStore::create(&path, &settings, &first).unwrap());
    let bytes = fs::read(&path).unwrap();
    assert_ne!(&bytes[..16], b"SQLite format 3\0");
    assert!(
        !bytes
            .windows(b"confidential-policy-fixture".len())
            .any(|w| w == b"confidential-policy-fixture")
    );
    assert!(ConfigStore::open(&path, &second).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let unkeyed = rusqlite::Connection::open(&path).unwrap();
    assert!(
        unkeyed
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r
                .get::<_, i64>(0))
            .is_err()
    );
    drop(unkeyed);
    assert_eq!(
        ConfigStore::open(&path, &first)
            .unwrap()
            .load()
            .unwrap()
            .settings,
        settings
    );
    let other = dir.0.join("second.sqlite");
    drop(ConfigStore::create(&other, &settings, &second).unwrap());
    assert!(ConfigStore::open(&other, &first).is_err());
}

#[test]
fn authenticated_pages_detect_tampering_without_reinitialization() {
    let dir = Temp::new();
    let key = DataKey::generate().unwrap();
    let path = dir.0.join("config.sqlite");
    drop(ConfigStore::create(&path, &dir.settings(), &key).unwrap());
    let mut bytes = fs::read(&path).unwrap();
    bytes[2048] ^= 1;
    fs::write(&path, &bytes).unwrap();
    assert!(ConfigStore::open(&path, &key).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn keys_are_generated_once_and_never_printed_in_debug_output() {
    let dir = Temp::new();
    let path = dir.0.join("instance.key");
    let key = DataKey::create_file(&path).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), 32);
    let before = fs::read(&path).unwrap();
    assert!(DataKey::create_file(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(format!("{key:?}"), "DataKey([REDACTED])");
    let loaded = DataKey::read_file(&path).unwrap();
    let database = dir.0.join("config.sqlite");
    drop(ConfigStore::create(&database, &dir.settings(), &key).unwrap());
    assert!(ConfigStore::open(&database, &loaded).is_ok());
    for length in [0, 31, 33, 4096] {
        fs::write(&path, vec![1; length]).unwrap();
        assert!(DataKey::read_file(&path).is_err());
    }
}

#[test]
fn explicit_legacy_import_encrypts_a_new_file_without_erasing_the_source() {
    let dir = Temp::new();
    let old = dir.0.join("legacy.sqlite");
    let new = dir.0.join("encrypted.sqlite");
    let connection = rusqlite::Connection::open(&old).unwrap();
    connection
        .execute_batch(include_str!("../src/config/schema.sql"))
        .unwrap();
    connection
        .execute_batch("PRAGMA application_id=1145980739; PRAGMA user_version=1;")
        .unwrap();
    connection.execute("INSERT INTO settings VALUES (1,4,?1,'127.0.0.1:5353','127.0.0.1:53',127,64,32,262144,2000)",[dir.settings().index_path.to_str().unwrap()]).unwrap();
    connection
        .execute("INSERT INTO allowed_clients VALUES (0,'127.0.0.0/8')", [])
        .unwrap();
    drop(connection);
    let bytes = fs::read(&old).unwrap();
    let key = DataKey::generate().unwrap();
    assert!(ConfigStore::open(&old, &key).is_err());
    let imported = ConfigStore::import_plaintext(&old, &new, &key)
        .unwrap()
        .load()
        .unwrap();
    assert_eq!(imported.revision, 1);
    assert_eq!(imported.settings.index_path, dir.settings().index_path);
    assert_eq!(fs::read(&old).unwrap(), bytes);
    assert!(ConfigStore::import_plaintext(&old, &new, &key).is_err());
    assert!(ConfigStore::import_plaintext(&new, &dir.0.join("invalid.sqlite"), &key).is_err());
    assert!(!dir.0.join("invalid.sqlite").exists());
}

#[cfg(unix)]
#[test]
fn key_files_reject_symlinks_and_group_or_world_access() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = Temp::new();
    let path = dir.0.join("instance.key");
    DataKey::create_file(&path).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let link = dir.0.join("alias.key");
    symlink(&path, &link).unwrap();
    assert!(DataKey::read_file(&link).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(DataKey::read_file(&path).is_err());
}
