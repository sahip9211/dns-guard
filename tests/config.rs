use dns_guard::{
    config::{ConfigStore, MAX_DATABASE_BYTES, Settings},
    server::ServerConfig,
};
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "dns-guard-config-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn db(&self) -> PathBuf {
        self.0.join("settings.sqlite")
    }
    fn settings(&self) -> Settings {
        Settings {
            index_path: self.0.join("rules.dngi"),
            dns: ServerConfig {
                upstream: "192.0.2.1:53".parse().unwrap(),
                ..ServerConfig::default()
            },
        }
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn configuration_roundtrips_defaults_and_all_limits_across_reopen() {
    let dir = Temp::new();
    let mut settings = dir.settings();
    settings.dns.allowed_clients = vec![
        "10.10.0.0/16".parse().unwrap(),
        "2001:db8::/32".parse().unwrap(),
    ];
    let mut db = ConfigStore::create(&dir.db(), &settings).unwrap();
    let saved = db.load().unwrap();
    assert_eq!(saved.revision, 1);
    assert_eq!(saved.settings, settings);
    settings.dns.cache_bytes = 0;
    settings.dns.categories = 0;
    settings.dns.max_inflight = 17;
    settings.dns.max_tcp_connections = 3;
    settings.dns.timeout = std::time::Duration::from_millis(101);
    assert_eq!(db.replace(1, &settings).unwrap(), 2);
    drop(db);
    let saved = ConfigStore::open(&dir.db()).unwrap().load().unwrap();
    assert_eq!(saved.revision, 2);
    assert_eq!(saved.settings, settings);
}

#[test]
fn invalid_changes_and_stale_revisions_preserve_the_entire_configuration() {
    let dir = Temp::new();
    let settings = dir.settings();
    let mut db = ConfigStore::create(&dir.db(), &settings).unwrap();
    let mut invalid = settings.clone();
    invalid.dns.max_inflight = 0;
    assert!(db.replace(1, &invalid).is_err());
    invalid = settings.clone();
    invalid.index_path = "relative.dngi".into();
    assert!(db.replace(1, &invalid).is_err());
    invalid = settings.clone();
    invalid.dns.timeout = std::time::Duration::from_nanos(1);
    assert!(db.replace(1, &invalid).is_err());
    assert!(db.replace(0, &settings).is_err());
    assert_eq!(db.load().unwrap().settings, settings);
    assert_eq!(db.load().unwrap().revision, 1);
}

#[test]
fn competing_editors_cannot_silently_overwrite_each_other() {
    let dir = Temp::new();
    let settings = dir.settings();
    drop(ConfigStore::create(&dir.db(), &settings).unwrap());
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = [17, 29]
        .into_iter()
        .map(|limit| {
            let path = dir.db();
            let mut settings = settings.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut db = ConfigStore::open(&path).unwrap();
                let revision = db.load().unwrap().revision;
                settings.dns.max_inflight = limit;
                barrier.wait();
                db.replace(revision, &settings)
            })
        })
        .collect();
    let successes = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .filter(Result::is_ok)
        .count();
    assert_eq!(successes, 1);
    let saved = ConfigStore::open(&dir.db()).unwrap().load().unwrap();
    assert_eq!(saved.revision, 2);
    assert!([17, 29].contains(&saved.settings.dns.max_inflight));
}

#[test]
fn missing_corrupt_foreign_and_future_databases_are_never_reset() {
    let dir = Temp::new();
    assert!(ConfigStore::open(&dir.db()).is_err());
    assert!(!dir.db().exists());
    for bytes in [
        vec![],
        b"not sqlite".to_vec(),
        vec![0; MAX_DATABASE_BYTES as usize + 1],
    ] {
        fs::write(dir.db(), &bytes).unwrap();
        assert!(ConfigStore::open(&dir.db()).is_err());
        assert!(ConfigStore::create(&dir.db(), &dir.settings()).is_err());
        assert_eq!(fs::read(dir.db()).unwrap(), bytes);
    }
    fs::remove_file(dir.db()).unwrap();
    let conn = rusqlite::Connection::open(dir.db()).unwrap();
    conn.execute_batch("CREATE TABLE unrelated(value); INSERT INTO unrelated VALUES (42);")
        .unwrap();
    drop(conn);
    let before = fs::read(dir.db()).unwrap();
    assert!(ConfigStore::open(&dir.db()).is_err());
    assert_eq!(fs::read(dir.db()).unwrap(), before);
    fs::remove_file(dir.db()).unwrap();
    drop(ConfigStore::create(&dir.db(), &dir.settings()).unwrap());
    let conn = rusqlite::Connection::open(dir.db()).unwrap();
    conn.execute_batch("PRAGMA user_version=999;").unwrap();
    drop(conn);
    let before = fs::read(dir.db()).unwrap();
    assert!(ConfigStore::open(&dir.db()).is_err());
    assert_eq!(fs::read(dir.db()).unwrap(), before);
}

#[test]
fn repeated_edits_remain_small_and_do_not_accumulate_wal_or_history() {
    let dir = Temp::new();
    let mut settings = dir.settings();
    let mut db = ConfigStore::create(&dir.db(), &settings).unwrap();
    for revision in 1..=200 {
        settings.dns.max_inflight = revision as usize;
        db.replace(revision, &settings).unwrap();
    }
    assert_eq!(db.load().unwrap().revision, 201);
    assert!(fs::metadata(dir.db()).unwrap().len() <= MAX_DATABASE_BYTES);
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
    drop(db);
    let conn = rusqlite::Connection::open(dir.db()).unwrap();
    assert_eq!(
        conn.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "delete"
    );
    assert_eq!(
        conn.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
}

#[test]
fn damaged_stored_values_are_rejected_before_service_start() {
    let dir = Temp::new();
    drop(ConfigStore::create(&dir.db(), &dir.settings()).unwrap());
    let conn = rusqlite::Connection::open(dir.db()).unwrap();
    conn.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE settings SET max_inflight=0;")
        .unwrap();
    drop(conn);
    assert!(
        ConfigStore::open(&dir.db())
            .and_then(|db| db.load())
            .is_err()
    );
}

#[test]
fn recovery_discards_a_flushed_but_uncommitted_change_after_process_exit() {
    let dir = Temp::new();
    let settings = dir.settings();
    drop(ConfigStore::create(&dir.db(), &settings).unwrap());
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "interrupted_writer_child", "--nocapture"])
        .env("DNS_GUARD_TEST_CRASH_DATABASE", dir.db())
        .output()
        .unwrap();
    assert_eq!(
        child.status.code(),
        Some(73),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(dir.0.join("settings.sqlite-journal").exists());
    let saved = ConfigStore::open(&dir.db()).unwrap().load().unwrap();
    assert_eq!(saved.revision, 1);
    assert_eq!(saved.settings, settings);
    assert!(!dir.0.join("settings.sqlite-journal").exists());
}

#[test]
fn interrupted_writer_child() {
    let Some(path) = std::env::var_os("DNS_GUARD_TEST_CRASH_DATABASE") else {
        return;
    };
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch("PRAGMA synchronous=EXTRA; BEGIN IMMEDIATE; UPDATE settings SET revision=2,max_inflight=123; DELETE FROM allowed_clients;").unwrap();
    conn.cache_flush().unwrap();
    // No Rust destructors/SQLite rollback: leave a real hot journal on disk.
    std::process::exit(73);
}

#[cfg(unix)]
#[test]
fn creation_is_private_and_symlinks_are_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = Temp::new();
    drop(ConfigStore::create(&dir.db(), &dir.settings()).unwrap());
    assert_eq!(
        fs::metadata(dir.db()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let link = dir.0.join("link.sqlite");
    symlink(dir.db(), &link).unwrap();
    assert!(ConfigStore::open(&link).is_err());
}

#[cfg(unix)]
#[test]
fn system_directory_aliases_work_without_following_a_database_symlink() {
    use std::os::unix::fs::symlink;
    let dir = Temp::new();
    let actual = dir.0.join("actual");
    fs::create_dir(&actual).unwrap();
    let alias = dir.0.join("alias");
    symlink(&actual, &alias).unwrap();
    let path = alias.join("settings.sqlite");
    drop(ConfigStore::create(&path, &dir.settings()).unwrap());
    assert_eq!(
        ConfigStore::open(&path).unwrap().load().unwrap().revision,
        1
    );
    let link = alias.join("redirect.sqlite");
    symlink(actual.join("settings.sqlite"), &link).unwrap();
    assert!(ConfigStore::open(&link).is_err());
}
