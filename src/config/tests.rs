use super::*;

#[test]
fn database_full_rolls_back_partial_work_without_losing_previous_settings() {
    let directory = std::env::temp_dir().join(format!("dns-config-full-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let path = directory.join("config.sqlite");
    let settings = Settings {
        index_path: directory.join("rules.dngi"),
        dns: ServerConfig::default(),
    };
    let mut store = ConfigStore::create(&path, &settings).unwrap();
    let tx = store.connection.transaction().unwrap();
    tx.execute_batch("UPDATE settings SET revision=2; DELETE FROM allowed_clients; CREATE TABLE overflow(value BLOB);").unwrap();
    let error = loop {
        if let Err(error) = tx.execute("INSERT INTO overflow VALUES (zeroblob(3000))", []) {
            break error;
        }
    };
    assert!(
        matches!(error, rusqlite::Error::SqliteFailure(e, _) if e.code == rusqlite::ErrorCode::DiskFull)
    );
    drop(tx);
    assert_eq!(
        store.load().unwrap(),
        SavedSettings {
            revision: 1,
            settings
        }
    );
    assert!(fs::metadata(&path).unwrap().len() <= MAX_DATABASE_BYTES);
    drop(store);
    ConfigStore::open(&path).unwrap();
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn bundled_sqlite_omits_unused_search_modules_and_extension_loading() {
    let connection = Connection::open_in_memory().unwrap();
    for name in ["ENABLE_FTS3", "ENABLE_FTS5", "ENABLE_RTREE"] {
        let enabled: bool = connection
            .query_row("SELECT sqlite_compileoption_used(?1)", [name], |r| r.get(0))
            .unwrap();
        assert!(!enabled, "unused SQLite module: {name}");
    }
    assert!(
        connection
            .query_row(
                "SELECT sqlite_compileoption_used('OMIT_LOAD_EXTENSION')",
                [],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
}
