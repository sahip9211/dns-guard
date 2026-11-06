//! Small transactional startup configuration. No connection is used by DNS queries.
use crate::{Error, Result, keys::DataKey, server::ServerConfig};
use rusqlite::{
    Connection, OpenFlags, TransactionBehavior, config::DbConfig, limits::Limit, params,
};
use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};

pub const MAX_DATABASE_BYTES: u64 = 64 * 1024;
pub const PAGE_CACHE_KIB: u32 = 32;
const PAGE_SIZE: u64 = 4096;
const APPLICATION_ID: i32 = 0x444e4743; // DNGC
const VERSION: i32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Absolute UTF-8 path: restarting from another working directory is safe.
    pub index_path: PathBuf,
    pub dns: ServerConfig,
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        let path = self
            .index_path
            .to_str()
            .ok_or_else(|| Error::new("index path must be UTF-8"))?;
        if !self.index_path.is_absolute() || path.len() > 2048 || path.chars().any(char::is_control)
        {
            return Err(Error::new(
                "index path must be absolute, at most 2048 bytes, without control characters",
            ));
        }
        // The persisted representation is milliseconds; never silently round a deadline.
        if !self.dns.timeout.as_nanos().is_multiple_of(1_000_000) {
            return Err(Error::new("timeout must be a whole number of milliseconds"));
        }
        self.dns.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedSettings {
    pub revision: u64,
    pub settings: Settings,
}

/// Synchronous startup/administration API. Do not call from a DNS executor task.
/// One owned connection, no pool, worker thread, SQL statement cache or history.
pub struct ConfigStore {
    connection: Connection,
}

impl ConfigStore {
    /// Create once. Existing files are never overwritten, including invalid/empty ones.
    /// An initialization failure leaves the file for inspection, not automatic reset.
    pub fn create(path: &Path, settings: &Settings, key: &DataKey) -> Result<Self> {
        settings.validate()?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        drop(options.open(path)?);
        let mut connection = connect(path, key)?;
        connection.execute_batch("PRAGMA page_size=4096; PRAGMA journal_mode=DELETE;")?;
        configure_budget(&connection)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Migration 0 -> 1 is atomic with the first complete settings revision.
        tx.execute_batch(include_str!("config/schema.sql"))?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)?;
        tx.pragma_update(None, "user_version", VERSION)?;
        write_settings(&tx, 1, settings)?;
        tx.commit()?;
        #[cfg(unix)]
        std::fs::File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
        Ok(Self { connection })
    }

    /// Open only a recognized database. Future versions, foreign schemas, oversize
    /// files and corrupt configuration fail closed. SQLite recovers hot journals.
    pub fn open(path: &Path, key: &DataKey) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_DATABASE_BYTES {
            return Err(Error::new(
                "configuration must be a regular, nonempty file within 64 KiB",
            ));
        }
        let connection = connect(path, key)?;
        Self::checked(connection)
    }

    /// Explicit, read-only import of a legacy plaintext v1 database. The source
    /// is retained; the encrypted destination must be new and starts revision 1.
    pub fn import_plaintext(source: &Path, destination: &Path, key: &DataKey) -> Result<Self> {
        use std::io::Read;
        let metadata = fs::symlink_metadata(source)?;
        if !metadata.is_file() || metadata.len() > MAX_DATABASE_BYTES {
            return Err(Error::new(
                "legacy configuration must be a regular file within 64 KiB",
            ));
        }
        let mut header = [0; 16];
        std::fs::File::open(source)?.read_exact(&mut header)?;
        if &header != b"SQLite format 3\0" {
            return Err(Error::new("source is not a plaintext SQLite database"));
        }
        let connection = Connection::open_with_flags(
            canonical_parent(source)?,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        restrict_connection(&connection)?;
        let saved = Self::checked(connection)?.load()?;
        Self::create(destination, &saved.settings, key)
    }

    fn checked(connection: Connection) -> Result<Self> {
        let application: i32 =
            connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i32 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if application != APPLICATION_ID || version != VERSION {
            return Err(Error::new(
                "unrecognized configuration or unsupported schema version; preserve the file and restore a compatible backup",
            ));
        }
        let journal: String = connection.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
        // SQLCipher returns its effective page size as text; legacy SQLite used
        // an integer. Accept only the exact supported size in either format.
        let page_size: rusqlite::types::Value =
            connection.pragma_query_value(None, "page_size", |r| r.get(0))?;
        let supported_page_size = match page_size {
            rusqlite::types::Value::Integer(size) => size == PAGE_SIZE as i64,
            rusqlite::types::Value::Text(size) => size == "4096",
            _ => false,
        };
        if journal != "delete" || !supported_page_size {
            return Err(Error::new(
                "unsupported configuration journal mode or page size",
            ));
        }
        let check: String = connection.query_row("PRAGMA quick_check(1)", [], |r| r.get(0))?;
        if check != "ok" {
            return Err(Error::new(
                "configuration integrity check failed; preserve the file and restore a backup",
            ));
        }
        let objects: i64 = connection.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get(0),
        )?;
        let tables: i64 = connection.query_row("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('settings','allowed_clients')", [], |r| r.get(0))?;
        if objects != 2 || tables != 2 {
            return Err(Error::new("unexpected configuration schema objects"));
        }
        configure_budget(&connection)?;
        let store = Self { connection };
        store.load()?;
        Ok(store)
    }

    /// Read row and ACL in one snapshot; a concurrent edit cannot mix generations.
    pub fn load(&self) -> Result<SavedSettings> {
        let tx = self.connection.unchecked_transaction()?;
        let saved = read_settings(&tx)?;
        tx.commit()?;
        Ok(saved)
    }

    /// Compare-and-swap the complete settings and ACL. Conflicts must be reloaded
    /// and reviewed by the caller; they are never silently retried as a new edit.
    pub fn replace(&mut self, expected_revision: u64, settings: &Settings) -> Result<u64> {
        settings.validate()?;
        let revision = expected_revision
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or_else(|| Error::new("configuration revision exhausted"))?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: u64 =
            tx.query_row("SELECT revision FROM settings WHERE id=1", [], |r| r.get(0))?;
        if current != expected_revision {
            return Err(Error::new(
                "configuration revision conflict; reload before editing",
            ));
        }
        write_settings(&tx, revision, settings)?;
        tx.commit()?;
        Ok(revision)
    }
}

fn connect(path: &Path, key: &DataKey) -> Result<Connection> {
    let connection = Connection::open_with_flags(
        canonical_parent(path)?,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let cipher: String = connection.pragma_query_value(None, "cipher_version", |r| r.get(0))?;
    if cipher.is_empty() {
        return Err(Error::new("encrypted configuration requires SQLCipher"));
    }
    // Key before any access to database pages. Never fall back to plaintext.
    let literal = key.sqlcipher_literal();
    connection
        .pragma_update(None, "key", &*literal)
        .map_err(|_| Error::new("unable to initialize encrypted configuration key"))?;
    drop(literal);
    connection.pragma_update(None, "cipher_memory_security", "ON")?;
    restrict_connection(&connection)?;
    Ok(connection)
}

fn canonical_parent(path: &Path) -> Result<PathBuf> {
    // SQLite's NOFOLLOW rejects symlinks in every path component. Canonicalize
    // the directory (e.g. macOS /var -> /private/var), never the database itself.
    let name = path
        .file_name()
        .ok_or_else(|| Error::new("configuration path must name a file"))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(fs::canonicalize(parent)?.join(name))
}

fn restrict_connection(connection: &Connection) -> Result<()> {
    connection.busy_timeout(Duration::from_millis(250))?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML, false)?;
    for (limit, value) in [
        (Limit::SQLITE_LIMIT_LENGTH, 4096),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, 8192),
        (Limit::SQLITE_LIMIT_COLUMN, 32),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 32),
        (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
        (Limit::SQLITE_LIMIT_EXPR_DEPTH, 32),
        (Limit::SQLITE_LIMIT_COMPOUND_SELECT, 1),
    ] {
        connection.set_limit(limit, value)?;
    }
    connection.execute_batch("PRAGMA synchronous=EXTRA; PRAGMA mmap_size=0; PRAGMA temp_store=MEMORY; PRAGMA cache_spill=OFF; PRAGMA journal_size_limit=0;")?;
    connection.pragma_update(None, "cache_size", -(PAGE_CACHE_KIB as i32))?;
    Ok(())
}

fn configure_budget(connection: &Connection) -> Result<()> {
    let maximum: u64 = connection.query_row("PRAGMA max_page_count=16", [], |r| r.get(0))?;
    if maximum * PAGE_SIZE > MAX_DATABASE_BYTES {
        return Err(Error::new("configuration exceeds database page budget"));
    }
    Ok(())
}

fn read_settings(connection: &Connection) -> Result<SavedSettings> {
    let count: u64 = connection.query_row("SELECT count(*) FROM settings", [], |r| r.get(0))?;
    if count != 1 {
        return Err(Error::new(
            "configuration must contain exactly one settings row",
        ));
    }
    let row = connection.query_row("SELECT revision,index_path,listen,upstream,categories,max_inflight,max_tcp_connections,cache_bytes,timeout_ms FROM settings WHERE id=1", [], |r| {
        Ok((r.get::<_, u64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, u32>(4)?, r.get::<_, usize>(5)?, r.get::<_, usize>(6)?, r.get::<_, usize>(7)?, r.get::<_, u64>(8)?))
    })?;
    if row.0 == 0 {
        return Err(Error::new("invalid configuration revision"));
    }
    let mut allowed_clients = Vec::new();
    let mut statement = connection
        .prepare("SELECT position,network FROM allowed_clients ORDER BY position LIMIT 33")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let position: usize = row.get(0)?;
        let text: String = row.get(1)?;
        if position != allowed_clients.len() || position >= 32 {
            return Err(Error::new("invalid client ACL positions or count"));
        }
        allowed_clients.push(
            text.parse()
                .map_err(|_| Error::new("invalid stored client network"))?,
        );
    }
    let settings = Settings {
        index_path: row.1.into(),
        dns: ServerConfig {
            listen: row
                .2
                .parse()
                .map_err(|_| Error::new("invalid stored listener"))?,
            upstream: row
                .3
                .parse()
                .map_err(|_| Error::new("invalid stored upstream"))?,
            categories: row.4,
            max_inflight: row.5,
            max_tcp_connections: row.6,
            cache_bytes: row.7,
            timeout: Duration::from_millis(row.8),
            allowed_clients,
        },
    };
    settings.validate()?;
    Ok(SavedSettings {
        revision: row.0,
        settings,
    })
}

fn write_settings(connection: &Connection, revision: u64, settings: &Settings) -> Result<()> {
    let dns = &settings.dns;
    connection.execute("INSERT INTO settings VALUES (1,?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,index_path=excluded.index_path,listen=excluded.listen,upstream=excluded.upstream,categories=excluded.categories,max_inflight=excluded.max_inflight,max_tcp_connections=excluded.max_tcp_connections,cache_bytes=excluded.cache_bytes,timeout_ms=excluded.timeout_ms",
        params![revision, settings.index_path.to_str(), dns.listen.to_string(), dns.upstream.to_string(), dns.categories, dns.max_inflight, dns.max_tcp_connections, dns.cache_bytes, dns.timeout.as_millis() as u64])?;
    connection.execute("DELETE FROM allowed_clients", [])?;
    let mut insert =
        connection.prepare("INSERT INTO allowed_clients(position,network) VALUES (?1,?2)")?;
    for (position, network) in dns.allowed_clients.iter().enumerate() {
        insert.execute(params![position, network.to_string()])?;
    }
    Ok(())
}

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Self::new(format!("configuration database: {error}"))
    }
}

#[cfg(test)]
mod tests;
