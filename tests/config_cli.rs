use dns_guard::{Action, Category, Limits, Rule, Scope, compile, config::ConfigStore};
use std::{
    fs,
    io::{BufRead, BufReader},
    net::UdpSocket,
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::Duration,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "dns-config-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let index = compile(
            &[Rule::new(
                "blocked.example",
                Scope::Domain,
                Action::Block,
                Category::ADS,
            )
            .unwrap()],
            Limits::default(),
        )
        .unwrap();
        fs::write(root.join("rules.dngi"), index.as_bytes()).unwrap();
        Self { root }
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_dns-guard"))
            .current_dir(&self.root)
            .args(args)
            .output()
            .unwrap()
    }
    fn init(&self) {
        let out = self.run(&[
            "config",
            "init",
            "settings.sqlite",
            "rules.dngi",
            "--upstream",
            "192.0.2.1:53",
            "--listen",
            "127.0.0.1:0",
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn config_cli_validates_persists_and_requires_revision_for_edits() {
    let f = Fixture::new();
    f.init();
    let out = f.run(&["config", "show", "settings.sqlite"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("revision=1"));
    let out = f.run(&[
        "config",
        "set",
        "settings.sqlite",
        "--revision",
        "1",
        "--cache-bytes",
        "0",
        "--categories",
        "none",
        "--allow-client",
        "10.0.0.0/8",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let db = ConfigStore::open(&f.root.join("settings.sqlite")).unwrap();
    let saved = db.load().unwrap();
    assert_eq!(saved.revision, 2);
    assert_eq!(saved.settings.dns.cache_bytes, 0);
    assert_eq!(saved.settings.dns.categories, 0);
    assert_eq!(saved.settings.dns.allowed_clients.len(), 1);
    assert!(saved.settings.index_path.is_absolute());
    for args in [
        vec!["config", "set", "settings.sqlite", "--cache-bytes", "4096"],
        vec![
            "config",
            "set",
            "settings.sqlite",
            "--revision",
            "1",
            "--cache-bytes",
            "4096",
        ],
        vec![
            "config",
            "set",
            "settings.sqlite",
            "--revision",
            "2",
            "--max-inflight",
            "0",
        ],
        vec![
            "config",
            "set",
            "settings.sqlite",
            "--revision",
            "2",
            "--index",
            "missing.dngi",
        ],
        vec![
            "config",
            "set",
            "settings.sqlite",
            "--revision",
            "2",
            "--cache-bytes",
            "4096",
            "--cache-bytes",
            "8192",
        ],
        vec![
            "serve",
            "--config",
            "settings.sqlite",
            "--cache-bytes",
            "4096",
        ],
        vec!["config", "init", "other.sqlite", "rules.dngi"],
    ] {
        assert!(!f.run(&args).status.success(), "{args:?}");
    }
    assert_eq!(db.load().unwrap(), saved);
    assert!(!f.root.join("other.sqlite").exists());
}

#[test]
fn service_uses_saved_configuration_from_another_directory_and_releases_database() {
    let f = Fixture::new();
    f.init();
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_dns-guard"))
            .args(["serve", "--config"])
            .arg(f.root.join("settings.sqlite"))
            .current_dir(std::env::temp_dir())
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let stderr = child.0.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else {
                break;
            };
            if let Some(address) = line
                .strip_prefix("DNS listening on ")
                .and_then(|s| s.split_whitespace().next())
            {
                let _ = tx.send(address.to_owned());
                break;
            }
        }
    });
    let address = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("service did not become ready");
    reader.join().unwrap();
    // Exclusive access remains possible while DNS is running; no hidden DB reader.
    let connection = rusqlite::Connection::open(f.root.join("settings.sqlite")).unwrap();
    connection.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let query=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07blocked\x07example\x00\x00\x01\x00\x01";
    socket.send_to(query, address).unwrap();
    let mut reply = [0; 512];
    let n = socket.recv(&mut reply).unwrap();
    assert!(n >= 12);
    assert_eq!(&reply[..2], &query[..2]);
    assert_eq!(reply[3] & 15, 5); // REFUSED, without an upstream dependency.
    connection.execute_batch("ROLLBACK").unwrap();
}
