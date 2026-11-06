use dns_guard::{Action, Category, Limits, Rule, Scope, compile};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpStream, UdpSocket},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "dns-management-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self { root }
    }
    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_dns-guard"))
            .current_dir(&self.root)
            .args(args)
            .output()
            .unwrap()
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
fn token_provisioning_is_explicit_and_preserves_existing_credentials() {
    let f = Fixture::new();
    let out = f.run(&["management", "token-create", "api.key"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bearer = String::from_utf8(out.stdout).unwrap();
    assert_eq!(bearer.trim().len(), 64);
    assert_eq!(
        hex::decode(bearer.trim()).unwrap(),
        fs::read(f.root.join("api.key")).unwrap()
    );
    let before = fs::read(f.root.join("api.key")).unwrap();
    assert!(
        !f.run(&["management", "token-create", "api.key"])
            .status
            .success()
    );
    assert_eq!(fs::read(f.root.join("api.key")).unwrap(), before);
    assert_eq!(
        f.run(&["management", "token-show", "--token-file", "api.key"])
            .stdout,
        bearer.as_bytes()
    );
    assert!(
        !f.run(&["management", "token-show", "--token-file", "missing.key"])
            .status
            .success()
    );
}

#[test]
fn incomplete_management_options_and_data_key_reuse_fail_closed() {
    let f = Fixture::new();
    f.run(&["management", "token-create", "api.key"]);
    for options in [
        vec!["--management-listen", "127.0.0.1:0"],
        vec!["--management-token-file", "api.key"],
        vec![
            "--management-listen",
            "0.0.0.0:8080",
            "--management-token-file",
            "api.key",
        ],
        vec![
            "--management-listen",
            "127.0.0.1:0",
            "--management-token-file",
            "api.key",
            "--management-token-keyring",
            "id",
        ],
        vec![
            "--management-listen",
            "127.0.0.1:0",
            "--management-listen",
            "127.0.0.1:1",
            "--management-token-file",
            "api.key",
        ],
    ] {
        let mut args = vec!["serve", "rules.dngi", "--upstream", "192.0.2.1:53"];
        args.extend(options);
        let out = f.run(&args);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("management"));
    }
    let out = f.run(&[
        "serve",
        "--config",
        "missing.sqlite",
        "--key-file",
        "api.key",
        "--management-listen",
        "127.0.0.1:0",
        "--management-token-file",
        "api.key",
    ]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("must not reuse"));
}

#[test]
fn dashboard_reports_real_dns_queries_without_logging_credentials() {
    counter_roundtrip(false);
    counter_roundtrip(true);
}

fn counter_roundtrip(saved_config: bool) {
    let f = Fixture::new();
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
    fs::write(f.root.join("rules.dngi"), index.as_bytes()).unwrap();
    let bearer =
        String::from_utf8(f.run(&["management", "token-create", "api.key"]).stdout).unwrap();
    let args = if saved_config {
        assert!(f.run(&["config", "keygen", "data.key"]).status.success());
        assert!(
            f.run(&[
                "config",
                "init",
                "settings.sqlite",
                "rules.dngi",
                "--key-file",
                "data.key",
                "--upstream",
                "192.0.2.1:53",
                "--listen",
                "127.0.0.1:0"
            ])
            .status
            .success()
        );
        vec![
            "serve",
            "--config",
            "settings.sqlite",
            "--key-file",
            "data.key",
        ]
    } else {
        vec![
            "serve",
            "rules.dngi",
            "--upstream",
            "192.0.2.1:53",
            "--listen",
            "127.0.0.1:0",
        ]
    };
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_dns-guard"))
            .current_dir(&f.root)
            .args(args)
            .args([
                "--management-listen",
                "127.0.0.1:0",
                "--management-token-file",
                "api.key",
            ])
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let stderr = child.0.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            if tx.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let mut dns = None;
    let mut management = None;
    while dns.is_none() || management.is_none() {
        let line = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(!line.contains(bearer.trim()));
        if let Some(value) = line.strip_prefix("DNS listening on ") {
            dns = value.split_whitespace().next().map(str::to_owned);
        }
        if let Some(value) = line.strip_prefix("Management listening on http://") {
            management = Some(value.to_owned());
        }
    }
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07blocked\x07example\x00\x00\x01\x00\x01";
    udp.send_to(query, dns.unwrap()).unwrap();
    let mut answer = [0; 512];
    let (n, _) = udp.recv_from(&mut answer).unwrap();
    assert!(n >= 12);
    assert_eq!(&answer[..2], &query[..2]);
    let addr = management.unwrap();
    let mut socket = TcpStream::connect(&addr).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        socket,
        "GET /api/v1/status HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {}\r\n\r\n",
        bearer.trim()
    )
    .unwrap();
    let mut reply = String::new();
    socket.read_to_string(&mut reply).unwrap();
    let value: serde_json::Value =
        serde_json::from_str(reply.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(value["dns"]["received"], 1);
    assert_eq!(value["dns"]["blocked"], 1);
    assert_eq!(value["dns"]["forwarded"], 0);
}
