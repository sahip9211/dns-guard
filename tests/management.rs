use dns_guard::{
    Action, Category, Index, Limits, Rule, Scope, compile,
    keys::{DataKey, ManagementToken},
    management::Management,
    server::Stats,
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

fn policy() -> Arc<Index> {
    Arc::new(
        compile(
            &[
                Rule::new("ads.example", Scope::Domain, Action::Block, Category::ADS).unwrap(),
                Rule::new(
                    "safe.ads.example",
                    Scope::Domain,
                    Action::Allow,
                    Category::ADS,
                )
                .unwrap(),
                Rule::new(
                    "adult.example",
                    Scope::Domain,
                    Action::Enforce,
                    Category::ADULT,
                )
                .unwrap(),
            ],
            Limits::default(),
        )
        .unwrap(),
    )
}

fn start() -> (Management, String) {
    let token = ManagementToken::generate().unwrap();
    let bearer = token.expose_bearer().to_string();
    let server = Management::start(
        "127.0.0.1:0".parse().unwrap(),
        token,
        Arc::new(Stats::default()),
        policy(),
        Category::ALL,
    )
    .unwrap();
    (server, bearer)
}

fn request(addr: SocketAddr, raw: &str) -> String {
    let mut socket = TcpStream::connect(addr).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket.write_all(raw.as_bytes()).unwrap();
    let mut reply = String::new();
    socket.read_to_string(&mut reply).unwrap();
    reply
}

fn get(addr: SocketAddr, path: &str, headers: &str) -> String {
    request(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{headers}\r\n"),
    )
}

#[test]
fn status_requires_independent_token_and_returns_versioned_real_counters() {
    let (server, token) = start();
    let addr = server.local_addr();
    assert!(get(addr, "/api/v1/status", "").starts_with("HTTP/1.1 401"));
    assert!(
        get(
            addr,
            "/api/v1/status",
            &format!("Authorization: Bearer {}\r\n", "0".repeat(64))
        )
        .starts_with("HTTP/1.1 401")
    );
    let reply = get(
        addr,
        "/api/v1/status",
        &format!("Authorization: Bearer {token}\r\n"),
    );
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    let data: serde_json::Value =
        serde_json::from_str(reply.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(data["schema_version"], 1);
    assert_eq!(data["policy"]["rules"], 3);
    assert_eq!(data["policy"]["bytes"], policy().as_bytes().len());
    assert_eq!(data["dns"]["received"], 0);
    assert_eq!(data["dns"].as_object().unwrap().len(), 15);
    assert!(!reply.contains(&token));
    assert!(!reply.contains("access-control-allow-origin"));
    assert!(reply.contains("cache-control: no-store"));
}

#[test]
fn rejects_rebinding_cross_origin_bodies_mutations_and_ambiguous_credentials() {
    let (server, token) = start();
    let addr = server.local_addr();
    for headers in [
        "Origin: https://evil.example\r\n".to_owned(),
        "Origin: null\r\n".to_owned(),
        "Sec-Fetch-Site: cross-site\r\n".to_owned(),
        format!("Origin: http://{addr}\r\nOrigin: https://evil.example\r\n"),
    ] {
        assert!(
            get(
                addr,
                "/api/v1/status",
                &format!("Authorization: Bearer {token}\r\n{headers}")
            )
            .starts_with("HTTP/1.1 403")
        );
    }
    assert!(
        request(addr, "GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n").starts_with("HTTP/1.1 403")
    );
    assert!(
        get(
            addr,
            "/api/v1/status",
            &format!("Authorization: Bearer {token}\r\nAuthorization: Bearer {token}\r\n")
        )
        .starts_with("HTTP/1.1 401")
    );
    assert!(get(addr, &format!("/api/v1/status?token={token}"), "").starts_with("HTTP/1.1 400"));
    assert!(get(addr, "/api/v1/status", "Content-Length: 1\r\n").starts_with("HTTP/1.1 400"));
    assert!(
        get(addr, "/api/v1/status", "Transfer-Encoding: chunked\r\n").starts_with("HTTP/1.1 400")
    );
    assert!(
        request(
            addr,
            &format!("POST /api/v1/status HTTP/1.1\r\nHost: {addr}\r\n\r\n")
        )
        .starts_with("HTTP/1.1 405")
    );
    assert!(
        get(
            addr,
            "/api/v1/status",
            &format!("Authorization: Bearer {token}\r\nOrigin: http://{addr}\r\n")
        )
        .starts_with("HTTP/1.1 200")
    );
}

#[test]
fn embedded_shell_has_security_headers_and_no_secret() {
    let (server, token) = start();
    for (path, mime) in [
        ("/", "text/html"),
        ("/app.js", "text/javascript"),
        ("/app.css", "text/css"),
    ] {
        let reply = get(server.local_addr(), path, "");
        assert!(reply.starts_with("HTTP/1.1 200"));
        assert!(reply.contains(mime));
        assert!(reply.contains("content-security-policy:"));
        assert!(reply.contains("x-frame-options: DENY"));
        assert!(reply.contains("x-content-type-options: nosniff"));
        assert!(!reply.contains(&token));
    }
    assert!(get(server.local_addr(), "/missing", "").starts_with("HTTP/1.1 404"));
}

#[test]
fn non_loopback_bind_is_rejected_and_shutdown_closes_slow_clients() {
    for address in ["0.0.0.0:0", "[::]:0", "192.0.2.1:0"] {
        assert!(
            Management::start(
                address.parse().unwrap(),
                ManagementToken::generate().unwrap(),
                Arc::new(Stats::default()),
                policy(),
                Category::ALL
            )
            .is_err()
        );
    }
    let (server, _) = start();
    let mut slow = TcpStream::connect(server.local_addr()).unwrap();
    slow.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    slow.write_all(b"GET / HTTP/1.1\r\n").unwrap();
    let started = Instant::now();
    drop(server);
    assert!(started.elapsed() < Duration::from_secs(2));
    let read = slow.read(&mut [0]);
    assert!(
        matches!(read, Ok(0))
            || read.is_err_and(|e| matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ))
    );
}

#[test]
fn token_debug_is_redacted_and_data_key_reuse_is_rejected() {
    let token = ManagementToken::generate().unwrap();
    let bearer = token.expose_bearer();
    assert_eq!(bearer.len(), 64);
    assert!(!format!("{token:?}").contains(bearer.as_str()));
    let bytes: [u8; 32] = hex::decode(bearer.as_str()).unwrap().try_into().unwrap();
    assert!(
        token
            .ensure_separate_from(&DataKey::from_bytes(bytes))
            .is_err()
    );
    assert!(
        token
            .ensure_separate_from(&DataKey::generate().unwrap())
            .is_ok()
    );
}

#[test]
fn oversized_headers_and_slow_requests_do_not_hold_unbounded_connections() {
    let (server, _) = start();
    let addr = server.local_addr();
    let mut socket = TcpStream::connect(addr).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        socket,
        "GET / HTTP/1.1\r\nHost: {addr}\r\nX-Pad: {}\r\n\r\n",
        "a".repeat(9000)
    )
    .unwrap();
    let mut reply = String::new();
    let result = socket.read_to_string(&mut reply);
    assert!(result.is_err() || reply.starts_with("HTTP/1.1 431"));
    let mut slow = TcpStream::connect(addr).unwrap();
    slow.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    slow.write_all(b"GET / HTTP/1.1\r\n").unwrap();
    let started = Instant::now();
    let read = slow.read(&mut [0]);
    assert!(
        matches!(read, Ok(0))
            || read.is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset)
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(get(addr, "/", "").starts_with("HTTP/1.1 200"));
}

#[test]
fn ipv6_numeric_loopback_supports_the_same_api() {
    let token = ManagementToken::generate().unwrap();
    let bearer = token.expose_bearer();
    let server = Management::start(
        "[::1]:0".parse().unwrap(),
        token,
        Arc::new(Stats::default()),
        policy(),
        Category::ALL,
    )
    .unwrap();
    let reply = get(
        server.local_addr(),
        "/api/v1/status",
        &format!("Authorization: Bearer {}\r\n", bearer.as_str()),
    );
    assert!(reply.starts_with("HTTP/1.1 200"));
}

#[test]
fn excess_connections_are_closed_while_existing_clients_are_slow() {
    let (server, _) = start();
    let addr = server.local_addr();
    let mut slow = Vec::new();
    for _ in 0..8 {
        let mut socket = TcpStream::connect(addr).unwrap();
        socket.write_all(b"GET / HTTP/1.1\r\n").unwrap();
        slow.push(socket);
    }
    let mut excess = TcpStream::connect(addr).unwrap();
    excess
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let result = excess.read(&mut [0]);
    assert!(
        matches!(result, Ok(0))
            || result.is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset)
    );
    drop(slow);
}

fn check_policy(addr: SocketAddr, token: &str, body: &str) -> String {
    request(
        addr,
        &format!(
            "POST /api/v1/policy/check HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
}

#[test]
fn policy_checker_uses_active_categories_and_exact_allow_enforce_semantics() {
    let (server, token) = start();
    for (domain, blocked, allowed, enforced) in [
        ("X.ADS.EXAMPLE.", 1, 0, 0),
        ("safe.ads.example", 0, 1, 0),
        ("adult.example", 2, 0, 2),
        ("notads.example", 0, 0, 0),
    ] {
        let reply = check_policy(
            server.local_addr(),
            &token,
            &format!(r#"{{"domain":"{domain}"}}"#),
        );
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        let data: serde_json::Value =
            serde_json::from_str(reply.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(data["schema_version"], 1);
        assert_eq!(
            data["domain"],
            domain.trim_end_matches('.').to_ascii_lowercase()
        );
        assert_eq!(data["blocked_categories"], blocked);
        assert_eq!(data["allowed_categories"], allowed);
        assert_eq!(data["enforced_categories"], enforced);
        assert_eq!(data["blocked"], blocked != 0);
    }
    let key = ManagementToken::generate().unwrap();
    let bearer = key.expose_bearer();
    let restricted = Management::start(
        "127.0.0.1:0".parse().unwrap(),
        key,
        Arc::new(Stats::default()),
        policy(),
        Category::ADS,
    )
    .unwrap();
    let reply = check_policy(
        restricted.local_addr(),
        &bearer,
        r#"{"domain":"adult.example"}"#,
    );
    let data: serde_json::Value =
        serde_json::from_str(reply.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(data["blocked"], false);
    assert_eq!(data["enabled_categories"], Category::ADS);
    let stats = get(
        server.local_addr(),
        "/api/v1/status",
        &format!("Authorization: Bearer {token}\r\n"),
    );
    let data: serde_json::Value =
        serde_json::from_str(stats.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(
        data["dns"]["received"], 0,
        "policy checks are not DNS traffic"
    );
}

#[test]
fn policy_checker_rejects_unauthorized_invalid_and_oversized_requests() {
    let (server, token) = start();
    let addr = server.local_addr();
    assert!(
        check_policy(addr, "invalid", r#"{"domain":"ads.example"}"#).starts_with("HTTP/1.1 401")
    );
    assert!(get(addr, "/api/v1/policy/check", "").starts_with("HTTP/1.1 405"));
    for body in [
        r#"{"domain":"bad..name"}"#,
        r#"{"domain":"127.0.0.1"}"#,
        r#"{"domain":"a.test","categories":0}"#,
        r#"{"domain":"a.test","domain":"b.test"}"#,
        r#"{}"#,
        r#"null"#,
        r#"{"domain":"a.test"} trailing"#,
    ] {
        assert!(
            check_policy(addr, &token, body).starts_with("HTTP/1.1 400"),
            "{body}"
        );
    }
    assert!(check_policy(addr, &token, &" ".repeat(513)).starts_with("HTTP/1.1 413"));
    let response = request(
        addr,
        &format!(
            "POST /api/v1/policy/check HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n"
        ),
    );
    assert!(response.starts_with("HTTP/1.1 415"));
    let response = request(
        addr,
        &format!(
            "POST /api/v1/policy/check HTTP/1.1\r\nHost: {addr}\r\nOrigin: https://evil.example\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\n\r\n"
        ),
    );
    assert!(response.starts_with("HTTP/1.1 403"));
    // Length enforcement must also work without a Content-Length header.
    let body = "a".repeat(513);
    let response = request(
        addr,
        &format!(
            "POST /api/v1/policy/check HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n201\r\n{body}\r\n0\r\n\r\n"
        ),
    );
    assert!(response.starts_with("HTTP/1.1 413"));
}
