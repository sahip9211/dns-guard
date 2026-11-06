#[path = "../examples/support/mod.rs"]
mod support;
#[path = "../examples/support/wire.rs"]
mod wire;
use dns_guard::{Action, Category, Limits, Rule, Scope, compile};
use std::fmt::Write;
use wire::{Buffer, parse_request};

#[test]
fn request_framing_handles_fragments_pipeline_and_close() {
    let first = b"GET /check/1/ads.test HTTP/1.1\r\nHost: localhost\r\n\r\n";
    for i in 0..first.len() {
        assert!(parse_request(&first[..i]).unwrap().is_none());
    }
    let combined = [
        first.as_slice(),
        b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, CLOSE\r\n\r\n",
    ]
    .concat();
    let a = parse_request(&combined).unwrap().unwrap();
    assert_eq!(
        (a.method, a.path, a.used, a.close),
        ("GET", "/check/1/ads.test", first.len(), false)
    );
    let b = parse_request(&combined[a.used..]).unwrap().unwrap();
    assert!(b.close);
    assert_eq!(b.path, "/health");
}

#[test]
fn ambiguous_or_body_bearing_requests_are_rejected() {
    for header in [
        "Content-Length: 1\r\n",
        "Content-Length: 0\r\nContent-Length: 0\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Content-Length: nope\r\n",
        "Host: extra\r\n",
    ] {
        let text = format!("GET /health HTTP/1.1\r\nHost: localhost\r\n{header}\r\n");
        assert!(parse_request(text.as_bytes()).is_err(), "{header}");
    }
    assert!(parse_request(b"GET /health HTTP/1.1\r\n\r\n").is_err());
    assert!(
        parse_request(b"GET http://elsewhere/health HTTP/1.1\r\nHost: localhost\r\n\r\n").is_err()
    );
}

#[test]
fn fixed_buffer_and_response_format_preserve_every_category_field() {
    let mut small = Buffer::<3>::new();
    small.write_str("abc").unwrap();
    assert!(small.write_str("d").is_err());
    assert_eq!(small.as_bytes(), b"abc");
    small.clear();
    assert!(small.as_bytes().is_empty());
    let index = compile(
        &[
            Rule::new("ads.test", Scope::Domain, Action::Block, Category::ALL).unwrap(),
            Rule::new("ads.test", Scope::Domain, Action::Allow, Category::ALL).unwrap(),
            Rule::new("ads.test", Scope::Domain, Action::Enforce, Category::ALL).unwrap(),
        ],
        Limits::default(),
    )
    .unwrap();
    let mut body = Buffer::<64>::new();
    let (status, elapsed) =
        support::route_into(&index, "GET", "/check/127/ads.test", &mut body).unwrap();
    assert_eq!(status, 200);
    assert!(elapsed.is_some());
    assert_eq!(
        body.as_bytes(),
        br#"{"blocked":127,"allowed":127,"enforced":127}"#
    );
    let mut wire = Buffer::<512>::new();
    let request = parse_request(b"GET /check/127/ads.test HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap()
        .unwrap();
    wire::encode_reply(&index, &request, &mut wire).unwrap();
    let text = std::str::from_utf8(wire.as_bytes()).unwrap();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(text.contains(&format!("Content-Length: {}\r\n", body.as_bytes().len())));
    assert!(text.ends_with(std::str::from_utf8(body.as_bytes()).unwrap()));
    assert!(text.contains("X-Lookup-Ns: "));
}
