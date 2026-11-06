//! Loopback-only k6 adapter, not the product API or a DNS server.
use dns_guard::{Index, Limits};
use std::{net::SocketAddr, path::Path};
use tiny_http::{Header, Response, Server, StatusCode};

mod support;
use support::route;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args.len() > 3 {
        return Err("usage: load_server INDEX [127.0.0.1:8787] [WORKERS=4]".into());
    }
    let address: SocketAddr = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("127.0.0.1:8787")
        .parse()?;
    if !address.ip().is_loopback() {
        return Err("test harness must bind to loopback".into());
    }
    let workers = args
        .get(2)
        .map(|s| s.parse::<usize>())
        .transpose()?
        .unwrap_or(4);
    if !(1..=64).contains(&workers) {
        return Err("workers must be in 1..=64".into());
    }
    let index = Index::load(Path::new(&args[0]), Limits::default().max_index_bytes)?;
    let server = Server::http(address)?;
    eprintln!(
        "k6 harness listening on http://{address}, workers={workers}, rules={}",
        index.rule_count()
    );
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let (server, index) = (&server, &index);
            scope.spawn(move || {
                while let Ok(request) = server.recv() {
                    let (status, body, elapsed) =
                        route(index, request.method().as_str(), request.url());
                    let mut response =
                        Response::from_string(body).with_status_code(StatusCode(status));
                    if let Some(ns) = elapsed {
                        response.add_header(
                            Header::from_bytes("X-Lookup-Ns", ns.to_string())
                                .expect("numeric timing header"),
                        );
                        response.add_header(
                            Header::from_bytes("Content-Type", "application/json")
                                .expect("static header"),
                        );
                    }
                    // Client disconnects do not terminate a worker.
                    let _ = request.respond(response);
                }
            });
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_guard::{Action, Category, Limits, Rule, Scope, compile};

    #[test]
    fn harness_exposes_decisions_timing_and_validates_requests() {
        let index = compile(
            &[
                Rule::new("ads.example", Scope::Domain, Action::Block, Category::ADS).unwrap(),
                Rule::new(
                    "safe.ads.example",
                    Scope::Domain,
                    Action::Allow,
                    Category::ADS,
                )
                .unwrap(),
            ],
            Limits::default(),
        )
        .unwrap();
        let (status, body, timing) = route(&index, "GET", "/check/1/ads.example");
        assert_eq!(status, 200);
        assert_eq!(body, "{\"blocked\":1,\"allowed\":0,\"enforced\":0}");
        assert!(timing.is_some());
        assert!(
            route(&index, "GET", "/check/1/safe.ads.example")
                .1
                .contains("\"blocked\":0")
        );
        assert_eq!(route(&index, "GET", "/check/128/ads.example").0, 400);
        assert_eq!(route(&index, "GET", "/check/1/bad..name").0, 400);
        assert_eq!(route(&index, "GET", "/check/1/a.example?x=1").0, 400);
        assert_eq!(route(&index, "POST", "/check/1/ads.example").0, 405);
        assert_eq!(route(&index, "GET", "/missing").0, 404);
        assert_eq!(route(&index, "GET", "/health").0, 200);
    }
}
