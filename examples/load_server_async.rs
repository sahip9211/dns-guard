//! Async, bounded loopback k6 adapter. Not the production management API.
use dns_guard::{Index, Limits};
use http_body_util::Full;
use hyper::{
    Request, Response, body::Bytes, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{convert::Infallible, io, net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpSocket},
    sync::Semaphore,
};
mod support;

fn runtime_for_workers(workers: usize) -> io::Result<tokio::runtime::Runtime> {
    if !(1..=64).contains(&workers) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workers must be in 1..=64",
        ));
    }
    let mut builder = if workers == 1 {
        tokio::runtime::Builder::new_current_thread()
    } else {
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.worker_threads(workers);
        builder
    };
    builder.enable_all().build()
}

fn bounded_listener(address: SocketAddr, backlog: u32) -> io::Result<TcpListener> {
    if !address.ip().is_loopback() || !(1..=4096).contains(&backlog) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "loopback and backlog in 1..=4096 required",
        ));
    }
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    // Match TcpListener::bind's Unix restart semantics without applying Unix
    // SO_REUSEADDR semantics to Windows.
    #[cfg(unix)]
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(backlog)
}

fn response(index: &Index, method: &str, url: &str) -> Response<Full<Bytes>> {
    let (status, body, elapsed) = support::route(index, method, url);
    let mut builder = Response::builder().status(status);
    if let Some(ns) = elapsed {
        builder = builder
            .header("x-lookup-ns", ns.to_string())
            .header("content-type", "application/json");
    }
    builder
        .body(Full::new(Bytes::from(body)))
        .expect("valid static headers and numeric timing")
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args.len() > 3 {
        return Err("usage: load_server_async INDEX [127.0.0.1:8787] [WORKERS=4]".into());
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
    let index = Arc::new(Index::load(
        Path::new(&args[0]),
        Limits::default().max_index_bytes,
    )?);
    runtime_for_workers(workers)?.block_on(async move {
        // Pending TCP accepts form the bounded ingress queue. At the active
        // connection limit, stop accepting instead of allocating more tasks.
        let listener = bounded_listener(address, 128)?;
        let permits = Arc::new(Semaphore::new(2048));
        eprintln!("async k6 harness listening on http://{address}, workers={workers}, rules={}, max_connections=2048, accept_backlog=128", index.rule_count());
        loop {
            // Bound active connection tasks; idle clients consume no OS thread.
            let permit = permits.clone().acquire_owned().await?;
            let (socket, _) = listener.accept().await?;
            socket.set_nodelay(true)?;
            let index = index.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let service = service_fn(move |request: Request<Incoming>| {
                    let result = response(&index, request.method().as_str(), request.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/"));
                    std::future::ready(Ok::<_, Infallible>(result))
                });
                // Keep parsing in Hyper; cap headers/buffers and header wait.
                let _ = http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(Duration::from_secs(10))
                    .max_headers(32)
                    .max_buf_size(8192)
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_guard::{Action, Category, Limits, Rule, Scope, compile};

    #[test]
    fn one_worker_stays_on_caller_thread_and_parallelism_is_explicit() {
        let rt = runtime_for_workers(1).unwrap();
        let caller = std::thread::current().id();
        assert_eq!(
            rt.block_on(async {
                tokio::spawn(async { std::thread::current().id() })
                    .await
                    .unwrap()
            }),
            caller
        );
        let parallel = runtime_for_workers(2).unwrap();
        assert_eq!(parallel.metrics().num_workers(), 2);
        assert_eq!(
            parallel.handle().runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        );
        assert!(runtime_for_workers(0).is_err());
        assert!(runtime_for_workers(65).is_err());
    }

    #[test]
    fn bounded_listener_accepts_loopback_and_rejects_invalid_backlogs() {
        let rt = runtime_for_workers(1).unwrap();
        rt.block_on(async {
            let addr = "127.0.0.1:0".parse().unwrap();
            assert!(bounded_listener(addr, 0).is_err());
            assert!(bounded_listener(addr, 4097).is_err());
            assert!(bounded_listener("0.0.0.0:0".parse().unwrap(), 128).is_err());
            let listener = bounded_listener(addr, 128).unwrap();
            let destination = listener.local_addr().unwrap();
            let client = tokio::net::TcpStream::connect(destination).await.unwrap();
            let (_, peer) = listener.accept().await.unwrap();
            assert_eq!(peer, client.local_addr().unwrap());
        });
    }

    #[test]
    fn async_adapter_preserves_routes_errors_and_timing() {
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
        let reply = response(&index, "GET", "/check/1/ads.example");
        assert_eq!(reply.status(), 200);
        assert_eq!(reply.headers()["content-type"], "application/json");
        assert!(
            reply.headers()["x-lookup-ns"]
                .to_str()
                .unwrap()
                .parse::<u128>()
                .is_ok()
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let body = runtime
            .block_on(http_body_util::BodyExt::collect(reply.into_body()))
            .unwrap()
            .to_bytes();
        assert_eq!(body, "{\"blocked\":1,\"allowed\":0,\"enforced\":0}");
        assert_eq!(
            response(&index, "POST", "/check/1/ads.example").status(),
            405
        );
        assert_eq!(
            response(&index, "GET", "/check/128/ads.example").status(),
            400
        );
        assert_eq!(response(&index, "GET", "/check/1/a..example").status(), 400);
        assert_eq!(
            response(&index, "GET", "/check/1/ads.example?x=1").status(),
            400
        );
        assert_eq!(response(&index, "GET", "/missing").status(), 404);
        assert_eq!(response(&index, "GET", "/health").status(), 200);
    }
}
