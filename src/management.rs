//! Optional, bounded, read-only loopback management. HTTP runs on a separate
//! runtime thread; only immutable policy metadata and atomic DNS counters cross it.
use crate::{
    keys::ManagementToken,
    server::{Stats, StatsSnapshot},
};
use http_body_util::Full;
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header,
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use std::{
    convert::Infallible,
    io,
    net::{SocketAddr, TcpListener},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{sync::oneshot, task::JoinSet};
use zeroize::Zeroizing;

const MAX_CONNECTIONS: usize = 8;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(3);
const ADMISSIONS_PER_SECOND: u32 = 64;

type Body = Full<Bytes>;

pub struct Management {
    address: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    finished: oneshot::Receiver<()>,
    thread: Option<thread::JoinHandle<io::Result<()>>>,
}

impl Management {
    /// Disabled unless explicitly started. No wildcard, LAN or public binds.
    pub fn start(
        address: SocketAddr,
        token: ManagementToken,
        stats: Arc<Stats>,
        rules: usize,
        index_bytes: usize,
    ) -> io::Result<Self> {
        if !address.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "management must bind a numeric loopback address",
            ));
        }
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let listener = {
            let _entered = runtime.enter();
            tokio::net::TcpListener::from_std(listener)?
        };
        let state = Arc::new(State {
            authority: address.to_string(),
            origin: http_origin(address),
            bearer: token.expose_bearer(),
            stats,
            started: Instant::now(),
            rules,
            index_bytes,
        });
        let (stop, mut stopping) = oneshot::channel();
        let (done, finished) = oneshot::channel();
        let thread = thread::Builder::new().name("dns-management".into()).spawn(move || {
            let result = runtime.block_on(async move {
                let mut tasks = JoinSet::new();
                let mut window = Instant::now();
                let mut admitted = 0;
                loop {
                    tokio::select! {
                        biased;
                        _ = &mut stopping => break,
                        _ = tasks.join_next(), if !tasks.is_empty() => {},
                        accepted = listener.accept() => {
                            let (socket, peer) = accepted?;
                            if !peer.ip().is_loopback() || tasks.len() >= MAX_CONNECTIONS { continue; }
                            if window.elapsed() >= Duration::from_secs(1) {
                                window = Instant::now();
                                admitted = 0;
                            }
                            // Bound all HTTP work, including unauthenticated/slow clients.
                            // Excess connections close before allocating a parser/task.
                            if admitted >= ADMISSIONS_PER_SECOND { continue; }
                            admitted += 1;
                            let state = state.clone();
                            tasks.spawn(async move {
                                let mut http = http1::Builder::new();
                                http.keep_alive(false).max_headers(32).max_buf_size(8192).max_header_size(8192);
                                let service = service_fn(move |req| {
                                    let response = state.respond(req);
                                    async { Ok::<_, Infallible>(response) }
                                });
                                let _ = tokio::time::timeout(CONNECTION_TIMEOUT,
                                    http.serve_connection(TokioIo::new(socket), service)).await;
                            });
                        }
                    }
                }
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                Ok(())
            });
            let _ = done.send(());
            result
        })?;
        Ok(Self {
            address,
            stop: Some(stop),
            finished,
            thread: Some(thread),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// Lets the DNS supervisor stop if the management thread unexpectedly exits.
    pub async fn stopped(&mut self) {
        let _ = (&mut self.finished).await;
    }

    pub fn shutdown(mut self) -> io::Result<()> {
        self.finish()
    }

    fn finish(&mut self) -> io::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            return thread
                .join()
                .map_err(|_| io::Error::other("management thread failed"))?;
        }
        Ok(())
    }
}
impl Drop for Management {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

struct State {
    authority: String,
    origin: String,
    bearer: Zeroizing<String>,
    stats: Arc<Stats>,
    started: Instant,
    rules: usize,
    index_bytes: usize,
}

#[derive(Serialize)]
struct Status {
    schema_version: u8,
    version: &'static str,
    uptime_seconds: u64,
    policy: Policy,
    dns: StatsSnapshot,
}
#[derive(Serialize)]
struct Policy {
    rules: usize,
    bytes: usize,
}

// Browsers omit the default HTTP port in Host and Origin. Keep the numeric
// address restriction while accepting both explicit and canonical port-80 Host.
fn http_origin(address: SocketAddr) -> String {
    if address.port() == 80 {
        match address.ip() {
            std::net::IpAddr::V4(ip) => format!("http://{ip}"),
            std::net::IpAddr::V6(ip) => format!("http://[{ip}]"),
        }
    } else {
        format!("http://{address}")
    }
}

impl State {
    fn accepts_origin(&self, headers: &header::HeaderMap) -> bool {
        let host = single(headers, "host");
        (host == Some(self.authority.as_bytes()) || host == Some(&self.origin.as_bytes()[7..]))
            && (!headers.contains_key("origin")
                || single(headers, "origin") == Some(self.origin.as_bytes()))
            && (!headers.contains_key("sec-fetch-site")
                || matches!(
                    single(headers, "sec-fetch-site"),
                    Some(b"same-origin" | b"none")
                ))
    }

    fn respond(&self, req: Request<Incoming>) -> Response<Body> {
        let headers = req.headers();
        // Require the exact numeric origin advertised at startup. No forwarded
        // host trust or CORS exceptions, including for the public login shell.
        if !self.accepts_origin(headers) {
            return error(StatusCode::FORBIDDEN, "origin rejected");
        }
        if req.method() != hyper::Method::GET {
            let mut response = error(StatusCode::METHOD_NOT_ALLOWED, "read-only endpoint");
            response
                .headers_mut()
                .insert(header::ALLOW, header::HeaderValue::from_static("GET"));
            return response;
        }
        if req.uri().query().is_some()
            || req.uri().authority().is_some()
            || headers.contains_key(header::TRANSFER_ENCODING)
            || headers.contains_key(header::EXPECT)
            || (headers.contains_key(header::CONTENT_LENGTH)
                && single(headers, "content-length") != Some(b"0"))
        {
            return error(
                StatusCode::BAD_REQUEST,
                "bodies and query parameters are not accepted",
            );
        }
        match req.uri().path() {
            "/" => response(
                StatusCode::OK,
                "text/html; charset=utf-8",
                Bytes::from_static(include_bytes!("../web/index.html")),
            ),
            "/app.js" => response(
                StatusCode::OK,
                "text/javascript; charset=utf-8",
                Bytes::from_static(include_bytes!("../web/app.js")),
            ),
            "/app.css" => response(
                StatusCode::OK,
                "text/css; charset=utf-8",
                Bytes::from_static(include_bytes!("../web/app.css")),
            ),
            "/api/v1/status" => {
                let supplied = single(headers, "authorization")
                    .and_then(|value| value.strip_prefix(b"Bearer "));
                if !supplied.is_some_and(|value| bool::from(value.ct_eq(self.bearer.as_bytes()))) {
                    let mut response = error(StatusCode::UNAUTHORIZED, "authentication required");
                    response.headers_mut().insert(
                        header::WWW_AUTHENTICATE,
                        header::HeaderValue::from_static("Bearer"),
                    );
                    return response;
                }
                let status = Status {
                    schema_version: 1,
                    version: env!("CARGO_PKG_VERSION"),
                    uptime_seconds: self.started.elapsed().as_secs(),
                    policy: Policy {
                        rules: self.rules,
                        bytes: self.index_bytes,
                    },
                    dns: self.stats.snapshot(),
                };
                match serde_json::to_vec(&status) {
                    Ok(bytes) => response(StatusCode::OK, "application/json", Bytes::from(bytes)),
                    Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "status unavailable"),
                }
            }
            _ => error(StatusCode::NOT_FOUND, "not found"),
        }
    }
}
fn single<'a>(headers: &'a header::HeaderMap, name: &str) -> Option<&'a [u8]> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    if values.next().is_some() {
        None
    } else {
        Some(first.as_bytes())
    }
}
fn error(code: StatusCode, message: &'static str) -> Response<Body> {
    response(
        code,
        "text/plain; charset=utf-8",
        Bytes::from_static(message.as_bytes()),
    )
}
fn response(code: StatusCode, mime: &'static str, body: Bytes) -> Response<Body> {
    Response::builder().status(code)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, "no-store")
        .header("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        .header("x-content-type-options", "nosniff")
        .header("x-frame-options", "DENY")
        .header("referrer-policy", "no-referrer")
        .header(header::CONNECTION, "close")
        .body(Full::new(body)).expect("static response headers are valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_http_port_matches_browser_origin_normalization() {
        for (address, host) in [("127.0.0.1:80", "127.0.0.1"), ("[::1]:80", "[::1]")] {
            let state = State {
                authority: address.into(),
                origin: http_origin(address.parse().unwrap()),
                bearer: Zeroizing::new(String::new()),
                stats: Arc::new(Stats::default()),
                started: Instant::now(),
                rules: 0,
                index_bytes: 0,
            };
            for allowed_host in [address, host] {
                let mut headers = header::HeaderMap::new();
                headers.insert("host", allowed_host.parse().unwrap());
                headers.insert("origin", format!("http://{host}").parse().unwrap());
                assert!(state.accepts_origin(&headers));
                headers.insert("host", "evil.example".parse().unwrap());
                assert!(!state.accepts_origin(&headers));
            }
        }
    }
}
