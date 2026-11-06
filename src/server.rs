//! Bounded DNS forwarding with one immutable policy snapshot and explicit client ACLs.
//! Bounded response caching; no recursive iteration, DNSSEC validation or query history.
use crate::{
    Category, Index,
    cache::{Cache, MAX_CACHE_BYTES, Usage, cache_key},
};
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, ResponseCode},
    rr::{DNSClass, RData, RecordType},
    serialize::binary::{BinDecodable, BinDecoder},
};
use ipnet::IpNet;
use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::timeout,
};

const MAX_QUERY: usize = 4096;
const UDP_PAYLOAD: u16 = 1232;
const TCP_IDLE: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub upstream: SocketAddr,
    pub categories: u32,
    pub max_inflight: usize,
    pub max_tcp_connections: usize,
    /// Cache-owned table and payload byte limit; zero disables caching.
    pub cache_bytes: usize,
    /// One deadline covering upstream connect, UDP receive, and TCP fallback.
    pub timeout: Duration,
    pub allowed_clients: Vec<IpNet>,
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:5353".parse().unwrap(),
            upstream: "127.0.0.1:53".parse().unwrap(),
            categories: Category::ALL,
            max_inflight: 64,
            max_tcp_connections: 32,
            cache_bytes: 256 * 1024,
            timeout: Duration::from_secs(2),
            allowed_clients: vec!["127.0.0.0/8".parse().unwrap(), "::1/128".parse().unwrap()],
        }
    }
}
impl ServerConfig {
    fn validate(&self) -> io::Result<()> {
        if !(1..=4096).contains(&self.max_inflight)
            || !(1..=1024).contains(&self.max_tcp_connections)
            || (self.cache_bytes != 0 && !(4096..=MAX_CACHE_BYTES).contains(&self.cache_bytes))
            || self.timeout.is_zero()
            || self.timeout > Duration::from_secs(30)
            || self.categories & !Category::ALL != 0
            || self.allowed_clients.is_empty()
            || self.allowed_clients.len() > 32
            || self.upstream.port() == 0
            || self.upstream.ip().is_unspecified()
            || self.upstream.ip().is_multicast()
            || self.upstream.ip() == IpAddr::from([255, 255, 255, 255])
            || (self.upstream.port() == self.listen.port()
                && (self.upstream.ip() == self.listen.ip()
                    || (self.listen.ip().is_unspecified() && self.upstream.ip().is_loopback())))
        {
            return Err(invalid(
                "invalid DNS limits, access list, or upstream address",
            ));
        }
        Ok(())
    }
    fn permits(&self, peer: IpAddr) -> bool {
        let peer = match peer {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(peer),
            _ => peer,
        };
        self.allowed_clients
            .iter()
            .any(|network| network.contains(&peer))
    }
}

#[derive(Default)]
pub struct Stats {
    received: AtomicU64,
    blocked: AtomicU64,
    forwarded: AtomicU64,
    upstream_errors: AtomicU64,
    invalid: AtomicU64,
    overloaded: AtomicU64,
    denied: AtomicU64,
    send_errors: AtomicU64,
    inflight: AtomicU64,
    peak_inflight: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    cache_entries: AtomicU64,
    cache_bytes: AtomicU64,
    cache_evictions: AtomicU64,
}
/// Approximate concurrent counters, not a transactional snapshot. No hostnames retained.
#[derive(Debug, Clone, Copy)]
pub struct StatsSnapshot {
    pub received: u64,
    pub blocked: u64,
    pub forwarded: u64,
    pub upstream_errors: u64,
    pub invalid: u64,
    pub overloaded: u64,
    pub denied: u64,
    pub send_errors: u64,
    pub inflight: u64,
    pub peak_inflight: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_entries: u64,
    pub cache_bytes: u64,
    pub cache_evictions: u64,
}
impl Stats {
    fn cache_usage(&self, usage: Usage) {
        self.cache_entries.store(usage.entries as u64, Relaxed);
        self.cache_bytes.store(usage.bytes as u64, Relaxed);
        self.cache_evictions.store(usage.evictions, Relaxed);
    }
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            received: self.received.load(Relaxed),
            blocked: self.blocked.load(Relaxed),
            forwarded: self.forwarded.load(Relaxed),
            upstream_errors: self.upstream_errors.load(Relaxed),
            invalid: self.invalid.load(Relaxed),
            overloaded: self.overloaded.load(Relaxed),
            denied: self.denied.load(Relaxed),
            send_errors: self.send_errors.load(Relaxed),
            inflight: self.inflight.load(Relaxed),
            peak_inflight: self.peak_inflight.load(Relaxed),
            cache_hits: self.cache_hits.load(Relaxed),
            cache_misses: self.cache_misses.load(Relaxed),
            cache_entries: self.cache_entries.load(Relaxed),
            cache_bytes: self.cache_bytes.load(Relaxed),
            cache_evictions: self.cache_evictions.load(Relaxed),
        }
    }
}
struct Inflight {
    _permit: OwnedSemaphorePermit,
    stats: Arc<Stats>,
}
impl Drop for Inflight {
    fn drop(&mut self) {
        self.stats.inflight.fetch_sub(1, Relaxed);
    }
}
struct State {
    config: ServerConfig,
    index: Arc<Index>,
    stats: Arc<Stats>,
    queries: Arc<Semaphore>,
    cache: Mutex<Cache>,
}
impl State {
    fn acquire(&self) -> Option<Inflight> {
        let permit = match self.queries.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.stats.overloaded.fetch_add(1, Relaxed);
                return None;
            }
        };
        let current = self.stats.inflight.fetch_add(1, Relaxed) + 1;
        self.stats.peak_inflight.fetch_max(current, Relaxed);
        Some(Inflight {
            _permit: permit,
            stats: self.stats.clone(),
        })
    }
}

pub struct Server {
    udp: Arc<UdpSocket>,
    tcp: TcpListener,
    state: Arc<State>,
}
impl Server {
    /// Bind both transports before serving; port zero selects one shared free port.
    pub async fn bind(config: ServerConfig, index: Arc<Index>) -> io::Result<Self> {
        config.validate()?;
        let tcp = TcpListener::bind(config.listen).await?;
        let address = tcp.local_addr()?;
        if address == config.upstream {
            return Err(invalid("upstream points to this listener"));
        }
        let udp = Arc::new(UdpSocket::bind(address).await?);
        let queries = Arc::new(Semaphore::new(config.max_inflight));
        let cache = Cache::new(config.cache_bytes);
        let stats = Arc::new(Stats::default());
        stats.cache_usage(cache.usage());
        Ok(Self {
            udp,
            tcp,
            state: Arc::new(State {
                config,
                index,
                queries,
                stats,
                cache: Mutex::new(cache),
            }),
        })
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tcp.local_addr()
    }
    pub fn stats(&self) -> Arc<Stats> {
        self.state.stats.clone()
    }

    /// Stop accepts and cancel/drain outstanding tasks when shutdown resolves.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> io::Result<()> {
        tokio::pin!(shutdown);
        let connections = Arc::new(Semaphore::new(self.state.config.max_tcp_connections));
        let mut tasks = JoinSet::new();
        let mut bytes = [0; MAX_QUERY + 1];
        loop {
            // Completed tasks must not accumulate when receiving continuous traffic.
            while tasks.try_join_next().is_some() {}
            tokio::select! {
                _ = &mut shutdown => break,
                received = self.udp.recv_from(&mut bytes) => {
                    let (n, peer) = received?;
                    self.state.stats.received.fetch_add(1, Relaxed);
                    if !self.state.config.permits(peer.ip()) { self.state.stats.denied.fetch_add(1, Relaxed); continue; }
                    if n > MAX_QUERY { self.state.stats.invalid.fetch_add(1, Relaxed); continue; }
                    let Some(permit) = self.state.acquire() else { continue; };
                    let packet = bytes[..n].to_vec();
                    let state = self.state.clone(); let socket = self.udp.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Some(response) = handle(&state, &packet, false).await
                            && !matches!(timeout(state.config.timeout, socket.send_to(&response, peer)).await, Ok(Ok(_))) { state.stats.send_errors.fetch_add(1, Relaxed); }
                    });
                }
                accepted = self.tcp.accept() => {
                    let (socket, peer) = accepted?;
                    if !self.state.config.permits(peer.ip()) { self.state.stats.denied.fetch_add(1, Relaxed); continue; }
                    let Ok(permit) = connections.clone().try_acquire_owned() else { self.state.stats.overloaded.fetch_add(1, Relaxed); continue; };
                    socket.set_nodelay(true)?;
                    let state = self.state.clone();
                    tasks.spawn(async move { let _permit = permit; serve_tcp(socket, state).await; });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}

async fn serve_tcp(mut socket: TcpStream, state: Arc<State>) {
    loop {
        // A deadline covers the whole frame, including its length prefix.
        let packet = match timeout(TCP_IDLE, read_frame(&mut socket, MAX_QUERY)).await {
            Ok(Ok(packet)) => packet,
            _ => return,
        };
        state.stats.received.fetch_add(1, Relaxed);
        let Some(_permit) = state.acquire() else {
            return;
        };
        let Some(response) = handle(&state, &packet, true).await else {
            return;
        };
        if !matches!(
            timeout(TCP_IDLE, write_frame(&mut socket, &response)).await,
            Ok(Ok(()))
        ) {
            state.stats.send_errors.fetch_add(1, Relaxed);
            return;
        }
    }
}
async fn read_frame(socket: &mut TcpStream, ceiling: usize) -> io::Result<Vec<u8>> {
    let n = socket.read_u16().await? as usize;
    if !(12..=ceiling).contains(&n) {
        return Err(invalid("DNS frame length outside limits"));
    }
    let mut bytes = vec![0; n];
    socket.read_exact(&mut bytes).await?;
    Ok(bytes)
}
async fn write_frame(socket: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
    let n = u16::try_from(bytes.len()).map_err(|_| invalid("DNS response too large"))?;
    socket.write_u16(n).await?;
    socket.write_all(bytes).await
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn decode(bytes: &[u8]) -> io::Result<Message> {
    let mut decoder = BinDecoder::new(bytes);
    let message = Message::read(&mut decoder).map_err(io::Error::other)?;
    if decoder.index() != bytes.len() {
        return Err(invalid("trailing DNS data"));
    }
    Ok(message)
}
fn local_reply(request: &Message, code: ResponseCode, truncated: bool) -> Vec<u8> {
    let mut response = Message::error_msg(request.metadata.id, request.metadata.op_code, code);
    response.queries = request.queries.clone();
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.checking_disabled = request.metadata.checking_disabled;
    response.metadata.recursion_available = true;
    response.metadata.truncation = truncated;
    if let Some(edns) = &request.edns {
        response.set_edns(
            Edns::new()
                .set_max_payload(UDP_PAYLOAD)
                .set_dnssec_ok(edns.flags().dnssec_ok)
                .clone(),
        );
    }
    response.to_vec().expect("bounded validated DNS question")
}

async fn handle(state: &State, bytes: &[u8], tcp: bool) -> Option<Vec<u8>> {
    if bytes.len() < 12 || bytes[2] & 0x80 != 0 {
        state.stats.invalid.fetch_add(1, Relaxed);
        return None;
    }
    // Reject large section counts before allocating parsed records. Only one
    // question and at most one additional (OPT) are supported for requests.
    let counts = [
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        u16::from_be_bytes([bytes[10], bytes[11]]),
    ];
    let parsed = if counts[0] == 1 && counts[1] == 0 && counts[2] == 0 && counts[3] <= 1 {
        decode(bytes).ok()
    } else {
        None
    };
    let Some(request) = parsed else {
        state.stats.invalid.fetch_add(1, Relaxed);
        let mut response = vec![0; 12];
        response[..2].copy_from_slice(&bytes[..2]);
        response[2] = 0x80 | (bytes[2] & 0x79);
        response[3] = 0x81;
        return Some(response);
    };
    if request.metadata.op_code != OpCode::Query {
        return Some(local_reply(&request, ResponseCode::NotImp, false));
    }
    if request.version() != 0 {
        return Some(local_reply(&request, ResponseCode::BADVERS, false));
    }
    let query = &request.queries[0];
    if !request.metadata.recursion_desired
        || request.metadata.truncation
        || request.metadata.response_code != ResponseCode::NoError
        || query.query_class != DNSClass::IN
        || matches!(query.query_type, RecordType::AXFR | RecordType::IXFR)
        || request.signature.is_some()
        || !request.additionals.is_empty()
    {
        return Some(local_reply(&request, ResponseCode::Refused, false));
    }
    if state
        .index
        .check_dns_labels(query.name.iter(), state.config.categories)
        .ok()?
        .is_blocked()
    {
        state.stats.blocked.fetch_add(1, Relaxed);
        return Some(local_reply(&request, ResponseCode::Refused, false));
    }
    let key = if state.config.cache_bytes == 0 {
        None
    } else {
        cache_key(&request)
    };
    if let Some(key) = &key {
        // This short cache lock never crosses an await or protects DNS I/O.
        let hit = {
            let mut cache = state.cache.lock().expect("cache lock poisoned");
            let hit = cache.get(key, request.metadata.id, Instant::now());
            state.stats.cache_usage(cache.usage());
            hit
        };
        if let Some(bytes) = hit {
            state.stats.cache_hits.fetch_add(1, Relaxed);
            return Some(client_reply(&request, bytes, tcp));
        }
        state.stats.cache_misses.fetch_add(1, Relaxed);
    }
    let result = timeout(
        state.config.timeout,
        forward(&request, state.config.upstream, tcp),
    )
    .await;
    match result {
        Ok(Ok((bytes, response))) => {
            // Apply the same category policy to CNAME destinations before
            // returning an alias answer. Each name keeps its own allow rules.
            for record in &response.answers {
                if let RData::CNAME(target) = &record.data
                    && state
                        .index
                        .check_dns_labels(target.0.iter(), state.config.categories)
                        .ok()?
                        .is_blocked()
                {
                    state.stats.blocked.fetch_add(1, Relaxed);
                    return Some(local_reply(&request, ResponseCode::Refused, false));
                }
            }
            if let Some(key) = key {
                let mut cache = state.cache.lock().expect("cache lock poisoned");
                cache.insert(key, &bytes, &response, Instant::now());
                state.stats.cache_usage(cache.usage());
            }
            state.stats.forwarded.fetch_add(1, Relaxed);
            Some(client_reply(&request, bytes, tcp))
        }
        _ => {
            state.stats.upstream_errors.fetch_add(1, Relaxed);
            Some(local_reply(&request, ResponseCode::ServFail, false))
        }
    }
}
fn client_reply(request: &Message, mut bytes: Vec<u8>, tcp: bool) -> Vec<u8> {
    if !tcp && bytes.len() > usize::from(request.max_payload().clamp(512, UDP_PAYLOAD)) {
        return local_reply(request, ResponseCode::NoError, true);
    }
    // Preserve record bytes/compression offsets; plain upstream DNS is not
    // independently authenticated. The cache additionally ages real RR TTLs.
    bytes[..2].copy_from_slice(&request.metadata.id.to_be_bytes());
    bytes[3] &= !0x20;
    bytes
}

fn matches_response(response: &Message, request: &Message) -> bool {
    response.metadata.message_type == MessageType::Response
        && response.metadata.id == request.metadata.id
        && response.metadata.op_code == request.metadata.op_code
        && response.queries == request.queries
        && response.signature.is_none()
}
async fn forward(
    request: &Message,
    upstream: SocketAddr,
    tcp: bool,
) -> io::Result<(Vec<u8>, Message)> {
    let mut request = request.clone();
    // Hickory uses its OS-seeded thread RNG, independently of client IDs.
    request.metadata.id = Message::query().metadata.id;
    if let Some(edns) = &mut request.edns {
        edns.set_max_payload(UDP_PAYLOAD);
    }
    let outgoing = request.to_vec().map_err(io::Error::other)?;
    if !tcp {
        let socket = UdpSocket::bind(if upstream.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        socket.connect(upstream).await?; // Kernel validates response address and port.
        socket.send(&outgoing).await?;
        let mut bytes = vec![0; MAX_QUERY + 1];
        loop {
            let n = socket.recv(&mut bytes).await?;
            if n > MAX_QUERY {
                continue;
            }
            let Ok(response) = decode(&bytes[..n]) else {
                continue;
            };
            if !matches_response(&response, &request) {
                continue;
            }
            if response.metadata.truncation {
                break;
            }
            bytes.truncate(n);
            return Ok((bytes, response));
        }
    }
    let mut socket = TcpStream::connect(upstream).await?;
    socket.set_nodelay(true)?;
    write_frame(&mut socket, &outgoing).await?;
    let bytes = read_frame(&mut socket, u16::MAX as usize).await?;
    let response = decode(&bytes)?;
    if !matches_response(&response, &request) || response.metadata.truncation {
        return Err(invalid("invalid upstream TCP response"));
    }
    Ok((bytes, response))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wildcard_listener_can_use_a_remote_upstream_on_the_same_port() {
        let mut config = ServerConfig {
            listen: "0.0.0.0:53".parse().unwrap(),
            upstream: "192.0.2.53:53".parse().unwrap(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
        config.upstream = "127.0.0.1:53".parse().unwrap();
        assert!(config.validate().is_err());
    }
}
