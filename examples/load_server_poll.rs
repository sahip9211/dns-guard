//! Safe, portable readiness-loop experiment. Loopback-only, restricted HTTP.
#![forbid(unsafe_code)]
use dns_guard::{Index, Limits};
use mio::{
    Events, Interest, Poll, Token,
    net::{TcpListener, TcpStream},
};
use std::{
    collections::{HashMap, VecDeque},
    io::{self, Read, Write},
    net::SocketAddr,
    path::Path,
    time::{Duration, Instant},
};
mod support;
#[path = "support/wire.rs"]
mod wire;

#[cfg(test)]
mod tests {
    use super::*;
    use dns_guard::{Action, Category, Rule, Scope, compile};
    #[test]
    fn partial_writes_resume_without_duplication() {
        struct Short {
            bytes: Vec<u8>,
            writable: bool,
        }
        impl Write for Short {
            fn write(&mut self, input: &[u8]) -> io::Result<usize> {
                if !self.writable {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                self.writable = false;
                let n = input.len().min(3);
                self.bytes.extend_from_slice(&input[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = Short {
            bytes: Vec::new(),
            writable: true,
        };
        let mut pos = 0;
        assert!(!flush_pending(&mut writer, b"abcdefgh", &mut pos).unwrap());
        assert_eq!(pos, 3);
        writer.writable = true;
        assert!(!flush_pending(&mut writer, b"abcdefgh", &mut pos).unwrap());
        writer.writable = true;
        assert!(flush_pending(&mut writer, b"abcdefgh", &mut pos).unwrap());
        assert_eq!(writer.bytes, b"abcdefgh");
    }
    #[test]
    fn partial_socket_reads_and_pipelined_replies_preserve_order_and_close() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (socket, _) = listener.accept().unwrap();
        socket.set_nonblocking(true).unwrap();
        let mut connection = Connection::new(TcpStream::from_std(socket));
        let mut poll = Poll::new().unwrap();
        poll.registry()
            .register(
                &mut connection.socket,
                Token(0),
                Interest::READABLE.add(Interest::WRITABLE),
            )
            .unwrap();
        let mut events = Events::with_capacity(8);
        let index = compile(
            &[Rule::new("ads.test", Scope::Domain, Action::Block, Category::ADS).unwrap()],
            Limits::default(),
        )
        .unwrap();
        client.write_all(b"GET /check/1/").unwrap();
        assert!(matches!(connection.drive(&index).unwrap(), State::Read));
        client.write_all(b"ads.test HTTP/1.1\r\nHost: local\r\n\r\nGET /health HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n").unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if matches!(connection.drive(&index).unwrap(), State::Close) {
                break;
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("socket did not finish before the test deadline");
            poll.poll(&mut events, Some(remaining)).unwrap();
        }
        drop(connection);
        let mut text = String::new();
        client.read_to_string(&mut text).unwrap();
        assert_eq!(text.matches("HTTP/1.1 200 OK").count(), 2);
        assert!(text.contains("{\"blocked\":1,\"allowed\":0,\"enforced\":0}HTTP/1.1 200 OK"));
        assert!(text.ends_with("\r\n\r\nok"));
    }
}

const MAX_CONNECTIONS: usize = 2048;
const MAX_HEADER: usize = 8192;
enum State {
    Read,
    Write,
    Again,
    Close,
}
struct Connection {
    socket: TcpStream,
    input: Vec<u8>,
    used: usize,
    output: wire::Buffer<512>,
    sent: usize,
    close: bool,
    queued: bool,
    writable: bool,
    activity: Instant,
}

fn flush_pending(writer: &mut impl Write, bytes: &[u8], sent: &mut usize) -> io::Result<bool> {
    while *sent < bytes.len() {
        match writer.write(&bytes[*sent..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => *sent += n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}
impl Connection {
    fn new(socket: TcpStream) -> Self {
        Self {
            socket,
            input: vec![0; 1024],
            used: 0,
            output: wire::Buffer::new(),
            sent: 0,
            close: false,
            queued: false,
            writable: false,
            activity: Instant::now(),
        }
    }
    fn reject(&mut self) -> io::Result<()> {
        use std::fmt::Write as _;
        self.output.clear();
        self.sent = 0;
        self.close = true;
        self.output.write_str("HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\nbad request")
            .map_err(io::Error::other)
    }
    fn drive(&mut self, index: &Index) -> io::Result<State> {
        let mut processed = 0;
        loop {
            if !self.output.as_bytes().is_empty() {
                if !flush_pending(&mut self.socket, self.output.as_bytes(), &mut self.sent)? {
                    return Ok(State::Write);
                }
                self.activity = Instant::now();
                self.output.clear();
                self.sent = 0;
            }
            if self.close {
                return Ok(State::Close);
            }
            if processed == 16 {
                return Ok(State::Again);
            }
            match wire::parse_request(&self.input[..self.used]) {
                Ok(Some(request)) => {
                    wire::encode_reply(index, &request, &mut self.output)
                        .map_err(io::Error::other)?;
                    self.close = request.close;
                    let consumed = request.used;
                    self.input.copy_within(consumed..self.used, 0);
                    self.used -= consumed;
                    processed += 1;
                    continue;
                }
                Err(_) => {
                    self.reject()?;
                    continue;
                }
                Ok(None) => {}
            }
            if self.used == self.input.len() {
                if self.input.len() == MAX_HEADER {
                    self.reject()?;
                    continue;
                }
                self.input.resize((self.input.len() * 2).min(MAX_HEADER), 0);
            }
            match self.socket.read(&mut self.input[self.used..]) {
                Ok(0) => return Ok(State::Close),
                Ok(n) => {
                    self.used += n;
                    self.activity = Instant::now();
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(State::Read),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args.len() > 3 {
        return Err("usage: load_server_poll INDEX [127.0.0.1:8787] [WORKERS=1]".into());
    }
    if args.get(2).is_some_and(|n| n != "1") {
        return Err("poll experiment uses exactly one worker".into());
    }
    let address: SocketAddr = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("127.0.0.1:8787")
        .parse()?;
    if !address.ip().is_loopback() {
        return Err("loopback required".into());
    }
    let index = Index::load(Path::new(&args[0]), Limits::default().max_index_bytes)?;
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);
    let mut listener = TcpListener::bind(address)?;
    poll.registry()
        .register(&mut listener, Token(0), Interest::READABLE)?;
    let mut connections: HashMap<Token, Connection> = HashMap::with_capacity(256);
    let mut ready = VecDeque::with_capacity(MAX_CONNECTIONS);
    let mut token = 1_usize;
    let mut last_expiry = Instant::now();
    eprintln!(
        "poll k6 harness listening on http://{address}, workers=1, rules={}, max_connections={MAX_CONNECTIONS}",
        index.rule_count()
    );
    loop {
        let timeout = if ready.is_empty() {
            Duration::from_secs(1)
        } else {
            Duration::ZERO
        };
        match poll.poll(&mut events, Some(timeout)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
        for event in &events {
            if event.token() == Token(0) {
                loop {
                    match listener.accept() {
                        Ok((mut socket, _)) => {
                            if connections.len() == MAX_CONNECTIONS {
                                continue;
                            }
                            socket.set_nodelay(true)?;
                            let id = Token(token);
                            token = token.checked_add(1).ok_or("connection token overflow")?;
                            poll.registry()
                                .register(&mut socket, id, Interest::READABLE)?;
                            connections.insert(id, Connection::new(socket));
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e.into()),
                    }
                }
            } else if let Some(c) = connections.get_mut(&event.token()) {
                if !c.queued {
                    c.queued = true;
                    ready.push_back(event.token());
                }
            }
        }
        // Fair bounded work: at most 256 ready connections, 16 replies each.
        for _ in 0..ready.len().min(256) {
            let id = ready.pop_front().expect("bounded queue length");
            let Some(c) = connections.get_mut(&id) else {
                continue;
            };
            c.queued = false;
            let state = c.drive(&index).unwrap_or(State::Close);
            if matches!(state, State::Close) {
                if let Some(mut c) = connections.remove(&id) {
                    let _ = poll.registry().deregister(&mut c.socket);
                }
                continue;
            }
            let writable = matches!(state, State::Write);
            if c.writable != writable {
                poll.registry().reregister(
                    &mut c.socket,
                    id,
                    if writable {
                        Interest::WRITABLE
                    } else {
                        Interest::READABLE
                    },
                )?;
                c.writable = writable;
            }
            if matches!(state, State::Again) {
                c.queued = true;
                ready.push_back(id);
            }
        }
        if last_expiry.elapsed() >= Duration::from_secs(1) {
            connections.retain(|_, c| {
                let timeout = if c.used == 0 && c.output.as_bytes().is_empty() {
                    60
                } else {
                    10
                };
                if c.activity.elapsed() < Duration::from_secs(timeout) {
                    true
                } else {
                    let _ = poll.registry().deregister(&mut c.socket);
                    false
                }
            });
            last_expiry = Instant::now();
        }
    }
}
