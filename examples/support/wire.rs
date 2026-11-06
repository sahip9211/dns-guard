//! Restricted loopback benchmark protocol, not a public HTTP server.
use dns_guard::Index;
use std::fmt::{self, Write};

pub struct Buffer<const N: usize> {
    bytes: [u8; N],
    len: usize,
}
impl<const N: usize> Buffer<N> {
    pub fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    pub fn clear(&mut self) {
        self.len = 0;
    }
}
impl<const N: usize> Write for Buffer<N> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if text.len() > N - self.len {
            return Err(fmt::Error);
        }
        self.bytes[self.len..self.len + text.len()].copy_from_slice(text.as_bytes());
        self.len += text.len();
        Ok(())
    }
}

#[derive(Debug)]
pub struct Parsed<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub used: usize,
    pub close: bool,
}

pub fn parse_request(input: &[u8]) -> Result<Option<Parsed<'_>>, &'static str> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut request = httparse::Request::new(&mut headers);
    let used = match request.parse(input).map_err(|_| "invalid HTTP")? {
        httparse::Status::Partial => return Ok(None),
        httparse::Status::Complete(n) => n,
    };
    let mut close = request.version != Some(1);
    let mut host = 0;
    let mut length = false;
    for header in request.headers.iter() {
        if header.name.eq_ignore_ascii_case("host") {
            host += 1;
            if header.value.is_empty() {
                return Err("empty host");
            }
        } else if header.name.eq_ignore_ascii_case("content-length") {
            if length || header.value != b"0" {
                return Err("request bodies not supported");
            }
            length = true;
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("request transfer encodings not supported");
        } else if header.name.eq_ignore_ascii_case("connection") {
            close |= header
                .value
                .split(|b| *b == b',')
                .any(|v| v.trim_ascii().eq_ignore_ascii_case(b"close"));
        }
    }
    if host > 1 || (request.version == Some(1) && host != 1) {
        return Err("invalid host count");
    }
    let method = request.method.ok_or("missing method")?;
    let path = request.path.ok_or("missing path")?;
    if !path.starts_with('/') {
        return Err("only origin-form requests supported");
    }
    Ok(Some(Parsed {
        method,
        path,
        used,
        close,
    }))
}

pub fn encode_reply(index: &Index, request: &Parsed<'_>, output: &mut Buffer<512>) -> fmt::Result {
    let mut body = Buffer::<256>::new();
    let (status, elapsed) =
        crate::support::route_into(index, request.method, request.path, &mut body)?;
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => return Err(fmt::Error),
    };
    output.clear();
    write!(
        output,
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n",
        body.as_bytes().len()
    )?;
    if let Some(ns) = elapsed {
        write!(
            output,
            "X-Lookup-Ns: {ns}\r\nContent-Type: application/json\r\n"
        )?;
    }
    if request.close {
        output.write_str("Connection: close\r\n")?;
    }
    output.write_str("\r\n")?;
    output.write_str(std::str::from_utf8(body.as_bytes()).map_err(|_| fmt::Error)?)
}
