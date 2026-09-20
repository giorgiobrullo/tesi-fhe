//! Bounded HTTP/1 request framing. Chunked bodies and persistent connections are unsupported.
use crate::http::body_limit;
use std::io::{self, BufRead, Read};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub(crate) const MAX_REQUEST_LINE_BYTES: usize = 4096;
pub(crate) const MAX_HEADER_LINE_BYTES: usize = 8192;
pub(crate) const MAX_HEADER_BYTES: usize = 16384;
pub(crate) const MAX_HEADER_COUNT: usize = 64;
pub(crate) const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const BODY_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub(crate) struct RequestError {
    pub(crate) status: u16,
    pub(crate) message: String,
}

impl RequestError {
    fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl From<io::Error> for RequestError {
    fn from(error: io::Error) -> Self {
        let status = match error.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => 408,
            _ => 400,
        };
        Self::new(status, format!("richiesta HTTP incompleta: {error}"))
    }
}

#[derive(Debug)]
pub(crate) struct RequestHead {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) content_length: usize,
}

fn line(
    reader: &mut impl BufRead,
    limit: usize,
    overflow_status: u16,
) -> Result<String, RequestError> {
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_until(b'\n', &mut bytes)?;
    if bytes.len() > limit {
        return Err(RequestError::new(overflow_status, "riga HTTP troppo lunga"));
    }
    if bytes.last() != Some(&b'\n') {
        return Err(RequestError::new(400, "riga HTTP troncata"));
    }
    String::from_utf8(bytes).map_err(|_| RequestError::new(400, "header HTTP non valido"))
}

fn loopback_host(value: &str) -> bool {
    let (host, port) = match value.trim().split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (value.trim(), None),
    };
    if host != "127.0.0.1" && !host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    port.is_none_or(|port| {
        !port.is_empty()
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && port.parse::<u16>().is_ok()
    })
}

pub(crate) fn read_head(reader: &mut impl BufRead) -> Result<RequestHead, RequestError> {
    let request_line = line(reader, MAX_REQUEST_LINE_BYTES, 414)?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() != 3 || !matches!(parts[2], "HTTP/1.0" | "HTTP/1.1") {
        return Err(RequestError::new(400, "riga iniziale HTTP non valida"));
    }
    let (method, path) = (parts[0], parts[1]);
    let mut content_length = None;
    let mut host_seen = false;
    let mut header_bytes = 0;
    let mut header_count = 0;
    loop {
        let header = line(reader, MAX_HEADER_LINE_BYTES, 431)?;
        header_bytes += header.len();
        if header_bytes > MAX_HEADER_BYTES {
            return Err(RequestError::new(431, "header HTTP troppo grandi"));
        }
        if header == "\r\n" || header == "\n" {
            break;
        }
        header_count += 1;
        if header_count > MAX_HEADER_COUNT {
            return Err(RequestError::new(431, "troppi header HTTP"));
        }
        let (name, value) = header
            .trim_end_matches(['\r', '\n'])
            .split_once(':')
            .ok_or_else(|| RequestError::new(400, "header HTTP privo di due punti"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            return Err(RequestError::new(400, "nome header HTTP non valido"));
        }
        // Browsers use the Python gateway. Direct browser traffic must not bypass
        // its origin checks through this unauthenticated, loopback-only API.
        if name.eq_ignore_ascii_case("origin")
            || name.to_ascii_lowercase().starts_with("sec-fetch-")
        {
            return Err(RequestError::new(
                403,
                "accesso diretto dal browser non consentito",
            ));
        }
        if name.eq_ignore_ascii_case("host") {
            if host_seen {
                return Err(RequestError::new(400, "header Host duplicato"));
            }
            host_seen = true;
            if !loopback_host(value) {
                return Err(RequestError::new(
                    403,
                    "Host deve indicare il servizio locale",
                ));
            }
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(RequestError::new(
                400,
                "Transfer-Encoding non supportato; usare Content-Length",
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(RequestError::new(400, "header Content-Length duplicato"));
            }
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(RequestError::new(400, "header Content-Length non valido"));
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| RequestError::new(400, "header Content-Length non valido"))?,
            );
        }
    }
    let max_body = body_limit(method, path).ok_or_else(|| RequestError::new(404, "non trovato"))?;
    let content_length = content_length.unwrap_or(0);
    if content_length > max_body {
        return Err(RequestError::new(413, format!("corpo troppo grande per {method} {path}: {content_length} byte, massimo {max_body}")));
    }
    Ok(RequestHead {
        method: method.into(),
        path: path.into(),
        content_length,
    })
}

pub(crate) fn read_body(
    reader: &mut impl Read,
    head: &RequestHead,
) -> Result<Vec<u8>, RequestError> {
    let mut body = vec![0; head.content_length];
    reader.read_exact(&mut body)?;
    Ok(body)
}

/// A deadline bounds the whole phase, including clients that send one byte per timeout.
pub(crate) struct DeadlineReader<'a> {
    stream: &'a TcpStream,
    deadline: Instant,
}

impl<'a> DeadlineReader<'a> {
    pub(crate) fn new(stream: &'a TcpStream, timeout: Duration) -> Self {
        Self {
            stream,
            deadline: Instant::now() + timeout,
        }
    }

    pub(crate) fn reset_deadline(&mut self, timeout: Duration) {
        self.deadline = Instant::now() + timeout;
    }
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "HTTP read deadline exceeded")
            })?;
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(bytes)
    }
}

#[cfg(test)]
#[path = "http_request_tests.rs"]
mod tests;
