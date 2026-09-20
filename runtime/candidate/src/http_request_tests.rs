use super::*;
use std::io::{BufReader, Cursor};
use std::net::TcpListener;

fn status(request: impl AsRef<[u8]>) -> u16 {
    read_head(&mut Cursor::new(request.as_ref()))
        .unwrap_err()
        .status
}

#[test]
fn body_is_read_exactly_after_case_insensitive_content_length() {
    let mut reader = BufReader::with_capacity(
        3,
        Cursor::new(b"POST /iscrivi HTTP/1.1\r\ncOnTeNt-LeNgTh: 3\r\n\r\nabcNEXT"),
    );
    let head = read_head(&mut reader).unwrap();
    assert_eq!(head.method, "POST");
    assert_eq!(head.path, "/iscrivi");
    assert_eq!(read_body(&mut reader, &head).unwrap(), b"abc");
    let mut remaining = String::new();
    reader.read_to_string(&mut remaining).unwrap();
    assert_eq!(remaining, "NEXT");
}

#[test]
fn incomplete_request_lines_headers_and_bodies_are_rejected() {
    for request in [
        "",
        "GET /stato HTTP/1.1",
        "GET /stato HTTP/1.1\r\n",
        "GET /stato HTTP/1.1\r\nHost: localhost",
    ] {
        assert_eq!(status(request), 400, "{request:?}");
    }
    let mut reader = Cursor::new(b"POST /iscrivi HTTP/1.1\r\nContent-Length: 4\r\n\r\nabc");
    let head = read_head(&mut reader).unwrap();
    assert_eq!(read_body(&mut reader, &head).unwrap_err().status, 400);
}

#[test]
fn malformed_or_ambiguous_framing_is_rejected() {
    for headers in [
        "Content-Length: 0\r\ncontent-length: 0\r\n",
        "Content-Length: -1\r\n",
        "Content-Length: +1\r\n",
        "Content-Length: \r\n",
        "Content-Length: 184467440737095516160\r\n",
        "Transfer-Encoding: chunked\r\n",
        "broken\r\n",
        " folded: yes\r\n",
    ] {
        assert_eq!(
            status(format!("GET /stato HTTP/1.1\r\n{headers}\r\n")),
            400,
            "{headers:?}"
        );
    }
    assert_eq!(status("GET /stato\r\n\r\n"), 400);
    assert_eq!(status("GET /stato HTTP/2.0\r\n\r\n"), 400);
}

#[test]
fn browser_requests_cannot_bypass_the_python_gateway() {
    for browser_header in [
        "Origin: https://foreign.example",
        "oRiGiN: http://127.0.0.1:8005",
        "Origin: null",
        "Sec-Fetch-Site: cross-site",
        "sec-fetch-site: same-origin",
        "Sec-Fetch-Mode: navigate",
    ] {
        let request = format!(
            "POST /reset HTTP/1.1\r\nHost: 127.0.0.1:9005\r\n{browser_header}\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n"
        );
        assert_eq!(status(request), 403, "{browser_header}");
    }
}

#[test]
fn foreign_malformed_and_duplicate_hosts_are_rejected() {
    for host in [
        "foreign.example:9005",
        "localhost.foreign.example:9005",
        "127.0.0.1@foreign.example:9005",
        "127.0.0.1:9005:80",
        "127.0.0.1:65536",
        "127.0.0.1:",
        "127.0.0.1:+9005",
        "",
    ] {
        assert_eq!(
            status(format!("POST /reset HTTP/1.1\r\nHost: {host}\r\n\r\n")),
            403,
            "{host:?}"
        );
    }
    assert_eq!(
        status("POST /reset HTTP/1.1\r\nHost: localhost\r\nhost: localhost\r\n\r\n"),
        400
    );
}

#[test]
fn native_clients_keep_access_to_configurable_loopback_ports() {
    for host in [
        "127.0.0.1",
        "127.0.0.1:9005",
        "localhost:49152",
        "LOCALHOST:9005",
    ] {
        let request = format!(
            "POST /chiave HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Python-urllib/3.12\r\nContent-Type: application/octet-stream\r\nContent-Length: 3\r\n\r\nkey"
        );
        let mut reader = Cursor::new(request);
        let head = read_head(&mut reader).unwrap();
        assert_eq!(head.path, "/chiave");
        assert_eq!(read_body(&mut reader, &head).unwrap(), b"key");
    }
}

#[test]
fn request_line_header_lines_total_headers_and_count_have_independent_limits() {
    assert_eq!(
        status(format!(
            "GET /{} HTTP/1.1\r\n\r\n",
            "x".repeat(MAX_REQUEST_LINE_BYTES)
        )),
        414
    );
    assert_eq!(
        status(format!(
            "GET /stato HTTP/1.1\r\nX: {}\r\n\r\n",
            "x".repeat(MAX_HEADER_LINE_BYTES)
        )),
        431
    );
    assert_eq!(
        status(format!(
            "GET /stato HTTP/1.1\r\n{}\r\n",
            "X: y\r\n".repeat(MAX_HEADER_COUNT + 1)
        )),
        431
    );
    let header = format!("X: {}\r\n", "x".repeat(MAX_HEADER_LINE_BYTES - 10));
    assert_eq!(
        status(format!("GET /stato HTTP/1.1\r\n{}\r\n", header.repeat(3))),
        431
    );
}

#[test]
fn route_limits_are_applied_before_reading_or_allocating_the_body() {
    assert_eq!(
        status("GET /stato HTTP/1.1\r\nContent-Length: 1\r\n\r\n"),
        413
    );
    assert_eq!(
        status("POST /iscrivi HTTP/1.1\r\nContent-Length: 8193\r\n\r\n"),
        413
    );
    assert_eq!(status("GET /missing HTTP/1.1\r\n\r\n"), 404);
    let mut empty = Cursor::new(b"GET /stato HTTP/1.0\n\n");
    assert_eq!(read_head(&mut empty).unwrap().content_length, 0);
}

#[test]
fn io_timeouts_have_an_explicit_http_status() {
    struct Timeout;
    impl Read for Timeout {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::TimedOut.into())
        }
    }
    assert_eq!(
        read_head(&mut BufReader::new(Timeout)).unwrap_err().status,
        408
    );
}

#[test]
fn socket_reads_have_a_deadline_even_when_the_peer_keeps_the_connection_open() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let mut reader = DeadlineReader::new(&server, Duration::from_millis(20));
    let error = reader.read(&mut [0u8; 1]).unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ));
    reader.reset_deadline(Duration::ZERO);
    assert_eq!(
        reader.read(&mut [0u8; 1]).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}
