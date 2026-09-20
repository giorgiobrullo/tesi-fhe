//! Sequential HTTP transport. Numerical global flags require one query per process.
use crate::gallery::{process_epoch, Galleria};
use crate::http_request::{self, DeadlineReader, BODY_TIMEOUT, HEADER_TIMEOUT};
use crate::protocol::*;
use crate::routes::{self, Response};
use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::Duration;
use tfhe::core_crypto::prelude::CiphertextModulus;

pub(crate) fn body_limit(method: &str, path: &str) -> Option<usize> {
    match (method, path) {
        ("POST", "/chiave") => Some(MAX_SERVER_KEY_BODY_BYTES),
        ("POST", "/g4-key") => Some(MAX_G4_KEY_BODY_BYTES),
        ("POST", "/iscrivi") => Some(MAX_ENROLLMENT_BODY_BYTES),
        ("POST", "/varco") => Some(MAX_PROBE_BODY_BYTES),
        ("POST", "/reset") | ("GET", "/stato") => Some(0),
        _ => None,
    }
}

pub(crate) fn serve(port: u16, dimension: usize, threshold: i64) -> Result<(), String> {
    let state = Mutex::new(Galleria {
        dim: dimension,
        t_default: threshold,
        iscritti: Vec::new(),
        chiave: None,
        chiave_sha256: None,
        g4_sha256: None,
        epoch: process_epoch(),
        revision: 0,
    });
    let listener =
        TcpListener::bind(("127.0.0.1", port)).map_err(|error| format!("HTTP bind: {error}"))?;
    let modulus = CiphertextModulus::<u64>::new_native();
    println!("varco fast uniform/mixed in ascolto su 127.0.0.1:{port} | dim={dimension} T={threshold} | Delta_score=2^51, Delta_low=2^{LOG_LOW_MOD16_DELTA}, Delta_digit=2^{LOG_DIGIT_DELTA}, base={OUTPUT_DIGIT_BASE} | params_id={A44_PARAMS_ID} fingerprint={A44_PARAMETER_FINGERPRINT_SHA256} variant={VARIANT_ID} circuit={CIRCUIT_SHA256}");
    println!("il server NON ha la chiave segreta: riceve byte cifrati e ne restituisce altri.");
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => handle(stream, &state, modulus),
            Err(error) => eprintln!("HTTP accept: {error}"),
        }
    }
    Ok(())
}

fn handle(mut stream: TcpStream, state: &Mutex<Galleria>, modulus: CiphertextModulus<u64>) {
    if stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .is_err()
    {
        return;
    }
    let request = (|| {
        let mut reader = BufReader::new(DeadlineReader::new(&stream, HEADER_TIMEOUT));
        let head = http_request::read_head(&mut reader)?;
        reader.get_mut().reset_deadline(BODY_TIMEOUT);
        let body = http_request::read_body(&mut reader, &head)?;
        Ok::<_, http_request::RequestError>((head, body))
    })();
    let response = match request {
        Ok((head, body)) => routes::handle(&head.method, &head.path, &body, state, modulus),
        Err(error) => (
            error.status,
            "application/json",
            String::new(),
            serde_json::json!({"errore": error.message})
                .to_string()
                .into_bytes(),
        ),
    };
    respond(&mut stream, response);
}

fn respond(stream: &mut TcpStream, (status, content_type, extra, body): Response) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        _ => "Response",
    };
    let header = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n", body.len());
    if stream.write_all(header.as_bytes()).is_ok() && stream.write_all(&body).is_ok() {
        let _ = stream.flush();
    }
}
