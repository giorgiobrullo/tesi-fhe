//! Persistent trusted demo adapter; the original A28 core remains unchanged.
#![recursion_limit = "512"]

#[allow(dead_code)]
#[path = "../vendor/private_argmin.rs"]
mod a28;
mod keys;
mod protocol;

use protocol::{Evaluation, Failure, Request};
use rayon::{ThreadPool, ThreadPoolBuilder};
use serde_json::{json, Value};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Instant;
use tfhe::core_crypto::prelude::*;

fn clock_failure() -> Failure {
    Failure::new("invalid_clock", "A28 could not sample the shared monotonic clock")
}

fn timespec_ns(seconds: i128, nanoseconds: i128) -> Result<u64, Failure> {
    let seconds = u64::try_from(seconds).map_err(|_| clock_failure())?;
    let nanoseconds = u64::try_from(nanoseconds).map_err(|_| clock_failure())?;
    if nanoseconds >= 1_000_000_000 {
        return Err(clock_failure());
    }
    seconds.checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(clock_failure)
}

fn monotonic_ns() -> Result<u64, Failure> {
    let mut timestamp = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime writes to an initialized, valid timespec. CLOCK_MONOTONIC
    // is also sampled by Python; Instant's implementation may use a different clock.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut timestamp) } != 0 {
        return Err(clock_failure());
    }
    timespec_ns(timestamp.tv_sec as i128, timestamp.tv_nsec as i128)
}

#[derive(serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum PhaseKind {
    Encryption,
    Fhe,
    Decryption,
}

#[derive(serde::Serialize)]
struct PhaseSpan {
    kind: PhaseKind,
    start_ns: u64,
    end_ns: u64,
}

impl PhaseSpan {
    fn new(kind: PhaseKind, start_ns: u64, end_ns: u64) -> Result<Self, Failure> {
        if end_ns < start_ns {
            return Err(clock_failure());
        }
        Ok(Self { kind, start_ns, end_ns })
    }

    fn finish(kind: PhaseKind, start_ns: u64) -> Result<Self, Failure> {
        Self::new(kind, start_ns, monotonic_ns()?)
    }
}

struct Engine {
    keys: keys::Keys,
    pool: ThreadPool,
    generator: EncryptionRandomGenerator<DefaultRandomGenerator>,
    threads: usize,
}

impl Engine {
    fn open(directory: PathBuf, threads: usize) -> Result<Self, String> {
        let pool = ThreadPoolBuilder::new().num_threads(threads).build().map_err(|_| "cannot create A28 thread pool".to_string())?;
        let keys = pool.install(|| keys::load_or_generate(&directory))?;
        let mut seeder = new_seeder();
        let generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder.as_mut());
        Ok(Self { keys, pool, generator, threads })
    }

    fn evaluate(&mut self, request: Evaluation<'_>) -> Result<Value, Failure> {
        let encryption_start_ns = monotonic_ns()?;
        let started = Instant::now();
        let polynomial_size = self.keys.secret.polynomial_size();
        let mut body = vec![0u64; polynomial_size.0];
        for (index, &value) in request.query.iter().enumerate() {
            body[index] = (value as u64).wrapping_mul(1u64 << a28::FULL_DELTA_LOG);
            body[a28::LOW_MOD16_POLYNOMIAL_OFFSET + index] =
                (value.rem_euclid(16) as u64).wrapping_mul(1u64 << a28::LOW_MOD16_DELTA_LOG);
        }
        let mut input = GlweCiphertext::new(0u64, self.keys.secret.glwe_dimension().to_glwe_size(),
            polynomial_size, CiphertextModulus::new_native());
        encrypt_glwe_ciphertext(&self.keys.secret, &mut input, &PlaintextList::from_container(body),
            self.keys.noise, &mut self.generator);
        let encryption_ms = started.elapsed().as_secs_f64() * 1000.0;
        let encryption_span = PhaseSpan::finish(PhaseKind::Encryption, encryption_start_ns)?;

        let fhe_start_ns = monotonic_ns()?;
        let started = Instant::now();
        // As in the progression wrapper, include native template views, norms and planning.
        let output = self.pool.install(|| {
            let (views, domain) = request.views_and_domain()?;
            a28::private_argmin(&self.keys.server, &input, &views, domain)
                .map_err(|_| Failure::new("evaluation_failed", "A28 could not evaluate this admitted request"))
        })?;
        let server_ms = started.elapsed().as_secs_f64() * 1000.0;
        let fhe_span = PhaseSpan::finish(PhaseKind::Fhe, fhe_start_ns)?;

        let decryption_start_ns = monotonic_ns()?;
        let started = Instant::now();
        let secret = self.keys.secret.as_lwe_secret_key();
        if output.code.lwe_size() != secret.lwe_dimension().to_lwe_size()
            || !output.code.ciphertext_modulus().is_native_modulus() {
            return Err(Failure::new("invalid_output", "A28 returned an unexpected ciphertext geometry"));
        }
        let phase = decrypt_lwe_ciphertext(&secret, &output.code).0;
        let selected_id = phase.wrapping_add(1u64 << (a28::CODE_DELTA_LOG - 1)) >> a28::CODE_DELTA_LOG;
        let expected_id = request.expected_id();
        let residue = phase.wrapping_sub(expected_id << a28::CODE_DELTA_LOG) as i64;
        if selected_id > request.gallery.len() as u64 || selected_id != expected_id
            || residue.unsigned_abs() >= 1u64 << (a28::CODE_DELTA_LOG - 1) {
            // The clear rule verifies the native result; it never replaces a wrong FHE output.
            return Err(Failure::new("fhe_mismatch", "The encrypted A28 result did not pass the clear-reference check"));
        }
        let decryption_ms = started.elapsed().as_secs_f64() * 1000.0;
        let decryption_span = PhaseSpan::finish(PhaseKind::Decryption, decryption_start_ns)?;
        Ok(json!({
            "selected_id": selected_id,
            "spans_ns": [encryption_span, fhe_span, decryption_span],
            "timings_ms": {"encryption": encryption_ms, "server": server_ms, "decryption": decryption_ms},
            "sizes": {"probe_ciphertext_bytes": input.as_ref().len() * 8,
                      "output_ciphertext_bytes": output.code.as_ref().len() * 8}
        }))
    }

    fn request(&mut self, request: &Request) -> Result<Value, Failure> {
        request.validate_id()?;
        if request.is_status()? {
            return Ok(json!({"ready": true, "core_sha256": keys::CORE_SHA256, "threads": self.threads}));
        }
        self.evaluate(request.evaluation()?)
    }
}

fn arguments() -> Result<(PathBuf, usize), String> {
    let mut args = std::env::args().skip(1);
    let mut directory = None;
    let mut threads = None;
    while let Some(option) = args.next() {
        match option.as_str() {
            "--keys" if directory.is_none() => directory = Some(PathBuf::from(args.next().ok_or("--keys needs a path")?)),
            "--threads" if threads.is_none() => {
                let count = args.next().ok_or("--threads needs a count")?.parse::<usize>()
                    .map_err(|_| "--threads must be an integer")?;
                if !(1..=64).contains(&count) { return Err("--threads must be in 1..64".into()); }
                threads = Some(count);
            }
            _ => return Err("usage: a28_web_worker --keys ABSOLUTE_PRIVATE_DIRECTORY [--threads 16]".into()),
        }
    }
    Ok((directory.ok_or("--keys is required")?, threads.unwrap_or(16)))
}

fn run() -> Result<(), String> {
    let (directory, threads) = arguments()?;
    let mut engine = Engine::open(directory, threads)?;
    eprintln!("A28 ready; threads={threads}; core={}", keys::CORE_SHA256);
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    while let Some(line) = protocol::read_line(&mut input).map_err(|_| "cannot read a request")? {
        let mut id = Value::Null;
        let result = match line {
            Err(error) => Err(error),
            Ok(bytes) => match serde_json::from_slice::<Request>(&bytes) {
                Err(_) => {
                    id = json!(protocol::recover_id(&bytes));
                    Err(Failure::invalid("expected one JSON request with bounded integer vectors"))
                }
                Ok(request) => {
                    if request.validate_id().is_ok() { id = json!(request.id); }
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| engine.request(&request)))
                        .unwrap_or_else(|_| Err(Failure::new("internal_error", "A28 could not complete the request")))
                }
            },
        };
        let response = match result {
            Ok(mut value) => { value["id"] = id; value },
            Err(error) => json!({"id": id, "error": error}),
        };
        serde_json::to_writer(&mut output, &response).map_err(|_| "cannot write a response")?;
        output.write_all(b"\n").and_then(|_| output.flush()).map_err(|_| "cannot flush a response")?;
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    std::panic::set_hook(Box::new(|_| eprintln!("A28: internal operation failed")));
    let result = std::panic::catch_unwind(run).unwrap_or_else(|_| Err("A28 startup failed".into()));
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => { eprintln!("A28: {message}"); std::process::ExitCode::FAILURE }
    }
}

#[cfg(test)]
mod timing_tests {
    use super::*;

    #[test]
    fn timespec_conversion_rejects_invalid_values_and_overflow() {
        assert_eq!(timespec_ns(4, 25).unwrap(), 4_000_000_025);
        assert_eq!(timespec_ns(0, 0).unwrap(), 0);
        for (seconds, nanoseconds) in [(-1, 0), (0, -1), (0, 1_000_000_000),
                                      (u64::MAX as i128, 0), (i128::MAX, 0)] {
            assert!(timespec_ns(seconds, nanoseconds).is_err());
        }
    }

    #[test]
    fn shared_os_clock_samples_are_monotonic() {
        let first = monotonic_ns().unwrap();
        let second = monotonic_ns().unwrap();
        assert!(second >= first);
    }

    #[test]
    fn phase_schema_has_integer_os_timestamps_and_stable_kinds() {
        let spans = [PhaseSpan::new(PhaseKind::Encryption, 100, 120).unwrap(),
                     PhaseSpan::new(PhaseKind::Fhe, 130, 170).unwrap(),
                     PhaseSpan::new(PhaseKind::Decryption, 180, 200).unwrap()];
        assert_eq!(serde_json::to_value(spans).unwrap(), json!([
            {"kind": "encryption", "start_ns": 100, "end_ns": 120},
            {"kind": "fhe", "start_ns": 130, "end_ns": 170},
            {"kind": "decryption", "start_ns": 180, "end_ns": 200}
        ]));
        assert!(PhaseSpan::new(PhaseKind::Fhe, 2, 1).is_err());
    }
}
