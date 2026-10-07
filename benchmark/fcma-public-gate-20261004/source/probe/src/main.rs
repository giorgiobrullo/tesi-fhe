//! Public pointwise arithmetic gate and separately authorized hot-buffer timing.
#[cfg(not(target_arch = "aarch64"))]
compile_error!("this source-only codegen probe is scoped to aarch64");

use pulp::aarch64::{Neon, NeonFcma};
use pulp::{c64, Simd, WithSimd};
use std::hint::black_box;
use std::io::{self, Write};
use std::process::ExitCode;
use std::time::Instant;

const FREQUENCIES: usize = 1024;
const OUTPUT_COMPLEX: usize = 2048;

struct Update<'a> {
    output: &'a mut [c64],
    lhs: &'a [c64],
    rhs: &'a [c64],
    first: bool,
}

impl WithSimd for Update<'_> {
    type Output = ();

    #[inline(always)]
    fn with_simd<S: Simd>(self, simd: S) {
        // Both checked aarch64 token types represent exactly one complex value.
        assert_eq!(S::C64_LANES, 1);
        let rhs = S::as_simd_c64s(self.rhs).0;
        if self.first {
            for (output, lhs) in self
                .output
                .chunks_exact_mut(FREQUENCIES)
                .zip(self.lhs.chunks_exact(FREQUENCIES))
            {
                let output = S::as_mut_simd_c64s(output).0;
                let lhs = S::as_simd_c64s(lhs).0;
                for ((output, lhs), rhs) in output.iter_mut().zip(lhs).zip(rhs) {
                    *output = simd.mul_c64s(*lhs, *rhs);
                }
            }
        } else {
            for (output, lhs) in self
                .output
                .chunks_exact_mut(FREQUENCIES)
                .zip(self.lhs.chunks_exact(FREQUENCIES))
            {
                let output = S::as_mut_simd_c64s(output).0;
                let lhs = S::as_simd_c64s(lhs).0;
                for ((output, lhs), rhs) in output.iter_mut().zip(lhs).zip(rhs) {
                    *output = simd.mul_add_c64s(*lhs, *rhs, *output);
                }
            }
        }
    }
}

#[inline(always)]
fn check_geometry(output: &[c64], lhs: &[c64], rhs: &[c64]) {
    assert_eq!(output.len(), OUTPUT_COMPLEX);
    assert_eq!(lhs.len(), OUTPUT_COMPLEX);
    assert_eq!(rhs.len(), FREQUENCIES);
}

// The token must come from the checked Pulp factory; no unchecked constructor.
#[no_mangle]
#[inline(never)]
pub fn neon_update(
    token: Neon,
    output: &mut [c64],
    lhs: &[c64],
    rhs: &[c64],
    first: bool,
) {
    check_geometry(output, lhs, rhs);
    Simd::vectorize(token, Update {
        output,
        lhs,
        rhs,
        first,
    });
}

#[no_mangle]
#[inline(never)]
pub fn fcma_update(
    token: NeonFcma,
    output: &mut [c64],
    lhs: &[c64],
    rhs: &[c64],
    first: bool,
) {
    check_geometry(output, lhs, rhs);
    Simd::vectorize(token, Update {
        output,
        lhs,
        rhs,
        first,
    });
}

const PULP_SOURCE_SHA256: &str =
    "428f60728d89512826a40714a4d63bf299d848430e5e1579a49d69f0fb505f29";
const REJECT_FPCR: u64 = (3 << 22) | (1 << 24) | 3;
const REPETITIONS: usize = 1000;
const WARMUP_PAIRS: usize = 64;

fn read_fpcr() -> u64 {
    let value: u64;
    // Read only: RN, gradual underflow and standard handling are admission gates.
    unsafe {
        std::arch::asm!("mrs {}, fpcr", out(reg) value,
            options(nomem, nostack, preserves_flags));
    }
    value
}

fn require_environment(expected: u64) -> io::Result<()> {
    let actual = read_fpcr();
    if actual & REJECT_FPCR != 0 || actual != expected {
        return Err(io::Error::other("unsupported or changed FPCR"));
    }
    Ok(())
}

fn random_normal(state: &mut u64) -> f64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    let exponent = 1015 + ((*state >> 52) % 17);
    f64::from_bits((*state & ((1 << 63) | ((1 << 52) - 1))) | (exponent << 52))
}

fn dyadic(i: usize, k: usize) -> f64 {
    (((i * 17 + k * 7) % 63) as f64 - 31.0) * 0.125
}

fn subnormal(i: usize, k: usize) -> f64 {
    let magnitude = if i % 4 == 0 { (i % 31 + 1) as u64 }
        else { (1 << 51) + (i * 7919 + k * 17) as u64 };
    f64::from_bits(magnitude | (((i + k) as u64 & 1) << 63))
}

struct Inputs { a0: Vec<c64>, a1: Vec<c64>, b0: Vec<c64>, b1: Vec<c64> }

impl Inputs {
    fn new(case: usize) -> Self {
        let mut state = 0x5a17_4c31_892b_d6efu64;
        let mut make = |length: usize, offset: usize| -> Vec<c64> {
            (0..length).map(|i| match case {
                0 => c64::new(dyadic(i, offset), dyadic(i, offset + 1)),
                3 if offset < 4 => c64::new(subnormal(i, offset), subnormal(i, offset + 1)),
                3 => {
                    let values = [0.5, -0.5, 1.0, -1.0, 2.0, -2.0];
                    c64::new(values[(i + offset) % 6], values[(i + offset + 1) % 6])
                }
                _ => c64::new(random_normal(&mut state), random_normal(&mut state)),
            }).collect()
        };
        let a0 = make(OUTPUT_COMPLEX, 0);
        let mut a1 = make(OUTPUT_COMPLEX, 2);
        let b0 = make(FREQUENCIES, 4);
        let mut b1 = make(FREQUENCIES, 6);
        if case == 2 {
            a1 = a0.iter().map(|z| c64::new(-z.re, -z.im)).collect();
            b1.clone_from(&b0);
        }
        Self { a0, a1, b0, b1 }
    }

    fn finite(&self) -> bool {
        [&self.a0, &self.a1, &self.b0, &self.b1].into_iter()
            .all(|row| row.iter().all(|z| z.re.is_finite() && z.im.is_finite()))
    }
}

fn pair(z: c64) -> String {
    format!("[\"{:016x}\",\"{:016x}\"]", z.re.to_bits(), z.im.to_bits())
}

fn validate(out: &mut impl Write, neon: Neon, fcma: NeonFcma, fpcr: u64) -> io::Result<()> {
    for case in 0..4 {
        require_environment(fpcr)?;
        let x = Inputs::new(case);
        if !x.finite() { return Err(io::Error::other("nonfinite public input")); }
        let mut n = vec![c64::new(0.0, 0.0); OUTPUT_COMPLEX];
        let mut f = n.clone();
        neon_update(neon, &mut n, &x.a0, &x.b0, true);
        let n_first = n.clone();
        neon_update(neon, &mut n, &x.a1, &x.b1, false);
        fcma_update(fcma, &mut f, &x.a0, &x.b0, true);
        let f_first = f.clone();
        fcma_update(fcma, &mut f, &x.a1, &x.b1, false);
        require_environment(fpcr)?;
        if [&n_first, &n, &f_first, &f].into_iter()
            .any(|row| row.iter().any(|z| !z.re.is_finite() || !z.im.is_finite())) {
            return Err(io::Error::other("nonfinite public output"));
        }
        for i in 0..OUTPUT_COMPLEX {
            writeln!(out, concat!("{{\"kind\":\"sample\",\"case\":{},\"index\":{},",
                "\"a0\":{},\"a1\":{},\"b0\":{},\"b1\":{},",
                "\"neon_first\":{},\"neon_final\":{},\"fcma_first\":{},\"fcma_final\":{}}}"),
                case, i, pair(x.a0[i]), pair(x.a1[i]), pair(x.b0[i % FREQUENCIES]),
                pair(x.b1[i % FREQUENCIES]), pair(n_first[i]), pair(n[i]), pair(f_first[i]), pair(f[i]))?;
        }
    }
    require_environment(fpcr)?;
    writeln!(out, "{{\"kind\":\"complete\",\"status\":\"VALIDATION_DUMP_COMPLETE\",\"cases\":4,\"rows\":8192,\"fpcr\":{}}}", read_fpcr())
}

fn checksum(output: &[c64]) -> io::Result<u64> {
    let mut sum = 0x9e37_79b9_7f4a_7c15u64;
    for z in output {
        if !z.re.is_finite() || !z.im.is_finite() {
            return Err(io::Error::other("nonfinite public benchmark output"));
        }
        sum = (sum.rotate_left(7) ^ z.re.to_bits()).rotate_left(11) ^ z.im.to_bits();
    }
    Ok(sum)
}

fn bench(out: &mut impl Write, neon: Neon, fcma: NeonFcma, fpcr: u64) -> io::Result<()> {
    let x = Inputs::new(1);
    if !x.finite() { return Err(io::Error::other("nonfinite public benchmark input")); }
    let mut n = vec![c64::new(0.0, 0.0); OUTPUT_COMPLEX];
    let mut f = n.clone();
    for _ in 0..WARMUP_PAIRS {
        neon_update(neon, black_box(&mut n), black_box(&x.a0), black_box(&x.b0), black_box(true));
        neon_update(neon, black_box(&mut n), black_box(&x.a1), black_box(&x.b1), black_box(false));
        fcma_update(fcma, black_box(&mut f), black_box(&x.a0), black_box(&x.b0), black_box(true));
        fcma_update(fcma, black_box(&mut f), black_box(&x.a1), black_box(&x.b1), black_box(false));
    }
    require_environment(fpcr)?;
    for block in 0..8 {
        let order = if block % 2 == 0 { [false, true, true, false] } else { [true, false, false, true] };
        for (position, use_fcma) in order.into_iter().enumerate() {
            require_environment(fpcr)?;
            let (backend, elapsed, sum) = if use_fcma {
                let start = Instant::now();
                for _ in 0..REPETITIONS {
                    fcma_update(fcma, black_box(&mut f), black_box(&x.a0), black_box(&x.b0), black_box(true));
                    fcma_update(fcma, black_box(&mut f), black_box(&x.a1), black_box(&x.b1), black_box(false));
                }
                let elapsed = start.elapsed().as_nanos();
                ("fcma", elapsed, checksum(black_box(&f))?)
            } else {
                let start = Instant::now();
                for _ in 0..REPETITIONS {
                    neon_update(neon, black_box(&mut n), black_box(&x.a0), black_box(&x.b0), black_box(true));
                    neon_update(neon, black_box(&mut n), black_box(&x.a1), black_box(&x.b1), black_box(false));
                }
                let elapsed = start.elapsed().as_nanos();
                ("neon", elapsed, checksum(black_box(&n))?)
            };
            require_environment(fpcr)?;
            writeln!(out, "{{\"kind\":\"batch\",\"block\":{},\"position\":{},\"backend\":\"{}\",\"repetitions\":{},\"elapsed_ns\":{},\"checksum\":\"{:016x}\"}}", block, position, backend, REPETITIONS, elapsed, sum)?;
        }
    }
    require_environment(fpcr)?;
    writeln!(out, "{{\"kind\":\"complete\",\"status\":\"BENCH_COMPLETE\",\"batches\":32,\"fpcr\":{}}}", read_fpcr())
}

fn run(mode: &str) -> io::Result<()> {
    black_box(neon_update as *const ());
    black_box(fcma_update as *const ());
    let neon = Neon::try_new();
    let fcma = NeonFcma::try_new();
    let fpcr = read_fpcr();
    let mut out = io::BufWriter::new(io::stdout().lock());
    let schema = if mode == "--validate" { "fcma_public_validate_v1" } else { "fcma_public_bench_v1" };
    writeln!(out, concat!("{{\"kind\":\"header\",\"schema\":\"{}\",\"arch\":\"aarch64\",",
        "\"pulp_version\":\"0.22.3\",\"pulp_source_sha256\":\"{}\",\"fpcr\":{},",
        "\"neon_available\":{},\"fcma_available\":{},\"cases\":{},\"elements_per_case\":2048,",
        "\"dataset_case\":{},\"lhs_complex\":2048,\"rhs_complex\":1024,\"warmup_pairs\":{}}}"),
        schema, PULP_SOURCE_SHA256, fpcr, neon.is_some(), fcma.is_some(),
        if mode == "--validate" { 4 } else { 1 }, if mode == "--bench" { "1" } else { "null" },
        if mode == "--bench" { WARMUP_PAIRS } else { 0 })?;
    out.flush()?;
    require_environment(fpcr)?;
    let neon = neon.ok_or_else(|| io::Error::other("checked Neon unavailable"))?;
    let fcma = fcma.ok_or_else(|| io::Error::other("checked NeonFcma unavailable"))?;
    if mode == "--validate" { validate(&mut out, neon, fcma, fpcr)?; }
    else { bench(&mut out, neon, fcma, fpcr)?; }
    out.flush()
}

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let mode = arguments.next().unwrap_or_default();
    if !matches!(mode.as_str(), "--validate" | "--bench") || arguments.next().is_some() {
        eprintln!("usage: current-fcma-codegen-probe --validate | --bench");
        return ExitCode::from(2);
    }
    match run(&mode) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => { eprintln!("{error}"); ExitCode::FAILURE }
    }
}
