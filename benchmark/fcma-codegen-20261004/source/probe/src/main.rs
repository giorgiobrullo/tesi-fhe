//! Retained pointwise code for disassembly; main never calls either update.
#[cfg(not(target_arch = "aarch64"))]
compile_error!("this source-only codegen probe is scoped to aarch64");

use pulp::aarch64::{Neon, NeonFcma};
use pulp::{c64, Simd, WithSimd};
use std::hint::black_box;
use std::process::ExitCode;

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

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    if arguments.next().as_deref() != Some("--capabilities") || arguments.next().is_some() {
        eprintln!("usage: current-fcma-codegen-probe --capabilities");
        return ExitCode::from(2);
    }

    // Retain both symbols through relocations, without invoking arithmetic.
    black_box(neon_update as *const ());
    black_box(fcma_update as *const ());
    let rust_neon = std::arch::is_aarch64_feature_detected!("neon");
    let rust_fcma = std::arch::is_aarch64_feature_detected!("fcma");
    let pulp_neon = Neon::try_new().is_some();
    let pulp_fcma = NeonFcma::try_new().is_some();
    println!(
        concat!(
            "{{\"schema\":1,\"scope\":\"capabilities_only\",\"arch\":\"aarch64\",",
            "\"pulp_version\":\"0.22.3\",\"rust_neon\":{},\"rust_fcma\":{},",
            "\"pulp_neon_checked\":{},\"pulp_neon_fcma_checked\":{},",
            "\"output_complex\":2048,\"lhs_complex\":2048,\"rhs_complex\":1024,",
            "\"arithmetic_called\":false,\"timing_performed\":false}}"
        ),
        rust_neon, rust_fcma, pulp_neon, pulp_fcma
    );
    if pulp_neon && pulp_fcma {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
