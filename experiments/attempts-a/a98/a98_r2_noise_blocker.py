#!/usr/bin/env python3
"""Reproduce the parameter-grounded blocker that prevented the first A98 R2 FHE run."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path


A98 = Path(__file__).resolve().parent
TFHE_ROOT = Path(
    "/opt/cargo/registry/src/"
    "index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0"
)

PINS = {
    A98 / "R2_PREREGISTRATION.json": (
        "2fe4fe948a0d734b50aa66c4723f1562bb6fb9062f9b75f999efe3e04df3088d"
    ),
    A98 / "runtime-gate/src/main.rs": (
        "527e6c29370a705500194dfded899a299abf7f2a0744093c32b0a32083363175"
    ),
    Path("/tmp/a98-r2-target.J3CTcB/release/a98-head-start-exact-adapter-r2"): (
        "383d42ac18b896e8ae32c995acb65a30234589485cf770c7be4732dafe53384d"
    ),
    TFHE_ROOT
    / "src/core_crypto/commons/noise_formulas/lwe_programmable_bootstrap.rs": (
        "353b8af37fb97976bb002e2113f3690492375fa07a9d22ec9ca4af6c79065d08"
    ),
    TFHE_ROOT / "src/core_crypto/commons/noise_formulas/noise_simulation/mod.rs": (
        "0c25c92b618d836c54bf98ef2ecdf8f8a44a9a03f5d257187eb3bd7cd527d1a2"
    ),
    TFHE_ROOT / "src/core_crypto/commons/noise_formulas/secure_noise.rs": (
        "bb5e98b5df2462813ee54624f1b29989f200e2824e281da9b66dda6df73f0bcc"
    ),
    TFHE_ROOT / "src/shortint/parameters/v0_11/classic/gaussian/"
    "p_fail_2_minus_64/ks_pbs.rs": (
        "ccc97d408b187b4ab3bc2ca41c614324323eaac693039ea5ebec65e0866d131a"
    ),
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pbs_variance_132_bits_security_gaussian_fft_mul_impl(
    input_lwe_dimension: float,
    output_glwe_dimension: float,
    output_polynomial_size: float,
    decomposition_base: float,
    decomposition_level_count: float,
    mantissa_size: float,
    modulus: float,
) -> float:
    """Literal Python transcription of the pinned tfhe-rs 1.7 generated formula."""

    conditional = (
        0.0
        if mantissa_size - math.log2(math.e) * math.log(modulus) >= 0.0
        else -mantissa_size + math.log2(math.e) * math.log(modulus)
    )
    return input_lwe_dimension * (
        0.00705
        * 2.0
        ** (
            2.0 * conditional
            + 2.88539008177793 * math.log(decomposition_base)
            - 2.88539008177793 * math.log(modulus)
        )
        * decomposition_level_count**1.01827
        * output_glwe_dimension**1.22003
        * output_polynomial_size**2.22003
        * (output_glwe_dimension + 1.0) ** 1.01827
        + decomposition_level_count
        * output_polynomial_size
        * (
            2.0 ** (4.0 - 2.88539008177793 * math.log(modulus))
            + 2.0
            ** (
                -0.0497829131652661 * output_glwe_dimension * output_polynomial_size
                + 5.31469187675068
            )
        )
        * ((1.0 / 12.0) * decomposition_base**2.0 + 0.166666666666667)
        * (output_glwe_dimension + 1.0)
        - (1.0 / 24.0) * modulus**-2.0
        + 0.5
        * output_glwe_dimension
        * output_polynomial_size
        * (
            0.0208333333333333 * modulus**-2.0
            + 0.0416666666666667
            * decomposition_base ** (-2.0 * decomposition_level_count)
        )
        + (1.0 / 24.0) * decomposition_base ** (-2.0 * decomposition_level_count)
    )


def minimal_glwe_stddev_for_132_bits_security_gaussian(
    glwe_dimension: int, polynomial_size: int, modulus: float
) -> float:
    equivalent_lwe_dimension = float(glwe_dimension * polynomial_size)
    variance = 2.0 ** (4.0 - 2.88539008177793 * math.log(modulus)) + 2.0 ** (
        5.31469187675068 - 0.0497829131652661 * equivalent_lwe_dimension
    )
    return math.sqrt(variance)


def report() -> dict[str, object]:
    observed_pins = {str(path): sha256_file(path) for path in PINS}
    mismatches = {
        str(path): {"expected": expected, "observed": observed_pins[str(path)]}
        for path, expected in PINS.items()
        if observed_pins[str(path)] != expected
    }
    if mismatches:
        raise RuntimeError(f"source or binary drift: {mismatches}")

    variance = pbs_variance_132_bits_security_gaussian_fft_mul_impl(
        input_lwe_dimension=859.0,
        output_glwe_dimension=1.0,
        output_polynomial_size=2048.0,
        decomposition_base=2.0**23,
        decomposition_level_count=1.0,
        mantissa_size=53.0,
        modulus=2.0**64,
    )
    sigma_normalized = math.sqrt(variance)
    sigma_u64 = sigma_normalized * 2.0**64
    existing_cap = 2.0**40
    cap_in_sigma = existing_cap / sigma_u64
    normal_marginal_inside_cap = math.erf(cap_in_sigma / math.sqrt(2.0))
    step = 2.0**52
    minimum_secure_glwe_stddev = minimal_glwe_stddev_for_132_bits_security_gaussian(
        glwe_dimension=1,
        polynomial_size=2048,
        modulus=2.0**64,
    )
    a44_glwe_stddev = 2.845267479601915e-15

    return {
        "schema": "a98.r2.no-run-noise-blocker.v1",
        "status": "BLOCKED_BEFORE_FHE_RUN",
        "fhe_invocations_consumed": 0,
        "reason": (
            "The frozen runtime rejects max absolute error above 2^40, but the pinned "
            "tfhe-rs A44 PBS formula predicts a one-sample sigma near 2^49 u64."
        ),
        "formula": {
            "name": "pbs_variance_132_bits_security_gaussian_fft_mul",
            "tfhe_version": "1.7.0",
            "security_model": "132-bit Gaussian FFT multiplication formula",
            "inputs": {
                "input_lwe_dimension": 859,
                "output_glwe_dimension": 1,
                "output_polynomial_size": 2048,
                "decomposition_base": 8388608,
                "decomposition_level_count": 1,
                "fft_mantissa_bits": 53,
                "native_modulus": "2^64",
            },
            "predicted_variance_normalized": variance,
            "predicted_sigma_normalized": sigma_normalized,
            "predicted_sigma_u64": sigma_u64,
            "predicted_sigma_u64_log2": math.log2(sigma_u64),
            "stated_precondition": (
                "BSK encryptions use the 132-bit minimal secure Gaussian GLWE noise."
            ),
            "minimum_secure_glwe_stddev": minimum_secure_glwe_stddev,
            "a44_glwe_stddev": a44_glwe_stddev,
            "a44_over_minimum_secure_glwe_stddev": (
                a44_glwe_stddev / minimum_secure_glwe_stddev
            ),
            "precondition_matches_to_source_rounding": True,
        },
        "invalid_frozen_cap": {
            "cap_u64": int(existing_cap),
            "cap_log2": 40,
            "cap_in_predicted_sigma": cap_in_sigma,
            "predicted_sigma_over_cap": sigma_u64 / existing_cap,
            "normal_marginal_probability_abs_error_inside_cap_diagnostic": (
                normal_marginal_inside_cap
            ),
            "aggregation": "maximum absolute error over all 2048 decrypted GLWE coefficients",
        },
        "lut_geometry": {
            "step_u64": int(step),
            "half_step_u64": int(step / 2.0),
            "step_in_predicted_sigma": step / sigma_u64,
            "half_step_in_predicted_sigma": (step / 2.0) / sigma_u64,
        },
        "logic": {
            "independence_assumed": False,
            "correlation_caveat": (
                "The 2048 decrypted coefficients share one BSK/output GLWE and are not treated "
                "as independent. The event max<=cap implies any fixed coefficient<=cap, so a "
                "max gate cannot be more likely to pass than its one-coordinate marginal."
            ),
            "normal_probability_scope": (
                "Diagnostic interpretation of the formula's sigma, not a certified tail bound."
            ),
            "p_fail_scope": (
                "The preset log2_p_fail=-64.088 belongs to its canonical shortint decoding "
                "contract; it is not a bound for this ramp LUT or for a maximum over 2048 slots."
            ),
        },
        "decision": {
            "run_current_binary": False,
            "reuse_current_binary_for_r2b": False,
            "why_new_binary_is_required": (
                "The 2^40 rejection is compiled into control flow, so a documentation-only "
                "contract change cannot remove the false-reject path."
            ),
            "primary_replacement_gate": (
                "Exact reference-vs-A98 correction/degrees and bitwise paired ciphertext output."
            ),
            "phase_error_replacement": (
                "Record signed error on the actually consumed extracted sample and full-GLWE "
                "diagnostics without comparing them to an invented cap."
            ),
        },
        "pins": observed_pins,
    }


if __name__ == "__main__":
    print(json.dumps(report(), indent=2, sort_keys=True))
