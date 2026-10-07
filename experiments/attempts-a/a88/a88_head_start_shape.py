#!/usr/bin/env python3
"""Static shape gate for applying Head Start digit extraction to A62/A30 scores."""

from __future__ import annotations

import hashlib
import itertools
import json
import math
from pathlib import Path


TORUS_BITS = 64
SCORE_BITS = 12
MAX_NORMALIZED_SCORE = (1 << SCORE_BITS) - 1
CURRENT_SCORE_DELTA_LOG = 52
CANDIDATE_SCORE_DELTA_LOG = 51
A44_MESSAGE_MODULUS = 2
A44_CARRY_MODULUS = 8
A44_GLWE_STD_DEV_NORMALIZED = 2.845267479601915e-15
A62_PROBE_NORM2_MAX = 1024
A62_MAX_DOMAIN_WIDTH = 4096
# Head Start's p includes TFHE's padding bit. TFHE-rs uses q/(2*M*C).
A44_PAPER_PLAINTEXT_MODULUS = 2 * A44_MESSAGE_MODULUS * A44_CARRY_MODULUS
A30_CURRENT_BR_PER_SCORE = 13

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REGISTRY = Path.home() / ".cargo/registry/src/index.crates.io-1949cf8c6b5b557f"
SOURCE_PINS = {
    ROOT / "tmp/pdfs/head-start-2025-2012.pdf": (
        "3086cc63916d5ef5385df49021888b3dcb6be30132f1733be07fceffba0eeb6d"
    ),
    ROOT / "tmp/pdfs/head-start-2025-2012.txt": (
        "9de7adb52ff80808ee6892a1dd2caa4b316238426ba225b5fdf9ba453ee20972"
    ),
    ROOT / "tmp/pdfs/head-start.patch": (
        "d19b72f6257d3db93e3651d87779816be4f210f60bf274cea5799b50743368cc"
    ),
    ROOT / "tmp/a62-a53-a44-integrated-prototype/src/private_argmin.rs": (
        "69049071d6c72b32d2db8cbe2f9972ec61c06266382f448f5a199c49b3b5fbab"
    ),
    ROOT / "tmp/a30-pfks-bridge-microbenchmark-design/README.md": (
        "9eac7a4e01505232a7912a1e38b5403e4bb99892564f9d28a754e931d9924ca9"
    ),
    REGISTRY
    / "tfhe-0.11.3/src/shortint/parameters/classic/gaussian/"
    "p_fail_2_minus_64/ks_pbs.rs": (
        "f1e7501d5401ba95899993aa6adc05450b547debf6eaa6ba502f0a265275ff65"
    ),
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_source_pins() -> list[dict[str, str]]:
    result = []
    for path, expected in SOURCE_PINS.items():
        if not path.is_file():
            raise RuntimeError(f"missing source pin: {path}")
        actual = sha256_file(path)
        if actual != expected:
            raise RuntimeError(f"source pin drift: {path}: {actual} != {expected}")
        try:
            display = str(path.relative_to(ROOT))
        except ValueError:
            display = str(path)
        result.append({"path": display, "sha256": actual})
    return result


def extended_plaintext_modulus(delta_log: int) -> int:
    if not 1 <= delta_log < TORUS_BITS:
        raise ValueError("delta_log must be in 1..63")
    return 1 << (TORUS_BITS - delta_log)


def clean_padding_value_count(delta_log: int) -> int:
    """Number of nonnegative values before TFHE's padding bit becomes one."""

    return extended_plaintext_modulus(delta_log) // 2


def ceil_sqrt(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("value must be a nonnegative plain int")
    root = math.isqrt(value)
    return root if root * root == value else root + 1


def a62_single_template_cauchy_width(template_norm2: int) -> int:
    """Reproduce A62's per-template score-bound width exactly."""

    if (
        isinstance(template_norm2, bool)
        or not isinstance(template_norm2, int)
        or template_norm2 < 0
    ):
        raise ValueError("template_norm2 must be a nonnegative plain int")
    return 4 * ceil_sqrt(template_norm2 * A62_PROBE_NORM2_MAX) + 1


def a62_max_single_template_norm2() -> int:
    """Largest norm compatible with at least one A62 width-limited gallery."""

    maximum_ceil_sqrt = (A62_MAX_DOMAIN_WIDTH - 1) // 4
    return maximum_ceil_sqrt**2 // A62_PROBE_NORM2_MAX


def score_encoding_row(delta_log: int) -> dict[str, object]:
    capacity = clean_padding_value_count(delta_log)
    half_decode_margin = 1 << (delta_log - 1)
    coefficient_sigma_torus = A44_GLWE_STD_DEV_NORMALIZED * (1 << TORUS_BITS)
    maximum_single_template_norm2 = a62_max_single_template_norm2()
    score_sigma_torus = (
        2
        * math.sqrt(maximum_single_template_norm2)
        * coefficient_sigma_torus
    )
    return {
        "delta_log": delta_log,
        "p_ext": extended_plaintext_modulus(delta_log),
        "clean_padding_value_count": capacity,
        "largest_clean_padding_value": capacity - 1,
        "covers_x_0_through_4095": MAX_NORMALIZED_SCORE < capacity,
        "initial_score_half_decode_margin_torus": half_decode_margin,
        "initial_glwe_coefficient_sigma_torus": coefficient_sigma_torus,
        "maximum_single_template_norm2_compatible_with_an_a62_domain": (
            maximum_single_template_norm2
        ),
        "single_template_cauchy_width_at_maximum_norm2": (
            a62_single_template_cauchy_width(maximum_single_template_norm2)
        ),
        "initial_score_sigma_torus": score_sigma_torus,
        "initial_score_half_decode_margin_in_sigma": half_decode_margin
        / score_sigma_torus,
        "initial_score_noise_model": (
            "conditional Gaussian variance propagation for the linear score convolution only"
        ),
        "deterministic_initial_score_noise_support_bound_available": False,
        "includes_head_start_ks_modulus_switch_or_dirty_pbs_noise": False,
    }


def regular_data_bits(p: int) -> int:
    if p < 4 or p & (p - 1):
        raise ValueError("paper plaintext modulus p must be a power of two >= 4")
    return p.bit_length() - 2


def dirty_schedule_capacity(schedule: tuple[int, ...]) -> int:
    if not schedule or any(value <= 0 for value in schedule):
        raise ValueError("schedule entries must be positive")
    return schedule[0] + sum(value - 1 for value in schedule[1:])


def minimum_dirty_iterations(message_bits: int, p: int) -> int:
    if message_bits <= 0:
        raise ValueError("message_bits must be positive")
    bits_per_regular_ciphertext = regular_data_bits(p)
    if message_bits <= bits_per_regular_ciphertext:
        return 1
    useful_after_first = bits_per_regular_ciphertext - 1
    if useful_after_first <= 0:
        raise ValueError("p leaves no useful bit after the first dirty iteration")
    return 1 + math.ceil(
        (message_bits - bits_per_regular_ciphertext) / useful_after_first
    )


def minimum_schedules(message_bits: int, p: int) -> tuple[tuple[int, ...], ...]:
    limit = regular_data_bits(p)
    iterations = minimum_dirty_iterations(message_bits, p)
    return tuple(
        schedule
        for schedule in itertools.product(range(1, limit + 1), repeat=iterations)
        if dirty_schedule_capacity(schedule) == message_bits
    )


def patch_surface() -> dict[str, object]:
    patch = (ROOT / "tmp/pdfs/head-start.patch").read_text()
    touched = [line for line in patch.splitlines() if line.startswith("diff --git ")]
    return {
        "lines": len(patch.splitlines()),
        "files_touched": len(touched),
        "changes_core_keyswitch": "lwe_keyswitch.rs" in patch,
        "changes_core_fft_bootstrap": "fft64/crypto/bootstrap.rs" in patch,
        "changes_workspace_and_benches": (
            "diff --git a/Cargo.toml" in patch and "tfhe/benches/integer/bench.rs" in patch
        ),
        "exact_named_standalone_api_marker_found": (
            "fn digit_decomposition" in patch or "fn dirty_msb" in patch.lower()
        ),
    }


def report() -> dict[str, object]:
    pins = verify_source_pins()
    current = score_encoding_row(CURRENT_SCORE_DELTA_LOG)
    candidate = score_encoding_row(CANDIDATE_SCORE_DELTA_LOG)
    p_sweep = []
    for p in (32, 64, 128, 256):
        schedules = minimum_schedules(SCORE_BITS, p)
        p_sweep.append(
            {
                "paper_plaintext_modulus_p": p,
                "data_bits_excluding_padding": regular_data_bits(p),
                "minimum_dirty_iterations": minimum_dirty_iterations(SCORE_BITS, p),
                "minimum_schedules": [list(schedule) for schedule in schedules],
                "is_current_a44_p16_geometry": p == A44_PAPER_PLAINTEXT_MODULUS,
                "a44_regular_output_geometry_available": (
                    p == A44_PAPER_PLAINTEXT_MODULUS
                ),
                "head_start_composed_noise_contract_available": False,
            }
        )

    p32_iterations = minimum_dirty_iterations(SCORE_BITS, A44_PAPER_PLAINTEXT_MODULUS)
    return {
        "status": "PASS_SHAPE_GATE_CURRENT_DIRECT_NO_GO_DELTA51_OPEN",
        "source_pins_verified": pins,
        "score_domain": {"bits": SCORE_BITS, "minimum": 0, "maximum": MAX_NORMALIZED_SCORE},
        "score_encodings": {"current": current, "candidate": candidate},
        "a44_regular_geometry": {
            "message_modulus": A44_MESSAGE_MODULUS,
            "carry_modulus": A44_CARRY_MODULUS,
            "paper_p_including_padding": A44_PAPER_PLAINTEXT_MODULUS,
            "data_bits_excluding_padding": regular_data_bits(
                A44_PAPER_PLAINTEXT_MODULUS
            ),
            "glwe_noise_std_dev_normalized": A44_GLWE_STD_DEV_NORMALIZED,
            "initial_score_noise_advisory": (
                "linear independent-Gaussian propagation only; not a support or composed-noise certificate"
            ),
        },
        "head_start_iteration_lower_bounds": p_sweep,
        "a30_bridge_screen": {
            "current_bridge_br_per_score": A30_CURRENT_BR_PER_SCORE,
            "head_start_p32_decomposition_floor_per_score": p32_iterations,
            "gross_br_difference_before_conversion_cleanup_and_canonicalization": (
                A30_CURRENT_BR_PER_SCORE - p32_iterations
            ),
            "head_start_p32_outputs_at_floor": p32_iterations,
            "a30_required_canonical_nibbles": 3,
            "direct_three_canonical_nibbles_proven": False,
        },
        "artifact_port_surface": patch_surface(),
        "claims": {
            "current_delta52_direct_compatible": False,
            "delta51_geometrically_compatible": True,
            "delta51_head_start_noise_certified": False,
            "standalone_tfhe_1_7_port_available": False,
            "runtime_or_exact_id_speedup_claim": False,
            "promotion_allowed": False,
        },
        "next_gates": [
            "isolate corrected KS/modulus-switch/PBS functions on pinned tfhe-rs 1.7",
            "exhaust x=0..4095 at Delta=2^51 on fresh keys and record phase errors",
            "prove a canonical score/limb mapping including every cleanup PBS",
            "compare total observed bridge BR/KS and latency against A30 B0, not the 4-PBS floor",
        ],
    }


def main() -> None:
    print(json.dumps(report(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
