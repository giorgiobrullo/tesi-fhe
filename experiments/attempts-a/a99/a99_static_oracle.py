#!/usr/bin/env python3
"""Static exact-ring oracle and source preflight for the A99 runtime gate.

This script does not compile Rust, generate keys, run FHE, or benchmark.  It
checks that the three materialized source arms share the exact A92 Chen slot
permutation and post-kernel mixed-payload geometry before the runtime gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "tmp/a99-chen-grouped-runtime"
RUST_SOURCE = ARTIFACT / "src/main.rs"
SOURCE_PINS_PATH = ARTIFACT / "SOURCE_PINS.json"
CARGO_LOCK_PATH = ARTIFACT / "Cargo.lock"

WORD_MODULUS = 1 << 64
POLYNOMIAL_SIZE = 2048
SCORE_DELTA_LOG = 59
ID_DELTA_LOG = 56
TRACE_DEGREES = (33, 65, 129, 257, 513, 1025, 2049)
PACK_DEGREES = (3, 5, 9)
STRICT_RADIUS = 63
BOX_SIZE = 128
LEFT_CONTROL = 4
RIGHT_CONTROL = 12
SAMPLE_STEP = 256

AUTO_PARAMETER_SETS = (
    ("23x1", 23, 1),
    ("8x5", 8, 5),
    ("7x6", 7, 6),
)

LOCAL_INPUT_PINS = {
    ROOT / "tmp/a92-chen-partial-trace-packing/README.md": (
        "7a8f4308cae3efa5ff75051967ef07b56daf55c7e51e130846c5953b0a7af225"
    ),
    ROOT / "tmp/a92-chen-partial-trace-packing/a92_chen_partial_trace.py": (
        "3c6c8e2cc39de5c03c027837a03c98a62b7dbd04b3b56171788e8cc6a81c814b"
    ),
    ROOT / "tmp/a92-chen-partial-trace-packing/artifacts/a92_static_result.json": (
        "85405bd3981c41c0d578a320d025dfec42a8e7e5f2cd14660527d3cd3f10cce0"
    ),
    ROOT / "tmp/a95-chen-radius-trace-sensitivity/README.md": (
        "ce51912a6096467dcd934bddfc12855c28ed6982b9b099c74e44fab922764f1c"
    ),
    ROOT / "tmp/a95-chen-radius-trace-sensitivity/a95_trace_radius_sensitivity.py": (
        "9d23140b5cf2b392784f280cb0aabfdd675ccd3e52659e4460f69fb006b0a6a1"
    ),
    ROOT / "tmp/a96-chen-normalized-rounding-preflight/README.md": (
        "946473a243a2c61dd129749f7e41729a65885a8a931319ef91a2f278009df003"
    ),
    ROOT / "tmp/a96-chen-normalized-rounding-preflight/a96_chen_rounding.py": (
        "5e071a359cf3e1948eaccaad5c205eb79a7bfcde4e267e1755f0d7ece1bac588"
    ),
    ROOT
    / "tmp/a96-chen-normalized-rounding-preflight/artifacts/a96_static_result.json": (
        "1e132be1b87de948603bd5e1c8127f88d00a53f64325c678adc93a8ef007df92"
    ),
    ROOT / "tmp/a97-chen-evalauto-materialization/Cargo.toml": (
        "560142b7e94c155928bf1b8d1bdd4f9bf0923aea766bc114c57fdbe891da4cec"
    ),
    ROOT / "tmp/a97-chen-evalauto-materialization/Cargo.lock": (
        "8887f8122cbb3426642637211c0a7be26baa9579e2468ad77c4f880c4002fe8b"
    ),
    ROOT / "tmp/a97-chen-evalauto-materialization/src/main.rs": (
        "7024620d3a1d68a02d6c1e9cc1d167a9dc4506fce18a264f4279a3af9d8f945f"
    ),
    ROOT
    / "tmp/a97-chen-evalauto-materialization/results/a97_clean_fresh5_trials64_2026-09-03.log": (
        "7a34bbf8b1d2c956c7f86e90940d1ac17db6ab1880626d1a5549189af59b90d9"
    ),
}

TFHE_API_PINS = {
    "src/core_crypto/algorithms/ggsw_conversion.rs": (
        "05c5baf113faa90ec51ac82d8ed0128175399f4ee99d9bf582ed46a8d339b040"
    ),
    "src/core_crypto/algorithms/ggsw_encryption.rs": (
        "833955bd7f71fd05e9fdff348b6b99f6c1a2c67acef3d15a6c09684962c4f179"
    ),
    "src/core_crypto/algorithms/glwe_encryption.rs": (
        "0ee4904cc5defa063cf5f9f9b998a96a6200cdfe01513874d38a68b7a8453ef0"
    ),
    "src/core_crypto/algorithms/glwe_sample_extraction.rs": (
        "981d3839cd83cb8c24b02fe48d945d61e23c9c0f2e714b554d9296eed304ec43"
    ),
    "src/core_crypto/fft_impl/fft64/crypto/ggsw.rs": (
        "0827fef75039f7f34e17a80ecba444c039e02a5a24dad0d2fbf21df64d6ac69f"
    ),
}


class StaticPreflightError(RuntimeError):
    """Raised when an exact invariant or a source pin drifts."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_local_pins() -> dict[str, str]:
    observed: dict[str, str] = {}
    for path, expected in LOCAL_INPUT_PINS.items():
        actual = sha256(path)
        if actual != expected:
            raise StaticPreflightError(
                f"local input drift for {path.relative_to(ROOT)}: {actual} != {expected}"
            )
        observed[str(path.relative_to(ROOT))] = actual
    return observed


def verify_source_pins() -> dict[str, Any]:
    pins = json.loads(SOURCE_PINS_PATH.read_text(encoding="utf-8"))
    if pins["dependencies_planned"]["tfhe"]["version"] != "0.11.3":
        raise StaticPreflightError("SOURCE_PINS tfhe version drift")
    if pins["tfhe_0_11_3_local_api_sources"] != TFHE_API_PINS:
        raise StaticPreflightError("SOURCE_PINS local API hash table drift")
    lock_pin = pins.get("generated_lockfile")
    if lock_pin is None or lock_pin.get("path") != "Cargo.lock":
        raise StaticPreflightError("SOURCE_PINS generated lockfile pin missing")
    actual_lock_sha256 = sha256(CARGO_LOCK_PATH)
    if actual_lock_sha256 != lock_pin.get("sha256"):
        raise StaticPreflightError("generated Cargo.lock drift")
    compiled_gate = pins.get("compiled_gate")
    actual_rust_source_sha256 = sha256(RUST_SOURCE)
    if (
        compiled_gate is None
        or compiled_gate.get("source_sha256") != actual_rust_source_sha256
    ):
        raise StaticPreflightError("compiled-gate Rust source pin drift")
    if compiled_gate.get("keygen_invoked") or compiled_gate.get("fhe_invoked"):
        raise StaticPreflightError("compiled gate must remain pre-FHE")
    parameter_source = pins["primary_sources"]["refined_tfhe_lhe"]["files"][
        "error_analysis/param.sage"
    ]
    if parameter_source["sha256"] != (
        "6d856bf9858491d34e79cb656afad7f653715eda71d2b6bded8489ab0fcb4f11"
    ):
        raise StaticPreflightError("refined-tfhe parameter pin drift")

    candidates = sorted((Path.home() / ".cargo/registry/src").glob("*/tfhe-0.11.3"))
    matches: list[Path] = []
    for candidate in candidates:
        if all(
            (candidate / relative).is_file()
            and sha256(candidate / relative) == expected
            for relative, expected in TFHE_API_PINS.items()
        ):
            matches.append(candidate)
    if not matches:
        raise StaticPreflightError("no local tfhe-0.11.3 source matches API pins")
    return {
        "source_pins_json_sha256": sha256(SOURCE_PINS_PATH),
        "matching_local_tfhe_source_trees": len(matches),
        "api_files_verified": len(TFHE_API_PINS),
        "tfhe_crate_checksum": pins["dependencies_planned"]["tfhe"]["crate_checksum"],
        "refined_parameter_source_sha256": parameter_source["sha256"],
        "generated_lockfile_sha256": actual_lock_sha256,
        "compiled_rust_source_sha256": actual_rust_source_sha256,
        "compiled_release_binary_sha256": compiled_gate["release_binary_sha256"],
        "compiled_release_binary_bytes": compiled_gate["release_binary_bytes"],
    }


def add(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    return tuple((a + b) % WORD_MODULUS for a, b in zip(left, right, strict=True))


def sub(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    return tuple((a - b) % WORD_MODULUS for a, b in zip(left, right, strict=True))


def automorphism(polynomial: Sequence[int], degree: int) -> tuple[int, ...]:
    if len(polynomial) != POLYNOMIAL_SIZE:
        raise StaticPreflightError("wrong polynomial size")
    if degree % 2 != 1 or not 1 <= degree < 2 * POLYNOMIAL_SIZE:
        raise StaticPreflightError("invalid automorphism degree")
    output = [0] * POLYNOMIAL_SIZE
    for exponent, coefficient in enumerate(polynomial):
        product = exponent * degree
        index = product % POLYNOMIAL_SIZE
        sign = -1 if (product // POLYNOMIAL_SIZE) % 2 else 1
        output[index] = (output[index] + sign * coefficient) % WORD_MODULUS
    return tuple(output)


def monomial_mul(polynomial: Sequence[int], degree: int) -> tuple[int, ...]:
    output = [0] * POLYNOMIAL_SIZE
    for index, value in enumerate(polynomial):
        exponent = index + degree
        if exponent < POLYNOMIAL_SIZE:
            output[exponent] = value
        else:
            output[exponent - POLYNOMIAL_SIZE] = (-value) % WORD_MODULUS
    return tuple(output)


def shifted_word(word: int, shift: int, rounding: str) -> int:
    if not 0 <= word < WORD_MODULUS or not 0 < shift < 64:
        raise StaticPreflightError("invalid public shift input")
    if rounding == "floor":
        return word >> shift
    if rounding == "nearest":
        divisor = 1 << shift
        return ((word + divisor // 2) // divisor) % (1 << (64 - shift))
    raise StaticPreflightError("unknown rounding mode")


def normalize(polynomial: Sequence[int], shift: int, rounding: str) -> tuple[int, ...]:
    return tuple(shifted_word(word, shift, rounding) for word in polynomial)


def merge(
    even: Sequence[int], odd: Sequence[int], subtree_count: int
) -> tuple[int, ...]:
    shifted_odd = monomial_mul(odd, POLYNOMIAL_SIZE // subtree_count)
    transformed = automorphism(sub(even, shifted_odd), subtree_count + 1)
    return add(add(transformed, even), shifted_odd)


def merge_g1_floor(
    even: Sequence[int], odd: Sequence[int], subtree_count: int
) -> tuple[int, ...]:
    # TFHEpp order: shift odd first, then unsigned coefficientwise floor /2.
    even_half = normalize(even, 1, "floor")
    odd_half = normalize(
        monomial_mul(odd, POLYNOMIAL_SIZE // subtree_count), 1, "floor"
    )
    transformed = automorphism(sub(even_half, odd_half), subtree_count + 1)
    return add(add(transformed, even_half), odd_half)


def pack_g1_floor(inputs: Sequence[Sequence[int]]) -> tuple[int, ...]:
    if not inputs or len(inputs) & (len(inputs) - 1):
        raise StaticPreflightError("packing arity must be a nonzero power of two")
    if len(inputs) == 1:
        return tuple(inputs[0])
    even = pack_g1_floor(inputs[0::2])
    odd = pack_g1_floor(inputs[1::2])
    return merge_g1_floor(even, odd, len(inputs))


def pack_g2(inputs: Sequence[Sequence[int]], rounding: str) -> tuple[int, ...]:
    if len(inputs) != 8:
        raise StaticPreflightError("A99 g2 gate requires eight inputs")
    embedded = [normalize(item, 2, rounding) for item in inputs]
    # Exact parity-split Chen DAG, matching recursive pack_g1_floor.
    bottom = (
        merge(embedded[0], embedded[4], 2),
        merge(embedded[2], embedded[6], 2),
        merge(embedded[1], embedded[5], 2),
        merge(embedded[3], embedded[7], 2),
    )
    middle = [merge(bottom[0], bottom[1], 4), merge(bottom[2], bottom[3], 4)]
    middle = [normalize(branch, 2, rounding) for branch in middle]
    output = merge(middle[0], middle[1], 8)
    output = add(output, automorphism(output, TRACE_DEGREES[0]))
    for first, second in zip(TRACE_DEGREES[1::2], TRACE_DEGREES[2::2], strict=True):
        output = normalize(output, 2, rounding)
        output = add(output, automorphism(output, first))
        output = add(output, automorphism(output, second))
    return output


def run_arm(inputs: Sequence[Sequence[int]], arm: str) -> tuple[int, ...]:
    if arm == "g1-floor":
        output = pack_g1_floor(inputs)
        for degree in TRACE_DEGREES:
            output = normalize(output, 1, "floor")
            output = add(output, automorphism(output, degree))
        return output
    if arm == "g2-floor":
        return pack_g2(inputs, "floor")
    if arm == "g2-nearest":
        return pack_g2(inputs, "nearest")
    raise StaticPreflightError(f"unknown arm: {arm}")


def sparse_input(word: int) -> tuple[int, ...]:
    return (word, *(0 for _ in range(POLYNOMIAL_SIZE - 1)))


def add_kernel_word(output: list[int], center: int, word: int) -> None:
    for offset in range(-STRICT_RADIUS, STRICT_RADIUS + 1):
        exponent = center + offset
        cycle, target = divmod(exponent, POLYNOMIAL_SIZE)
        signed = word if cycle % 2 == 0 else -word
        output[target] = (output[target] + signed) % WORD_MODULUS


def public_kernel(polynomial: Sequence[int]) -> tuple[int, ...]:
    output = [0] * POLYNOMIAL_SIZE
    for index, word in enumerate(polynomial):
        if word:
            add_kernel_word(output, index, word)
    return tuple(output)


def virtual_sample(polynomial: Sequence[int], degree: int) -> int:
    cycle, index = divmod(degree, POLYNOMIAL_SIZE)
    return polynomial[index] if cycle % 2 == 0 else (-polynomial[index]) % WORD_MODULUS


def encode(value: int, delta_log: int) -> int:
    return value * (1 << delta_log) % WORD_MODULUS


def fixtures() -> tuple[tuple[tuple[int, ...], tuple[int, ...]], ...]:
    return (
        (
            (encode(0, 59), encode(7, 59), encode(15, 59), encode(0, 56)),
            (encode(0, 59), encode(7, 59), encode(15, 59), encode(127, 56)),
        ),
        (
            (encode(1, 59), encode(2, 59), encode(3, 59), encode(17, 56)),
            (encode(4, 59), encode(5, 59), encode(6, 59), encode(91, 56)),
        ),
        (
            (encode(15, 59), encode(0, 59), encode(8, 59), encode(63, 56)),
            (encode(2, 59), encode(14, 59), encode(1, 59), encode(64, 56)),
        ),
    )


def slot_words(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    return (
        (-right[2]) % WORD_MODULUS,
        (-right[3]) % WORD_MODULUS,
        left[0],
        left[1],
        left[2],
        left[3],
        right[0],
        right[1],
    )


def basis_slot_audit() -> dict[str, Any]:
    basis = 1 << 32
    arms = ("g1-floor", "g2-floor", "g2-nearest")
    checks = 0
    mappings: dict[str, list[int]] = {}
    for arm in arms:
        mapped: list[int] = []
        for source_slot in range(8):
            inputs = [
                sparse_input(basis if index == source_slot else 0) for index in range(8)
            ]
            observed = run_arm(inputs, arm)
            expected = [0] * POLYNOMIAL_SIZE
            expected[source_slot * SAMPLE_STEP] = basis
            if observed != tuple(expected):
                nonzero = [index for index, value in enumerate(observed) if value]
                raise StaticPreflightError(
                    f"{arm} source slot {source_slot} mismatch; nonzero={nonzero[:16]}"
                )
            mapped.append(source_slot * SAMPLE_STEP)
            checks += POLYNOMIAL_SIZE
        mappings[arm] = mapped
    expected_mapping = [index * SAMPLE_STEP for index in range(8)]
    if any(mapping != expected_mapping for mapping in mappings.values()):
        raise StaticPreflightError("an arm changed the Chen slot permutation")
    return {
        "arms": list(arms),
        "basis_word": basis,
        "coefficient_checks": checks,
        "slot_to_coefficient": mappings,
        "all_arms_identical": True,
    }


def mixed_payload_audit() -> dict[str, Any]:
    arms = ("g1-floor", "g2-floor", "g2-nearest")
    word_checks = 0
    tuple_checks = 0
    full_polynomial_checks = 0
    for fixture_index, (left, right) in enumerate(fixtures()):
        words = slot_words(left, right)
        inputs = [sparse_input(word) for word in words]
        expected_pre_kernel = [0] * POLYNOMIAL_SIZE
        for index, word in enumerate(words):
            expected_pre_kernel[index * SAMPLE_STEP] = word
        expected_post_kernel = public_kernel(expected_pre_kernel)
        for arm in arms:
            pre_kernel = run_arm(inputs, arm)
            if pre_kernel != tuple(expected_pre_kernel):
                raise StaticPreflightError(
                    f"{arm} fixture {fixture_index} pre-kernel polynomial mismatch"
                )
            post_kernel = public_kernel(pre_kernel)
            if post_kernel != expected_post_kernel:
                raise StaticPreflightError(
                    f"{arm} fixture {fixture_index} public kernel mismatch"
                )
            full_polynomial_checks += 2 * POLYNOMIAL_SIZE
            for control, expected_tuple in (
                (LEFT_CONTROL, left),
                (RIGHT_CONTROL, right),
            ):
                for error in range(-STRICT_RADIUS, STRICT_RADIUS + 1):
                    observed = tuple(
                        virtual_sample(
                            post_kernel,
                            control * BOX_SIZE + error + index * SAMPLE_STEP,
                        )
                        for index in range(4)
                    )
                    if observed != expected_tuple:
                        raise StaticPreflightError(
                            f"{arm} fixture {fixture_index} control {control} error {error} mismatch"
                        )
                    tuple_checks += 1
                    word_checks += 4
    return {
        "fixtures": len(fixtures()),
        "arms": list(arms),
        "full_polynomial_checks": full_polynomial_checks,
        "robust_tuple_checks": tuple_checks,
        "robust_word_checks": word_checks,
        "controls": [LEFT_CONTROL, RIGHT_CONTROL],
        "inclusive_rotation_errors": [-STRICT_RADIUS, STRICT_RADIUS],
        "mixed_score_delta_log": SCORE_DELTA_LOG,
        "mixed_id_delta_log": ID_DELTA_LOG,
        "reject_zero_exercised": True,
        "id_127_exercised": True,
    }


def expected_evalauto_degrees() -> list[int]:
    return [3, 3, 3, 3, 5, 5, 9, *TRACE_DEGREES]


def source_text_audit() -> dict[str, Any]:
    source = RUST_SOURCE.read_text(encoding="utf-8")
    required = (
        'name: "23x1"',
        'name: "8x5"',
        'name: "7x6"',
        "normalize_glwe_assign(&mut even_half, 1, Rounding::Floor)",
        "normalize_glwe_assign(&mut odd_half, 1, Rounding::Floor)",
        "normalize_lwe_assign(&mut shifted, 2, rounding)",
        "merge_unnormalized(&inputs[0], &inputs[4], 2, keys, audit)",
        "merge_unnormalized(&inputs[2], &inputs[6], 2, keys, audit)",
        "merge_unnormalized(&inputs[1], &inputs[5], 2, keys, audit)",
        "merge_unnormalized(&inputs[3], &inputs[7], 2, keys, audit)",
        "automorphism_oracle_inverse(&input_phase, degree)",
        "message_reference_available=false",
        "cross_parameter_pairing=false",
        "causal_cross_parameter_comparison_allowed=false",
        "const MAX_FRESH_KEYSETS: usize = 16;",
        "const MAX_TRIALS_PER_KEYSET: usize = 64;",
        '"--ack-component-only"',
        "runtime requires both --run and --ack-component-only",
        "full_selector_proven=false",
        "composed_pfail_proven=false",
        "runtime_frontier_promoted=false",
    )
    missing = [needle for needle in required if needle not in source]
    if missing:
        raise StaticPreflightError(f"Rust scaffold lost required markers: {missing}")
    forbidden = ("DECOMPOSITION_BASE_LOG", "DECOMPOSITION_LEVEL_COUNT")
    present_forbidden = [needle for needle in forbidden if needle in source]
    if present_forbidden:
        raise StaticPreflightError(
            f"stale fixed decomposition markers: {present_forbidden}"
        )
    if "mod_inverse" in source or "inverse_mod" in source:
        raise StaticPreflightError("normalization must not introduce a modular inverse")
    return {
        "rust_source_sha256": sha256(RUST_SOURCE),
        "required_markers_checked": len(required),
        "stale_fixed_decomposition_markers_absent": True,
        "modular_inverse_markers_absent": True,
    }


def key_ledger() -> list[dict[str, Any]]:
    rows = []
    for name, base_log, level_count in AUTO_PARAMETER_SETS:
        bytes_per_key = level_count * 4 * (POLYNOMIAL_SIZE // 2) * 16
        rows.append(
            {
                "name": name,
                "base_log": base_log,
                "level_count": level_count,
                "full_fourier_bytes_per_key": bytes_per_key,
                "ten_full_fourier_keys_bytes": 10 * bytes_per_key,
                "ten_full_fourier_keys_mib": 10 * bytes_per_key / (1024 * 1024),
            }
        )
    return rows


def schedule_ledger() -> dict[str, Any]:
    degrees = expected_evalauto_degrees()
    multiplicity = {str(key): value for key, value in sorted(Counter(degrees).items())}
    if len(degrees) != 14 or multiplicity != {
        "3": 4,
        "5": 2,
        "9": 1,
        "33": 1,
        "65": 1,
        "129": 1,
        "257": 1,
        "513": 1,
        "1025": 1,
        "2049": 1,
    }:
        raise StaticPreflightError("EvalAuto schedule drift")
    return {
        "evalauto_calls": len(degrees),
        "degree_multiplicity": multiplicity,
        "g1_normalization_objects": 21,
        "g1_coefficient_touches": 21 * 2 * POLYNOMIAL_SIZE,
        "g2_normalization_objects": 13,
        "g2_coefficient_touches": 8 * (POLYNOMIAL_SIZE + 1) + 5 * 2 * POLYNOMIAL_SIZE,
        "g2_groups": [2, 2, 2, 2, 2],
        "maximum_internal_evalauto_gain_g2": 2,
    }


def build_report() -> dict[str, Any]:
    return {
        "schema": "a99.chen-grouped-runtime.static-preflight.v3",
        "date": "2026-09-03",
        "status": "COMPILED_DRY_ONLY_AWAITING_FHE_GATE",
        "static_environment": {
            "python": "3.12.11",
            "uv": "0.11.29",
            "system_python_3_9_supported": False,
        },
        "local_input_pins": verify_local_pins(),
        "primary_and_api_source_pins": verify_source_pins(),
        "source_text_audit": source_text_audit(),
        "basis_slot_audit": basis_slot_audit(),
        "mixed_payload_audit": mixed_payload_audit(),
        "schedule_ledger": schedule_ledger(),
        "key_ledger": key_ledger(),
        "runtime_scope": {
            "real_lwe_encryptions_planned": True,
            "full_fourier_ggsw_first_gate": True,
            "stage_actual_phase_audit_planned": True,
            "timed_path_separate_from_client_decryption": True,
            "cross_parameter_pairing": False,
            "causal_cross_parameter_timing_or_noise_comparison_allowed": False,
            "offline_cargo_lockfile_generated": True,
            "cargo_fmt_check_passed": True,
            "rust_compilation_passed": True,
            "rust_tests_passed": 7,
            "release_binary_built": True,
            "fail_closed_dry_plan_passed": True,
            "fhe_run_in_this_static_report": False,
            "full_selector_included": False,
            "encrypted_control_blind_rotation_included": False,
            "tie_first_encrypted_decision_proven": False,
            "full_tournament_proven": False,
            "composed_pfail_proven": False,
            "runtime_frontier_promoted": False,
        },
        "interpretation": {
            "exact": [
                "clear u64 ring geometry for all eight basis inputs and three arms",
                "mixed Delta59/Delta56 slot map and width-127 robust extraction geometry",
                "normalization object/coefficient counts and full-GGSW storage geometry",
            ],
            "awaits_build_and_fhe": [
                "Rust API/type correctness",
                "real grouped-normalization ciphertext correctness",
                "EvalAuto noise sufficiency for each decomposition",
                "all timings",
            ],
        },
    }


def canonical_bytes(report: dict[str, Any]) -> bytes:
    return json.dumps(report, sort_keys=True, separators=(",", ":")).encode()


def write_or_verify(
    report: dict[str, Any], output: Path, verify: bool, expected_digest: str | None
) -> str:
    digest = hashlib.sha256(canonical_bytes(report)).hexdigest()
    if expected_digest is not None and digest != expected_digest:
        raise StaticPreflightError(
            f"canonical digest mismatch: observed {digest}, expected {expected_digest}"
        )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if verify:
        if not output.exists():
            raise StaticPreflightError(f"missing frozen report: {output}")
        if output.read_text(encoding="utf-8") != rendered:
            raise StaticPreflightError("frozen report does not match reconstruction")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    return digest


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--expected-canonical-sha256")
    return parser.parse_args(argv)


def main() -> None:
    args = parse_args()
    digest = write_or_verify(
        build_report(), args.output, args.verify, args.expected_canonical_sha256
    )
    print(f"canonical_sha256={digest}")
    print("status=COMPILED_DRY_ONLY_AWAITING_FHE_GATE")


if __name__ == "__main__":
    main()
