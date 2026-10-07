#!/usr/bin/env python3
"""Static exact-ring oracle and source preflight for the A104 runtime candidate.

This script does not compile Rust, generate keys, run FHE, or benchmark.  It
checks that five source arms preserve the useful A92 geometry, while allowing
the documented A99/MS differences in interleaved residual cells.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import runpy
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "tmp/a104-ms-pack-chen-runtime"
RUST_SOURCE = ARTIFACT / "src/main.rs"
SOURCE_PINS_PATH = ARTIFACT / "SOURCE_PINS.json"
CARGO_LOCK_PATH = ARTIFACT / "Cargo.lock"
A92_SCRIPT = ROOT / "tmp/a92-chen-partial-trace-packing/a92_chen_partial_trace.py"

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
    ("10x4", 10, 4),
    ("8x5", 8, 5),
    ("7x6", 7, 6),
)
ARMS = ("g1-floor", "g2-floor", "g2-nearest", "ms-floor", "ms-nearest")
PARITY_TEMPORAL_DEGREES = (3, 3, 5, 3, 3, 5, 9, *TRACE_DEGREES)
GROUPED_TEMPORAL_DEGREES = (3, 3, 3, 3, 5, 5, 9, *TRACE_DEGREES)

LOCAL_INPUT_PINS = {
    ROOT / "tmp/a92-chen-partial-trace-packing/a92_chen_partial_trace.py": (
        "3c6c8e2cc39de5c03c027837a03c98a62b7dbd04b3b56171788e8cc6a81c814b"
    ),
    ROOT / "tmp/a92-chen-partial-trace-packing/artifacts/a92_static_result.json": (
        "85405bd3981c41c0d578a320d025dfec42a8e7e5f2cd14660527d3cd3f10cce0"
    ),
    ROOT / "tmp/a87-packed-dynamic-pfks-tuple-selector/a87_packed_pfks.py": (
        "4b895a48703806612156e258356a5d3c957e0abae3ec44648ba5520cfda193ff"
    ),
    ROOT / "tmp/a99-chen-grouped-runtime/src/main.rs": (
        "3c563d728be8b634c02d47802c0a2289675683d40c68139420688e1745bf342b"
    ),
    ROOT / "tmp/a99-chen-grouped-runtime/a99_static_oracle.py": (
        "8b9d138e35c6fa78ca1de47d5bc0864309a174b30433335b27127901f31b5055"
    ),
    ROOT / "tmp/a99-chen-grouped-runtime/artifacts/a99_static_result.json": (
        "09f0810312303fffc3f3fd4b87944b23f9a98555f21c2eb291e37cd81146235e"
    ),
    ROOT / "tmp/a102-revhomtrace-mapping/a102_revhomtrace_mapping.py": (
        "51e27becec3ca4084008057a9e17188bf2ec9f65a598996a3f3bd1118ff9280d"
    ),
    ROOT / "tmp/a102-revhomtrace-mapping/artifacts/a102_static_result.json": (
        "277c25fba3fff2da4f6f2b1e68244b79bf115e4fbfea3ca298805c1253a0c9e0"
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
    declared_local: dict[str, str] = {}
    local_tables = (
        (ROOT / pins["derived_from_a99"]["directory"], pins["derived_from_a99"]),
        (ROOT / "tmp/a102-revhomtrace-mapping", pins["a102_mapping_inputs"]),
        (ROOT, pins["contract_inputs"]),
    )
    for base, table in local_tables:
        for relative, expected in table.items():
            if relative == "directory":
                continue
            path = base / relative
            actual = sha256(path)
            if actual != expected:
                raise StaticPreflightError(
                    f"declared local source drift for {path.relative_to(ROOT)}: "
                    f"{actual} != {expected}"
                )
            declared_local[str(path.relative_to(ROOT))] = actual
    if pins["dependencies_planned"]["tfhe"]["version"] != "0.11.3":
        raise StaticPreflightError("SOURCE_PINS tfhe version drift")
    if pins["tfhe_0_11_3_local_api_sources"] != TFHE_API_PINS:
        raise StaticPreflightError("SOURCE_PINS local API hash table drift")
    lock_pin = pins.get("cargo_lockfile")
    if lock_pin is None or lock_pin.get("path") != "Cargo.lock":
        raise StaticPreflightError("SOURCE_PINS Cargo.lock pin missing")
    actual_lock_sha256 = sha256(CARGO_LOCK_PATH)
    if actual_lock_sha256 != lock_pin.get("sha256"):
        raise StaticPreflightError("Cargo.lock drift")
    cargo_toml = (ARTIFACT / "Cargo.toml").read_text(encoding="utf-8")
    lock_text = CARGO_LOCK_PATH.read_text(encoding="utf-8")
    dependency_markers = {
        "aligned-vec": ('aligned-vec = "=0.6.4"', "0.6.4"),
        "tfhe": ('tfhe = { version = "=0.11.3", features = ["integer"] }', "0.11.3"),
    }
    for name, (toml_marker, version) in dependency_markers.items():
        metadata = pins["dependencies_planned"][name]
        if metadata["version"] != version or toml_marker not in cargo_toml:
            raise StaticPreflightError(f"Cargo.toml dependency pin drift for {name}")
        blocks = [
            block
            for block in lock_text.split("[[package]]")
            if f'name = "{name}"' in block and f'version = "{version}"' in block
        ]
        checksum_marker = f'checksum = "{metadata["crate_checksum"]}"'
        if len(blocks) != 1 or checksum_marker not in blocks[0]:
            raise StaticPreflightError(f"Cargo.lock package pin drift for {name}")
    if 'name = "a104_ms_pack_chen_runtime"' not in cargo_toml or not re.search(
        r'\[\[package\]\]\s+name = "a104_ms_pack_chen_runtime"\s+version = "0\.1\.0"',
        lock_text,
    ):
        raise StaticPreflightError("A104 Cargo root package identity drift")
    paper = pins["primary_sources"]["revhomtrace_paper"]
    repository = pins["primary_sources"]["official_revhomtrace_repository"]
    if paper["pdf_sha256"] != (
        "4f1033580542c56baa8a493aab178681082df768cd3446cc4470bc75b49589a9"
    ):
        raise StaticPreflightError("RevHomTrace paper pin drift")
    if paper.get("url") != "https://eprint.iacr.org/2025/1088.pdf":
        raise StaticPreflightError("RevHomTrace paper URL drift")
    if repository["commit"] != "47c8f6f6b65a451a14b542dc45c873f1e962decd":
        raise StaticPreflightError("RevHomTrace repository commit drift")
    if repository.get("tree") != "e2283e183bd4c0e43b9ef3462c8e0decaa9508e5":
        raise StaticPreflightError("RevHomTrace repository tree drift")
    if repository.get("remote") != "https://github.com/Stirling75/RevHomTrace.git":
        raise StaticPreflightError("RevHomTrace repository remote drift")
    expected_official_files = {
        "src/automorphism_rev.rs": "95ac14c63c57e5d34426a8dcfffaa1be6c7b9e3338d630eced108fa70089cf72",
        "src/glwe_conv_rev.rs": "f4800309bd004e3b8246b3713972300e0c8dde4321038e40feef5955c14fcc30",
        "src/mod_switch.rs": "411385cb04f659f2d66c0e32ebb6d8ce69be6b735227a1b8ee1e3c2f2cb9b38c",
        "src/mod_switch_rev.rs": "76a72d24442880cc2d12e3152c7d0b684143e9864a2e6fdd2cf31acb7ca5fd03",
        "src/int_lhe_instance.rs": "904cd82f996a8e2f41aa433b67fac18d96629573d27cbbc81fef1efe95946733",
        "benches/bench_ks.rs": "b6e93ac1bd0ca1bd17a0d930a79eadc16cad371752f73eba159bb88a5371d1d7",
    }
    if repository["files"] != expected_official_files:
        raise StaticPreflightError("official RevHomTrace source pin drift")

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
        "declared_local_artifacts_verified": len(declared_local),
        "declared_local_artifact_hashes": declared_local,
        "matching_local_tfhe_source_trees": len(matches),
        "api_files_verified": len(TFHE_API_PINS),
        "tfhe_crate_checksum": pins["dependencies_planned"]["tfhe"]["crate_checksum"],
        "cargo_lockfile_sha256": actual_lock_sha256,
        "official_repository_commit": repository["commit"],
        "official_repository_tree": repository["tree"],
        "official_files_pinned": len(expected_official_files),
        "official_pins_inherited_from_hash_verified_a102": True,
        "paper_or_official_repository_redownloaded_in_a104": False,
        "a104_rust_source_sha256": sha256(RUST_SOURCE),
        "a104_compiled_or_built": False,
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


def merge_ms(
    even: Sequence[int],
    odd: Sequence[int],
    subtree_count: int,
    rounding: str,
) -> tuple[int, ...]:
    shifted_odd = monomial_mul(odd, POLYNOMIAL_SIZE // subtree_count)
    normalized_difference = normalize(sub(even, shifted_odd), 1, rounding)
    transformed = automorphism(normalized_difference, subtree_count + 1)
    return add(add(normalized_difference, transformed), shifted_odd)


def pack_ms(inputs: Sequence[Sequence[int]], rounding: str) -> tuple[int, ...]:
    if not inputs or len(inputs) & (len(inputs) - 1):
        raise StaticPreflightError("packing arity must be a nonzero power of two")
    if len(inputs) == 1:
        return tuple(inputs[0])
    even = pack_ms(inputs[0::2], rounding)
    odd = pack_ms(inputs[1::2], rounding)
    return merge_ms(even, odd, len(inputs), rounding)


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
    if arm in ("ms-floor", "ms-nearest"):
        rounding = arm.removeprefix("ms-")
        output = pack_ms(inputs, rounding)
        for degree in TRACE_DEGREES:
            output = normalize(output, 1, rounding)
            output = add(output, automorphism(output, degree))
        return output
    raise StaticPreflightError(f"unknown arm: {arm}")


def run_root_arm(inputs: Sequence[Sequence[int]], arm: str) -> tuple[int, ...]:
    if len(inputs) != 2:
        raise StaticPreflightError("root requires exactly two inputs")
    if arm == "g1-floor":
        output = pack_g1_floor(inputs)
        rounding = "floor"
        for degree in TRACE_DEGREES:
            output = normalize(output, 1, rounding)
            output = add(output, automorphism(output, degree))
        return output
    if arm in ("ms-floor", "ms-nearest"):
        rounding = arm.removeprefix("ms-")
        output = pack_ms(inputs, rounding)
        for degree in TRACE_DEGREES:
            output = normalize(output, 1, rounding)
            output = add(output, automorphism(output, degree))
        return output
    if arm in ("g2-floor", "g2-nearest"):
        rounding = arm.removeprefix("g2-")
        embedded = [normalize(item, 2, rounding) for item in inputs]
        output = merge(embedded[0], embedded[1], 2)
        output = add(output, automorphism(output, TRACE_DEGREES[0]))
        for first, second in zip(TRACE_DEGREES[1::2], TRACE_DEGREES[2::2], strict=True):
            output = normalize(output, 2, rounding)
            output = add(output, automorphism(output, first))
            output = add(output, automorphism(output, second))
        return output
    raise StaticPreflightError(f"unknown root arm: {arm}")


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
    checks = 0
    mappings: dict[str, list[int]] = {}
    for arm in ARMS:
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
        "arms": list(ARMS),
        "basis_word": basis,
        "coefficient_checks": checks,
        "slot_to_coefficient": mappings,
        "all_arms_identical": True,
    }


def mixed_payload_audit() -> dict[str, Any]:
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
        for arm in ARMS:
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
        "arms": list(ARMS),
        "full_polynomial_checks": full_polynomial_checks,
        "robust_tuple_checks": tuple_checks,
        "robust_word_checks": word_checks,
        "certified_reads_per_arm_per_fixture": 2 * 127 * 4,
        "controls": [LEFT_CONTROL, RIGHT_CONTROL],
        "inclusive_rotation_errors": [-STRICT_RADIUS, STRICT_RADIUS],
        "mixed_score_delta_log": SCORE_DELTA_LOG,
        "mixed_id_delta_log": ID_DELTA_LOG,
        "reject_zero_exercised": True,
        "id_127_exercised": True,
    }


def dense_residual_audit() -> dict[str, Any]:
    rng = random.Random(0xA104)
    inputs = tuple(
        tuple(
            (rng.randrange(1 << 20) << 20) % WORD_MODULUS
            for _ in range(POLYNOMIAL_SIZE)
        )
        for _ in range(8)
    )
    outputs = {
        "g1-floor": run_arm(inputs, "g1-floor"),
        "ms-floor": run_arm(inputs, "ms-floor"),
    }
    for arm, output in outputs.items():
        off_support = [
            index
            for index, value in enumerate(output)
            if value and index % (POLYNOMIAL_SIZE // 16)
        ]
        if off_support:
            raise StaticPreflightError(f"{arm} dense output escaped partial support")
        for slot, source in enumerate(inputs):
            if output[slot * SAMPLE_STEP] != source[0]:
                raise StaticPreflightError(f"{arm} dense wanted slot {slot} mismatch")

    g1 = outputs["g1-floor"]
    ms = outputs["ms-floor"]
    wanted_disagreements = [
        index
        for index in range(0, POLYNOMIAL_SIZE, SAMPLE_STEP)
        if g1[index] != ms[index]
    ]
    residual_indices = list(range(POLYNOMIAL_SIZE // 16, POLYNOMIAL_SIZE, SAMPLE_STEP))
    residual_disagreements = [
        index for index in residual_indices if g1[index] != ms[index]
    ]
    residual_nonzero = [index for index in residual_indices if ms[index] != 0]
    if wanted_disagreements:
        raise StaticPreflightError("dense A99/MS wanted slots differ")
    if not residual_disagreements or not residual_nonzero:
        raise StaticPreflightError(
            "dense fixture did not exercise allowed residual differences"
        )

    post = {arm: public_kernel(output) for arm, output in outputs.items()}
    certified_checks = 0
    certified_disagreements = 0
    for slot, source in enumerate(inputs):
        center = slot * SAMPLE_STEP
        for error in range(-STRICT_RADIUS, STRICT_RADIUS + 1):
            g1_word = virtual_sample(post["g1-floor"], center + error)
            ms_word = virtual_sample(post["ms-floor"], center + error)
            if g1_word != source[0] or ms_word != source[0]:
                raise StaticPreflightError(
                    f"dense certified sample mismatch at slot={slot},error={error}"
                )
            certified_disagreements += int(g1_word != ms_word)
            certified_checks += 1
    return {
        "fixture_seed": "0xA104",
        "coefficient_low_zero_bits": 20,
        "wanted_slot_disagreement_indices": wanted_disagreements,
        "residual_cell_disagreement_indices": residual_disagreements,
        "residual_nonzero_indices": residual_nonzero,
        "global_full_polynomial_equality_required": False,
        "certified_width127_checks_per_arm": certified_checks,
        "certified_width127_disagreements": certified_disagreements,
        "off_support_nonzero_allowed": False,
    }


def root_geometry_audit() -> dict[str, Any]:
    rng = random.Random(0xA104_200)
    pairs = [
        (encode(0, ID_DELTA_LOG), encode(0, ID_DELTA_LOG)),
        (encode(0, ID_DELTA_LOG), encode(127, ID_DELTA_LOG)),
        (encode(127, ID_DELTA_LOG), encode(0, ID_DELTA_LOG)),
        (encode(63, ID_DELTA_LOG), encode(64, ID_DELTA_LOG)),
    ]
    pairs.extend(
        (
            encode(rng.randrange(128), ID_DELTA_LOG),
            encode(rng.randrange(128), ID_DELTA_LOG),
        )
        for _ in range(8)
    )
    checks = 0
    mappings: dict[str, list[int]] = {}
    for arm in ARMS:
        for fixture_index, (left, right) in enumerate(pairs):
            difference = (right - left) % WORD_MODULUS
            for variant, root_words in (
                ("D2", (left, right)),
                ("D1", (0, difference)),
            ):
                inputs = tuple(sparse_input(word) for word in root_words)
                pre_shift = run_root_arm(inputs, arm)
                if (
                    pre_shift[0] != root_words[0]
                    or pre_shift[POLYNOMIAL_SIZE // 2] != root_words[1]
                ):
                    raise StaticPreflightError(
                        f"{arm} {variant} root wanted-slot mismatch at {fixture_index}"
                    )
                if any(
                    value
                    for index, value in enumerate(pre_shift)
                    if index not in (0, POLYNOMIAL_SIZE // 2)
                ):
                    raise StaticPreflightError(
                        f"{arm} {variant} sparse root has unexpected residual"
                    )
                shifted = monomial_mul(pre_shift, LEFT_CONTROL * BOX_SIZE)
                post_kernel = public_kernel(shifted)
                for control, expected in (
                    (LEFT_CONTROL, left),
                    (RIGHT_CONTROL, right),
                ):
                    for error in range(-STRICT_RADIUS, STRICT_RADIUS + 1):
                        observed = virtual_sample(
                            post_kernel, control * BOX_SIZE + error
                        )
                        if variant == "D1":
                            observed = (left + observed) % WORD_MODULUS
                        if observed != expected:
                            raise StaticPreflightError(
                                f"{arm} {variant} root sample mismatch at "
                                f"fixture={fixture_index},control={control},error={error}"
                            )
                        checks += 1
        mappings[arm] = [0, POLYNOMIAL_SIZE // 2]
    return {
        "arms": list(ARMS),
        "variants": ["D2", "D1"],
        "input_order_d2": ["L0", "R0"],
        "input_order_d1": ["0", "R0-L0"],
        "d1_left_add_after_extraction": True,
        "fixture_seed": "0xA104_200",
        "fixture_pairs": len(pairs),
        "pre_shift_slot_indices": mappings,
        "public_global_shift": LEFT_CONTROL * BOX_SIZE,
        "post_shift_centers": [LEFT_CONTROL * BOX_SIZE, RIGHT_CONTROL * BOX_SIZE],
        "id_delta_log": ID_DELTA_LOG,
        "certified_reads": checks,
        "certified_reads_per_arm_variant_fixture": 2 * 127,
        "root_fhe_included": False,
    }


def inherited_contract_audit() -> dict[str, Any]:
    a92 = runpy.run_path(str(A92_SCRIPT))
    inherited = a92["contract_audit"](trials=90, seed=0xA104)
    required_ragged = {33, 63, 64, 65, 126}
    if not required_ragged.issubset(inherited["ragged_sizes"]):
        raise StaticPreflightError("A92 ragged contract coverage drift")
    if inherited["tie_policy"] != "first minimum":
        raise StaticPreflightError("stable-first tie contract drift")
    if inherited["output_contract"] != "0 reject / i+1 exact nearest accepted identity":
        raise StaticPreflightError("exact ID output contract drift")
    return {
        **inherited,
        "transfer_basis": (
            "each A104 arm passes the same non-root wanted-slot and root maps; "
            "the encrypted selector remains outside A104"
        ),
        "arms_covered_by_geometry_before_transfer": list(ARMS),
    }


def expected_evalauto_degrees() -> list[int]:
    return [3, 3, 3, 3, 5, 5, 9, *TRACE_DEGREES]


def rust_format_record_audit(source: str, record: str) -> dict[str, int]:
    """Count static println placeholders and top-level arguments without rustc."""
    marker = f'"{record},'
    if source.count(marker) != 1:
        raise StaticPreflightError(f"expected one {record} format record")
    literal_start = source.index(marker)
    literal_end = source.index('"', literal_start + 1)
    literal = source[literal_start + 1 : literal_end]
    if "{{" in literal or "}}" in literal:
        raise StaticPreflightError(f"escaped braces not supported in {record} audit")
    placeholders = len(re.findall(r"\{[^{}]*\}", literal))

    call_open = source.rfind("println!(", 0, literal_start) + len("println!")
    if call_open < len("println!") or source[call_open] != "(":
        raise StaticPreflightError(f"cannot locate println call for {record}")
    depth = 0
    call_close = None
    for index in range(call_open, len(source)):
        character = source[index]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                call_close = index
                break
    if call_close is None:
        raise StaticPreflightError(f"unterminated println call for {record}")

    argument_source = source[literal_end + 1 : call_close]
    if not argument_source.lstrip().startswith(","):
        raise StaticPreflightError(f"missing argument separator for {record}")
    argument_source = argument_source.lstrip()[1:]
    delimiter_depth = 0
    item_start = 0
    items: list[str] = []
    for index, character in enumerate(argument_source):
        if character in "([{":
            delimiter_depth += 1
        elif character in ")]}":
            delimiter_depth -= 1
        elif character == "," and delimiter_depth == 0:
            item = argument_source[item_start:index].strip()
            if item:
                items.append(item)
            item_start = index + 1
    tail = argument_source[item_start:].strip()
    if tail:
        items.append(tail)
    if delimiter_depth != 0:
        raise StaticPreflightError(f"unbalanced delimiters in {record} arguments")
    if placeholders != len(items):
        raise StaticPreflightError(
            f"{record} format mismatch: {placeholders} placeholders != {len(items)} args"
        )
    return {"placeholders": placeholders, "arguments": len(items)}


def source_text_audit() -> dict[str, Any]:
    source = RUST_SOURCE.read_text(encoding="utf-8")
    required = (
        'name: "23x1"',
        'name: "10x4"',
        'name: "8x5"',
        'name: "7x6"',
        'Self::MsFloor => "ms-floor"',
        'Self::MsNearest => "ms-nearest"',
        "normalize_glwe_stage(&mut even_half, 1, Rounding::Floor, audit, timings)",
        "normalize_glwe_stage(&mut odd_half, 1, Rounding::Floor, audit, timings)",
        "normalize_lwe_stage(&mut shifted, 2, rounding, audit, timings)",
        "merge_unnormalized(&inputs[0], &inputs[4], 2, keys, audit, timings)",
        "merge_unnormalized(&inputs[2], &inputs[6], 2, keys, audit, timings)",
        "merge_unnormalized(&inputs[1], &inputs[5], 2, keys, audit, timings)",
        "merge_unnormalized(&inputs[3], &inputs[7], 2, keys, audit, timings)",
        "fn merge_ms(",
        "glwe_ciphertext_sub_assign(&mut normalized_difference, &shifted_odd)",
        "normalize_glwe_stage(&mut normalized_difference, 1, rounding, audit, timings)",
        "glwe_ciphertext_add_assign(&mut output, &normalized_difference)",
        "glwe_ciphertext_add_assign(&mut output, &shifted_odd)",
        "centered_abs_error_mod_power_of_two",
        "comparison_modulus_log: 64 - shift",
        "normalization_evalauto_kernel_extraction_timing_separate=true",
        "certified_reads_per_case=1016",
        "cross_arm_pairing=true",
        "automorphism_oracle_inverse(&input_phase, degree)",
        "message_reference_available=false",
        "cross_parameter_pairing=false",
        "causal_cross_parameter_comparison_allowed=false",
        "const MAX_FRESH_KEYSETS: usize = 16;",
        "const MAX_TRIALS_PER_KEYSET: usize = 64;",
        '"--ack-component-only"',
        '"--ack-host-load-cleared"',
        "runtime requires --run, --ack-component-only, and --ack-host-load-cleared",
        "expected_normalization_words",
        "expected_evalauto_degrees",
        "normalization_signature_matches",
        "audit_pre_kernel_phase(&packed, &fixture, &glwe_secret_key)",
        "outcome.pre_kernel_off_support_decode_failures =",
        "|| outcome.pre_kernel_off_support_decode_failures != 0",
        "pre_kernel_off_support_decode_failures={}",
        "whole_polynomial_cross_arm_equality_required=false",
        "empirical_pfail_reported=false",
        "root_fhe_included=false",
        "full_selector_proven=false",
        "composed_pfail_proven=false",
        "runtime_frontier_promoted=false",
    )
    missing = [needle for needle in required if needle not in source]
    if missing:
        raise StaticPreflightError(f"Rust scaffold lost required markers: {missing}")
    forbidden = (
        "DECOMPOSITION_BASE_LOG",
        "DECOMPOSITION_LEVEL_COUNT",
        "empirical_component_case_pfail_upper95_if_zero",
        "empirical_upper_95_zero_failures",
    )
    present_forbidden = [needle for needle in forbidden if needle in source]
    if present_forbidden:
        raise StaticPreflightError(
            f"stale fixed decomposition markers: {present_forbidden}"
        )
    if "mod_inverse" in source or "inverse_mod" in source:
        raise StaticPreflightError("normalization must not introduce a modular inverse")
    merge_start = source.index("fn merge_ms(")
    merge_end = source.index("fn pack_ms(", merge_start)
    merge_source = source[merge_start:merge_end]
    ordered = (
        "monomial_mul_assign(&mut shifted_odd",
        "glwe_ciphertext_sub_assign(&mut normalized_difference",
        "normalize_glwe_stage(&mut normalized_difference",
        "let mut output = eval_auto(",
        "glwe_ciphertext_add_assign(&mut output, &normalized_difference)",
        "glwe_ciphertext_add_assign(&mut output, &shifted_odd)",
    )
    positions = [merge_source.index(marker) for marker in ordered]
    if positions != sorted(positions):
        raise StaticPreflightError("MS merge operation order drift")
    forbidden_source_markers = ("artifact=A99", "usage: a99_chen_grouped_runtime")
    present_stale = [marker for marker in forbidden_source_markers if marker in source]
    if present_stale:
        raise StaticPreflightError(f"stale A99 runtime identity: {present_stale}")
    pre_kernel_call = "audit_pre_kernel_phase(&packed, &fixture, &glwe_secret_key)"
    if source.count(pre_kernel_call) != 1:
        raise StaticPreflightError("pre-kernel phase audit must be wired exactly once")
    format_records = {
        record: rust_format_record_audit(source, record)
        for record in (
            "PLAN",
            "KEY",
            "PRIMITIVE_AUDIT",
            "STAGE_NORMALIZATION_AUDIT",
            "STAGE_AUDIT_CALL",
            "CASE",
            "PRIMITIVE_RESULT",
            "ARM_RESULT",
            "RESULT",
        )
    }
    return {
        "rust_source_sha256": sha256(RUST_SOURCE),
        "required_markers_checked": len(required),
        "stale_fixed_decomposition_markers_absent": True,
        "unjustified_empirical_pfail_marker_absent": True,
        "modular_inverse_markers_absent": True,
        "ms_merge_operation_order_checked": list(ordered),
        "pre_kernel_phase_audit_call_count": source.count(pre_kernel_call),
        "rust_format_records": format_records,
        "stale_a99_runtime_identity_absent": True,
        "rust_typecheck_or_build_run": False,
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
        "parity_recursive_temporal_degrees_g1_ms": list(PARITY_TEMPORAL_DEGREES),
        "grouped_temporal_degrees_g2": list(GROUPED_TEMPORAL_DEGREES),
        "selected_payload_depth": 10,
        "distinct_automorphism_keys": 10,
        "trace_target": 16,
        "partial_revhomtrace_temporal_degrees_ascending": list(TRACE_DEGREES),
        "g1_normalization_objects": 21,
        "g1_coefficient_touches": 21 * 2 * POLYNOMIAL_SIZE,
        "g2_normalization_objects": 13,
        "g2_coefficient_touches": 8 * (POLYNOMIAL_SIZE + 1) + 5 * 2 * POLYNOMIAL_SIZE,
        "g2_groups": [2, 2, 2, 2, 2],
        "maximum_internal_evalauto_gain_g2": 2,
        "ms_normalization_objects": 14,
        "ms_coefficient_touches": 14 * 2 * POLYNOMIAL_SIZE,
        "ms_merge": "D=E-X^sO; H(D); H(D)+EvalAuto(H(D))+X^sO",
        "root": {
            "evalauto_calls": 8,
            "g1_normalization_objects": 9,
            "g2_normalization_objects": 5,
            "ms_normalization_objects": 8,
            "g1_coefficient_touches": 9 * 2 * POLYNOMIAL_SIZE,
            "g2_coefficient_touches": 2 * (POLYNOMIAL_SIZE + 1)
            + 3 * 2 * POLYNOMIAL_SIZE,
            "ms_coefficient_touches": 8 * 2 * POLYNOMIAL_SIZE,
        },
    }


def build_report() -> dict[str, Any]:
    return {
        "schema": "a104.ms-pack-chen-runtime.static-preflight.v1",
        "date": "2026-09-03",
        "status": "STATIC_SOURCE_CANDIDATE_NO_RUST_OR_FHE_RUN",
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
        "dense_residual_audit": dense_residual_audit(),
        "root_geometry_audit": root_geometry_audit(),
        "inherited_clear_tournament_contract": inherited_contract_audit(),
        "schedule_ledger": schedule_ledger(),
        "key_ledger": key_ledger(),
        "runtime_scope": {
            "real_lwe_encryptions_planned": True,
            "full_fourier_ggsw_first_gate": True,
            "stage_actual_phase_audit_planned": True,
            "stage_normalization_error_mod_small_q_planned": True,
            "pre_kernel_wanted_and_off_support_decode_gate_planned": True,
            "pre_kernel_interleaved_residual_magnitude_diagnostic_only": True,
            "whole_polynomial_cross_arm_equality_required": False,
            "empirical_pfail_reported": False,
            "normalization_evalauto_kernel_extraction_timing_separate": True,
            "timed_path_separate_from_client_decryption": True,
            "cross_arm_pairing": True,
            "cross_parameter_pairing": False,
            "causal_cross_parameter_timing_or_noise_comparison_allowed": False,
            "cargo_lockfile_inherited_and_root_name_adjusted": True,
            "cargo_or_rustc_invoked": False,
            "rust_format_checked": False,
            "rust_compilation_passed": False,
            "rust_tests_run": False,
            "release_binary_built": False,
            "fail_closed_dry_default_source_audited": True,
            "double_runtime_acknowledgement_source_audited": True,
            "fhe_run_in_this_static_report": False,
            "full_selector_included": False,
            "encrypted_control_blind_rotation_included": False,
            "root_fhe_included": False,
            "tie_first_encrypted_decision_proven": False,
            "full_tournament_proven": False,
            "composed_pfail_proven": False,
            "runtime_frontier_promoted": False,
        },
        "interpretation": {
            "exact": [
                "clear u64 ring geometry for all eight basis inputs and five arms",
                "mixed Delta59/Delta56 slot map and width-127 robust extraction geometry",
                "wanted-slot and certified-read equality despite permitted residual differences",
                "zero clear support outside wanted and documented residual cells",
                "root D2/D1 clear geometry, D1 add-back, and inherited ragged/tie/reject exact-ID contract",
                "normalization object/coefficient counts and full-GGSW storage geometry",
            ],
            "awaits_build_and_fhe": [
                "Rust API/type correctness",
                "real baseline and MS ciphertext correctness",
                "EvalAuto noise sufficiency for each decomposition",
                "normalization residual and covariance sufficiency",
                "ciphertext residual/off-support magnitudes and decode margins",
                "all timings",
            ],
            "forbidden": [
                "runtime speedup",
                "iid/binomial p-fail from correlated within-keyset trials",
                "A44 p-fail or paper-bound transfer",
                "root or full-selector FHE correctness",
                "runtime-frontier promotion",
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
    print("status=STATIC_SOURCE_CANDIDATE_NO_RUST_OR_FHE_RUN")


if __name__ == "__main__":
    main()
