#!/usr/bin/env python3
"""Static A102 mapping for RevHomTrace/MS-PackLWEs and the A92/A99 geometry.

This file executes clear arithmetic only.  It does not compile Rust, generate a
key, evaluate FHE, estimate latency, or promote a runtime result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE_PINS_PATH = HERE / "SOURCE_PINS.json"

WORD_BITS = 64
WORD_MODULUS = 1 << WORD_BITS
POLYNOMIAL_SIZE = 2_048
POLYNOMIAL_LOG = 11
GLWE_DIMENSION = 1
GLWE_SIZE = GLWE_DIMENSION + 1
INPUT_COUNT = 8
A92_TRACE_TARGET = 16
PAPER_TRACE_TARGET = INPUT_COUNT
SLOT_STEP = POLYNOMIAL_SIZE // INPUT_COUNT
PARTIAL_SUPPORT_STEP = POLYNOMIAL_SIZE // A92_TRACE_TARGET
ROBUST_RADIUS = 63
ROBUST_WIDTH = 2 * ROBUST_RADIUS + 1
NONROOT_NODES = 126
SELECTOR_NODES = 127
ROOT_INPUT_COUNT = 2

LOCAL_INPUT_PINS = {
    "tmp/a92-chen-partial-trace-packing/README.md": (
        "7a8f4308cae3efa5ff75051967ef07b56daf55c7e51e130846c5953b0a7af225"
    ),
    "tmp/a92-chen-partial-trace-packing/a92_chen_partial_trace.py": (
        "3c6c8e2cc39de5c03c027837a03c98a62b7dbd04b3b56171788e8cc6a81c814b"
    ),
    "tmp/a92-chen-partial-trace-packing/artifacts/a92_static_result.json": (
        "85405bd3981c41c0d578a320d025dfec42a8e7e5f2cd14660527d3cd3f10cce0"
    ),
    "tmp/a96-chen-normalized-rounding-preflight/README.md": (
        "946473a243a2c61dd129749f7e41729a65885a8a931319ef91a2f278009df003"
    ),
    "tmp/a96-chen-normalized-rounding-preflight/a96_chen_rounding.py": (
        "5e071a359cf3e1948eaccaad5c205eb79a7bfcde4e267e1755f0d7ece1bac588"
    ),
    "tmp/a96-chen-normalized-rounding-preflight/artifacts/a96_static_result.json": (
        "1e132be1b87de948603bd5e1c8127f88d00a53f64325c678adc93a8ef007df92"
    ),
    "tmp/a99-chen-grouped-runtime/README.md": (
        "f7ae26d0464dd7d16555ea31517fa1efe530e94738ed277419a83a103ebec632"
    ),
    "tmp/a99-chen-grouped-runtime/a99_static_oracle.py": (
        "8b9d138e35c6fa78ca1de47d5bc0864309a174b30433335b27127901f31b5055"
    ),
    "tmp/a99-chen-grouped-runtime/artifacts/a99_static_result.json": (
        "09f0810312303fffc3f3fd4b87944b23f9a98555f21c2eb291e37cd81146235e"
    ),
    "tmp/a99-chen-grouped-runtime/src/main.rs": (
        "3c563d728be8b634c02d47802c0a2289675683d40c68139420688e1745bf342b"
    ),
    "tmp/a99-chen-grouped-runtime/SOURCE_PINS.json": (
        "7abb011b197409cf16f106ecb667a37d6db7376605c00308a300f4cc1032ce8b"
    ),
}


class StaticMappingError(RuntimeError):
    """Raised when a frozen premise or clear-ring invariant fails."""


@dataclass(frozen=True)
class LedgerRow:
    name: str
    status: str
    input_count: int
    trace_target: int
    evalauto_rank: int
    packing_evalauto_calls: int
    trace_evalauto_calls: int
    total_evalauto_calls: int
    selected_path_depth: int
    distinct_automorphism_keys: int
    trace_order: str
    normalization_layout: str
    logical_normalization_objects: int
    ingress_normalization_bits: int | None
    logical_normalized_scalar_words: int
    direct_shift_element_visits: int
    official_helper_element_loop_iterations: int | None
    glwe_ks_forward: int
    glwe_ks_backward: int
    theoretical_noise_or_bound: str
    assumptions_and_scope: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def verify_local_inputs() -> dict[str, str]:
    observed: dict[str, str] = {}
    for relative, expected in LOCAL_INPUT_PINS.items():
        path = ROOT / relative
        if not path.is_file():
            raise StaticMappingError(f"missing pinned local input: {relative}")
        actual = sha256_file(path)
        if actual != expected:
            raise StaticMappingError(
                f"local input drift for {relative}: {actual} != {expected}"
            )
        observed[relative] = actual
    return observed


def verify_source_pins() -> dict[str, Any]:
    pins = json.loads(SOURCE_PINS_PATH.read_text(encoding="utf-8"))
    paper = pins["primary_sources"]["revhomtrace_paper"]
    repository = pins["primary_sources"]["official_repository"]
    if paper["pdf_sha256"] != (
        "4f1033580542c56baa8a493aab178681082df768cd3446cc4470bc75b49589a9"
    ):
        raise StaticMappingError("RevHomTrace paper pin drift")
    if repository["commit"] != "47c8f6f6b65a451a14b542dc45c873f1e962decd":
        raise StaticMappingError("RevHomTrace repository commit drift")
    required = {
        "src/automorphism_rev.rs": (
            "95ac14c63c57e5d34426a8dcfffaa1be6c7b9e3338d630eced108fa70089cf72"
        ),
        "src/glwe_conv_rev.rs": (
            "f4800309bd004e3b8246b3713972300e0c8dde4321038e40feef5955c14fcc30"
        ),
        "src/mod_switch_rev.rs": (
            "76a72d24442880cc2d12e3152c7d0b684143e9864a2e6fdd2cf31acb7ca5fd03"
        ),
        "benches/bench_ks.rs": (
            "b6e93ac1bd0ca1bd17a0d930a79eadc16cad371752f73eba159bb88a5371d1d7"
        ),
    }
    files = repository["files"]
    for relative, expected in required.items():
        if files[relative]["sha256"] != expected:
            raise StaticMappingError(f"remote source pin drift for {relative}")
    return {
        "source_pins_sha256": sha256_file(SOURCE_PINS_PATH),
        "paper_pdf_sha256": paper["pdf_sha256"],
        "repository_commit": repository["commit"],
        "required_remote_file_pins": len(required),
    }


def verify_optional_source_tree(source_tree: Path) -> dict[str, Any]:
    pins = json.loads(SOURCE_PINS_PATH.read_text(encoding="utf-8"))
    repository = pins["primary_sources"]["official_repository"]
    git_head = source_tree / ".git" / "HEAD"
    if not git_head.exists():
        raise StaticMappingError("optional source tree is not a Git checkout")
    import subprocess

    commit = subprocess.run(
        ["git", "-C", str(source_tree), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if commit != repository["commit"]:
        raise StaticMappingError(
            f"optional source-tree commit drift: {commit} != {repository['commit']}"
        )
    checked = 0
    for relative, metadata in repository["files"].items():
        actual = sha256_file(source_tree / relative)
        if actual != metadata["sha256"]:
            raise StaticMappingError(f"optional source-tree hash drift: {relative}")
        checked += 1
    return {"commit": commit, "files_verified": checked}


def is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def add(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    return tuple((a + b) % WORD_MODULUS for a, b in zip(left, right, strict=True))


def sub(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    return tuple((a - b) % WORD_MODULUS for a, b in zip(left, right, strict=True))


def normalize(polynomial: Sequence[int], bits: int, rounding: str) -> tuple[int, ...]:
    if not 0 < bits < WORD_BITS:
        raise StaticMappingError("invalid normalization width")
    divisor = 1 << bits
    small_modulus = 1 << (WORD_BITS - bits)
    if rounding == "floor":
        return tuple(word >> bits for word in polynomial)
    if rounding == "nearest":
        return tuple(
            ((word + divisor // 2) // divisor) % small_modulus for word in polynomial
        )
    raise StaticMappingError(f"unknown rounding rule: {rounding}")


def automorphism(polynomial: Sequence[int], degree: int) -> tuple[int, ...]:
    if len(polynomial) != POLYNOMIAL_SIZE:
        raise StaticMappingError("wrong polynomial size")
    if degree % 2 != 1 or not 1 <= degree < 2 * POLYNOMIAL_SIZE:
        raise StaticMappingError("invalid automorphism degree")
    output = [0] * POLYNOMIAL_SIZE
    for exponent, coefficient in enumerate(polynomial):
        product = exponent * degree
        index = product % POLYNOMIAL_SIZE
        sign = -1 if (product // POLYNOMIAL_SIZE) % 2 else 1
        output[index] = (output[index] + sign * coefficient) % WORD_MODULUS
    return tuple(output)


def monomial_mul(polynomial: Sequence[int], degree: int) -> tuple[int, ...]:
    if not 0 <= degree < POLYNOMIAL_SIZE:
        raise StaticMappingError("invalid monomial degree")
    output = [0] * POLYNOMIAL_SIZE
    for index, coefficient in enumerate(polynomial):
        exponent = index + degree
        if exponent < POLYNOMIAL_SIZE:
            output[exponent] = coefficient
        else:
            output[exponent - POLYNOMIAL_SIZE] = (-coefficient) % WORD_MODULUS
    return tuple(output)


def packing_degree_multiset(input_count: int) -> tuple[int, ...]:
    if not is_power_of_two(input_count):
        raise StaticMappingError("packing input count must be a power of two")
    return tuple(
        degree
        for count in (1 << exponent for exponent in range(1, input_count.bit_length()))
        for degree in (count + 1,) * (input_count // count)
    )


def packing_execution_order(input_count: int) -> tuple[int, ...]:
    if not is_power_of_two(input_count):
        raise StaticMappingError("packing input count must be a power of two")
    if input_count == 1:
        return ()
    child = packing_execution_order(input_count // 2)
    return (*child, *child, input_count + 1)


def trace_degrees(trace_target: int, *, reverse: bool) -> tuple[int, ...]:
    if (
        not is_power_of_two(trace_target)
        or trace_target > POLYNOMIAL_SIZE
        or POLYNOMIAL_SIZE % trace_target
    ):
        raise StaticMappingError("invalid trace target")
    exponents = range(
        int(math.log2(trace_target)) + 1,
        POLYNOMIAL_LOG + 1,
    )
    degrees = tuple((1 << exponent) + 1 for exponent in exponents)
    return degrees if reverse else tuple(reversed(degrees))


def merge_unnormalized(
    even: Sequence[int], odd: Sequence[int], subtree_count: int
) -> tuple[int, ...]:
    shifted_odd = monomial_mul(odd, POLYNOMIAL_SIZE // subtree_count)
    difference = sub(even, shifted_odd)
    return add(add(automorphism(difference, subtree_count + 1), even), shifted_odd)


def merge_a99_g1_floor(
    even: Sequence[int], odd: Sequence[int], subtree_count: int
) -> tuple[int, ...]:
    shifted_odd = monomial_mul(odd, POLYNOMIAL_SIZE // subtree_count)
    even_half = normalize(even, 1, "floor")
    odd_half = normalize(shifted_odd, 1, "floor")
    difference = sub(even_half, odd_half)
    return add(
        add(automorphism(difference, subtree_count + 1), even_half),
        odd_half,
    )


def merge_ms(
    even: Sequence[int],
    odd: Sequence[int],
    subtree_count: int,
    *,
    rounding: str,
) -> tuple[int, ...]:
    """Algorithm 6: H(E-X^s O)+Auto(H(E-X^s O))+X^s O."""
    shifted_odd = monomial_mul(odd, POLYNOMIAL_SIZE // subtree_count)
    normalized_difference = normalize(sub(even, shifted_odd), 1, rounding)
    return add(
        add(
            normalized_difference,
            automorphism(normalized_difference, subtree_count + 1),
        ),
        shifted_odd,
    )


def recursive_pack(
    inputs: Sequence[Sequence[int]], *, variant: str, rounding: str = "floor"
) -> tuple[int, ...]:
    if not inputs or not is_power_of_two(len(inputs)):
        raise StaticMappingError("packing arity must be a nonzero power of two")
    if len(inputs) == 1:
        return tuple(inputs[0])
    even = recursive_pack(inputs[0::2], variant=variant, rounding=rounding)
    odd = recursive_pack(inputs[1::2], variant=variant, rounding=rounding)
    if variant == "a99-g1":
        return merge_a99_g1_floor(even, odd, len(inputs))
    if variant == "ms":
        return merge_ms(even, odd, len(inputs), rounding=rounding)
    if variant == "unnormalized":
        return merge_unnormalized(even, odd, len(inputs))
    raise StaticMappingError(f"unknown packing variant: {variant}")


def reverse_trace(
    polynomial: Sequence[int], trace_target: int, *, rounding: str
) -> tuple[int, ...]:
    output = tuple(polynomial)
    for degree in trace_degrees(trace_target, reverse=True):
        output = normalize(output, 1, rounding)
        output = add(output, automorphism(output, degree))
    return output


def run_a99_g1(inputs: Sequence[Sequence[int]]) -> tuple[int, ...]:
    packed = recursive_pack(inputs, variant="a99-g1")
    return reverse_trace(packed, A92_TRACE_TARGET, rounding="floor")


def run_ms(
    inputs: Sequence[Sequence[int]],
    *,
    trace_target: int,
    rounding: str = "floor",
) -> tuple[int, ...]:
    packed = recursive_pack(inputs, variant="ms", rounding=rounding)
    return reverse_trace(packed, trace_target, rounding=rounding)


def run_a99_g2(inputs: Sequence[Sequence[int]], rounding: str) -> tuple[int, ...]:
    if len(inputs) != INPUT_COUNT:
        raise StaticMappingError("A99 g2 model requires eight inputs")
    embedded = [normalize(item, 2, rounding) for item in inputs]
    bottom = (
        merge_unnormalized(embedded[0], embedded[4], 2),
        merge_unnormalized(embedded[2], embedded[6], 2),
        merge_unnormalized(embedded[1], embedded[5], 2),
        merge_unnormalized(embedded[3], embedded[7], 2),
    )
    middle = (
        normalize(merge_unnormalized(bottom[0], bottom[1], 4), 2, rounding),
        normalize(merge_unnormalized(bottom[2], bottom[3], 4), 2, rounding),
    )
    output = merge_unnormalized(middle[0], middle[1], 8)
    degrees = trace_degrees(A92_TRACE_TARGET, reverse=True)
    output = add(output, automorphism(output, degrees[0]))
    for first, second in zip(degrees[1::2], degrees[2::2], strict=True):
        output = normalize(output, 2, rounding)
        output = add(output, automorphism(output, first))
        output = add(output, automorphism(output, second))
    return output


def zero_polynomial() -> tuple[int, ...]:
    return (0,) * POLYNOMIAL_SIZE


def constant_input(word: int) -> tuple[int, ...]:
    return (word % WORD_MODULUS, *(0 for _ in range(POLYNOMIAL_SIZE - 1)))


def encoded_fixture_words() -> tuple[int, ...]:
    def encode(value: int, delta: int) -> int:
        return (value << delta) % WORD_MODULUS

    left = (encode(1, 59), encode(2, 59), encode(3, 59), encode(17, 56))
    right = (encode(4, 59), encode(5, 59), encode(6, 59), encode(91, 56))
    return (
        (-right[2]) % WORD_MODULUS,
        (-right[3]) % WORD_MODULUS,
        *left,
        right[0],
        right[1],
    )


def public_width_kernel(polynomial: Sequence[int]) -> tuple[int, ...]:
    output = [0] * POLYNOMIAL_SIZE
    for index, word in enumerate(polynomial):
        if word == 0:
            continue
        for offset in range(-ROBUST_RADIUS, ROBUST_RADIUS + 1):
            cycle, target = divmod(index + offset, POLYNOMIAL_SIZE)
            sign = -1 if cycle % 2 else 1
            output[target] = (output[target] + sign * word) % WORD_MODULUS
    return tuple(output)


def virtual_sample(polynomial: Sequence[int], degree: int) -> int:
    cycle, index = divmod(degree, POLYNOMIAL_SIZE)
    value = polynomial[index]
    return value if cycle % 2 == 0 else (-value) % WORD_MODULUS


def schedule_audit() -> dict[str, Any]:
    packing_by_layer = packing_degree_multiset(INPUT_COUNT)
    packing_temporal = packing_execution_order(INPUT_COUNT)
    partial = trace_degrees(A92_TRACE_TARGET, reverse=True)
    full = trace_degrees(PAPER_TRACE_TARGET, reverse=True)
    if packing_by_layer != (3, 3, 3, 3, 5, 5, 9):
        raise StaticMappingError("packing schedule drift")
    if packing_temporal != (3, 3, 5, 3, 3, 5, 9):
        raise StaticMappingError("packing temporal order drift")
    if partial != (33, 65, 129, 257, 513, 1025, 2049):
        raise StaticMappingError("partial reverse-trace schedule drift")
    if full != (17, 33, 65, 129, 257, 513, 1025, 2049):
        raise StaticMappingError("full reverse-trace schedule drift")
    standard_full = trace_degrees(PAPER_TRACE_TARGET, reverse=False)
    return {
        "packing_evalauto_degrees_by_layer": list(packing_by_layer),
        "packing_evalauto_temporal_order_even_first": list(packing_temporal),
        "packing_degree_multiplicity": {
            str(degree): packing_by_layer.count(degree)
            for degree in sorted(set(packing_by_layer))
        },
        "a92_partial_revtrace_degrees": list(partial),
        "paper_full_revtrace_degrees": list(full),
        "paper_full_standard_trace_degrees": list(standard_full),
        "a92_omitted_degree": 17,
        "partial_total_evalauto": len(packing_by_layer) + len(partial),
        "full_total_evalauto": len(packing_by_layer) + len(full),
        "partial_distinct_keys": len(set((*packing_by_layer, *partial))),
        "full_distinct_keys": len(set((*packing_by_layer, *full))),
    }


def parameter_audit() -> dict[str, Any]:
    """Freeze only parameters visible in the pinned source and A99 harness."""
    return {
        "ring": {
            "native_torus_bits": WORD_BITS,
            "polynomial_size": POLYNOMIAL_SIZE,
            "base_glwe_rank": GLWE_DIMENSION,
            "input_count": INPUT_COUNT,
        },
        "official_rank1_revhomtrace": {
            "INT_LHE_BASE_64_REV": {
                "lwe_dimension": 873,
                "glwe_rank": 1,
                "auto_base_log": 10,
                "auto_levels": 4,
                "auto_fft": "Split(37)",
            },
            "INT_LHE_BASE_256_REV": {
                "lwe_dimension": 953,
                "glwe_rank": 1,
                "auto_base_log": 7,
                "auto_levels": 6,
                "auto_fft": "Split(35)",
            },
        },
        "official_rank2_hp": {
            "INT_LHE_BASE_64": {
                "base_glwe_rank": 1,
                "large_glwe_rank": 2,
                "to_large": "base_log=15,levels=3,Split(42)",
                "auto": "base_log=12,levels=4,Split(40)",
                "from_large": "base_log=12,levels=3,Split(42)",
            },
            "INT_LHE_BASE_256": {
                "base_glwe_rank": 1,
                "large_glwe_rank": 2,
                "to_large": "base_log=15,levels=3,Split(42)",
                "auto": "base_log=9,levels=6,Split(37)",
                "from_large": "base_log=10,levels=4,Split(38)",
            },
        },
        "a99_tfhe_rs_0_11_3_full_fourier_ggsw_sweep": [
            "base_log=23,levels=1",
            "base_log=8,levels=5",
            "base_log=7,levels=6",
        ],
        "comparability_warning": (
            "the official AutomorphKey uses custom Fourier/split-FFT GLWE "
            "keyswitch code; A99 uses TFHE-rs 0.11.3 full Fourier GGSW "
            "external products, so decomposition labels do not imply equal kernels"
        ),
        "official_bench_ks_frozen_input_count": 4,
        "official_paper_table6_input_counts": [4, 32, 256, 2_048],
        "official_n8_measurement_available": False,
    }


def exact_geometry_audit() -> dict[str, Any]:
    words = encoded_fixture_words()
    sparse_inputs = tuple(constant_input(word) for word in words)
    arms = {
        "a99-g1-floor": run_a99_g1(sparse_inputs),
        "a99-g2-floor": run_a99_g2(sparse_inputs, "floor"),
        "a99-g2-nearest": run_a99_g2(sparse_inputs, "nearest"),
        "ms-partial-floor": run_ms(
            sparse_inputs, trace_target=A92_TRACE_TARGET, rounding="floor"
        ),
        "ms-partial-nearest": run_ms(
            sparse_inputs, trace_target=A92_TRACE_TARGET, rounding="nearest"
        ),
    }
    for name, output in arms.items():
        for slot, word in enumerate(words):
            index = slot * SLOT_STEP
            if output[index] != word:
                raise StaticMappingError(
                    f"{name} slot {slot} mismatch: {output[index]} != {word}"
                )
        if any(
            word and index % PARTIAL_SUPPORT_STEP for index, word in enumerate(output)
        ):
            raise StaticMappingError(f"{name} violates partial-trace support")
    reference = arms["a99-g1-floor"]
    if any(output != reference for output in arms.values()):
        raise StaticMappingError("encoded exact arms disagree")

    kernel = public_width_kernel(arms["ms-partial-floor"])
    checks = 0
    for slot, expected_word in enumerate(words):
        center = slot * SLOT_STEP
        for error in range(-ROBUST_RADIUS, ROBUST_RADIUS + 1):
            observed = virtual_sample(kernel, center + error)
            if observed != expected_word:
                raise StaticMappingError(
                    f"kernel isolation failed at slot={slot}, error={error}"
                )
            checks += 1

    # Dense, highly divisible phase polynomials exercise the interleaved
    # residual cells without introducing coefficient-rounding residuals.
    rng = random.Random(0xA102)
    dense_inputs = tuple(
        tuple(
            (rng.randrange(1 << 20) << 20) % WORD_MODULUS
            for _ in range(POLYNOMIAL_SIZE)
        )
        for _ in range(INPUT_COUNT)
    )
    dense_outputs = {
        "a99-g1-floor": run_a99_g1(dense_inputs),
        "ms-partial-floor": run_ms(
            dense_inputs, trace_target=A92_TRACE_TARGET, rounding="floor"
        ),
    }
    for name, output in dense_outputs.items():
        if any(
            word and index % PARTIAL_SUPPORT_STEP for index, word in enumerate(output)
        ):
            raise StaticMappingError(f"dense {name} output violates partial support")
        for slot, source in enumerate(dense_inputs):
            if output[slot * SLOT_STEP] != source[0]:
                raise StaticMappingError(f"dense {name} wanted-slot mismatch")
        dense_kernel = public_width_kernel(output)
        for slot, source in enumerate(dense_inputs):
            for error in range(-ROBUST_RADIUS, ROBUST_RADIUS + 1):
                if virtual_sample(dense_kernel, slot * SLOT_STEP + error) != source[0]:
                    raise StaticMappingError(
                        f"dense {name} guard failed at slot={slot}, error={error}"
                    )
                checks += 1
    dense_g1 = dense_outputs["a99-g1-floor"]
    dense_ms = dense_outputs["ms-partial-floor"]
    wanted_disagreements = sum(
        dense_g1[index] != dense_ms[index]
        for index in range(0, POLYNOMIAL_SIZE, SLOT_STEP)
    )
    if wanted_disagreements:
        raise StaticMappingError("dense A99-g1/MS wanted slots disagree")
    residual_disagreements = sum(
        dense_g1[index] != dense_ms[index]
        for index in range(PARTIAL_SUPPORT_STEP, POLYNOMIAL_SIZE, SLOT_STEP)
    )
    residual_nonzero = sum(
        dense_ms[index] != 0
        for index in range(PARTIAL_SUPPORT_STEP, POLYNOMIAL_SIZE, SLOT_STEP)
    )
    if residual_nonzero == 0:
        raise StaticMappingError("dense fixture failed to exercise residual cells")
    if residual_disagreements == 0:
        raise StaticMappingError("dense fixture failed to distinguish A99-g1 from MS")

    root_words = ((17 << 56) % WORD_MODULUS, (91 << 56) % WORD_MODULUS)
    root_inputs = tuple(constant_input(word) for word in root_words)
    root_outputs = {
        "a99-g1-floor": run_a99_g1(root_inputs),
        "ms-partial-floor": run_ms(
            root_inputs, trace_target=A92_TRACE_TARGET, rounding="floor"
        ),
    }
    for name, output in root_outputs.items():
        for slot, expected_word in enumerate(root_words):
            if output[slot * (POLYNOMIAL_SIZE // ROOT_INPUT_COUNT)] != expected_word:
                raise StaticMappingError(f"root {name} wanted-slot mismatch")

    return {
        "arms": list(arms),
        "encoded_full_polynomial_equality": True,
        "encoded_slot_checks": len(arms) * INPUT_COUNT,
        "partial_support_step": PARTIAL_SUPPORT_STEP,
        "wanted_slot_step": SLOT_STEP,
        "residual_interleaved_cells_exercised": residual_nonzero,
        "width127_robust_sample_checks": checks,
        "dense_wanted_slot_disagreements": wanted_disagreements,
        "dense_residual_cell_disagreements": residual_disagreements,
        "dense_global_a99_g1_ms_equality_expected": False,
        "dense_certified_samples_equal": True,
        "root_wanted_slot_checks": len(root_outputs) * len(root_words),
    }


def ledger_rows() -> list[LedgerRow]:
    partial_trace_calls = len(trace_degrees(A92_TRACE_TARGET, reverse=True))
    full_trace_calls = len(trace_degrees(PAPER_TRACE_TARGET, reverse=True))
    pack_calls = INPUT_COUNT - 1
    partial_depth = int(math.log2(INPUT_COUNT)) + partial_trace_calls
    full_depth = int(math.log2(INPUT_COUNT)) + full_trace_calls
    return [
        LedgerRow(
            name="A99-g1-floor-partial",
            status="materialized A99 arm; FHE run pending",
            input_count=8,
            trace_target=16,
            evalauto_rank=1,
            packing_evalauto_calls=pack_calls,
            trace_evalauto_calls=partial_trace_calls,
            total_evalauto_calls=14,
            selected_path_depth=partial_depth,
            distinct_automorphism_keys=10,
            trace_order="reverse",
            normalization_layout="21 GLWE floor /2: two branches per merge plus trace",
            logical_normalization_objects=21,
            ingress_normalization_bits=None,
            logical_normalized_scalar_words=21 * GLWE_SIZE * POLYNOMIAL_SIZE,
            direct_shift_element_visits=21 * GLWE_SIZE * POLYNOMIAL_SIZE,
            official_helper_element_loop_iterations=None,
            glwe_ks_forward=0,
            glwe_ks_backward=0,
            theoretical_noise_or_bound=(
                "A96 distributed deterministic floor-only bound: 43,008 torus "
                "units before the width-127 kernel, 5,462,016 after it"
            ),
            assumptions_and_scope=(
                "exact EvalAuto/stage algebra and binary k=1 secret; excludes input, "
                "EvalAuto, FFT, PBS, extraction error and covariance"
            ),
        ),
        LedgerRow(
            name="A99-g2-floor-or-nearest-partial",
            status="materialized A99 arms; FHE run pending",
            input_count=8,
            trace_target=16,
            evalauto_rank=1,
            packing_evalauto_calls=pack_calls,
            trace_evalauto_calls=partial_trace_calls,
            total_evalauto_calls=14,
            selected_path_depth=partial_depth,
            distinct_automorphism_keys=10,
            trace_order="reverse grouped in pairs",
            normalization_layout="8 input LWEs plus 5 live GLWEs, each nearest/floor /4",
            logical_normalization_objects=13,
            ingress_normalization_bits=2,
            logical_normalized_scalar_words=8 * (POLYNOMIAL_SIZE + 1)
            + 5 * GLWE_SIZE * POLYNOMIAL_SIZE,
            direct_shift_element_visits=8 * (POLYNOMIAL_SIZE + 1)
            + 5 * GLWE_SIZE * POLYNOMIAL_SIZE,
            official_helper_element_loop_iterations=None,
            glwe_ks_forward=0,
            glwe_ks_backward=0,
            theoretical_noise_or_bound=(
                "A96 conditional grouped floor factor 15 on a selected path; no "
                "promoted composed variance or failure bound"
            ),
            assumptions_and_scope=(
                "q/4 block-boundary invariant; not Algorithm 6's per-level q/2 "
                "recurrence and therefore outside Lee Lemma 5"
            ),
        ),
        LedgerRow(
            name="Standard-PackLWEs-full-paper-source",
            status="paper/source-backed comparator; not an A44 measurement",
            input_count=8,
            trace_target=8,
            evalauto_rank=1,
            packing_evalauto_calls=pack_calls,
            trace_evalauto_calls=full_trace_calls,
            total_evalauto_calls=15,
            selected_path_depth=full_depth,
            distinct_automorphism_keys=11,
            trace_order="standard descending degrees",
            normalization_layout="8 input LWEs preprocessed once by /2048",
            logical_normalization_objects=8,
            ingress_normalization_bits=11,
            logical_normalized_scalar_words=8 * (POLYNOMIAL_SIZE + 1),
            direct_shift_element_visits=8 * (POLYNOMIAL_SIZE + 1),
            official_helper_element_loop_iterations=2 * 8 * (POLYNOMIAL_SIZE + 1),
            glwe_ks_forward=0,
            glwe_ks_backward=0,
            theoretical_noise_or_bound=(
                "Lemma 3 at N=2048,n=8: Vin + 4,194,304 VMS + 1,376,256 VAuto"
            ),
            assumptions_and_scope=(
                "paper modulus-switch and EvalAuto model; source helper uses unsigned "
                "floor, so its mean-zero VMS premise is not automatically inherited"
            ),
        ),
        LedgerRow(
            name="MS-PackLWEs-full-paper",
            status="paper/source-backed algorithm; not an A44 measurement",
            input_count=8,
            trace_target=8,
            evalauto_rank=1,
            packing_evalauto_calls=pack_calls,
            trace_evalauto_calls=full_trace_calls,
            total_evalauto_calls=15,
            selected_path_depth=full_depth,
            distinct_automorphism_keys=11,
            trace_order="reverse",
            normalization_layout="one GLWE /2 before every EvalAuto",
            logical_normalization_objects=15,
            ingress_normalization_bits=None,
            logical_normalized_scalar_words=15 * GLWE_SIZE * POLYNOMIAL_SIZE,
            direct_shift_element_visits=15 * GLWE_SIZE * POLYNOMIAL_SIZE,
            official_helper_element_loop_iterations=2
            * 15
            * GLWE_SIZE
            * POLYNOMIAL_SIZE,
            glwe_ks_forward=0,
            glwe_ks_backward=0,
            theoretical_noise_or_bound=("Lemma 5 at N=2048: Vin + 44 VMS + 11 VAuto"),
            assumptions_and_scope=(
                "full n=8 packing, paper centered-nearest modulus-switch model and its "
                "error assumptions; not a bound for source-faithful unsigned floor"
            ),
        ),
        LedgerRow(
            name="MS-PackLWEs-A92-partial",
            status="A102 static candidate; no TFHE-rs port or FHE result",
            input_count=8,
            trace_target=16,
            evalauto_rank=1,
            packing_evalauto_calls=pack_calls,
            trace_evalauto_calls=partial_trace_calls,
            total_evalauto_calls=14,
            selected_path_depth=partial_depth,
            distinct_automorphism_keys=10,
            trace_order="reverse",
            normalization_layout="one GLWE /2 before every EvalAuto",
            logical_normalization_objects=14,
            ingress_normalization_bits=None,
            logical_normalized_scalar_words=14 * GLWE_SIZE * POLYNOMIAL_SIZE,
            direct_shift_element_visits=14 * GLWE_SIZE * POLYNOMIAL_SIZE,
            official_helper_element_loop_iterations=2
            * 14
            * GLWE_SIZE
            * POLYNOMIAL_SIZE,
            glwe_ks_forward=0,
            glwe_ks_backward=0,
            theoretical_noise_or_bound=(
                "derived retained-coefficient recurrence candidate: Vin + 40 VMS + "
                "10 VAuto"
            ),
            assumptions_and_scope=(
                "conditional extension of Lemma 5 after omitting degree 17; requires "
                "an A92-specific proof and width-127 kernel covariance composition"
            ),
        ),
        LedgerRow(
            name="HP-PackLWEs-full-paper",
            status="paper/source-backed comparator; not an A44 measurement",
            input_count=8,
            trace_target=8,
            evalauto_rank=2,
            packing_evalauto_calls=pack_calls,
            trace_evalauto_calls=full_trace_calls,
            total_evalauto_calls=15,
            selected_path_depth=full_depth,
            distinct_automorphism_keys=11,
            trace_order="standard",
            normalization_layout="8 rank-2 GLWEs preprocessed once by /2048",
            logical_normalization_objects=8,
            ingress_normalization_bits=11,
            logical_normalized_scalar_words=8 * (2 + 1) * POLYNOMIAL_SIZE,
            direct_shift_element_visits=8 * (2 + 1) * POLYNOMIAL_SIZE,
            official_helper_element_loop_iterations=2 * 8 * (2 + 1) * POLYNOMIAL_SIZE,
            glwe_ks_forward=8,
            glwe_ks_backward=1,
            theoretical_noise_or_bound=(
                "Lemma 4 at N=2048,n=8: Vin + 4,194,304 VS-to-S' + "
                "4,194,304 VMS + 1,376,256 VAuto,k' + VS'-to-S"
            ),
            assumptions_and_scope=(
                "full n=8 packing under rank k'=2 and official paper parameter family; "
                "not a bound for A44 or partial width-127 geometry"
            ),
        ),
        LedgerRow(
            name="HP-PackLWEs-A92-partial-custom",
            status="hypothetical only; unchanged HP code would return half scale",
            input_count=8,
            trace_target=16,
            evalauto_rank=2,
            packing_evalauto_calls=pack_calls,
            trace_evalauto_calls=partial_trace_calls,
            total_evalauto_calls=14,
            selected_path_depth=partial_depth,
            distinct_automorphism_keys=10,
            trace_order="standard or reverse only with a new proof",
            normalization_layout="8 rank-2 GLWEs custom-preprocessed once by /1024",
            logical_normalization_objects=8,
            ingress_normalization_bits=10,
            logical_normalized_scalar_words=8 * (2 + 1) * POLYNOMIAL_SIZE,
            direct_shift_element_visits=8 * (2 + 1) * POLYNOMIAL_SIZE,
            official_helper_element_loop_iterations=None,
            glwe_ks_forward=8,
            glwe_ks_backward=1,
            theoretical_noise_or_bound=(
                "none: unchanged /2048 code is mis-scaled, while /1024 has no theorem"
            ),
            assumptions_and_scope=(
                "hypothetical rank-2 adaptation; needs a new partial-trace correctness "
                "and noise proof plus a custom /1024 preprocessing entry point"
            ),
        ),
        LedgerRow(
            name="RevHomTrace-postpack-n8-component",
            status="paper/source-backed trace component, isolated from packing",
            input_count=8,
            trace_target=8,
            evalauto_rank=1,
            packing_evalauto_calls=0,
            trace_evalauto_calls=full_trace_calls,
            total_evalauto_calls=full_trace_calls,
            selected_path_depth=full_trace_calls,
            distinct_automorphism_keys=full_trace_calls,
            trace_order="reverse ascending degrees 17..2049",
            normalization_layout="one rank-1 GLWE /2 before each of 8 EvalAuto calls",
            logical_normalization_objects=full_trace_calls,
            ingress_normalization_bits=None,
            logical_normalized_scalar_words=full_trace_calls
            * GLWE_SIZE
            * POLYNOMIAL_SIZE,
            direct_shift_element_visits=full_trace_calls * GLWE_SIZE * POLYNOMIAL_SIZE,
            official_helper_element_loop_iterations=2
            * full_trace_calls
            * GLWE_SIZE
            * POLYNOMIAL_SIZE,
            glwe_ks_forward=0,
            glwe_ks_backward=0,
            theoretical_noise_or_bound=(
                "Lemma 5 trace portion: +32 VMS + 8 VAuto; full constant trace "
                "Theorem 4 is +44 VMS + 11 VAuto"
            ),
            assumptions_and_scope=(
                "trace target n=8 after packing; same centered-nearest assumptions as "
                "the paper, not source unsigned-floor transfer"
            ),
        ),
    ]


def n127_ledger() -> dict[str, Any]:
    a99_g1_norm_objects = NONROOT_NODES * 21 + 9
    ms_partial_norm_objects = NONROOT_NODES * 14 + 8
    partial_evalauto = NONROOT_NODES * 14 + 8
    full_evalauto = NONROOT_NODES * 15 + 11
    payload_inputs = NONROOT_NODES * INPUT_COUNT + ROOT_INPUT_COUNT
    return {
        "selector_nodes": SELECTOR_NODES,
        "payload_inputs": payload_inputs,
        "invariants_common_to_all_rows": {
            "public_width127_kernel_products": SELECTOR_NODES,
            "encrypted_control_and_tournament_costs": "unchanged and not included",
        },
        "A99_g1_partial": {
            "evalauto_calls_rank1": partial_evalauto,
            "normalization_objects": a99_g1_norm_objects,
            "normalized_scalar_words": a99_g1_norm_objects
            * GLWE_SIZE
            * POLYNOMIAL_SIZE,
        },
        "A99_g2_partial": {
            "evalauto_calls_rank1": partial_evalauto,
            "normalized_scalar_words": 4_662_258,
            "normalization_objects_are_mixed_lwe_glwe": True,
        },
        "MS_A92_partial": {
            "evalauto_calls_rank1": partial_evalauto,
            "normalization_objects": ms_partial_norm_objects,
            "normalized_scalar_words": ms_partial_norm_objects
            * GLWE_SIZE
            * POLYNOMIAL_SIZE,
            "direct_shift_element_visits": ms_partial_norm_objects
            * GLWE_SIZE
            * POLYNOMIAL_SIZE,
            "official_helper_element_loop_iterations": 2
            * ms_partial_norm_objects
            * GLWE_SIZE
            * POLYNOMIAL_SIZE,
            "official_helper_temporary_allocations": ms_partial_norm_objects,
        },
        "MS_full_paper_geometry": {
            "evalauto_calls_rank1": full_evalauto,
            "normalization_objects": full_evalauto,
            "normalized_scalar_words": full_evalauto * GLWE_SIZE * POLYNOMIAL_SIZE,
        },
        "HP_full_paper_geometry": {
            "evalauto_calls_rank2": full_evalauto,
            "forward_glwe_keyswitches": payload_inputs,
            "backward_glwe_keyswitches": SELECTOR_NODES,
            "ingress_normalized_scalar_words_rank2": payload_inputs
            * 3
            * POLYNOMIAL_SIZE,
        },
    }


def compatibility_audit() -> dict[str, Any]:
    if PARTIAL_SUPPORT_STEP <= 2 * ROBUST_RADIUS:
        raise StaticMappingError("A92 guard geometry is not isolated")
    if POLYNOMIAL_SIZE // 32 > 2 * ROBUST_RADIUS:
        raise StaticMappingError("two-stage omission unexpectedly safe")
    partial_gain = INPUT_COUNT * (POLYNOMIAL_SIZE // A92_TRACE_TARGET)
    full_gain = INPUT_COUNT * (POLYNOMIAL_SIZE // PAPER_TRACE_TARGET)
    if (partial_gain, full_gain) != (1_024, 2_048):
        raise StaticMappingError("selected-path gain drift")
    return {
        "ms_partial_trace_algebraically_composable": True,
        "official_converter_drop_in": False,
        "official_converter_issue": (
            "it hard-codes trace target to lwe_count=8 and keeps pack_lwes_rev private"
        ),
        "required_trace_target": A92_TRACE_TARGET,
        "required_reverse_trace_degrees": list(
            trace_degrees(A92_TRACE_TARGET, reverse=True)
        ),
        "support_spacing": PARTIAL_SUPPORT_STEP,
        "kernel_width": ROBUST_WIDTH,
        "guard_coefficients_between_support_cells": (
            PARTIAL_SUPPORT_STEP - ROBUST_WIDTH
        ),
        "two_trace_stages_omitted_is_unsafe": True,
        "a99_partial_trace_is_already_revhomtrace_order": True,
        "a99_ms_delta": (
            "replace separate H(E),H(X^sO) by one H(E-X^sO) in each merge"
        ),
        "grouped_normalization_direct_theorem_transfer": False,
        "grouped_reason": (
            "q/4 block boundaries are not Algorithm 6's per-level q/2 recurrence"
        ),
        "hp_unchanged_partial_nonroot_scale_ratio": "1/2",
        "hp_unchanged_partial_root_scale_ratio": "1/8",
        "hp_partial_required_nonroot_ingress_divisor": partial_gain,
        "hp_partial_required_root_ingress_divisor": 256,
        "hp_full_ingress_divisor": full_gain,
        "encrypted_exact_id_semantics_proven_here": False,
    }


def port_requirements() -> list[str]:
    return [
        "Add a distinct MS-floor merge arm after A99 type-checking; do not silently rewrite g1.",
        "Preserve parity recursion and the exact D2 slot/sign order.",
        "Compute shifted_odd before subtraction; normalize the combined difference only.",
        "Reuse A99 degrees and A97 full-GGSW EvalAuto first; no new key degree is needed.",
        "Keep trace degrees 33..2049 in ascending order; this is partial RevHomTrace n=16.",
        "Add source-faithful floor/2 and paper-aligned nearest/2 as separately labelled arms.",
        "Audit each modulus-switch phase outside timing; paper VMS assumes centered rounding.",
        "Add the paper's 10x4 decomposition as a lead, but do not transfer its p-fail or timing.",
        "Replay mixed Delta59/Delta56 outputs through the width-127 kernel for all errors.",
        "Measure full-GGSW and pseudo-GGSW variants separately if A101 passes.",
        "Compose covariance/noise through the public kernel before any failure claim.",
        "Retest root, ragged N<=127, threshold equality, reject 0, and stable first tie end to end.",
    ]


def build_report(optional_source_tree: Path | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "a102.revhomtrace-ms-packlwes.static-mapping.v1",
        "date": "2026-09-03",
        "status": "STATIC_GO_FOR_MS_A92_PORT_DESIGN_ONLY",
        "promotion_to_runtime_frontier_allowed": False,
        "cargo_rustc_keygen_fhe_or_timing_run": False,
        "local_input_pins": verify_local_inputs(),
        "primary_source_pins": verify_source_pins(),
        "schedule": schedule_audit(),
        "parameters": parameter_audit(),
        "exact_clear_geometry": exact_geometry_audit(),
        "per_nonroot_ledger": [asdict(row) for row in ledger_rows()],
        "n127_structural_ledger": n127_ledger(),
        "compatibility": compatibility_audit(),
        "tfhe_rs_0_11_3_port_requirements": port_requirements(),
        "claims": {
            "allowed": [
                "MS-PackLWEs can reuse A99's ten key degrees and 14-call A92 schedule",
                "A99's retained trace is already in RevHomTrace order",
                "MS reduces g1 logical GLWE normalizations from 21 to 14 per non-root node",
                "the exact encoded clear geometry and width-127 isolation pass",
            ],
            "forbidden": [
                "runtime speedup",
                "A44 noise sufficiency or p-fail",
                "paper benchmark transfer to this host or TFHE-rs 0.11.3",
                "full selector, tournament, or exact-ID correctness",
                "novelty claim for RevHomTrace or MS-PackLWEs",
            ],
        },
    }
    if optional_source_tree is not None:
        report["optional_official_source_tree_verification"] = (
            verify_optional_source_tree(optional_source_tree)
        )
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", nargs="?", type=Path)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--expected-canonical-sha256")
    parser.add_argument("--source-tree", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = build_report(args.source_tree)
    digest = canonical_sha256(report)
    if args.expected_canonical_sha256 and digest != args.expected_canonical_sha256:
        raise StaticMappingError(
            f"canonical report drift: {digest} != {args.expected_canonical_sha256}"
        )
    if args.output:
        if args.verify:
            saved = json.loads(args.output.read_text(encoding="utf-8"))
            if saved != report:
                raise StaticMappingError("saved report differs from reconstruction")
        else:
            args.output.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
    print(
        json.dumps(
            {
                "canonical_sha256": digest,
                "status": report["status"],
                "promotion_to_runtime_frontier_allowed": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
