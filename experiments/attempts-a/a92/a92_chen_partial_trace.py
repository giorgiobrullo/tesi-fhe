#!/usr/bin/env python3
"""Static A92 gate for Chen packing in the exact A87 tuple selector.

This module proves only clear-ring geometry, an ideal exact-arithmetic partial
trace identity, source/ledger arithmetic, and the inherited clear contract.  It
does not execute an automorphism key switch, generate a key, bound ciphertext
rounding/noise, or make a latency claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import runpy
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REGISTRY = (
    Path.home() / ".cargo" / "registry" / "src" / "index.crates.io-1949cf8c6b5b557f"
)
TFHE_0113 = REGISTRY / "tfhe-0.11.3"

POLYNOMIAL_SIZE = 2_048
POLYNOMIAL_LOG = 11
WORD_MODULUS = 1 << 64
GLWE_DIMENSION = 1
GLWE_SIZE = GLWE_DIMENSION + 1
FOURIER_COMPLEX_BYTES = 16
FOURIER_POLYNOMIAL_SIZE = POLYNOMIAL_SIZE // 2
DECOMPOSITION_LEVELS = 1
A44_SMALL_LWE_DIMENSION = 859

BOX_SIZE = 128
LEFT_CONTROL = 4
RIGHT_CONTROL = 12
STRICT_RADIUS = 63
ROBUST_CELL_WIDTH = 2 * STRICT_RADIUS + 1
NONROOT_OUTPUTS = 4
NONROOT_PACKING_ARITY = 8
ROOT_PACKING_ARITY = 2
CHEN_SAMPLE_STEP = 256
PARTIAL_TRACE_STAGES = tuple(range(4, POLYNOMIAL_LOG))
FULL_TRACE_STAGES = tuple(range(3, POLYNOMIAL_LOG))
UNSAFE_TRACE_STAGES = tuple(range(5, POLYNOMIAL_LOG))
USED_AUTOMORPHISM_KEY_INDICES = (0, 1, 2, 4, 5, 6, 7, 8, 9, 10)

A87_SCRIPT = ROOT / "tmp/a87-packed-dynamic-pfks-tuple-selector/a87_packed_pfks.py"
A87_REPORT = (
    ROOT / "tmp/a87-packed-dynamic-pfks-tuple-selector/artifacts/a87_static_result.json"
)
A86_SCRIPT = ROOT / "tmp/a86-a30-pfks-parameter-preflight/a86_pfks_preflight.py"

LOCAL_SOURCE_PINS = {
    A87_SCRIPT: "4b895a48703806612156e258356a5d3c957e0abae3ec44648ba5520cfda193ff",
    A87_REPORT: "72f20b2c9e1c3eca45eca0043b843971a8ad698fcf54682b72cb34bacd1536fc",
    A86_SCRIPT: "15a2a73d725951dda0073f294d62bf2615cc21fe4ee4f85bca1c9cf4398e1dd6",
    TFHE_0113 / "src/core_crypto/entities/ggsw_ciphertext.rs": (
        "dd175759511c1650508762502b01f4a68667dbd3461aa1731857a7fdfce1c821"
    ),
    TFHE_0113 / "src/core_crypto/algorithms/lwe_programmable_bootstrapping/fft64.rs": (
        "174c74c30625316491a408b34f5a7bd135ead4652df63d102b8791b13e957e52"
    ),
    TFHE_0113 / "src/core_crypto/algorithms/ggsw_encryption.rs": (
        "833955bd7f71fd05e9fdff348b6b99f6c1a2c67acef3d15a6c09684962c4f179"
    ),
    TFHE_0113 / "src/core_crypto/algorithms/glwe_sample_extraction.rs": (
        "981d3839cd83cb8c24b02fe48d945d61e23c9c0f2e714b554d9296eed304ec43"
    ),
}

TFHEPP_COMMIT = "c2518753a62619b469e8222b71a9480036d1a515"
TFHEPP_REMOTE_PINS = {
    "include/tfhe/keyswitch.hpp": {
        "sha256": "eb9b976e0c7ac09b9626023f0fbb537e679d3fdc71431fa1e120da8633df4281",
        "relevant_lines": "293-332,391-437",
        "role": "EvalAuto, AnnihilateKeySwitching, PackLWEs, and Chen packing",
    },
    "include/tfhe/evalkeygens.hpp": {
        "sha256": "5f8e9861a416347ce813127734ee39fb8fddfaad3173fa77b065c00c75a121fa",
        "relevant_lines": "206-226",
        "role": "automorphism and annihilate key generation",
    },
    "include/params.hpp": {
        "sha256": "71207a0cfe75db1c8fa7a19346ebddddd087c397555bc87e45603b7a8e64203c",
        "relevant_lines": "163-217,267-275",
        "role": "TLWE/TRLWE/HalfTRGSWFFT/EvalAutoKey/AnnihilateKey layouts",
    },
    "test/tfhe/chenspacking.cpp": {
        "sha256": "d4acfa55f1df539abd5a2c5b67a2c4913c2d0f05803204a631867900b793f62f",
        "relevant_lines": "9-52",
        "role": "upstream executable packing test and output spacing",
    },
}


class StaticProofError(RuntimeError):
    """Raised when a frozen static premise or exact identity fails."""


@dataclass(frozen=True)
class ChenLedger:
    gallery_size: int
    nonroot_nodes: int
    selector_nodes: int
    eval_auto_nonroot: int
    eval_auto_root: int
    eval_auto_total: int
    inverse_sample_embeddings: int
    nontrivial_input_lwes_d2: int
    nontrivial_input_lwes_d1: int
    trivial_zero_input_lwes_d1: int
    public_kernel_glwe_multiplications: int
    glwe_monomial_shifts: int
    glwe_addition_passes: int
    coefficient_halvings: int
    input_lwe_negations: int
    lwe_preselection_subtractions_d1: int
    lwe_postselection_additions_d1: int
    pfpks_calls: int
    blind_rotations_inherited: int
    classic_key_switches_inherited: int
    marginals_inherited: int


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
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


def verify_local_source_pins() -> list[dict[str, str]]:
    evidence: list[dict[str, str]] = []
    for path, expected in LOCAL_SOURCE_PINS.items():
        if not path.is_file():
            raise StaticProofError(f"missing pinned local input: {path}")
        actual = sha256_file(path)
        if actual != expected:
            raise StaticProofError(
                f"pinned local input drift: {path}: {actual} != {expected}"
            )
        try:
            display = str(path.relative_to(ROOT))
        except ValueError:
            display = f"cargo-registry/tfhe-0.11.3/{path.relative_to(TFHE_0113)}"
        evidence.append({"path": display, "sha256": actual})
    return evidence


def validate_word(word: int) -> None:
    if (
        isinstance(word, bool)
        or not isinstance(word, int)
        or not 0 <= word < WORD_MODULUS
    ):
        raise StaticProofError("payload is not a canonical u64 torus word")


def negacyclic_sample(polynomial: Sequence[int], virtual_degree: int) -> int:
    if len(polynomial) != POLYNOMIAL_SIZE:
        raise StaticProofError("polynomial has the wrong size")
    cycles, index = divmod(virtual_degree, POLYNOMIAL_SIZE)
    value = polynomial[index]
    validate_word(value)
    return value if cycles % 2 == 0 else (-value) % WORD_MODULUS


def signed_kernel_terms() -> tuple[tuple[int, int], ...]:
    terms: list[tuple[int, int]] = []
    for error in range(-STRICT_RADIUS, STRICT_RADIUS + 1):
        cycles, index = divmod(error, POLYNOMIAL_SIZE)
        terms.append((index, -1 if cycles % 2 else 1))
    return tuple(terms)


def add_shifted_kernel(body: list[int], center: int, word: int) -> None:
    validate_word(word)
    for kernel_index, kernel_sign in signed_kernel_terms():
        # ``kernel_sign`` already represents the negative virtual exponents in
        # Z[X]/(X^N+1).  Shift the stored polynomial coefficient; converting
        # it back to a negative exponent here would apply the negacyclic sign
        # twice.
        cycles, output_index = divmod(center + kernel_index, POLYNOMIAL_SIZE)
        sign = kernel_sign * (-1 if cycles % 2 else 1)
        body[output_index] = (body[output_index] + sign * word) % WORD_MODULUS


def reference_cell_body(
    left: Sequence[int], right: Sequence[int], *, variant: str
) -> tuple[int, ...]:
    if len(left) != len(right) or len(left) not in (1, NONROOT_OUTPUTS):
        raise StaticProofError("A92 supports only the k=4 node and k=1 root")
    if any(
        isinstance(word, bool)
        or not isinstance(word, int)
        or not 0 <= word < WORD_MODULUS
        for word in (*left, *right)
    ):
        raise StaticProofError("payload tuple is outside the canonical u64 ring")
    normalized = variant.upper()
    if normalized not in {"D2", "D1"}:
        raise StaticProofError("variant must be D2 or D1")
    body = [0] * POLYNOMIAL_SIZE
    for output_index, (left_word, right_word) in enumerate(
        zip(left, right, strict=True)
    ):
        sample = output_index * CHEN_SAMPLE_STEP
        if normalized == "D2":
            add_shifted_kernel(body, LEFT_CONTROL * BOX_SIZE + sample, left_word)
            add_shifted_kernel(body, RIGHT_CONTROL * BOX_SIZE + sample, right_word)
        else:
            delta = (right_word - left_word) % WORD_MODULUS
            add_shifted_kernel(body, RIGHT_CONTROL * BOX_SIZE + sample, delta)
    return tuple(body)


def chen_slot_words(
    left: Sequence[int], right: Sequence[int], *, variant: str
) -> tuple[int, ...]:
    if len(left) != len(right) or len(left) not in (1, NONROOT_OUTPUTS):
        raise StaticProofError("A92 supports only the k=4 node and k=1 root")
    for word in (*left, *right):
        validate_word(word)
    normalized = variant.upper()
    if normalized not in {"D2", "D1"}:
        raise StaticProofError("variant must be D2 or D1")
    if len(left) == 1:
        if normalized == "D2":
            return (left[0], right[0])
        return (0, (right[0] - left[0]) % WORD_MODULUS)
    if normalized == "D2":
        # Slots t*256.  The two negative entries compensate X^(2048+t)=-X^t.
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
    delta = tuple(
        (right_word - left_word) % WORD_MODULUS
        for left_word, right_word in zip(left, right, strict=True)
    )
    return (
        (-delta[2]) % WORD_MODULUS,
        (-delta[3]) % WORD_MODULUS,
        0,
        0,
        0,
        0,
        delta[0],
        delta[1],
    )


def ideal_chen_kernel_body(
    left: Sequence[int], right: Sequence[int], *, variant: str
) -> tuple[int, ...]:
    slots = chen_slot_words(left, right, variant=variant)
    body = [0] * POLYNOMIAL_SIZE
    if len(slots) == ROOT_PACKING_ARITY:
        slot_step = POLYNOMIAL_SIZE // ROOT_PACKING_ARITY
        global_shift = LEFT_CONTROL * BOX_SIZE
    elif len(slots) == NONROOT_PACKING_ARITY:
        slot_step = POLYNOMIAL_SIZE // NONROOT_PACKING_ARITY
        global_shift = 0
    else:
        raise StaticProofError("unexpected Chen packing arity")
    for slot_index, word in enumerate(slots):
        add_shifted_kernel(body, global_shift + slot_index * slot_step, word)
    return tuple(body)


def extract_tuple(
    body: Sequence[int], *, control: int, error: int, output_count: int
) -> tuple[int, ...]:
    if control not in (LEFT_CONTROL, RIGHT_CONTROL):
        raise StaticProofError("control must be the p16 center 4 or 12")
    if isinstance(error, bool) or not isinstance(error, int):
        raise StaticProofError("rotation error must be an integer")
    if output_count not in (1, NONROOT_OUTPUTS):
        raise StaticProofError("output count must be one or four")
    rotation = control * BOX_SIZE + error
    return tuple(
        negacyclic_sample(body, rotation + output_index * CHEN_SAMPLE_STEP)
        for output_index in range(output_count)
    )


def select_tuple(
    left: Sequence[int],
    right: Sequence[int],
    *,
    control: int,
    error: int,
    variant: str,
) -> tuple[int, ...]:
    body = ideal_chen_kernel_body(left, right, variant=variant)
    selected = extract_tuple(body, control=control, error=error, output_count=len(left))
    if variant.upper() == "D1":
        return tuple(
            (left_word + delta) % WORD_MODULUS
            for left_word, delta in zip(left, selected, strict=True)
        )
    return selected


def apply_automorphism_to_basis(
    exponent: int, automorphism_degree: int
) -> tuple[int, int]:
    cycles, output_exponent = divmod(exponent * automorphism_degree, POLYNOMIAL_SIZE)
    return output_exponent, -1 if cycles % 2 else 1


def trace_basis_numerator(exponent: int, stages: Sequence[int]) -> dict[int, int]:
    """Return numerator of product(I+sigma_d)/2^len(stages) on X^exponent."""

    terms: dict[int, int] = {exponent: 1}
    for stage in stages:
        degree = (1 << (stage + 1)) + 1
        following: defaultdict[int, int] = defaultdict(int)
        for current_exponent, coefficient in terms.items():
            following[current_exponent] += coefficient
            output_exponent, sign = apply_automorphism_to_basis(
                current_exponent, degree
            )
            following[output_exponent] += sign * coefficient
        terms = {key: value for key, value in following.items() if value}
    return terms


def projection_audit() -> dict[str, Any]:
    specifications = (
        ("full", FULL_TRACE_STAGES, 256),
        ("partial_safe", PARTIAL_TRACE_STAGES, 128),
        ("skip_two_unsafe", UNSAFE_TRACE_STAGES, 64),
    )
    checks = 0
    for label, stages, support_step in specifications:
        denominator = 1 << len(stages)
        for exponent in range(POLYNOMIAL_SIZE):
            expected = {exponent: denominator} if exponent % support_step == 0 else {}
            observed = trace_basis_numerator(exponent, stages)
            if observed != expected:
                raise StaticProofError(
                    f"{label} trace projection mismatch at exponent {exponent}"
                )
            checks += 1
    safe_gap = 128 - ROBUST_CELL_WIDTH
    unsafe_overlap = ROBUST_CELL_WIDTH - 64
    if safe_gap != 1 or unsafe_overlap != 63:
        raise StaticProofError("guard/overlap arithmetic drift")
    return {
        "exact_basis_checks": checks,
        "full_projection_support_step": 256,
        "full_eval_auto_stages": list(FULL_TRACE_STAGES),
        "partial_projection_support_step": 128,
        "partial_eval_auto_stages": list(PARTIAL_TRACE_STAGES),
        "omitted_standard_stage": 3,
        "safe_guard_coefficients_between_radius63_cells": safe_gap,
        "skip_two_support_step": 64,
        "skip_two_cell_overlap_coefficients": unsafe_overlap,
        "partial_trace_is_maximal_for_one_shared_width127_kernel": True,
        "scope": "ideal exact phase arithmetic; ciphertext u64 division rounding excluded",
    }


def geometry_audit(*, fuzz_trials: int, seed: int) -> dict[str, Any]:
    if (
        isinstance(fuzz_trials, bool)
        or not isinstance(fuzz_trials, int)
        or fuzz_trials <= 0
    ):
        raise StaticProofError("fuzz_trials must be a positive integer")
    basis_cases = 0
    robust_samples = 0
    for output_count in (1, NONROOT_OUTPUTS):
        input_count = 2 * output_count
        for active in range(input_count):
            left = [0] * output_count
            right = [0] * output_count
            (left if active < output_count else right)[active % output_count] = 1
            for variant in ("D2", "D1"):
                reference = reference_cell_body(left, right, variant=variant)
                observed = ideal_chen_kernel_body(left, right, variant=variant)
                if observed != reference:
                    raise StaticProofError(
                        f"{variant} basis body mismatch k={output_count}, active={active}"
                    )
                for control, expected in (
                    (LEFT_CONTROL, tuple(left)),
                    (RIGHT_CONTROL, tuple(right)),
                ):
                    for error in range(-STRICT_RADIUS, STRICT_RADIUS + 1):
                        selected = select_tuple(
                            left,
                            right,
                            control=control,
                            error=error,
                            variant=variant,
                        )
                        if selected != expected:
                            raise StaticProofError(
                                f"{variant} robust basis mismatch at error {error}"
                            )
                        robust_samples += output_count
                basis_cases += 1

    rng = random.Random(seed)
    for _ in range(fuzz_trials):
        output_count = rng.choice((1, NONROOT_OUTPUTS))
        left = tuple(rng.randrange(WORD_MODULUS) for _ in range(output_count))
        right = tuple(rng.randrange(WORD_MODULUS) for _ in range(output_count))
        control = rng.choice((LEFT_CONTROL, RIGHT_CONTROL))
        error = rng.randrange(-STRICT_RADIUS, STRICT_RADIUS + 1)
        expected = left if control == LEFT_CONTROL else right
        for variant in ("D2", "D1"):
            if (
                select_tuple(left, right, control=control, error=error, variant=variant)
                != expected
            ):
                raise StaticProofError("deterministic u64 fuzz mismatch")
    nonroot_centers = {
        "left": [LEFT_CONTROL * BOX_SIZE + j * CHEN_SAMPLE_STEP for j in range(4)],
        "right": [RIGHT_CONTROL * BOX_SIZE + j * CHEN_SAMPLE_STEP for j in range(4)],
    }
    folded = sorted(
        center % POLYNOMIAL_SIZE
        for centers in nonroot_centers.values()
        for center in centers
    )
    if folded != list(range(0, POLYNOMIAL_SIZE, CHEN_SAMPLE_STEP)):
        raise StaticProofError("nonroot centers are not exactly the eight Chen slots")
    return {
        "status": "PASS_EXACT_CLEAR_RING_GEOMETRY",
        "basis_cases": basis_cases,
        "robust_output_word_checks": robust_samples,
        "deterministic_u64_fuzz_trials": fuzz_trials,
        "fuzz_variants_per_trial": 2,
        "sample_step": CHEN_SAMPLE_STEP,
        "nonroot_virtual_centers": nonroot_centers,
        "nonroot_folded_centers": folded,
        "d2_slot_order": ["-R2", "-R3", "L0", "L1", "L2", "L3", "R0", "R1"],
        "d1_slot_order": ["-D2", "-D3", "0", "0", "0", "0", "D0", "D1"],
        "root_slot_order_d2": ["L0", "R0"],
        "root_slot_order_d1": ["0", "D0"],
        "root_global_monomial_shift": LEFT_CONTROL * BOX_SIZE,
        "single_public_kernel_width": ROBUST_CELL_WIDTH,
        "arbitrary_u64_exact_by_module_linearity": True,
    }


def _encode_candidate(
    a87: dict[str, Any], candidate: Any, root: bool
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    return a87["_encode_payload"](candidate, root)


def chen_choose(
    a87: dict[str, Any], left: Any, right: Any, *, variant: str, root: bool, error: int
) -> Any:
    control = (
        RIGHT_CONTROL
        if a87["weighted_relation"](left.key, right.key) > 0
        else LEFT_CONTROL
    )
    left_words, scales = _encode_candidate(a87, left, root)
    right_words, right_scales = _encode_candidate(a87, right, root)
    if scales != right_scales:
        raise StaticProofError("candidate payload scales differ")
    selected_words = select_tuple(
        left_words,
        right_words,
        control=control,
        error=error,
        variant=variant,
    )
    decoded = a87["_decode_payload"](selected_words, scales)
    selected = right if control == RIGHT_CONTROL else left
    expected = (selected.code,) if root else (*selected.key, selected.code)
    if decoded != expected:
        raise StaticProofError(
            "A92 candidate selection differs from stable A87 selection"
        )
    if root:
        return a87["Candidate"](selected.key, decoded[0])
    return a87["Candidate"](tuple(decoded[:3]), decoded[3])


def chen_tournament_code(
    a87: dict[str, Any], scores: Sequence[int], *, variant: str
) -> int:
    if not scores or len(scores) > 127:
        raise StaticProofError("gallery size must be in [1,127]")
    level = [a87["Candidate"](a87["bridge_key"](a87["SENTINEL_SCORE"]), 0)]
    level.extend(
        a87["Candidate"](a87["bridge_key"](score), index + 1)
        for index, score in enumerate(scores)
    )
    node_index = 0
    while len(level) > 1:
        following = []
        root_level = len(level) == 2
        for offset in range(0, len(level), 2):
            if offset + 1 == len(level):
                following.append(level[offset])
                continue
            error = (37 * node_index % (2 * STRICT_RADIUS + 1)) - STRICT_RADIUS
            following.append(
                chen_choose(
                    a87,
                    level[offset],
                    level[offset + 1],
                    variant=variant,
                    root=root_level,
                    error=error,
                )
            )
            node_index += 1
        level = following
    return level[0].code


def contract_audit(*, trials: int, seed: int) -> dict[str, Any]:
    a87 = runpy.run_path(str(A87_SCRIPT))
    rng = random.Random(seed)
    boundary_cases = (
        (2, 0, 0),
        (2, 1023, 1024),
        (3, 4, 4, 7),
        (3, 1024, 1024, 1024),
        (5, 8, 2, 2, 3, 2),
        (127, *([1024] * 126), 1023),
    )
    cases: list[tuple[int, ...]] = []
    for declared_size, *scores in boundary_cases:
        if declared_size != len(scores):
            raise StaticProofError("internal boundary fixture length mismatch")
        cases.append(tuple(scores))
    for size in (1, 2, 3, 33, 63, 64, 65, 126, 127):
        for _ in range(max(1, trials // 9)):
            cases.append(tuple(rng.randrange(0, 4096) for _ in range(size)))
    checked = 0
    for scores in cases:
        expected = a87["reference_code"](scores)
        for variant in ("D2", "D1"):
            observed = chen_tournament_code(a87, scores, variant=variant)
            if observed != expected:
                raise StaticProofError(
                    f"{variant} tournament contract mismatch for N={len(scores)}"
                )
            checked += 1
    return {
        "status": "PASS_INHERITED_EXACT_0_ID_CONTRACT",
        "gallery_cases": len(cases),
        "variant_cases": checked,
        "random_trial_budget": trials,
        "ragged_sizes": [33, 63, 64, 65, 126],
        "tie_policy": "first minimum",
        "threshold_policy": "accept minimum <= 1023; reject as 0 otherwise",
        "output_contract": "0 reject / i+1 exact nearest accepted identity",
    }


def eval_auto_count(arity: int) -> int:
    if arity not in (ROOT_PACKING_ARITY, NONROOT_PACKING_ARITY):
        raise StaticProofError("packing arity must be two or eight")
    recursive = arity - 1
    return recursive + len(PARTIAL_TRACE_STAGES)


def coefficient_halvings(arity: int) -> int:
    recursive = 2 * (arity - 1) * GLWE_SIZE * POLYNOMIAL_SIZE
    trace = len(PARTIAL_TRACE_STAGES) * GLWE_SIZE * POLYNOMIAL_SIZE
    return recursive + trace


def chen_ledger(gallery_size: int) -> ChenLedger:
    if (
        isinstance(gallery_size, bool)
        or not isinstance(gallery_size, int)
        or not 1 <= gallery_size <= 127
    ):
        raise StaticProofError("gallery size must be an integer in [1,127]")
    a87 = runpy.run_path(str(A87_SCRIPT))
    baseline = a87["packed_ledger"](gallery_size, pfks_variant="D2")
    nonroot = gallery_size - 1
    nodes = gallery_size
    eval_nonroot = eval_auto_count(NONROOT_PACKING_ARITY)
    eval_root = eval_auto_count(ROOT_PACKING_ARITY)
    dynamic_outputs = 4 * nonroot + 1
    embeddings = NONROOT_PACKING_ARITY * nonroot + ROOT_PACKING_ARITY
    return ChenLedger(
        gallery_size=gallery_size,
        nonroot_nodes=nonroot,
        selector_nodes=nodes,
        eval_auto_nonroot=eval_nonroot,
        eval_auto_root=eval_root,
        eval_auto_total=nonroot * eval_nonroot + eval_root,
        inverse_sample_embeddings=embeddings,
        nontrivial_input_lwes_d2=embeddings,
        nontrivial_input_lwes_d1=dynamic_outputs,
        trivial_zero_input_lwes_d1=embeddings - dynamic_outputs,
        public_kernel_glwe_multiplications=nodes,
        glwe_monomial_shifts=nonroot * (NONROOT_PACKING_ARITY - 1) + 2,
        glwe_addition_passes=nonroot * eval_nonroot + eval_root,
        coefficient_halvings=(
            nonroot * coefficient_halvings(NONROOT_PACKING_ARITY)
            + coefficient_halvings(ROOT_PACKING_ARITY)
        ),
        input_lwe_negations=2 * nonroot,
        lwe_preselection_subtractions_d1=dynamic_outputs,
        lwe_postselection_additions_d1=dynamic_outputs,
        pfpks_calls=0,
        blind_rotations_inherited=baseline.total_blind_rotations,
        classic_key_switches_inherited=baseline.total_classic_key_switches,
        marginals_inherited=baseline.total_marginals,
    )


def key_ledger() -> dict[str, Any]:
    used_keys = len(USED_AUTOMORPHISM_KEY_INDICES)
    full_per_key = (
        DECOMPOSITION_LEVELS
        * GLWE_SIZE
        * GLWE_SIZE
        * FOURIER_POLYNOMIAL_SIZE
        * FOURIER_COMPLEX_BYTES
    )
    # TFHEpp's EvalAutoKey contains k HalfTRGSWFFT objects.  At k=1 and l=1,
    # each stores one Fourier TRLWE rather than a full 2x2 GGSW level matrix.
    half_per_key = (
        GLWE_DIMENSION
        * DECOMPOSITION_LEVELS
        * GLWE_SIZE
        * FOURIER_POLYNOMIAL_SIZE
        * FOURIER_COMPLEX_BYTES
    )
    pfpks_bytes = 67_141_632
    return {
        "automorphism_key_indices": list(USED_AUTOMORPHISM_KEY_INDICES),
        "automorphism_degrees": [
            (1 << (index + 1)) + 1 for index in USED_AUTOMORPHISM_KEY_INDICES
        ],
        "standard_full_fourier_ggsw_bytes_per_key": full_per_key,
        "standard_full_fourier_ggsw_total_bytes": used_keys * full_per_key,
        "standard_full_fourier_ggsw_total_mib": used_keys * full_per_key / 2**20,
        "tfhepp_half_fourier_ggsw_bytes_per_key": half_per_key,
        "tfhepp_half_fourier_ggsw_total_bytes": used_keys * half_per_key,
        "tfhepp_half_fourier_ggsw_total_mib": used_keys * half_per_key / 2**20,
        "a87_pfpks_level1_bytes": pfpks_bytes,
        "a87_pfpks_level1_mib": pfpks_bytes / 2**20,
        "pfpks_to_standard_full_key_size_ratio": pfpks_bytes
        / (used_keys * full_per_key),
        "pfpks_to_tfhepp_half_key_size_ratio": pfpks_bytes / (used_keys * half_per_key),
        "latency_ready_first_port": (
            "stock full Fourier GGSW external product; custom polynomial GGSW keygen still required"
        ),
        "optional_later_port": "TFHEpp-style half-GGSW external product",
    }


def ledger_audit() -> dict[str, Any]:
    a87 = runpy.run_path(str(A87_SCRIPT))
    a87_d2 = a87["packed_ledger"](127, pfks_variant="D2")
    a87_d1 = a87["packed_ledger"](127, pfks_variant="D1")
    chen = chen_ledger(127)
    if chen.eval_auto_total != 1_772:
        raise StaticProofError("N127 partial Chen EvalAuto ledger drift")
    if chen.coefficient_halvings != 10_874_880:
        raise StaticProofError("N127 coefficient-halving ledger drift")
    if chen.glwe_monomial_shifts != 884:
        raise StaticProofError("N127 monomial-shift ledger drift")
    if (
        a87_d2.pfks_calls,
        a87_d1.pfks_calls,
        a87_d2.public_polynomial_multiplications,
        a87_d1.public_polynomial_multiplications,
    ) != (1_010, 505, 1_010, 505):
        raise StaticProofError("source-pinned A87 ledger drift")
    external_product_orientation = chen.eval_auto_total / A44_SMALL_LWE_DIMENSION
    return {
        "status": "PASS_STRUCTURAL_LEDGER_NOT_LATENCY",
        "a87_packed_d2_n127": asdict(a87_d2),
        "a87_packed_d1_n127": asdict(a87_d1),
        "a92_partial_chen_n127": asdict(chen),
        "exact_structural_delta_from_a87_d2": {
            "pfpks_calls": -a87_d2.pfks_calls,
            "public_polynomial_multiplications": (
                chen.public_kernel_glwe_multiplications
                - a87_d2.public_polynomial_multiplications
            ),
            "eval_auto_calls": chen.eval_auto_total,
            "blind_rotations": 0,
            "classic_key_switches": 0,
            "marginals": 0,
        },
        "exact_structural_delta_from_a87_d1": {
            "pfpks_calls": -a87_d1.pfks_calls,
            "public_polynomial_multiplications": (
                chen.public_kernel_glwe_multiplications
                - a87_d1.public_polynomial_multiplications
            ),
            "eval_auto_calls": chen.eval_auto_total,
            "blind_rotations": 0,
            "classic_key_switches": 0,
            "marginals": 0,
        },
        "eval_auto_count_divided_by_one_a44_br_859_steps": external_product_orientation,
        "orientation_warning": (
            "the quotient is not a timing estimate: EvalAuto implementation, full/half key, "
            "clear permutations, memory traffic, scheduling, and noise all remain unmeasured"
        ),
        "key_ledger": key_ledger(),
    }


def build_report(*, fuzz_trials: int = 4_096) -> dict[str, Any]:
    local_pins = verify_local_source_pins()
    report: dict[str, Any] = {
        "schema_version": 1,
        "attempt": "A92",
        "status": "GO_STATIC_GEOMETRY_AND_LEDGER_NO_RUNTIME_PROMOTION",
        "scope": (
            "source-pinned clear-ring geometry, ideal exact trace projection, inherited "
            "exact-ID contract, key/operation ledger; no Cargo, keygen, FHE, noise bound, or timing"
        ),
        "local_source_pins_verified": local_pins,
        "remote_primary_source_manifest": {
            "repository": "https://github.com/virtualsecureplatform/TFHEpp",
            "commit": TFHEPP_COMMIT,
            "commit_was_remote_HEAD_when_recorded_2026_09_03": True,
            "network_revalidation_is_not_part_of_offline_gate": True,
            "files": TFHEPP_REMOTE_PINS,
            "upstream_name": "Modified Chen's Packing / annihilate key switching",
        },
        "geometry": geometry_audit(fuzz_trials=fuzz_trials, seed=0xA92),
        "partial_trace": projection_audit(),
        "contract": contract_audit(trials=126, seed=0xA920),
        "ledger": ledger_audit(),
        "promotion_gates": {
            "clear_ring_geometry": True,
            "ideal_partial_trace_projection": True,
            "exact_0_id_contract": True,
            "source_port_typechecked": False,
            "automorphism_keygen_executed": False,
            "ciphertext_phase_error_measured": False,
            "joint_output_failures_measured": False,
            "a44_composed_p_fail_bounded": False,
            "runtime_measured": False,
            "promotion_to_runtime_frontier_allowed": False,
        },
        "next_gate": [
            "port one A44 full-GGSW EvalAuto with custom polynomial-message keygen using public core APIs",
            "validate exact automorphism phases before and after each u64 halving stage",
            "run isolated k=4 D2 fixtures with all 127 rotation errors and mixed Delta59/Delta56 payloads",
            "record joint four-output phase errors and compare full versus optional half-GGSW port",
            "time EvalAuto, halving, one width-127 kernel multiply, and the following control BR separately",
            "only then extend the source-pinned A30/A87 tournament scaffold",
        ],
        "known_nonclaims": [
            "Chen packing is prior art and is not claimed as a new primitive",
            "the workload-specific slot map and omitted trace stage have not been prior-art audited",
            "ideal exact phase arithmetic does not model unsigned ciphertext division rounding",
            "separated residual plaintext cells do not imply separated or independent ciphertext noise",
            "primitive counts and smaller keys do not imply a wall-clock speedup",
            "no security level or composed failure probability was derived for the new automorphism keys",
        ],
    }
    report["canonical_sha256"] = canonical_sha256(report)
    return report


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise StaticProofError("saved report must be a JSON object")
    return value


def verify_saved_report(
    path: Path, *, expected_sha256: str | None = None
) -> dict[str, Any]:
    observed = load_json(path)
    recorded = observed.get("canonical_sha256")
    if not isinstance(recorded, str) or len(recorded) != 64:
        raise StaticProofError("saved report has no canonical digest")
    payload = dict(observed)
    del payload["canonical_sha256"]
    actual = canonical_sha256(payload)
    if recorded != actual:
        raise StaticProofError(
            f"saved report canonical digest mismatch: {recorded} != {actual}"
        )
    if expected_sha256 is not None and actual != expected_sha256:
        raise StaticProofError(
            f"unexpected canonical digest: {actual} != {expected_sha256}"
        )
    if observed.get("status") != "GO_STATIC_GEOMETRY_AND_LEDGER_NO_RUNTIME_PROMOTION":
        raise StaticProofError("saved report status drift")
    gates = observed.get("promotion_gates")
    if (
        not isinstance(gates, dict)
        or gates.get("promotion_to_runtime_frontier_allowed") is not False
    ):
        raise StaticProofError("saved report improperly permits runtime promotion")
    verify_local_source_pins()
    return observed


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fuzz-trials", type=int, default=4_096)
    parser.add_argument("--write", type=Path)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--expected-canonical-sha256")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    if args.verify is not None:
        report = verify_saved_report(
            args.verify, expected_sha256=args.expected_canonical_sha256
        )
    else:
        report = build_report(fuzz_trials=args.fuzz_trials)
        if args.write is not None:
            args.write.parent.mkdir(parents=True, exist_ok=True)
            args.write.write_text(
                json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n",
                encoding="utf-8",
            )
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
