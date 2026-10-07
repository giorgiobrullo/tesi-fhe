#!/usr/bin/env python3
"""Static/exhaustive gate for the A98 tfhe-rs 1.7 Head Start port.

This program only reads pinned source and performs integer arithmetic.  It never invokes Cargo,
rustc, key generation, FHE, or a benchmark, and it never writes an output file.
"""

from __future__ import annotations

import functools
import hashlib
import itertools
import json
from pathlib import Path
from typing import Iterable, Sequence


TORUS_BITS = 64
A44_LWE_DIMENSION = 859
A44_LOG_MODULUS = 12
A44_BASE_LOG = 3
A44_LEVEL_COUNT = 5
A44_PRECISION = A44_BASE_LOG * A44_LEVEL_COUNT
A44_STATE_COUNT = 1 << A44_PRECISION

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PINS_PATH = HERE / "SOURCE_PINS.json"


def _plain_int(name: str, value: int, minimum: int, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be a plain int")
    if value < minimum or (maximum is not None and value > maximum):
        suffix = f"..{maximum}" if maximum is not None else " or greater"
        raise ValueError(f"{name} must be in {minimum}{suffix}")
    return value


def word_mask(word_bits: int) -> int:
    word_bits = _plain_int("word_bits", word_bits, 2)
    return (1 << word_bits) - 1


def wrap(value: int, word_bits: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("value must be a plain int")
    return value & word_mask(word_bits)


def to_signed(value: int, word_bits: int) -> int:
    value = wrap(value, word_bits)
    sign_bit = 1 << (word_bits - 1)
    return value - (1 << word_bits) if value & sign_bit else value


def rust_trunc_div2(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("value must be a plain int")
    return value // 2 if value >= 0 else -((-value) // 2)


def arithmetic_shift_right(value: int, shift: int, word_bits: int) -> int:
    shift = _plain_int("shift", shift, 0, word_bits - 1)
    return wrap(to_signed(value, word_bits) >> shift, word_bits)


def _validate_modulus(word_bits: int, log_modulus: int) -> None:
    _plain_int("word_bits", word_bits, 2)
    _plain_int("log_modulus", log_modulus, 1, word_bits - 1)


def modulus_switch(value: int, word_bits: int, log_modulus: int) -> int:
    _validate_modulus(word_bits, log_modulus)
    value = wrap(value, word_bits)
    shift = word_bits - log_modulus
    return wrap(value + (1 << (shift - 1)), word_bits) >> shift


def lifted_round(value: int, word_bits: int, log_modulus: int) -> int:
    return wrap(
        modulus_switch(value, word_bits, log_modulus)
        << (word_bits - log_modulus),
        word_bits,
    )


def round_error(value: int, word_bits: int, log_modulus: int) -> int:
    value = _plain_int("mask element", value, 0, word_mask(word_bits))
    return to_signed(lifted_round(value, word_bits, log_modulus) - value, word_bits)


def correction_components(
    mask: Sequence[int], word_bits: int, log_modulus: int
) -> dict[str, int]:
    """Independent transcription of the patch and tfhe-rs centered corrections."""

    _validate_modulus(word_bits, log_modulus)
    half_sum = 0
    halving_error_doubled_sum = 0
    patch_wrapped_negated_error_sum = 0
    mathematical_error_sum = 0
    for value in mask:
        error = round_error(value, word_bits, log_modulus)
        half_error = rust_trunc_div2(error)
        half_sum = wrap(half_sum + half_error, word_bits)
        halving_error_doubled_sum += 2 * half_error - error
        patch_wrapped_negated_error_sum = wrap(
            patch_wrapped_negated_error_sum - error, word_bits
        )
        mathematical_error_sum += error

    tfhe_halving_adjustment = rust_trunc_div2(halving_error_doubled_sum)
    tfhe_pre_half_case = to_signed(
        half_sum - wrap(tfhe_halving_adjustment, word_bits), word_bits
    )
    half_case = 1 << (word_bits - log_modulus - 1)
    tfhe_centered = to_signed(tfhe_pre_half_case - half_case, word_bits)

    sign_bit = 1 << (word_bits - 1)
    patch_floor_half = wrap(
        (patch_wrapped_negated_error_sum >> 1)
        + (patch_wrapped_negated_error_sum & sign_bit),
        word_bits,
    )
    patch_head_start = to_signed(-patch_floor_half, word_bits)
    tie_bit = int(
        halving_error_doubled_sum < 0
        and halving_error_doubled_sum % 2 != 0
    )
    adapter = to_signed(tfhe_centered + half_case + tie_bit, word_bits)
    return {
        "mathematical_error_sum": mathematical_error_sum,
        "halving_error_doubled_sum": halving_error_doubled_sum,
        "tfhe_pre_half_case": tfhe_pre_half_case,
        "tfhe_centered": tfhe_centered,
        "half_case": half_case,
        "tie_bit": tie_bit,
        "adapter": adapter,
        "patch_head_start": patch_head_start,
    }


def switched_body_degree(
    body: int,
    correction: int,
    word_bits: int,
    log_modulus: int,
) -> int:
    return modulus_switch(
        wrap(body + correction, word_bits), word_bits, log_modulus
    )


@functools.lru_cache(maxsize=1)
def exhaustive_adapter_summary() -> dict[str, object]:
    cases = 0
    tie_zero = 0
    tie_one = 0
    by_word_bits: dict[str, int] = {}
    for word_bits in range(5, 9):
        modulus = 1 << word_bits
        word_cases = 0
        for log_modulus in range(2, word_bits):
            for first, second in itertools.product(range(modulus), repeat=2):
                parts = correction_components(
                    (first, second), word_bits, log_modulus
                )
                if parts["adapter"] != parts["patch_head_start"]:
                    raise AssertionError(
                        "centered raw-parts adapter diverged from Head Start"
                    )
                if parts["tie_bit"] == 0:
                    tie_zero += 1
                elif parts["tie_bit"] == 1:
                    tie_one += 1
                else:
                    raise AssertionError("tie escaped one-bit range")
                cases += 1
                word_cases += 1
        by_word_bits[str(word_bits)] = word_cases

    if tie_zero == 0 or tie_one == 0:
        raise AssertionError("exhaustive domain did not cover both tie classes")
    return {
        "word_bits": [5, 6, 7, 8],
        "log_modulus_range": "2..word_bits-1",
        "mask_dimension": 2,
        "cases": cases,
        "cases_by_word_bits": by_word_bits,
        "adapter_mismatches": 0,
        "tie_zero_cases": tie_zero,
        "tie_one_cases": tie_one,
    }


def _xorshift64(state: int) -> int:
    state ^= state << 13
    state ^= state >> 7
    state ^= state << 17
    return state & ((1 << 64) - 1)


@functools.lru_cache(maxsize=1)
def a44_adapter_summary() -> dict[str, object]:
    step = 1 << (TORUS_BITS - A44_LOG_MODULUS)
    edge_values = (
        0,
        1,
        step // 2 - 1,
        step // 2,
        step // 2 + 1,
        step - 1,
        step,
        (1 << 64) - 1,
        (1 << 64) - step,
        (1 << 64) - step + 1,
    )
    state = 0xA98C_E17E_5EED_0044
    tie_counts = [0, 0]
    cases = 64
    for case in range(cases):
        mask = []
        for index in range(A44_LWE_DIMENSION):
            state = _xorshift64(state)
            value = state
            if index < len(edge_values):
                value = edge_values[(index + case) % len(edge_values)]
            mask.append(value)
        parts = correction_components(mask, TORUS_BITS, A44_LOG_MODULUS)
        if parts["adapter"] != parts["patch_head_start"]:
            raise AssertionError("A44-shaped adapter mismatch")
        tie_counts[parts["tie_bit"]] += 1

    residual_bound = A44_LWE_DIMENSION * (step // 2)
    if residual_bound >= 1 << 63:
        raise AssertionError("A44 residual bound does not fit signed i64")
    return {
        "vectors": cases,
        "mask_coefficients_per_vector": A44_LWE_DIMENSION,
        "coefficients_checked": cases * A44_LWE_DIMENSION,
        "adapter_mismatches": 0,
        "tie_zero_vectors": tie_counts[0],
        "tie_one_vectors": tie_counts[1],
        "worst_case_absolute_residual_sum_bound": residual_bound,
        "tfhe_i64_accumulator_safe_under_a44_shape": True,
    }


@functools.lru_cache(maxsize=1)
def exhaustive_a44_tie_aggregate_summary() -> dict[str, int]:
    """Exhaust every possible H=sum(2*trunc(d_i/2)-d_i) for 859 coefficients.

    Each summand is -1, 0, or +1, so every integer in [-859, 859] is reachable.  The even parts
    of the residuals contribute an arbitrary common integer T and cancel from this identity.
    """

    cases = 0
    tie_one = 0
    for halving_error_sum in range(-A44_LWE_DIMENSION, A44_LWE_DIMENSION + 1):
        # If D=2*T-H, then ceil(D/2)-T = -floor(H/2).
        head_start_minus_common = -(halving_error_sum // 2)
        tfhe_pre_minus_common = -rust_trunc_div2(halving_error_sum)
        tie_bit = int(halving_error_sum < 0 and halving_error_sum % 2 != 0)
        if tfhe_pre_minus_common + tie_bit != head_start_minus_common:
            raise AssertionError("aggregate tie identity failed")
        cases += 1
        tie_one += tie_bit
    return {
        "reachable_h_signatures": cases,
        "tie_one_signatures": tie_one,
        "identity_mismatches": 0,
    }


def modulus_switch_boundary_witness() -> dict[str, object]:
    step = 1 << (TORUS_BITS - A44_LOG_MODULUS)
    mask = (step - 1,)
    parts = correction_components(mask, TORUS_BITS, A44_LOG_MODULUS)
    anchor_body = 63 * step
    boundary_body = anchor_body + step // 2 - 1
    anchor_head = switched_body_degree(
        anchor_body, parts["patch_head_start"], TORUS_BITS, A44_LOG_MODULUS
    )
    anchor_centered = switched_body_degree(
        anchor_body, parts["tfhe_centered"], TORUS_BITS, A44_LOG_MODULUS
    )
    boundary_head = switched_body_degree(
        boundary_body,
        parts["patch_head_start"],
        TORUS_BITS,
        A44_LOG_MODULUS,
    )
    boundary_centered = switched_body_degree(
        boundary_body, parts["tfhe_centered"], TORUS_BITS, A44_LOG_MODULUS
    )
    boundary_adapter = switched_body_degree(
        boundary_body, parts["adapter"], TORUS_BITS, A44_LOG_MODULUS
    )
    expected = (anchor_head, anchor_centered, boundary_head, boundary_centered)
    if expected != (63, 63, 64, 63) or boundary_adapter != boundary_head:
        raise AssertionError("pinned modulus-switch boundary witness drifted")
    return {
        "mask": [step - 1],
        "tie_bit": parts["tie_bit"],
        "head_start_correction": parts["patch_head_start"],
        "tfhe_centered_correction": parts["tfhe_centered"],
        "adapter_correction": parts["adapter"],
        "anchor_degrees": {"head_start": anchor_head, "centered": anchor_centered},
        "boundary_degrees": {
            "head_start": boundary_head,
            "centered": boundary_centered,
            "adapter": boundary_adapter,
        },
        "direct_centered_same_lut_exact": False,
        "raw_parts_adapter_exact_at_witness": True,
    }


def _validate_decomposition(word_bits: int, base_log: int, level_count: int) -> int:
    _plain_int("word_bits", word_bits, 2)
    _plain_int("base_log", base_log, 1, word_bits - 1)
    _plain_int("level_count", level_count, 1)
    precision = base_log * level_count
    if precision >= word_bits:
        raise ValueError("decomposition precision must be smaller than word_bits")
    return precision


def patch_bit_trick_terms(
    state: int,
    word_bits: int = TORUS_BITS,
    base_log: int = A44_BASE_LOG,
    level_count: int = A44_LEVEL_COUNT,
) -> tuple[tuple[int, int], ...]:
    _validate_decomposition(word_bits, base_log, level_count)
    # The patch passes a positive precision-bit state.  The same private iterator is also used
    # below to model the public API, whose balancing initializer may sign-extend that state.
    state = _plain_int("state", state, 0, word_mask(word_bits))
    mod_b_mask = (1 << base_log) - 1
    terms = []
    for level in range(level_count, 0, -1):
        residue = state & mod_b_mask
        state = arithmetic_shift_right(state, base_log, word_bits)
        carry = (
            (wrap(residue - 1, word_bits) | state) & residue
        ) >> (base_log - 1)
        state = wrap(state + carry, word_bits)
        digit = to_signed(residue - (carry << base_log), word_bits)
        terms.append((level, digit))
    return tuple(terms)


def independent_branch_terms(
    state: int,
    word_bits: int = TORUS_BITS,
    base_log: int = A44_BASE_LOG,
    level_count: int = A44_LEVEL_COUNT,
) -> tuple[tuple[int, int], ...]:
    precision = _validate_decomposition(word_bits, base_log, level_count)
    state = _plain_int("state", state, 0, (1 << precision) - 1)
    basis = 1 << base_log
    basis_mask = basis - 1
    half_basis = basis // 2
    terms = []
    for level in range(level_count, 0, -1):
        residue = state & basis_mask
        next_state = arithmetic_shift_right(state, base_log, word_bits)
        next_residue = next_state & basis_mask
        carry = int(
            residue > half_basis
            or (residue == half_basis and next_residue >= half_basis)
        )
        state = wrap(next_state + carry, word_bits)
        terms.append((level, residue - carry * basis))
    return tuple(terms)


def public_init_state(
    rounded: int,
    word_bits: int = TORUS_BITS,
    base_log: int = A44_BASE_LOG,
    level_count: int = A44_LEVEL_COUNT,
) -> int:
    precision = _validate_decomposition(word_bits, base_log, level_count)
    rounded = _plain_int("rounded", rounded, 0, word_mask(word_bits))
    non_representable = word_bits - precision
    state = rounded >> (non_representable - 1)
    rounding_bit = state & 1
    state = (state + 1) >> 1
    state &= (1 << precision) - 1
    shifted_random = rounding_bit << (precision - 1)
    need_balance = (
        (wrap(state - 1, word_bits) | shifted_random) & state
    ) >> (precision - 1)
    return wrap(state - (need_balance << precision), word_bits)


def recompose(
    terms: Iterable[tuple[int, int]],
    word_bits: int = TORUS_BITS,
    base_log: int = A44_BASE_LOG,
) -> int:
    total = 0
    for level, digit in terms:
        total = wrap(
            total + digit * (1 << (word_bits - base_log * level)), word_bits
        )
    return total


@functools.lru_cache(maxsize=1)
def exhaustive_decomposer_summary() -> dict[str, object]:
    local_mismatches = 0
    public_mismatch_states: list[int] = []
    difference_shapes: set[tuple[int, ...]] = set()
    recomposition_mismatches = 0
    absolute_digit_mismatches = 0
    for state in range(A44_STATE_COUNT):
        patch = patch_bit_trick_terms(state)
        local = independent_branch_terms(state)
        rounded = state << (TORUS_BITS - A44_PRECISION)
        public = patch_bit_trick_terms(public_init_state(rounded))
        local_mismatches += int(local != patch)
        if public != patch:
            public_mismatch_states.append(state)
            difference_shapes.add(
                tuple(
                    patch_digit - public_digit
                    for (_, patch_digit), (_, public_digit) in zip(patch, public)
                )
            )
        recomposition_mismatches += int(recompose(patch) != rounded)
        recomposition_mismatches += int(recompose(public) != rounded)
        absolute_digit_mismatches += int(
            tuple(abs(value) for _, value in patch)
            != tuple(abs(value) for _, value in public)
        )

    contiguous = public_mismatch_states == list(
        range(public_mismatch_states[0], public_mismatch_states[-1] + 1)
    )
    return {
        "states_exhausted": A44_STATE_COUNT,
        "emitted_levels": [5, 4, 3, 2, 1],
        "local_vs_patch_mismatches": local_mismatches,
        "public_vs_patch_bitwise_mismatches": len(public_mismatch_states),
        "first_public_mismatch": public_mismatch_states[0],
        "last_public_mismatch": public_mismatch_states[-1],
        "public_mismatch_interval_contiguous": contiguous,
        "patch_minus_public_digit_shapes": [
            list(shape) for shape in sorted(difference_shapes)
        ],
        "functional_recomposition_mismatches": recomposition_mismatches,
        "absolute_digit_vector_mismatches": absolute_digit_mismatches,
    }


def patch_round(value: int, word_bits: int, precision: int) -> tuple[int, int]:
    _plain_int("word_bits", word_bits, 2)
    _plain_int("precision", precision, 1, word_bits - 1)
    value = _plain_int("value", value, 0, word_mask(word_bits))
    discarded = word_bits - precision
    rounding_mask = 1 << (discarded - 1)
    selection_mask = wrap(-(1 << discarded), word_bits)
    rounded = wrap(value + rounding_mask, word_bits) & selection_mask
    return rounded, wrap(value - rounded, word_bits)


def patch_halve_correction(value: int, word_bits: int) -> int:
    value = _plain_int("value", value, 0, word_mask(word_bits))
    sign_bit = 1 << (word_bits - 1)
    return wrap((value >> 1) + (value & sign_bit), word_bits)


@functools.lru_cache(maxsize=1)
def exhaustive_rounding_summary() -> dict[str, int]:
    rounding_cases = 0
    halving_cases = 0
    for word_bits in range(3, 13):
        for precision in range(1, word_bits):
            quantum = 1 << (word_bits - precision)
            half_quantum = quantum // 2
            for value in range(1 << word_bits):
                rounded, error = patch_round(value, word_bits, precision)
                remainder = value & (quantum - 1)
                floor = value - remainder
                oracle = (
                    floor
                    if remainder < half_quantum
                    else wrap(floor + quantum, word_bits)
                )
                if rounded != oracle:
                    raise AssertionError("patch rounding diverged from branch oracle")
                if rounded % quantum != 0:
                    raise AssertionError("patch rounding produced an unrepresentable value")
                signed_error = to_signed(error, word_bits)
                if not -half_quantum <= signed_error < half_quantum:
                    raise AssertionError("patch rounding escaped nearest-bin residual bound")
                rounding_cases += 1
        for value in range(1 << word_bits):
            actual = to_signed(patch_halve_correction(value, word_bits), word_bits)
            expected = to_signed(value, word_bits) // 2
            if actual != expected:
                raise AssertionError("patch signed floor-half transcription mismatch")
            halving_cases += 1
    return {
        "rounding_cases": rounding_cases,
        "rounding_mismatches": 0,
        "halving_cases": halving_cases,
        "halving_mismatches": 0,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_manifest() -> dict[str, object]:
    loaded = json.loads(PINS_PATH.read_text())
    if loaded.get("schema") != "a98.source-pins.v1":
        raise RuntimeError("unexpected A98 pin-manifest schema")
    return loaded


def locate_tfhe_source(manifest: dict[str, object]) -> Path:
    expected = manifest["tfhe_1_7_sources"]
    if not isinstance(expected, dict):
        raise RuntimeError("invalid tfhe source-pin map")
    registry = Path.home() / ".cargo" / "registry" / "src"
    candidates = sorted(path for path in registry.glob("*/tfhe-1.7.0") if path.is_dir())
    complete = [
        path
        for path in candidates
        if all((path / relative).is_file() for relative in expected)
    ]
    if len(complete) != 1:
        raise RuntimeError(
            f"expected one complete tfhe-1.7.0 source tree, found {len(complete)}"
        )
    return complete[0]


def locate_tfhe_archive() -> Path:
    cache = Path.home() / ".cargo" / "registry" / "cache"
    candidates = sorted(cache.glob("*/tfhe-1.7.0.crate"))
    if len(candidates) != 1:
        raise RuntimeError(f"expected one cached tfhe-1.7.0 archive, found {len(candidates)}")
    return candidates[0]


def verify_source_pins() -> dict[str, object]:
    manifest = source_manifest()
    groups: dict[str, list[dict[str, str]]] = {
        "repository_sources": [],
        "tfhe_1_7_sources": [],
        "protected_read_only": [],
    }
    for group in ("repository_sources", "protected_read_only"):
        expected = manifest[group]
        if not isinstance(expected, dict):
            raise RuntimeError(f"invalid source-pin group: {group}")
        for relative, digest in sorted(expected.items()):
            path = ROOT / relative
            if not path.is_file():
                raise RuntimeError(f"missing pinned source: {relative}")
            actual = sha256_file(path)
            if actual != digest:
                raise RuntimeError(f"source drift: {relative}: {actual} != {digest}")
            groups[group].append({"path": relative, "sha256": actual})

    tfhe_root = locate_tfhe_source(manifest)
    tfhe_expected = manifest["tfhe_1_7_sources"]
    if not isinstance(tfhe_expected, dict):
        raise RuntimeError("invalid tfhe source pins")
    for relative, digest in sorted(tfhe_expected.items()):
        actual = sha256_file(tfhe_root / relative)
        if actual != digest:
            raise RuntimeError(f"tfhe source drift: {relative}: {actual} != {digest}")
        groups["tfhe_1_7_sources"].append(
            {"path": f"cargo-registry/tfhe-1.7.0/{relative}", "sha256": actual}
        )

    archive = locate_tfhe_archive()
    actual_archive = sha256_file(archive)
    expected_archive = manifest["tfhe_1_7_crate_archive_sha256"]
    if actual_archive != expected_archive:
        raise RuntimeError(
            f"tfhe crate archive drift: {actual_archive} != {expected_archive}"
        )
    return {
        "verified_counts": {group: len(rows) for group, rows in groups.items()},
        "tfhe_crate_archive": {
            "path": "cargo-registry/cache/tfhe-1.7.0.crate",
            "sha256": actual_archive,
        },
    }


def verify_source_fragments() -> dict[str, bool]:
    manifest = source_manifest()
    tfhe = locate_tfhe_source(manifest)
    patch = (ROOT / "tmp/pdfs/head-start.patch").read_text()
    modulus_switch_source = (
        tfhe / "src/core_crypto/algorithms/modulus_switch.rs"
    ).read_text()
    lazy_source = (
        tfhe / "src/core_crypto/entities/modulus_switched_lwe_ciphertext.rs"
    ).read_text()
    pbs_source = (
        tfhe
        / "src/core_crypto/algorithms/lwe_programmable_bootstrapping/fft64_pbs.rs"
    ).read_text()
    iterator_source = (
        tfhe / "src/core_crypto/commons/math/decomposition/iter.rs"
    ).read_text()
    decomposer_source = (
        tfhe / "src/core_crypto/commons/math/decomposition/decomposer.rs"
    ).read_text()
    term_source = (
        tfhe / "src/core_crypto/commons/math/decomposition/term.rs"
    ).read_text()
    port = (HERE / "src/lib.rs").read_text()
    cargo = (HERE / "Cargo.toml").read_text()

    checks = {
        "patch_rounds_mask_before_private_iterator": (
            "let rounded_to_floor = (input_mask_element).wrapping_add(rounding_mask);"
            in patch
            and "let rounded = rounded_to_floor.bitand(selection_mask);" in patch
            and "rounded >> (Scalar::BITS - precision)" in patch
        ),
        "patch_uses_private_iterator_values": (
            "SignedDecompositionIter::new(" in patch
            and "decomposed.value()" in patch
        ),
        "patch_applies_wrapped_floor_half": (
            "correction_term = (correction_term >> 1).wrapping_add(correction_term.bitand(msb));"
            in patch
        ),
        "centered_api_is_public": (
            "pub fn lwe_ciphertext_centered_binary_modulus_switch<" in modulus_switch_source
        ),
        "centered_subtracts_half_case": (
            "sum_half_mask_round_errors.wrapping_sub(half_case)" in modulus_switch_source
        ),
        "lazy_raw_parts_are_public": (
            "pub fn into_raw_parts(self)" in lazy_source
            and "pub fn from_raw_parts(" in lazy_source
        ),
        "stock_blind_rotate_accepts_trait": (
            "pub fn blind_rotate_assign<" in pbs_source
            and "msed_input: &impl ModulusSwitchedLweCiphertext<usize>" in pbs_source
        ),
        "private_iterator_constructor_confirmed": "pub(crate) fn new(" in iterator_source,
        "private_decompose_bit_trick_confirmed": (
            "fn decomposition_bit_trick" in iterator_source
            and "res.wrapping_sub(carry << base_log)" in iterator_source
        ),
        "public_decomposer_rebalances_first": (
            "self.init_decomposer_state(input)" in decomposer_source
        ),
        "tfhe_term_constructor_is_private": (
            "pub(crate) fn new(" in term_source and "pub fn value(&self) -> T" in term_source
        ),
        "port_uses_centered_raw_parts_adapter": (
            "lwe_ciphertext_centered_binary_modulus_switch(lwe_in, log_modulus)" in port
            and "centered.into_raw_parts()" in port
            and ".wrapping_add(half_case)" in port
            and ".wrapping_add(tie_bit)" in port
            and "LazyStandardModulusSwitchedLweCiphertext::from_raw_parts(" in port
        ),
        "port_transcribes_private_iterator": (
            "let residue = self.state & self.mod_b_mask;" in port
            and "((self.state as i64) >> self.base_log) as u64" in port
            and "residue.wrapping_sub(carry << self.base_log)" in port
        ),
        "port_rejects_non_native_ciphertext": (
            "if !lwe_in.ciphertext_modulus().is_native_modulus()" in port
        ),
        "port_pins_exact_tfhe_dependency": (
            'tfhe = { version = "=1.7.0", default-features = false }' in cargo
        ),
        "port_has_no_unsafe_block": "unsafe" not in port,
        "port_has_no_binary_target": not (HERE / "src/main.rs").exists()
        and "[[bin]]" not in cargo,
        "cargo_lock_intentionally_not_generated": not (HERE / "Cargo.lock").exists(),
        "cargo_target_absent": not (HERE / "target").exists(),
    }
    if not all(checks.values()):
        failed = sorted(name for name, passed in checks.items() if not passed)
        raise RuntimeError(f"source-fragment checks failed: {failed}")
    return checks


def report() -> dict[str, object]:
    pins = verify_source_pins()
    fragments = verify_source_fragments()
    adapter = exhaustive_adapter_summary()
    a44 = a44_adapter_summary()
    a44_tie = exhaustive_a44_tie_aggregate_summary()
    witness = modulus_switch_boundary_witness()
    decomposer = exhaustive_decomposer_summary()
    rounding = exhaustive_rounding_summary()
    return {
        "schema": "a98.head-start-exact-adapter-port.static.v1",
        "status": "STATIC_PORT_READY_COMPILE_DEFERRED_FOR_A97_TIMING_ISOLATION",
        "scope": {
            "source_and_integer_checks_only": True,
            "cargo_or_rustc_invoked": False,
            "rust_typechecked": False,
            "key_generation_or_fhe_invoked": False,
            "runtime_or_noise_measured": False,
            "composed_pfail_certified": False,
            "exact_id_integration_promoted": False,
        },
        "a44_contract": {
            "torus_bits": TORUS_BITS,
            "lwe_dimension_at_modulus_switch": A44_LWE_DIMENSION,
            "log_modulus": A44_LOG_MODULUS,
            "ks_base_log": A44_BASE_LOG,
            "ks_level_count": A44_LEVEL_COUNT,
            "ks_precision": A44_PRECISION,
        },
        "centered_raw_parts_adapter": {
            "small_word_exhaustive": adapter,
            "a44_shaped_diagnostics": a44,
            "a44_all_reachable_tie_aggregates": a44_tie,
            "boundary_witness": witness,
            "integer_geometry_verdict": "GO_EXACT",
            "compiled_fhe_verdict": "NOT_RUN",
        },
        "local_patch_decomposer": {
            "a44_full_state_exhaustive": decomposer,
            "rounding_and_correction_exhaustive": rounding,
            "integer_digit_stream_verdict": "GO_BITWISE_EXACT",
            "compiled_keyswitch_verdict": "NOT_RUN",
            "public_signed_decomposer_note": (
                "functionally equal mod q but not bitwise equal on 1820 states; A94 leaves its "
                "noise law conditional"
            ),
        },
        "provenance": pins,
        "source_fragment_checks": fragments,
        "next_gate_after_neighboring_timing_run": [
            "generate and pin Cargo.lock without modifying tfhe-rs sources",
            "cargo check and run only pure integer Rust tests first",
            "fresh-key paired local-port versus pinned-patch keyswitch and PBS boundary tests",
            "measure paired phase error, failures, and latency before any exact-ID promotion",
        ],
    }


def main() -> None:
    print(json.dumps(report(), indent=2, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
