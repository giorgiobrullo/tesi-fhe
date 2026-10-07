#!/usr/bin/env python3
"""Static A89 model for a Head Start / tfhe-rs 1.7 modulus-switch adapter.

This is deliberately a source-and-integer model.  It does not compile Rust, generate keys,
execute FHE, estimate runtime, or certify a composed noise/failure bound.
"""

from __future__ import annotations

import functools
import hashlib
import itertools
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


TORUS_BITS = 64
A44_SMALL_LWE_DIMENSION = 859
A44_GLWE_DIMENSION = 1
A44_POLYNOMIAL_SIZE = 2048
A44_KS_INPUT_LWE_DIMENSION = A44_GLWE_DIMENSION * A44_POLYNOMIAL_SIZE
A44_KS_OUTPUT_LWE_DIMENSION = A44_SMALL_LWE_DIMENSION
A44_MODULUS_SWITCH_LWE_DIMENSION = A44_SMALL_LWE_DIMENSION
A44_LOG_MODULUS = 12
A44_KS_BASE_LOG = 3
A44_KS_LEVEL_COUNT = 5
A44_KS_PRECISION = A44_KS_BASE_LOG * A44_KS_LEVEL_COUNT
A44_ROTATION_STEP = 1 << (TORUS_BITS - A44_LOG_MODULUS)
A44_HALF_CASE = A44_ROTATION_STEP // 2

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

REPO_SOURCE_PINS = {
    "tmp/pdfs/head-start.patch": (
        "d19b72f6257d3db93e3651d87779816be4f210f60bf274cea5799b50743368cc"
    ),
    "tmp/pdfs/head-start-2025-2012.txt": (
        "9de7adb52ff80808ee6892a1dd2caa4b316238426ba225b5fdf9ba453ee20972"
    ),
    "tmp/a88-head-start-score-shape-preflight/README.md": (
        "8ece3a8ca389be4c5545fca07186054f2e6e41c49ab246c1c10f3f8339b157e6"
    ),
    "tmp/u2-a62-tfhe-1_7-same-param-port/src/private_argmin.rs": (
        "4561a4d3a134ba603cef0b458a686e33cc251435c8c2e33b75e0410f8687010c"
    ),
}

TFHE_SOURCE_PINS = {
    "src/core_crypto/fft_impl/common.rs": (
        "85e2789e9e7bb931420dea5e951468b7db35ccfc9b9b28d0fe256fb1b362ab03"
    ),
    "src/core_crypto/algorithms/modulus_switch.rs": (
        "d6db1e94476fb89fea9c823242ef6be12f3908be426903e5ff05a6aa48aa1345"
    ),
    "src/core_crypto/entities/modulus_switched_lwe_ciphertext.rs": (
        "68b692b3e941b98a4a0290e67979733f82a0449e95856f7d1f821140159f562d"
    ),
    "src/core_crypto/algorithms/lwe_programmable_bootstrapping/fft64_pbs.rs": (
        "21c8009e0999c78401dea57a1d7bcbe91c47b80b231357b42eab9552a20abd71"
    ),
    "src/core_crypto/fft_impl/fft64/crypto/bootstrap.rs": (
        "2b789c4cc9959d01ee72a597c0de0316ac315ae3ede1ba128143f350c0b34b9b"
    ),
    "src/core_crypto/commons/math/decomposition/decomposer.rs": (
        "5aea64df5e3bd75d01e3dcc3ca62bd734f4c0b376850a1123900ac5ca59de7f2"
    ),
    "src/core_crypto/commons/math/decomposition/iter.rs": (
        "80731dfeb8f2de330c671d82403dce14437ecb951cb00e49232716a6c15cad57"
    ),
    "src/core_crypto/commons/numeric/unsigned.rs": (
        "e35efd169bd893b12a188461e9d68ac447a06b8fdce3adeacb0768d18397f584"
    ),
    "src/core_crypto/algorithms/lwe_keyswitch.rs": (
        "4e21ac924972ca8884257aa5bb778f672c07b4c35be542b51e86583bfcd45913"
    ),
}


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
    sign = 1 << (word_bits - 1)
    return value - (1 << word_bits) if value & sign else value


def rust_trunc_div2(value: int) -> int:
    """Rust signed integer division by two: truncate toward zero."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("value must be a plain int")
    return value // 2 if value >= 0 else -((-value) // 2)


def arithmetic_shr_unsigned(value: int, shift: int, word_bits: int) -> int:
    shift = _plain_int("shift", shift, 0, word_bits - 1)
    return wrap(to_signed(value, word_bits) >> shift, word_bits)


def _validate_modulus(word_bits: int, log_modulus: int, *, centered: bool) -> None:
    _plain_int("word_bits", word_bits, 2)
    upper = word_bits - 1 if centered else word_bits
    _plain_int("log_modulus", log_modulus, 1, upper)


def modulus_switch(value: int, word_bits: int, log_modulus: int) -> int:
    """Transcription of tfhe-rs 1.7 fft_impl::common::modulus_switch."""

    _validate_modulus(word_bits, log_modulus, centered=False)
    value = wrap(value, word_bits)
    if log_modulus == word_bits:
        return value
    shift = word_bits - log_modulus
    rounded = wrap(value + (1 << (shift - 1)), word_bits)
    return rounded >> shift


def lifted_round(value: int, word_bits: int, log_modulus: int) -> int:
    _validate_modulus(word_bits, log_modulus, centered=False)
    return wrap(
        modulus_switch(value, word_bits, log_modulus) << (word_bits - log_modulus),
        word_bits,
    )


def mask_round_error_signed(value: int, word_bits: int, log_modulus: int) -> int:
    """Signed d_i = lifted_round(a_i) - a_i used by tfhe-rs."""

    value = wrap(value, word_bits)
    return to_signed(lifted_round(value, word_bits, log_modulus) - value, word_bits)


@dataclass(frozen=True)
class CorrectionComponents:
    mask_round_error_sum: int
    halving_error_doubled_sum: int
    tfhe_pre_half_case: int
    tfhe_centered: int
    head_start: int
    adapter_tie_bit: int


def head_start_source_correction(
    mask: Sequence[int], word_bits: int, log_modulus: int
) -> int:
    """Body correction added by the pinned Head Start FFT patch.

    The patch accumulates a_i - round(a_i), takes its signed floor-half with an unsigned bit
    trick, and subtracts that result from b.  The return value is signed for readability.
    """

    _validate_modulus(word_bits, log_modulus, centered=True)
    correction_term = 0
    for value in mask:
        value = _plain_int("mask element", value, 0, word_mask(word_bits))
        correction_term = wrap(
            correction_term - mask_round_error_signed(value, word_bits, log_modulus),
            word_bits,
        )
    msb = 1 << (word_bits - 1)
    signed_floor_half = wrap(
        (correction_term >> 1) + (correction_term & msb), word_bits
    )
    return to_signed(-signed_floor_half, word_bits)


def correction_components(
    mask: Sequence[int], word_bits: int, log_modulus: int
) -> CorrectionComponents:
    """Transcribe tfhe-rs centered correction and relate it to Head Start."""

    _validate_modulus(word_bits, log_modulus, centered=True)
    half_sum_wrapped = 0
    halving_error_doubled_sum = 0
    round_error_sum = 0
    for value in mask:
        value = _plain_int("mask element", value, 0, word_mask(word_bits))
        error = mask_round_error_signed(value, word_bits, log_modulus)
        half_error = rust_trunc_div2(error)
        halving_error_doubled = 2 * half_error - error
        half_sum_wrapped = wrap(half_sum_wrapped + half_error, word_bits)
        halving_error_doubled_sum += halving_error_doubled
        round_error_sum += error

    summed_halving_error = rust_trunc_div2(halving_error_doubled_sum)
    pre_half_case = to_signed(
        half_sum_wrapped - wrap(summed_halving_error, word_bits), word_bits
    )
    half_case = 1 << (word_bits - log_modulus - 1)
    centered = to_signed(pre_half_case - half_case, word_bits)
    correction_term = wrap(-round_error_sum, word_bits)
    msb = 1 << (word_bits - 1)
    signed_floor_half = wrap(
        (correction_term >> 1) + (correction_term & msb), word_bits
    )
    head_start = to_signed(-signed_floor_half, word_bits)
    tie_bit = int(
        halving_error_doubled_sum < 0 and abs(halving_error_doubled_sum) % 2 == 1
    )
    return CorrectionComponents(
        mask_round_error_sum=round_error_sum,
        halving_error_doubled_sum=halving_error_doubled_sum,
        tfhe_pre_half_case=pre_half_case,
        tfhe_centered=centered,
        head_start=head_start,
        adapter_tie_bit=tie_bit,
    )


def exact_adapter_correction(
    mask: Sequence[int], word_bits: int, log_modulus: int
) -> int:
    """Correction obtained from centered raw parts + half_case + public tie bit."""

    components = correction_components(mask, word_bits, log_modulus)
    half_case = 1 << (word_bits - log_modulus - 1)
    return to_signed(
        components.tfhe_centered + half_case + components.adapter_tie_bit,
        word_bits,
    )


def switched_body_degree(
    body: int,
    mask: Sequence[int],
    word_bits: int,
    log_modulus: int,
    mode: str,
) -> int:
    body = _plain_int("body", body, 0, word_mask(word_bits))
    components = correction_components(mask, word_bits, log_modulus)
    corrections = {
        "head_start": components.head_start,
        "tfhe_centered": components.tfhe_centered,
        "tfhe_centered_without_half_case": components.tfhe_pre_half_case,
        "exact_adapter": exact_adapter_correction(mask, word_bits, log_modulus),
    }
    if mode not in corrections:
        raise ValueError(f"unsupported correction mode: {mode}")
    return modulus_switch(
        wrap(body + corrections[mode], word_bits), word_bits, log_modulus
    )


def switched_phase_degree(
    body: int,
    mask: Sequence[int],
    secret_bits: Sequence[int],
    word_bits: int,
    log_modulus: int,
    mode: str,
) -> int:
    if len(mask) != len(secret_bits):
        raise ValueError("mask and secret_bits must have the same length")
    if any(bit not in (0, 1) or isinstance(bit, bool) for bit in secret_bits):
        raise ValueError("secret_bits must contain plain integer zeroes or ones")
    target_mask = (1 << log_modulus) - 1
    mask_degree = sum(
        modulus_switch(value, word_bits, log_modulus) * bit
        for value, bit in zip(mask, secret_bits)
    )
    return (
        switched_body_degree(body, mask, word_bits, log_modulus, mode) - mask_degree
    ) & target_mask


def head_start_cd_four_bit_accumulator() -> tuple[int, ...]:
    """Pinned generate_cd_acc four-bit body, including negate/rotate postprocessing."""

    block_values = (61, 63, 1, 3) * 4
    box_size = A44_POLYNOMIAL_SIZE // 16
    coefficients = [
        value * (1 << 58) for value in block_values for _ in range(box_size)
    ]
    half_box = box_size // 2
    modulus = 1 << TORUS_BITS
    coefficients[:half_box] = [(-value) % modulus for value in coefficients[:half_box]]
    coefficients = coefficients[half_box:] + coefficients[:half_box]
    return tuple(coefficients)


def _source_decomposition_terms(
    initial_state: int, word_bits: int, base_log: int, level_count: int
) -> tuple[tuple[int, int], ...]:
    """Transcription of SignedDecompositionIter::new + decompose_one_level."""

    _plain_int("word_bits", word_bits, 2)
    _plain_int("base_log", base_log, 1, word_bits - 1)
    _plain_int("level_count", level_count, 1)
    if base_log * level_count >= word_bits:
        raise ValueError("decomposition precision must be smaller than word_bits")
    state = _plain_int("initial_state", initial_state, 0, word_mask(word_bits))
    mod_b_mask = (1 << base_log) - 1
    terms = []
    for current_level in range(level_count, 0, -1):
        residue = state & mod_b_mask
        state = arithmetic_shr_unsigned(state, base_log, word_bits)
        carry = ((wrap(residue - 1, word_bits) | state) & residue) >> (base_log - 1)
        state = wrap(state + carry, word_bits)
        digit = to_signed(residue - (carry << base_log), word_bits)
        terms.append((current_level, digit))
    return tuple(terms)


def local_public_digit_terms(
    initial_state: int, word_bits: int, base_log: int, level_count: int
) -> tuple[tuple[int, int], ...]:
    """Tiny external iterator using only public integer operations.

    Its branch is the prose condition above decompose_one_level in the pinned source, independent
    of the source's bit-trick transcription used by _source_decomposition_terms.
    """

    _plain_int("word_bits", word_bits, 2)
    _plain_int("base_log", base_log, 1, word_bits - 1)
    _plain_int("level_count", level_count, 1)
    if base_log * level_count >= word_bits:
        raise ValueError("decomposition precision must be smaller than word_bits")
    state = _plain_int("initial_state", initial_state, 0, word_mask(word_bits))
    basis = 1 << base_log
    basis_mask = basis - 1
    half_basis = basis // 2
    terms = []
    for current_level in range(level_count, 0, -1):
        residue = state & basis_mask
        next_state = arithmetic_shr_unsigned(state, base_log, word_bits)
        next_residue = next_state & basis_mask
        carry = int(
            residue > half_basis
            or (residue == half_basis and next_residue >= half_basis)
        )
        state = wrap(next_state + carry, word_bits)
        terms.append((current_level, residue - carry * basis))
    return tuple(terms)


def public_init_decomposer_state(
    value: int, word_bits: int, base_log: int, level_count: int
) -> int:
    """Transcription of SignedDecomposer::init_decomposer_state."""

    value = _plain_int("value", value, 0, word_mask(word_bits))
    precision = base_log * level_count
    if not 0 < precision < word_bits:
        raise ValueError("decomposition precision must be in 1..word_bits-1")
    non_rep_bits = word_bits - precision
    state = value >> (non_rep_bits - 1)
    rounding_bit = state & 1
    state = (state + 1) >> 1
    state &= (1 << precision) - 1
    shifted_random = rounding_bit << (precision - 1)
    need_balance = ((wrap(state - 1, word_bits) | shifted_random) & state) >> (
        precision - 1
    )
    return wrap(state - (need_balance << precision), word_bits)


def patch_ks_terms_from_rounded(
    rounded: int,
    word_bits: int = TORUS_BITS,
    base_log: int = A44_KS_BASE_LOG,
    level_count: int = A44_KS_LEVEL_COUNT,
) -> tuple[tuple[int, int], ...]:
    precision = base_log * level_count
    rounded = _plain_int("rounded", rounded, 0, word_mask(word_bits))
    quantum = 1 << (word_bits - precision)
    if rounded % quantum:
        raise ValueError(
            "rounded is not exactly representable at the requested precision"
        )
    return _source_decomposition_terms(
        rounded >> (word_bits - precision), word_bits, base_log, level_count
    )


def public_ks_terms_from_rounded(
    rounded: int,
    word_bits: int = TORUS_BITS,
    base_log: int = A44_KS_BASE_LOG,
    level_count: int = A44_KS_LEVEL_COUNT,
) -> tuple[tuple[int, int], ...]:
    rounded = _plain_int("rounded", rounded, 0, word_mask(word_bits))
    state = public_init_decomposer_state(rounded, word_bits, base_log, level_count)
    return _source_decomposition_terms(state, word_bits, base_log, level_count)


def local_patch_ks_terms_from_rounded(
    rounded: int,
    word_bits: int = TORUS_BITS,
    base_log: int = A44_KS_BASE_LOG,
    level_count: int = A44_KS_LEVEL_COUNT,
) -> tuple[tuple[int, int], ...]:
    precision = base_log * level_count
    rounded = _plain_int("rounded", rounded, 0, word_mask(word_bits))
    quantum = 1 << (word_bits - precision)
    if rounded % quantum:
        raise ValueError(
            "rounded is not exactly representable at the requested precision"
        )
    return local_public_digit_terms(
        rounded >> (word_bits - precision), word_bits, base_log, level_count
    )


def recompose_terms(
    terms: Iterable[tuple[int, int]],
    word_bits: int,
    base_log: int,
) -> int:
    result = 0
    for level, digit in terms:
        _plain_int("level", level, 1)
        if isinstance(digit, bool) or not isinstance(digit, int):
            raise ValueError("digit must be a plain int")
        shift = word_bits - base_log * level
        if shift < 0:
            raise ValueError("term level exceeds word precision")
        result = wrap(result + digit * (1 << shift), word_bits)
    return result


def locate_tfhe_source() -> Path:
    registry = Path.home() / ".cargo/registry/src"
    candidates = sorted(path for path in registry.glob("*/tfhe-1.7.0") if path.is_dir())
    complete = [
        path
        for path in candidates
        if all((path / relative).is_file() for relative in TFHE_SOURCE_PINS)
    ]
    if len(complete) != 1:
        raise RuntimeError(
            f"expected exactly one complete tfhe-1.7.0 registry source, found {len(complete)}"
        )
    return complete[0]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_source_pins() -> list[dict[str, str]]:
    rows = []
    for relative, expected in REPO_SOURCE_PINS.items():
        path = ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"missing source pin: {relative}")
        actual = sha256_file(path)
        if actual != expected:
            raise RuntimeError(f"source pin drift: {relative}: {actual} != {expected}")
        rows.append({"path": relative, "sha256": actual})

    tfhe_root = locate_tfhe_source()
    for relative, expected in TFHE_SOURCE_PINS.items():
        path = tfhe_root / relative
        actual = sha256_file(path)
        if actual != expected:
            raise RuntimeError(
                f"tfhe source pin drift: {relative}: {actual} != {expected}"
            )
        rows.append({"path": f"cargo-registry/tfhe-1.7.0/{relative}", "sha256": actual})
    return rows


@functools.lru_cache(maxsize=1)
def exhaustive_small_word_summary() -> dict[str, object]:
    correction_cases = 0
    body_cases = 0
    tie_zero_seen = False
    tie_one_seen = False
    direct_degree_differences: set[int] = set()
    for word_bits in range(5, 8):
        modulus = 1 << word_bits
        for log_modulus in range(2, word_bits):
            half_case = 1 << (word_bits - log_modulus - 1)
            for first, second in itertools.product(range(modulus), repeat=2):
                mask = (first, second)
                components = correction_components(mask, word_bits, log_modulus)
                # With two elements and log_modulus >= 2, the mathematical sum cannot cross the
                # signed word boundary.  The Head Start unsigned trick therefore equals ceil(D/2).
                expected_head = -((-components.mask_round_error_sum) // 2)
                if components.head_start != expected_head:
                    raise AssertionError("Head Start aggregate-half identity failed")
                if components.head_start != (
                    components.tfhe_pre_half_case + components.adapter_tie_bit
                ):
                    raise AssertionError(
                        "centered/Head Start correction relation failed"
                    )
                if components.tfhe_centered != (
                    components.tfhe_pre_half_case - half_case
                ):
                    raise AssertionError("half-case relation failed")
                if components.adapter_tie_bit == 0:
                    tie_zero_seen = True
                elif components.adapter_tie_bit == 1:
                    tie_one_seen = True
                else:
                    raise AssertionError("tie bit escaped {0,1}")
                correction_cases += 1

            for mask_element, body in itertools.product(range(modulus), repeat=2):
                mask = (mask_element,)
                components = correction_components(mask, word_bits, log_modulus)
                head = modulus_switch(
                    wrap(body + components.head_start, word_bits),
                    word_bits,
                    log_modulus,
                )
                centered = modulus_switch(
                    wrap(body + components.tfhe_centered, word_bits),
                    word_bits,
                    log_modulus,
                )
                adapted_correction = to_signed(
                    components.tfhe_pre_half_case + components.adapter_tie_bit,
                    word_bits,
                )
                adapted = modulus_switch(
                    wrap(body + adapted_correction, word_bits),
                    word_bits,
                    log_modulus,
                )
                if adapted != head:
                    raise AssertionError("exact adapter degree mismatch")
                direct_degree_differences.add(
                    (head - centered) & ((1 << log_modulus) - 1)
                )
                body_cases += 1

    return {
        "word_bits": [5, 6, 7],
        "log_modulus_min": 2,
        "mask_dimension_for_correction_relation": 2,
        "correction_cases": correction_cases,
        "single_mask_body_cases": body_cases,
        "adapter_mismatches": 0,
        "tie_zero_seen": tie_zero_seen,
        "tie_one_seen": tie_one_seen,
        "direct_centered_modular_degree_differences": sorted(direct_degree_differences),
    }


@functools.lru_cache(maxsize=1)
def a44_fuzz_summary() -> dict[str, object]:
    rng = random.Random(0xA89)
    vectors = 64
    tie_ones = 0
    for _ in range(vectors):
        mask = [
            rng.getrandbits(TORUS_BITS) for _ in range(A44_MODULUS_SWITCH_LWE_DIMENSION)
        ]
        components = correction_components(mask, TORUS_BITS, A44_LOG_MODULUS)
        if exact_adapter_correction(mask, TORUS_BITS, A44_LOG_MODULUS) != (
            components.head_start
        ):
            raise AssertionError("A44 adapter correction mismatch")
        tie_ones += components.adapter_tie_bit
    return {
        "seed_hex": "0xA89",
        "vectors": vectors,
        "mask_dimension": A44_MODULUS_SWITCH_LWE_DIMENSION,
        "adapter_mismatches": 0,
        "tie_bit_one_vectors": tie_ones,
        "status": "diagnostic_fuzz_not_a_proof_or_fhe_attestation",
    }


@functools.lru_cache(maxsize=1)
def ks_exhaustive_summary() -> dict[str, object]:
    precision_modulus = 1 << A44_KS_PRECISION
    quantum = 1 << (TORUS_BITS - A44_KS_PRECISION)
    mismatch_states = []
    difference_shapes: set[tuple[int, ...]] = set()
    recomposition_mismatches = 0
    local_iterator_mismatches = 0
    for truncated in range(precision_modulus):
        rounded = truncated << (TORUS_BITS - A44_KS_PRECISION)
        patch_terms = patch_ks_terms_from_rounded(rounded)
        public_terms = public_ks_terms_from_rounded(rounded)
        local_terms = local_patch_ks_terms_from_rounded(rounded)
        if local_terms != patch_terms:
            local_iterator_mismatches += 1
        if public_terms != patch_terms:
            mismatch_states.append(truncated)
            difference_shapes.add(
                tuple(
                    patch_digit - public_digit
                    for (_, patch_digit), (_, public_digit) in zip(
                        patch_terms, public_terms
                    )
                )
            )
        if recompose_terms(patch_terms, TORUS_BITS, A44_KS_BASE_LOG) != rounded:
            recomposition_mismatches += 1
        if recompose_terms(public_terms, TORUS_BITS, A44_KS_BASE_LOG) != rounded:
            recomposition_mismatches += 1
        if rounded % quantum:
            raise AssertionError("unreachable nonrepresentable rounded value")

    contiguous = mismatch_states == list(
        range(mismatch_states[0], mismatch_states[-1] + 1)
    )
    basis = 1 << A44_KS_BASE_LOG
    return {
        "states_exhausted": precision_modulus,
        "patch_vs_public_digit_stream_mismatches": len(mismatch_states),
        "first_mismatch_state": mismatch_states[0],
        "last_mismatch_state": mismatch_states[-1],
        "mismatch_states_contiguous": contiguous,
        "emitted_levels_in_order": [5, 4, 3, 2, 1],
        "patch_minus_public_digit_shapes": [
            list(shape) for shape in sorted(difference_shapes)
        ],
        "exact_difference": ("+B at level 1 only: +4 instead of -4, where B=8"),
        "truncated_ring_recomposition_delta": basis**A44_KS_LEVEL_COUNT,
        "truncated_ring_modulus": precision_modulus,
        "full_torus_recomposition_delta": 1 << TORUS_BITS,
        "functional_recomposition_mismatches_mod_2_pow_64": recomposition_mismatches,
        "local_public_integer_iterator_mismatches": local_iterator_mismatches,
        "digit_stream_source_equivalent": False,
        "plaintext_functionally_equivalent_mod_q": True,
        "noise_equivalent": False,
        "noise_delta_when_mismatching": (
            "patch minus public KS phase includes -B times the level-1 KSK encryption error "
            "for each mismatching mask coefficient; no bound composed here"
        ),
    }


def a44_direct_drop_in_counterexample() -> dict[str, object]:
    step = A44_ROTATION_STEP
    mask = (step - 1,) + (0,) * (A44_MODULUS_SWITCH_LWE_DIMENSION - 1)
    body_same = 63 * step
    body_cross = 63 * step + A44_HALF_CASE - 1
    secret = (0,) * A44_MODULUS_SWITCH_LWE_DIMENSION
    same_head = switched_phase_degree(
        body_same, mask, secret, TORUS_BITS, A44_LOG_MODULUS, "head_start"
    )
    same_centered = switched_phase_degree(
        body_same, mask, secret, TORUS_BITS, A44_LOG_MODULUS, "tfhe_centered"
    )
    cross_head = switched_phase_degree(
        body_cross, mask, secret, TORUS_BITS, A44_LOG_MODULUS, "head_start"
    )
    cross_centered = switched_phase_degree(
        body_cross, mask, secret, TORUS_BITS, A44_LOG_MODULUS, "tfhe_centered"
    )
    accumulator = head_start_cd_four_bit_accumulator()
    return {
        "mask_dimension": len(mask),
        "mask_first_element": mask[0],
        "mask_remaining_elements": "858 zeroes",
        "secret_bits": "859 zeroes",
        "mask_round_error": mask_round_error_signed(
            mask[0], TORUS_BITS, A44_LOG_MODULUS
        ),
        "head_start_correction": correction_components(
            mask, TORUS_BITS, A44_LOG_MODULUS
        ).head_start,
        "tfhe_pre_half_case_correction": correction_components(
            mask, TORUS_BITS, A44_LOG_MODULUS
        ).tfhe_pre_half_case,
        "body_with_zero_degree_gap": body_same,
        "zero_gap_degrees": {"head_start": same_head, "tfhe_centered": same_centered},
        "body_crossing_real_cd_lut_boundary": body_cross,
        "boundary_degrees": {
            "head_start": cross_head,
            "tfhe_centered": cross_centered,
        },
        "head_start_cd_accumulator_coefficients_at_boundary": {
            str(cross_centered): accumulator[cross_centered],
            str(cross_head): accumulator[cross_head],
        },
        "fixed_integer_lut_rotation_can_match_both_bodies": False,
    }


def a44_counterexample_inputs() -> tuple[tuple[int, ...], tuple[int, ...]]:
    mask = (A44_ROTATION_STEP - 1,) + (0,) * (A44_MODULUS_SWITCH_LWE_DIMENSION - 1)
    secret = (0,) * A44_MODULUS_SWITCH_LWE_DIMENSION
    return mask, secret


def report() -> dict[str, object]:
    pins = verify_source_pins()
    small = exhaustive_small_word_summary()
    fuzz = a44_fuzz_summary()
    ks = ks_exhaustive_summary()
    witness = a44_direct_drop_in_counterexample()
    a44_aggregate_bound = A44_MODULUS_SWITCH_LWE_DIMENSION * A44_HALF_CASE
    return {
        "schema": "a89.centered-ms-adapter-static.v1",
        "status": "GO_EXACT_ADAPTER_PORT_DIRECT_DROP_IN_NO_GO_PUBLIC_KS_DECOMPOSER_NO_GO",
        "scope": {
            "static_source_and_integer_model_only": True,
            "cargo_or_rustc_run": False,
            "fhe_or_key_generation_run": False,
            "runtime_measured": False,
            "composed_noise_or_pfail_certified": False,
        },
        "a44_contract": {
            "torus_bits": TORUS_BITS,
            "small_lwe_and_modulus_switch_dimension": A44_SMALL_LWE_DIMENSION,
            "glwe_dimension": A44_GLWE_DIMENSION,
            "polynomial_size": A44_POLYNOMIAL_SIZE,
            "corrected_ks_input_lwe_dimension": A44_KS_INPUT_LWE_DIMENSION,
            "corrected_ks_output_lwe_dimension": A44_KS_OUTPUT_LWE_DIMENSION,
            "rotation_modulus_log": A44_LOG_MODULUS,
            "rotation_step": A44_ROTATION_STEP,
            "half_case": A44_HALF_CASE,
            "ks_base_log": A44_KS_BASE_LOG,
            "ks_level_count": A44_KS_LEVEL_COUNT,
            "ks_precision": A44_KS_PRECISION,
            "worst_case_absolute_mask_residual_sum_bound": a44_aggregate_bound,
            "signed_i64_accumulation_safe": a44_aggregate_bound < (1 << 63),
        },
        "modulus_switch_relation": {
            "definitions": {
                "d_i": "lift(round(a_i))-a_i interpreted as signed",
                "D": "sum_i d_i",
                "H": "count(negative odd d_i)-count(positive odd d_i)",
                "head_start_pre_switch_body_correction": "ceil(D/2)",
                "tfhe_pre_half_case_correction": (
                    "ceil(D/2), except floor(D/2) when H is negative and odd"
                ),
                "exact_adapter_tie_bit": "1 iff H is negative and odd, else 0",
                "tfhe_centered_correction": "tfhe_pre_half_case-half_case",
            },
            "small_word_exhaustive": small,
            "a44_shaped_diagnostic_fuzz": fuzz,
            "direct_same_lut_drop_in_exact": False,
            "fixed_integer_lut_rotation_repairs_all_inputs": False,
            "counterexample": witness,
            "exact_source_adapter_recipe": [
                "call public lwe_ciphertext_centered_binary_modulus_switch",
                "take public into_raw_parts",
                "add back public half_case and the public-mask tie bit",
                "rebuild public LazyStandardModulusSwitchedLweCiphertext::from_raw_parts",
                "pass it to stock public generic blind_rotate_assign",
            ],
            "adapter_matches_head_start_mask_and_body_degrees": True,
            "head_start_fft_file_edit_appears_avoidable": True,
            "stock_body_first_vs_patch_body_last_ideal_rotation_commutes": True,
            "fft_ciphertext_bit_identity_or_noise_equivalence_attested": False,
            "adapter_typechecked": False,
        },
        "corrected_keyswitch": ks,
        "verdict": {
            "direct_centered_function_with_unchanged_head_start_lut": "NO_GO_EXACT",
            "centered_raw_parts_plus_half_case_and_tie_adapter": "GO_TO_ISOLATED_TYPECHECK",
            "public_signed_decomposer_as_patch_iterator_replacement": "NO_GO_SOURCE_AND_NOISE",
            "tiny_local_public_integer_digit_iterator": "GO_TO_ISOLATED_TYPECHECK",
            "corrected_ks_still_separate_from_modulus_switch_adapter": True,
            "promotion_to_exact_id_or_speed_claim": False,
            "next_gate": (
                "isolated Rust typecheck, then exhaustive fresh-key FHE boundary test and "
                "paired noise/runtime measurement"
            ),
        },
        "source_pins": pins,
    }


def main() -> None:
    print(json.dumps(report(), indent=2, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
