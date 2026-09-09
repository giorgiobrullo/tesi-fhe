#!/usr/bin/env python3
"""Static model of an A34 exact-ID response made of two nibble LWEs.

The experimental A34 two-nibble scan already ends in a low- and a high-digit
reduction.  This protocol variant returns those digits directly at the standard
p=16 scale (Delta=2^59) and lets the client reconstruct ``low + 16 * high``.
There is no final encrypted weighted sum at the narrower code scale.

This module checks clear semantics, torus rounding cells, projected wire size,
and structural BR/KS/output-marginal counts.  Its probability arithmetic is
explicitly conditional: it does not transfer TFHE-rs's nominal per-PBS p-fail
to the custom raw-core circuit and is not an end-to-end certificate.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass
from typing import Optional, Sequence, Union

if __package__:
    from .a34_two_nibble_scan_output_model import (
        BOOL_DELTA_LOG,
        MAX_GALLERY_SIZE,
        P16,
        PrimitiveCounts,
        a34_two_nibble_replacement_counts,
        a34_two_nibble_stage_counts,
        evaluate_a34_two_nibble,
    )
else:  # Direct ``python benchmark/<script>.py`` invocation.
    from a34_two_nibble_scan_output_model import (
        BOOL_DELTA_LOG,
        MAX_GALLERY_SIZE,
        P16,
        PrimitiveCounts,
        a34_two_nibble_replacement_counts,
        a34_two_nibble_stage_counts,
        evaluate_a34_two_nibble,
    )


TORUS_BITS = 64
TORUS_MODULUS = 1 << TORUS_BITS
NIBBLE_HALF_SLOT_MARGIN = 1 << (BOOL_DELTA_LOG - 1)
LEGACY_CODE_DELTA_LOG = 56
LEGACY_CODE_HALF_SLOT_MARGIN = 1 << (LEGACY_CODE_DELTA_LOG - 1)
NOMINAL_LOG2_P_FAIL = -71.625

# Pinned by the current TFHE-rs parameter geometry and exact-ID E2E evidence:
# output LWE dimension 2048, hence 2049 u64 coefficients.  The existing binary
# format writes one u64 header-length prefix and eight u64 header words.
OUTPUT_LWE_SIZE_WORDS = 2_049
OUTPUT_HEADER_WORDS = 8
OUTPUT_HEADER_LENGTH_PREFIX_WORDS = 1
OUTPUT_CIPHERTEXTS = 2
WORD_BYTES = 8

A33_N127_COUNTS = PrimitiveCounts(
    blind_rotations=4_273,
    key_switches=3_892,
    output_marginals=4_908,
)


class ProtocolDecodeError(ValueError):
    """The decrypted response does not satisfy the public exact-ID contract."""


@dataclass(frozen=True)
class ExactIdResult:
    gallery_size: int
    low_nibble: int
    high_nibble: int
    code: int
    authorized: bool
    index: Optional[int]


@dataclass(frozen=True)
class TwoLweClearTrace:
    gallery_size: int
    candidates: tuple[bool, ...]
    low_nibble: int
    high_nibble: int
    output_scale_logs: tuple[int, int]
    code: int
    authorized: bool
    index: Optional[int]


@dataclass(frozen=True)
class WireProjection:
    status: str
    output_mode_implies_fixed_ciphertext_count: bool
    header_length_prefix_words: int
    header_words: int
    lwe_size_words: int
    ciphertext_payload_words: int
    total_words: int
    word_bytes: int
    ciphertext_order: str
    current_single_lwe_result_bytes: int
    proposed_two_lwe_result_bytes: int
    additional_bytes: int
    size_ratio: float


@dataclass(frozen=True)
class DecodeGeometry:
    nibble_delta_log: int
    nibble_adjacent_spacing: int
    nibble_half_slot_margin: int
    legacy_code_delta_log: int
    legacy_code_half_slot_margin: int
    absolute_margin_ratio: int


@dataclass(frozen=True)
class ConditionalFailureAccounting:
    status: str
    nominal_log2_p_fail: float
    nominal_per_output_probability: float
    terminal_output_marginals: int
    terminal_outputs_are_statistically_independent: bool
    conditional_terminal_union_upper: float
    conditional_terminal_union_log2: float
    stage_output_marginals: int
    conditional_stage_union_upper: float
    conditional_stage_union_log2: float
    whole_blind_rotations: int
    conditional_whole_blind_rotation_union_upper: float
    conditional_whole_blind_rotation_union_log2: float
    whole_key_switches_structural: int
    key_switches_added_as_independent_failure_events: bool
    whole_output_marginals: int
    conditional_whole_union_upper: float
    conditional_whole_union_log2: float
    separate_unbootstrapped_final_sum_term: bool
    final_decode_term_status: str
    terminal_source: str
    end_to_end_numeric_upper: Optional[float]
    assumptions_needed: tuple[str, ...]
    obligations_still_open: tuple[str, ...]


@dataclass(frozen=True)
class ValidationSummary:
    gallery_sizes_checked: int
    reject_cases: int
    singleton_cases: int
    tied_suffix_cases: int
    code_bijection_cases: int
    in_cell_noise_cases: int
    total_cases: int


def _validate_gallery_size(gallery_size: int) -> None:
    if type(gallery_size) is not int or not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError("gallery size must be an integer in 1..128")


def _validate_nibble(value: int, label: str) -> None:
    if type(value) is not int or not 0 <= value < P16:
        raise ProtocolDecodeError("{} must be an integer in 0..15".format(label))


def split_exact_code(code: int, gallery_size: int) -> tuple[int, int]:
    """Map reject/one-based exact ID into its unique base-16 pair."""
    _validate_gallery_size(gallery_size)
    if type(code) is not int or not 0 <= code <= gallery_size:
        raise ValueError("exact-ID code must be an integer in 0..gallery_size")
    return code & 0xF, code >> 4


def combine_exact_digits(
    low_nibble: int, high_nibble: int, gallery_size: int
) -> ExactIdResult:
    """Validate two clear nibbles and reconstruct the existing exact-ID result."""
    _validate_gallery_size(gallery_size)
    _validate_nibble(low_nibble, "low nibble")
    _validate_nibble(high_nibble, "high nibble")
    code = low_nibble + P16 * high_nibble
    if code > gallery_size:
        raise ProtocolDecodeError(
            "decoded exact-ID code {} exceeds gallery size {}".format(
                code, gallery_size
            )
        )
    return ExactIdResult(
        gallery_size=gallery_size,
        low_nibble=low_nibble,
        high_nibble=high_nibble,
        code=code,
        authorized=code != 0,
        index=None if code == 0 else code - 1,
    )


def encode_nibble_phase(nibble: int) -> int:
    """Encode one independent p=16 slot at Delta=2^59 on the 64-bit torus."""
    _validate_nibble(nibble, "nibble")
    return nibble << BOOL_DELTA_LOG


def add_signed_torus_error(encoded_phase: int, signed_error: int) -> int:
    if type(encoded_phase) is not int or not 0 <= encoded_phase < TORUS_MODULUS:
        raise ValueError("encoded phase must be a u64")
    if type(signed_error) is not int:
        raise ValueError("signed torus error must be an integer")
    return (encoded_phase + signed_error) % TORUS_MODULUS


def decode_nibble_phase(plaintext_phase: int) -> int:
    """Round a torus plaintext to a nibble, including negative noise around zero."""
    if type(plaintext_phase) is not int or not 0 <= plaintext_phase < TORUS_MODULUS:
        raise ProtocolDecodeError("decrypted phase must be a u64")
    rounded = (plaintext_phase + NIBBLE_HALF_SLOT_MARGIN) >> BOOL_DELTA_LOG
    # A small negative error around encoded zero is represented close to 2^64.
    if rounded == (1 << (TORUS_BITS - BOOL_DELTA_LOG)):
        rounded = 0
    if not 0 <= rounded < P16:
        raise ProtocolDecodeError(
            "decrypted phase rounded outside the independent p=16 slots"
        )
    return rounded


def decode_two_lwe_phases(
    low_plaintext_phase: int, high_plaintext_phase: int, gallery_size: int
) -> ExactIdResult:
    """Client-side decryption contract after the two LWE plaintexts are obtained."""
    return combine_exact_digits(
        decode_nibble_phase(low_plaintext_phase),
        decode_nibble_phase(high_plaintext_phase),
        gallery_size,
    )


def evaluate_a34_two_lwe(
    candidates: Sequence[Union[bool, int]],
) -> TwoLweClearTrace:
    """Interpret the A34 two-nibble terminal reductions as two direct outputs."""
    base = evaluate_a34_two_nibble(candidates)
    low_nibble = base.low_reduction.nibble
    high_nibble = base.high_reduction.nibble
    result = combine_exact_digits(low_nibble, high_nibble, base.gallery_size)
    if result.code != base.code:
        raise AssertionError("two-LWE reconstruction drifted from the A34 clear model")
    return TwoLweClearTrace(
        gallery_size=base.gallery_size,
        candidates=base.candidates,
        low_nibble=low_nibble,
        high_nibble=high_nibble,
        output_scale_logs=(BOOL_DELTA_LOG, BOOL_DELTA_LOG),
        code=result.code,
        authorized=result.authorized,
        index=result.index,
    )


def projected_wire_layout(
    *,
    lwe_size_words: int = OUTPUT_LWE_SIZE_WORDS,
    header_words: int = OUTPUT_HEADER_WORDS,
) -> WireProjection:
    """Project raw response bytes using the current exact-ID container geometry.

    A new output-mode value must bind the body to exactly two equal-size LWEs, so
    the existing eight-word header need not gain a separate ciphertext-count word.
    This is a format projection, not a claim that the service implements it.
    """
    if type(lwe_size_words) is not int or lwe_size_words <= 0:
        raise ValueError("LWE size must be a positive word count")
    if type(header_words) is not int or header_words <= 0:
        raise ValueError("header size must be a positive word count")
    shared_words = OUTPUT_HEADER_LENGTH_PREFIX_WORDS + header_words
    payload_words = OUTPUT_CIPHERTEXTS * lwe_size_words
    total_words = shared_words + payload_words
    current_bytes = WORD_BYTES * (shared_words + lwe_size_words)
    proposed_bytes = WORD_BYTES * total_words
    return WireProjection(
        status="projected_from_current_raw_u64_container_not_implemented",
        output_mode_implies_fixed_ciphertext_count=True,
        header_length_prefix_words=OUTPUT_HEADER_LENGTH_PREFIX_WORDS,
        header_words=header_words,
        lwe_size_words=lwe_size_words,
        ciphertext_payload_words=payload_words,
        total_words=total_words,
        word_bytes=WORD_BYTES,
        ciphertext_order="low_nibble_then_high_nibble",
        current_single_lwe_result_bytes=current_bytes,
        proposed_two_lwe_result_bytes=proposed_bytes,
        additional_bytes=proposed_bytes - current_bytes,
        size_ratio=proposed_bytes / current_bytes,
    )


def decode_geometry() -> DecodeGeometry:
    return DecodeGeometry(
        nibble_delta_log=BOOL_DELTA_LOG,
        nibble_adjacent_spacing=1 << BOOL_DELTA_LOG,
        nibble_half_slot_margin=NIBBLE_HALF_SLOT_MARGIN,
        legacy_code_delta_log=LEGACY_CODE_DELTA_LOG,
        legacy_code_half_slot_margin=LEGACY_CODE_HALF_SLOT_MARGIN,
        absolute_margin_ratio=(NIBBLE_HALF_SLOT_MARGIN // LEGACY_CODE_HALF_SLOT_MARGIN),
    )


def _conditional_union(event_count: int, log2_p_fail: float) -> tuple[float, float]:
    if event_count <= 0:
        raise ValueError("event count must be positive")
    if not math.isfinite(log2_p_fail) or log2_p_fail > 0.0:
        raise ValueError("nominal log2 p-fail must be finite and non-positive")
    upper = min(1.0, event_count * (2.0**log2_p_fail))
    return upper, math.log2(upper) if upper else float("-inf")


def conditional_failure_accounting(
    gallery_size: int, nominal_log2_p_fail: float = NOMINAL_LOG2_P_FAIL
) -> ConditionalFailureAccounting:
    """Compute conditional arithmetic without promoting it to a certificate."""
    _validate_gallery_size(gallery_size)
    counts = a34_two_nibble_replacement_counts(gallery_size)
    stage = a34_two_nibble_stage_counts(gallery_size)
    terminal_upper, terminal_log2 = _conditional_union(2, nominal_log2_p_fail)
    stage_upper, stage_log2 = _conditional_union(
        stage.scan_output_marginals, nominal_log2_p_fail
    )
    whole_br_upper, whole_br_log2 = _conditional_union(
        counts.blind_rotations, nominal_log2_p_fail
    )
    whole_upper, whole_log2 = _conditional_union(
        counts.output_marginals, nominal_log2_p_fail
    )
    groups = (gallery_size + 2) // 3
    terminal_source = (
        "two_correlated_sample_extractions_from_the_selector_rotation"
        if groups == 1
        else "two_distinct_terminal_p16_identity_blind_rotations"
    )
    return ConditionalFailureAccounting(
        status=("narrow_final_sum_term_removed_but_whole_bound_remains_conditional"),
        nominal_log2_p_fail=nominal_log2_p_fail,
        nominal_per_output_probability=2.0**nominal_log2_p_fail,
        terminal_output_marginals=2,
        terminal_outputs_are_statistically_independent=False,
        conditional_terminal_union_upper=terminal_upper,
        conditional_terminal_union_log2=terminal_log2,
        stage_output_marginals=stage.scan_output_marginals,
        conditional_stage_union_upper=stage_upper,
        conditional_stage_union_log2=stage_log2,
        whole_blind_rotations=counts.blind_rotations,
        conditional_whole_blind_rotation_union_upper=whole_br_upper,
        conditional_whole_blind_rotation_union_log2=whole_br_log2,
        whole_key_switches_structural=counts.key_switches,
        key_switches_added_as_independent_failure_events=False,
        whole_output_marginals=counts.output_marginals,
        conditional_whole_union_upper=whole_upper,
        conditional_whole_union_log2=whole_log2,
        separate_unbootstrapped_final_sum_term=False,
        final_decode_term_status=(
            "absorbed_into_the_two_terminal_output_events_if_each_event_bound_"
            "covers_the_full_decrypt_and_round_cell"
        ),
        terminal_source=terminal_source,
        end_to_end_numeric_upper=None,
        assumptions_needed=(
            "each custom raw-core terminal output has a conditional decoding-error "
            "probability no greater than the nominal per-PBS value",
            "every upstream custom LUT receives only its proved reachable states and "
            "noise budget under a correct-prefix condition",
            "the terminal ciphertexts are returned directly, with no server-side "
            "linear weighting, addition, rescaling, or modulus change",
            "the client uses the modeled p=16 torus rounding convention",
        ),
        obligations_still_open=(
            "transfer the pinned shortint parameter's nominal p-fail to every custom "
            "core_crypto PBS and correlated extracted marginal",
            "propagate initial, score-lane, key-switch, and bounded fan-in noise to "
            "every reachable PBS input",
            "audit the concrete two-LWE accumulator coefficients and sample-extraction "
            "degrees in an isolated Rust implementation",
            "validate the two-LWE path empirically without interpreting zero observed "
            "errors as evidence at the nominal cryptographic tail",
        ),
    )


def validate_protocol() -> ValidationSummary:
    """Deterministically check exact-ID semantics and every in-cell edge."""
    reject_cases = 0
    singleton_cases = 0
    tied_suffix_cases = 0
    for gallery_size in range(1, MAX_GALLERY_SIZE + 1):
        rejected = evaluate_a34_two_lwe([False] * gallery_size)
        if (rejected.low_nibble, rejected.high_nibble, rejected.code) != (0, 0, 0):
            raise AssertionError(
                "all-reject encoding drifted at N={}".format(gallery_size)
            )
        reject_cases += 1
        for winner in range(gallery_size):
            singleton = [False] * gallery_size
            singleton[winner] = True
            if evaluate_a34_two_lwe(singleton).code != winner + 1:
                raise AssertionError("singleton winner drifted")
            singleton_cases += 1

            tied_suffix = [index >= winner for index in range(gallery_size)]
            if evaluate_a34_two_lwe(tied_suffix).code != winner + 1:
                raise AssertionError("tie-first semantics drifted")
            tied_suffix_cases += 1

    code_bijection_cases = 0
    for code in range(MAX_GALLERY_SIZE + 1):
        digits = split_exact_code(code, MAX_GALLERY_SIZE)
        if combine_exact_digits(*digits, MAX_GALLERY_SIZE).code != code:
            raise AssertionError("base-16 response mapping is not bijective")
        code_bijection_cases += 1

    in_cell_noise_cases = 0
    for digit in range(P16):
        center = encode_nibble_phase(digit)
        for error in (
            -(NIBBLE_HALF_SLOT_MARGIN - 1),
            -1,
            0,
            1,
            NIBBLE_HALF_SLOT_MARGIN - 1,
        ):
            observed = decode_nibble_phase(add_signed_torus_error(center, error))
            if observed != digit:
                raise AssertionError("in-cell p=16 rounding changed a digit")
            in_cell_noise_cases += 1

    total = (
        reject_cases
        + singleton_cases
        + tied_suffix_cases
        + code_bijection_cases
        + in_cell_noise_cases
    )
    return ValidationSummary(
        gallery_sizes_checked=MAX_GALLERY_SIZE,
        reject_cases=reject_cases,
        singleton_cases=singleton_cases,
        tied_suffix_cases=tied_suffix_cases,
        code_bijection_cases=code_bijection_cases,
        in_cell_noise_cases=in_cell_noise_cases,
        total_cases=total,
    )


def report(gallery_size: int, include_validation: bool = True) -> dict[str, object]:
    _validate_gallery_size(gallery_size)
    counts = a34_two_nibble_replacement_counts(gallery_size)
    stage = a34_two_nibble_stage_counts(gallery_size)
    comparison = None
    if gallery_size == 127:
        comparison = {
            "a33_current": asdict(A33_N127_COUNTS),
            "projected_savings_vs_a33": {
                "blind_rotations": A33_N127_COUNTS.blind_rotations
                - counts.blind_rotations,
                "key_switches": A33_N127_COUNTS.key_switches - counts.key_switches,
                "output_marginals": A33_N127_COUNTS.output_marginals
                - counts.output_marginals,
            },
        }
    return {
        "schema_version": 1,
        "model": "a34-two-lwe-nibble-response",
        "status": "static projection; no Rust, service, Cargo, key, or FHE validation",
        "plaintext_contract": {
            "reject": {"code": 0, "digits": [0, 0]},
            "accepted": "one-based code i+1 in 1..gallery_size",
            "reconstruction": "code = low_nibble + 16 * high_nibble",
            "maximum": {"code": 128, "digits": [0, 8]},
            "semantic_leakage": (
                "same exact ID/reject value at plaintext level; the two-digit mapping "
                "is bijective on codes 0..128"
            ),
            "transcript_caveat": (
                "two fixed-size ciphertexts and a new public output mode differ from "
                "the current one-ciphertext transcript"
            ),
        },
        "decode_geometry": asdict(decode_geometry()),
        "wire_projection": asdict(projected_wire_layout()),
        "scan_output_stage": asdict(stage),
        "whole_core_projection": asdict(counts),
        "n127_comparison": comparison,
        "conditional_failure_accounting": asdict(
            conditional_failure_accounting(gallery_size)
        ),
        "decoder_limit": (
            "range checks reject noncanonical/out-of-gallery pairs but cannot detect "
            "every in-range wrong-ID digit error; authentication or redundancy is not modeled"
        ),
        "validation": asdict(validate_protocol()) if include_validation else None,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gallery-size", type=int, default=127)
    parser.add_argument("--no-validate", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    print(
        json.dumps(
            report(args.gallery_size, include_validation=not args.no_validate),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
