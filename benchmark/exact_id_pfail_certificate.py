#!/usr/bin/env python3
"""Static certificate audit for the A33 and projected A34/A36 exact-ID paths.

This module intentionally does not execute TFHE.  It separates arithmetic that
is rigorous once per-node hypotheses are supplied (geometry and union bounds)
from TFHE-rs's nominal shortint contract and from Gaussian sensitivity models.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass
from functools import cache

try:
    from benchmark.a38_initial_score_bound import report as initial_score_report
except ModuleNotFoundError:  # Support direct execution from benchmark/.
    from a38_initial_score_bound import report as initial_score_report


TORUS_BITS = 64
TORUS_MODULUS = 1 << TORUS_BITS
POLYNOMIAL_SIZE = 2_048
ROTATION_MODULUS = 2 * POLYNOMIAL_SIZE

P16 = 16
P256 = 256
BOOL_DELTA_LOG = 59
CODE_DELTA_LOG = 56
MAX_CODE = 128
SHORTINT_MAX_NOISE_LEVEL = 5
NOMINAL_LOG2_P_FAIL = -71.625
CODE_CENTER_SPACING_STEPS = ROTATION_MODULUS * (1 << CODE_DELTA_LOG) // TORUS_MODULUS
P256_BOX_WIDTH_STEPS = POLYNOMIAL_SIZE // P256
MAX_DISTINCT_CODE_MARGIN_STEPS = CODE_CENTER_SPACING_STEPS // 2

# Formula outputs already recorded by the extraction-noise audit.  They are
# model inputs, not formal upper bounds supplied by TFHE-rs 0.11.3.
PBS_VARIANCE = 1.133226667479e-9
KEY_SWITCH_VARIANCE = 3.526608149211e-7
MODULUS_SWITCH_VARIANCE = 2.187987168630e-6

A33_N127_BLIND_ROTATIONS = 4_273
A33_N127_KEY_SWITCHES = 3_892
A33_N127_OUTPUT_MARGINALS = 4_908

COMPOSED_N127_BLIND_ROTATIONS = 3_655
COMPOSED_N127_KEY_SWITCHES = 3_274
COMPOSED_N127_OUTPUT_MARGINALS = 4_206


@dataclass(frozen=True)
class ConditionalUnion:
    event_count: int
    per_event_log2_upper: float
    probability_upper: float
    log2_probability_upper: float
    independence_required: bool
    status: str


@dataclass(frozen=True)
class TrailingP256Audit:
    input_code_min: int
    input_code_max: int
    input_delta_log: int
    input_center_spacing_rotation_steps: int
    message_modulus: int
    helper_box_width_rotation_steps: int
    helper_unmerged_half_box_margin_steps: int
    largest_distinct_code_margin_steps: int
    largest_distinct_code_margin_torus: int
    largest_distinct_code_margin_normalized: float
    reachable_base_slots: tuple[int, ...]
    endpoint_is_antipode_of_zero: bool
    raw_identity_negacyclic_compatible: bool
    centered_identity_offset_codes: int
    post_pbs_public_shift_codes_for_legacy_decode: int
    centered_identity_negacyclic_compatible: bool
    centered_body_exhaustive_open_margin_verified: bool
    first_boundary_collision_rotation_steps: int
    summed_fresh_code_roots: int
    gaussian_input_sigma_without_modulus_switch: float
    gaussian_input_tail_without_modulus_switch: float
    gaussian_input_log2_tail_without_modulus_switch: float
    gaussian_input_sigma_with_modulus_switch: float
    gaussian_input_tail_with_modulus_switch: float
    gaussian_input_log2_tail_with_modulus_switch: float
    gaussian_fresh_output_log2_tail: float
    gaussian_numbers_are_probability_bounds: bool
    nominal_shortint_pfail_applies: bool
    closes_final_decode: bool
    conclusion: str


@dataclass(frozen=True)
class StrictA36Schedule:
    bit_indices: tuple[int, ...]
    bit_noise_l1: tuple[int, ...]
    zero_test_input_l1: tuple[int, ...]
    state_l1_after_update: tuple[int, ...]
    refresh_after_bit_indices: tuple[int, ...]
    initial_state_is_direct_fresh_code_two: bool
    maximum_raw_input_l1: int
    nominal_limit: int
    extra_refresh_nodes_at_n127: int
    projected_blind_rotations_at_n127: int
    projected_key_switches_at_n127: int
    projected_output_marginals_at_n127: int
    removes_double_margin_rescaling_assumption: bool


@dataclass(frozen=True)
class TwoLweTerminalAudit:
    plaintext_mapping: str
    output_lwes: int
    output_delta_log: int
    half_slot_margin_torus: int
    half_slot_margin_normalized: float
    margin_ratio_over_code56: int
    maximum_terminal_fanin: int
    maximum_terminal_noise_level: int
    each_root_fresh: bool
    roots_statistically_independent: bool
    nominal_per_root_probability: float
    terminal_union: ConditionalUnion
    closes_terminal_decode_under_nominal_contract: bool
    closes_end_to_end: bool
    conditions: tuple[str, ...]
    conclusion: str


def conditional_union(event_count: int, log2_upper: float) -> ConditionalUnion:
    """Return Boole's inequality; no event independence is assumed."""
    if event_count <= 0:
        raise ValueError("event_count must be positive")
    if not math.isfinite(log2_upper) or log2_upper > 0:
        raise ValueError("log2_upper must be finite and non-positive")
    upper = min(1.0, event_count * (2.0**log2_upper))
    return ConditionalUnion(
        event_count=event_count,
        per_event_log2_upper=log2_upper,
        probability_upper=upper,
        log2_probability_upper=math.log2(upper) if upper else float("-inf"),
        independence_required=False,
        status="formal_arithmetic_conditional_on_each_event_upper",
    )


def _gaussian_two_sided_tail(sigma: float, margin: float) -> tuple[float, float]:
    """Return a Gaussian sensitivity value and its log2, including tiny tails."""
    if sigma <= 0 or margin <= 0:
        raise ValueError("sigma and margin must be positive")
    z = margin / sigma
    probability = math.erfc(z / math.sqrt(2.0))
    if probability:
        return probability, math.log2(probability)

    # Stable Mills-series evaluation for tails below binary64's range.
    inverse_z_squared = 1.0 / (z * z)
    series = 1.0
    term = 1.0
    for order in range(1, 32):
        candidate = term * (-(2 * order - 1) * inverse_z_squared)
        if abs(candidate) >= abs(term):
            break
        series += candidate
        term = candidate
    log_probability = (
        math.log(2.0)
        - 0.5 * z * z
        - 0.5 * math.log(2.0 * math.pi)
        - math.log(z)
        + math.log(series)
    )
    return 0.0, log_probability / math.log(2.0)


def _negacyclic_coefficient(body: tuple[int, ...], degree: int) -> int:
    cycles, index = divmod(degree, len(body))
    return -body[index] if cycles % 2 else body[index]


@cache
def centered_p256_body() -> tuple[int, ...]:
    """Construct the maximum-margin centered code LUT in signed code units.

    Only the strict neighborhoods ``abs(rotation_error) < 8`` are assigned by
    this proof object.  Midpoints are filled from the lower code; no assignment
    can make a midpoint belong to both adjacent, differently labelled codes.
    """
    body: list[int | None] = [None] * POLYNOMIAL_SIZE
    margin = MAX_DISTINCT_CODE_MARGIN_STEPS
    for code in range(MAX_CODE + 1):
        desired = code - MAX_CODE // 2
        center = code * CODE_CENTER_SPACING_STEPS
        for error in range(-margin + 1, margin):
            cycles, index = divmod(center + error, POLYNOMIAL_SIZE)
            stored = -desired if cycles % 2 else desired
            if body[index] is not None and body[index] != stored:
                raise AssertionError("centered p256 neighborhoods conflict")
            body[index] = stored

    # The unassigned coefficients are exactly the decision midpoints.  Pick the
    # lower-code label to make the half-open convention deterministic.
    for code in range(MAX_CODE):
        boundary = code * CODE_CENTER_SPACING_STEPS + margin
        cycles, index = divmod(boundary, POLYNOMIAL_SIZE)
        desired = code - MAX_CODE // 2
        body[index] = -desired if cycles % 2 else desired
    if any(value is None for value in body):
        raise AssertionError("centered p256 proof body is incomplete")
    return tuple(int(value) for value in body)


def sample_centered_p256(code: int, rotation_error: int = 0) -> int:
    if not 0 <= code <= MAX_CODE:
        raise ValueError("code must be in 0..128")
    return _negacyclic_coefficient(
        centered_p256_body(), code * CODE_CENTER_SPACING_STEPS + rotation_error
    )


def _verify_centered_p256_open_margin() -> bool:
    for code in range(MAX_CODE + 1):
        expected = code - MAX_CODE // 2
        for error in range(
            -MAX_DISTINCT_CODE_MARGIN_STEPS + 1,
            MAX_DISTINCT_CODE_MARGIN_STEPS,
        ):
            if sample_centered_p256(code, error) != expected:
                return False
    return True


def trailing_p256_audit(summed_fresh_code_roots: int = 3) -> TrailingP256Audit:
    """Audit a one-BR/one-KS refresh of the A33 code sum at Delta=2^56.

    A p=256 helper has eight-coefficient boxes, while consecutive reachable
    code centers are sixteen coefficients apart.  A custom shifted/coalesced
    body can therefore reach an open margin of eight coefficients, but no LUT
    distinguishing every adjacent code can exceed it.
    """
    if summed_fresh_code_roots <= 0:
        raise ValueError("summed_fresh_code_roots must be positive")
    delta = 1 << CODE_DELTA_LOG
    center_spacing = CODE_CENTER_SPACING_STEPS
    box_width = P256_BOX_WIDTH_STEPS
    helper_half_box = box_width // 2
    maximum_margin_steps = MAX_DISTINCT_CODE_MARGIN_STEPS
    maximum_margin_torus = maximum_margin_steps * TORUS_MODULUS // ROTATION_MODULUS
    maximum_margin_normalized = maximum_margin_torus / TORUS_MODULUS

    # code 0..127 selects the even p=256 base slots.  Code 128 is the
    # negacyclic antipode of code zero rather than an independent base slot.
    reachable_base_slots = tuple(2 * code for code in range(MAX_CODE))
    raw_zero = 0
    raw_endpoint = MAX_CODE * delta
    centered_zero = (0 - MAX_CODE // 2) * delta
    centered_endpoint = (MAX_CODE - MAX_CODE // 2) * delta

    variance_without_ms = summed_fresh_code_roots * PBS_VARIANCE + KEY_SWITCH_VARIANCE
    variance_with_ms = variance_without_ms + MODULUS_SWITCH_VARIANCE
    sigma_without_ms = math.sqrt(variance_without_ms)
    sigma_with_ms = math.sqrt(variance_with_ms)
    tail_without_ms, log2_without_ms = _gaussian_two_sided_tail(
        sigma_without_ms, maximum_margin_normalized
    )
    tail_with_ms, log2_with_ms = _gaussian_two_sided_tail(
        sigma_with_ms, maximum_margin_normalized
    )
    _, fresh_output_log2 = _gaussian_two_sided_tail(
        math.sqrt(PBS_VARIANCE), maximum_margin_normalized
    )

    return TrailingP256Audit(
        input_code_min=0,
        input_code_max=MAX_CODE,
        input_delta_log=CODE_DELTA_LOG,
        input_center_spacing_rotation_steps=center_spacing,
        message_modulus=P256,
        helper_box_width_rotation_steps=box_width,
        helper_unmerged_half_box_margin_steps=helper_half_box,
        largest_distinct_code_margin_steps=maximum_margin_steps,
        largest_distinct_code_margin_torus=maximum_margin_torus,
        largest_distinct_code_margin_normalized=maximum_margin_normalized,
        reachable_base_slots=reachable_base_slots,
        endpoint_is_antipode_of_zero=(MAX_CODE * center_spacing == POLYNOMIAL_SIZE),
        raw_identity_negacyclic_compatible=(raw_endpoint % TORUS_MODULUS)
        == ((-raw_zero) % TORUS_MODULUS),
        centered_identity_offset_codes=-(MAX_CODE // 2),
        post_pbs_public_shift_codes_for_legacy_decode=MAX_CODE // 2,
        centered_identity_negacyclic_compatible=(centered_endpoint % TORUS_MODULUS)
        == ((-centered_zero) % TORUS_MODULUS),
        centered_body_exhaustive_open_margin_verified=(
            _verify_centered_p256_open_margin()
        ),
        first_boundary_collision_rotation_steps=maximum_margin_steps,
        summed_fresh_code_roots=summed_fresh_code_roots,
        gaussian_input_sigma_without_modulus_switch=sigma_without_ms,
        gaussian_input_tail_without_modulus_switch=tail_without_ms,
        gaussian_input_log2_tail_without_modulus_switch=log2_without_ms,
        gaussian_input_sigma_with_modulus_switch=sigma_with_ms,
        gaussian_input_tail_with_modulus_switch=tail_with_ms,
        gaussian_input_log2_tail_with_modulus_switch=log2_with_ms,
        gaussian_fresh_output_log2_tail=fresh_output_log2,
        gaussian_numbers_are_probability_bounds=False,
        nominal_shortint_pfail_applies=False,
        closes_final_decode=False,
        conclusion=(
            "A centered custom LUT can make the reachable plaintext mapping valid, "
            "but the input selection margin is only the original code56 decode radius. "
            "The extra PBS moves the unproved narrow-cell obligation to its input and "
            "also leaves a narrow-cell decode obligation on its output."
        ),
    )


def strict_a36_schedule() -> StrictA36Schedule:
    """A conservative A36 refresh schedule that never rescales NoiseLevel by margin."""
    bit_indices = (7, 6, 5, 4, 3, 2, 1, 0)
    bit_l1 = (2, 2, 2, 2, 2, 1, 1, 1)
    refresh_after = (6, 4, 2, 0)
    state_l1 = 1  # A34 top emits code 2 directly in a fresh p16 output.
    inputs: list[int] = []
    after_updates: list[int] = []
    for bit_index, source_l1 in zip(bit_indices, bit_l1):
        inputs.append(state_l1 + source_l1)
        state_l1 += 2  # fresh local-zero and fresh global-any outputs
        after_updates.append(state_l1)
        if bit_index in refresh_after:
            state_l1 = 1  # the canonicalizer directly emits code 2
    extra = 2 * 127
    return StrictA36Schedule(
        bit_indices=bit_indices,
        bit_noise_l1=bit_l1,
        zero_test_input_l1=tuple(inputs),
        state_l1_after_update=tuple(after_updates),
        refresh_after_bit_indices=refresh_after,
        initial_state_is_direct_fresh_code_two=True,
        maximum_raw_input_l1=max(inputs + after_updates + [5]),
        nominal_limit=SHORTINT_MAX_NOISE_LEVEL,
        extra_refresh_nodes_at_n127=extra,
        projected_blind_rotations_at_n127=COMPOSED_N127_BLIND_ROTATIONS + extra,
        projected_key_switches_at_n127=COMPOSED_N127_KEY_SWITCHES + extra,
        projected_output_marginals_at_n127=COMPOSED_N127_OUTPUT_MARGINALS + extra,
        removes_double_margin_rescaling_assumption=True,
    )


def two_lwe_terminal_audit() -> TwoLweTerminalAudit:
    """Audit direct low/high p16 outputs, not the two code56 roots in A38."""
    half_margin = 1 << (BOOL_DELTA_LOG - 1)
    code56_half_margin = 1 << (CODE_DELTA_LOG - 1)
    terminal_union = conditional_union(2, NOMINAL_LOG2_P_FAIL)
    return TwoLweTerminalAudit(
        plaintext_mapping="(low, high)=(code mod 16, floor(code/16))",
        output_lwes=2,
        output_delta_log=BOOL_DELTA_LOG,
        half_slot_margin_torus=half_margin,
        half_slot_margin_normalized=half_margin / TORUS_MODULUS,
        margin_ratio_over_code56=half_margin // code56_half_margin,
        maximum_terminal_fanin=SHORTINT_MAX_NOISE_LEVEL,
        maximum_terminal_noise_level=SHORTINT_MAX_NOISE_LEVEL,
        each_root_fresh=True,
        roots_statistically_independent=False,
        nominal_per_root_probability=2.0**NOMINAL_LOG2_P_FAIL,
        terminal_union=terminal_union,
        closes_terminal_decode_under_nominal_contract=True,
        closes_end_to_end=False,
        conditions=(
            "each terminal is an official shortint p16 identity PBS or a proved-equivalent "
            "raw implementation",
            "each terminal input has tracked NoiseLevel at most five without margin rescaling",
            "both p16 ciphertexts are returned directly with no weighting, addition, or rescale",
            "the client rounds each ciphertext independently at Delta=2^59",
        ),
        conclusion=(
            "This route genuinely removes the code56 final-sum obligation under the pinned "
            "shortint nominal contract.  It does not prove the upstream custom extraction, "
            "classifier, or current A36 double-margin assumptions."
        ),
    )


def report() -> dict[str, object]:
    strict = strict_a36_schedule()
    initial_score = initial_score_report()
    if initial_score["initial_score_decode_failure_probability_upper"] != 0.0:
        raise AssertionError("the deterministic initial-score obligation regressed")
    return {
        "status": "static_certificate_audit_no_fhe_executed",
        "nominal_parameter": {
            "log2_p_fail": NOMINAL_LOG2_P_FAIL,
            "max_noise_level": SHORTINT_MAX_NOISE_LEVEL,
        },
        "formal_conditional_union_bounds": {
            "a33_output_marginals": asdict(
                conditional_union(A33_N127_OUTPUT_MARGINALS, NOMINAL_LOG2_P_FAIL)
            ),
            "projected_a34_a36_output_marginals": asdict(
                conditional_union(COMPOSED_N127_OUTPUT_MARGINALS, NOMINAL_LOG2_P_FAIL)
            ),
            "strict_a36_schedule_output_marginals": asdict(
                conditional_union(
                    strict.projected_output_marginals_at_n127,
                    NOMINAL_LOG2_P_FAIL,
                )
            ),
            "scope": (
                "The arithmetic is a formal union bound only after a valid conditional "
                "upper bound has been supplied for every listed event."
            ),
        },
        "trailing_p256": asdict(trailing_p256_audit()),
        "trailing_p256_a38_two_roots": asdict(trailing_p256_audit(2)),
        "two_lwe_terminal": asdict(two_lwe_terminal_audit()),
        "strict_a36_schedule": asdict(strict),
        "initial_score_support": initial_score,
        "end_to_end_numeric_upper": None,
        "blocking_obligations": [
            "starting after the deterministically bounded initial score, prove or "
            "contractually transfer a tail bound for every extractor correction and "
            "A34-top classifier input under the correct-prefix condition",
            "replace current A36 margin-normalized L1=10 reasoning with the strict raw-L1 "
            "schedule or prove an explicit scaled-margin tail theorem",
            "use official/equivalent p16 ManyLUT and retain correlation provenance for all "
            "multi-sample outputs",
            "return the two terminal nibbles at Delta=2^59 instead of summing code56 roots",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    print(json.dumps(report(), indent=None if args.compact else 2, sort_keys=True))


if __name__ == "__main__":
    main()
