#!/usr/bin/env python3
"""Static model of the A50 canonical-state, radix-15 A36 proposal.

Only the eight gallery-wide OR trees of A36 are widened.  The model keeps the
existing A38 bit sources, changes the live-state encoding from 0/2 to 0/1, and
uses the max-noise-15 A44 parameter contract as a *conditional* prerequisite.

This module performs clear semantics, raw negacyclic-geometry, conservative
raw-L1, and structural-count checks.  It does not run TFHE, Cargo, keygen, or a
latency benchmark, and it does not claim an end-to-end p-fail bound.
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
from dataclasses import asdict, dataclass
from functools import cache
from typing import Sequence


MAX_GALLERY_SIZE = 128
SCORE_BITS = (7, 6, 5, 4, 3, 2, 1, 0)
A38_SOURCE_WEIGHTS = (1, 1, 1, 1, 1, 8, 4, 2)
A50_BIT_CONTRIBUTIONS = (-1, -1, -1, -1, -1, 8, -4, -2)
CHUNK_END_LEVELS = (3, 7)
ACTIVE_CODE = 1
INACTIVE_CODE = 0
A38_REDUCTION_RADIX = 5
A40_REDUCTION_RADIX = 7
A50_REDUCTION_RADIX = 15
SCAN_GROUP_SIZE = 3

P16 = 16
POLYNOMIAL_SIZE = 2_048
P16_BOX_SIZE = POLYNOMIAL_SIZE // P16
STANDARD_HALF_SLOT_ROTATIONS = P16_BOX_SIZE // 2
SIGNED_CODE_PERIOD = 2 * P16
A44_MAX_NOISE_LEVEL = 15
CURRENT_MAX_NOISE_LEVEL = 5
A44_PER_EVENT_LOG2_P_FAIL = -64.088


@dataclass(frozen=True)
class OperationCounts:
    blind_rotations: int
    key_switches: int
    output_marginals: int

    def __sub__(self, other: "OperationCounts") -> "OperationCounts":
        return OperationCounts(
            self.blind_rotations - other.blind_rotations,
            self.key_switches - other.key_switches,
            self.output_marginals - other.output_marginals,
        )


@dataclass(frozen=True)
class SizeCountRow:
    gallery_size: int
    a38: OperationCounts
    a40: OperationCounts
    a50: OperationCounts
    a50_delta_vs_a38: OperationCounts
    a50_delta_vs_a40: OperationCounts
    a38_or_nodes_per_bit: int
    a40_or_nodes_per_bit: int
    a50_or_nodes_per_bit: int


@dataclass(frozen=True)
class NoiseLevelRow:
    bit_index: int
    semantic_bit_contribution: int
    state_l1_before: int
    source_l1: int
    zero_test_input_l1: int
    state_l1_after_update: int
    refreshed_after_level: bool


@dataclass(frozen=True)
class NoiseAudit:
    levels: tuple[NoiseLevelRow, ...]
    boundary_refresh_input_l1: int
    final_refresh_input_l1: int
    maximum_or_input_l1: int
    maximum_raw_l1: int
    current_max_noise_level: int
    a44_max_noise_level: int
    current_parameter_covers_without_rescaling: bool
    a44_covers_without_rescaling: bool
    margin_rescaling_factor: int


@dataclass(frozen=True)
class ReachabilityLevel:
    bit_index: int
    semantic_bit_contribution: int
    states_before: tuple[tuple[int, bool], ...]
    zero_test_inputs: tuple[int, ...]
    states_after_linear_update: tuple[tuple[int, bool], ...]
    states_after_optional_refresh: tuple[tuple[int, bool], ...]
    refreshed: bool


@dataclass(frozen=True)
class ReachabilityAudit:
    levels: tuple[ReachabilityLevel, ...]
    reachable_zero_test_inputs: tuple[int, ...]
    reachable_refresh_inputs: tuple[int, ...]
    target_code: int
    signed_target_antipode: int
    target_antipode_reachable: bool
    live_state_invariant_holds: bool
    inactive_states_never_positive: bool


@dataclass(frozen=True)
class RawGeometryAudit:
    polynomial_size: int
    box_size: int
    open_half_slot_margin_rotations: int
    target_code: int
    signed_target_antipode: int
    target_antipode_reachable: bool
    target_one_lut_exact_on_all_reachable_centers: bool
    radix15_or_exact_on_all_centers: bool
    radix15_or_has_standard_open_margin: bool
    radix16_center_output: int
    radix16_required_output: int
    radix16_negacyclic_no_go: bool


@dataclass(frozen=True)
class LevelTrace:
    bit_index: int
    semantic_bit_contribution: int
    bits: tuple[int, ...]
    states_before: tuple[int, ...]
    zero_test_inputs: tuple[int, ...]
    zero_candidates: tuple[int, ...]
    any_zero: int
    states_after_linear_update: tuple[int, ...]
    states_after_optional_refresh: tuple[int, ...]
    refreshed: bool


@dataclass(frozen=True)
class A50Trace:
    initial_candidates: tuple[bool, ...]
    suffixes: tuple[int, ...]
    levels: tuple[LevelTrace, ...]
    final_candidates: tuple[bool, ...]
    reference_candidates: tuple[bool, ...]
    code: int
    reference_code: int


@dataclass(frozen=True)
class OpenSetClearTrace:
    translated_scores: tuple[int, ...]
    translated_threshold: int
    admitted: tuple[bool, ...]
    minimum_high_candidates: tuple[bool, ...]
    a50: A50Trace
    code: int
    reference_code: int


@dataclass(frozen=True)
class PairValidationSummary:
    candidate_masks: int
    suffix_pairs: int
    total_cases: int


def negacyclic_coefficient(body: Sequence[int], degree: int) -> int:
    """Read a signed coefficient in Z[X]/(X^N+1)."""
    if len(body) != POLYNOMIAL_SIZE:
        raise ValueError("unexpected accumulator polynomial size")
    cycles, index = divmod(degree, POLYNOMIAL_SIZE)
    return -body[index] if cycles % 2 else body[index]


def sample_signed_code(
    body: Sequence[int], code: int, rotation_error: int = 0
) -> int:
    """Sample ``code * 2^59`` on the exact p16 blind-rotation grid."""
    center = (code % SIGNED_CODE_PERIOD) * P16_BOX_SIZE
    return negacyclic_coefficient(body, center + rotation_error)


@cache
def target_one_accumulator_body() -> tuple[int, ...]:
    """Raw p16 body for ``input == 1``, with standard half-slot margin.

    The independent half-torus contains codes 0..15.  The body is one on
    [0.5, 1.5) slots.  Its negacyclic extension is necessarily -1 around the
    antipode 17 (signed code -15), which the reachability proof must exclude.
    """
    body = [0] * POLYNOMIAL_SIZE
    start = STANDARD_HALF_SLOT_ROTATIONS
    end = P16_BOX_SIZE + STANDARD_HALF_SLOT_ROTATIONS
    body[start:end] = [ACTIVE_CODE] * (end - start)
    return tuple(body)


@cache
def canonical_or_accumulator_body() -> tuple[int, ...]:
    """Raw p16 OR body for a sum of at most fifteen canonical 0/1 flags."""
    body = [0] * POLYNOMIAL_SIZE
    start = STANDARD_HALF_SLOT_ROTATIONS
    end = 15 * P16_BOX_SIZE + STANDARD_HALF_SLOT_ROTATIONS
    body[start:end] = [ACTIVE_CODE] * (end - start)
    return tuple(body)


def target_one(code: int) -> int:
    return sample_signed_code(target_one_accumulator_body(), code)


def canonical_or_gate(values: Sequence[int]) -> int:
    if not 2 <= len(values) <= A50_REDUCTION_RADIX:
        raise ValueError("a radix-15 OR gate needs 2..15 inputs")
    if any(value not in (0, 1) for value in values):
        raise ValueError("OR inputs must be canonical 0/1 flags")
    return sample_signed_code(canonical_or_accumulator_body(), sum(values))


def reduce_canonical_or(values: Sequence[int]) -> int:
    if not values or any(value not in (0, 1) for value in values):
        raise ValueError("expected a non-empty canonical Boolean vector")
    level = tuple(values)
    while len(level) > 1:
        next_level: list[int] = []
        for start in range(0, len(level), A50_REDUCTION_RADIX):
            chunk = level[start : start + A50_REDUCTION_RADIX]
            next_level.append(chunk[0] if len(chunk) == 1 else canonical_or_gate(chunk))
        level = tuple(next_level)
    return level[0]


def _validate_inputs(
    candidates: Sequence[bool | int], suffixes: Sequence[int]
) -> tuple[tuple[bool, ...], tuple[int, ...]]:
    raw_candidates = tuple(candidates)
    raw_suffixes = tuple(suffixes)
    if not 1 <= len(raw_candidates) <= MAX_GALLERY_SIZE:
        raise ValueError("gallery size must be in 1..128")
    if len(raw_candidates) != len(raw_suffixes):
        raise ValueError("candidate and suffix lengths differ")
    if any(value not in (False, True, 0, 1) for value in raw_candidates):
        raise ValueError("candidate values must be Boolean")
    if any(not isinstance(value, int) or not 0 <= value <= 255 for value in raw_suffixes):
        raise ValueError("suffix values must be bytes")
    return tuple(bool(value) for value in raw_candidates), raw_suffixes


def reference_candidates(
    candidates: tuple[bool, ...], suffixes: tuple[int, ...]
) -> tuple[bool, ...]:
    admitted = [suffix for candidate, suffix in zip(candidates, suffixes) if candidate]
    if not admitted:
        return tuple(False for _ in candidates)
    minimum = min(admitted)
    return tuple(
        candidate and suffix == minimum
        for candidate, suffix in zip(candidates, suffixes)
    )


def evaluate_a50(
    candidates: Sequence[bool | int], suffixes: Sequence[int]
) -> A50Trace:
    """Evaluate A50 clear semantics and assert exact low-byte candidate selection."""
    canonical_candidates, canonical_suffixes = _validate_inputs(candidates, suffixes)
    states = tuple(ACTIVE_CODE if candidate else INACTIVE_CODE for candidate in canonical_candidates)
    levels: list[LevelTrace] = []

    for level, (bit_index, contribution) in enumerate(
        zip(SCORE_BITS, A50_BIT_CONTRIBUTIONS)
    ):
        bits = tuple((suffix >> bit_index) & 1 for suffix in canonical_suffixes)
        inputs = tuple(state + contribution * bit for state, bit in zip(states, bits))
        zero_candidates = tuple(target_one(value) for value in inputs)
        if any(value not in (0, 1) for value in zero_candidates):
            raise AssertionError("reachable zero-test input hit the target antipode")
        any_zero = reduce_canonical_or(zero_candidates)
        updated = tuple(
            state + zero - any_zero
            for state, zero in zip(states, zero_candidates)
        )
        refreshed = level in CHUNK_END_LEVELS
        next_states = (
            tuple(target_one(state) for state in updated) if refreshed else updated
        )
        if any(state > ACTIVE_CODE for state in next_states):
            raise AssertionError("candidate state escaped the canonical/dead invariant")
        levels.append(
            LevelTrace(
                bit_index=bit_index,
                semantic_bit_contribution=contribution,
                bits=bits,
                states_before=states,
                zero_test_inputs=inputs,
                zero_candidates=zero_candidates,
                any_zero=any_zero,
                states_after_linear_update=updated,
                states_after_optional_refresh=next_states,
                refreshed=refreshed,
            )
        )
        states = next_states

    final_candidates = tuple(state == ACTIVE_CODE for state in states)
    reference = reference_candidates(canonical_candidates, canonical_suffixes)
    code = next((index + 1 for index, value in enumerate(final_candidates) if value), 0)
    reference_code = next((index + 1 for index, value in enumerate(reference) if value), 0)
    if final_candidates != reference or code != reference_code:
        raise AssertionError("A50 disagrees with exact low-byte minimum semantics")
    return A50Trace(
        initial_candidates=canonical_candidates,
        suffixes=canonical_suffixes,
        levels=tuple(levels),
        final_candidates=final_candidates,
        reference_candidates=reference,
        code=code,
        reference_code=reference_code,
    )


def evaluate_open_set_scores(
    translated_scores: Sequence[int], translated_threshold: int = 1_023
) -> OpenSetClearTrace:
    """Compose A50 with the clear contract of the unchanged A34 top stage.

    Scores are the aligned unsigned 12-bit values consumed by A34/A36.  This is
    an observable-semantics oracle, not a model of A34's encrypted internals:
    it admits scores under the public translated threshold, keeps the minimum
    high nibble, lets A50 select the exact low-byte minimum, and checks the
    resulting first-tie ID against direct clear argmin.
    """
    scores = tuple(translated_scores)
    if not 1 <= len(scores) <= MAX_GALLERY_SIZE:
        raise ValueError("gallery size must be in 1..128")
    if any(not isinstance(score, int) or not 0 <= score <= 4_095 for score in scores):
        raise ValueError("translated scores must be unsigned 12-bit integers")
    if not isinstance(translated_threshold, int) or not 0 <= translated_threshold <= 4_095:
        raise ValueError("translated threshold must be an unsigned 12-bit integer")

    admitted = tuple(score <= translated_threshold for score in scores)
    admitted_high = [
        score >> 8 for score, is_admitted in zip(scores, admitted) if is_admitted
    ]
    minimum_high = min(admitted_high) if admitted_high else None
    candidates = tuple(
        is_admitted and score >> 8 == minimum_high
        for score, is_admitted in zip(scores, admitted)
    )
    a50_trace = evaluate_a50(candidates, tuple(score & 0xFF for score in scores))
    winner = min(range(len(scores)), key=lambda index: (scores[index], index))
    reference_code = winner + 1 if scores[winner] <= translated_threshold else 0
    if a50_trace.code != reference_code:
        raise AssertionError("A50 composition disagrees with open-set exact-ID semantics")
    return OpenSetClearTrace(
        translated_scores=scores,
        translated_threshold=translated_threshold,
        admitted=admitted,
        minimum_high_candidates=candidates,
        a50=a50_trace,
        code=a50_trace.code,
        reference_code=reference_code,
    )


def reachability_audit() -> ReachabilityAudit:
    """Exhaust the local induction, including every feasible value of global ``a``.

    ``live`` is semantic liveness before the current bit.  When local ``z`` is
    one, global ``a`` must be one.  Otherwise both values are conservatively
    explored because another live template may or may not have a zero bit.
    """
    states: set[tuple[int, bool]] = {(INACTIVE_CODE, False), (ACTIVE_CODE, True)}
    levels: list[ReachabilityLevel] = []
    all_inputs: set[int] = set()
    refresh_inputs: set[int] = set()

    for level, (bit_index, contribution) in enumerate(
        zip(SCORE_BITS, A50_BIT_CONTRIBUTIONS)
    ):
        before = tuple(sorted(states))
        inputs: set[int] = set()
        updated_states: set[tuple[int, bool]] = set()
        for state, live in before:
            if live != (state == ACTIVE_CODE):
                raise AssertionError("live/state invariant broken before zero-test")
            if not live and state > INACTIVE_CODE:
                raise AssertionError("inactive state became positive")
            for bit in (0, 1):
                input_code = state + contribution * bit
                inputs.add(input_code)
                zero = target_one(input_code)
                expected_zero = int(live and bit == 0)
                if zero != expected_zero:
                    raise AssertionError(
                        f"zero-test collision at b{bit_index}: state={state}, bit={bit}"
                    )
                possible_any = (1,) if zero else (0, 1)
                for any_zero in possible_any:
                    next_live = live and (
                        (bit == 0 and any_zero == 1)
                        or (bit == 1 and any_zero == 0)
                    )
                    next_state = state + zero - any_zero
                    if next_live != (next_state == ACTIVE_CODE):
                        raise AssertionError("linear update violates live-state induction")
                    if not next_live and next_state > INACTIVE_CODE:
                        raise AssertionError("linear update resurrected an inactive state")
                    updated_states.add((next_state, next_live))

        refreshed = level in CHUNK_END_LEVELS
        if refreshed:
            refresh_inputs.update(state for state, _ in updated_states)
            next_states = {
                (target_one(state), live) for state, live in updated_states
            }
            for state, live in next_states:
                if state != int(live):
                    raise AssertionError("boundary refresh is not canonical")
        else:
            next_states = updated_states

        levels.append(
            ReachabilityLevel(
                bit_index=bit_index,
                semantic_bit_contribution=contribution,
                states_before=before,
                zero_test_inputs=tuple(sorted(inputs)),
                states_after_linear_update=tuple(sorted(updated_states)),
                states_after_optional_refresh=tuple(sorted(next_states)),
                refreshed=refreshed,
            )
        )
        all_inputs.update(inputs)
        states = next_states

    antipode = ACTIVE_CODE - P16
    return ReachabilityAudit(
        levels=tuple(levels),
        reachable_zero_test_inputs=tuple(sorted(all_inputs)),
        reachable_refresh_inputs=tuple(sorted(refresh_inputs)),
        target_code=ACTIVE_CODE,
        signed_target_antipode=antipode,
        target_antipode_reachable=antipode in all_inputs or antipode in refresh_inputs,
        live_state_invariant_holds=all(live == (state == ACTIVE_CODE) for state, live in states),
        inactive_states_never_positive=all(live or state <= INACTIVE_CODE for state, live in states),
    )


def raw_geometry_audit() -> RawGeometryAudit:
    reachability = reachability_audit()
    target_body = target_one_accumulator_body()
    or_body = canonical_or_accumulator_body()
    reachable = set(reachability.reachable_zero_test_inputs) | set(
        reachability.reachable_refresh_inputs
    )

    target_exact = True
    for code in reachable:
        expected = int(code == ACTIVE_CODE)
        for error in range(
            -STANDARD_HALF_SLOT_ROTATIONS + 1,
            STANDARD_HALF_SLOT_ROTATIONS,
        ):
            target_exact &= sample_signed_code(target_body, code, error) == expected

    radix15_exact = True
    radix15_margin = True
    for count in range(A50_REDUCTION_RADIX + 1):
        expected = int(count > 0)
        radix15_exact &= sample_signed_code(or_body, count) == expected
        for error in range(
            -STANDARD_HALF_SLOT_ROTATIONS + 1,
            STANDARD_HALF_SLOT_ROTATIONS,
        ):
            radix15_margin &= sample_signed_code(or_body, count, error) == expected

    radix16_output = sample_signed_code(or_body, 16)
    return RawGeometryAudit(
        polynomial_size=POLYNOMIAL_SIZE,
        box_size=P16_BOX_SIZE,
        open_half_slot_margin_rotations=STANDARD_HALF_SLOT_ROTATIONS,
        target_code=ACTIVE_CODE,
        signed_target_antipode=ACTIVE_CODE - P16,
        target_antipode_reachable=reachability.target_antipode_reachable,
        target_one_lut_exact_on_all_reachable_centers=target_exact,
        radix15_or_exact_on_all_centers=radix15_exact,
        radix15_or_has_standard_open_margin=radix15_margin,
        radix16_center_output=radix16_output,
        radix16_required_output=1,
        radix16_negacyclic_no_go=radix16_output != 1,
    )


def noise_audit() -> NoiseAudit:
    """Conservative raw-L1 ledger; no widened-margin discount is credited."""
    rows: list[NoiseLevelRow] = []
    state_l1 = 1  # fresh A34 top-candidate output; no clear x2 adapter
    refresh_inputs: list[int] = []
    for level, (bit_index, contribution) in enumerate(
        zip(SCORE_BITS, A50_BIT_CONTRIBUTIONS)
    ):
        source_l1 = 1  # each existing bit source enters with coefficient magnitude one
        zero_input = state_l1 + source_l1
        state_after = state_l1 + 1 + 1  # previous state + fresh z - fresh any_zero
        refreshed = level in CHUNK_END_LEVELS
        rows.append(
            NoiseLevelRow(
                bit_index=bit_index,
                semantic_bit_contribution=contribution,
                state_l1_before=state_l1,
                source_l1=source_l1,
                zero_test_input_l1=zero_input,
                state_l1_after_update=state_after,
                refreshed_after_level=refreshed,
            )
        )
        if refreshed:
            refresh_inputs.append(state_after)
            state_l1 = 1
        else:
            state_l1 = state_after

    maximum_or = A50_REDUCTION_RADIX
    maximum_raw = max(
        maximum_or,
        *(row.zero_test_input_l1 for row in rows),
        *refresh_inputs,
    )
    return NoiseAudit(
        levels=tuple(rows),
        boundary_refresh_input_l1=refresh_inputs[0],
        final_refresh_input_l1=refresh_inputs[1],
        maximum_or_input_l1=maximum_or,
        maximum_raw_l1=maximum_raw,
        current_max_noise_level=CURRENT_MAX_NOISE_LEVEL,
        a44_max_noise_level=A44_MAX_NOISE_LEVEL,
        current_parameter_covers_without_rescaling=maximum_raw <= CURRENT_MAX_NOISE_LEVEL,
        a44_covers_without_rescaling=maximum_raw <= A44_MAX_NOISE_LEVEL,
        margin_rescaling_factor=1,
    )


def reduction_nodes(
    items: int, radix: int, *, forward_singletons: bool
) -> int:
    if items < 1 or radix < 2:
        raise ValueError("invalid reduction shape")
    nodes = 0
    while items > 1:
        full, tail = divmod(items, radix)
        nodes += full + int(tail >= 2) if forward_singletons else full + int(tail != 0)
        items = full + int(tail != 0)
    return nodes


def _a34_or_reduction_nodes(items: int) -> int:
    nodes = 0
    while items > 1:
        items = (items + 3) // 4
        nodes += items
    return nodes


def _radix4_exclusive_prefix_nodes(items: int) -> int:
    if items <= 2:
        return 0
    if items <= 4:
        return items - 2
    totals = 0
    expansion = 0
    groups = 0
    for start in range(0, items, 4):
        length = min(items - start, 4)
        groups += 1
        totals += int(length > 1)
        expansion += max(length - 2, 0) if start == 0 else length - 1
    return totals + expansion + _radix4_exclusive_prefix_nodes(groups)


def _first_one_scan_nodes(items: int) -> int:
    groups = (items + SCAN_GROUP_SIZE - 1) // SCAN_GROUP_SIZE
    group_totals = sum(
        min(items - start, SCAN_GROUP_SIZE) > 1
        for start in range(0, items, SCAN_GROUP_SIZE)
    )
    return group_totals + _radix4_exclusive_prefix_nodes(groups) + items


def _output_code_positions(gallery_size: int) -> tuple[int, ...]:
    return tuple(
        bit
        for bit in range(gallery_size.bit_length())
        if any((((index + 1) >> bit) & 1) for index in range(gallery_size))
    )


def _output_code_nodes(gallery_size: int) -> int:
    positions = _output_code_positions(gallery_size)
    bit_nodes = 0
    for bit in positions:
        enabled = sum(
            (((index + 1) >> bit) & 1) == 1 for index in range(gallery_size)
        )
        bit_nodes += max(_a34_or_reduction_nodes(enabled), 1)
    return bit_nodes + (len(positions) + 2) // 3


def _exclusive_prefix_nodes(items: int, radix: int) -> int:
    if items <= 2:
        return 0
    if items <= radix:
        return items - 2
    totals = 0
    expansion = 0
    groups = 0
    for start in range(0, items, radix):
        length = min(items - start, radix)
        groups += 1
        totals += int(length > 1)
        expansion += max(length - 2, 0) if start == 0 else length - 1
    return totals + expansion + _exclusive_prefix_nodes(groups, radix)


def _a38_scan_output_nodes(gallery_size: int) -> tuple[int, int]:
    groups = (gallery_size + SCAN_GROUP_SIZE - 1) // SCAN_GROUP_SIZE
    group_nodes = sum(
        min(gallery_size - start, SCAN_GROUP_SIZE) > 1
        for start in range(0, gallery_size, SCAN_GROUP_SIZE)
    )
    prefix_nodes = _exclusive_prefix_nodes(groups, A38_REDUCTION_RADIX)
    digit_nodes = 2 * reduction_nodes(
        groups, A38_REDUCTION_RADIX, forward_singletons=False
    )
    blind_rotations = 2 * group_nodes + prefix_nodes + groups + digit_nodes
    output_marginals = blind_rotations + groups
    return blind_rotations, output_marginals


def a38_counts(gallery_size: int) -> OperationCounts:
    """Port of the frozen A38 structural counter for all N=1..128."""
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError("gallery size must be in 1..128")
    n = gallery_size
    old_total = (
        27 * n
        + 8 * _a34_or_reduction_nodes(n)
        + _first_one_scan_nodes(n)
        + _output_code_nodes(n)
        - 1
    )
    old_low = 12 * n + 8 * _a34_or_reduction_nodes(n)
    old_scan_output = _first_one_scan_nodes(n) + _output_code_nodes(n)
    new_low = 10 * n + 8 * reduction_nodes(
        n, A38_REDUCTION_RADIX, forward_singletons=False
    )
    new_scan_output, new_scan_marginals = _a38_scan_output_nodes(n)
    blind_rotations = old_total - old_low - old_scan_output + new_low + new_scan_output
    key_switches = blind_rotations - 3 * n
    output_marginals = blind_rotations + 4 * n + (
        new_scan_marginals - new_scan_output
    )
    return OperationCounts(blind_rotations, key_switches, output_marginals)


def _variant_counts(
    gallery_size: int, radix: int, *, forward_singletons: bool
) -> OperationCounts:
    baseline = a38_counts(gallery_size)
    old_nodes = reduction_nodes(
        gallery_size, A38_REDUCTION_RADIX, forward_singletons=False
    )
    new_nodes = reduction_nodes(
        gallery_size, radix, forward_singletons=forward_singletons
    )
    saving = 8 * (old_nodes - new_nodes)
    delta = OperationCounts(saving, saving, saving)
    return baseline - delta


def a40_counts(gallery_size: int) -> OperationCounts:
    return _variant_counts(
        gallery_size, A40_REDUCTION_RADIX, forward_singletons=True
    )


def a50_counts(gallery_size: int) -> OperationCounts:
    return _variant_counts(
        gallery_size, A50_REDUCTION_RADIX, forward_singletons=True
    )


def size_count_row(gallery_size: int) -> SizeCountRow:
    a38 = a38_counts(gallery_size)
    a40 = a40_counts(gallery_size)
    a50 = a50_counts(gallery_size)
    return SizeCountRow(
        gallery_size=gallery_size,
        a38=a38,
        a40=a40,
        a50=a50,
        a50_delta_vs_a38=a50 - a38,
        a50_delta_vs_a40=a50 - a40,
        a38_or_nodes_per_bit=reduction_nodes(
            gallery_size, A38_REDUCTION_RADIX, forward_singletons=False
        ),
        a40_or_nodes_per_bit=reduction_nodes(
            gallery_size, A40_REDUCTION_RADIX, forward_singletons=True
        ),
        a50_or_nodes_per_bit=reduction_nodes(
            gallery_size, A50_REDUCTION_RADIX, forward_singletons=True
        ),
    )


def all_size_count_rows() -> tuple[SizeCountRow, ...]:
    """Exact BR/KS/marginal totals and deltas for every N in 1..128."""
    return tuple(size_count_row(n) for n in range(1, MAX_GALLERY_SIZE + 1))


def validate_all_two_template_inputs() -> PairValidationSummary:
    masks = tuple(itertools.product((False, True), repeat=2))
    cases = 0
    for candidates in masks:
        for first in range(256):
            for second in range(256):
                evaluate_a50(candidates, (first, second))
                cases += 1
    return PairValidationSummary(
        candidate_masks=len(masks),
        suffix_pairs=256 * 256,
        total_cases=cases,
    )


def summary(*, include_all_sizes: bool, validate_pairs: bool) -> dict[str, object]:
    reachability = reachability_audit()
    geometry = raw_geometry_audit()
    noise = noise_audit()
    selected = tuple(size_count_row(n) for n in (1, 2, 3, 64, 127, 128))
    n127 = a50_counts(127)
    result: dict[str, object] = {
        "verdict": "conditional_go_with_a44_max_noise_15",
        "scope": "only_eight_a36_gallery_wide_or_trees",
        "reachability": asdict(reachability),
        "raw_geometry": asdict(geometry),
        "noise": asdict(noise),
        "selected_counts": [asdict(row) for row in selected],
        "n127_conditional_union_log2": math.log2(n127.output_marginals)
        + A44_PER_EVENT_LOG2_P_FAIL,
        "end_to_end_numeric_upper": None,
        "open_obligations": (
            "implement the raw LUTs and canonical state machine in an isolated Rust candidate",
            "validate every reachable center and boundary under noisy FHE",
            "map custom raw LUT events to the A44 preset p-fail contract",
            "recount runtime BR, KS, and output marginals",
            "benchmark latency without changing scan/output radix five",
        ),
    }
    if include_all_sizes:
        result["all_n1_128_counts"] = [asdict(row) for row in all_size_count_rows()]
    if validate_pairs:
        result["exhaustive_two_template_validation"] = asdict(
            validate_all_two_template_inputs()
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--all-sizes",
        action="store_true",
        help="include exact A38/A40/A50 totals and deltas for every N=1..128",
    )
    parser.add_argument(
        "--validate-pairs",
        action="store_true",
        help="exhaust all four candidate masks and all 256^2 suffix pairs",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()
    payload = summary(
        include_all_sizes=args.all_sizes,
        validate_pairs=args.validate_pairs,
    )
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("A50 static verdict:", payload["verdict"])
        print("maximum raw L1:", payload["noise"]["maximum_raw_l1"])
        print("N=127 A50 counts:", asdict(a50_counts(127)))
        print("end-to-end numeric upper:", payload["end_to_end_numeric_upper"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
