#!/usr/bin/env python3
"""Clear model for the noise-bounded, non-fused A36 candidate update.

The A33 aligned path compares the remaining score bits ``b7..b0`` while a
Boolean ciphertext marks every still-live template.  A36 represents that state
at step two instead: live is ``2`` and dead states drift through
``0, -2, ..., -8``.  For every bit it computes

    z = 2 iff state == 2 and bit == 0
    a = 2 iff any template has z == 2
    state <- state + z - a

refreshes ``state == 2`` to step two after ``b4``, and emits an ordinary
``0/1`` Boolean after ``b0`` for the unchanged A33 scan.  The bit weights are
chosen from the ciphertext scales already produced by A33:
``(-2, -2, -2, -2, -2, 8, -4, -2)`` for ``b7..b0``.

The custom p=16 accumulator modeled here places its decision boundary in an
unused code slot.  Its open input margin is therefore ``Delta_bool``, twice the
usual half-slot margin.  This keeps the conservative linear L1 bound at or
below the parameter set's nominal ``max_noise_level=5`` after normalization.

This module is a clear, structural model only.  It does not execute TFHE, alter
the frozen A33 core, or establish an end-to-end cryptographic failure bound.
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import asdict, dataclass
from functools import cache
from itertools import product
from typing import Sequence


MAX_GALLERY_SIZE = 128
SCORE_BITS = (7, 6, 5, 4, 3, 2, 1, 0)
A33_SOURCE_WEIGHTS = (1, 1, 1, 1, 1, 8, 4, 2)
A36_BIT_WEIGHTS = (-2, -2, -2, -2, -2, 8, -4, -2)
CHUNK_END_LEVELS = (3, 7)
ACTIVE_CODE = 2
INACTIVE_CODE = 0
OR_RADIX = 4

P16 = 16
P32 = 32
POLYNOMIAL_SIZE = 2_048
P16_BOX_SIZE = POLYNOMIAL_SIZE // P16
P32_BOX_SIZE = POLYNOMIAL_SIZE // P32
BLIND_ROTATION_MODULUS = 2 * POLYNOMIAL_SIZE
BLIND_ROTATION_MODULUS_LOG = BLIND_ROTATION_MODULUS.bit_length() - 1
TORUS_BITS = 64
TORUS_MASK = (1 << TORUS_BITS) - 1
BOOL_DELTA_LOG = 59
BOOL_DELTA = 1 << BOOL_DELTA_LOG
STANDARD_P16_HALF_SLOT_MARGIN = BOOL_DELTA // 2
CUSTOM_OPEN_MARGIN = BOOL_DELTA
SHORTINT_MAX_NOISE_LEVEL = 5

CURRENT_A33_N127_PBS = 4_273
CURRENT_A33_N127_KS = 3_892
DEFAULT_VALIDATION_SEED = 0xA36_2026_0902


@dataclass(frozen=True)
class PrimitiveCounts:
    blind_rotations: int
    key_switches: int
    output_marginals: int


@dataclass(frozen=True)
class ReplacementCounts:
    gallery_size: int
    a33_alternating_updates: PrimitiveCounts
    a36_chunked_updates: PrimitiveCounts
    savings: PrimitiveCounts


@dataclass(frozen=True)
class ProjectedCoreCounts:
    blind_rotations: int
    key_switches: int


@dataclass(frozen=True)
class NoiseLevelAudit:
    bit_index: int
    bit_weight: int
    state_l1_before: int
    bit_l1: int
    zero_test_input_l1: int
    state_l1_after: int
    normalized_zero_test_l1: float


@dataclass(frozen=True)
class NoiseAudit:
    first_chunk_initial_l1: int
    second_chunk_initial_l1: int
    levels: tuple[NoiseLevelAudit, ...]
    boundary_canonicalizer_l1: int
    final_canonicalizer_l1: int
    or_node_l1: int
    custom_margin: int
    standard_margin: int
    conservative_max_noise_level: int
    worst_normalized_l1: float
    every_input_within_bound: bool


@dataclass(frozen=True)
class RawAccumulatorAudit:
    polynomial_size: int
    message_modulus: int
    box_size: int
    active_center_slots: tuple[int, ...]
    final_boolean_center_slots: tuple[int, ...]
    or_center_slots: tuple[int, ...]
    reachable_zero_inputs_by_level: tuple[tuple[int, ...], ...]
    reachable_boundary_states: tuple[int, ...]
    reachable_final_states: tuple[int, ...]
    target_code: int
    target_antipode: int
    target_antipode_reachable: bool
    open_rotation_margin: int
    open_torus_margin: int


@dataclass(frozen=True)
class InterlacedFusionAudit:
    bit_weight: int
    input_code_active_bit_one: int
    p32_sample_degrees: tuple[int, int]
    p32_sample_separation: int
    p32_sample_separation_torus: int
    maximum_simultaneous_open_margin: int
    optimistic_input_l1: int
    normalized_l1_at_maximum_margin: float
    conservative_max_noise_level: int
    valid: bool


@dataclass(frozen=True)
class InterlacedSearchAudit:
    bit_weights_checked: tuple[int, ...]
    sample_degrees_checked_per_weight: int
    public_offsets_checked_per_layout: int
    public_offset_quantum: int
    required_open_rotation_margin: int
    solutions: tuple[tuple[int, int, int, int], ...]


@dataclass(frozen=True)
class LevelTrace:
    bit_index: int
    bit_weight: int
    bits: tuple[int, ...]
    zero_test_inputs: tuple[int, ...]
    zero_candidates: tuple[int, ...]
    any_zero: int
    states_after_linear_update: tuple[int, ...]
    states_after_optional_refresh: tuple[int, ...]
    refreshed: bool


@dataclass(frozen=True)
class A36Trace:
    gallery_size: int
    initial_candidates: tuple[bool, ...]
    suffixes: tuple[int, ...]
    levels: tuple[LevelTrace, ...]
    final_candidates: tuple[bool, ...]
    reference_candidates: tuple[bool, ...]
    code: int
    reference_code: int


@dataclass(frozen=True)
class ValidationSummary:
    gallery_sizes_checked: int
    all_reject_cases: int
    unique_winner_cases: int
    no_resurrection_cases: int
    tie_cases: int
    deterministic_random_cases: int
    exhaustive_small_cases: int
    max_gallery_pair_cases: int
    total_cases: int
    seed: int


def _validate_gallery_inputs(
    candidates: Sequence[bool | int], suffixes: Sequence[int]
) -> tuple[tuple[bool, ...], tuple[int, ...]]:
    raw_candidates = tuple(candidates)
    raw_suffixes = tuple(suffixes)
    if not 1 <= len(raw_candidates) <= MAX_GALLERY_SIZE:
        raise ValueError(f"gallery size must be in 1..{MAX_GALLERY_SIZE}")
    if len(raw_candidates) != len(raw_suffixes):
        raise ValueError("candidate and suffix vectors must have equal length")
    if any(value not in (False, True, 0, 1) for value in raw_candidates):
        raise ValueError("candidate values must be Boolean")
    if any(
        not isinstance(value, int) or not 0 <= value <= 0xFF for value in raw_suffixes
    ):
        raise ValueError("suffix values must be bytes")
    return tuple(bool(value) for value in raw_candidates), raw_suffixes


def negacyclic_coefficient(body: Sequence[int], degree: int) -> int:
    """Read a signed raw polynomial coefficient in Z[X]/(X^N+1)."""
    if len(body) != POLYNOMIAL_SIZE:
        raise ValueError("unexpected accumulator polynomial size")
    cycles, index = divmod(degree, POLYNOMIAL_SIZE)
    return -body[index] if cycles % 2 else body[index]


def tfhe_modulus_switch_u64(phase: int) -> int:
    """Reproduce the rounded native-torus switch used before blind rotation."""
    if not 0 <= phase <= TORUS_MASK:
        raise ValueError("phase must be a native u64 value")
    rounding = 1 << (TORUS_BITS - BLIND_ROTATION_MODULUS_LOG - 1)
    return ((phase + rounding) & TORUS_MASK) >> (
        TORUS_BITS - BLIND_ROTATION_MODULUS_LOG
    )


def sample_after_noiseless_blind_rotation(
    body: Sequence[int], input_phase: int, sample_degree: int = 0
) -> int:
    if not 0 <= sample_degree < POLYNOMIAL_SIZE:
        raise ValueError("sample degree is outside the GLWE polynomial")
    rotation = tfhe_modulus_switch_u64(input_phase)
    return negacyclic_coefficient(body, rotation + sample_degree)


def sample_signed_code(
    body: Sequence[int], code: int, rotation_error: int = 0, sample_degree: int = 0
) -> int:
    """Sample a logical ``code * Delta_bool`` plus an exact rotation error."""
    center = (code % (2 * P16)) * P16_BOX_SIZE
    return negacyclic_coefficient(body, center + rotation_error + sample_degree)


@cache
def step2_active_accumulator_body() -> tuple[int, ...]:
    """Raw p=16 body with output 2 on the open-margin neighborhood of code 2.

    The half-open plateau ``[1, 3)`` places both decision boundaries in unused
    code slots.  Negacyclic extension supplies output -2 around antipode 18.
    """
    body = [0] * POLYNOMIAL_SIZE
    body[P16_BOX_SIZE : 3 * P16_BOX_SIZE] = [ACTIVE_CODE] * (2 * P16_BOX_SIZE)
    return tuple(body)


@cache
def final_boolean_accumulator_body() -> tuple[int, ...]:
    """Raw p=16 finalizer with the same margin and ordinary Boolean output."""
    body = [0] * POLYNOMIAL_SIZE
    body[P16_BOX_SIZE : 3 * P16_BOX_SIZE] = [1] * (2 * P16_BOX_SIZE)
    return tuple(body)


@cache
def step2_or_accumulator_body() -> tuple[int, ...]:
    """Raw p=16 OR body for sums 0,2,4,6,8, with output at step two."""
    body = [0] * POLYNOMIAL_SIZE
    body[P16_BOX_SIZE : 9 * P16_BOX_SIZE] = [ACTIVE_CODE] * (8 * P16_BOX_SIZE)
    return tuple(body)


def _or_reduce_step2(values: Sequence[int]) -> int:
    if not values:
        raise ValueError("OR reduction requires at least one value")
    if any(value not in (INACTIVE_CODE, ACTIVE_CODE) for value in values):
        raise ValueError("OR inputs must use the step-two Boolean encoding")
    body = step2_or_accumulator_body()
    level = tuple(values)
    while len(level) > 1:
        level = tuple(
            sample_signed_code(body, sum(level[start : start + OR_RADIX]))
            for start in range(0, len(level), OR_RADIX)
        )
    return level[0]


def _reference_candidates(
    candidates: tuple[bool, ...], suffixes: tuple[int, ...]
) -> tuple[bool, ...]:
    live_values = [value for candidate, value in zip(candidates, suffixes) if candidate]
    if not live_values:
        return tuple(False for _ in candidates)
    minimum = min(live_values)
    return tuple(
        candidate and value == minimum for candidate, value in zip(candidates, suffixes)
    )


def evaluate_a36_chunked_candidates(
    candidates: Sequence[bool | int], suffixes: Sequence[int]
) -> A36Trace:
    """Evaluate the two-chunk state machine and return all clear checkpoints."""
    canonical_candidates, canonical_suffixes = _validate_gallery_inputs(
        candidates, suffixes
    )
    active_body = step2_active_accumulator_body()
    final_body = final_boolean_accumulator_body()
    states = tuple(
        ACTIVE_CODE if candidate else INACTIVE_CODE
        for candidate in canonical_candidates
    )
    levels: list[LevelTrace] = []

    for level, (bit_index, bit_weight) in enumerate(zip(SCORE_BITS, A36_BIT_WEIGHTS)):
        bits = tuple((value >> bit_index) & 1 for value in canonical_suffixes)
        inputs = tuple(state + bit_weight * bit for state, bit in zip(states, bits))
        zero_candidates = tuple(
            sample_signed_code(active_body, value) for value in inputs
        )
        if any(value not in (INACTIVE_CODE, ACTIVE_CODE) for value in zero_candidates):
            raise AssertionError("reachable zero-test input hit a negacyclic antipode")
        any_zero = _or_reduce_step2(zero_candidates)
        updated = tuple(
            state + zero - any_zero for state, zero in zip(states, zero_candidates)
        )
        refreshed = level in CHUNK_END_LEVELS
        if level == CHUNK_END_LEVELS[0]:
            next_states = tuple(
                sample_signed_code(active_body, state) for state in updated
            )
        elif level == CHUNK_END_LEVELS[1]:
            next_states = tuple(
                sample_signed_code(final_body, state) for state in updated
            )
        else:
            next_states = updated
        levels.append(
            LevelTrace(
                bit_index=bit_index,
                bit_weight=bit_weight,
                bits=bits,
                zero_test_inputs=inputs,
                zero_candidates=zero_candidates,
                any_zero=any_zero,
                states_after_linear_update=updated,
                states_after_optional_refresh=next_states,
                refreshed=refreshed,
            )
        )
        states = next_states

    final_candidates = tuple(state == 1 for state in states)
    reference = _reference_candidates(canonical_candidates, canonical_suffixes)
    code = next(
        (index + 1 for index, candidate in enumerate(final_candidates) if candidate), 0
    )
    reference_code = next(
        (index + 1 for index, candidate in enumerate(reference) if candidate), 0
    )
    if final_candidates != reference or code != reference_code:
        raise AssertionError(
            "A36 state machine disagrees with lexicographic minimum semantics"
        )
    return A36Trace(
        gallery_size=len(canonical_candidates),
        initial_candidates=canonical_candidates,
        suffixes=canonical_suffixes,
        levels=tuple(levels),
        final_candidates=final_candidates,
        reference_candidates=reference,
        code=code,
        reference_code=reference_code,
    )


def _reachable_sets() -> tuple[
    tuple[tuple[int, ...], ...], tuple[int, ...], tuple[int, ...]
]:
    states = {INACTIVE_CODE, ACTIVE_CODE}
    inputs_by_level: list[tuple[int, ...]] = []
    boundary_states: tuple[int, ...] = ()
    active_body = step2_active_accumulator_body()
    final_body = final_boolean_accumulator_body()

    for level, weight in enumerate(A36_BIT_WEIGHTS):
        inputs = {state + weight * bit for state in states for bit in (0, 1)}
        inputs_by_level.append(tuple(sorted(inputs)))
        next_states: set[int] = set()
        for state in states:
            for bit in (0, 1):
                zero = sample_signed_code(active_body, state + weight * bit)
                possible_any = (
                    (ACTIVE_CODE,) if zero == ACTIVE_CODE else (0, ACTIVE_CODE)
                )
                for any_zero in possible_any:
                    next_states.add(state + zero - any_zero)
        if level == CHUNK_END_LEVELS[0]:
            boundary_states = tuple(sorted(next_states))
            states = {sample_signed_code(active_body, state) for state in next_states}
        elif level == CHUNK_END_LEVELS[1]:
            final_states = tuple(sorted(next_states))
            states = {sample_signed_code(final_body, state) for state in next_states}
        else:
            states = next_states
    return tuple(inputs_by_level), boundary_states, final_states


def raw_accumulator_audit() -> RawAccumulatorAudit:
    active_body = step2_active_accumulator_body()
    final_body = final_boolean_accumulator_body()
    or_body = step2_or_accumulator_body()
    inputs_by_level, boundary_states, final_states = _reachable_sets()
    reachable_inputs = {
        value % (2 * P16) for values in inputs_by_level for value in values
    }
    reachable_states = {value % (2 * P16) for value in boundary_states + final_states}
    target_antipode = ACTIVE_CODE + P16

    for values in inputs_by_level:
        for value in values:
            expected = ACTIVE_CODE if value == ACTIVE_CODE else INACTIVE_CODE
            if sample_signed_code(active_body, value) != expected:
                raise AssertionError(
                    "active LUT center is not exact on a reachable input"
                )
            for error in range(-P16_BOX_SIZE + 1, P16_BOX_SIZE):
                if sample_signed_code(active_body, value, error) != expected:
                    raise AssertionError(
                        "active LUT does not preserve its open Delta margin"
                    )
    for value in boundary_states + final_states:
        expected = ACTIVE_CODE if value == ACTIVE_CODE else INACTIVE_CODE
        for error in range(-P16_BOX_SIZE + 1, P16_BOX_SIZE):
            if sample_signed_code(active_body, value, error) != expected:
                raise AssertionError(
                    "canonicalizer does not preserve its open Delta margin"
                )
            final_expected = 1 if value == ACTIVE_CODE else 0
            if sample_signed_code(final_body, value, error) != final_expected:
                raise AssertionError(
                    "final Boolean LUT does not preserve its open Delta margin"
                )
    for count_code in (0, 2, 4, 6, 8):
        expected = ACTIVE_CODE if count_code else INACTIVE_CODE
        for error in range(-P16_BOX_SIZE + 1, P16_BOX_SIZE):
            if sample_signed_code(or_body, count_code, error) != expected:
                raise AssertionError("OR LUT does not preserve its open Delta margin")

    return RawAccumulatorAudit(
        polynomial_size=POLYNOMIAL_SIZE,
        message_modulus=P16,
        box_size=P16_BOX_SIZE,
        active_center_slots=tuple(
            sample_signed_code(active_body, code) for code in range(2 * P16)
        ),
        final_boolean_center_slots=tuple(
            sample_signed_code(final_body, code) for code in range(2 * P16)
        ),
        or_center_slots=tuple(
            sample_signed_code(or_body, code) for code in range(2 * P16)
        ),
        reachable_zero_inputs_by_level=inputs_by_level,
        reachable_boundary_states=boundary_states,
        reachable_final_states=final_states,
        target_code=ACTIVE_CODE,
        target_antipode=target_antipode,
        target_antipode_reachable=(
            target_antipode in reachable_inputs or target_antipode in reachable_states
        ),
        open_rotation_margin=P16_BOX_SIZE,
        open_torus_margin=CUSTOM_OPEN_MARGIN,
    )


def noise_audit() -> NoiseAudit:
    levels: list[NoiseLevelAudit] = []
    state_l1 = 2  # clear multiplication of the existing fresh A33 candidate by two
    boundary_l1 = 0
    bit_l1_values = (2, 2, 2, 2, 2, 1, 1, 1)

    for level, (bit_index, bit_weight, bit_l1) in enumerate(
        zip(SCORE_BITS, A36_BIT_WEIGHTS, bit_l1_values)
    ):
        input_l1 = state_l1 + bit_l1
        state_after = state_l1 + 2  # one fresh z and one fresh global a
        levels.append(
            NoiseLevelAudit(
                bit_index=bit_index,
                bit_weight=bit_weight,
                state_l1_before=state_l1,
                bit_l1=bit_l1,
                zero_test_input_l1=input_l1,
                state_l1_after=state_after,
                normalized_zero_test_l1=input_l1 / 2,
            )
        )
        state_l1 = state_after
        if level == CHUNK_END_LEVELS[0]:
            boundary_l1 = state_l1
            state_l1 = 1  # fresh canonicalizer output

    final_l1 = state_l1
    normalized = [entry.normalized_zero_test_l1 for entry in levels]
    normalized.extend((boundary_l1 / 2, final_l1 / 2, OR_RADIX / 2))
    worst = max(normalized)
    return NoiseAudit(
        first_chunk_initial_l1=2,
        second_chunk_initial_l1=1,
        levels=tuple(levels),
        boundary_canonicalizer_l1=boundary_l1,
        final_canonicalizer_l1=final_l1,
        or_node_l1=OR_RADIX,
        custom_margin=CUSTOM_OPEN_MARGIN,
        standard_margin=STANDARD_P16_HALF_SLOT_MARGIN,
        conservative_max_noise_level=SHORTINT_MAX_NOISE_LEVEL,
        worst_normalized_l1=worst,
        every_input_within_bound=worst <= SHORTINT_MAX_NOISE_LEVEL,
    )


def interlaced_b13_fusion_audit() -> InterlacedFusionAudit:
    """Return the geometric counterexample to the proposed raw p=32 fusion.

    At active state 2 and bit one, B=13 gives input code 15.  Degree zero and
    degree N/32 read adjacent p=32 boxes, but must output 2 and 0.  Public output
    offsets cannot remove every such disagreement: making the two raw outputs
    equal for inactive ``(0, 0)`` forces unequal raw outputs for active-bit-one
    ``(2, 0)``, and vice versa.  The maximum simultaneous margin is therefore
    half their separation, Delta_bool/4.
    """
    separation_torus = BOOL_DELTA // 2
    maximum_margin = separation_torus // 2
    optimistic_input_l1 = 10
    normalized = optimistic_input_l1 * (STANDARD_P16_HALF_SLOT_MARGIN / maximum_margin)
    return InterlacedFusionAudit(
        bit_weight=13,
        input_code_active_bit_one=15,
        p32_sample_degrees=(0, P32_BOX_SIZE),
        p32_sample_separation=P32_BOX_SIZE,
        p32_sample_separation_torus=separation_torus,
        maximum_simultaneous_open_margin=maximum_margin,
        optimistic_input_l1=optimistic_input_l1,
        normalized_l1_at_maximum_margin=normalized,
        conservative_max_noise_level=SHORTINT_MAX_NOISE_LEVEL,
        valid=normalized <= SHORTINT_MAX_NOISE_LEVEL,
    )


@cache
def interlaced_full_margin_search() -> InterlacedSearchAudit:
    """Exhaust raw two-sample layouts that could replace the boundary refresh.

    The search covers every nonzero bit weight modulo 32, every second sample
    degree in ``1..N-1``, and both public output offsets.  Offsets are enumerated
    at ``Delta_bool/2``: this is exhaustive for feasibility because all desired
    outputs are multiples of ``2*Delta_bool`` and every equality introduced by
    anti-periodicity has coefficients in ``{-2,-1,0,1,2}``.  Any continuous
    solution therefore has a representative on this half-Delta lattice.

    A layout has full open margin only if every pair of differently labeled raw
    samples is separated by at least ``2*N/16`` rotation degrees.  Constraint
    compatibility is represented as a bit set over all 64^2 offset pairs.
    """
    offset_modulus = 64
    offset_pairs = tuple(
        (left, right)
        for left in range(offset_modulus)
        for right in range(offset_modulus)
    )
    inactive_states = (0, -2, -4, -6, -8)

    # Row: state, bit, output kind (0=canonical, 1=z), constant,
    # offset-left coefficient, offset-right coefficient, antipode flag.
    rows: list[tuple[int, int, int, int, int, int, int]] = []
    for active, state in ((True, ACTIVE_CODE),) + tuple(
        (False, value) for value in inactive_states
    ):
        for bit in (0, 1):
            canonical = 4 if active else 0
            zero = 4 if active and bit == 0 else 0
            rows.extend(
                (
                    (state, bit, 0, canonical, -1, 0, 0),
                    (state, bit, 1, zero, 0, -1, 0),
                    (state, bit, 0, (-canonical) % offset_modulus, 1, 0, 1),
                    (state, bit, 1, (-zero) % offset_modulus, 0, 1, 1),
                )
            )

    all_offsets = (1 << len(offset_pairs)) - 1
    equality_masks: dict[tuple[int, int], int] = {}
    for left in range(len(rows)):
        left_constant, left_a, left_b = rows[left][3:6]
        for right in range(left + 1, len(rows)):
            right_constant, right_a, right_b = rows[right][3:6]
            mask = 0
            for index, (offset_a, offset_b) in enumerate(offset_pairs):
                left_value = (
                    left_constant + left_a * offset_a + left_b * offset_b
                ) % offset_modulus
                right_value = (
                    right_constant + right_a * offset_a + right_b * offset_b
                ) % offset_modulus
                if left_value == right_value:
                    mask |= 1 << index
            equality_masks[left, right] = mask

    solutions: list[tuple[int, int, int, int]] = []
    required_separation = 2 * P16_BOX_SIZE
    for bit_weight in range(1, 2 * P16):
        for sample_degree in range(1, POLYNOMIAL_SIZE):
            positions = []
            for state, bit, output_kind, _, _, _, antipode in rows:
                input_code = (state + bit_weight * bit) % (2 * P16)
                position = input_code * P16_BOX_SIZE
                if output_kind == 1:
                    position += sample_degree
                if antipode:
                    position += POLYNOMIAL_SIZE
                positions.append(position % BLIND_ROTATION_MODULUS)

            feasible_offsets = all_offsets
            for left, left_position in enumerate(positions):
                for right in range(left + 1, len(positions)):
                    right_position = positions[right]
                    distance = min(
                        (right_position - left_position) % BLIND_ROTATION_MODULUS,
                        (left_position - right_position) % BLIND_ROTATION_MODULUS,
                    )
                    if distance < required_separation:
                        feasible_offsets &= equality_masks[left, right]
                        if not feasible_offsets:
                            break
                if not feasible_offsets:
                    break
            if feasible_offsets:
                offset_index = (feasible_offsets & -feasible_offsets).bit_length() - 1
                offset_a, offset_b = offset_pairs[offset_index]
                solutions.append((bit_weight, sample_degree, offset_a, offset_b))

    return InterlacedSearchAudit(
        bit_weights_checked=tuple(range(1, 2 * P16)),
        sample_degrees_checked_per_weight=POLYNOMIAL_SIZE - 1,
        public_offsets_checked_per_layout=len(offset_pairs),
        public_offset_quantum=BOOL_DELTA // 2,
        required_open_rotation_margin=P16_BOX_SIZE,
        solutions=tuple(solutions),
    )


def replacement_counts(gallery_size: int) -> ReplacementCounts:
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError(f"gallery size must be in 1..{MAX_GALLERY_SIZE}")
    baseline = PrimitiveCounts(*(12 * gallery_size,) * 3)
    candidate = PrimitiveCounts(*(10 * gallery_size,) * 3)
    savings = PrimitiveCounts(*(2 * gallery_size,) * 3)
    return ReplacementCounts(
        gallery_size=gallery_size,
        a33_alternating_updates=baseline,
        a36_chunked_updates=candidate,
        savings=savings,
    )


def projected_n127_totals() -> ProjectedCoreCounts:
    savings = replacement_counts(127).savings
    return ProjectedCoreCounts(
        blind_rotations=CURRENT_A33_N127_PBS - savings.blind_rotations,
        key_switches=CURRENT_A33_N127_KS - savings.key_switches,
    )


def _assert_matches_reference(
    candidates: Sequence[bool | int], suffixes: Sequence[int]
) -> None:
    trace = evaluate_a36_chunked_candidates(candidates, suffixes)
    if (
        trace.final_candidates != trace.reference_candidates
        or trace.code != trace.reference_code
    ):
        raise AssertionError("A36 validation mismatch")


def validate_model(
    *,
    random_patterns_per_size: int = 8,
    exhaustive_through: int = 5,
    include_max_gallery_pairs: bool = True,
    seed: int = DEFAULT_VALIDATION_SEED,
) -> ValidationSummary:
    """Run deterministic exhaustive and adversarial clear checks through N=128."""
    if random_patterns_per_size < 0:
        raise ValueError("random_patterns_per_size cannot be negative")
    if not 0 <= exhaustive_through <= 8:
        raise ValueError("exhaustive_through must be in 0..8")
    raw_accumulator_audit()
    audit = noise_audit()
    if not audit.every_input_within_bound:
        raise AssertionError("A36 exceeds the conservative normalized noise bound")
    if interlaced_b13_fusion_audit().valid:
        raise AssertionError("the rejected p=32 fusion unexpectedly passed")

    rng = random.Random(seed)
    all_reject_cases = 0
    unique_winner_cases = 0
    no_resurrection_cases = 0
    tie_cases = 0
    random_cases = 0
    exhaustive_cases = 0
    pair_cases = 0

    for gallery_size in range(1, MAX_GALLERY_SIZE + 1):
        _assert_matches_reference([False] * gallery_size, [0] * gallery_size)
        all_reject_cases += 1

        _assert_matches_reference([True] * gallery_size, [173] * gallery_size)
        tie_cases += 1

        for winner in range(gallery_size):
            suffixes = [255] * gallery_size
            suffixes[winner] = 0
            _assert_matches_reference([True] * gallery_size, suffixes)
            unique_winner_cases += 1

            candidates = [False] * gallery_size
            candidates[winner] = True
            suffixes = [0] * gallery_size
            suffixes[winner] = 255
            _assert_matches_reference(candidates, suffixes)
            no_resurrection_cases += 1

        for _ in range(random_patterns_per_size):
            candidates = [bool(rng.getrandbits(1)) for _ in range(gallery_size)]
            suffixes = [rng.randrange(256) for _ in range(gallery_size)]
            _assert_matches_reference(candidates, suffixes)
            random_cases += 1

    # Each template independently takes one of four adversarial states.  Two
    # have an active bit and two are deliberately inactive with extreme scores.
    states = ((False, 0), (False, 255), (True, 0), (True, 255))
    for gallery_size in range(1, exhaustive_through + 1):
        for case in product(states, repeat=gallery_size):
            candidates, suffixes = zip(*case)
            _assert_matches_reference(candidates, suffixes)
            exhaustive_cases += 1

    if include_max_gallery_pairs:
        gallery_size = MAX_GALLERY_SIZE
        for left in range(gallery_size):
            for right in range(left + 1, gallery_size):
                suffixes = [255] * gallery_size
                suffixes[left] = 0
                suffixes[right] = 0
                _assert_matches_reference([True] * gallery_size, suffixes)
                pair_cases += 1

    total = (
        all_reject_cases
        + unique_winner_cases
        + no_resurrection_cases
        + tie_cases
        + random_cases
        + exhaustive_cases
        + pair_cases
    )
    return ValidationSummary(
        gallery_sizes_checked=MAX_GALLERY_SIZE,
        all_reject_cases=all_reject_cases,
        unique_winner_cases=unique_winner_cases,
        no_resurrection_cases=no_resurrection_cases,
        tie_cases=tie_cases,
        deterministic_random_cases=random_cases,
        exhaustive_small_cases=exhaustive_cases,
        max_gallery_pair_cases=pair_cases,
        total_cases=total,
        seed=seed,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--random-patterns-per-size", type=int, default=8)
    parser.add_argument("--exhaustive-through", type=int, default=5)
    parser.add_argument("--skip-max-gallery-pairs", action="store_true")
    args = parser.parse_args()
    summary = validate_model(
        random_patterns_per_size=args.random_patterns_per_size,
        exhaustive_through=args.exhaustive_through,
        include_max_gallery_pairs=not args.skip_max_gallery_pairs,
    )
    output = {
        "status": "clear_model_valid_non_fused_only",
        "validation": asdict(summary),
        "raw_accumulator": asdict(raw_accumulator_audit()),
        "noise": asdict(noise_audit()),
        "rejected_interlaced_fusion": asdict(interlaced_b13_fusion_audit()),
        "interlaced_full_margin_search": asdict(interlaced_full_margin_search()),
        "n127_replacement": asdict(replacement_counts(127)),
        "n127_projected_totals": asdict(projected_n127_totals()),
    }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
