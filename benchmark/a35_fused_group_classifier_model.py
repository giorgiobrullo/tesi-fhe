#!/usr/bin/env python3
"""Clear model of the separate, noise-blocked A35 fused group classifier.

The proposed optimization starts from three fresh Boolean candidate ciphertexts
``c0, c1, c2`` at ``Delta_bool = 2^59`` and forms

    2 * (c0 + 2*c1 + 4*c2).

This addresses even p=16 slots ``2*x`` for ``x in 0..7``.  One blind rotation
then exposes the group flag at sample degree zero and the group-local first-live
position at degree ``N/16``.  A one- or two-item gallery tail is modeled
explicitly; a singleton is cloned and performs no blind rotation.

The module reproduces the signed coefficient layout made by tfhe-rs 0.11.3's
``generate_programmable_bootstrap_glwe_lut`` and its noiseless
``polynomial_wrapping_monic_monomial_div`` sampling convention.  It also plugs
the fused pair of outputs into the unchanged A34 two-nibble clear downstream so
that exact first-ID, all-reject, tie-first, and no-resurrection semantics can be
checked for every gallery size 1..128.

This is deliberately *not* an implementation candidate yet.  The direct input
has fresh-output linear L1 weight 14, above the parameter set's conservative
``max_noise_level=5``.  An exhaustive integer-coefficient collision search
proves that any scalar linear encoding capable of separating the four priority
classes has L1 weight at least 7.  Thus even the better unscaled/N/2 layout is
still outside that conservative bound.  This clear model performs no FHE and
makes no cryptographic failure-probability claim.
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import asdict, dataclass
from functools import cache
from itertools import product
from typing import Callable, Sequence


MAX_GALLERY_SIZE = 128
GROUP_SIZE = 3
OR_RADIX = 4
P16 = 16
POLYNOMIAL_SIZE = 2_048
BOX_SIZE = POLYNOMIAL_SIZE // P16
HALF_BOX_SIZE = BOX_SIZE // 2
BLIND_ROTATION_MODULUS = 2 * POLYNOMIAL_SIZE
BLIND_ROTATION_MODULUS_LOG = BLIND_ROTATION_MODULUS.bit_length() - 1
TORUS_BITS = 64
TORUS_MASK = (1 << TORUS_BITS) - 1
BOOL_DELTA_LOG = 59
BOOL_DELTA = 1 << BOOL_DELTA_LOG
CODE_DELTA_LOG = 56
FUSED_SAMPLE_DEGREES = (0, BOX_SIZE)
PROPOSED_INPUT_COEFFICIENTS = (2, 4, 8)
UNSCALED_INPUT_COEFFICIENTS = (1, 2, 4)
SHORTINT_MAX_NOISE_LEVEL = 5
DEFAULT_VALIDATION_SEED = 0xA35_2026_0902


@dataclass(frozen=True)
class PrimitiveCounts:
    blind_rotations: int
    key_switches: int
    output_marginals: int


@dataclass(frozen=True)
class FusedAccumulatorLayout:
    polynomial_size: int
    message_modulus: int
    box_size: int
    half_box_size: int
    logical_slots: tuple[int, ...]
    virtual_signed_slots: tuple[int, ...]
    sample_degrees: tuple[int, int]
    input_delta_log: int
    output_delta_log: int
    half_slot_torus_margin: int


@dataclass(frozen=True)
class FusedGroupTrace:
    group_length: int
    candidates: tuple[bool, ...]
    padded_candidates: tuple[bool, bool, bool]
    pattern: int
    input_logical_slot: int
    input_torus_phase: int
    blind_rotation_degree: int
    sample_degrees: tuple[int, int]
    group_flag: bool
    local_first: int
    reference_flag: bool
    reference_local_first: int
    used_blind_rotation: bool


@dataclass(frozen=True)
class A35GroupOutputTrace:
    group_index: int
    group: FusedGroupTrace
    prefix: bool
    selector_state: int
    selected_code: int
    low_nibble: int
    high_nibble: int
    active: bool


@dataclass(frozen=True)
class A35FusedCircuitTrace:
    gallery_size: int
    candidates: tuple[bool, ...]
    group_flags: tuple[bool, ...]
    group_prefixes: tuple[bool, ...]
    groups: tuple[A35GroupOutputTrace, ...]
    final_code_outputs: tuple[int, int]
    code: int


@dataclass(frozen=True)
class A35FusedStageCounts:
    gallery_size: int
    groups: int
    fused_group_blind_rotations: int
    fused_group_output_marginals: int
    group_prefix_blind_rotations: int
    dual_selector_blind_rotations: int
    digit_reduction_blind_rotations: int
    scan_output_blind_rotations: int
    scan_output_key_switches: int
    scan_output_marginals: int
    final_code_outputs: int


@dataclass(frozen=True)
class LinearEncodingAudit:
    proposed_coefficients: tuple[int, int, int]
    proposed_l1: int
    proposed_squared_l2: int
    conservative_max_noise_level: int
    minimum_exact_priority_l1: int
    minimum_witness: tuple[int, int, int]
    unscaled_witness_l1: int
    proposed_within_conservative_bound: bool
    minimum_within_conservative_bound: bool


@dataclass(frozen=True)
class ValidationSummary:
    gallery_sizes_checked: int
    all_reject_cases: int
    winner_positions_checked: int
    systematic_adversarial_cases: int
    deterministic_random_cases: int
    exhaustive_small_cases: int
    max_gallery_pair_cases: int
    total_cases: int
    exhaustive_through: int
    random_patterns_per_winner: int
    seed: int


def _priority_outputs(bits: Sequence[bool | int]) -> tuple[int, int]:
    """Return ``(any, first-one-based-position)`` for exactly three bits."""
    if len(bits) != GROUP_SIZE or any(bit not in (False, True, 0, 1) for bit in bits):
        raise ValueError("priority input must contain exactly three Boolean values")
    canonical = tuple(bool(bit) for bit in bits)
    local_first = next(
        (index + 1 for index, candidate in enumerate(canonical) if candidate), 0
    )
    return int(local_first != 0), local_first


@cache
def fused_logical_slots() -> tuple[int, ...]:
    """Return the sixteen independent p=16 outputs in even/odd pairs."""
    slots: list[int] = []
    for pattern in range(1 << GROUP_SIZE):
        bits = tuple(bool((pattern >> index) & 1) for index in range(GROUP_SIZE))
        flag, local_first = _priority_outputs(bits)
        slots.extend((flag, local_first))
    result = tuple(slots)
    assert len(result) == P16
    return result


@cache
def _tfhe_generate_lut_signed_body_cached(
    logical_slots: tuple[int, ...],
) -> tuple[int, ...]:
    body = [value for value in logical_slots for _ in range(BOX_SIZE)]
    for index in range(HALF_BOX_SIZE):
        body[index] = -body[index]
    body = body[HALF_BOX_SIZE:] + body[:HALF_BOX_SIZE]
    assert len(body) == POLYNOMIAL_SIZE
    return tuple(body)


def tfhe_generate_lut_signed_body(logical_slots: Sequence[int]) -> tuple[int, ...]:
    """Signed-unit analogue of tfhe-rs 0.11.3's GLWE LUT helper.

    The helper fills one box per independent slot, negates the first half of
    box zero for native-modulus anti-periodicity, then rotates the polynomial
    left by half a box.  Rust stores negative torus coefficients by wrapping;
    signed units make that convention directly inspectable here.
    """
    slots = tuple(logical_slots)
    if len(slots) != P16:
        raise ValueError("a p=16 accumulator requires sixteen logical slots")
    return _tfhe_generate_lut_signed_body_cached(slots)


def tfhe_generate_lut_u64_body(logical_slots: Sequence[int]) -> tuple[int, ...]:
    """Return the actual native-u64 torus coefficients at ``Delta_bool``."""
    return tuple(
        (coefficient * BOOL_DELTA) & TORUS_MASK
        for coefficient in tfhe_generate_lut_signed_body(logical_slots)
    )


def negacyclic_coefficient(body: Sequence[int], degree: int) -> int:
    """Read ``body[degree]`` in Z[X]/(X^N+1), including negative degrees."""
    if len(body) != POLYNOMIAL_SIZE:
        raise ValueError("unexpected accumulator polynomial size")
    cycles, index = divmod(degree, POLYNOMIAL_SIZE)
    return -body[index] if cycles % 2 else body[index]


def tfhe_modulus_switch_u64(phase: int) -> int:
    """Reproduce tfhe-rs' rounded native-torus PBS modulus switch."""
    if not 0 <= phase <= TORUS_MASK:
        raise ValueError("phase must be a native u64 torus value")
    rounding = 1 << (TORUS_BITS - BLIND_ROTATION_MODULUS_LOG - 1)
    rounded = (phase + rounding) & TORUS_MASK
    return rounded >> (TORUS_BITS - BLIND_ROTATION_MODULUS_LOG)


def sample_after_noiseless_blind_rotation(
    body: Sequence[int], input_phase: int, sample_degree: int
) -> int:
    """Model division by ``X^d`` followed by one GLWE sample extraction.

    If ``B(X)=A(X)/X^d``, coefficient ``r`` of ``B`` is the negacyclic
    extension of ``A[d+r]``.  This is the exact clear convention used by
    ``polynomial_wrapping_monic_monomial_div`` during blind rotation.
    """
    if not 0 <= sample_degree < POLYNOMIAL_SIZE:
        raise ValueError("sample degree is outside the GLWE polynomial")
    monomial_degree = tfhe_modulus_switch_u64(input_phase)
    return negacyclic_coefficient(body, monomial_degree + sample_degree)


def fused_accumulator_layout() -> FusedAccumulatorLayout:
    slots = fused_logical_slots()
    body = tfhe_generate_lut_signed_body(slots)
    centered = tuple(
        negacyclic_coefficient(body, slot * BOX_SIZE) for slot in range(P16)
    )
    virtual = tuple(
        negacyclic_coefficient(body, slot * BOX_SIZE) for slot in range(2 * P16)
    )
    assert centered == slots
    assert virtual == slots + tuple(-value for value in slots)
    return FusedAccumulatorLayout(
        polynomial_size=POLYNOMIAL_SIZE,
        message_modulus=P16,
        box_size=BOX_SIZE,
        half_box_size=HALF_BOX_SIZE,
        logical_slots=slots,
        virtual_signed_slots=virtual,
        sample_degrees=FUSED_SAMPLE_DEGREES,
        input_delta_log=BOOL_DELTA_LOG,
        output_delta_log=BOOL_DELTA_LOG,
        half_slot_torus_margin=BOOL_DELTA // 2,
    )


def _canonical_group(group: Sequence[bool | int]) -> tuple[bool, ...]:
    values = tuple(group)
    if not 1 <= len(values) <= GROUP_SIZE:
        raise ValueError("a group must contain one, two, or three candidates")
    if any(value not in (False, True, 0, 1) for value in values):
        raise ValueError("group candidates must be Boolean")
    return tuple(bool(value) for value in values)


@cache
def _evaluate_fused_group_cached(canonical: tuple[bool, ...]) -> FusedGroupTrace:
    padded = canonical + (False,) * (GROUP_SIZE - len(canonical))
    pattern = sum(int(bit) << index for index, bit in enumerate(padded))
    input_slot = 2 * pattern
    input_phase = input_slot * BOOL_DELTA
    degree = tfhe_modulus_switch_u64(input_phase)
    reference_flag, reference_local = _priority_outputs(padded)

    if len(canonical) == 1:
        flag = int(canonical[0])
        local_first = flag
        used_blind_rotation = False
    else:
        body = tfhe_generate_lut_signed_body(fused_logical_slots())
        flag = sample_after_noiseless_blind_rotation(body, input_phase, 0)
        local_first = sample_after_noiseless_blind_rotation(body, input_phase, BOX_SIZE)
        used_blind_rotation = True

    if (flag, local_first) != (reference_flag, reference_local):
        raise AssertionError("fused accumulator disagrees with priority semantics")
    return FusedGroupTrace(
        group_length=len(canonical),
        candidates=canonical,
        padded_candidates=(padded[0], padded[1], padded[2]),
        pattern=pattern,
        input_logical_slot=input_slot,
        input_torus_phase=input_phase,
        blind_rotation_degree=degree,
        sample_degrees=FUSED_SAMPLE_DEGREES,
        group_flag=bool(flag),
        local_first=local_first,
        reference_flag=bool(reference_flag),
        reference_local_first=reference_local,
        used_blind_rotation=used_blind_rotation,
    )


def evaluate_fused_group(group: Sequence[bool | int]) -> FusedGroupTrace:
    """Evaluate one group, including the singleton bypass and two-item tail."""
    return _evaluate_fused_group_cached(_canonical_group(group))


def _or_reduce(values: Sequence[bool]) -> bool:
    if not values:
        raise ValueError("OR reduction requires at least one value")
    level = list(values)
    while len(level) > 1:
        level = [
            any(level[start : start + OR_RADIX])
            for start in range(0, len(level), OR_RADIX)
        ]
    return level[0]


def _exclusive_prefix_or(flags: Sequence[bool]) -> tuple[bool, ...]:
    """Clear analogue of the unchanged radix-4 A34 prefix network."""
    if not flags:
        raise ValueError("prefix network requires at least one flag")
    if len(flags) <= OR_RADIX:
        return tuple(
            False if index == 0 else any(flags[:index]) for index in range(len(flags))
        )

    block_totals = tuple(
        _or_reduce(flags[start : start + OR_RADIX])
        for start in range(0, len(flags), OR_RADIX)
    )
    block_prefixes = _exclusive_prefix_or(block_totals)
    result: list[bool] = []
    for index in range(len(flags)):
        block = index // OR_RADIX
        offset = index % OR_RADIX
        if offset == 0:
            result.append(block_prefixes[block])
            continue
        start = block * OR_RADIX
        inputs = list(flags[start:index])
        if block > 0:
            inputs.insert(0, block_prefixes[block])
        result.append(inputs[0] if len(inputs) == 1 else _or_reduce(inputs))
    return tuple(result)


def _canonical_candidates(candidates: Sequence[bool | int]) -> tuple[bool, ...]:
    values = tuple(candidates)
    if not 1 <= len(values) <= MAX_GALLERY_SIZE:
        raise ValueError(f"gallery size must be in 1..{MAX_GALLERY_SIZE}")
    if any(value not in (False, True, 0, 1) for value in values):
        raise ValueError("candidates must be Boolean")
    return tuple(bool(value) for value in values)


def evaluate_a35_fused_two_nibble(
    candidates: Sequence[bool | int],
) -> A35FusedCircuitTrace:
    """Compose the fused group classifier with unchanged A34 clear downstream."""
    canonical = _canonical_candidates(candidates)
    fused_groups = tuple(
        evaluate_fused_group(canonical[start : start + GROUP_SIZE])
        for start in range(0, len(canonical), GROUP_SIZE)
    )
    flags = tuple(group.group_flag for group in fused_groups)
    prefixes = _exclusive_prefix_or(flags)
    if not len(fused_groups) == len(flags) == len(prefixes):
        raise AssertionError("group topology vectors have different lengths")

    outputs: list[A35GroupOutputTrace] = []
    for group_index, (group, prefix) in enumerate(zip(fused_groups, prefixes)):
        selector_state = group.local_first + 4 * int(prefix)
        selected_code = (
            GROUP_SIZE * group_index + selector_state
            if 1 <= selector_state <= group.group_length
            else 0
        )
        outputs.append(
            A35GroupOutputTrace(
                group_index=group_index,
                group=group,
                prefix=prefix,
                selector_state=selector_state,
                selected_code=selected_code,
                low_nibble=selected_code & 0xF,
                high_nibble=selected_code >> 4,
                active=selected_code != 0,
            )
        )

    if sum(output.active for output in outputs) > 1:
        raise AssertionError("more than one group survived prefix suppression")
    low_code = sum(output.low_nibble for output in outputs)
    high_code = 16 * sum(output.high_nibble for output in outputs)
    return A35FusedCircuitTrace(
        gallery_size=len(canonical),
        candidates=canonical,
        group_flags=flags,
        group_prefixes=prefixes,
        groups=tuple(outputs),
        final_code_outputs=(low_code, high_code),
        code=low_code + high_code,
    )


def or_reduction_blind_rotations(items: int) -> int:
    if items <= 0:
        raise ValueError("reduction requires at least one item")
    count = 0
    while items > 1:
        items = (items + OR_RADIX - 1) // OR_RADIX
        count += items
    return count


def exclusive_prefix_blind_rotations(items: int) -> int:
    if items <= 0:
        raise ValueError("prefix network requires at least one item")
    if items <= 2:
        return 0
    if items <= OR_RADIX:
        return items - 2

    totals = 0
    expansion = 0
    blocks = 0
    for start in range(0, items, OR_RADIX):
        length = min(OR_RADIX, items - start)
        blocks += 1
        totals += int(length > 1)
        expansion += max(0, length - 2) if start == 0 else length - 1
    return totals + expansion + exclusive_prefix_blind_rotations(blocks)


def _group_count(gallery_size: int) -> int:
    return (gallery_size + GROUP_SIZE - 1) // GROUP_SIZE


def _fused_group_node_count(gallery_size: int) -> int:
    return sum(
        min(GROUP_SIZE, gallery_size - start) > 1
        for start in range(0, gallery_size, GROUP_SIZE)
    )


def a35_fused_stage_counts(gallery_size: int) -> A35FusedStageCounts:
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError(f"gallery size must be in 1..{MAX_GALLERY_SIZE}")
    groups = _group_count(gallery_size)
    fused_nodes = _fused_group_node_count(gallery_size)
    prefix_nodes = exclusive_prefix_blind_rotations(groups)
    selector_nodes = groups
    digit_nodes = 2 * or_reduction_blind_rotations(groups)
    rotations = fused_nodes + prefix_nodes + selector_nodes + digit_nodes
    fused_marginals = 2 * fused_nodes
    selector_marginals = 2 * selector_nodes
    marginals = fused_marginals + prefix_nodes + selector_marginals + digit_nodes
    return A35FusedStageCounts(
        gallery_size=gallery_size,
        groups=groups,
        fused_group_blind_rotations=fused_nodes,
        fused_group_output_marginals=fused_marginals,
        group_prefix_blind_rotations=prefix_nodes,
        dual_selector_blind_rotations=selector_nodes,
        digit_reduction_blind_rotations=digit_nodes,
        scan_output_blind_rotations=rotations,
        scan_output_key_switches=rotations,
        scan_output_marginals=marginals,
        final_code_outputs=2,
    )


def a35_fused_replacement_counts(gallery_size: int) -> PrimitiveCounts:
    """Keep the frozen A33 pre-scan core and replace only scan/output."""
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError(f"gallery size must be in 1..{MAX_GALLERY_SIZE}")
    gallery_reduction = or_reduction_blind_rotations(gallery_size)
    pairs = (gallery_size + 1) // 2
    pair_reduction = or_reduction_blind_rotations(pairs)
    pre_scan_br = 27 * gallery_size + 9 * gallery_reduction + pairs + pair_reduction
    pre_scan_ks = 24 * gallery_size + 9 * gallery_reduction + pairs + pair_reduction
    pre_scan_marginals = pre_scan_br + 5 * gallery_size
    stage = a35_fused_stage_counts(gallery_size)
    return PrimitiveCounts(
        blind_rotations=pre_scan_br + stage.scan_output_blind_rotations,
        key_switches=pre_scan_ks + stage.scan_output_key_switches,
        output_marginals=pre_scan_marginals + stage.scan_output_marginals,
    )


def _encoding_separates_priority_classes(coefficients: Sequence[int]) -> bool:
    if len(coefficients) != GROUP_SIZE:
        raise ValueError("three coefficients are required")
    phase_to_output: dict[int, tuple[int, int]] = {}
    for bits in product((0, 1), repeat=GROUP_SIZE):
        phase = sum(coefficient * bit for coefficient, bit in zip(coefficients, bits))
        output = _priority_outputs(bits)
        previous = phase_to_output.setdefault(phase, output)
        if previous != output:
            return False
    return True


def minimum_linear_priority_encoding_l1(
    maximum_l1: int = 7,
) -> tuple[int, tuple[int, int, int]]:
    """Exhaust all integer triples through ``maximum_l1`` in increasing L1."""
    if maximum_l1 < 0:
        raise ValueError("maximum L1 must be non-negative")
    for l1 in range(maximum_l1 + 1):
        for coefficients in product(range(-l1, l1 + 1), repeat=GROUP_SIZE):
            if sum(abs(value) for value in coefficients) != l1:
                continue
            if _encoding_separates_priority_classes(coefficients):
                return l1, (coefficients[0], coefficients[1], coefficients[2])
    raise ValueError(f"no valid encoding found through L1={maximum_l1}")


def linear_encoding_audit() -> LinearEncodingAudit:
    minimum_l1, witness = minimum_linear_priority_encoding_l1()
    proposed_l1 = sum(abs(value) for value in PROPOSED_INPUT_COEFFICIENTS)
    return LinearEncodingAudit(
        proposed_coefficients=PROPOSED_INPUT_COEFFICIENTS,
        proposed_l1=proposed_l1,
        proposed_squared_l2=sum(value * value for value in PROPOSED_INPUT_COEFFICIENTS),
        conservative_max_noise_level=SHORTINT_MAX_NOISE_LEVEL,
        minimum_exact_priority_l1=minimum_l1,
        minimum_witness=witness,
        unscaled_witness_l1=sum(abs(value) for value in UNSCALED_INPUT_COEFFICIENTS),
        proposed_within_conservative_bound=proposed_l1 <= SHORTINT_MAX_NOISE_LEVEL,
        minimum_within_conservative_bound=minimum_l1 <= SHORTINT_MAX_NOISE_LEVEL,
    )


def assert_n127_counts() -> None:
    stage = a35_fused_stage_counts(127)
    assert stage.fused_group_blind_rotations == 42
    assert stage.group_prefix_blind_rotations == 53
    assert stage.dual_selector_blind_rotations == 43
    assert stage.digit_reduction_blind_rotations == 30
    assert stage.scan_output_blind_rotations == 168
    assert stage.scan_output_key_switches == 168
    assert stage.scan_output_marginals == 253
    assert a35_fused_replacement_counts(127) == PrimitiveCounts(4_069, 3_688, 4_789)


def _reference_code(candidates: Sequence[bool]) -> int:
    return next((index + 1 for index, value in enumerate(candidates) if value), 0)


def _validate_case(candidates: Sequence[bool], label: str) -> None:
    trace = evaluate_a35_fused_two_nibble(candidates)
    expected = _reference_code(candidates)
    if trace.code != expected:
        raise AssertionError(f"{label}: expected code {expected}, got {trace.code}")
    expected_prefixes = tuple(
        any(trace.group_flags[:index]) for index in range(len(trace.group_flags))
    )
    if trace.group_prefixes != expected_prefixes:
        raise AssertionError(f"{label}: group prefix mismatch")
    active_groups = [group for group in trace.groups if group.active]
    if expected == 0:
        if active_groups or any(trace.final_code_outputs):
            raise AssertionError(f"{label}: all-reject case emitted a code")
        return
    if len(active_groups) != 1 or active_groups[0].selected_code != expected:
        raise AssertionError(f"{label}: exact first-ID selection failed")
    winning_group = (expected - 1) // GROUP_SIZE
    for group in trace.groups[winning_group + 1 :]:
        if group.active or group.low_nibble or group.high_nibble:
            raise AssertionError(f"{label}: a later candidate was resurrected")


def _winner_pattern(
    gallery_size: int, first: int, later_predicate: Callable[[int], bool]
) -> tuple[bool, ...]:
    return tuple(
        index == first or (index > first and later_predicate(index))
        for index in range(gallery_size)
    )


def validate_model(
    *,
    max_gallery_size: int = MAX_GALLERY_SIZE,
    exhaustive_through: int = 10,
    random_patterns_per_winner: int = 2,
    seed: int = DEFAULT_VALIDATION_SEED,
    include_max_gallery_pairs: bool = True,
) -> ValidationSummary:
    """Check every N/first-winner topology plus deterministic adversaries."""
    if not 1 <= max_gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError(f"maximum gallery size must be in 1..{MAX_GALLERY_SIZE}")
    if not 0 <= exhaustive_through <= max_gallery_size:
        raise ValueError("exhaustive range is outside the requested galleries")
    if random_patterns_per_winner < 0:
        raise ValueError("random pattern count cannot be negative")

    all_reject_cases = 0
    winner_positions_checked = 0
    systematic_adversarial_cases = 0
    deterministic_random_cases = 0
    exhaustive_small_cases = 0
    max_gallery_pair_cases = 0
    rng = random.Random(seed)

    for gallery_size in range(1, max_gallery_size + 1):
        _validate_case((False,) * gallery_size, f"N={gallery_size}/all-reject")
        all_reject_cases += 1
        for first in range(gallery_size):
            singleton = tuple(index == first for index in range(gallery_size))
            _validate_case(singleton, f"N={gallery_size}/first={first}/singleton")
            winner_positions_checked += 1
            predicates = (
                lambda _index: True,
                lambda index, first=first: (index - first) % 2 == 0,
                lambda index, first=first: (index - first) % 2 == 1,
                lambda index: index % GROUP_SIZE == 0,
                lambda index: index % GROUP_SIZE == 1,
                lambda index: index % GROUP_SIZE == 2,
            )
            for pattern_index, predicate in enumerate(predicates):
                _validate_case(
                    _winner_pattern(gallery_size, first, predicate),
                    f"N={gallery_size}/first={first}/systematic={pattern_index}",
                )
                systematic_adversarial_cases += 1
            for sample in range(random_patterns_per_winner):
                bits = [False] * gallery_size
                bits[first] = True
                for index in range(first + 1, gallery_size):
                    bits[index] = bool(rng.getrandbits(1))
                _validate_case(
                    tuple(bits),
                    f"N={gallery_size}/first={first}/random={sample}",
                )
                deterministic_random_cases += 1

        if gallery_size <= exhaustive_through:
            for mask in range(1 << gallery_size):
                pattern = tuple(
                    bool((mask >> index) & 1) for index in range(gallery_size)
                )
                _validate_case(pattern, f"N={gallery_size}/exhaustive={mask}")
                exhaustive_small_cases += 1

    if include_max_gallery_pairs:
        for first in range(max_gallery_size):
            for later in range(first + 1, max_gallery_size):
                pattern = tuple(
                    index == first or index == later
                    for index in range(max_gallery_size)
                )
                _validate_case(pattern, f"N={max_gallery_size}/pair={first},{later}")
                max_gallery_pair_cases += 1

    total_cases = (
        all_reject_cases
        + winner_positions_checked
        + systematic_adversarial_cases
        + deterministic_random_cases
        + exhaustive_small_cases
        + max_gallery_pair_cases
    )
    return ValidationSummary(
        gallery_sizes_checked=max_gallery_size,
        all_reject_cases=all_reject_cases,
        winner_positions_checked=winner_positions_checked,
        systematic_adversarial_cases=systematic_adversarial_cases,
        deterministic_random_cases=deterministic_random_cases,
        exhaustive_small_cases=exhaustive_small_cases,
        max_gallery_pair_cases=max_gallery_pair_cases,
        total_cases=total_cases,
        exhaustive_through=exhaustive_through,
        random_patterns_per_winner=random_patterns_per_winner,
        seed=seed,
    )


def report(
    gallery_size: int, validation: ValidationSummary | None
) -> dict[str, object]:
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError(f"gallery size must be in 1..{MAX_GALLERY_SIZE}")
    return {
        "schema_version": 1,
        "model": "a35-fused-group-classifier-clear",
        "status": "semantic/layout PASS; conservative-noise BLOCKED",
        "scope": "clear semantics, exact tfhe-rs 0.11.3 layout, and structural counts only",
        "gallery_size": gallery_size,
        "accumulator": asdict(fused_accumulator_layout()),
        "linear_encoding_audit": asdict(linear_encoding_audit()),
        "a35_scan_output": asdict(a35_fused_stage_counts(gallery_size)),
        "a35_replacement_whole_core": asdict(
            a35_fused_replacement_counts(gallery_size)
        ),
        "validation": asdict(validation) if validation is not None else None,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gallery-size", type=int, default=127)
    parser.add_argument("--no-validate", action="store_true")
    parser.add_argument("--exhaustive-through", type=int, default=10)
    parser.add_argument("--random-patterns-per-winner", type=int, default=2)
    parser.add_argument("--seed", type=int, default=DEFAULT_VALIDATION_SEED)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    assert_n127_counts()
    validation = None
    if not args.no_validate:
        validation = validate_model(
            exhaustive_through=args.exhaustive_through,
            random_patterns_per_winner=args.random_patterns_per_winner,
            seed=args.seed,
        )
    print(json.dumps(report(args.gallery_size, validation), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
