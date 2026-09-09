#!/usr/bin/env python3
"""Clear audit model for the separate A35 block-label aggregation proposal.

After the unchanged A34 group-of-three scan, each group selector emits one
block-local label in ``0..12`` instead of two nibbles.  Four globally one-hot
labels are summed, and the proposal asks one p=16 blind rotation per block to
emit both low and high ID nibbles before the usual radix-4 digit reductions.

The ideal clear circuit is exact: it returns zero for all-reject and otherwise
the first one-based identity, including ties and gallery tails through N=128.
All immediate linear input bounds are at most five.  However, the proposed
single-accumulator dual decoder is not realizable for a full block.  Block zero
has thirteen reachable states (inactive plus IDs 1..12), thirteen distinct low
nibbles, and a high nibble fixed to zero.  Two translated 13-element sample
sets over the sixteen anti-periodic coefficient orbits overlap at least ten
times, while only the coefficient carrying low zero can satisfy a high-zero
overlap.  Exact enumeration also finds no box-aligned second extraction degree.

Two independent p=16 decoder LUTs are valid and keep every noise L1 bound at or
below five, but they cost two blind rotations per block.  They can reuse the
same key-switched input, so the fallback keeps the nominal KS count.  At N=127
it has the same BR count as the existing A34 two-nibble path while reducing KS
and output marginals.  The nominal one-BR counts are reported only as an
unrealizable counterfactual.  This model executes no FHE and makes no p-fail or
latency claim.
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import asdict, dataclass
from functools import cache
from typing import Callable, Sequence


MAX_GALLERY_SIZE = 128
GROUP_SIZE = 3
GROUPS_PER_BLOCK = 4
IDS_PER_BLOCK = GROUP_SIZE * GROUPS_PER_BLOCK
OR_RADIX = 4
P16 = 16
SIGNED_PHASE_MODULUS = 2 * P16
POLYNOMIAL_SIZE = 2_048
BOX_SIZE = POLYNOMIAL_SIZE // P16
HALF_BOX_SIZE = BOX_SIZE // 2
BOOL_DELTA_LOG = 59
BOOL_DELTA = 1 << BOOL_DELTA_LOG
CODE_DELTA_LOG = 56
TORUS_BITS = 64
TORUS_MASK = (1 << TORUS_BITS) - 1
SHORTINT_MAX_NOISE_LEVEL = 5
DEFAULT_VALIDATION_SEED = 0xA35_B10C_2026_0902


@dataclass(frozen=True)
class PrimitiveCounts:
    blind_rotations: int
    key_switches: int
    output_marginals: int


@dataclass(frozen=True)
class GroupLabelTrace:
    group_index: int
    group_length: int
    candidates: tuple[bool, ...]
    flag: bool
    prefix: bool
    local_first: int
    selector_state: int
    block_index: int
    position_in_block: int
    label: int
    active: bool


@dataclass(frozen=True)
class BlockDecodeTrace:
    block_index: int
    labels: tuple[int, ...]
    label_sum: int
    selected_code: int
    low_nibble: int
    high_nibble: int
    active: bool


@dataclass(frozen=True)
class A35BlockLabelTrace:
    gallery_size: int
    candidates: tuple[bool, ...]
    group_flags: tuple[bool, ...]
    group_prefixes: tuple[bool, ...]
    groups: tuple[GroupLabelTrace, ...]
    blocks: tuple[BlockDecodeTrace, ...]
    final_code_outputs: tuple[int, int]
    code: int


@dataclass(frozen=True)
class PackedLayoutAttempt:
    block_index: int
    reachable_max_label: int
    first_output: str
    second_output: str
    second_sample_offset_slots: int
    consistent: bool
    assigned_independent_slots: tuple[int | None, ...]
    conflict_independent_slot: int | None
    existing_value: int | None
    requested_value: int | None


@dataclass(frozen=True)
class PackingImpossibilityCertificate:
    reachable_states: int
    coefficient_orbits: int
    minimum_shifted_set_overlap: int
    maximum_compatible_overlap: int
    impossible: bool
    applies_to_arbitrary_injective_input_codes: bool
    anti_periodic_signs_help_for_zero: bool


@dataclass(frozen=True)
class NoiseAudit:
    group_flag_l1: int
    local_first_l1: int
    group_prefix_l1: int
    label_selector_l1: int
    block_label_sum_l1: int
    digit_reduction_l1: int
    conservative_max_noise_level: int
    every_bound_within_limit: bool


@dataclass(frozen=True)
class A35BlockLabelStageCounts:
    gallery_size: int
    groups: int
    blocks: int
    direct_single_group_selector: bool
    group_flag_blind_rotations: int
    local_first_blind_rotations: int
    group_prefix_blind_rotations: int
    label_selector_blind_rotations: int
    block_decoder_blind_rotations: int
    block_decoder_key_switches: int
    digit_reduction_blind_rotations: int
    scan_output_blind_rotations: int
    scan_output_key_switches: int
    scan_output_marginals: int
    final_code_outputs: int
    realizable_with_scalar_p16_accumulators: bool


@dataclass(frozen=True)
class CountComparison:
    nominal_one_rotation_per_block_stage: A35BlockLabelStageCounts
    feasible_two_rotations_per_block_stage: A35BlockLabelStageCounts
    nominal_whole_core: PrimitiveCounts
    feasible_whole_core: PrimitiveCounts


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


def _validate_gallery_size(gallery_size: int) -> None:
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError(f"gallery size must be in 1..{MAX_GALLERY_SIZE}")


def _canonical_candidates(candidates: Sequence[bool | int]) -> tuple[bool, ...]:
    values = tuple(candidates)
    _validate_gallery_size(len(values))
    if any(value not in (False, True, 0, 1) for value in values):
        raise ValueError("candidates must be Boolean")
    return tuple(bool(value) for value in values)


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


def _local_first(group: Sequence[bool]) -> int:
    return next((index + 1 for index, value in enumerate(group) if value), 0)


def evaluate_a35_block_label(candidates: Sequence[bool | int]) -> A35BlockLabelTrace:
    """Evaluate the ideal block-label circuit before its layout feasibility gate."""
    canonical = _canonical_candidates(candidates)
    candidate_groups = tuple(
        canonical[start : start + GROUP_SIZE]
        for start in range(0, len(canonical), GROUP_SIZE)
    )
    flags = tuple(any(group) for group in candidate_groups)
    prefixes = _exclusive_prefix_or(flags)
    if not len(candidate_groups) == len(flags) == len(prefixes):
        raise AssertionError("group topology vectors have different lengths")

    group_traces: list[GroupLabelTrace] = []
    for group_index, (group, flag, prefix) in enumerate(
        zip(candidate_groups, flags, prefixes)
    ):
        local_first = _local_first(group)
        selector_state = local_first + 4 * int(prefix)
        active = 1 <= selector_state <= len(group)
        label = (
            GROUP_SIZE * (group_index % GROUPS_PER_BLOCK) + selector_state
            if active
            else 0
        )
        if not 0 <= label <= IDS_PER_BLOCK:
            raise AssertionError("block-local label left the p=16 domain")
        group_traces.append(
            GroupLabelTrace(
                group_index=group_index,
                group_length=len(group),
                candidates=group,
                flag=flag,
                prefix=prefix,
                local_first=local_first,
                selector_state=selector_state,
                block_index=group_index // GROUPS_PER_BLOCK,
                position_in_block=group_index % GROUPS_PER_BLOCK,
                label=label,
                active=active,
            )
        )

    block_traces: list[BlockDecodeTrace] = []
    for block_index, start in enumerate(range(0, len(group_traces), GROUPS_PER_BLOCK)):
        block_groups = group_traces[start : start + GROUPS_PER_BLOCK]
        labels = tuple(group.label for group in block_groups)
        if sum(label != 0 for label in labels) > 1:
            raise AssertionError(
                "global prefix suppression did not make labels one-hot"
            )
        label_sum = sum(labels)
        selected_code = IDS_PER_BLOCK * block_index + label_sum if label_sum else 0
        block_traces.append(
            BlockDecodeTrace(
                block_index=block_index,
                labels=labels,
                label_sum=label_sum,
                selected_code=selected_code,
                low_nibble=selected_code & 0xF,
                high_nibble=selected_code >> 4,
                active=selected_code != 0,
            )
        )

    if sum(block.active for block in block_traces) > 1:
        raise AssertionError("more than one block survived")
    low_code = sum(block.low_nibble for block in block_traces)
    high_code = 16 * sum(block.high_nibble for block in block_traces)
    return A35BlockLabelTrace(
        gallery_size=len(canonical),
        candidates=canonical,
        group_flags=flags,
        group_prefixes=prefixes,
        groups=tuple(group_traces),
        blocks=tuple(block_traces),
        final_code_outputs=(low_code, high_code),
        code=low_code + high_code,
    )


@cache
def tfhe_generate_lut_signed_body(logical_slots: tuple[int, ...]) -> tuple[int, ...]:
    """Signed-unit form of tfhe-rs 0.11.3's p=16 LUT helper."""
    if len(logical_slots) != P16:
        raise ValueError("a p=16 LUT requires sixteen independent slots")
    body = [value for value in logical_slots for _ in range(BOX_SIZE)]
    for index in range(HALF_BOX_SIZE):
        body[index] = -body[index]
    body = body[HALF_BOX_SIZE:] + body[:HALF_BOX_SIZE]
    return tuple(body)


def negacyclic_coefficient(body: Sequence[int], degree: int) -> int:
    if len(body) != POLYNOMIAL_SIZE:
        raise ValueError("unexpected polynomial size")
    cycles, index = divmod(degree, POLYNOMIAL_SIZE)
    return -body[index] if cycles % 2 else body[index]


def sample_exact_label(body: Sequence[int], label: int, sample_degree: int = 0) -> int:
    """Sample a noiseless literal label input at ``label * Delta_bool``."""
    if not 0 <= label < P16:
        raise ValueError("literal label is outside p=16")
    if not 0 <= sample_degree < POLYNOMIAL_SIZE:
        raise ValueError("sample degree is outside the polynomial")
    # Exact multiples need no rounding term: modulus_switch(label*2^59)=label*N/16.
    monomial_degree = label * BOX_SIZE
    return negacyclic_coefficient(body, monomial_degree + sample_degree)


def _decoder_digits(block_index: int, label: int) -> tuple[int, int]:
    if block_index < 0 or not 0 <= label <= IDS_PER_BLOCK:
        raise ValueError("invalid block decoder input")
    code = IDS_PER_BLOCK * block_index + label if label else 0
    return code & 0xF, code >> 4


def single_output_decoder_slots(block_index: int, output: str) -> tuple[int, ...]:
    """A valid degree-zero p=16 fallback table for one output digit."""
    if output not in ("low", "high"):
        raise ValueError("output must be 'low' or 'high'")
    digit_index = 0 if output == "low" else 1
    return tuple(
        _decoder_digits(block_index, label)[digit_index]
        if label <= IDS_PER_BLOCK
        else 0
        for label in range(P16)
    )


def _assign_packed_constraint(
    slots: list[int | None], phase_slot: int, requested_output: int
) -> tuple[bool, int, int | None, int]:
    """Apply one sample constraint modulo the p=16 anti-periodic sign."""
    phase = phase_slot % SIGNED_PHASE_MODULUS
    independent_slot = phase % P16
    requested = requested_output % SIGNED_PHASE_MODULUS
    required_independent = (
        requested if phase < P16 else (-requested) % SIGNED_PHASE_MODULUS
    )
    existing = slots[independent_slot]
    if existing is not None and existing != required_independent:
        return False, independent_slot, existing, required_independent
    slots[independent_slot] = required_independent
    return True, independent_slot, existing, required_independent


def attempt_literal_packed_decoder(
    block_index: int,
    reachable_max_label: int,
    second_sample_offset_slots: int,
    *,
    first_output: str = "low",
) -> PackedLayoutAttempt:
    """Try two box-aligned samples from one literal-label p=16 accumulator."""
    if not 0 <= reachable_max_label <= IDS_PER_BLOCK:
        raise ValueError("reachable label bound must be in 0..12")
    if not 1 <= second_sample_offset_slots < P16:
        raise ValueError("second sample offset must be in 1..15 boxes")
    if first_output not in ("low", "high"):
        raise ValueError("first output must be 'low' or 'high'")
    second_output = "high" if first_output == "low" else "low"
    first_index = 0 if first_output == "low" else 1
    second_index = 1 - first_index
    slots: list[int | None] = [None] * P16

    for label in range(reachable_max_label + 1):
        digits = _decoder_digits(block_index, label)
        for phase, requested in (
            (label, digits[first_index]),
            (label + second_sample_offset_slots, digits[second_index]),
        ):
            consistent, slot, existing, required = _assign_packed_constraint(
                slots, phase, requested
            )
            if not consistent:
                return PackedLayoutAttempt(
                    block_index=block_index,
                    reachable_max_label=reachable_max_label,
                    first_output=first_output,
                    second_output=second_output,
                    second_sample_offset_slots=second_sample_offset_slots,
                    consistent=False,
                    assigned_independent_slots=tuple(slots),
                    conflict_independent_slot=slot,
                    existing_value=existing,
                    requested_value=required,
                )
    return PackedLayoutAttempt(
        block_index=block_index,
        reachable_max_label=reachable_max_label,
        first_output=first_output,
        second_output=second_output,
        second_sample_offset_slots=second_sample_offset_slots,
        consistent=True,
        assigned_independent_slots=tuple(slots),
        conflict_independent_slot=None,
        existing_value=None,
        requested_value=None,
    )


def literal_packed_decoder_solutions(
    block_index: int, reachable_max_label: int
) -> tuple[PackedLayoutAttempt, ...]:
    return tuple(
        attempt
        for first_output in ("low", "high")
        for offset in range(1, P16)
        for attempt in (
            attempt_literal_packed_decoder(
                block_index,
                reachable_max_label,
                offset,
                first_output=first_output,
            ),
        )
        if attempt.consistent
    )


def full_first_block_impossibility_certificate() -> PackingImpossibilityCertificate:
    states = IDS_PER_BLOCK + 1
    minimum_overlap = max(0, 2 * states - P16)
    # For block zero every requested high digit is zero, while the low outputs
    # 0..12 are distinct.  Anti-periodicity maps zero to zero, so only low-zero
    # can agree with an overlapping high constraint.
    maximum_compatible = 1
    return PackingImpossibilityCertificate(
        reachable_states=states,
        coefficient_orbits=P16,
        minimum_shifted_set_overlap=minimum_overlap,
        maximum_compatible_overlap=maximum_compatible,
        impossible=minimum_overlap > maximum_compatible,
        applies_to_arbitrary_injective_input_codes=True,
        anti_periodic_signs_help_for_zero=False,
    )


def scalar_packed_layout_feasible(gallery_size: int) -> bool:
    """Whether the literal packed route is available for every gallery block."""
    _validate_gallery_size(gallery_size)
    if gallery_size <= GROUP_SIZE:
        return True  # Existing direct two-half group selector, no block decoder.
    for block_index, start in enumerate(range(0, gallery_size, IDS_PER_BLOCK)):
        reachable = min(IDS_PER_BLOCK, gallery_size - start)
        if not literal_packed_decoder_solutions(block_index, reachable):
            return False
    return True


def noise_audit() -> NoiseAudit:
    bounds = (3, 4, 4, 5, 4, 4)
    return NoiseAudit(
        group_flag_l1=bounds[0],
        local_first_l1=bounds[1],
        group_prefix_l1=bounds[2],
        label_selector_l1=bounds[3],
        block_label_sum_l1=bounds[4],
        digit_reduction_l1=bounds[5],
        conservative_max_noise_level=SHORTINT_MAX_NOISE_LEVEL,
        every_bound_within_limit=max(bounds) <= SHORTINT_MAX_NOISE_LEVEL,
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


def _group_node_count(gallery_size: int) -> int:
    return sum(
        min(GROUP_SIZE, gallery_size - start) > 1
        for start in range(0, gallery_size, GROUP_SIZE)
    )


def a35_block_label_stage_counts(
    gallery_size: int, *, packed_decoder_rotations: int
) -> A35BlockLabelStageCounts:
    """Count nominal one-BR or feasible two-BR block decoding.

    ``packed_decoder_rotations=1`` is a counterfactual for galleries whose
    scalar packed layout is impossible.  ``2`` is the realizable fallback.
    """
    _validate_gallery_size(gallery_size)
    if packed_decoder_rotations not in (1, 2):
        raise ValueError("a block decoder must use one or two rotations")
    groups = _group_count(gallery_size)
    group_nodes = _group_node_count(gallery_size)
    prefix_nodes = exclusive_prefix_blind_rotations(groups)

    if groups == 1:
        # Retain the already valid A34 direct dual selector for N<=3.
        return A35BlockLabelStageCounts(
            gallery_size=gallery_size,
            groups=groups,
            blocks=1,
            direct_single_group_selector=True,
            group_flag_blind_rotations=group_nodes,
            local_first_blind_rotations=group_nodes,
            group_prefix_blind_rotations=prefix_nodes,
            label_selector_blind_rotations=1,
            block_decoder_blind_rotations=0,
            block_decoder_key_switches=0,
            digit_reduction_blind_rotations=0,
            scan_output_blind_rotations=2 * group_nodes + 1,
            scan_output_key_switches=2 * group_nodes + 1,
            scan_output_marginals=2 * group_nodes + 2,
            final_code_outputs=2,
            realizable_with_scalar_p16_accumulators=True,
        )

    blocks = (groups + GROUPS_PER_BLOCK - 1) // GROUPS_PER_BLOCK
    digit_nodes = 2 * or_reduction_blind_rotations(blocks)
    decoder_nodes = packed_decoder_rotations * blocks
    rotations = 2 * group_nodes + prefix_nodes + groups + decoder_nodes + digit_nodes
    # Both fallback accumulators rotate the same already-switched small-LWE
    # input, so they require one shared input KS per block, not one per BR.
    key_switches = 2 * group_nodes + prefix_nodes + groups + blocks + digit_nodes
    marginals = 2 * group_nodes + prefix_nodes + groups + 2 * blocks + digit_nodes
    layout_feasible = scalar_packed_layout_feasible(gallery_size)
    return A35BlockLabelStageCounts(
        gallery_size=gallery_size,
        groups=groups,
        blocks=blocks,
        direct_single_group_selector=False,
        group_flag_blind_rotations=group_nodes,
        local_first_blind_rotations=group_nodes,
        group_prefix_blind_rotations=prefix_nodes,
        label_selector_blind_rotations=groups,
        block_decoder_blind_rotations=decoder_nodes,
        block_decoder_key_switches=blocks,
        digit_reduction_blind_rotations=digit_nodes,
        scan_output_blind_rotations=rotations,
        scan_output_key_switches=key_switches,
        scan_output_marginals=marginals,
        final_code_outputs=2,
        realizable_with_scalar_p16_accumulators=(
            layout_feasible or packed_decoder_rotations == 2
        ),
    )


def _whole_core_counts(
    gallery_size: int, stage: A35BlockLabelStageCounts
) -> PrimitiveCounts:
    gallery_reduction = or_reduction_blind_rotations(gallery_size)
    pairs = (gallery_size + 1) // 2
    pair_reduction = or_reduction_blind_rotations(pairs)
    pre_scan_br = 27 * gallery_size + 9 * gallery_reduction + pairs + pair_reduction
    pre_scan_ks = 24 * gallery_size + 9 * gallery_reduction + pairs + pair_reduction
    pre_scan_marginals = pre_scan_br + 5 * gallery_size
    return PrimitiveCounts(
        pre_scan_br + stage.scan_output_blind_rotations,
        pre_scan_ks + stage.scan_output_key_switches,
        pre_scan_marginals + stage.scan_output_marginals,
    )


def count_comparison(gallery_size: int) -> CountComparison:
    nominal = a35_block_label_stage_counts(gallery_size, packed_decoder_rotations=1)
    feasible = a35_block_label_stage_counts(gallery_size, packed_decoder_rotations=2)
    return CountComparison(
        nominal_one_rotation_per_block_stage=nominal,
        feasible_two_rotations_per_block_stage=feasible,
        nominal_whole_core=_whole_core_counts(gallery_size, nominal),
        feasible_whole_core=_whole_core_counts(gallery_size, feasible),
    )


def assert_n127_counts() -> None:
    comparison = count_comparison(127)
    nominal = comparison.nominal_one_rotation_per_block_stage
    feasible = comparison.feasible_two_rotations_per_block_stage
    assert (nominal.groups, nominal.blocks) == (43, 11)
    assert nominal.group_flag_blind_rotations == 42
    assert nominal.local_first_blind_rotations == 42
    assert nominal.group_prefix_blind_rotations == 53
    assert nominal.label_selector_blind_rotations == 43
    assert nominal.block_decoder_blind_rotations == 11
    assert nominal.block_decoder_key_switches == 11
    assert nominal.digit_reduction_blind_rotations == 8
    assert (nominal.scan_output_blind_rotations, nominal.scan_output_key_switches) == (
        199,
        199,
    )
    assert nominal.scan_output_marginals == 210
    assert not nominal.realizable_with_scalar_p16_accumulators
    assert comparison.nominal_whole_core == PrimitiveCounts(4_100, 3_719, 4_746)
    assert (
        feasible.scan_output_blind_rotations,
        feasible.scan_output_key_switches,
    ) == (210, 199)
    assert feasible.scan_output_marginals == 210
    assert feasible.realizable_with_scalar_p16_accumulators
    assert comparison.feasible_whole_core == PrimitiveCounts(4_111, 3_719, 4_746)


def _reference_code(candidates: Sequence[bool]) -> int:
    return next((index + 1 for index, value in enumerate(candidates) if value), 0)


def _validate_case(candidates: Sequence[bool], label: str) -> None:
    trace = evaluate_a35_block_label(candidates)
    expected = _reference_code(candidates)
    if trace.code != expected:
        raise AssertionError(f"{label}: expected code {expected}, got {trace.code}")
    expected_prefixes = tuple(
        any(trace.group_flags[:index]) for index in range(len(trace.group_flags))
    )
    if trace.group_prefixes != expected_prefixes:
        raise AssertionError(f"{label}: prefix mismatch")
    active_groups = [group for group in trace.groups if group.active]
    active_blocks = [block for block in trace.blocks if block.active]
    if expected == 0:
        if active_groups or active_blocks or any(trace.final_code_outputs):
            raise AssertionError(f"{label}: all-reject emitted a code")
        return
    if len(active_groups) != 1 or len(active_blocks) != 1:
        raise AssertionError(f"{label}: output is not globally one-hot")
    if active_blocks[0].selected_code != expected:
        raise AssertionError(f"{label}: block decoder selected the wrong ID")
    for group in trace.groups[active_groups[0].group_index + 1 :]:
        if group.active or group.label:
            raise AssertionError(f"{label}: a later group was resurrected")


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
    _validate_gallery_size(max_gallery_size)
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
    _validate_gallery_size(gallery_size)
    comparison = count_comparison(gallery_size)
    certificate = full_first_block_impossibility_certificate()
    return {
        "schema_version": 1,
        "model": "a35-block-label-clear-layout-audit",
        "status": "clear semantics PASS; one-BR packed decoder BLOCKED",
        "scope": "clear semantics, scalar-p16 layout, noise L1, and structural counts only",
        "gallery_size": gallery_size,
        "noise": asdict(noise_audit()),
        "full_first_block_packing_certificate": asdict(certificate),
        "literal_full_block_solution_count": len(
            literal_packed_decoder_solutions(0, IDS_PER_BLOCK)
        ),
        "counts": asdict(comparison),
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
