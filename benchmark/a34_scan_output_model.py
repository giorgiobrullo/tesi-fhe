#!/usr/bin/env python3
"""Clear, exhaustive model of the proposed A34 scan-and-output circuit.

This file models only plaintext semantics and structural primitive counts.  It does
not execute TFHE, estimate a failure probability, or modify the frozen A33 core.

The candidate vector is the Boolean output of exact argmin selection: every true
entry is an admissible minimum, so the required result is zero for an empty vector
and otherwise the one-based position of its first true entry.  A34 groups candidates
by three, selects the first local entry, suppresses every group after the first live
group, emits two base-8 code digits with one p=16 blind rotation per group, reduces
the digits through radix-4 trees, and constructs the 64/128 digit separately.
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import asdict, dataclass
from functools import cache
from typing import Callable, Sequence


MAX_GALLERY_SIZE = 128
FIRST_WINNER_GROUP = 3
REDUCTION_RADIX = 4
CODE_RADIX = 8
HIGH_GROUP = 21  # Group 21 starts at one-based identity 64.
DEFAULT_VALIDATION_SEED = 0xA34_2026_0902
LOCAL_FIRST_LUT = (0, 3, 2, 1, 1)


@dataclass(frozen=True)
class SelectorLut:
    """Two functions packed into the independent halves of one p=16 accumulator.

    ``first_slots`` occupy logical accumulator slots 0..7.  If present,
    ``second_slots`` occupy slots 8..15 and are read through a second LWE sample
    extraction from the same blind rotation.  Slots 16..31 are not independent:
    negacyclicity fixes them to the negatives of slots 0..15.
    """

    mode: str
    first_slots: tuple[int, ...]
    second_slots: tuple[int, ...] | None

    def __post_init__(self) -> None:
        if len(self.first_slots) != CODE_RADIX:
            raise ValueError("first selector table must contain eight slots")
        if self.second_slots is not None and len(self.second_slots) != CODE_RADIX:
            raise ValueError("second selector table must contain eight slots")
        for value in self.first_slots:
            if not 0 <= value < CODE_RADIX:
                raise ValueError("first selector output is not a base-8 digit")
        if self.second_slots is not None:
            for value in self.second_slots:
                if not 0 <= value < CODE_RADIX:
                    raise ValueError("second selector output is not a base-8 digit")

    @property
    def sample_count(self) -> int:
        return 1 + int(self.second_slots is not None)

    @property
    def independent_slots(self) -> tuple[int, ...]:
        second = self.second_slots or (0,) * CODE_RADIX
        return self.first_slots + second

    @property
    def signed_negacyclic_slots(self) -> tuple[int, ...]:
        independent = self.independent_slots
        return independent + tuple(-value for value in independent)

    def sample(self, selector_state: int) -> tuple[int, ...]:
        if not 0 <= selector_state < CODE_RADIX:
            raise ValueError("selector state must fit the reachable p=16 half-domain")
        first = self.first_slots[selector_state]
        if self.second_slots is None:
            return (first,)
        return first, self.second_slots[selector_state]


@dataclass(frozen=True)
class GroupTrace:
    group_index: int
    group_length: int
    candidates: tuple[bool, ...]
    flag: bool
    prefix: bool
    local_first: int
    selector_state: int
    selector_mode: str
    selector_samples: tuple[int, ...]
    low_digit: int
    middle_digit: int
    id128_flag: int
    active: bool
    selected_code: int


@dataclass(frozen=True)
class DigitReductionTrace:
    levels: tuple[tuple[int, ...], ...]
    blind_rotations: int
    result: int


@dataclass(frozen=True)
class A34Trace:
    gallery_size: int
    candidates: tuple[bool, ...]
    group_flags: tuple[bool, ...]
    group_prefixes: tuple[bool, ...]
    groups: tuple[GroupTrace, ...]
    low_reduction: DigitReductionTrace
    middle_reduction: DigitReductionTrace
    prefix_before_64: bool
    any_at_or_after_64: bool
    id128_flag: int
    high_lut_input: int
    high_digit: int
    code: int


@dataclass(frozen=True)
class A34StageCounts:
    gallery_size: int
    groups: int
    group_flag_blind_rotations: int
    local_first_blind_rotations: int
    group_prefix_blind_rotations: int
    dual_selector_blind_rotations: int
    digit_reduction_blind_rotations: int
    high_flag_reduction_blind_rotations: int
    high_digit_blind_rotations: int
    scan_output_blind_rotations: int
    scan_output_key_switches: int
    selector_output_marginals: int
    scan_output_marginals: int


@dataclass(frozen=True)
class PrimitiveCounts:
    blind_rotations: int
    key_switches: int
    output_marginals: int


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


def or_reduction_blind_rotations(items: int) -> int:
    """Number of radix-4 OR nodes, with singleton nodes implemented as clones."""
    if items <= 0:
        raise ValueError("OR reduction must contain at least one item")
    count = 0
    while items > 1:
        items = (items + REDUCTION_RADIX - 1) // REDUCTION_RADIX
        count += items
    return count


def radix4_exclusive_prefix_blind_rotations(items: int) -> int:
    """Structural count of the recursive exclusive-prefix network used by A33."""
    if items <= 0:
        raise ValueError("prefix network must contain at least one item")
    if items <= 2:
        return 0
    if items <= REDUCTION_RADIX:
        return items - 2

    totals = 0
    expansion = 0
    groups = 0
    for start in range(0, items, REDUCTION_RADIX):
        length = min(REDUCTION_RADIX, items - start)
        groups += 1
        totals += int(length > 1)
        expansion += max(0, length - 2) if start == 0 else length - 1
    return totals + expansion + radix4_exclusive_prefix_blind_rotations(groups)


def _or_reduce(values: Sequence[bool]) -> bool:
    if not values:
        raise ValueError("OR reduction must contain at least one item")
    level = list(values)
    while len(level) > 1:
        level = [
            any(level[start : start + REDUCTION_RADIX])
            for start in range(0, len(level), REDUCTION_RADIX)
        ]
    return level[0]


def _radix4_exclusive_prefix(flags: Sequence[bool]) -> tuple[bool, ...]:
    """Clear evaluation of the same recursive network counted above."""
    if not flags:
        raise ValueError("prefix network must contain at least one item")
    if len(flags) <= REDUCTION_RADIX:
        return tuple(
            False if index == 0 else any(flags[:index]) for index in range(len(flags))
        )

    block_totals = tuple(
        _or_reduce(flags[start : start + REDUCTION_RADIX])
        for start in range(0, len(flags), REDUCTION_RADIX)
    )
    block_prefixes = _radix4_exclusive_prefix(block_totals)
    prefixes: list[bool] = []
    for index in range(len(flags)):
        block = index // REDUCTION_RADIX
        offset = index % REDUCTION_RADIX
        if offset == 0:
            prefixes.append(block_prefixes[block])
            continue
        start = block * REDUCTION_RADIX
        inputs = list(flags[start:index])
        if block > 0:
            inputs.insert(0, block_prefixes[block])
        prefixes.append(inputs[0] if len(inputs) == 1 else _or_reduce(inputs))
    return tuple(prefixes)


def _local_first_lut(flag: bool, candidates: Sequence[bool]) -> int:
    """Evaluate v=f+2*c0+c1 and map it to local index 0, 1, 2, or 3."""
    c0 = int(candidates[0])
    c1 = int(candidates[1]) if len(candidates) > 1 else 0
    value = int(flag) + 2 * c0 + c1
    return LOCAL_FIRST_LUT[value]


def _active_code(group_index: int, group_length: int, selector_state: int) -> int:
    if selector_state >= 4:
        return 0
    local_first = selector_state
    if not 1 <= local_first <= group_length:
        return 0
    return FIRST_WINNER_GROUP * group_index + local_first


@cache
def selector_lut(gallery_size: int, group_index: int, group_length: int) -> SelectorLut:
    """Build the public p=16 accumulator layout for one group.

    The final N=127 group needs one sample because ID 127 has equal low and
    middle base-8 digits (7, 7).  At N=128 the final group still has equal
    digits for both reachable IDs, so the second sample carries E=[ID=128].
    All other groups use the two independent halves for low and middle digits.
    """
    _validate_gallery_size(gallery_size)
    groups = (gallery_size + FIRST_WINNER_GROUP - 1) // FIRST_WINNER_GROUP
    if not 0 <= group_index < groups:
        raise ValueError("group index is outside this gallery")
    expected_length = min(
        FIRST_WINNER_GROUP, gallery_size - group_index * FIRST_WINNER_GROUP
    )
    if group_length != expected_length:
        raise ValueError("group length does not match gallery tail")

    codes = tuple(
        _active_code(group_index, group_length, state) for state in range(CODE_RADIX)
    )
    low = tuple(code % CODE_RADIX if code else 0 for code in codes)
    middle = tuple((code // CODE_RADIX) % CODE_RADIX if code else 0 for code in codes)

    is_final_group = group_index == groups - 1
    if gallery_size == 127 and is_final_group:
        if low != middle:
            raise AssertionError("N=127 tail digits must be cloneable")
        return SelectorLut("n127_tail_clone", low, None)
    if gallery_size == 128 and is_final_group:
        if low != middle:
            raise AssertionError("N=128 tail digits must be cloneable")
        id128 = tuple(int(code == 128) for code in codes)
        return SelectorLut("n128_tail_digit_and_e", low, id128)
    return SelectorLut("dual_base8_digits", low, middle)


def _reduce_digit(values: Sequence[int]) -> DigitReductionTrace:
    """Refresh a one-hot collection of base-8 digits through a radix-4 tree."""
    if not values:
        raise ValueError("digit reduction must contain at least one item")
    if any(not 0 <= value < CODE_RADIX for value in values):
        raise ValueError("digit reduction received a non-base-8 value")
    if sum(value != 0 for value in values) > 1:
        raise AssertionError("more than one group survived; no-resurrection failed")

    level = tuple(values)
    levels = [level]
    blind_rotations = 0
    while len(level) > 1:
        next_level: list[int] = []
        for start in range(0, len(level), REDUCTION_RADIX):
            chunk = level[start : start + REDUCTION_RADIX]
            value = sum(chunk)
            if not 0 <= value < CODE_RADIX:
                raise AssertionError("reachable radix-4 digit left the p=16 safe half")
            next_level.append(value)
        level = tuple(next_level)
        levels.append(level)
        blind_rotations += len(level)
    return DigitReductionTrace(tuple(levels), blind_rotations, level[0])


def _high_digit_lut(value: int) -> int:
    """Map H-P21+2E to the base-64 digit, failing closed on other states."""
    return {1: 1, 3: 2}.get(value, 0)


def evaluate_a34_scan_output(candidates: Sequence[bool | int]) -> A34Trace:
    """Evaluate the proposed A34 scan/output network in the clear."""
    canonical = _canonical_candidates(candidates)
    gallery_size = len(canonical)
    candidate_groups = tuple(
        canonical[start : start + FIRST_WINNER_GROUP]
        for start in range(0, gallery_size, FIRST_WINNER_GROUP)
    )
    group_flags = tuple(any(group) for group in candidate_groups)
    group_prefixes = _radix4_exclusive_prefix(group_flags)
    if not len(candidate_groups) == len(group_flags) == len(group_prefixes):
        raise AssertionError("group topology vectors have different lengths")

    groups: list[GroupTrace] = []
    for group_index, (group, flag, prefix) in enumerate(
        zip(candidate_groups, group_flags, group_prefixes)
    ):
        local_first = int(flag) if len(group) == 1 else _local_first_lut(flag, group)
        selector_state = local_first + 4 * int(prefix)
        lut = selector_lut(gallery_size, group_index, len(group))
        samples = lut.sample(selector_state)
        selected_code = _active_code(group_index, len(group), selector_state)
        active = selected_code != 0

        if lut.mode == "n127_tail_clone":
            low_digit = samples[0]
            middle_digit = samples[0]
            id128_flag = 0
        elif lut.mode == "n128_tail_digit_and_e":
            low_digit = samples[0]
            middle_digit = samples[0]
            id128_flag = samples[1]
        else:
            low_digit, middle_digit = samples
            id128_flag = 0

        groups.append(
            GroupTrace(
                group_index=group_index,
                group_length=len(group),
                candidates=group,
                flag=flag,
                prefix=prefix,
                local_first=local_first,
                selector_state=selector_state,
                selector_mode=lut.mode,
                selector_samples=samples,
                low_digit=low_digit,
                middle_digit=middle_digit,
                id128_flag=id128_flag,
                active=active,
                selected_code=selected_code,
            )
        )

    low_reduction = _reduce_digit([group.low_digit for group in groups])
    middle_reduction = _reduce_digit([group.middle_digit for group in groups])

    if gallery_size >= 64:
        prefix_before_64 = group_prefixes[HIGH_GROUP]
        any_at_or_after_64 = _or_reduce(group_flags[HIGH_GROUP:])
        id128_flag = groups[-1].id128_flag if gallery_size == 128 else 0
        high_lut_input = (
            int(any_at_or_after_64) - int(prefix_before_64) + 2 * id128_flag
        )
        high_digit = _high_digit_lut(high_lut_input)
    else:
        prefix_before_64 = False
        any_at_or_after_64 = False
        id128_flag = 0
        high_lut_input = 0
        high_digit = 0

    code = (
        low_reduction.result
        + CODE_RADIX * middle_reduction.result
        + CODE_RADIX * CODE_RADIX * high_digit
    )
    return A34Trace(
        gallery_size=gallery_size,
        candidates=canonical,
        group_flags=group_flags,
        group_prefixes=group_prefixes,
        groups=tuple(groups),
        low_reduction=low_reduction,
        middle_reduction=middle_reduction,
        prefix_before_64=prefix_before_64,
        any_at_or_after_64=any_at_or_after_64,
        id128_flag=id128_flag,
        high_lut_input=high_lut_input,
        high_digit=high_digit,
        code=code,
    )


def _group_pbs_count(gallery_size: int) -> int:
    return sum(
        min(FIRST_WINNER_GROUP, gallery_size - start) > 1
        for start in range(0, gallery_size, FIRST_WINNER_GROUP)
    )


def a34_stage_counts(gallery_size: int) -> A34StageCounts:
    """Compute A34 scan/output BR, KS and output-marginal counts from topology."""
    _validate_gallery_size(gallery_size)
    groups = (gallery_size + FIRST_WINNER_GROUP - 1) // FIRST_WINNER_GROUP
    group_nodes = _group_pbs_count(gallery_size)
    prefix_nodes = radix4_exclusive_prefix_blind_rotations(groups)
    selector_nodes = groups
    digit_nodes = 2 * or_reduction_blind_rotations(groups)
    high_flag_nodes = (
        or_reduction_blind_rotations(groups - HIGH_GROUP) if gallery_size >= 64 else 0
    )
    high_digit_nodes = int(gallery_size >= 64)
    blind_rotations = (
        2 * group_nodes
        + prefix_nodes
        + selector_nodes
        + digit_nodes
        + high_flag_nodes
        + high_digit_nodes
    )

    selector_marginals = 2 * groups - int(gallery_size == 127)
    output_marginals = blind_rotations - selector_nodes + selector_marginals
    return A34StageCounts(
        gallery_size=gallery_size,
        groups=groups,
        group_flag_blind_rotations=group_nodes,
        local_first_blind_rotations=group_nodes,
        group_prefix_blind_rotations=prefix_nodes,
        dual_selector_blind_rotations=selector_nodes,
        digit_reduction_blind_rotations=digit_nodes,
        high_flag_reduction_blind_rotations=high_flag_nodes,
        high_digit_blind_rotations=high_digit_nodes,
        scan_output_blind_rotations=blind_rotations,
        scan_output_key_switches=blind_rotations,
        selector_output_marginals=selector_marginals,
        scan_output_marginals=output_marginals,
    )


def _a33_first_one_scan_blind_rotations(gallery_size: int) -> int:
    groups = (gallery_size + FIRST_WINNER_GROUP - 1) // FIRST_WINNER_GROUP
    group_totals = _group_pbs_count(gallery_size)
    return group_totals + radix4_exclusive_prefix_blind_rotations(groups) + gallery_size


def _a33_output_blind_rotations(gallery_size: int) -> int:
    bit_positions = range(gallery_size.bit_length())
    bit_nodes = 0
    for bit in bit_positions:
        selected = sum(bool((code >> bit) & 1) for code in range(1, gallery_size + 1))
        bit_nodes += max(1, or_reduction_blind_rotations(selected))
    return bit_nodes + (gallery_size.bit_length() + 2) // 3


def a33_reference_counts(gallery_size: int) -> PrimitiveCounts:
    """Recompute current A33 totals without importing or modifying the Rust core."""
    _validate_gallery_size(gallery_size)
    reduction = or_reduction_blind_rotations(gallery_size)
    pairs = (gallery_size + 1) // 2
    pair_reduction = or_reduction_blind_rotations(pairs)
    scan = _a33_first_one_scan_blind_rotations(gallery_size)
    output = _a33_output_blind_rotations(gallery_size)
    blind_rotations = (
        27 * gallery_size + 9 * reduction + pairs + pair_reduction + scan + output
    )
    key_switches = blind_rotations - 3 * gallery_size
    # Four split/correction ManyLUT rotations and the aligned classifier each
    # expose one extra marginal per template beyond their BR count.
    output_marginals = blind_rotations + 5 * gallery_size
    return PrimitiveCounts(blind_rotations, key_switches, output_marginals)


def a34_replacement_counts(gallery_size: int) -> PrimitiveCounts:
    """Replace only A33 scan/output while keeping its pre-scan core unchanged."""
    _validate_gallery_size(gallery_size)
    reduction = or_reduction_blind_rotations(gallery_size)
    pairs = (gallery_size + 1) // 2
    pair_reduction = or_reduction_blind_rotations(pairs)
    pre_scan_blind_rotations = (
        27 * gallery_size + 9 * reduction + pairs + pair_reduction
    )
    pre_scan_key_switches = 24 * gallery_size + 9 * reduction + pairs + pair_reduction
    stage = a34_stage_counts(gallery_size)
    return PrimitiveCounts(
        blind_rotations=pre_scan_blind_rotations + stage.scan_output_blind_rotations,
        key_switches=pre_scan_key_switches + stage.scan_output_key_switches,
        output_marginals=pre_scan_blind_rotations
        + 5 * gallery_size
        + stage.scan_output_marginals,
    )


def assert_n127_counts() -> None:
    """Freeze the A34 structural target used to decide whether Rust work is warranted."""
    stage = a34_stage_counts(127)
    assert stage.scan_output_blind_rotations == 220
    assert stage.scan_output_key_switches == 220
    assert stage.scan_output_marginals == 262
    assert a33_reference_counts(127) == PrimitiveCounts(4_273, 3_892, 4_908)
    assert a34_replacement_counts(127) == PrimitiveCounts(4_121, 3_740, 4_798)


def _reference_code(candidates: Sequence[bool]) -> int:
    return next((index + 1 for index, value in enumerate(candidates) if value), 0)


def _validate_case(candidates: Sequence[bool], label: str) -> None:
    trace = evaluate_a34_scan_output(candidates)
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
        if active_groups:
            raise AssertionError(f"{label}: all-reject case created a winner")
        if any(
            group.low_digit or group.middle_digit or group.id128_flag
            for group in trace.groups
        ):
            raise AssertionError(f"{label}: all-reject case emitted a code digit")
        return

    if len(active_groups) != 1:
        raise AssertionError(f"{label}: expected exactly one active group")
    active = active_groups[0]
    if active.selected_code != expected:
        raise AssertionError(f"{label}: selector chose {active.selected_code}")

    winning_group = (expected - 1) // FIRST_WINNER_GROUP
    for group in trace.groups[winning_group + 1 :]:
        if group.flag and not group.prefix:
            raise AssertionError(f"{label}: later live group lacks a prefix")
        if group.active or group.low_digit or group.middle_digit or group.id128_flag:
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
    exhaustive_through: int = 12,
    random_patterns_per_winner: int = 4,
    seed: int = DEFAULT_VALIDATION_SEED,
    include_max_gallery_pairs: bool = True,
) -> ValidationSummary:
    """Run deterministic semantic validation across every supported topology.

    Every N and every possible first-winner position are covered.  Small galleries
    additionally enumerate every Boolean candidate vector.  Dense, alternating,
    group-boundary and seeded pseudo-random suffixes exercise suppression of later
    tied candidates; the maximum gallery also covers every two-candidate pair.
    """
    _validate_gallery_size(max_gallery_size)
    if not 0 <= exhaustive_through <= max_gallery_size:
        raise ValueError("exhaustive_through is outside the requested gallery range")
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
        rejected = (False,) * gallery_size
        _validate_case(rejected, f"N={gallery_size}/all-reject")
        all_reject_cases += 1

        for first in range(gallery_size):
            singleton = tuple(index == first for index in range(gallery_size))
            _validate_case(singleton, f"N={gallery_size}/first={first}/singleton")
            winner_positions_checked += 1

            predicates = (
                lambda _index: True,
                lambda index, first=first: (index - first) % 2 == 0,
                lambda index, first=first: (index - first) % 2 == 1,
                lambda index: index % FIRST_WINNER_GROUP == 0,
                lambda index: index % FIRST_WINNER_GROUP == 1,
                lambda index: index % FIRST_WINNER_GROUP == 2,
            )
            for pattern_index, predicate in enumerate(predicates):
                pattern = _winner_pattern(gallery_size, first, predicate)
                _validate_case(
                    pattern,
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
        gallery_size = max_gallery_size
        for first in range(gallery_size):
            for later in range(first + 1, gallery_size):
                pattern = tuple(
                    index == first or index == later for index in range(gallery_size)
                )
                _validate_case(
                    pattern,
                    f"N={gallery_size}/pair={first},{later}",
                )
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
    a33 = a33_reference_counts(gallery_size)
    a34 = a34_replacement_counts(gallery_size)
    stage = a34_stage_counts(gallery_size)
    return {
        "schema_version": 1,
        "model": "a34-clear-scan-output",
        "scope": "clear semantics and structural counts only; no FHE or p-fail claim",
        "gallery_size": gallery_size,
        "p16_input_noise_weight_bounds": {
            "local_first": 4,
            "group_selector": 5,
            "high_digit": 4,
        },
        "a34_scan_output": asdict(stage),
        "a33_reference_whole_core": asdict(a33),
        "a34_replacement_whole_core": asdict(a34),
        "structural_savings": {
            "blind_rotations": a33.blind_rotations - a34.blind_rotations,
            "key_switches": a33.key_switches - a34.key_switches,
            "output_marginals": a33.output_marginals - a34.output_marginals,
        },
        "validation": asdict(validation) if validation is not None else None,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gallery-size", type=int, default=127)
    parser.add_argument("--no-validate", action="store_true")
    parser.add_argument("--exhaustive-through", type=int, default=12)
    parser.add_argument("--random-patterns-per-winner", type=int, default=4)
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
