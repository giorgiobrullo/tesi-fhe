#!/usr/bin/env python3
"""Static model for A51: A50 plus radix-15 scan/output reductions.

The model is deliberately non-cryptographic.  It proves clear semantics,
enumerates reduction shapes, and records conservative raw-L1 obligations under
the audited A44 ``max_noise_level=15`` premise.  It does not compile Rust,
generate keys, execute TFHE, benchmark latency, or establish an end-to-end
probability-of-failure bound.
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
from dataclasses import asdict, dataclass
from typing import Sequence


MAX_GALLERY_SIZE = 128
SCORE_BITS = (7, 6, 5, 4, 3, 2, 1, 0)
A50_BIT_CONTRIBUTIONS = (-1, -1, -1, -1, -1, 8, -4, -2)
A50_CHUNK_END_LEVELS = (3, 7)
SCAN_GROUP_SIZE = 3
A38_RADIX = 5
A40_RADIX = 7
A51_RADIX = 15
A44_MAX_NOISE_LEVEL = 15
A44_LOG2_P_FAIL_PER_EVENT = -64.088

P16 = 16
POLYNOMIAL_SIZE = 2_048
P16_BOX_SIZE = POLYNOMIAL_SIZE // P16
P16_OPEN_HALF_SLOT_ROTATIONS = P16_BOX_SIZE // 2


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
class ReductionLevel:
    input_items: int
    chunk_lengths: tuple[int, ...]
    pbs_fanins: tuple[int, ...]
    singleton_forwards: int
    output_items: int


@dataclass(frozen=True)
class ReductionShape:
    items: int
    radix: int
    forward_singletons: bool
    levels: tuple[ReductionLevel, ...]
    pbs_nodes: int
    singleton_forwards: int
    maximum_pbs_fanin: int


@dataclass(frozen=True)
class ScanOutputCounts:
    gallery_size: int
    groups: int
    group_or_nodes: int
    local_first_nodes: int
    prefix_nodes: int
    selector_blind_rotations: int
    low_digit_nodes: int
    high_digit_nodes: int
    blind_rotations: int
    key_switches: int
    output_marginals: int


@dataclass(frozen=True)
class CountBreakdown:
    gallery_size: int
    invariant_blind_rotations: int
    low_selection_blind_rotations: int
    scan_output: ScanOutputCounts
    total: OperationCounts


@dataclass(frozen=True)
class NoiseRow:
    family: str
    instances_n127: int
    maximum_input_raw_l1: int
    output_marginals_per_blind_rotation: int
    fits_a44_max15_without_rescaling: bool
    note: str


@dataclass(frozen=True)
class P16OrGeometry:
    polynomial_size: int
    plaintext_modulus: int
    box_size: int
    open_half_slot_rotations: int
    centers_0_through_15_exact: bool
    strict_interior_errors_exact: bool
    code_16_output: int
    code_16_required_or_output: int
    radix_16_negacyclic_no_go: bool


@dataclass(frozen=True)
class A50LowTrace:
    initial_candidates: tuple[bool, ...]
    suffixes: tuple[int, ...]
    zero_test_raw_inputs_by_level: tuple[tuple[int, ...], ...]
    any_zero_by_level: tuple[int, ...]
    states_after_level: tuple[tuple[int, ...], ...]
    final_candidates: tuple[bool, ...]


@dataclass(frozen=True)
class ScanTrace:
    candidates: tuple[bool, ...]
    group_flags: tuple[int, ...]
    local_first: tuple[int, ...]
    group_prefixes: tuple[int, ...]
    low_digits: tuple[int, ...]
    high_digits: tuple[int, ...]
    low_code: int
    high_digit: int
    code: int
    group_or_fanins: tuple[int, ...]
    prefix_or_fanins: tuple[int, ...]
    low_digit_fanins: tuple[int, ...]
    high_digit_fanins: tuple[int, ...]


@dataclass(frozen=True)
class FullTrace:
    scores: tuple[int, ...]
    threshold: int
    a34_top_candidates: tuple[bool, ...]
    final_minimum_candidates: tuple[bool, ...]
    scan: ScanTrace
    code: int
    reference_code: int


def ceil_div(value: int, divisor: int) -> int:
    if value < 0 or divisor < 1:
        raise ValueError("invalid ceil-div operands")
    return (value + divisor - 1) // divisor


def reduction_shape(
    items: int, radix: int, *, forward_singletons: bool
) -> ReductionShape:
    """Return the exact level shape of a tree reduction."""
    if items < 1 or radix < 2:
        raise ValueError("invalid reduction shape")
    initial_items = items
    levels: list[ReductionLevel] = []
    while items > 1:
        chunks = tuple(
            min(radix, items - start) for start in range(0, items, radix)
        )
        fanins = tuple(
            length
            for length in chunks
            if not (forward_singletons and length == 1)
        )
        forwards = sum(length == 1 for length in chunks) if forward_singletons else 0
        next_items = len(chunks)
        levels.append(
            ReductionLevel(
                input_items=items,
                chunk_lengths=chunks,
                pbs_fanins=fanins,
                singleton_forwards=forwards,
                output_items=next_items,
            )
        )
        items = next_items
    all_fanins = tuple(fanin for level in levels for fanin in level.pbs_fanins)
    return ReductionShape(
        items=initial_items,
        radix=radix,
        forward_singletons=forward_singletons,
        levels=tuple(levels),
        pbs_nodes=len(all_fanins),
        singleton_forwards=sum(level.singleton_forwards for level in levels),
        maximum_pbs_fanin=max(all_fanins, default=0),
    )


def _negacyclic_coefficient(body: Sequence[int], degree: int) -> int:
    cycles, index = divmod(degree, len(body))
    return -body[index] if cycles % 2 else body[index]


def _radix15_or_body() -> tuple[int, ...]:
    """Raw p16 half-torus body with a standard open half-slot margin."""
    body = [0] * POLYNOMIAL_SIZE
    body[
        P16_OPEN_HALF_SLOT_ROTATIONS : 15 * P16_BOX_SIZE
        + P16_OPEN_HALF_SLOT_ROTATIONS
    ] = [1] * (15 * P16_BOX_SIZE)
    return tuple(body)


def _sample_signed_p16_code(code: int, rotation_error: int = 0) -> int:
    return _negacyclic_coefficient(
        _radix15_or_body(), code * P16_BOX_SIZE + rotation_error
    )


def p16_or_geometry() -> P16OrGeometry:
    center_exact = all(
        _sample_signed_p16_code(code) == int(code > 0) for code in range(16)
    )
    interior_exact = all(
        _sample_signed_p16_code(code, error) == int(code > 0)
        for code in range(16)
        for error in range(
            -P16_OPEN_HALF_SLOT_ROTATIONS + 1,
            P16_OPEN_HALF_SLOT_ROTATIONS,
        )
    )
    code_16 = _sample_signed_p16_code(16)
    return P16OrGeometry(
        polynomial_size=POLYNOMIAL_SIZE,
        plaintext_modulus=P16,
        box_size=P16_BOX_SIZE,
        open_half_slot_rotations=P16_OPEN_HALF_SLOT_ROTATIONS,
        centers_0_through_15_exact=center_exact,
        strict_interior_errors_exact=interior_exact,
        code_16_output=code_16,
        code_16_required_or_output=1,
        radix_16_negacyclic_no_go=code_16 != 1,
    )


def canonical_or_gate(values: Sequence[int], fanins: list[int] | None = None) -> int:
    """Clear counterpart of one radix-15 canonical Boolean OR PBS."""
    values = tuple(values)
    if not 2 <= len(values) <= A51_RADIX:
        raise ValueError("a canonical OR PBS needs 2..15 inputs")
    if any(value not in (0, 1) for value in values):
        raise ValueError("canonical OR inputs must be 0/1")
    if fanins is not None:
        fanins.append(len(values))
    return int(any(values))


def reduce_canonical_or(
    values: Sequence[int], *, radix: int = A51_RADIX, fanins: list[int] | None = None
) -> int:
    """Reduce canonical flags, forwarding every singleton tail."""
    level = tuple(values)
    if not level or any(value not in (0, 1) for value in level):
        raise ValueError("expected a non-empty canonical Boolean vector")
    if not 2 <= radix <= A51_RADIX:
        raise ValueError("this p16 model supports radix 2..15")
    while len(level) > 1:
        next_level: list[int] = []
        for start in range(0, len(level), radix):
            chunk = level[start : start + radix]
            if len(chunk) == 1:
                next_level.append(chunk[0])
            else:
                next_level.append(canonical_or_gate(chunk, fanins))
        level = tuple(next_level)
    return level[0]


def exclusive_prefix_or(
    flags: Sequence[int], *, radix: int = A51_RADIX, fanins: list[int] | None = None
) -> tuple[int, ...]:
    """Exclusive OR-prefix with the exact recursive A38/A51 topology."""
    flags = tuple(flags)
    if not flags or any(flag not in (0, 1) for flag in flags):
        raise ValueError("expected non-empty canonical flags")
    if not 2 <= radix <= A51_RADIX:
        raise ValueError("this p16 model supports radix 2..15")
    if len(flags) <= radix:
        outputs = [0]
        if len(flags) >= 2:
            outputs.append(flags[0])
        for index in range(2, len(flags)):
            outputs.append(canonical_or_gate(flags[:index], fanins))
        return tuple(outputs)

    block_totals: list[int] = []
    for start in range(0, len(flags), radix):
        block = flags[start : start + radix]
        if len(block) == 1:
            block_totals.append(block[0])
        else:
            block_totals.append(canonical_or_gate(block, fanins))
    block_prefixes = exclusive_prefix_or(block_totals, radix=radix, fanins=fanins)

    outputs: list[int] = []
    for index in range(len(flags)):
        block_index, offset = divmod(index, radix)
        if offset == 0:
            outputs.append(block_prefixes[block_index])
            continue
        start = block_index * radix
        inputs: list[int] = []
        if block_index > 0:
            inputs.append(block_prefixes[block_index])
        inputs.extend(flags[start : start + offset])
        outputs.append(
            inputs[0] if len(inputs) == 1 else canonical_or_gate(inputs, fanins)
        )
    return tuple(outputs)


def exclusive_prefix_nodes(items: int, radix: int) -> int:
    """Count the recursive prefix PBS nodes; all one-input paths are forwarded."""
    if items < 1 or radix < 2:
        raise ValueError("invalid prefix shape")
    if items <= 2:
        return 0
    if items <= radix:
        return items - 2
    totals = 0
    expansion = 0
    groups = 0
    for start in range(0, items, radix):
        length = min(radix, items - start)
        groups += 1
        totals += int(length > 1)
        expansion += max(0, length - 2) if start == 0 else length - 1
    return totals + expansion + exclusive_prefix_nodes(groups, radix)


def _target_one(code: int) -> int:
    """Clear A50 target-one LUT on its proved reachable signed domain."""
    if code == 1 - P16:
        raise AssertionError("the target-one antipode must be unreachable")
    return int(code == 1)


def select_low_byte_candidates(
    initial_candidates: Sequence[bool | int], suffixes: Sequence[int]
) -> A50LowTrace:
    """Evaluate the A50 canonical-state selection over score bits b7..b0."""
    candidates = tuple(bool(value) for value in initial_candidates)
    suffixes = tuple(suffixes)
    if not 1 <= len(candidates) <= MAX_GALLERY_SIZE or len(candidates) != len(suffixes):
        raise ValueError("invalid candidate/suffix vectors")
    if any(not isinstance(value, int) or not 0 <= value <= 255 for value in suffixes):
        raise ValueError("suffixes must be bytes")

    states = tuple(int(candidate) for candidate in candidates)
    inputs_by_level: list[tuple[int, ...]] = []
    any_zero_by_level: list[int] = []
    states_by_level: list[tuple[int, ...]] = []
    for level, (bit_index, contribution) in enumerate(
        zip(SCORE_BITS, A50_BIT_CONTRIBUTIONS)
    ):
        bits = tuple((suffix >> bit_index) & 1 for suffix in suffixes)
        raw_inputs = tuple(
            state + contribution * bit for state, bit in zip(states, bits)
        )
        zeros = tuple(_target_one(value) for value in raw_inputs)
        any_zero = reduce_canonical_or(zeros)
        states = tuple(
            state + zero - any_zero
            for state, zero in zip(states, zeros)
        )
        if level in A50_CHUNK_END_LEVELS:
            states = tuple(_target_one(state) for state in states)
        inputs_by_level.append(raw_inputs)
        any_zero_by_level.append(any_zero)
        states_by_level.append(states)

    final = tuple(state == 1 for state in states)
    admitted_suffixes = [
        suffix for candidate, suffix in zip(candidates, suffixes) if candidate
    ]
    if admitted_suffixes:
        minimum = min(admitted_suffixes)
        reference = tuple(
            candidate and suffix == minimum
            for candidate, suffix in zip(candidates, suffixes)
        )
    else:
        reference = (False,) * len(candidates)
    if final != reference:
        raise AssertionError("A50 low-byte state machine disagrees with reference")
    return A50LowTrace(
        initial_candidates=candidates,
        suffixes=suffixes,
        zero_test_raw_inputs_by_level=tuple(inputs_by_level),
        any_zero_by_level=tuple(any_zero_by_level),
        states_after_level=tuple(states_by_level),
        final_candidates=final,
    )


def _local_first(group: Sequence[int], flag: int) -> int:
    """Frozen group-of-three local-first LUT: 0 or one-based position 1..3."""
    group = tuple(group)
    if not 1 <= len(group) <= SCAN_GROUP_SIZE:
        raise ValueError("scan groups have size 1..3")
    if len(group) == 1:
        return flag
    encoded = flag + 2 * group[0] + group[1]
    return {0: 0, 1: 3, 2: 2, 3: 1, 4: 1}[encoded]


def _reduce_digit(values: Sequence[int], fanins: list[int]) -> int:
    """Reduce one-hot p16 digits with identity PBS and singleton forwarding."""
    level = tuple(values)
    if not level or any(not 0 <= value <= 15 for value in level):
        raise ValueError("digits must be in 0..15")
    if sum(value != 0 for value in level) > 1:
        raise ValueError("A51 digit reduction relies on the selected-group one-hot invariant")
    while len(level) > 1:
        next_level: list[int] = []
        for start in range(0, len(level), A51_RADIX):
            chunk = level[start : start + A51_RADIX]
            if len(chunk) == 1:
                next_level.append(chunk[0])
                continue
            fanins.append(len(chunk))
            value = sum(chunk)
            if not 0 <= value <= 15:
                raise AssertionError("digit identity LUT escaped p16")
            next_level.append(value)
        level = tuple(next_level)
    return level[0]


def scan_first_candidate(candidates: Sequence[bool | int]) -> ScanTrace:
    """Run the retained group-of-three scan with radix-15 prefix/output trees."""
    canonical = tuple(int(bool(value)) for value in candidates)
    if not 1 <= len(canonical) <= MAX_GALLERY_SIZE:
        raise ValueError("gallery size must be in 1..128")

    group_or_fanins: list[int] = []
    groups = tuple(
        canonical[start : start + SCAN_GROUP_SIZE]
        for start in range(0, len(canonical), SCAN_GROUP_SIZE)
    )
    flags = tuple(
        group[0]
        if len(group) == 1
        else canonical_or_gate(group, group_or_fanins)
        for group in groups
    )
    local = tuple(_local_first(group, flag) for group, flag in zip(groups, flags))
    prefix_fanins: list[int] = []
    prefixes = exclusive_prefix_or(flags, fanins=prefix_fanins)

    low_digits: list[int] = []
    high_digits: list[int] = []
    for group_index, (state, prefix) in enumerate(zip(local, prefixes)):
        if prefix or state == 0:
            code = 0
        else:
            code = SCAN_GROUP_SIZE * group_index + state
        low_digits.append(code % P16)
        high_digits.append(code // P16)

    if sum(value != 0 for value in low_digits) > 1:
        raise AssertionError("more than one low digit survived selection")
    if sum(value != 0 for value in high_digits) > 1:
        raise AssertionError("more than one high digit survived selection")
    low_fanins: list[int] = []
    high_fanins: list[int] = []
    low_code = _reduce_digit(low_digits, low_fanins)
    high_digit = _reduce_digit(high_digits, high_fanins)
    code = low_code + P16 * high_digit
    reference = next((index + 1 for index, value in enumerate(canonical) if value), 0)
    if code != reference:
        raise AssertionError("A51 scan disagrees with first-candidate reference")
    return ScanTrace(
        candidates=tuple(bool(value) for value in canonical),
        group_flags=flags,
        local_first=local,
        group_prefixes=prefixes,
        low_digits=tuple(low_digits),
        high_digits=tuple(high_digits),
        low_code=low_code,
        high_digit=high_digit,
        code=code,
        group_or_fanins=tuple(group_or_fanins),
        prefix_or_fanins=tuple(prefix_fanins),
        low_digit_fanins=tuple(low_fanins),
        high_digit_fanins=tuple(high_fanins),
    )


def reference_exact_id(scores: Sequence[int], threshold: int) -> int:
    scores = tuple(scores)
    winner, minimum = min(enumerate(scores), key=lambda item: (item[1], item[0]))
    return winner + 1 if minimum <= threshold else 0


def evaluate_full(scores: Sequence[int], threshold: int) -> FullTrace:
    """Model the aligned-uniform-threshold A38/A50/A51 clear contract."""
    scores = tuple(scores)
    if not 1 <= len(scores) <= MAX_GALLERY_SIZE:
        raise ValueError("gallery size must be in 1..128")
    if any(not isinstance(score, int) or not 0 <= score <= 4_095 for score in scores):
        raise ValueError("scores must be 12-bit unsigned integers")

    admitted = tuple(score <= threshold for score in scores)
    admitted_high = [
        score >> 8 for score, is_admitted in zip(scores, admitted) if is_admitted
    ]
    if admitted_high:
        minimum_high = min(admitted_high)
        top_candidates = tuple(
            is_admitted and (score >> 8) == minimum_high
            for score, is_admitted in zip(scores, admitted)
        )
    else:
        top_candidates = (False,) * len(scores)

    low_trace = select_low_byte_candidates(
        top_candidates, tuple(score & 0xFF for score in scores)
    )
    scan = scan_first_candidate(low_trace.final_candidates)
    reference = reference_exact_id(scores, threshold)
    if scan.code != reference:
        raise AssertionError("full A51 clear pipeline disagrees with exact-ID contract")
    return FullTrace(
        scores=scores,
        threshold=threshold,
        a34_top_candidates=top_candidates,
        final_minimum_candidates=low_trace.final_candidates,
        scan=scan,
        code=scan.code,
        reference_code=reference,
    )


def _a34_reduction_nodes(items: int) -> int:
    nodes = 0
    while items > 1:
        items = ceil_div(items, 4)
        nodes += items
    return nodes


def _legacy_prefix_nodes(items: int) -> int:
    return exclusive_prefix_nodes(items, 4)


def _legacy_first_one_scan_nodes(items: int) -> int:
    groups = ceil_div(items, SCAN_GROUP_SIZE)
    group_totals = sum(
        min(SCAN_GROUP_SIZE, items - start) > 1
        for start in range(0, items, SCAN_GROUP_SIZE)
    )
    return group_totals + _legacy_prefix_nodes(groups) + items


def _output_bit_positions(gallery_size: int) -> tuple[int, ...]:
    return tuple(
        bit
        for bit in range(gallery_size.bit_length())
        if any(((index + 1) >> bit) & 1 for index in range(gallery_size))
    )


def _legacy_output_nodes(gallery_size: int) -> int:
    bit_nodes = 0
    for bit in _output_bit_positions(gallery_size):
        contributors = sum(
            ((index + 1) >> bit) & 1 for index in range(gallery_size)
        )
        bit_nodes += max(1, _a34_reduction_nodes(contributors))
    return bit_nodes + ceil_div(len(_output_bit_positions(gallery_size)), 3)


def scan_output_counts(
    gallery_size: int, *, radix: int, forward_digit_singletons: bool
) -> ScanOutputCounts:
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError("gallery size must be in 1..128")
    groups = ceil_div(gallery_size, SCAN_GROUP_SIZE)
    group_nodes = sum(
        min(SCAN_GROUP_SIZE, gallery_size - start) > 1
        for start in range(0, gallery_size, SCAN_GROUP_SIZE)
    )
    prefix_nodes = exclusive_prefix_nodes(groups, radix)
    digit_nodes = reduction_shape(
        groups, radix, forward_singletons=forward_digit_singletons
    ).pbs_nodes
    blind_rotations = 2 * group_nodes + prefix_nodes + groups + 2 * digit_nodes
    return ScanOutputCounts(
        gallery_size=gallery_size,
        groups=groups,
        group_or_nodes=group_nodes,
        local_first_nodes=group_nodes,
        prefix_nodes=prefix_nodes,
        selector_blind_rotations=groups,
        low_digit_nodes=digit_nodes,
        high_digit_nodes=digit_nodes,
        blind_rotations=blind_rotations,
        key_switches=blind_rotations,
        output_marginals=blind_rotations + groups,
    )


def a38_counts(gallery_size: int) -> OperationCounts:
    """Port of the frozen A38 structural formula for N=1..128."""
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError("gallery size must be in 1..128")
    n = gallery_size
    old_total = (
        27 * n
        + 8 * _a34_reduction_nodes(n)
        + _legacy_first_one_scan_nodes(n)
        + _legacy_output_nodes(n)
        - 1
    )
    old_low = 12 * n + 8 * _a34_reduction_nodes(n)
    old_scan_output = _legacy_first_one_scan_nodes(n) + _legacy_output_nodes(n)
    a38_low = 10 * n + 8 * reduction_shape(
        n, A38_RADIX, forward_singletons=False
    ).pbs_nodes
    a38_scan = scan_output_counts(
        n, radix=A38_RADIX, forward_digit_singletons=False
    )
    blind_rotations = old_total - old_low - old_scan_output + a38_low + a38_scan.blind_rotations
    return OperationCounts(
        blind_rotations=blind_rotations,
        key_switches=blind_rotations - 3 * n,
        output_marginals=blind_rotations + 4 * n + a38_scan.groups,
    )


def _low_radix_variant_counts(
    gallery_size: int, *, radix: int, forward_singletons: bool
) -> OperationCounts:
    baseline = a38_counts(gallery_size)
    old_nodes = reduction_shape(
        gallery_size, A38_RADIX, forward_singletons=False
    ).pbs_nodes
    new_nodes = reduction_shape(
        gallery_size, radix, forward_singletons=forward_singletons
    ).pbs_nodes
    saving = 8 * (old_nodes - new_nodes)
    return OperationCounts(
        baseline.blind_rotations - saving,
        baseline.key_switches - saving,
        baseline.output_marginals - saving,
    )


def a40_counts(gallery_size: int) -> OperationCounts:
    return _low_radix_variant_counts(
        gallery_size, radix=A40_RADIX, forward_singletons=True
    )


def a50_counts(gallery_size: int) -> OperationCounts:
    return _low_radix_variant_counts(
        gallery_size, radix=A51_RADIX, forward_singletons=True
    )


def count_breakdown(gallery_size: int) -> CountBreakdown:
    a38 = a38_counts(gallery_size)
    a38_low = 10 * gallery_size + 8 * reduction_shape(
        gallery_size, A38_RADIX, forward_singletons=False
    ).pbs_nodes
    old_scan = scan_output_counts(
        gallery_size, radix=A38_RADIX, forward_digit_singletons=False
    )
    invariant = a38.blind_rotations - a38_low - old_scan.blind_rotations
    low = 10 * gallery_size + 8 * reduction_shape(
        gallery_size, A51_RADIX, forward_singletons=True
    ).pbs_nodes
    new_scan = scan_output_counts(
        gallery_size, radix=A51_RADIX, forward_digit_singletons=True
    )
    blind_rotations = invariant + low + new_scan.blind_rotations
    total = OperationCounts(
        blind_rotations,
        blind_rotations - 3 * gallery_size,
        blind_rotations + 4 * gallery_size + new_scan.groups,
    )
    return CountBreakdown(
        gallery_size=gallery_size,
        invariant_blind_rotations=invariant,
        low_selection_blind_rotations=low,
        scan_output=new_scan,
        total=total,
    )


def a51_counts(gallery_size: int) -> OperationCounts:
    return count_breakdown(gallery_size).total


def a50_noise_sequence() -> tuple[tuple[int, int], ...]:
    """Return (zero-test input L1, update/refresh input L1) per A50 level."""
    rows: list[tuple[int, int]] = []
    state_l1 = 1
    for level in range(8):
        zero_test_l1 = state_l1 + 1
        updated_l1 = state_l1 + 1 + 1
        rows.append((zero_test_l1, updated_l1))
        state_l1 = 1 if level in A50_CHUNK_END_LEVELS else updated_l1
    return tuple(rows)


def noise_ledger_n127() -> tuple[NoiseRow, ...]:
    """Every changed or immediately adjacent A50/A51 LUT family at N=127."""
    n = 127
    groups = ceil_div(n, SCAN_GROUP_SIZE)
    low_nodes = reduction_shape(n, A51_RADIX, forward_singletons=True).pbs_nodes
    scan = scan_output_counts(n, radix=A51_RADIX, forward_digit_singletons=True)
    specifications = (
        (
            "A34 residual/top classifier (unchanged A44 premise)",
            n,
            8,
            1,
            "imported unchanged-family maximum; A51 does not re-derive its LUT equivalence",
        ),
        (
            "A50 target-one zero tests",
            8 * n,
            8,
            1,
            "per-level maxima are 2,4,6,8 then 2,4,6,8; weighted bit roots enter at L1=1",
        ),
        (
            "A50 boundary/final target-one refresh",
            2 * n,
            9,
            1,
            "state+z-a has L1 9 at b4 and b0",
        ),
        (
            "A50 candidate canonical OR",
            8 * low_nodes,
            15,
            1,
            "radix-15 sum of fresh canonical zero flags",
        ),
        (
            "scan group-of-three OR",
            scan.group_or_nodes,
            3,
            1,
            "tail group of one is forwarded",
        ),
        (
            "scan local-first",
            scan.local_first_nodes,
            4,
            1,
            "flag + 2*c0 + c1; tail group of one is forwarded",
        ),
        (
            "scan radix-15 exclusive-prefix OR",
            scan.prefix_nodes,
            15,
            1,
            "all gate inputs are canonical; one-input paths are forwarded",
        ),
        (
            "scan group selector",
            groups,
            5,
            2,
            "local_first + 4*prefix; one blind rotation emits low/high digit marginals",
        ),
        (
            "low-digit identity/final reduction",
            scan.low_digit_nodes,
            15,
            1,
            "at most 15 fresh roots per chunk; global selected-group one-hot keeps plaintext in 0..15",
        ),
        (
            "high-digit identity/final reduction",
            scan.high_digit_nodes,
            15,
            1,
            "at most 15 fresh roots per chunk; logical high digit remains 0..7",
        ),
    )
    return tuple(
        NoiseRow(
            family=family,
            instances_n127=instances,
            maximum_input_raw_l1=raw_l1,
            output_marginals_per_blind_rotation=marginals,
            fits_a44_max15_without_rescaling=raw_l1 <= A44_MAX_NOISE_LEVEL,
            note=note,
        )
        for family, instances, raw_l1, marginals, note in specifications
    )


def validate_static() -> dict[str, object]:
    """Run the complete cheap certificate used by the command-line report."""
    for length in range(2, A51_RADIX + 1):
        for bits in itertools.product((0, 1), repeat=length):
            assert canonical_or_gate(bits) == int(any(bits))
    geometry = p16_or_geometry()
    assert geometry.centers_0_through_15_exact
    assert geometry.strict_interior_errors_exact
    assert geometry.radix_16_negacyclic_no_go

    prefix_fanins: list[int] = []
    pattern = tuple((index % 4) == 1 for index in range(43))
    prefix = exclusive_prefix_or(pattern, fanins=prefix_fanins)
    assert prefix == tuple(int(any(pattern[:index])) for index in range(43))
    assert len(prefix_fanins) == exclusive_prefix_nodes(43, A51_RADIX) == 43
    assert max(prefix_fanins) == 15

    fixtures = (
        ((1,), 1),
        ((0,), 0),
        ((1, 1), 1),
        ((0,) * 126 + (1,), 127),
        ((0,) * 127 + (1,), 128),
        ((0,) * 63 + (1,) + (0,) * 62 + (1,), 64),
    )
    for candidates, expected in fixtures:
        assert scan_first_candidate(candidates).code == expected

    ledger = noise_ledger_n127()
    assert all(row.fits_a44_max15_without_rescaling for row in ledger)
    n127 = count_breakdown(127)
    assert n127.total == OperationCounts(3_432, 3_051, 3_983)
    return {
        "verdict": "conditional_static_go_under_a44_max15",
        "scope": "aligned_uniform_threshold_fast_path_static_only",
        "n127": {
            "a38": asdict(a38_counts(127)),
            "a40": asdict(a40_counts(127)),
            "a50": asdict(a50_counts(127)),
            "a51": asdict(a51_counts(127)),
            "a51_delta_vs_a38": asdict(a51_counts(127) - a38_counts(127)),
            "a51_delta_vs_a40": asdict(a51_counts(127) - a40_counts(127)),
            "a51_delta_vs_a50": asdict(a51_counts(127) - a50_counts(127)),
            "breakdown": asdict(n127),
        },
        "candidate_tree_shapes": {
            "a38_radix5": asdict(
                reduction_shape(127, A38_RADIX, forward_singletons=False)
            ),
            "a40_radix7": asdict(
                reduction_shape(127, A40_RADIX, forward_singletons=True)
            ),
            "a51_radix15": asdict(
                reduction_shape(127, A51_RADIX, forward_singletons=True)
            ),
        },
        "p16_radix15_or_geometry": asdict(geometry),
        "group_count": 43,
        "prefix_nodes": {
            "a38_radix5": exclusive_prefix_nodes(43, A38_RADIX),
            "a51_radix15": exclusive_prefix_nodes(43, A51_RADIX),
        },
        "digit_tree_shapes": {
            "a38_radix5": asdict(
                reduction_shape(43, A38_RADIX, forward_singletons=False)
            ),
            "a51_radix15": asdict(
                reduction_shape(43, A51_RADIX, forward_singletons=True)
            ),
        },
        "a50_noise_sequence_zero_test_then_update": a50_noise_sequence(),
        "noise_ledger_n127": [asdict(row) for row in ledger],
        "maximum_changed_or_adjacent_raw_l1": max(
            row.maximum_input_raw_l1 for row in ledger
        ),
        "margin_rescaling_factor": 1,
        "conditional_union_only": {
            "event_count": a51_counts(127).output_marginals,
            "per_event_log2_p_fail": A44_LOG2_P_FAIL_PER_EVENT,
            "query_log2_upper_if_every_event_inherits_contract": math.log2(
                a51_counts(127).output_marginals
            )
            + A44_LOG2_P_FAIL_PER_EVENT,
            "end_to_end_numeric_upper": None,
        },
        "non_eligible_structures": (
            "A34 category-state reduction is not a canonical Boolean OR",
            "group size remains three because local-first/selector state geometry is not a radix substitution",
            "score extraction and classifier LUTs are invariant prerequisites, not redesigned here",
        ),
        "open_obligations": (
            "freeze and implement A50 canonical-state raw LUTs in Rust",
            "implement radix-15 prefix and digit trees with singleton forwarding",
            "validate reachable centers, strict boundaries, first ties, reject, and IDs 127/128 under fresh-key FHE",
            "recount runtime BR, KS, and shared-rotation marginals",
            "prove custom-LUT and ManyLUT events inherit A44 per-event p-fail",
            "add the Gaussian initial-score tail and authenticated parameter binding for an end-to-end bound",
            "benchmark latency on a controlled paired workload",
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit full JSON")
    args = parser.parse_args()
    payload = validate_static()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("A51 static verdict:", payload["verdict"])
        print("N=127 A51 counts:", payload["n127"]["a51"])
        print("N=127 delta vs A38:", payload["n127"]["a51_delta_vs_a38"])
        print("maximum changed/adjacent raw L1:", payload["maximum_changed_or_adjacent_raw_l1"])
        print(
            "end-to-end numeric upper:",
            payload["conditional_union_only"]["end_to_end_numeric_upper"],
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
