#!/usr/bin/env python3
"""Static A53 model: group-four scan and radix-15 scan/output after A50.

The model is deliberately clear/static.  It proves the reachable p16 geometry,
constructs literal negacyclic dual-sample selector bodies, tracks conservative
raw L1 without margin rescaling, and projects structural BR/KS/marginal counts.
It never invokes TFHE, Cargo, key generation, or a latency benchmark.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import pathlib
import runpy
from dataclasses import asdict, dataclass
from functools import cache
from typing import Iterator, Mapping, Sequence


MAX_GALLERY_SIZE = 128
GROUP_SIZE = 4
REDUCTION_RADIX = 15
OUTPUT_BASE = 15
P16 = 16
SIGNED_INPUT_PERIOD = 2 * P16
POLYNOMIAL_SIZE = 2_048
BOX_SIZE = POLYNOMIAL_SIZE // P16
HALF_BOX_SIZE = BOX_SIZE // 2
STRICT_MARGIN_RADIUS = HALF_BOX_SIZE - 1
BOOL_OUTPUT_PERIOD = 32
CODE_OUTPUT_PERIOD = 256
A44_MAX_NOISE_LEVEL = 15
CURRENT_MAX_NOISE_LEVEL = 5
A44_PER_EVENT_LOG2_P_FAIL = -64.088

A50_MODEL_SHA256 = "19196d9e17a30e5197601dacf42b9416239608a99489b4a1a284f488e102c4cb"
A50_README_SHA256 = "e77950baab2beb45010d7d2deb44c7c6ca265a7d21408c61a4627db73b7481e3"


@dataclass(frozen=True)
class PrimitiveCounts:
    blind_rotations: int
    key_switches: int
    output_marginals: int

    def __add__(self, other: "PrimitiveCounts") -> "PrimitiveCounts":
        return PrimitiveCounts(
            self.blind_rotations + other.blind_rotations,
            self.key_switches + other.key_switches,
            self.output_marginals + other.output_marginals,
        )

    def __sub__(self, other: "PrimitiveCounts") -> "PrimitiveCounts":
        return PrimitiveCounts(
            self.blind_rotations - other.blind_rotations,
            self.key_switches - other.key_switches,
            self.output_marginals - other.output_marginals,
        )


@dataclass(frozen=True)
class SelectorLayout:
    group_index: int
    group_length: int
    output_base: int
    output_period: int
    direct_code_scale: bool
    second_sample_degree: int
    low_public_offset: int
    high_public_offset: int
    assigned_independent_slots: int


@dataclass(frozen=True)
class SelectorLayoutAudit:
    ordinary_layouts_checked: int
    direct_layouts_checked: int
    ordinary_layouts_found: int
    direct_layouts_found: int
    second_sample_degree: int
    all_centers_and_strict_margins_exact: bool
    base16_full_group_failures_with_all_box_aligned_degrees: tuple[int, ...]
    base15_fixed_half_turn_layouts_complete: bool


@dataclass(frozen=True)
class NoiseAudit:
    group_flag_l1: int
    local_first_l1_by_group_length: tuple[int, ...]
    prefix_or_l1: int
    signed_selector_l1: int
    digit_reduction_l1: int
    maximum_raw_l1: int
    current_max_noise_level: int
    a44_max_noise_level: int
    current_parameter_covers_without_rescaling: bool
    a44_covers_without_rescaling: bool
    margin_rescaling_factor: int


@dataclass(frozen=True)
class GroupTrace:
    group_index: int
    group_length: int
    candidates: tuple[bool, ...]
    flag: int
    local_phase: int
    local_first: int
    prefix: int
    selector_input: int
    low_output: int
    high_output: int
    selected_code: int


@dataclass(frozen=True)
class ScanTrace:
    gallery_size: int
    candidates: tuple[bool, ...]
    group_flags: tuple[int, ...]
    group_prefixes: tuple[int, ...]
    groups: tuple[GroupTrace, ...]
    reduced_low: int
    reduced_high: int
    code: int
    reference_code: int


@dataclass(frozen=True)
class ScanCounts:
    gallery_size: int
    groups: int
    non_singleton_groups: int
    group_flag_nodes: int
    local_first_nodes: int
    prefix_nodes: int
    selector_blind_rotations: int
    selector_key_switches: int
    selector_marginals: int
    digit_reduction_nodes: int
    total: PrimitiveCounts


@dataclass(frozen=True)
class FullCountRow:
    gallery_size: int
    a38: PrimitiveCounts
    a50: PrimitiveCounts
    a53_scan: PrimitiveCounts
    a53_full: PrimitiveCounts
    a53_delta_vs_a50: PrimitiveCounts
    a53_delta_vs_a38: PrimitiveCounts


@dataclass(frozen=True)
class LargerGroupSearch:
    first_excluded_group_size: int
    feature_order: tuple[str, ...]
    coefficient_l1_limit: int
    signed_integer_coefficient_vectors_checked: int
    Boolean_patterns_per_vector: int
    exact_scalar_phase_solutions: int
    every_vector_has_cross_priority_exact_phase_collision: bool
    public_input_offset_can_repair_exact_collision: bool
    public_output_offset_or_arbitrary_codes_can_repair_exact_collision: bool
    excludes_every_larger_group_by_restriction: bool
    excluded_class: str
    not_excluded: tuple[str, ...]


@cache
def _a50_namespace() -> dict[str, object]:
    path = (
        pathlib.Path(__file__).resolve().parents[1]
        / "a50-canonical-radix15-model"
        / "a50_canonical_radix15_model.py"
    )
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != A50_MODEL_SHA256:
        raise AssertionError(f"A50 provenance drift: {digest}")
    return runpy.run_path(str(path))


def _negacyclic_sample(
    body: Sequence[int], degree: int, output_period: int
) -> int:
    if len(body) != POLYNOMIAL_SIZE:
        raise ValueError("unexpected accumulator body length")
    cycles, index = divmod(degree, POLYNOMIAL_SIZE)
    value = body[index]
    return value % output_period if cycles % 2 == 0 else (-value) % output_period


def _assign_body_value(
    assignments: dict[int, int], index: int, value: int, output_period: int
) -> bool:
    value %= output_period
    existing = assignments.get(index)
    if existing is not None and existing != value:
        return False
    assignments[index] = value
    return True


def _build_robust_body(
    slot_values: Mapping[int, int], output_period: int
) -> tuple[int, ...]:
    """Materialize strict standard-half-slot cells for independent slots 0..15."""
    coefficients: dict[int, int] = {}
    for slot, desired in slot_values.items():
        if not 0 <= slot < P16:
            raise ValueError("independent slot is outside 0..15")
        for error in range(-STRICT_MARGIN_RADIUS, STRICT_MARGIN_RADIUS + 1):
            cycles, index = divmod(slot * BOX_SIZE + error, POLYNOMIAL_SIZE)
            body_value = desired if cycles % 2 == 0 else -desired
            if not _assign_body_value(
                coefficients, index, body_value, output_period
            ):
                raise AssertionError("overlapping robust cells require different values")
    return tuple(coefficients.get(index, 0) for index in range(POLYNOMIAL_SIZE))


def _virtual_requirement(
    phase: int, raw_output: int, output_period: int
) -> tuple[int, int]:
    virtual = phase % SIGNED_INPUT_PERIOD
    slot = virtual % P16
    required = raw_output if virtual < P16 else -raw_output
    return slot, required % output_period


def _first_position(bits: Sequence[bool | int]) -> int:
    return next((index + 1 for index, bit in enumerate(bits) if bit), 0)


def group_local_phase(bits: Sequence[bool | int]) -> int:
    values = tuple(bool(value) for value in bits)
    if not 1 <= len(values) <= GROUP_SIZE:
        raise ValueError("group length must be in 1..4")
    padded = values + (False,) * (GROUP_SIZE - len(values))
    flag = int(any(padded))
    return flag + 4 * int(padded[0]) + 2 * int(padded[1]) + int(padded[2])


@cache
def local_phase_table(group_length: int) -> tuple[tuple[int, int], ...]:
    if not 1 <= group_length <= GROUP_SIZE:
        raise ValueError("group length must be in 1..4")
    outputs: dict[int, int] = {}
    for bits in itertools.product((False, True), repeat=group_length):
        phase = group_local_phase(bits)
        position = _first_position(bits)
        existing = outputs.get(phase)
        if existing is not None and existing != position:
            raise AssertionError("local phase aliases different first positions")
        outputs[phase] = position
    return tuple(sorted(outputs.items()))


@cache
def local_first_body(group_length: int) -> tuple[int, ...]:
    slots = dict(local_phase_table(group_length))
    body = _build_robust_body(slots, BOOL_OUTPUT_PERIOD)
    for phase, expected in local_phase_table(group_length):
        for error in range(-STRICT_MARGIN_RADIUS, STRICT_MARGIN_RADIUS + 1):
            actual = _negacyclic_sample(
                body, phase * BOX_SIZE + error, BOOL_OUTPUT_PERIOD
            )
            if actual != expected:
                raise AssertionError("local-first robust body is not exact")
    return body


@cache
def canonical_or_body() -> tuple[int, ...]:
    slots = {slot: int(slot > 0) for slot in range(P16)}
    body = _build_robust_body(slots, BOOL_OUTPUT_PERIOD)
    for count in range(REDUCTION_RADIX + 1):
        expected = int(count > 0)
        for error in range(-STRICT_MARGIN_RADIUS, STRICT_MARGIN_RADIUS + 1):
            actual = _negacyclic_sample(
                body, count * BOX_SIZE + error, BOOL_OUTPUT_PERIOD
            )
            if actual != expected:
                raise AssertionError("radix-15 OR robust body is not exact")
    return body


@cache
def identity_digit_body() -> tuple[int, ...]:
    slots = {slot: slot for slot in range(P16)}
    body = _build_robust_body(slots, BOOL_OUTPUT_PERIOD)
    for digit in range(P16):
        for error in range(-STRICT_MARGIN_RADIUS, STRICT_MARGIN_RADIUS + 1):
            actual = _negacyclic_sample(
                body, digit * BOX_SIZE + error, BOOL_OUTPUT_PERIOD
            )
            if actual != digit:
                raise AssertionError("identity digit body is not exact")
    return body


@cache
def final_digit_body(multiplier: int) -> tuple[int, ...]:
    """Final p16 digit LUT at Delta_code, for low (1) or base-15 high (15)."""
    if multiplier not in (1, OUTPUT_BASE):
        raise ValueError("final digit multiplier must be one or the output base")
    slots = {
        slot: (multiplier * slot) % CODE_OUTPUT_PERIOD for slot in range(P16)
    }
    body = _build_robust_body(slots, CODE_OUTPUT_PERIOD)
    for digit in range(P16):
        expected = multiplier * digit
        for error in range(-STRICT_MARGIN_RADIUS, STRICT_MARGIN_RADIUS + 1):
            actual = _negacyclic_sample(
                body, digit * BOX_SIZE + error, CODE_OUTPUT_PERIOD
            )
            if actual != expected:
                raise AssertionError("final digit body is not exact")
    return body


def _selector_outputs(
    group_index: int, group_length: int, *, direct_code_scale: bool
) -> dict[int, tuple[int, int]]:
    if not 0 <= group_index < (MAX_GALLERY_SIZE + GROUP_SIZE - 1) // GROUP_SIZE:
        raise ValueError("group index is outside supported gallery")
    if not 1 <= group_length <= GROUP_SIZE:
        raise ValueError("group length must be in 1..4")
    if direct_code_scale and group_index != 0:
        raise ValueError("direct code scale is used only for the sole group")
    outputs: dict[int, tuple[int, int]] = {}
    for prefix in (0, 1):
        for local in range(group_length + 1):
            phase = local - GROUP_SIZE * prefix
            code = GROUP_SIZE * group_index + local if local and not prefix else 0
            low_digit = code % OUTPUT_BASE
            high_digit = code // OUTPUT_BASE
            desired = (
                (low_digit, OUTPUT_BASE * high_digit)
                if direct_code_scale
                else (low_digit, high_digit)
            )
            existing = outputs.get(phase)
            if existing is not None and existing != desired:
                raise AssertionError("selector phase aliases different desired outputs")
            outputs[phase] = desired
    return outputs


def _selector_slot_assignments(
    outputs: Mapping[int, tuple[int, int]],
    low_offset: int,
    high_offset: int,
    output_period: int,
    second_degree_slots: int,
) -> dict[int, int] | None:
    assignments: dict[int, int] = {}
    for phase, (desired_low, desired_high) in outputs.items():
        for virtual_phase, desired, public_offset in (
            (phase, desired_low, low_offset),
            (phase + second_degree_slots, desired_high, high_offset),
        ):
            raw = (desired - public_offset) % output_period
            slot, required = _virtual_requirement(
                virtual_phase, raw, output_period
            )
            if not _assign_body_value(assignments, slot, required, output_period):
                return None
    return assignments


def _verify_selector_layout(layout: SelectorLayout) -> None:
    outputs = _selector_outputs(
        layout.group_index,
        layout.group_length,
        direct_code_scale=layout.direct_code_scale,
    )
    assignments = _selector_slot_assignments(
        outputs,
        layout.low_public_offset,
        layout.high_public_offset,
        layout.output_period,
        layout.second_sample_degree // BOX_SIZE,
    )
    if assignments is None:
        raise AssertionError("saved selector layout is inconsistent")
    body = _build_robust_body(assignments, layout.output_period)
    for phase, (desired_low, desired_high) in outputs.items():
        for error in range(-STRICT_MARGIN_RADIUS, STRICT_MARGIN_RADIUS + 1):
            raw_low = _negacyclic_sample(
                body, phase * BOX_SIZE + error, layout.output_period
            )
            raw_high = _negacyclic_sample(
                body,
                phase * BOX_SIZE + layout.second_sample_degree + error,
                layout.output_period,
            )
            low = (raw_low + layout.low_public_offset) % layout.output_period
            high = (raw_high + layout.high_public_offset) % layout.output_period
            if (low, high) != (desired_low, desired_high):
                raise AssertionError(
                    "dual-sample selector fails literal negacyclic margin check"
                )


@cache
def selector_layout(
    group_index: int, group_length: int, direct_code_scale: bool = False
) -> SelectorLayout:
    """Find and verify a literal degree-0/N/2 two-output selector.

    Base 16 collides for boundary groups.  Base 15 plus independent public
    plaintext offsets after the two extractions admits every group and tail.
    """
    output_period = CODE_OUTPUT_PERIOD if direct_code_scale else BOOL_OUTPUT_PERIOD
    outputs = _selector_outputs(
        group_index, group_length, direct_code_scale=direct_code_scale
    )
    second_degree_slots = P16 // 2
    for low_offset in range(output_period):
        for high_offset in range(output_period):
            assignments = _selector_slot_assignments(
                outputs,
                low_offset,
                high_offset,
                output_period,
                second_degree_slots,
            )
            if assignments is None:
                continue
            layout = SelectorLayout(
                group_index=group_index,
                group_length=group_length,
                output_base=OUTPUT_BASE,
                output_period=output_period,
                direct_code_scale=direct_code_scale,
                second_sample_degree=POLYNOMIAL_SIZE // 2,
                low_public_offset=low_offset,
                high_public_offset=high_offset,
                assigned_independent_slots=len(assignments),
            )
            _verify_selector_layout(layout)
            return layout
    raise AssertionError("no robust base-15 dual-sample selector layout")


def _base_layout_exists(
    group_index: int,
    group_length: int,
    output_base: int,
    second_degree_slots: int,
) -> bool:
    outputs: dict[int, tuple[int, int]] = {}
    for prefix in (0, 1):
        for local in range(group_length + 1):
            phase = local - GROUP_SIZE * prefix
            code = GROUP_SIZE * group_index + local if local and not prefix else 0
            desired = (code % output_base, code // output_base)
            existing = outputs.get(phase)
            if existing is not None and existing != desired:
                return False
            outputs[phase] = desired
    for low_offset in range(BOOL_OUTPUT_PERIOD):
        for high_offset in range(BOOL_OUTPUT_PERIOD):
            if (
                _selector_slot_assignments(
                    outputs,
                    low_offset,
                    high_offset,
                    BOOL_OUTPUT_PERIOD,
                    second_degree_slots,
                )
                is not None
            ):
                return True
    return False


@cache
def selector_layout_audit() -> SelectorLayoutAudit:
    ordinary = [
        selector_layout(group, length)
        for group in range((MAX_GALLERY_SIZE + GROUP_SIZE - 1) // GROUP_SIZE)
        for length in range(1, GROUP_SIZE + 1)
    ]
    direct = [selector_layout(0, length, True) for length in range(1, GROUP_SIZE + 1)]

    base16_failures = []
    for group in range((MAX_GALLERY_SIZE + GROUP_SIZE - 1) // GROUP_SIZE):
        if not any(
            _base_layout_exists(group, GROUP_SIZE, 16, degree)
            for degree in range(1, P16)
        ):
            base16_failures.append(group)
    return SelectorLayoutAudit(
        ordinary_layouts_checked=len(ordinary),
        direct_layouts_checked=len(direct),
        ordinary_layouts_found=len(ordinary),
        direct_layouts_found=len(direct),
        second_sample_degree=POLYNOMIAL_SIZE // 2,
        all_centers_and_strict_margins_exact=True,
        base16_full_group_failures_with_all_box_aligned_degrees=tuple(
            base16_failures
        ),
        base15_fixed_half_turn_layouts_complete=len(ordinary) == 128,
    )


def exclusive_prefix(flags: Sequence[bool | int]) -> tuple[int, ...]:
    prefixes, _ = exclusive_prefix_with_count(flags)
    return prefixes


def exclusive_prefix_with_count(
    flags: Sequence[bool | int], radix: int = REDUCTION_RADIX
) -> tuple[tuple[int, ...], int]:
    """Mirror the recursive block-prefix topology and count actual PBS nodes."""
    values = tuple(int(bool(flag)) for flag in flags)
    if not values or radix < 2:
        raise ValueError("prefix needs a non-empty Boolean vector and radix >=2")

    nodes = 0

    def or_gate(inputs: Sequence[int]) -> int:
        nonlocal nodes
        if not inputs:
            return 0
        if len(inputs) == 1:
            return inputs[0]
        if len(inputs) > radix:
            raise AssertionError("OR gate exceeds configured radix")
        nodes += 1
        return int(any(inputs))

    def recurse(current: tuple[int, ...]) -> tuple[int, ...]:
        if len(current) <= radix:
            return tuple(or_gate(current[:index]) for index in range(len(current)))
        blocks = tuple(
            current[start : start + radix]
            for start in range(0, len(current), radix)
        )
        totals = tuple(or_gate(block) for block in blocks)
        block_prefixes = recurse(totals)
        prefixes: list[int] = []
        for index in range(len(current)):
            block = index // radix
            offset = index % radix
            if offset == 0:
                prefixes.append(block_prefixes[block])
                continue
            inputs = list(current[block * radix : index])
            if block > 0:
                inputs.insert(0, block_prefixes[block])
            prefixes.append(or_gate(inputs))
        return tuple(prefixes)

    result = recurse(values)
    reference = tuple(int(any(values[:index])) for index in range(len(values)))
    if result != reference:
        raise AssertionError("recursive radix-15 prefix disagrees with direct prefix")
    return result, nodes


def reduce_one_hot_digits_with_count(
    values: Sequence[int], radix: int = REDUCTION_RADIX
) -> tuple[int, int]:
    """Reduce one-hot p16 digits, forwarding singleton tails exactly."""
    level = tuple(values)
    if not level or any(not 0 <= value < P16 for value in level):
        raise ValueError("digit reduction needs non-empty p16 digits")
    if sum(value != 0 for value in level) > 1:
        raise AssertionError("digit vector is not globally one-hot")
    nodes = 0
    while len(level) > 1:
        next_level: list[int] = []
        for start in range(0, len(level), radix):
            chunk = level[start : start + radix]
            if len(chunk) == 1:
                next_level.append(chunk[0])
            else:
                nodes += 1
                value = sum(chunk)
                if not 0 <= value < P16:
                    raise AssertionError("digit chunk escaped p16")
                next_level.append(value)
        level = tuple(next_level)
    return level[0], nodes


def evaluate_scan(candidates: Sequence[bool | int]) -> ScanTrace:
    canonical = tuple(bool(candidate) for candidate in candidates)
    if not 1 <= len(canonical) <= MAX_GALLERY_SIZE:
        raise ValueError("gallery size must be in 1..128")
    groups = tuple(
        canonical[start : start + GROUP_SIZE]
        for start in range(0, len(canonical), GROUP_SIZE)
    )
    flags = tuple(int(any(group)) for group in groups)
    prefixes, prefix_nodes = exclusive_prefix_with_count(flags)
    if prefix_nodes != exclusive_prefix_nodes(len(flags)):
        raise AssertionError("runtime prefix mirror disagrees with structural counter")
    direct = len(groups) == 1
    traces: list[GroupTrace] = []
    low_outputs: list[int] = []
    high_outputs: list[int] = []

    for group_index, (group, flag, prefix) in enumerate(
        zip(groups, flags, prefixes)
    ):
        phase = group_local_phase(group)
        local = _first_position(group)
        if dict(local_phase_table(len(group)))[phase] != local:
            raise AssertionError("local-first table mismatch")
        selector_input = local - GROUP_SIZE * prefix
        selector_layout(group_index, len(group), direct)
        outputs = _selector_outputs(
            group_index, len(group), direct_code_scale=direct
        )
        low, high = outputs[selector_input]
        low_outputs.append(low)
        high_outputs.append(high)
        selected_code = low + high if direct else low + OUTPUT_BASE * high
        traces.append(
            GroupTrace(
                group_index=group_index,
                group_length=len(group),
                candidates=group,
                flag=flag,
                local_phase=phase,
                local_first=local,
                prefix=prefix,
                selector_input=selector_input,
                low_output=low,
                high_output=high,
                selected_code=selected_code,
            )
        )

    if direct:
        reduced_low = low_outputs[0]
        reduced_high = high_outputs[0]
        code = reduced_low + reduced_high
    else:
        if sum(value != 0 for value in low_outputs) > 1:
            raise AssertionError("low outputs are not globally one-hot")
        if sum(value != 0 for value in high_outputs) > 1:
            raise AssertionError("high outputs are not globally one-hot")
        reduced_low, low_nodes = reduce_one_hot_digits_with_count(low_outputs)
        reduced_high, high_nodes = reduce_one_hot_digits_with_count(high_outputs)
        if low_nodes + high_nodes != 2 * reduction_nodes(len(groups)):
            raise AssertionError("digit mirror disagrees with structural counter")
        if not 0 <= reduced_low < OUTPUT_BASE or not 0 <= reduced_high < P16:
            raise AssertionError("base-15 digit escaped p16")
        code = reduced_low + OUTPUT_BASE * reduced_high

    reference_code = next(
        (index + 1 for index, candidate in enumerate(canonical) if candidate), 0
    )
    if code != reference_code:
        raise AssertionError("group-four scan violates first-tie exact ID")
    return ScanTrace(
        gallery_size=len(canonical),
        candidates=canonical,
        group_flags=flags,
        group_prefixes=prefixes,
        groups=tuple(traces),
        reduced_low=reduced_low,
        reduced_high=reduced_high,
        code=code,
        reference_code=reference_code,
    )


def noise_audit() -> NoiseAudit:
    local_l1 = (1, 7, 8, 8)
    maximum = max(4, *local_l1, REDUCTION_RADIX, 5, REDUCTION_RADIX)
    return NoiseAudit(
        group_flag_l1=GROUP_SIZE,
        local_first_l1_by_group_length=local_l1,
        prefix_or_l1=REDUCTION_RADIX,
        signed_selector_l1=1 + GROUP_SIZE,
        digit_reduction_l1=REDUCTION_RADIX,
        maximum_raw_l1=maximum,
        current_max_noise_level=CURRENT_MAX_NOISE_LEVEL,
        a44_max_noise_level=A44_MAX_NOISE_LEVEL,
        current_parameter_covers_without_rescaling=maximum
        <= CURRENT_MAX_NOISE_LEVEL,
        a44_covers_without_rescaling=maximum <= A44_MAX_NOISE_LEVEL,
        margin_rescaling_factor=1,
    )


def reduction_nodes(items: int, radix: int = REDUCTION_RADIX) -> int:
    """Reduction gates when a singleton tail is forwarded without a PBS."""
    if items < 1 or radix < 2:
        raise ValueError("invalid reduction shape")
    nodes = 0
    while items > 1:
        full, tail = divmod(items, radix)
        nodes += full + int(tail >= 2)
        items = full + int(tail > 0)
    return nodes


def exclusive_prefix_nodes(items: int, radix: int = REDUCTION_RADIX) -> int:
    """Exact recursive block-prefix count with singleton forwarding."""
    if items < 1 or radix < 2:
        raise ValueError("invalid prefix shape")
    if items <= 2:
        return 0
    if items <= radix:
        return items - 2
    lengths = tuple(min(radix, items - start) for start in range(0, items, radix))
    block_totals = sum(length >= 2 for length in lengths)
    expansion = max(lengths[0] - 2, 0) + sum(
        length - 1 for length in lengths[1:]
    )
    return (
        block_totals
        + expansion
        + exclusive_prefix_nodes(len(lengths), radix)
    )


def scan_counts(gallery_size: int) -> ScanCounts:
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError("gallery size must be in 1..128")
    lengths = tuple(
        min(GROUP_SIZE, gallery_size - start)
        for start in range(0, gallery_size, GROUP_SIZE)
    )
    groups = len(lengths)
    non_singletons = sum(length >= 2 for length in lengths)
    group_flags = non_singletons
    local_first = non_singletons
    prefix = exclusive_prefix_nodes(groups)
    selectors = groups
    digit_nodes = 2 * reduction_nodes(groups)
    blind_rotations = group_flags + local_first + prefix + selectors + digit_nodes
    marginals = group_flags + local_first + prefix + 2 * selectors + digit_nodes
    return ScanCounts(
        gallery_size=gallery_size,
        groups=groups,
        non_singleton_groups=non_singletons,
        group_flag_nodes=group_flags,
        local_first_nodes=local_first,
        prefix_nodes=prefix,
        selector_blind_rotations=selectors,
        selector_key_switches=selectors,
        selector_marginals=2 * selectors,
        digit_reduction_nodes=digit_nodes,
        total=PrimitiveCounts(blind_rotations, blind_rotations, marginals),
    )


def full_count_row(gallery_size: int) -> FullCountRow:
    namespace = _a50_namespace()
    raw_a38 = namespace["a38_counts"](gallery_size)
    raw_a50 = namespace["a50_counts"](gallery_size)
    old_scan_br, old_scan_marginals = namespace["_a38_scan_output_nodes"](
        gallery_size
    )
    a38 = PrimitiveCounts(
        raw_a38.blind_rotations,
        raw_a38.key_switches,
        raw_a38.output_marginals,
    )
    a50 = PrimitiveCounts(
        raw_a50.blind_rotations,
        raw_a50.key_switches,
        raw_a50.output_marginals,
    )
    old_scan = PrimitiveCounts(old_scan_br, old_scan_br, old_scan_marginals)
    new_scan = scan_counts(gallery_size).total
    full = a50 - old_scan + new_scan
    return FullCountRow(
        gallery_size=gallery_size,
        a38=a38,
        a50=a50,
        a53_scan=new_scan,
        a53_full=full,
        a53_delta_vs_a50=full - a50,
        a53_delta_vs_a38=full - a38,
    )


def all_count_rows() -> tuple[FullCountRow, ...]:
    return tuple(full_count_row(size) for size in range(1, MAX_GALLERY_SIZE + 1))


def _integer_vectors_exact_l1(
    dimensions: int, total_l1: int, prefix: tuple[int, ...] = ()
) -> Iterator[tuple[int, ...]]:
    if dimensions == 1:
        if total_l1 == 0:
            yield prefix + (0,)
        else:
            yield prefix + (total_l1,)
            yield prefix + (-total_l1,)
        return
    for magnitude in range(total_l1 + 1):
        if magnitude == 0:
            yield from _integer_vectors_exact_l1(
                dimensions - 1, total_l1, prefix + (0,)
            )
        else:
            yield from _integer_vectors_exact_l1(
                dimensions - 1, total_l1 - magnitude, prefix + (magnitude,)
            )
            yield from _integer_vectors_exact_l1(
                dimensions - 1, total_l1 - magnitude, prefix + (-magnitude,)
            )


@cache
def larger_group_search() -> LargerGroupSearch:
    """Exhaust the broad one-flag scalar-affine class first at group size five.

    Features are one fresh group flag plus every candidate bit.  Any public
    input offset preserves exact phase equality.  Every coefficient vector with
    raw L1<=15 aliases two distinct priority classes at the *same* phase mod 32,
    so neither antiperiodic output coding nor any public output offset can help.
    """
    group_size = 5
    patterns = []
    for mask in range(1 << group_size):
        bits = tuple((mask >> index) & 1 for index in range(group_size))
        priority = _first_position(bits)
        patterns.append((mask, bits, priority))

    checked = 0
    solutions = 0
    for l1 in range(A44_MAX_NOISE_LEVEL + 1):
        for coefficients in _integer_vectors_exact_l1(group_size + 1, l1):
            checked += 1
            flag_coefficient, *candidate_coefficients = coefficients
            priorities_by_phase: dict[int, int] = {}
            collision = False
            for mask, bits, priority in patterns:
                phase = (
                    flag_coefficient * int(mask != 0)
                    + sum(
                        coefficient * bit
                        for coefficient, bit in zip(candidate_coefficients, bits)
                    )
                ) % SIGNED_INPUT_PERIOD
                existing = priorities_by_phase.get(phase)
                if existing is not None and existing != priority:
                    collision = True
                    break
                priorities_by_phase[phase] = priority
            if not collision:
                solutions += 1

    return LargerGroupSearch(
        first_excluded_group_size=group_size,
        feature_order=("group_flag", "c0", "c1", "c2", "c3", "c4"),
        coefficient_l1_limit=A44_MAX_NOISE_LEVEL,
        signed_integer_coefficient_vectors_checked=checked,
        Boolean_patterns_per_vector=1 << group_size,
        exact_scalar_phase_solutions=solutions,
        every_vector_has_cross_priority_exact_phase_collision=solutions == 0,
        public_input_offset_can_repair_exact_collision=False,
        public_output_offset_or_arbitrary_codes_can_repair_exact_collision=False,
        excludes_every_larger_group_by_restriction=solutions == 0,
        excluded_class=(
            "one fresh OR flag plus one integer affine combination of all candidate "
            "flags, raw L1<=15, followed by one scalar raw p16 PBS"
        ),
        not_excluded=(
            "two or more local classifier PBS stages",
            "PFKS or programmable packing",
            "multilane ciphertexts",
            "a parameter contract with raw L1 above 15",
        ),
    )


def summary(include_all_sizes: bool) -> dict[str, object]:
    layouts = selector_layout_audit()
    noise = noise_audit()
    search = larger_group_search()
    selected = tuple(full_count_row(size) for size in (1, 2, 3, 4, 64, 127, 128))
    n127 = full_count_row(127).a53_full
    payload: dict[str, object] = {
        "verdict": "static_conditional_go_base15_dual_sample",
        "scope": "replace only A38 scan/output after A50 low selection",
        "selector_layout_audit": asdict(layouts),
        "noise": asdict(noise),
        "larger_group_search": asdict(search),
        "selected_counts": [asdict(row) for row in selected],
        "n127_conditional_union_log2": math.log2(n127.output_marginals)
        + A44_PER_EVENT_LOG2_P_FAIL,
        "end_to_end_numeric_upper": None,
        "open_obligations": (
            "materialize group-local, selector, base-15 digit, and final code LUTs in Rust",
            "FHE-test every signed selector input and public-offset witness on fresh A44 keys",
            "confirm two correlated selector marginals per blind rotation at runtime",
            "map all custom raw LUTs to the A44 per-event p-fail contract",
            "retain the existing terminal exact-code caveat at Delta=2^56",
        ),
    }
    if include_all_sizes:
        payload["all_n1_128_counts"] = [asdict(row) for row in all_count_rows()]
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all-sizes", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = summary(args.all_sizes)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("A53 verdict:", payload["verdict"])
        print("N=127:", asdict(full_count_row(127).a53_full))
        print("end-to-end numeric upper:", payload["end_to_end_numeric_upper"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
