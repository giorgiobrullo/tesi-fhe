#!/usr/bin/env python3
"""Clear/layout audit for a four-candidate A34 scan/output experiment.

The direct scalar encoding of four Boolean candidates needs L1 at least 15,
well above the frozen p=16 parameter's conservative ``max_noise_level=5``.
This model therefore evaluates a two-stage classifier.  The left pair is
bootstrapped to ``q in {0, 4, 8}``, then ``q + c2 + 2*c3`` has L1 four and the
reachable priority classes are::

    none {0}, fourth {2}, third {1, 3},
    second {4, 5, 6, 7}, first {8, 9, 10, 11}.

A full four-item group cannot extract both an injective local-first code and a
nonzero group flag from one scalar p=16 accumulator.  The blocker is stronger
than a search over box-aligned offsets: every one of the 2,048 possible second
extraction degrees is inconsistent when both outputs retain the standard
strict in-box radius of 63 coefficients.  Three-item tails are packable.

Global suppression itself is valid: local positions use even codes
``{0, 2, 4, 6, 8}`` and the prefix bit shifts them to the disjoint odd set.
However, a full group's low/high ID nibbles usually cannot share one scalar
selector accumulator either.  At N=127 only full group 3 and the final
three-item tail group 31 pack.  The realizable count therefore uses two blind
rotations sharing one key switch for every other dual-output operation.

This is a clear/count model only.  It does not run FHE, change the live A33
core, establish an end-to-end p-fail, or claim a latency improvement.
"""

from __future__ import annotations

import argparse
import itertools
import json
import random
from dataclasses import asdict, dataclass
from functools import cache
from typing import Callable, Mapping, Sequence


MAX_GALLERY_SIZE = 128
GROUP_SIZE = 4
P16 = 16
SIGNED_PHASE_MODULUS = 2 * P16
POLYNOMIAL_SIZE = 2_048
BOX_SIZE = POLYNOMIAL_SIZE // P16
HALF_BOX_SIZE = BOX_SIZE // 2
STRICT_IN_BOX_RADIUS = HALF_BOX_SIZE - 1
BOOL_DELTA_LOG = 59
CODE_DELTA_LOG = 56
SHORTINT_MAX_NOISE_LEVEL = 5
RADIX4 = 4
RADIX5 = 5
LOCAL_CODES = (0, 2, 4, 6, 8)
DEFAULT_VALIDATION_SEED = 0xA36_04_2026_0902


@dataclass(frozen=True)
class PrimitiveCounts:
    blind_rotations: int
    key_switches: int
    output_marginals: int


@dataclass(frozen=True)
class DirectEncodingAudit:
    searched_through_l1: int
    solutions_within_limit: int
    minimum_exact_l1: int
    example_coefficients: tuple[int, ...]
    within_conservative_limit: bool


@dataclass(frozen=True)
class LayoutSolution:
    first_output: str
    second_output: str
    second_sample_offset_slots: int


@dataclass(frozen=True)
class RobustPackingCertificate:
    extraction_degrees_checked_per_output_order: int
    output_orders_checked: int
    strict_in_box_radius: int
    satisfiable_layouts: int
    allows_arbitrary_nonzero_flag_code: bool
    allows_arbitrary_distinct_nonzero_local_codes: bool
    impossible: bool


@dataclass(frozen=True)
class SuppressionAudit:
    active_phases: tuple[int, ...]
    suppressed_phases: tuple[int, ...]
    disjoint: bool
    input_l1: int
    within_conservative_limit: bool


@dataclass(frozen=True)
class NoiseAudit:
    left_pair_l1: int
    second_classifier_l1: int
    suppression_l1: int
    radix: int
    prefix_l1: int
    digit_reduction_l1: int
    maximum_l1: int
    conservative_max_noise_level: int
    within_conservative_limit: bool


@dataclass(frozen=True)
class GroupTrace:
    group_index: int
    group_length: int
    candidates: tuple[bool, ...]
    left_pair_phase: int
    q: int
    second_phase: int
    local_first: int
    even_local_code: int
    flag: bool
    prefix: bool
    selector_phase: int
    active: bool
    low_nibble: int
    high_nibble: int
    selected_code: int


@dataclass(frozen=True)
class A36Trace:
    gallery_size: int
    candidates: tuple[bool, ...]
    group_flags: tuple[bool, ...]
    group_prefixes: tuple[bool, ...]
    groups: tuple[GroupTrace, ...]
    final_code_outputs: tuple[int, int]
    code: int


@dataclass(frozen=True)
class StageCounts:
    gallery_size: int
    radix: int
    groups: int
    classifier_blind_rotations: int
    classifier_key_switches: int
    classifier_marginals: int
    prefix_nodes: int
    selector_blind_rotations: int
    selector_key_switches: int
    selector_marginals: int
    digit_reduction_nodes: int
    scan_output_blind_rotations: int
    scan_output_key_switches: int
    scan_output_marginals: int
    packed_classifier_groups: int
    packed_selector_groups: int
    realizable: bool


@dataclass(frozen=True)
class CountComparison:
    unrealizable_all_packed_stage: StageCounts
    feasible_without_optional_packing_stage: StageCounts
    feasible_best_box_packing_stage: StageCounts
    unrealizable_all_packed_whole_core: PrimitiveCounts
    feasible_without_optional_packing_whole_core: PrimitiveCounts
    feasible_best_box_packing_whole_core: PrimitiveCounts


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


def _validate_radix(radix: int) -> None:
    if radix not in (RADIX4, RADIX5):
        raise ValueError("this audit supports only radix four and five")


def _canonical_candidates(candidates: Sequence[bool | int]) -> tuple[bool, ...]:
    values = tuple(candidates)
    _validate_gallery_size(len(values))
    if any(value not in (False, True, 0, 1) for value in values):
        raise ValueError("candidates must be Boolean")
    return tuple(bool(value) for value in values)


def _first_position(bits: Sequence[bool | int]) -> int:
    return next((index + 1 for index, bit in enumerate(bits) if bit), 0)


def left_pair_q(c0: bool | int, c1: bool | int) -> int:
    """The first p=16 LUT: phases 0..3 map to q=(0, 8, 4, 8)."""
    if c0 not in (False, True, 0, 1) or c1 not in (False, True, 0, 1):
        raise ValueError("left-pair inputs must be Boolean")
    if c0:
        return 8
    if c1:
        return 4
    return 0


@cache
def classifier_phase_table(group_length: int) -> tuple[tuple[int, int], ...]:
    """Return unique ``(phase, local_first)`` states for a padded group."""
    if not 1 <= group_length <= GROUP_SIZE:
        raise ValueError("group length must be in 1..4")
    states: dict[int, int] = {}
    for bits in itertools.product((False, True), repeat=group_length):
        padded = bits + (False,) * (GROUP_SIZE - group_length)
        q = left_pair_q(padded[0], padded[1])
        phase = q + int(padded[2]) + 2 * int(padded[3])
        position = _first_position(padded)
        existing = states.get(phase)
        if existing is not None and existing != position:
            raise AssertionError("two-stage phase aliases different priorities")
        states[phase] = position
    return tuple(sorted(states.items()))


@cache
def direct_encoding_audit(max_l1: int = 15) -> DirectEncodingAudit:
    """Exhaust all integer four-bit scalar encodings through ``max_l1``."""
    if max_l1 < SHORTINT_MAX_NOISE_LEVEL:
        raise ValueError("search must include the conservative limit")
    minimum = None
    witness: tuple[int, ...] | None = None
    within_limit = 0
    patterns = tuple(itertools.product((0, 1), repeat=GROUP_SIZE))
    for l1 in range(max_l1 + 1):
        for coefficients in itertools.product(range(-l1, l1 + 1), repeat=GROUP_SIZE):
            if sum(abs(value) for value in coefficients) != l1:
                continue
            outputs_by_phase: dict[int, int] = {}
            consistent = True
            for bits in patterns:
                phase = sum(a * bit for a, bit in zip(coefficients, bits))
                phase %= SIGNED_PHASE_MODULUS
                output = _first_position(bits)
                if phase in outputs_by_phase and outputs_by_phase[phase] != output:
                    consistent = False
                    break
                outputs_by_phase[phase] = output
            if not consistent:
                continue
            if l1 <= SHORTINT_MAX_NOISE_LEVEL:
                within_limit += 1
            if minimum is None:
                minimum = l1
                witness = coefficients
        if minimum is not None:
            break
    if minimum is None or witness is None:
        raise AssertionError("search bound did not reach a direct encoding witness")
    return DirectEncodingAudit(
        searched_through_l1=max_l1,
        solutions_within_limit=within_limit,
        minimum_exact_l1=minimum,
        example_coefficients=witness,
        within_conservative_limit=minimum <= SHORTINT_MAX_NOISE_LEVEL,
    )


def negacyclic_slot_requirement(phase: int, requested: int) -> tuple[int, int]:
    """Map a virtual p=16 phase to its independent slot and signed value."""
    signed_phase = phase % SIGNED_PHASE_MODULUS
    slot = signed_phase % P16
    value = requested % SIGNED_PHASE_MODULUS
    required = value if signed_phase < P16 else (-value) % SIGNED_PHASE_MODULUS
    return slot, required


def _assign_slot(assignments: dict[int, int], phase: int, requested: int) -> bool:
    slot, required = negacyclic_slot_requirement(phase, requested)
    existing = assignments.get(slot)
    if existing is not None and existing != required:
        return False
    assignments[slot] = required
    return True


def packed_layout_solutions(
    phase_outputs: Mapping[int, tuple[int, int]],
    *,
    output_names: tuple[str, str],
) -> tuple[LayoutSolution, ...]:
    """Enumerate exact box-aligned two-output p=16 translations."""
    if not phase_outputs:
        raise ValueError("packing search needs reachable states")
    solutions: list[LayoutSolution] = []
    for swap in (False, True):
        first_index, second_index = (1, 0) if swap else (0, 1)
        first_name, second_name = (
            (output_names[1], output_names[0]) if swap else output_names
        )
        for offset in range(1, P16):
            assignments: dict[int, int] = {}
            consistent = True
            for phase, outputs in phase_outputs.items():
                if not _assign_slot(assignments, phase, outputs[first_index]):
                    consistent = False
                    break
                if not _assign_slot(assignments, phase + offset, outputs[second_index]):
                    consistent = False
                    break
            if consistent:
                solutions.append(LayoutSolution(first_name, second_name, offset))
    return tuple(solutions)


def classifier_packed_solutions(
    group_length: int, *, even_local_codes: bool = True
) -> tuple[LayoutSolution, ...]:
    scale = 2 if even_local_codes else 1
    phase_outputs = {
        phase: (scale * position, int(position != 0))
        for phase, position in classifier_phase_table(group_length)
    }
    return packed_layout_solutions(
        phase_outputs, output_names=("local_first", "group_flag")
    )


def _relation_satisfiable(
    relations: Sequence[tuple[int, int, int]], variable_count: int = 6
) -> bool:
    """Solve signed mod-32 equalities with four distinct nonzero local codes.

    Variable zero is fixed to 0, variables 1..4 are arbitrary distinct nonzero
    local codes, and variable 5 is an arbitrary nonzero flag code.  This
    deliberately over-approximates usable positive p=16 encodings.
    """
    adjacency: list[list[tuple[int, int]]] = [[] for _ in range(variable_count)]
    for left, right, sign in relations:
        adjacency[left].append((right, sign))
        adjacency[right].append((left, sign))

    components: list[tuple[dict[int, int], bool]] = []
    visited: set[int] = set()
    for seed in range(variable_count):
        if seed in visited:
            continue
        relative = {seed: 1}
        force_self_negative = False
        pending = [seed]
        visited.add(seed)
        while pending:
            current = pending.pop()
            for neighbor, sign in adjacency[current]:
                wanted = relative[current] * sign
                if neighbor in relative:
                    if relative[neighbor] != wanted:
                        force_self_negative = True
                    continue
                relative[neighbor] = wanted
                visited.add(neighbor)
                pending.append(neighbor)
        components.append((relative, force_self_negative))

    zero_component = next(component for component in components if 0 in component[0])
    if any(variable in zero_component[0] for variable in range(1, variable_count)):
        return False

    values: list[int | None] = [None] * variable_count
    values[0] = 0
    nonzero_components = [
        component for component in components if 0 not in component[0]
    ]

    def assign(component_index: int) -> bool:
        if component_index == len(nonzero_components):
            locals_ = values[1:5]
            return (
                all(value not in (None, 0) for value in values[1:])
                and len(set(locals_)) == 4
            )
        relative, force_self_negative = nonzero_components[component_index]
        roots: Sequence[int] = (16,) if force_self_negative else range(1, 32)
        for root in roots:
            for variable, sign in relative.items():
                values[variable] = (sign * root) % SIGNED_PHASE_MODULUS
            if assign(component_index + 1):
                return True
        for variable in relative:
            values[variable] = None
        return False

    return assign(0)


def _robust_relations(
    second_degree: int, *, swap: bool
) -> tuple[tuple[int, int, int], ...]:
    """Build all coefficient-orbit conflicts for two robust extractions."""
    if not 0 <= second_degree < POLYNOMIAL_SIZE:
        raise ValueError("extraction degree is outside the accumulator")
    first_kind, second_kind = ("flag", "local") if swap else ("local", "flag")

    def variable(kind: str, position: int) -> int:
        if position == 0:
            return 0
        return 5 if kind == "flag" else position

    relations: list[tuple[int, int, int]] = []
    states = classifier_phase_table(GROUP_SIZE)
    radius_twice = 2 * STRICT_IN_BOX_RADIUS
    for first_phase, first_position in states:
        first_center = first_phase * BOX_SIZE
        for second_phase, second_position in states:
            second_center = second_phase * BOX_SIZE + second_degree
            # Intervals represent every strict in-box coefficient.  Equality
            # after an odd N shift changes the requested accumulator sign.
            for half_turns in range(-2, 3):
                shifted_second = second_center + half_turns * POLYNOMIAL_SIZE
                if abs(first_center - shifted_second) <= radius_twice:
                    relations.append(
                        (
                            variable(first_kind, first_position),
                            variable(second_kind, second_position),
                            1 if half_turns % 2 == 0 else -1,
                        )
                    )
    return tuple(relations)


@cache
def robust_full_group_packing_certificate() -> RobustPackingCertificate:
    satisfiable = 0
    for swap in (False, True):
        for degree in range(POLYNOMIAL_SIZE):
            if _relation_satisfiable(_robust_relations(degree, swap=swap)):
                satisfiable += 1
    return RobustPackingCertificate(
        extraction_degrees_checked_per_output_order=POLYNOMIAL_SIZE,
        output_orders_checked=2,
        strict_in_box_radius=STRICT_IN_BOX_RADIUS,
        satisfiable_layouts=satisfiable,
        allows_arbitrary_nonzero_flag_code=True,
        allows_arbitrary_distinct_nonzero_local_codes=True,
        impossible=satisfiable == 0,
    )


def suppression_audit() -> SuppressionAudit:
    active = tuple(LOCAL_CODES)
    suppressed = tuple(value + 1 for value in LOCAL_CODES)
    return SuppressionAudit(
        active_phases=active,
        suppressed_phases=suppressed,
        disjoint=set(active).isdisjoint(suppressed),
        input_l1=2,
        within_conservative_limit=2 <= SHORTINT_MAX_NOISE_LEVEL,
    )


@cache
def selector_phase_outputs(
    group_index: int, group_length: int
) -> tuple[tuple[int, tuple[int, int]], ...]:
    if not 0 <= group_index < (MAX_GALLERY_SIZE + GROUP_SIZE - 1) // GROUP_SIZE:
        raise ValueError("group index is outside the supported gallery")
    if not 1 <= group_length <= GROUP_SIZE:
        raise ValueError("group length must be in 1..4")
    outputs: dict[int, tuple[int, int]] = {}
    for prefix in (False, True):
        for position in range(group_length + 1):
            phase = LOCAL_CODES[position] + int(prefix)
            code = GROUP_SIZE * group_index + position if position and not prefix else 0
            outputs[phase] = (code & 0xF, code >> 4)
    return tuple(sorted(outputs.items()))


def selector_packed_solutions(
    group_index: int, group_length: int
) -> tuple[LayoutSolution, ...]:
    return packed_layout_solutions(
        dict(selector_phase_outputs(group_index, group_length)),
        output_names=("low_nibble", "high_nibble"),
    )


def _or_reduce(values: Sequence[bool], *, radix: int) -> bool:
    _validate_radix(radix)
    if not values:
        raise ValueError("OR reduction requires at least one input")
    level = list(values)
    while len(level) > 1:
        level = [
            any(level[start : start + radix]) for start in range(0, len(level), radix)
        ]
    return level[0]


def exclusive_prefix_or(flags: Sequence[bool | int], *, radix: int) -> tuple[bool, ...]:
    _validate_radix(radix)
    values = tuple(flags)
    if not values or any(value not in (False, True, 0, 1) for value in values):
        raise ValueError("prefix inputs must be a non-empty Boolean sequence")
    canonical = tuple(bool(value) for value in values)
    if len(canonical) <= radix:
        return tuple(
            False if index == 0 else any(canonical[:index])
            for index in range(len(canonical))
        )
    block_totals = tuple(
        _or_reduce(canonical[start : start + radix], radix=radix)
        for start in range(0, len(canonical), radix)
    )
    block_prefixes = exclusive_prefix_or(block_totals, radix=radix)
    prefixes: list[bool] = []
    for index in range(len(canonical)):
        block = index // radix
        offset = index % radix
        if offset == 0:
            prefixes.append(block_prefixes[block])
            continue
        start = block * radix
        inputs = list(canonical[start:index])
        if block > 0:
            inputs.insert(0, block_prefixes[block])
        prefixes.append(
            inputs[0] if len(inputs) == 1 else _or_reduce(inputs, radix=radix)
        )
    return tuple(prefixes)


def _reduce_one_hot_digits(values: Sequence[int], *, radix: int) -> int:
    _validate_radix(radix)
    if not values or any(not 0 <= value < P16 for value in values):
        raise ValueError("digit reduction requires non-empty p=16 digits")
    if sum(value != 0 for value in values) > 1:
        raise AssertionError("digit inputs are not globally one-hot")
    level = list(values)
    while len(level) > 1:
        level = [
            sum(level[start : start + radix]) for start in range(0, len(level), radix)
        ]
        if any(not 0 <= value < P16 for value in level):
            raise AssertionError("one-hot digit left the p=16 domain")
    return level[0]


def evaluate_a36_group4(
    candidates: Sequence[bool | int], *, radix: int = RADIX4
) -> A36Trace:
    canonical = _canonical_candidates(candidates)
    _validate_radix(radix)
    candidate_groups = tuple(
        canonical[start : start + GROUP_SIZE]
        for start in range(0, len(canonical), GROUP_SIZE)
    )
    flags = tuple(any(group) for group in candidate_groups)
    prefixes = exclusive_prefix_or(flags, radix=radix)
    traces: list[GroupTrace] = []
    for group_index, (group, flag, prefix) in enumerate(
        zip(candidate_groups, flags, prefixes)
    ):
        padded = group + (False,) * (GROUP_SIZE - len(group))
        left_phase = int(padded[0]) + 2 * int(padded[1])
        q = left_pair_q(padded[0], padded[1])
        second_phase = q + int(padded[2]) + 2 * int(padded[3])
        local_first = _first_position(padded)
        expected = dict(classifier_phase_table(len(group)))[second_phase]
        if local_first != expected:
            raise AssertionError("two-stage classifier selected the wrong local ID")
        even_code = LOCAL_CODES[local_first]
        selector_phase = even_code + int(prefix)
        active = bool(local_first) and not prefix
        selected_code = GROUP_SIZE * group_index + local_first if active else 0
        traces.append(
            GroupTrace(
                group_index=group_index,
                group_length=len(group),
                candidates=group,
                left_pair_phase=left_phase,
                q=q,
                second_phase=second_phase,
                local_first=local_first,
                even_local_code=even_code,
                flag=flag,
                prefix=prefix,
                selector_phase=selector_phase,
                active=active,
                low_nibble=selected_code & 0xF,
                high_nibble=selected_code >> 4,
                selected_code=selected_code,
            )
        )

    low = _reduce_one_hot_digits([trace.low_nibble for trace in traces], radix=radix)
    high = _reduce_one_hot_digits([trace.high_nibble for trace in traces], radix=radix)
    outputs = (low, P16 * high)
    return A36Trace(
        gallery_size=len(canonical),
        candidates=canonical,
        group_flags=flags,
        group_prefixes=prefixes,
        groups=tuple(traces),
        final_code_outputs=outputs,
        code=sum(outputs),
    )


def reduction_nodes(items: int, *, radix: int) -> int:
    _validate_radix(radix)
    if items <= 0:
        raise ValueError("reduction requires at least one item")
    nodes = 0
    while items > 1:
        items = (items + radix - 1) // radix
        nodes += items
    return nodes


def exclusive_prefix_nodes(items: int, *, radix: int) -> int:
    _validate_radix(radix)
    if items <= 0:
        raise ValueError("prefix requires at least one item")
    if items <= 2:
        return 0
    if items <= radix:
        return items - 2
    totals = 0
    expansion = 0
    blocks = 0
    for start in range(0, items, radix):
        length = min(radix, items - start)
        blocks += 1
        totals += int(length > 1)
        expansion += max(0, length - 2) if start == 0 else length - 1
    return totals + expansion + exclusive_prefix_nodes(blocks, radix=radix)


def noise_audit(radix: int) -> NoiseAudit:
    _validate_radix(radix)
    bounds = (3, 4, 2, radix, radix)
    return NoiseAudit(
        left_pair_l1=bounds[0],
        second_classifier_l1=bounds[1],
        suppression_l1=bounds[2],
        radix=radix,
        prefix_l1=bounds[3],
        digit_reduction_l1=bounds[4],
        maximum_l1=max(bounds),
        conservative_max_noise_level=SHORTINT_MAX_NOISE_LEVEL,
        within_conservative_limit=max(bounds) <= SHORTINT_MAX_NOISE_LEVEL,
    )


def _group_lengths(gallery_size: int) -> tuple[int, ...]:
    return tuple(
        min(GROUP_SIZE, gallery_size - start)
        for start in range(0, gallery_size, GROUP_SIZE)
    )


def _classifier_counts(
    group_lengths: Sequence[int], *, packing_policy: str
) -> tuple[PrimitiveCounts, int]:
    if packing_policy not in ("ideal", "none", "available"):
        raise ValueError("unknown classifier packing policy")
    blind_rotations = key_switches = marginals = packed = 0
    for length in group_lengths:
        if length == 1:
            continue
        if length == 2:
            # Tail-specialized first PBS directly emits local code and flag.
            blind_rotations += 1
            key_switches += 1
            marginals += 2
            packed += 1
            continue
        blind_rotations += 1  # left pair -> q
        key_switches += 1
        marginals += 1
        can_pack = bool(classifier_packed_solutions(length))
        use_packing = packing_policy == "ideal" or (
            packing_policy == "available" and can_pack
        )
        blind_rotations += 1 if use_packing else 2
        key_switches += 1  # both fallback rotations share this switched input
        marginals += 2
        packed += int(use_packing)
    return PrimitiveCounts(blind_rotations, key_switches, marginals), packed


def _selector_counts(
    group_lengths: Sequence[int], *, packing_policy: str
) -> tuple[PrimitiveCounts, int]:
    if packing_policy not in ("ideal", "none", "available"):
        raise ValueError("unknown selector packing policy")
    blind_rotations = packed = 0
    for group_index, length in enumerate(group_lengths):
        can_pack = bool(selector_packed_solutions(group_index, length))
        use_packing = packing_policy == "ideal" or (
            packing_policy == "available" and can_pack
        )
        blind_rotations += 1 if use_packing else 2
        packed += int(use_packing)
    groups = len(group_lengths)
    return PrimitiveCounts(blind_rotations, groups, 2 * groups), packed


def stage_counts(gallery_size: int, *, radix: int, packing_policy: str) -> StageCounts:
    _validate_gallery_size(gallery_size)
    _validate_radix(radix)
    lengths = _group_lengths(gallery_size)
    classifier, packed_classifiers = _classifier_counts(
        lengths, packing_policy=packing_policy
    )
    selector, packed_selectors = _selector_counts(
        lengths, packing_policy=packing_policy
    )
    prefix = exclusive_prefix_nodes(len(lengths), radix=radix)
    digits = 2 * reduction_nodes(len(lengths), radix=radix)
    rotations = classifier.blind_rotations + prefix + selector.blind_rotations + digits
    key_switches = classifier.key_switches + prefix + selector.key_switches + digits
    marginals = (
        classifier.output_marginals + prefix + selector.output_marginals + digits
    )
    ideal_layout_exists = all(
        length < GROUP_SIZE or classifier_packed_solutions(length) for length in lengths
    ) and all(
        selector_packed_solutions(group_index, length)
        for group_index, length in enumerate(lengths)
    )
    realizable = packing_policy != "ideal" or ideal_layout_exists
    return StageCounts(
        gallery_size=gallery_size,
        radix=radix,
        groups=len(lengths),
        classifier_blind_rotations=classifier.blind_rotations,
        classifier_key_switches=classifier.key_switches,
        classifier_marginals=classifier.output_marginals,
        prefix_nodes=prefix,
        selector_blind_rotations=selector.blind_rotations,
        selector_key_switches=selector.key_switches,
        selector_marginals=selector.output_marginals,
        digit_reduction_nodes=digits,
        scan_output_blind_rotations=rotations,
        scan_output_key_switches=key_switches,
        scan_output_marginals=marginals,
        packed_classifier_groups=packed_classifiers,
        packed_selector_groups=packed_selectors,
        realizable=realizable,
    )


def _pre_scan_counts(gallery_size: int, *, radix: int) -> PrimitiveCounts:
    gallery_reduction = reduction_nodes(gallery_size, radix=radix)
    pairs = (gallery_size + 1) // 2
    pair_reduction = reduction_nodes(pairs, radix=radix)
    blind_rotations = 27 * gallery_size + 9 * gallery_reduction + pairs + pair_reduction
    key_switches = 24 * gallery_size + 9 * gallery_reduction + pairs + pair_reduction
    return PrimitiveCounts(
        blind_rotations,
        key_switches,
        blind_rotations + 5 * gallery_size,
    )


def _whole_core(
    gallery_size: int, *, radix: int, stage: StageCounts
) -> PrimitiveCounts:
    pre = _pre_scan_counts(gallery_size, radix=radix)
    return PrimitiveCounts(
        pre.blind_rotations + stage.scan_output_blind_rotations,
        pre.key_switches + stage.scan_output_key_switches,
        pre.output_marginals + stage.scan_output_marginals,
    )


def count_comparison(gallery_size: int, *, radix: int) -> CountComparison:
    ideal = stage_counts(gallery_size, radix=radix, packing_policy="ideal")
    fallback = stage_counts(gallery_size, radix=radix, packing_policy="none")
    available = stage_counts(gallery_size, radix=radix, packing_policy="available")
    return CountComparison(
        unrealizable_all_packed_stage=ideal,
        feasible_without_optional_packing_stage=fallback,
        feasible_best_box_packing_stage=available,
        unrealizable_all_packed_whole_core=_whole_core(
            gallery_size, radix=radix, stage=ideal
        ),
        feasible_without_optional_packing_whole_core=_whole_core(
            gallery_size, radix=radix, stage=fallback
        ),
        feasible_best_box_packing_whole_core=_whole_core(
            gallery_size, radix=radix, stage=available
        ),
    )


def assert_n127_counts() -> None:
    expected = {
        RADIX4: (
            PrimitiveCounts(156, 156, 220),
            PrimitiveCounts(220, 156, 220),
            PrimitiveCounts(217, 156, 220),
            PrimitiveCounts(4_057, 3_676, 4_756),
            PrimitiveCounts(4_121, 3_676, 4_756),
            PrimitiveCounts(4_118, 3_676, 4_756),
        ),
        RADIX5: (
            PrimitiveCounts(153, 153, 217),
            PrimitiveCounts(217, 153, 217),
            PrimitiveCounts(214, 153, 217),
            PrimitiveCounts(3_978, 3_597, 4_677),
            PrimitiveCounts(4_042, 3_597, 4_677),
            PrimitiveCounts(4_039, 3_597, 4_677),
        ),
    }
    for radix, values in expected.items():
        comparison = count_comparison(127, radix=radix)
        stages = (
            comparison.unrealizable_all_packed_stage,
            comparison.feasible_without_optional_packing_stage,
            comparison.feasible_best_box_packing_stage,
        )
        actual_stages = tuple(
            PrimitiveCounts(
                stage.scan_output_blind_rotations,
                stage.scan_output_key_switches,
                stage.scan_output_marginals,
            )
            for stage in stages
        )
        assert actual_stages == values[:3]
        assert (
            comparison.unrealizable_all_packed_whole_core,
            comparison.feasible_without_optional_packing_whole_core,
            comparison.feasible_best_box_packing_whole_core,
        ) == values[3:]
        assert not stages[0].realizable
        assert stages[1].realizable and stages[2].realizable
        assert stages[2].packed_classifier_groups == 1
        assert stages[2].packed_selector_groups == 2


def _reference_code(candidates: Sequence[bool]) -> int:
    return next((index + 1 for index, value in enumerate(candidates) if value), 0)


def _validate_case(candidates: Sequence[bool], *, radix: int, label: str) -> None:
    trace = evaluate_a36_group4(candidates, radix=radix)
    expected = _reference_code(candidates)
    if trace.code != expected:
        raise AssertionError(f"{label}: expected {expected}, got {trace.code}")
    expected_prefixes = tuple(
        any(trace.group_flags[:index]) for index in range(len(trace.group_flags))
    )
    if trace.group_prefixes != expected_prefixes:
        raise AssertionError(f"{label}: prefix mismatch")
    active = [group for group in trace.groups if group.active]
    if expected == 0:
        if active or any(trace.final_code_outputs):
            raise AssertionError(f"{label}: all-reject emitted a code")
        return
    if len(active) != 1 or active[0].selected_code != expected:
        raise AssertionError(f"{label}: output is not the unique first identity")
    for later in trace.groups[active[0].group_index + 1 :]:
        if later.active or later.selected_code:
            raise AssertionError(f"{label}: a later group was resurrected")


def _winner_pattern(
    gallery_size: int, first: int, predicate: Callable[[int], bool]
) -> tuple[bool, ...]:
    return tuple(
        index == first or (index > first and predicate(index))
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
        raise ValueError("exhaustive range is outside requested galleries")
    if random_patterns_per_winner < 0:
        raise ValueError("random pattern count cannot be negative")
    counters = {
        "all_reject": 0,
        "winner": 0,
        "systematic": 0,
        "random": 0,
        "exhaustive": 0,
        "pairs": 0,
    }
    rng = random.Random(seed)
    for gallery_size in range(1, max_gallery_size + 1):
        _validate_case(
            (False,) * gallery_size,
            radix=RADIX4,
            label=f"N={gallery_size}/reject",
        )
        counters["all_reject"] += 1
        for first in range(gallery_size):
            singleton = tuple(index == first for index in range(gallery_size))
            _validate_case(
                singleton,
                radix=RADIX4,
                label=f"N={gallery_size}/first={first}/single",
            )
            counters["winner"] += 1
            predicates = (
                lambda _index: True,
                lambda index, first=first: (index - first) % 2 == 0,
                lambda index, first=first: (index - first) % 2 == 1,
                lambda index: index % GROUP_SIZE == 0,
                lambda index: index % GROUP_SIZE == 3,
            )
            for pattern_index, predicate in enumerate(predicates):
                pattern = _winner_pattern(gallery_size, first, predicate)
                _validate_case(
                    pattern,
                    radix=RADIX4,
                    label=(
                        f"N={gallery_size}/first={first}/systematic={pattern_index}"
                    ),
                )
                counters["systematic"] += 1
            for sample in range(random_patterns_per_winner):
                bits = [False] * gallery_size
                bits[first] = True
                for index in range(first + 1, gallery_size):
                    bits[index] = bool(rng.getrandbits(1))
                _validate_case(
                    tuple(bits),
                    radix=RADIX4,
                    label=f"N={gallery_size}/first={first}/random={sample}",
                )
                counters["random"] += 1
        if gallery_size <= exhaustive_through:
            for mask in range(1 << gallery_size):
                pattern = tuple(
                    bool((mask >> index) & 1) for index in range(gallery_size)
                )
                _validate_case(
                    pattern,
                    radix=RADIX4,
                    label=f"N={gallery_size}/mask={mask}",
                )
                counters["exhaustive"] += 1
    if include_max_gallery_pairs:
        for first in range(max_gallery_size):
            for later in range(first + 1, max_gallery_size):
                pattern = tuple(
                    index in (first, later) for index in range(max_gallery_size)
                )
                _validate_case(
                    pattern,
                    radix=RADIX4,
                    label=f"N={max_gallery_size}/pair={first},{later}",
                )
                counters["pairs"] += 1
    total = sum(counters.values())
    return ValidationSummary(
        gallery_sizes_checked=max_gallery_size,
        all_reject_cases=counters["all_reject"],
        winner_positions_checked=counters["winner"],
        systematic_adversarial_cases=counters["systematic"],
        deterministic_random_cases=counters["random"],
        exhaustive_small_cases=counters["exhaustive"],
        max_gallery_pair_cases=counters["pairs"],
        total_cases=total,
        exhaustive_through=exhaustive_through,
        random_patterns_per_winner=random_patterns_per_winner,
        seed=seed,
    )


def report(
    gallery_size: int, validation: ValidationSummary | None
) -> dict[str, object]:
    _validate_gallery_size(gallery_size)
    robust = robust_full_group_packing_certificate()
    return {
        "schema_version": 1,
        "model": "a36-group4-clear-layout-audit",
        "status": "clear exact; full-group dual-output packing blocked",
        "scope": "clear semantics, p16 translation/noise audit, structural counts only",
        "gallery_size": gallery_size,
        "direct_encoding": asdict(direct_encoding_audit()),
        "classifier_phase_tables": {
            str(length): classifier_phase_table(length)
            for length in range(1, GROUP_SIZE + 1)
        },
        "full_group_box_aligned_solution_counts": {
            "standard_local_codes": len(
                classifier_packed_solutions(GROUP_SIZE, even_local_codes=False)
            ),
            "even_local_codes": len(classifier_packed_solutions(GROUP_SIZE)),
        },
        "tail_classifier_solution_counts": {
            str(length): len(classifier_packed_solutions(length))
            for length in range(1, GROUP_SIZE)
        },
        "robust_full_group_packing_certificate": asdict(robust),
        "suppression": asdict(suppression_audit()),
        "noise": {
            "radix4": asdict(noise_audit(RADIX4)),
            "radix5": asdict(noise_audit(RADIX5)),
        },
        "packed_selectors": [
            group_index
            for group_index, length in enumerate(_group_lengths(gallery_size))
            if selector_packed_solutions(group_index, length)
        ],
        "counts": {
            "radix4": asdict(count_comparison(gallery_size, radix=RADIX4)),
            "radix5": asdict(count_comparison(gallery_size, radix=RADIX5)),
        },
        "final_code_outputs": {
            "count": 2,
            "scale_log": CODE_DELTA_LOG,
            "weights": [1, P16],
        },
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
