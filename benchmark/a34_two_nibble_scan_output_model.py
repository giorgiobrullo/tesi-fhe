#!/usr/bin/env python3
"""Clear model of the experimental A34 two-nibble scan/output circuit.

This variant keeps the group-of-three first-winner scan, but encodes the selected
one-based identity as two base-16 digits.  One p=16 selector blind rotation emits
the low nibble from independent slots 0..7 and the high nibble from independent
slots 8..15.  Two radix-4 one-hot reductions produce exactly two ciphertexts at
the final code scale; their clear values sum to 0 or the first matching identity.

The model proves plaintext semantics, accumulator layout, scale transitions, and
structural BR/KS/output-marginal counts.  It does not execute TFHE or claim a
cryptographic failure probability.
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
REDUCTION_RADIX = 4
P16 = 16
SELECTOR_STATES = 8
FINAL_CODE_OUTPUTS = 2
BOOL_DELTA_LOG = 59
CODE_DELTA_LOG = 56
TORUS_BITS = 64
DEFAULT_VALIDATION_SEED = 0xA34_16_2026_0902
LOCAL_FIRST_LUT = (0, 3, 2, 1, 1)


@dataclass(frozen=True)
class P16IdentityLayout:
    """Independent and virtual slots of the standard p=16 identity LUT."""

    independent_slots: tuple[int, ...]
    independent_encoded_phases: tuple[int, ...]
    virtual_signed_slots: tuple[int, ...]
    input_delta_log: int
    adjacent_slot_spacing: int
    half_slot_margin: int
    largest_independent_phase: int
    padding_boundary: int


@dataclass(frozen=True)
class NibbleSelectorLut:
    """Two eight-state functions packed into one p=16 accumulator."""

    low_slots: tuple[int, ...]
    high_slots: tuple[int, ...]

    def __post_init__(self) -> None:
        if (
            len(self.low_slots) != SELECTOR_STATES
            or len(self.high_slots) != SELECTOR_STATES
        ):
            raise ValueError("each selector table must contain eight slots")
        if any(not 0 <= value < P16 for value in self.independent_slots):
            raise ValueError("selector output is not a base-16 digit")

    @property
    def independent_slots(self) -> tuple[int, ...]:
        return self.low_slots + self.high_slots

    @property
    def virtual_signed_slots(self) -> tuple[int, ...]:
        independent = self.independent_slots
        return independent + tuple(-value for value in independent)

    @property
    def output_marginals(self) -> int:
        return FINAL_CODE_OUTPUTS

    def sample(self, selector_state: int) -> tuple[int, int]:
        if not 0 <= selector_state < SELECTOR_STATES:
            raise ValueError("selector state must be in the reachable half 0..7")
        return self.low_slots[selector_state], self.high_slots[selector_state]


@dataclass(frozen=True)
class GroupTrace:
    group_index: int
    group_length: int
    candidates: tuple[bool, ...]
    flag: bool
    prefix: bool
    local_first: int
    selector_state: int
    low_nibble: int
    high_nibble: int
    active: bool
    selected_code: int


@dataclass(frozen=True)
class NibbleReductionTrace:
    levels: tuple[tuple[int, ...], ...]
    blind_rotations: int
    nibble: int
    code_weight: int
    code_component: int
    selector_scale_log: int
    final_scale_log: int


@dataclass(frozen=True)
class A34TwoNibbleTrace:
    gallery_size: int
    candidates: tuple[bool, ...]
    group_flags: tuple[bool, ...]
    group_prefixes: tuple[bool, ...]
    groups: tuple[GroupTrace, ...]
    low_reduction: NibbleReductionTrace
    high_reduction: NibbleReductionTrace
    final_code_outputs: tuple[int, int]
    final_code_output_scale_logs: tuple[int, int]
    code: int


@dataclass(frozen=True)
class A34TwoNibbleStageCounts:
    gallery_size: int
    groups: int
    group_flag_blind_rotations: int
    local_first_blind_rotations: int
    group_prefix_blind_rotations: int
    dual_selector_blind_rotations: int
    digit_reduction_blind_rotations: int
    scan_output_blind_rotations: int
    scan_output_key_switches: int
    selector_output_marginals: int
    scan_output_marginals: int
    final_code_outputs: int


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


def p16_identity_layout() -> P16IdentityLayout:
    """Describe why values 0..15 at 2^59 use a standard p=16 identity LUT.

    `generate_programmable_bootstrap_glwe_lut(..., message_modulus=16, ...)`
    supplies sixteen independent slots before the padding/negacyclic half-turn.
    At Delta=2^59, nibble ``d`` lands at the center of independent slot ``d``.
    Thus no p=32 reinterpretation is needed: it would halve the box width while
    the standard p=16 layout already gives the intended 2^58 decision margin.
    """
    spacing = 1 << BOOL_DELTA_LOG
    independent = tuple(range(P16))
    phases = tuple(value * spacing for value in independent)
    virtual = independent + tuple(-value for value in independent)
    layout = P16IdentityLayout(
        independent_slots=independent,
        independent_encoded_phases=phases,
        virtual_signed_slots=virtual,
        input_delta_log=BOOL_DELTA_LOG,
        adjacent_slot_spacing=spacing,
        half_slot_margin=spacing // 2,
        largest_independent_phase=phases[-1],
        padding_boundary=1 << (TORUS_BITS - 1),
    )
    assert layout.largest_independent_phase < layout.padding_boundary
    assert all(
        layout.virtual_signed_slots[index + P16] == -layout.virtual_signed_slots[index]
        for index in range(P16)
    )
    return layout


def p16_identity(value: int) -> int:
    """Clear semantics of the p=16 refresh used inside nibble reductions."""
    if not 0 <= value < P16:
        raise ValueError("p=16 identity input must be a nibble")
    return value


def _validate_gallery_size(gallery_size: int) -> None:
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError(f"gallery size must be in 1..{MAX_GALLERY_SIZE}")


def _group_count(gallery_size: int) -> int:
    return (gallery_size + GROUP_SIZE - 1) // GROUP_SIZE


def _canonical_candidates(candidates: Sequence[bool | int]) -> tuple[bool, ...]:
    values = tuple(candidates)
    _validate_gallery_size(len(values))
    if any(value not in (False, True, 0, 1) for value in values):
        raise ValueError("candidates must be Boolean")
    return tuple(bool(value) for value in values)


def or_reduction_blind_rotations(items: int) -> int:
    """Count radix-4 reduction nodes, including refreshed singleton tails."""
    if items <= 0:
        raise ValueError("reduction must contain at least one item")
    count = 0
    while items > 1:
        items = (items + REDUCTION_RADIX - 1) // REDUCTION_RADIX
        count += items
    return count


def radix4_exclusive_prefix_blind_rotations(items: int) -> int:
    """Count the recursive exclusive-prefix network shared with A33/A34."""
    if items <= 0:
        raise ValueError("prefix network must contain at least one item")
    if items <= 2:
        return 0
    if items <= REDUCTION_RADIX:
        return items - 2

    totals = 0
    expansion = 0
    blocks = 0
    for start in range(0, items, REDUCTION_RADIX):
        length = min(REDUCTION_RADIX, items - start)
        blocks += 1
        totals += int(length > 1)
        expansion += max(0, length - 2) if start == 0 else length - 1
    return totals + expansion + radix4_exclusive_prefix_blind_rotations(blocks)


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


def _local_first(flag: bool, candidates: Sequence[bool]) -> int:
    c0 = int(candidates[0])
    c1 = int(candidates[1]) if len(candidates) > 1 else 0
    return LOCAL_FIRST_LUT[int(flag) + 2 * c0 + c1]


def _active_code(group_index: int, group_length: int, selector_state: int) -> int:
    if not 1 <= selector_state <= group_length:
        return 0
    return GROUP_SIZE * group_index + selector_state


@cache
def selector_lut(
    gallery_size: int, group_index: int, group_length: int
) -> NibbleSelectorLut:
    _validate_gallery_size(gallery_size)
    groups = _group_count(gallery_size)
    if not 0 <= group_index < groups:
        raise ValueError("group index is outside this gallery")
    expected_length = min(GROUP_SIZE, gallery_size - group_index * GROUP_SIZE)
    if group_length != expected_length:
        raise ValueError("group length does not match gallery tail")

    codes = tuple(
        _active_code(group_index, group_length, state)
        for state in range(SELECTOR_STATES)
    )
    return NibbleSelectorLut(
        low_slots=tuple(code & 0xF for code in codes),
        high_slots=tuple((code >> 4) & 0xF for code in codes),
    )


def _reduce_nibble(values: Sequence[int], code_weight: int) -> NibbleReductionTrace:
    """Refresh one-hot nibbles, converting only the final outputs to code scale."""
    if not values:
        raise ValueError("nibble reduction must contain at least one item")
    if any(not 0 <= value < P16 for value in values):
        raise ValueError("nibble reduction received a non-nibble")
    if sum(value != 0 for value in values) > 1:
        raise AssertionError("more than one group survived; no-resurrection failed")
    if code_weight not in (1, P16):
        raise ValueError("code weight must select the low or high nibble")

    level = tuple(values)
    levels = [level]
    blind_rotations = 0
    while len(level) > 1:
        next_level = []
        for start in range(0, len(level), REDUCTION_RADIX):
            chunk = level[start : start + REDUCTION_RADIX]
            # The encrypted input is the sum of at most four fresh marginals.
            # One-hot group suppression proves its plaintext remains in 0..15.
            next_level.append(p16_identity(sum(chunk)))
        level = tuple(next_level)
        levels.append(level)
        blind_rotations += len(level)

    selector_scale_log = CODE_DELTA_LOG if len(values) == 1 else BOOL_DELTA_LOG
    return NibbleReductionTrace(
        levels=tuple(levels),
        blind_rotations=blind_rotations,
        nibble=level[0],
        code_weight=code_weight,
        code_component=code_weight * level[0],
        selector_scale_log=selector_scale_log,
        final_scale_log=CODE_DELTA_LOG,
    )


def evaluate_a34_two_nibble(candidates: Sequence[bool | int]) -> A34TwoNibbleTrace:
    """Evaluate the experimental two-nibble scan/output circuit in the clear."""
    canonical = _canonical_candidates(candidates)
    gallery_size = len(canonical)
    candidate_groups = tuple(
        canonical[start : start + GROUP_SIZE]
        for start in range(0, gallery_size, GROUP_SIZE)
    )
    group_flags = tuple(any(group) for group in candidate_groups)
    group_prefixes = _radix4_exclusive_prefix(group_flags)
    if not len(candidate_groups) == len(group_flags) == len(group_prefixes):
        raise AssertionError("group topology vectors have different lengths")

    groups: list[GroupTrace] = []
    for group_index, (group, flag, prefix) in enumerate(
        zip(candidate_groups, group_flags, group_prefixes)
    ):
        local_first = int(flag) if len(group) == 1 else _local_first(flag, group)
        selector_state = local_first + 4 * int(prefix)
        low_nibble, high_nibble = selector_lut(
            gallery_size, group_index, len(group)
        ).sample(selector_state)
        selected_code = _active_code(group_index, len(group), selector_state)
        groups.append(
            GroupTrace(
                group_index=group_index,
                group_length=len(group),
                candidates=group,
                flag=flag,
                prefix=prefix,
                local_first=local_first,
                selector_state=selector_state,
                low_nibble=low_nibble,
                high_nibble=high_nibble,
                active=selected_code != 0,
                selected_code=selected_code,
            )
        )

    low_reduction = _reduce_nibble(
        [group.low_nibble for group in groups], code_weight=1
    )
    high_reduction = _reduce_nibble(
        [group.high_nibble for group in groups], code_weight=P16
    )
    final_code_outputs = (
        low_reduction.code_component,
        high_reduction.code_component,
    )
    final_scales = (
        low_reduction.final_scale_log,
        high_reduction.final_scale_log,
    )
    if len(final_code_outputs) != FINAL_CODE_OUTPUTS or final_scales != (
        CODE_DELTA_LOG,
        CODE_DELTA_LOG,
    ):
        raise AssertionError("two code-scale output invariant failed")

    return A34TwoNibbleTrace(
        gallery_size=gallery_size,
        candidates=canonical,
        group_flags=group_flags,
        group_prefixes=group_prefixes,
        groups=tuple(groups),
        low_reduction=low_reduction,
        high_reduction=high_reduction,
        final_code_outputs=final_code_outputs,
        final_code_output_scale_logs=final_scales,
        code=sum(final_code_outputs),
    )


def _group_node_count(gallery_size: int) -> int:
    return sum(
        min(GROUP_SIZE, gallery_size - start) > 1
        for start in range(0, gallery_size, GROUP_SIZE)
    )


def a34_two_nibble_stage_counts(gallery_size: int) -> A34TwoNibbleStageCounts:
    _validate_gallery_size(gallery_size)
    groups = _group_count(gallery_size)
    group_nodes = _group_node_count(gallery_size)
    prefix_nodes = radix4_exclusive_prefix_blind_rotations(groups)
    selector_nodes = groups
    digit_nodes = 2 * or_reduction_blind_rotations(groups)
    blind_rotations = 2 * group_nodes + prefix_nodes + selector_nodes + digit_nodes
    selector_marginals = 2 * groups
    output_marginals = blind_rotations - selector_nodes + selector_marginals
    return A34TwoNibbleStageCounts(
        gallery_size=gallery_size,
        groups=groups,
        group_flag_blind_rotations=group_nodes,
        local_first_blind_rotations=group_nodes,
        group_prefix_blind_rotations=prefix_nodes,
        dual_selector_blind_rotations=selector_nodes,
        digit_reduction_blind_rotations=digit_nodes,
        scan_output_blind_rotations=blind_rotations,
        scan_output_key_switches=blind_rotations,
        selector_output_marginals=selector_marginals,
        scan_output_marginals=output_marginals,
        final_code_outputs=FINAL_CODE_OUTPUTS,
    )


def a34_two_nibble_replacement_counts(gallery_size: int) -> PrimitiveCounts:
    """Keep the frozen A33 pre-scan core and replace only scan/output."""
    _validate_gallery_size(gallery_size)
    gallery_reduction = or_reduction_blind_rotations(gallery_size)
    pairs = (gallery_size + 1) // 2
    pair_reduction = or_reduction_blind_rotations(pairs)
    pre_scan_br = 27 * gallery_size + 9 * gallery_reduction + pairs + pair_reduction
    pre_scan_ks = 24 * gallery_size + 9 * gallery_reduction + pairs + pair_reduction
    pre_scan_marginals = pre_scan_br + 5 * gallery_size
    stage = a34_two_nibble_stage_counts(gallery_size)
    return PrimitiveCounts(
        blind_rotations=pre_scan_br + stage.scan_output_blind_rotations,
        key_switches=pre_scan_ks + stage.scan_output_key_switches,
        output_marginals=pre_scan_marginals + stage.scan_output_marginals,
    )


def assert_n127_counts() -> None:
    stage = a34_two_nibble_stage_counts(127)
    assert stage.scan_output_blind_rotations == 210
    assert stage.scan_output_key_switches == 210
    assert stage.scan_output_marginals == 253
    assert stage.final_code_outputs == FINAL_CODE_OUTPUTS
    assert a34_two_nibble_replacement_counts(127) == PrimitiveCounts(
        4_111, 3_730, 4_789
    )


def _reference_code(candidates: Sequence[bool]) -> int:
    return next((index + 1 for index, value in enumerate(candidates) if value), 0)


def _validate_case(candidates: Sequence[bool], label: str) -> None:
    trace = evaluate_a34_two_nibble(candidates)
    expected = _reference_code(candidates)
    if trace.code != expected:
        raise AssertionError(f"{label}: expected code {expected}, got {trace.code}")
    if len(trace.final_code_outputs) != FINAL_CODE_OUTPUTS:
        raise AssertionError(f"{label}: final output count is not two")
    if trace.final_code_output_scale_logs != (CODE_DELTA_LOG, CODE_DELTA_LOG):
        raise AssertionError(f"{label}: final outputs are not both at code scale")

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
    if len(active_groups) != 1:
        raise AssertionError(f"{label}: expected exactly one active group")
    if active_groups[0].selected_code != expected:
        raise AssertionError(f"{label}: selector chose the wrong group-local ID")

    winning_group = (expected - 1) // GROUP_SIZE
    for group in trace.groups[winning_group + 1 :]:
        if group.flag and not group.prefix:
            raise AssertionError(f"{label}: later live group lacks a prefix")
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
    exhaustive_through: int = 12,
    random_patterns_per_winner: int = 4,
    seed: int = DEFAULT_VALIDATION_SEED,
    include_max_gallery_pairs: bool = True,
) -> ValidationSummary:
    """Exercise every N/first-winner topology plus deterministic adversaries."""
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
                _validate_case(pattern, f"N={gallery_size}/pair={first},{later}")
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
    layout = p16_identity_layout()
    return {
        "schema_version": 1,
        "model": "a34-two-nibble-clear-scan-output",
        "status": "experimental; separate from the base-8 A34 candidate",
        "scope": "clear semantics, p16 layout, scales, and structural counts only",
        "gallery_size": gallery_size,
        "p16_identity": asdict(layout),
        "p16_input_noise_weight_bounds": {
            "or": 4,
            "local_first": 4,
            "group_selector": 5,
            "nibble_reduction": 4,
        },
        "final_code_outputs": {
            "count": FINAL_CODE_OUTPUTS,
            "scale_logs": [CODE_DELTA_LOG, CODE_DELTA_LOG],
            "weights": [1, P16],
        },
        "a34_two_nibble_scan_output": asdict(a34_two_nibble_stage_counts(gallery_size)),
        "a34_two_nibble_replacement_whole_core": asdict(
            a34_two_nibble_replacement_counts(gallery_size)
        ),
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
