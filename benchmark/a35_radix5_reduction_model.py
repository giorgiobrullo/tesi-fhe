#!/usr/bin/env python3
"""Clear/count audit of radix-5 OR reductions for the A33/A34 circuits.

The production parameter set declares ``max_noise_level=5``.  Every input to an
OR node is a fresh Boolean at ``Delta_bool=2^59``; replacing radix four with
radix five therefore reaches, but does not exceed, the declared algebraic
limit.  The sign-based OR input is ``(1/2-s)*Delta_bool`` for ``s in 0..5`` and
retains a minimum decision margin of ``Delta_bool/2``.  Prefix expansion has at
most one fresh block prefix plus four fresh local flags.  One-hot A34 digit
reductions may sum five noisy ciphertexts, but their reachable plaintext stays
in ``0..15`` because at most one digit is nonzero.

This module checks clear OR/reduction/prefix semantics and recomputes exact
structural BR/KS/output-marginal counts for the frozen A33 output, the A34
base-8 candidate, and the A34 two-nibble candidate.  It does not modify those
implementations, run FHE, estimate latency, or promote the parameter set's
nominal per-PBS p-fail to an end-to-end bound.  The core_crypto path does not
carry the shortint NoiseLevel tracker, and shared-query/multi-output errors can
be correlated.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from itertools import product
from typing import Sequence


MAX_GALLERY_SIZE = 128
GROUP_SIZE = 3
BASE8_HIGH_GROUP = 21
RADIX4 = 4
RADIX5 = 5
P16 = 16
BOOL_DELTA_LOG = 59
BOOL_DELTA = 1 << BOOL_DELTA_LOG
SHORTINT_MAX_NOISE_LEVEL = 5


@dataclass(frozen=True)
class PrimitiveCounts:
    blind_rotations: int
    key_switches: int
    output_marginals: int


@dataclass(frozen=True)
class OrSignContract:
    fan_in: int
    count: int
    signed_input_half_delta_units: int
    output: int
    nearest_decision_margin: int
    fresh_input_l1: int
    within_p16_signed_half: bool
    within_max_noise_level: bool


@dataclass(frozen=True)
class NoiseAudit:
    radix: int
    reduction_input_l1: int
    prefix_block_total_l1: int
    prefix_first_block_expansion_l1: int
    prefix_later_block_expansion_l1: int
    one_hot_digit_reduction_l1: int
    p16_largest_reachable_digit: int
    p16_half_slot_margin: int
    existing_odd_normalization_l1: int
    maximum_local_l1: int
    conservative_max_noise_level: int
    within_declared_limit: bool
    shortint_tracker_enforced_by_core: bool


@dataclass(frozen=True)
class ReductionTopology:
    items: int
    radix: int
    level_widths: tuple[int, ...]
    blind_rotations: int


@dataclass(frozen=True)
class CountBreakdown:
    gallery_size: int
    radix: int
    pre_scan: PrimitiveCounts
    scan_output: PrimitiveCounts
    whole_core: PrimitiveCounts


@dataclass(frozen=True)
class A33StageDetails:
    first_one_scan_blind_rotations: int
    output_blind_rotations: int
    gallery_reduction_blind_rotations_each: int
    pair_reduction_blind_rotations: int


@dataclass(frozen=True)
class A34StageDetails:
    groups: int
    group_nodes: int
    prefix_nodes: int
    selector_nodes: int
    digit_reduction_nodes: int
    high_flag_nodes: int
    high_digit_nodes: int


@dataclass(frozen=True)
class N127Comparison:
    a33_radix4: CountBreakdown
    a33_radix5: CountBreakdown
    a33_savings: PrimitiveCounts
    a34_base8_radix4: CountBreakdown
    a34_base8_radix5: CountBreakdown
    a34_base8_savings: PrimitiveCounts
    a34_two_nibble_radix4: CountBreakdown
    a34_two_nibble_radix5: CountBreakdown
    a34_two_nibble_savings: PrimitiveCounts


def _validate_radix(radix: int) -> None:
    if radix not in (RADIX4, RADIX5):
        raise ValueError("this audit compares only radix four and five")


def _validate_gallery_size(gallery_size: int) -> None:
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError(f"gallery size must be in 1..{MAX_GALLERY_SIZE}")


def or_sign_contract(fan_in: int, count: int) -> OrSignContract:
    """Model the constant-sign-accumulator OR used by the Rust core.

    Half-delta units avoid fractions: the pre-PBS signed phase is ``1-2*s``.
    The nearest sign boundary is zero; the padding boundary is at +/-32 such
    units for a p=16 accumulator at Delta=2^59.
    """
    if not 1 <= fan_in <= RADIX5 or not 0 <= count <= fan_in:
        raise ValueError("invalid OR count/fan-in")
    half_units = 1 - 2 * count
    padding_half_units = 2 * P16
    return OrSignContract(
        fan_in=fan_in,
        count=count,
        signed_input_half_delta_units=half_units,
        output=int(count != 0),
        nearest_decision_margin=abs(half_units) * (BOOL_DELTA // 2),
        fresh_input_l1=fan_in,
        within_p16_signed_half=abs(half_units) < padding_half_units,
        within_max_noise_level=fan_in <= SHORTINT_MAX_NOISE_LEVEL,
    )


def or_gate(bits: Sequence[bool | int], *, radix: int) -> bool:
    _validate_radix(radix)
    values = tuple(bits)
    if not 1 <= len(values) <= radix:
        raise ValueError("OR gate input count is outside its radix")
    if any(value not in (False, True, 0, 1) for value in values):
        raise ValueError("OR inputs must be Boolean")
    contract = or_sign_contract(radix, sum(bool(value) for value in values))
    if not contract.within_p16_signed_half:
        raise AssertionError("OR phase crossed the p=16 signed half-domain")
    return bool(contract.output)


def reduction_topology(items: int, *, radix: int) -> ReductionTopology:
    _validate_radix(radix)
    if items <= 0:
        raise ValueError("reduction requires at least one item")
    widths = [items]
    nodes = 0
    while items > 1:
        items = (items + radix - 1) // radix
        widths.append(items)
        nodes += items
    return ReductionTopology(
        items=widths[0],
        radix=radix,
        level_widths=tuple(widths),
        blind_rotations=nodes,
    )


def reduce_or(bits: Sequence[bool | int], *, radix: int) -> bool:
    _validate_radix(radix)
    level = list(bits)
    if not level:
        raise ValueError("OR reduction requires at least one item")
    while len(level) > 1:
        level = [
            or_gate(level[start : start + radix], radix=radix)
            for start in range(0, len(level), radix)
        ]
    return bool(level[0])


def reduce_one_hot_digits(values: Sequence[int], *, radix: int) -> int:
    """Clear p=16 identity reduction used by the A34 output digits."""
    _validate_radix(radix)
    level = list(values)
    if not level or any(not 0 <= value < P16 for value in level):
        raise ValueError("digit reduction requires p=16 digits")
    if sum(value != 0 for value in level) > 1:
        raise ValueError("digit inputs must be globally one-hot")
    while len(level) > 1:
        next_level = []
        for start in range(0, len(level), radix):
            value = sum(level[start : start + radix])
            if not 0 <= value < P16:
                raise AssertionError("one-hot p=16 plaintext invariant failed")
            next_level.append(value)
        level = next_level
    return level[0]


def exclusive_prefix_or(flags: Sequence[bool | int], *, radix: int) -> tuple[bool, ...]:
    """Generalized clear form of the Rust radix-4 recursive prefix network."""
    _validate_radix(radix)
    values = tuple(flags)
    if not values or any(value not in (False, True, 0, 1) for value in values):
        raise ValueError("prefix flags must be a non-empty Boolean sequence")
    canonical = tuple(bool(value) for value in values)
    if len(canonical) <= radix:
        return tuple(
            False if index == 0 else any(canonical[:index])
            for index in range(len(canonical))
        )

    block_totals = tuple(
        reduce_or(canonical[start : start + radix], radix=radix)
        for start in range(0, len(canonical), radix)
    )
    block_prefixes = exclusive_prefix_or(block_totals, radix=radix)
    result: list[bool] = []
    for index in range(len(canonical)):
        block = index // radix
        offset = index % radix
        if offset == 0:
            result.append(block_prefixes[block])
            continue
        start = block * radix
        inputs = list(canonical[start:index])
        if block > 0:
            inputs.insert(0, block_prefixes[block])
        result.append(inputs[0] if len(inputs) == 1 else or_gate(inputs, radix=radix))
    return tuple(result)


def exclusive_prefix_blind_rotations(items: int, *, radix: int) -> int:
    _validate_radix(radix)
    if items <= 0:
        raise ValueError("prefix network requires at least one item")
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
    return totals + expansion + exclusive_prefix_blind_rotations(blocks, radix=radix)


def noise_audit(radix: int = RADIX5) -> NoiseAudit:
    _validate_radix(radix)
    bounds = (radix, radix, radix - 1, radix, radix, 5)
    return NoiseAudit(
        radix=radix,
        reduction_input_l1=bounds[0],
        prefix_block_total_l1=bounds[1],
        prefix_first_block_expansion_l1=bounds[2],
        prefix_later_block_expansion_l1=bounds[3],
        one_hot_digit_reduction_l1=bounds[4],
        p16_largest_reachable_digit=P16 - 1,
        p16_half_slot_margin=BOOL_DELTA // 2,
        existing_odd_normalization_l1=bounds[5],
        maximum_local_l1=max(bounds),
        conservative_max_noise_level=SHORTINT_MAX_NOISE_LEVEL,
        within_declared_limit=max(bounds) <= SHORTINT_MAX_NOISE_LEVEL,
        shortint_tracker_enforced_by_core=False,
    )


def _group_count(gallery_size: int) -> int:
    return (gallery_size + GROUP_SIZE - 1) // GROUP_SIZE


def _group_nodes(gallery_size: int) -> int:
    return sum(
        min(GROUP_SIZE, gallery_size - start) > 1
        for start in range(0, gallery_size, GROUP_SIZE)
    )


def _pre_scan_counts(gallery_size: int, radix: int) -> PrimitiveCounts:
    reduction = reduction_topology(gallery_size, radix=radix).blind_rotations
    pairs = (gallery_size + 1) // 2
    pair_reduction = reduction_topology(pairs, radix=radix).blind_rotations
    blind_rotations = 27 * gallery_size + 9 * reduction + pairs + pair_reduction
    key_switches = 24 * gallery_size + 9 * reduction + pairs + pair_reduction
    return PrimitiveCounts(
        blind_rotations,
        key_switches,
        blind_rotations + 5 * gallery_size,
    )


def _selected_codes(gallery_size: int, bit_position: int) -> int:
    return sum((code >> bit_position) & 1 for code in range(1, gallery_size + 1))


def a33_stage_details(gallery_size: int, *, radix: int) -> A33StageDetails:
    _validate_gallery_size(gallery_size)
    _validate_radix(radix)
    groups = _group_count(gallery_size)
    scan = (
        _group_nodes(gallery_size)
        + exclusive_prefix_blind_rotations(groups, radix=radix)
        + gallery_size
    )
    bit_count = gallery_size.bit_length()
    output = (
        sum(
            max(
                1,
                reduction_topology(
                    _selected_codes(gallery_size, bit_position), radix=radix
                ).blind_rotations,
            )
            for bit_position in range(bit_count)
        )
        + (bit_count + 2) // 3
    )
    pairs = (gallery_size + 1) // 2
    return A33StageDetails(
        first_one_scan_blind_rotations=scan,
        output_blind_rotations=output,
        gallery_reduction_blind_rotations_each=reduction_topology(
            gallery_size, radix=radix
        ).blind_rotations,
        pair_reduction_blind_rotations=reduction_topology(
            pairs, radix=radix
        ).blind_rotations,
    )


def a33_counts(gallery_size: int, *, radix: int) -> CountBreakdown:
    _validate_gallery_size(gallery_size)
    pre = _pre_scan_counts(gallery_size, radix)
    details = a33_stage_details(gallery_size, radix=radix)
    stage_rotations = (
        details.first_one_scan_blind_rotations + details.output_blind_rotations
    )
    stage = PrimitiveCounts(stage_rotations, stage_rotations, stage_rotations)
    whole = PrimitiveCounts(
        pre.blind_rotations + stage.blind_rotations,
        pre.key_switches + stage.key_switches,
        pre.output_marginals + stage.output_marginals,
    )
    return CountBreakdown(gallery_size, radix, pre, stage, whole)


def a34_stage_details(
    gallery_size: int, *, radix: int, two_nibble: bool
) -> A34StageDetails:
    _validate_gallery_size(gallery_size)
    _validate_radix(radix)
    groups = _group_count(gallery_size)
    high_flag_nodes = 0
    high_digit_nodes = 0
    if not two_nibble and gallery_size >= 64:
        high_flag_nodes = reduction_topology(
            groups - BASE8_HIGH_GROUP, radix=radix
        ).blind_rotations
        high_digit_nodes = 1
    return A34StageDetails(
        groups=groups,
        group_nodes=_group_nodes(gallery_size),
        prefix_nodes=exclusive_prefix_blind_rotations(groups, radix=radix),
        selector_nodes=groups,
        digit_reduction_nodes=2
        * reduction_topology(groups, radix=radix).blind_rotations,
        high_flag_nodes=high_flag_nodes,
        high_digit_nodes=high_digit_nodes,
    )


def a34_counts(gallery_size: int, *, radix: int, two_nibble: bool) -> CountBreakdown:
    pre = _pre_scan_counts(gallery_size, radix)
    details = a34_stage_details(gallery_size, radix=radix, two_nibble=two_nibble)
    rotations = (
        2 * details.group_nodes
        + details.prefix_nodes
        + details.selector_nodes
        + details.digit_reduction_nodes
        + details.high_flag_nodes
        + details.high_digit_nodes
    )
    selector_marginals = (
        2 * details.groups
        if two_nibble
        else 2 * details.groups - int(gallery_size == 127)
    )
    marginals = rotations - details.selector_nodes + selector_marginals
    stage = PrimitiveCounts(rotations, rotations, marginals)
    whole = PrimitiveCounts(
        pre.blind_rotations + stage.blind_rotations,
        pre.key_switches + stage.key_switches,
        pre.output_marginals + stage.output_marginals,
    )
    return CountBreakdown(gallery_size, radix, pre, stage, whole)


def _subtract(left: PrimitiveCounts, right: PrimitiveCounts) -> PrimitiveCounts:
    return PrimitiveCounts(
        left.blind_rotations - right.blind_rotations,
        left.key_switches - right.key_switches,
        left.output_marginals - right.output_marginals,
    )


def n127_comparison() -> N127Comparison:
    a33_r4 = a33_counts(127, radix=RADIX4)
    a33_r5 = a33_counts(127, radix=RADIX5)
    base8_r4 = a34_counts(127, radix=RADIX4, two_nibble=False)
    base8_r5 = a34_counts(127, radix=RADIX5, two_nibble=False)
    two_r4 = a34_counts(127, radix=RADIX4, two_nibble=True)
    two_r5 = a34_counts(127, radix=RADIX5, two_nibble=True)
    return N127Comparison(
        a33_radix4=a33_r4,
        a33_radix5=a33_r5,
        a33_savings=_subtract(a33_r4.whole_core, a33_r5.whole_core),
        a34_base8_radix4=base8_r4,
        a34_base8_radix5=base8_r5,
        a34_base8_savings=_subtract(base8_r4.whole_core, base8_r5.whole_core),
        a34_two_nibble_radix4=two_r4,
        a34_two_nibble_radix5=two_r5,
        a34_two_nibble_savings=_subtract(two_r4.whole_core, two_r5.whole_core),
    )


def assert_n127_counts() -> None:
    comparison = n127_comparison()
    assert comparison.a33_radix4.whole_core == PrimitiveCounts(4_273, 3_892, 4_908)
    assert comparison.a33_radix5.pre_scan == PrimitiveCounts(3_825, 3_444, 4_460)
    assert comparison.a33_radix5.scan_output == PrimitiveCounts(341, 341, 341)
    assert comparison.a33_radix5.whole_core == PrimitiveCounts(4_166, 3_785, 4_801)
    assert comparison.a33_savings == PrimitiveCounts(107, 107, 107)

    assert comparison.a34_base8_radix4.whole_core == PrimitiveCounts(
        4_121, 3_740, 4_798
    )
    assert comparison.a34_base8_radix5.scan_output == PrimitiveCounts(208, 208, 250)
    assert comparison.a34_base8_radix5.whole_core == PrimitiveCounts(
        4_033, 3_652, 4_710
    )
    assert comparison.a34_base8_savings == PrimitiveCounts(88, 88, 88)

    assert comparison.a34_two_nibble_radix4.whole_core == PrimitiveCounts(
        4_111, 3_730, 4_789
    )
    assert comparison.a34_two_nibble_radix5.scan_output == PrimitiveCounts(
        201, 201, 244
    )
    assert comparison.a34_two_nibble_radix5.whole_core == PrimitiveCounts(
        4_026, 3_645, 4_704
    )
    assert comparison.a34_two_nibble_savings == PrimitiveCounts(85, 85, 85)


def validate_clear_semantics() -> dict[str, int]:
    """Exhaust small spaces and all supported topology widths."""
    or_cases = 0
    prefix_cases = 0
    one_hot_cases = 0
    for radix in (RADIX4, RADIX5):
        for width in range(1, radix + 1):
            for bits in product((False, True), repeat=width):
                assert or_gate(bits, radix=radix) == any(bits)
                or_cases += 1
        for width in range(1, 11):
            for bits in product((False, True), repeat=width):
                expected = tuple(any(bits[:index]) for index in range(width))
                assert exclusive_prefix_or(bits, radix=radix) == expected
                prefix_cases += 1
        for width in range(1, MAX_GALLERY_SIZE + 1):
            assert reduce_one_hot_digits((0,) * width, radix=radix) == 0
            one_hot_cases += 1
            for position in range(width):
                for digit in (1, 7, 15):
                    values = [0] * width
                    values[position] = digit
                    assert reduce_one_hot_digits(values, radix=radix) == digit
                    one_hot_cases += 1
    return {
        "or_cases": or_cases,
        "prefix_cases": prefix_cases,
        "one_hot_cases": one_hot_cases,
        "total_cases": or_cases + prefix_cases + one_hot_cases,
    }


def report(validate: bool) -> dict[str, object]:
    comparison = n127_comparison()
    return {
        "schema_version": 1,
        "model": "a35-radix5-clear-count-audit",
        "status": "structural max-noise compatibility PASS; FHE/p-fail unproven",
        "noise": asdict(noise_audit()),
        "or_sign_states": [
            asdict(or_sign_contract(RADIX5, count)) for count in range(6)
        ],
        "n127": asdict(comparison),
        "validation": validate_clear_semantics() if validate else None,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-validate", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    assert_n127_counts()
    print(json.dumps(report(not args.no_validate), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
