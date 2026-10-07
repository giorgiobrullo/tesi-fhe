#!/usr/bin/env python3
"""Clear semantics, checked-gate ledger, and source-pin verifier for A64.

This module deliberately does not execute TFHE.  It models a reference circuit in
which every encrypted bit is a one-block ``RadixCiphertext`` of degree at most one,
and every binary Boolean gate is one call to an integer ``checked_bit*`` API.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

TFHE_VERSION = "0.11.3"
PARAMETER_SYMBOL = "V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64"
LOG2_P_FAIL_PER_PBS = -71.625
MESSAGE_MODULUS = 4
CARRY_MODULUS = 4
MAX_NOISE_LEVEL = 5
NOMINAL_NOISE_LEVEL = 1

DIMENSION = 512
SELECTORS_PER_COORDINATE = 7
COORDINATE_MIN = -3
COORDINATE_MAX = 3
PROBE_NORM2_MAX = 1024
MAX_GALLERY_SIZE = 128

QUERY_SQUARE_BITS = 4
QUERY_NORM_BITS = 13
DISTANCE_CONTRIBUTION_BITS = 6
DISTANCE_BITS = 14
THRESHOLD_BITS = 15
ID_BITS = 8

# Broad coordinate-box score support.  Thresholds outside it have no useful
# data-dependent semantics and are rejected at clear setup time.
SCORE_MIN = -4608
SCORE_MAX = 13824


class ContractError(ValueError):
    """Raised for a public configuration outside the A64 contract."""


@dataclass(frozen=True)
class GateBreakdown:
    gallery_size: int
    encrypted_input_blocks: int
    encrypted_output_blocks: int
    one_hot_validation: int
    query_square_lookups: int
    query_norm_tree: int
    query_norm_check: int
    valid_mask_join: int
    distance_lookups: int
    distance_trees: int
    scan: int
    terminal_threshold_add: int
    terminal_threshold_compare: int
    terminal_allow: int
    output_mask: int
    pbs_upper_bound: int
    union_log2_p_fail: float
    union_p_fail: float


class GateCounter:
    """Evaluate Boolean formulas while counting checked binary gate calls.

    ``not_`` is expressed as checked XOR with a trivial encrypted one, so it is
    intentionally counted as one possible PBS too.
    """

    def __init__(self) -> None:
        self.gates = 0

    def and_(self, left: bool, right: bool) -> bool:
        self.gates += 1
        return left and right

    def or_(self, left: bool, right: bool) -> bool:
        self.gates += 1
        return left or right

    def xor(self, left: bool, right: bool) -> bool:
        self.gates += 1
        return left ^ right

    def not_(self, value: bool) -> bool:
        return self.xor(value, True)

    def mux(self, take_left: bool, left: bool, right: bool) -> bool:
        # right XOR (take_left AND (left XOR right))
        delta = self.xor(left, right)
        masked = self.and_(take_left, delta)
        return self.xor(right, masked)


def bits_le(value: int, width: int) -> list[bool]:
    return [bool((value >> bit) & 1) for bit in range(width)]


def unsigned_from_bits(bits: Sequence[bool]) -> int:
    return sum(int(bit) << index for index, bit in enumerate(bits))


def signed_from_bits(bits: Sequence[bool]) -> int:
    unsigned = unsigned_from_bits(bits)
    width = len(bits)
    if bits[-1]:
        return unsigned - (1 << width)
    return unsigned


def half_adder(counter: GateCounter, left: bool, right: bool) -> tuple[bool, bool]:
    return counter.xor(left, right), counter.and_(left, right)


def full_adder(
    counter: GateCounter, left: bool, right: bool, carry: bool
) -> tuple[bool, bool]:
    pair_xor = counter.xor(left, right)
    out = counter.xor(pair_xor, carry)
    carry_direct = counter.and_(left, right)
    carry_via_input = counter.and_(carry, pair_xor)
    carry_out = counter.or_(carry_direct, carry_via_input)
    return out, carry_out


def add_bits(
    counter: GateCounter,
    left: Sequence[bool],
    right: Sequence[bool],
    *,
    keep_carry: bool,
) -> list[bool]:
    if len(left) != len(right) or len(left) < 2:
        raise ValueError("equal widths >= 2 required")
    out0, carry = half_adder(counter, left[0], right[0])
    out = [out0]
    for index in range(1, len(left)):
        if index == len(left) - 1 and not keep_carry:
            pair_xor = counter.xor(left[index], right[index])
            out.append(counter.xor(pair_xor, carry))
        else:
            bit, carry = full_adder(counter, left[index], right[index], carry)
            out.append(bit)
    if keep_carry:
        out.append(carry)
    return out


def unsigned_lt(
    counter: GateCounter, left: Sequence[bool], right: Sequence[bool]
) -> bool:
    """Ripple-borrow ``left < right`` using 4w-2 checked gates."""

    if len(left) != len(right) or not left:
        raise ValueError("equal non-empty widths required")
    differing = counter.xor(left[0], right[0])
    borrow = counter.and_(right[0], differing)
    for left_bit, right_bit in zip(left[1:], right[1:]):
        differing = counter.xor(left_bit, right_bit)
        right_vs_borrow = counter.xor(right_bit, borrow)
        change = counter.and_(differing, right_vs_borrow)
        borrow = counter.xor(borrow, change)
    return borrow


def signed_lt(
    counter: GateCounter, left: Sequence[bool], right: Sequence[bool]
) -> bool:
    if len(left) != len(right) or not left:
        raise ValueError("equal non-empty widths required")
    unsigned_result = unsigned_lt(counter, left, right)
    sign_differs = counter.xor(left[-1], right[-1])
    return counter.xor(unsigned_result, sign_differs)


def signed_le(
    counter: GateCounter, left: Sequence[bool], right: Sequence[bool]
) -> bool:
    return counter.not_(signed_lt(counter, right, left))


def exactly_one_of_seven(counter: GateCounter, selectors: Sequence[bool]) -> bool:
    if len(selectors) != SELECTORS_PER_COORDINATE:
        raise ValueError("seven selectors required")
    duplicate = counter.and_(selectors[0], selectors[1])
    seen = counter.or_(selectors[0], selectors[1])
    for selector in selectors[2:]:
        collision = counter.and_(seen, selector)
        duplicate = counter.or_(duplicate, collision)
        seen = counter.or_(seen, selector)
    return counter.and_(seen, counter.not_(duplicate))


def xor_lookup(
    counter: GateCounter,
    selectors: Sequence[bool],
    clear_values: Sequence[int],
    width: int,
) -> list[bool]:
    """One-hot lookup using only XOR reductions.

    Correctness is conditioned on exactly one selector being true.  For an
    invalid selector vector it still returns a width-bit value, which is later
    masked by the encrypted validity bit.
    """

    if len(selectors) != len(clear_values):
        raise ValueError("selector/value size mismatch")
    outputs: list[bool] = []
    mask = (1 << width) - 1
    for bit_index in range(width):
        chosen = [
            selector
            for selector, value in zip(selectors, clear_values)
            if ((value & mask) >> bit_index) & 1
        ]
        if not chosen:
            outputs.append(False)
            continue
        value = chosen[0]
        for selector in chosen[1:]:
            value = counter.xor(value, selector)
        outputs.append(value)
    return outputs


def query_square_lookup(counter: GateCounter, selectors: Sequence[bool]) -> list[bool]:
    values = [coordinate * coordinate for coordinate in range(-3, 4)]
    return xor_lookup(counter, selectors, values, QUERY_SQUARE_BITS)


def distance_lookup(
    counter: GateCounter, selectors: Sequence[bool], template_coordinate: int
) -> list[bool]:
    if not COORDINATE_MIN <= template_coordinate <= COORDINATE_MAX:
        raise ValueError("template coordinate outside [-3, 3]")
    values = [
        (query_coordinate - template_coordinate) ** 2
        for query_coordinate in range(-3, 4)
    ]
    return xor_lookup(counter, selectors, values, DISTANCE_CONTRIBUTION_BITS)


def full_sum_tree_gate_count(leaves: int, leaf_width: int) -> int:
    if leaves < 1 or leaves & (leaves - 1):
        raise ValueError("a positive power-of-two leaf count is required")
    total = 0
    level = 0
    adders = leaves // 2
    while adders:
        width = leaf_width + level
        total += adders * (5 * width - 3)
        adders //= 2
        level += 1
    return total


def distance_sum_tree_gate_count() -> int:
    # The last carry is discarded.  It is zero for every valid query by the
    # Cauchy bound; invalid queries are encrypted-mask rejected.
    full_first_eight_levels = sum(
        (DIMENSION >> (level + 1))
        * (5 * (DISTANCE_CONTRIBUTION_BITS + level) - 3)
        for level in range(8)
    )
    final_modular_adder = 5 * DISTANCE_BITS - 6
    return full_first_eight_levels + final_modular_adder


def lookup_xor_gate_count(clear_values: Sequence[int], width: int) -> int:
    mask = (1 << width) - 1
    return sum(
        max(
            0,
            sum(((value & mask) >> bit_index) & 1 for value in clear_values) - 1,
        )
        for bit_index in range(width)
    )


def distance_lookup_gate_count(template_coordinate: int) -> int:
    values = [
        (query_coordinate - template_coordinate) ** 2
        for query_coordinate in range(-3, 4)
    ]
    return lookup_xor_gate_count(values, DISTANCE_CONTRIBUTION_BITS)


def query_square_lookup_gate_count() -> int:
    return lookup_xor_gate_count(
        [coordinate * coordinate for coordinate in range(-3, 4)], QUERY_SQUARE_BITS
    )


def valid_distance_upper_bound() -> int:
    template_norm2_max = DIMENSION * COORDINATE_MAX**2
    # This mirrors A41's conservative integer Cauchy rounding.
    radius = 2 * math.isqrt(PROBE_NORM2_MAX * template_norm2_max)
    if radius * radius < 4 * PROBE_NORM2_MAX * template_norm2_max:
        radius += 2
    return PROBE_NORM2_MAX + template_norm2_max + radius


def validate_gallery(
    gallery: Sequence[Sequence[int]], thresholds: Sequence[int]
) -> None:
    if not 1 <= len(gallery) <= MAX_GALLERY_SIZE:
        raise ContractError("gallery size must be in 1..=128")
    if len(thresholds) != len(gallery):
        raise ContractError("one threshold per gallery entry is required")
    for index, template in enumerate(gallery):
        if len(template) != DIMENSION:
            raise ContractError(f"template {index} does not have 512 coordinates")
        if any(
            coordinate < COORDINATE_MIN or coordinate > COORDINATE_MAX
            for coordinate in template
        ):
            raise ContractError(f"template {index} has a coordinate outside [-3, 3]")
    for index, threshold in enumerate(thresholds):
        if not SCORE_MIN <= threshold <= SCORE_MAX:
            raise ContractError(
                f"threshold {index} outside [{SCORE_MIN}, {SCORE_MAX}]"
            )


def query_is_valid(query: Sequence[int]) -> bool:
    return (
        len(query) == DIMENSION
        and all(COORDINATE_MIN <= coordinate <= COORDINATE_MAX for coordinate in query)
        and sum(coordinate * coordinate for coordinate in query) <= PROBE_NORM2_MAX
    )


def score(query: Sequence[int], template: Sequence[int]) -> int:
    template_norm2 = sum(value * value for value in template)
    dot = sum(left * right for left, right in zip(query, template))
    return template_norm2 - 2 * dot


def squared_distance(query: Sequence[int], template: Sequence[int]) -> int:
    return sum((left - right) ** 2 for left, right in zip(query, template))


def clear_score_protocol(
    query: Sequence[int],
    gallery: Sequence[Sequence[int]],
    thresholds: Sequence[int],
) -> int:
    validate_gallery(gallery, thresholds)
    if not query_is_valid(query):
        return 0
    scores = [score(query, template) for template in gallery]
    winner = min(range(len(scores)), key=lambda index: (scores[index], index))
    return winner + 1 if scores[winner] <= thresholds[winner] else 0


def clear_a64_protocol(
    query: Sequence[int],
    gallery: Sequence[Sequence[int]],
    thresholds: Sequence[int],
) -> int:
    """A64's distance/selected-threshold formulation in clear arithmetic."""

    validate_gallery(gallery, thresholds)
    if not query_is_valid(query):
        return 0
    query_norm2 = sum(value * value for value in query)
    distances = [squared_distance(query, template) for template in gallery]
    winner = min(range(len(distances)), key=lambda index: (distances[index], index))
    accepted = distances[winner] <= query_norm2 + thresholds[winner]
    return winner + 1 if accepted else 0


def worst_case_gate_breakdown(gallery_size: int) -> GateBreakdown:
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ContractError("gallery size must be in 1..=128")

    encrypted_input_blocks = DIMENSION * SELECTORS_PER_COORDINATE
    encrypted_output_blocks = ID_BITS

    one_hot_validation = DIMENSION * 19 + (DIMENSION - 1)
    query_square_lookups = DIMENSION * query_square_lookup_gate_count()
    query_norm_tree = full_sum_tree_gate_count(DIMENSION, QUERY_SQUARE_BITS)
    query_norm_check = 13
    valid_mask_join = 1

    worst_distance_lookup = max(
        distance_lookup_gate_count(coordinate)
        for coordinate in range(COORDINATE_MIN, COORDINATE_MAX + 1)
    )
    distance_lookups = gallery_size * DIMENSION * worst_distance_lookup
    distance_trees = gallery_size * distance_sum_tree_gate_count()

    unsigned_less_14 = 4 * DISTANCE_BITS - 2
    distance_mux = 3 * DISTANCE_BITS
    shared_not_take = 1
    public_id_select = ID_BITS
    public_threshold_select = THRESHOLD_BITS
    scan_per_challenger = (
        unsigned_less_14
        + distance_mux
        + shared_not_take
        + public_id_select
        + public_threshold_select
    )
    scan = (gallery_size - 1) * scan_per_challenger

    terminal_threshold_add = 5 * THRESHOLD_BITS - 6
    terminal_threshold_compare = (4 * THRESHOLD_BITS - 2) + 2 + 1
    terminal_allow = 1
    output_mask = ID_BITS

    pbs_upper_bound = sum(
        (
            one_hot_validation,
            query_square_lookups,
            query_norm_tree,
            query_norm_check,
            valid_mask_join,
            distance_lookups,
            distance_trees,
            scan,
            terminal_threshold_add,
            terminal_threshold_compare,
            terminal_allow,
            output_mask,
        )
    )
    union_log2_p_fail = math.log2(pbs_upper_bound) + LOG2_P_FAIL_PER_PBS
    union_p_fail = 2.0**union_log2_p_fail

    return GateBreakdown(
        gallery_size=gallery_size,
        encrypted_input_blocks=encrypted_input_blocks,
        encrypted_output_blocks=encrypted_output_blocks,
        one_hot_validation=one_hot_validation,
        query_square_lookups=query_square_lookups,
        query_norm_tree=query_norm_tree,
        query_norm_check=query_norm_check,
        valid_mask_join=valid_mask_join,
        distance_lookups=distance_lookups,
        distance_trees=distance_trees,
        scan=scan,
        terminal_threshold_add=terminal_threshold_add,
        terminal_threshold_compare=terminal_threshold_compare,
        terminal_allow=terminal_allow,
        output_mask=output_mask,
        pbs_upper_bound=pbs_upper_bound,
        union_log2_p_fail=union_log2_p_fail,
        union_p_fail=union_p_fail,
    )


def _resolve_pin_path(raw_path: str) -> Path:
    expanded = Path(os.path.expandvars(os.path.expanduser(raw_path)))
    return expanded if expanded.is_absolute() else ROOT / expanded


def verify_source_pins(pin_file: Path | None = None) -> list[dict[str, object]]:
    path = pin_file or HERE / "source_pins.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    results: list[dict[str, object]] = []
    for source in payload["sources"]:
        resolved = _resolve_pin_path(source["path"])
        data = resolved.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != source["sha256"]:
            raise AssertionError(
                f"sha256 drift for {source['id']}: {digest} != {source['sha256']}"
            )
        text = data.decode("utf-8")
        missing = [marker for marker in source["markers"] if marker not in text]
        if missing:
            raise AssertionError(f"missing markers for {source['id']}: {missing}")
        results.append(
            {
                "id": source["id"],
                "path": str(resolved),
                "sha256": digest,
                "markers": len(source["markers"]),
            }
        )
    return results


def summary() -> dict[str, object]:
    counts = {str(size): asdict(worst_case_gate_breakdown(size)) for size in (1, 8, 127, 128)}
    return {
        "status": "static reference design; no Cargo, keygen, or FHE execution",
        "tfhe": TFHE_VERSION,
        "parameter": PARAMETER_SYMBOL,
        "representation": {
            "query": "512 x 7 encrypted one-hot one-block radix bits",
            "query_norm_bits": QUERY_NORM_BITS,
            "distance_bits": DISTANCE_BITS,
            "selected_threshold_bits": THRESHOLD_BITS,
            "id_bits": ID_BITS,
            "output_bits": ID_BITS,
        },
        "bounds": {
            "valid_distance_upper_conservative": valid_distance_upper_bound(),
            "distance_capacity": (1 << DISTANCE_BITS) - 1,
            "score_support": [SCORE_MIN, SCORE_MAX],
            "per_checked_gate_packed_noise_max": 3,
            "preset_max_noise_level": MAX_NOISE_LEVEL,
            "per_pbs_log2_p_fail": LOG2_P_FAIL_PER_PBS,
        },
        "counts": counts,
        "closed_formula": "M(N) = 24029 + 18984*N, 1 <= N <= 128",
        "raw_core_crypto_calls": 0,
        "many_lut_calls": 0,
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verify-pins", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    output = summary()
    if args.verify_pins:
        output["pins"] = verify_source_pins()
    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        n128 = output["counts"]["128"]
        print(output["status"])
        print(output["closed_formula"])
        print(
            "N=128: "
            f"M={n128['pbs_upper_bound']}, "
            f"union_log2={n128['union_log2_p_fail']:.12f}, "
            f"union_p={n128['union_p_fail']:.12e}"
        )
        if args.verify_pins:
            print(f"pins: {len(output['pins'])} verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
