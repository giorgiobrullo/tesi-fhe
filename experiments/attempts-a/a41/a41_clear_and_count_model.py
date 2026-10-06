#!/usr/bin/env python3
"""Clear semantics and structural-count model for isolated A41.

A41 keeps the implemented A38 graph and changes only its terminal encoding:
two independent p=16 LWE roots at Delta=2^59 carry ``low`` and ``high``.
This file proves no cryptographic failure probability and runs no FHE.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from itertools import product


MAX_GALLERY_SIZE = 128
SCAN_GROUP_SIZE = 3
REDUCTION_RADIX = 5
LEGACY_REDUCTION_RADIX = 4
BOOL_DELTA_LOG = 59
LWE_SIZE_WORDS = 2_049
HEADER_WORDS_WITH_LENGTH_PREFIX = 9
WORD_BYTES = 8


@dataclass(frozen=True)
class Counts:
    blind_rotations: int
    key_switches: int
    output_marginals: int


@dataclass(frozen=True)
class ClearResult:
    gallery_size: int
    candidates: tuple[int, ...]
    group_flags: tuple[int, ...]
    local_first: tuple[int, ...]
    group_prefixes: tuple[int, ...]
    low_digits: tuple[int, ...]
    high_digits: tuple[int, ...]
    low_nibble: int
    high_nibble: int
    code: int


def ceil_div(value: int, divisor: int) -> int:
    return (value + divisor - 1) // divisor


def reduction_nodes(items: int, radix: int) -> int:
    nodes = 0
    while items > 1:
        items = ceil_div(items, radix)
        nodes += items
    return nodes


def exclusive_prefix_nodes(items: int, radix: int) -> int:
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
    return totals + expansion + exclusive_prefix_nodes(blocks, radix)


def output_bit_positions(gallery_size: int) -> tuple[int, ...]:
    return tuple(
        bit
        for bit in range(gallery_size.bit_length())
        if any(((index + 1) >> bit) & 1 for index in range(gallery_size))
    )


def legacy_first_one_scan_nodes(items: int) -> int:
    groups = ceil_div(items, SCAN_GROUP_SIZE)
    group_totals = sum(
        min(SCAN_GROUP_SIZE, items - start) > 1
        for start in range(0, items, SCAN_GROUP_SIZE)
    )
    return group_totals + exclusive_prefix_nodes(groups, LEGACY_REDUCTION_RADIX) + items


def legacy_output_nodes(gallery_size: int) -> int:
    positions = output_bit_positions(gallery_size)
    bit_nodes = 0
    for bit in positions:
        contributors = sum(
            ((index + 1) >> bit) & 1 for index in range(gallery_size)
        )
        bit_nodes += max(1, reduction_nodes(contributors, LEGACY_REDUCTION_RADIX))
    return bit_nodes + ceil_div(len(positions), 3)


def a41_counts(gallery_size: int) -> Counts:
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError("gallery_size must be in 1..128")
    n = gallery_size
    old_total = (
        27 * n
        + 8 * reduction_nodes(n, LEGACY_REDUCTION_RADIX)
        + legacy_first_one_scan_nodes(n)
        + legacy_output_nodes(n)
        - 1
    )
    old_low = 12 * n + 8 * reduction_nodes(n, LEGACY_REDUCTION_RADIX)
    old_scan_output = legacy_first_one_scan_nodes(n) + legacy_output_nodes(n)
    new_low = 10 * n + 8 * reduction_nodes(n, REDUCTION_RADIX)
    groups = ceil_div(n, SCAN_GROUP_SIZE)
    group_nodes = sum(
        min(SCAN_GROUP_SIZE, n - start) > 1
        for start in range(0, n, SCAN_GROUP_SIZE)
    )
    prefix_nodes = exclusive_prefix_nodes(groups, REDUCTION_RADIX)
    digit_nodes = 2 * reduction_nodes(groups, REDUCTION_RADIX)
    new_scan_output = 2 * group_nodes + prefix_nodes + groups + digit_nodes
    blind_rotations = old_total - old_low - old_scan_output + new_low + new_scan_output
    return Counts(
        blind_rotations=blind_rotations,
        key_switches=blind_rotations - 3 * n,
        output_marginals=blind_rotations + 4 * n + groups,
    )


def prudent_raw_l1_counts(gallery_size: int) -> Counts:
    """Separate projection: refresh after b6 and b2 in addition to b4 and b0."""
    base = a41_counts(gallery_size)
    added_refreshes = 2 * gallery_size
    return Counts(
        blind_rotations=base.blind_rotations + added_refreshes,
        key_switches=base.key_switches + added_refreshes,
        output_marginals=base.output_marginals + added_refreshes,
    )


def evaluate(candidates: tuple[int, ...]) -> ClearResult:
    if not 1 <= len(candidates) <= MAX_GALLERY_SIZE:
        raise ValueError("candidate vector length must be in 1..128")
    if any(value not in (0, 1) for value in candidates):
        raise ValueError("candidates must be Boolean")

    chunks = tuple(
        candidates[start : start + SCAN_GROUP_SIZE]
        for start in range(0, len(candidates), SCAN_GROUP_SIZE)
    )
    group_flags = tuple(int(any(chunk)) for chunk in chunks)
    local_first = tuple(
        next((offset + 1 for offset, bit in enumerate(chunk) if bit), 0)
        for chunk in chunks
    )
    group_prefixes = tuple(int(any(group_flags[:group])) for group in range(len(chunks)))

    codes = tuple(
        SCAN_GROUP_SIZE * group + state if state and not prefix else 0
        for group, (state, prefix) in enumerate(zip(local_first, group_prefixes))
    )
    low_digits = tuple(code & 0xF for code in codes)
    high_digits = tuple(code >> 4 for code in codes)
    low_nibble = sum(low_digits)
    high_nibble = sum(high_digits)
    code = low_nibble + 16 * high_nibble

    expected = next(
        (index + 1 for index, candidate in enumerate(candidates) if candidate),
        0,
    )
    assert code == expected
    assert 0 <= low_nibble <= 15
    assert 0 <= high_nibble <= 8
    assert sum(value != 0 for value in codes) <= 1
    return ClearResult(
        gallery_size=len(candidates),
        candidates=candidates,
        group_flags=group_flags,
        local_first=local_first,
        group_prefixes=group_prefixes,
        low_digits=low_digits,
        high_digits=high_digits,
        low_nibble=low_nibble,
        high_nibble=high_nibble,
        code=code,
    )


def wire_projection() -> dict[str, int | float]:
    single_bytes = WORD_BYTES * (HEADER_WORDS_WITH_LENGTH_PREFIX + LWE_SIZE_WORDS)
    two_bytes = WORD_BYTES * (HEADER_WORDS_WITH_LENGTH_PREFIX + 2 * LWE_SIZE_WORDS)
    return {
        "single_lwe_bytes": single_bytes,
        "two_lwe_bytes": two_bytes,
        "additional_bytes": two_bytes - single_bytes,
        "size_ratio": two_bytes / single_bytes,
    }


def validate() -> dict[str, object]:
    exhaustive_vectors = 0
    for gallery_size in range(1, 17):
        for candidate_tuple in product((0, 1), repeat=gallery_size):
            evaluate(candidate_tuple)
            exhaustive_vectors += 1

    representative_vectors = 0
    for gallery_size in range(1, MAX_GALLERY_SIZE + 1):
        evaluate((0,) * gallery_size)
        representative_vectors += 1
        for first in range(gallery_size):
            prefixes = (
                (0,) * first + (1,) + (0,) * (gallery_size - first - 1),
                (0,) * first + (1,) * (gallery_size - first),
                (0,) * first
                + (1,)
                + tuple((index - first) % 2 for index in range(first + 1, gallery_size)),
            )
            for candidates in prefixes:
                evaluate(candidates)
                representative_vectors += 1

    # Exhaust every selector state and prefix flag independently. Reachable prefix=1 states must
    # be suppressed; prefix=0 exposes the first local position as a one-based global identity.
    selector_states = 0
    for gallery_size in range(1, MAX_GALLERY_SIZE + 1):
        groups = ceil_div(gallery_size, SCAN_GROUP_SIZE)
        for group in range(groups):
            group_len = min(SCAN_GROUP_SIZE, gallery_size - group * SCAN_GROUP_SIZE)
            for state in range(group_len + 1):
                for prefix in (0, 1):
                    code = SCAN_GROUP_SIZE * group + state if state and not prefix else 0
                    assert (code & 0xF) + 16 * (code >> 4) == code
                    assert 0 <= (code & 0xF) <= 15
                    assert 0 <= (code >> 4) <= 8
                    selector_states += 1

    current = a41_counts(127)
    prudent = prudent_raw_l1_counts(127)
    assert current == Counts(3_655, 3_274, 4_206)
    assert prudent == Counts(3_909, 3_528, 4_460)
    wire = wire_projection()
    assert wire["single_lwe_bytes"] == 16_464
    assert wire["two_lwe_bytes"] == 32_856
    assert wire["additional_bytes"] == 16_392
    return {
        "status": "PASS",
        "scope": "clear_and_structural_only_no_fhe_no_pfail_claim",
        "exhaustive_binary_vectors_n_le_16": exhaustive_vectors,
        "representative_vectors_n_le_128": representative_vectors,
        "selector_states": selector_states,
        "a41_terminal_only_n127": asdict(current),
        "prudent_raw_l1_n127": asdict(prudent),
        "prudent_delta_n127": {
            key: getattr(prudent, key) - getattr(current, key)
            for key in asdict(current)
        },
        "wire": wire,
        "root_delta_log": BOOL_DELTA_LOG,
        "client_reconstruction": "low + 16 * high",
        "upstream_pfail_obligations_open": [
            "score_and_initial_extraction",
            "correlated_raw_extraction_paths",
            "A34_top_classifier",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args()
    summary = validate()
    if arguments.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(
            "PASS,A41_clear_and_count_model,"
            f"vectors={summary['exhaustive_binary_vectors_n_le_16'] + summary['representative_vectors_n_le_128']},"
            "N127=3655/3274/4206,prudent_N127=3909/3528/4460,"
            "wire=32856B,linear_postprocessing=false,end_to_end_pfail=false"
        )


if __name__ == "__main__":
    main()
