#!/usr/bin/env python3
"""Static selector-layout audit for the A109 p=8191 BGV candidate.

This module is cleartext-only.  It proves lane counts and exact 0/ID semantics
for two ways of consuming one SIMD strict-comparison result.  It does not
instantiate HElib, generate keys, execute FHE, or predict runtime.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from math import ceil, log2, prod
from typing import Sequence


GALLERY_SIZE = 127
SCORE_MIN = 0
SCORE_MAX = 4095
PLAINTEXT_PRIME = 8191
SIMD_SLOTS = 16384
BLOCK_WIDTH = 128
INFERRED_LT_DEPTH = 16
BSGS_BABY_SIZE = 12


@dataclass(frozen=True)
class StaticLedger:
    gallery_size: int
    plaintext_prime: int
    simd_slots: int
    block_width: int
    unordered_pairs: int
    inferred_lt_depth: int
    d_pair_lanes: int
    d_threshold_lanes: int
    d_public_pad_lanes: int
    d_factor_lanes: int
    d_unused_lanes: int
    d_selector_levels: int
    d_inferred_depth_after_scores: int
    h_pair_lanes: int
    h_threshold_lanes: int
    h_comparison_active_lanes: int
    h_zero_roots: int
    h_public_pad_lanes: int
    h_selector_levels: int
    h_inferred_depth_after_scores: int
    h_fermat_equality_depth: int
    h_fermat_inferred_depth_after_scores: int
    candidate_input_score_fanout_rotations: int
    candidate_d_post_lt_rotations: int
    candidate_h_post_lt_rotations: int
    candidate_d_total_rotations: int
    candidate_h_total_rotations: int
    selector_ciphertext_multiplications: int


def next_power_of_two(value: int) -> int:
    if value < 1:
        raise ValueError("value must be positive")
    return 1 << (value - 1).bit_length()


def _validate(scores: Sequence[int], thresholds: Sequence[int]) -> None:
    if not scores or len(scores) != len(thresholds):
        raise ValueError("scores and thresholds must be non-empty and aligned")
    if any(score < SCORE_MIN or score > SCORE_MAX for score in scores):
        raise ValueError(f"scores must lie in [{SCORE_MIN}, {SCORE_MAX}]")
    if len(scores) >= PLAINTEXT_PRIME:
        raise ValueError("loss counts must not wrap modulo the plaintext prime")


def reject_bit(score: int, threshold: int) -> int:
    """Strict reject bit for inclusive acceptance score <= threshold."""

    if threshold < SCORE_MIN:
        return 1
    if threshold >= SCORE_MAX:
        return 0
    return int(threshold < score)


def pair_bit(scores: Sequence[int], earlier: int, later: int) -> int:
    """Return c_ij=[s_j<s_i] for i<j.

    This bit says that the later index wins strictly.  Its complement says the
    earlier index wins, including ties.
    """

    if not 0 <= earlier < later < len(scores):
        raise ValueError("pair_bit requires 0 <= earlier < later < N")
    return int(scores[later] < scores[earlier])


def reference_output_code(scores: Sequence[int], thresholds: Sequence[int]) -> int:
    _validate(scores, thresholds)
    winner = min(range(len(scores)), key=lambda index: (scores[index], index))
    return winner + 1 if scores[winner] <= thresholds[winner] else 0


def d_comparison_blocks(
    scores: Sequence[int], thresholds: Sequence[int]
) -> tuple[tuple[int, ...], ...]:
    """Candidate-major duplicated comparison outputs.

    Cell (i,j), i!=j, holds the same c_min(i,j),max(i,j) in both mirrored
    positions.  The diagonal holds the strict reject bit.  The final cell is
    a public padding zero at this stage and is not an active LT lane.
    """

    _validate(scores, thresholds)
    n = len(scores)
    width = next_power_of_two(n)
    blocks: list[tuple[int, ...]] = []
    for candidate in range(n):
        row: list[int] = []
        for opponent in range(n):
            if candidate == opponent:
                row.append(reject_bit(scores[candidate], thresholds[candidate]))
            else:
                earlier, later = sorted((candidate, opponent))
                row.append(pair_bit(scores, earlier, later))
        row.extend([0] * (width - n))
        blocks.append(tuple(row))
    return tuple(blocks)


def d_factor_blocks(
    scores: Sequence[int], thresholds: Sequence[int]
) -> tuple[tuple[int, ...], ...]:
    """Convert duplicated LT outputs directly to candidate-win factors."""

    compared = d_comparison_blocks(scores, thresholds)
    n = len(scores)
    width = next_power_of_two(n)
    blocks: list[tuple[int, ...]] = []
    for candidate, row in enumerate(compared):
        factors: list[int] = []
        for opponent in range(n):
            bit = row[opponent]
            if candidate == opponent:
                factors.append(1 - bit)
            elif candidate < opponent:
                factors.append(1 - bit)
            else:
                factors.append(bit)
        factors.extend([1] * (width - n))
        blocks.append(tuple(factors))
    return tuple(blocks)


def d_selector_bits(
    scores: Sequence[int], thresholds: Sequence[int]
) -> tuple[int, ...]:
    return tuple(prod(block) for block in d_factor_blocks(scores, thresholds))


def d_output_code(scores: Sequence[int], thresholds: Sequence[int]) -> int:
    return sum(
        (index + 1) * bit
        for index, bit in enumerate(d_selector_bits(scores, thresholds))
    )


def h_sparse_upper_blocks(
    scores: Sequence[int], thresholds: Sequence[int]
) -> tuple[tuple[int, ...], ...]:
    """One-copy comparison layout: upper triangle plus reject diagonal."""

    _validate(scores, thresholds)
    n = len(scores)
    width = next_power_of_two(n)
    blocks: list[tuple[int, ...]] = []
    for row_index in range(n):
        row: list[int] = []
        for column in range(n):
            if row_index < column:
                row.append(pair_bit(scores, row_index, column))
            elif row_index == column:
                row.append(reject_bit(scores[row_index], thresholds[row_index]))
            else:
                row.append(0)
        row.extend([0] * (width - n))
        blocks.append(tuple(row))
    return tuple(blocks)


def h_loss_blocks(
    scores: Sequence[int], thresholds: Sequence[int]
) -> tuple[tuple[int, ...], ...]:
    """Expand one pair bit into the loss of exactly one endpoint.

    For i<j, c_ij is candidate i's loss and 1-c_ij is candidate j's loss.
    The diagonal contributes the reject bit.  Thus the row sum is zero iff
    that row is the stable first argmin and its threshold accepts.
    """

    sparse = h_sparse_upper_blocks(scores, thresholds)
    n = len(scores)
    width = next_power_of_two(n)
    blocks: list[tuple[int, ...]] = []
    for candidate in range(n):
        row: list[int] = []
        for opponent in range(n):
            if candidate < opponent:
                row.append(sparse[candidate][opponent])
            elif candidate > opponent:
                row.append(1 - sparse[opponent][candidate])
            else:
                row.append(sparse[candidate][candidate])
        row.extend([0] * (width - n))
        blocks.append(tuple(row))
    return tuple(blocks)


def h_loss_counts(scores: Sequence[int], thresholds: Sequence[int]) -> tuple[int, ...]:
    return tuple(sum(block) for block in h_loss_blocks(scores, thresholds))


def bounded_zero_factors(value: int, maximum: int, prime: int) -> tuple[int, ...]:
    """Factors of the exact delta-at-zero polynomial on [0, maximum]."""

    if not 0 <= value <= maximum:
        raise ValueError("value is outside the zero-indicator promise")
    if maximum >= prime:
        raise ValueError("roots would collide modulo the plaintext prime")
    return tuple(
        (1 - value * pow(root, -1, prime)) % prime for root in range(1, maximum + 1)
    )


def bounded_zero_indicator(value: int, maximum: int, prime: int) -> int:
    return prod(bounded_zero_factors(value, maximum, prime)) % prime


def h_zero_factor_blocks(
    scores: Sequence[int], thresholds: Sequence[int]
) -> tuple[tuple[int, ...], ...]:
    """Materialize N root factors and pad them to one power-of-two block."""

    n = len(scores)
    width = next_power_of_two(n + 1)
    blocks: list[tuple[int, ...]] = []
    for count in h_loss_counts(scores, thresholds):
        factors = list(bounded_zero_factors(count, n, PLAINTEXT_PRIME))
        factors.extend([1] * (width - len(factors)))
        blocks.append(tuple(factors))
    return tuple(blocks)


def h_selector_bits(
    scores: Sequence[int], thresholds: Sequence[int]
) -> tuple[int, ...]:
    return tuple(
        prod(block) % PLAINTEXT_PRIME
        for block in h_zero_factor_blocks(scores, thresholds)
    )


def h_output_code(scores: Sequence[int], thresholds: Sequence[int]) -> int:
    return sum(
        (index + 1) * bit
        for index, bit in enumerate(h_selector_bits(scores, thresholds))
    )


def stable_loss_ranks(scores: Sequence[int]) -> tuple[int, ...]:
    """Clear reference ranks under the total order (score, original index)."""

    return tuple(
        sum(
            (scores[other], other) < (scores[index], index)
            for other in range(len(scores))
        )
        for index in range(len(scores))
    )


def bsgs_rotation_support(
    maximum_index: int, *, scale: int, baby_size: int = BSGS_BABY_SIZE
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Non-identity baby/giant shifts for arithmetic-progression diagonals.

    This only inventories a standard diagonal-method/BSGS candidate.  It is
    not an HElib automorphism schedule, a lower bound, or a timing model.
    """

    if maximum_index < 0 or scale < 1 or baby_size < 1:
        raise ValueError("invalid BSGS support parameters")
    babies = {scale * (index % baby_size) for index in range(maximum_index + 1)}
    giants = {
        scale * baby_size * (index // baby_size) for index in range(maximum_index + 1)
    }
    babies.discard(0)
    giants.discard(0)
    return tuple(sorted(babies)), tuple(sorted(giants))


def build_ledger() -> StaticLedger:
    n = GALLERY_SIZE
    width = next_power_of_two(n)
    if width != BLOCK_WIDTH:
        raise AssertionError("N=127 must use 128-cell candidate blocks")
    if n * width > SIMD_SLOTS:
        raise AssertionError("candidate-major layout no longer fits one ciphertext")

    pairs = n * (n - 1) // 2
    selector_levels = int(log2(width))
    scatter_babies, scatter_giants = bsgs_rotation_support(n - 1, scale=width - 1)
    scatter_rotations = len(scatter_babies) + len(scatter_giants)
    if scatter_rotations != 21:
        raise AssertionError("candidate BSGS scatter ledger drift")

    row_or_column_broadcast = selector_levels
    input_fanout = scatter_rotations + 2 * row_or_column_broadcast
    d_post_lt = selector_levels + selector_levels

    transpose_babies, transpose_giants = bsgs_rotation_support(n - 1, scale=width - 1)
    transpose_rotations = len(transpose_babies) + len(transpose_giants)
    h_post_lt = (
        transpose_rotations
        + selector_levels  # row Hamming-weight reduction
        + selector_levels  # count fanout to 128 root-factor cells
        + selector_levels  # bounded-root product tree
        + selector_levels  # ID slot sum
    )

    h_active = pairs + n
    d_factor_lanes = n * width
    if 2 * pairs + n + n != d_factor_lanes:
        raise AssertionError("duplicated layout partition drift")
    if h_active != 8128 or d_factor_lanes != 16256:
        raise AssertionError("frozen N=127 capacity arithmetic drift")

    fermat_depth = ceil(log2(PLAINTEXT_PRIME - 1))
    return StaticLedger(
        gallery_size=n,
        plaintext_prime=PLAINTEXT_PRIME,
        simd_slots=SIMD_SLOTS,
        block_width=width,
        unordered_pairs=pairs,
        inferred_lt_depth=INFERRED_LT_DEPTH,
        d_pair_lanes=2 * pairs,
        d_threshold_lanes=n,
        d_public_pad_lanes=n,
        d_factor_lanes=d_factor_lanes,
        d_unused_lanes=SIMD_SLOTS - d_factor_lanes,
        d_selector_levels=selector_levels,
        d_inferred_depth_after_scores=INFERRED_LT_DEPTH + selector_levels,
        h_pair_lanes=pairs,
        h_threshold_lanes=n,
        h_comparison_active_lanes=h_active,
        h_zero_roots=n,
        h_public_pad_lanes=n,
        h_selector_levels=selector_levels,
        h_inferred_depth_after_scores=INFERRED_LT_DEPTH + selector_levels,
        h_fermat_equality_depth=fermat_depth,
        h_fermat_inferred_depth_after_scores=INFERRED_LT_DEPTH + fermat_depth,
        candidate_input_score_fanout_rotations=input_fanout,
        candidate_d_post_lt_rotations=d_post_lt,
        candidate_h_post_lt_rotations=h_post_lt,
        candidate_d_total_rotations=input_fanout + d_post_lt,
        candidate_h_total_rotations=input_fanout + h_post_lt,
        selector_ciphertext_multiplications=selector_levels,
    )


def result_document() -> dict[str, object]:
    ledger = build_ledger()
    scores = [4095] * GALLERY_SIZE
    scores[93] = 17
    scores[94] = 17
    thresholds = [1023] * GALLERY_SIZE
    smoke = {
        "reference": reference_output_code(scores, thresholds),
        "duplicated_candidate_major": d_output_code(scores, thresholds),
        "one_copy_loss_count": h_output_code(scores, thresholds),
    }
    if len(set(smoke.values())) != 1:
        raise AssertionError("frozen smoke outputs diverged")

    return {
        "status": "PASS_STATIC_D_BENCHMARK_WORTHY_H_SINGLE_QUERY_DOMINATED_UNDER_FIXED_CONTEXT",
        "scope": {
            "fhe_executed": False,
            "helib_built": False,
            "keys_generated": False,
            "timing_measured": False,
            "runtime_speedup_claimed": False,
        },
        "ledger": asdict(ledger),
        "semantics": {
            "output": "0 reject or exact stable-first index+1",
            "threshold": "inclusive score<=threshold",
            "winner_threshold_only": True,
            "smoke": smoke,
        },
        "decision": {
            "D": "BENCHMARK_WORTHY_NOT_PROMOTED",
            "H_fixed_context_single_query": "NEGATIVE_DOMINATED_BY_D_AT_STATIC_CIPHERTEXT_OPERATION_BOUNDARY",
            "H_compaction_or_throughput": "RETAINED_UNMEASURED_LEAD",
            "reason": (
                "Both fit one fixed 16384-slot ciphertext and invoke the same SIMD LT once. "
                "D spends spare lanes to duplicate pair bits and avoids H's post-LT "
                "transpose, loss reduction, and count fanout. H's 8128 active lanes can "
                "matter only if a real compaction/batching schedule turns occupancy into "
                "end-to-end savings."
            ),
        },
        "rotation_ledger_warning": (
            "The 49-vs-84 totals are one explicit diagonal/BSGS candidate schedule from "
            "a packed 127-score input, not lower bounds, HElib measurements, or speedups."
        ),
    }


def main() -> None:
    print(json.dumps(result_document(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
