#!/usr/bin/env python3
"""Static A109 exact-ID mapping for a BGV comparison circuit.

This module is deliberately cleartext-only.  It proves the lane schedule and
the protocol semantics; it does not instantiate HElib, choose a ciphertext
modulus, estimate RLWE security, generate keys, or report FHE timings.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from math import ceil, floor, gcd, log2, prod, sqrt
from typing import Sequence


GALLERY_SIZE = 127
SCORE_BITS = 12
SCORE_MIN = 0
SCORE_MAX = (1 << SCORE_BITS) - 1
ALIGNED_THRESHOLD = 1023

# Representation-coherent, but not parameterized for noise/security/runtime.
PLAINTEXT_PRIME = 8191
CYCLOTOMIC_ORDER = 81920
DIGIT_SUBSPACE_DEGREE = 1
DIGIT_VECTOR_LENGTH = 1


@dataclass(frozen=True)
class ComparisonLane:
    """One pair-comparison or threshold-decision lane.

    For a pair lane, the comparator evaluates score[later] < score[earlier].
    For a threshold lane, it evaluates threshold[index] < score[index], i.e.
    the encrypted reject bit for an inclusive in-domain threshold.  A threshold
    below/above the score domain is resolved to a public one/zero instead.
    """

    kind: str
    earlier: int | None = None
    later: int | None = None
    index: int | None = None


@dataclass(frozen=True)
class StaticLedger:
    gallery_size: int
    score_bits: int
    score_min: int
    score_max: int
    plaintext_prime: int
    cyclotomic_order: int
    ring_degree: int
    plaintext_order_mod_m: int
    simd_slots: int
    univariate_exact_max: int
    unordered_pair_lanes: int
    threshold_lanes: int
    comparison_lanes: int
    comparison_ciphertexts_at_candidate_capacity: int
    semantic_factors_per_candidate: int
    padded_factors_per_candidate: int
    factor_lanes: int
    factor_ciphertexts_at_candidate_capacity: int
    selector_product_levels: int
    inferred_lt_depth_from_paper_formula: int
    inferred_selector_depth_after_scores: int
    inferred_univariate_non_scalar_multiplications: int


def is_prime(value: int) -> bool:
    if value < 2:
        return False
    if value % 2 == 0:
        return value == 2
    divisor = 3
    while divisor * divisor <= value:
        if value % divisor == 0:
            return False
        divisor += 2
    return True


def euler_phi(value: int) -> int:
    if value < 1:
        raise ValueError("Euler phi requires a positive integer")
    result = value
    remaining = value
    factor = 2
    while factor * factor <= remaining:
        if remaining % factor == 0:
            while remaining % factor == 0:
                remaining //= factor
            result -= result // factor
        factor += 1
    if remaining > 1:
        result -= result // remaining
    return result


def multiplicative_order(base: int, modulus: int) -> int:
    if gcd(base, modulus) != 1:
        raise ValueError("base and modulus must be coprime")
    candidate = 1
    residue = base % modulus
    while residue != 1:
        residue = (residue * base) % modulus
        candidate += 1
        if candidate > euler_phi(modulus):
            raise AssertionError("multiplicative order search exceeded phi(modulus)")
    return candidate


def next_power_of_two(value: int) -> int:
    if value < 1:
        raise ValueError("value must be positive")
    return 1 << (value - 1).bit_length()


def comparison_lanes(gallery_size: int = GALLERY_SIZE) -> tuple[ComparisonLane, ...]:
    """Return the frozen N=127 cyclic-diagonal comparison layout.

    For odd N, offsets 1..floor(N/2) enumerate every unordered pair exactly
    once.  Endpoints are re-oriented by original index so equality always
    favours the earlier gallery entry.  The final N lanes compare each public
    threshold with its encrypted score and therefore produce reject bits.
    """

    if gallery_size < 1 or gallery_size % 2 == 0:
        raise ValueError("this frozen cyclic layout requires positive odd N")

    lanes: list[ComparisonLane] = []
    for offset in range(1, gallery_size // 2 + 1):
        for start in range(gallery_size):
            other = (start + offset) % gallery_size
            earlier, later = sorted((start, other))
            lanes.append(ComparisonLane("pair", earlier=earlier, later=later))

    lanes.extend(ComparisonLane("threshold", index=index) for index in range(gallery_size))
    return tuple(lanes)


def pair_lane_index(gallery_size: int = GALLERY_SIZE) -> dict[tuple[int, int], int]:
    result: dict[tuple[int, int], int] = {}
    for lane_index, lane in enumerate(comparison_lanes(gallery_size)):
        if lane.kind != "pair":
            continue
        assert lane.earlier is not None and lane.later is not None
        key = (lane.earlier, lane.later)
        if key in result:
            raise AssertionError(f"duplicate unordered pair {key}")
        result[key] = lane_index
    return result


def evaluate_comparison_lanes(
    scores: Sequence[int], thresholds: Sequence[int]
) -> tuple[int, ...]:
    if len(scores) != len(thresholds):
        raise ValueError("scores and thresholds must have the same length")
    _validate_scores(scores)

    values: list[int] = []
    for lane in comparison_lanes(len(scores)):
        if lane.kind == "pair":
            assert lane.earlier is not None and lane.later is not None
            values.append(int(scores[lane.later] < scores[lane.earlier]))
        elif lane.kind == "threshold":
            assert lane.index is not None
            threshold = thresholds[lane.index]
            if threshold < SCORE_MIN:
                values.append(1)
            elif threshold >= SCORE_MAX:
                values.append(0)
            else:
                values.append(int(threshold < scores[lane.index]))
        else:
            raise AssertionError(f"unknown lane kind {lane.kind}")
    return tuple(values)


def candidate_factor_blocks(
    scores: Sequence[int], thresholds: Sequence[int]
) -> tuple[tuple[int, ...], ...]:
    """Materialize 128 factors per candidate for the one-hot stable argmin.

    Each block contains 126 pair factors, one inclusive-accept factor, and one
    public padding one.  Thus all 127 products use an identical seven-level
    balanced multiplication tree.
    """

    lane_values = evaluate_comparison_lanes(scores, thresholds)
    n = len(scores)
    lookup = pair_lane_index(n)
    pair_lane_count = n * (n - 1) // 2
    padded_size = next_power_of_two(n)
    blocks: list[tuple[int, ...]] = []

    for candidate in range(n):
        factors: list[int] = []
        for opponent in range(n):
            if opponent == candidate:
                continue
            earlier, later = sorted((candidate, opponent))
            strict_later_wins = lane_values[lookup[(earlier, later)]]
            factors.append(
                1 - strict_later_wins if candidate == earlier else strict_later_wins
            )

        reject = lane_values[pair_lane_count + candidate]
        factors.append(1 - reject)
        factors.extend([1] * (padded_size - len(factors)))
        if len(factors) != padded_size:
            raise AssertionError("candidate factor block has the wrong size")
        blocks.append(tuple(factors))

    return tuple(blocks)


def stable_selector_bits(
    scores: Sequence[int], thresholds: Sequence[int]
) -> tuple[int, ...]:
    return tuple(prod(block) for block in candidate_factor_blocks(scores, thresholds))


def exact_output_code(scores: Sequence[int], thresholds: Sequence[int]) -> int:
    """Return 0 reject or the exact first-argmin index plus one."""

    selectors = stable_selector_bits(scores, thresholds)
    return sum((index + 1) * selected for index, selected in enumerate(selectors))


def reference_output_code(scores: Sequence[int], thresholds: Sequence[int]) -> int:
    if not scores or len(scores) != len(thresholds):
        raise ValueError("scores and thresholds must be non-empty and aligned")
    _validate_scores(scores)
    winner = min(range(len(scores)), key=lambda index: (scores[index], index))
    return winner + 1 if scores[winner] <= thresholds[winner] else 0


def _validate_scores(scores: Sequence[int]) -> None:
    if not scores:
        raise ValueError("scores must be non-empty")
    if len(scores) % 2 == 0:
        raise ValueError("the frozen cyclic layout requires odd N")
    if any(score < SCORE_MIN or score > SCORE_MAX for score in scores):
        raise ValueError(f"scores must lie in [{SCORE_MIN}, {SCORE_MAX}]")


def inferred_lt_depth(plaintext_prime: int, digit_degree: int, digit_count: int) -> int:
    """Normalize Eq. (8) to the explicit integer digit count l.

    The paper writes the final term through log_p(2^b)/d.  Since encoding uses
    l=ceil(log_p(2^b)/d) slots and l=1 here, the structurally meaningful term
    is floor(log2(l)) = 0.  This is an inference, not a measured HElib level.
    """

    if plaintext_prime < 3 or digit_degree < 1 or digit_count < 1:
        raise ValueError("invalid comparison parameters")
    return (
        floor(log2(digit_degree))
        + floor(log2(plaintext_prime - 1))
        + floor(log2(digit_count))
        + 4
    )


def inferred_univariate_multiplications(plaintext_prime: int) -> int:
    """Rounded paper asymptotic estimate for d=l=1, including its +2 term."""

    t_estimate = sqrt(2 * plaintext_prime - 4) + 1.5 * log2(2 * plaintext_prime - 4)
    return ceil(t_estimate + 2)


def build_ledger() -> StaticLedger:
    if not is_prime(PLAINTEXT_PRIME):
        raise AssertionError("p=8191 must be prime")
    ring_degree = euler_phi(CYCLOTOMIC_ORDER)
    order = multiplicative_order(PLAINTEXT_PRIME, CYCLOTOMIC_ORDER)
    if ring_degree != 32768:
        raise AssertionError(f"unexpected phi(m): {ring_degree}")
    if order != 2:
        raise AssertionError(f"unexpected ord_m(p): {order}")
    if ring_degree % order:
        raise AssertionError("slot count is not integral")
    slots = ring_degree // order
    if slots != 16384:
        raise AssertionError(f"unexpected slot count: {slots}")

    lanes = comparison_lanes()
    pair_count = GALLERY_SIZE * (GALLERY_SIZE - 1) // 2
    if len(pair_lane_index()) != pair_count:
        raise AssertionError("cyclic diagonals do not cover every pair exactly once")
    if len(lanes) != pair_count + GALLERY_SIZE:
        raise AssertionError("comparison lane count drift")

    padded_factors = next_power_of_two(GALLERY_SIZE)
    factor_lanes = GALLERY_SIZE * padded_factors
    if len(lanes) > slots or factor_lanes > slots:
        raise AssertionError("the one-ciphertext lane claim no longer holds")

    lt_depth = inferred_lt_depth(
        PLAINTEXT_PRIME, DIGIT_SUBSPACE_DEGREE, DIGIT_VECTOR_LENGTH
    )
    selector_levels = int(log2(padded_factors))
    return StaticLedger(
        gallery_size=GALLERY_SIZE,
        score_bits=SCORE_BITS,
        score_min=SCORE_MIN,
        score_max=SCORE_MAX,
        plaintext_prime=PLAINTEXT_PRIME,
        cyclotomic_order=CYCLOTOMIC_ORDER,
        ring_degree=ring_degree,
        plaintext_order_mod_m=order,
        simd_slots=slots,
        univariate_exact_max=(PLAINTEXT_PRIME - 1) // 2,
        unordered_pair_lanes=pair_count,
        threshold_lanes=GALLERY_SIZE,
        comparison_lanes=len(lanes),
        comparison_ciphertexts_at_candidate_capacity=ceil(len(lanes) / slots),
        semantic_factors_per_candidate=GALLERY_SIZE,
        padded_factors_per_candidate=padded_factors,
        factor_lanes=factor_lanes,
        factor_ciphertexts_at_candidate_capacity=ceil(factor_lanes / slots),
        selector_product_levels=selector_levels,
        inferred_lt_depth_from_paper_formula=lt_depth,
        inferred_selector_depth_after_scores=lt_depth + selector_levels,
        inferred_univariate_non_scalar_multiplications=inferred_univariate_multiplications(
            PLAINTEXT_PRIME
        ),
    )


def static_result() -> dict[str, object]:
    ledger = build_ledger()
    return {
        "artifact": "A109",
        "status": "STATIC_BENCHMARK_WORTHY_NOT_IMPLEMENTED",
        "ledger": asdict(ledger),
        "semantics": {
            "comparison": "strict LT",
            "tie_policy": "first gallery index wins",
            "threshold": "winner score <= winner threshold is accepted",
            "output": "single encrypted code: 0 reject, index+1 accept",
        },
        "gates": {
            "algebraic_mapping": "PASS",
            "bgv_parameters_q_noise_security": "UNKNOWN",
            "helib_runtime": "NOT_RUN",
            "boostcom_runtime_transfer": "FORBIDDEN",
            "boostcom_public_artifact": "NOT_FOUND_BY_BOUNDED_SEARCH",
            "comparison_circuit_source": "AVAILABLE_AT_PINNED_COMMIT",
        },
    }


if __name__ == "__main__":
    import json

    print(json.dumps(static_result(), indent=2, sort_keys=True))
