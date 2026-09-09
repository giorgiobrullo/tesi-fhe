#!/usr/bin/env python3
"""Deterministic support bound for A38's encrypted score convolution.

This audit stops before the first key switch or programmable bootstrap.  It
uses only constraints enforced by the exact-ID core and the finite support of
TFHE-rs ``TUniform(17)`` encryption noise.  Consequently, the reported zero
failure term applies to the initial GLWE encryption and clear-template score
convolution only; it says nothing about the later KS/PBS/FFT path.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass


TORUS_BITS = 64
TORUS_MODULUS = 1 << TORUS_BITS
POLYNOMIAL_SIZE = 2_048
PROBE_DIM = 512
PROBE_NORM2_MAX = 1_024
TEMPLATE_COORDINATE_MAX = 3
MAX_SCORE_DOMAIN_WIDTH = 4_096
GLWE_TUNIFORM_BOUND_LOG2 = 17
FULL_DELTA_LOG = 52
LOW_DELTA_LOG = 60
LOW_LANE_OFFSET = 1_024


@dataclass(frozen=True)
class L1Witness:
    count_abs_0: int
    count_abs_1: int
    count_abs_2: int
    count_abs_3: int
    norm2: int
    l1: int


@dataclass(frozen=True)
class LaneAudit:
    name: str
    offset: int
    extraction_degree: int
    error_source_start: int
    error_source_end_inclusive: int
    delta_log: int
    half_slot_margin_torus: int
    maximum_score_error_torus: int
    margin_over_error: float
    log2_margin_over_error: float
    support_cannot_cross_decode_boundary: bool


def ceil_sqrt(value: int) -> int:
    if value < 0:
        raise ValueError("value must be non-negative")
    root = math.isqrt(value)
    return root if root * root == value else root + 1


def single_template_domain_width(norm2: int) -> int:
    """Mirror the core's inclusive Cauchy domain width for one template."""
    if norm2 < 0:
        raise ValueError("norm2 must be non-negative")
    radius = 2 * ceil_sqrt(norm2 * PROBE_NORM2_MAX)
    return 2 * radius + 1


def maximum_admissible_template_norm2() -> int:
    """Largest norm squared whose individual Cauchy domain fits 4096 values."""
    low = 0
    high = PROBE_DIM * TEMPLATE_COORDINATE_MAX**2
    while low < high:
        middle = (low + high + 1) // 2
        if single_template_domain_width(middle) <= MAX_SCORE_DOMAIN_WIDTH:
            low = middle
        else:
            high = middle - 1
    return low


def maximum_l1_witness(norm2_budget: int) -> L1Witness:
    """Solve the finite integer problem for 512 coordinates in {0,1,2,3}."""
    if norm2_budget < 0:
        raise ValueError("norm2_budget must be non-negative")
    best: L1Witness | None = None
    for count_abs_3 in range(min(PROBE_DIM, norm2_budget // 9) + 1):
        remaining_after_3 = norm2_budget - 9 * count_abs_3
        maximum_twos = min(PROBE_DIM - count_abs_3, remaining_after_3 // 4)
        for count_abs_2 in range(maximum_twos + 1):
            remaining = remaining_after_3 - 4 * count_abs_2
            count_abs_1 = min(
                PROBE_DIM - count_abs_3 - count_abs_2,
                remaining,
            )
            witness = L1Witness(
                count_abs_0=(PROBE_DIM - count_abs_1 - count_abs_2 - count_abs_3),
                count_abs_1=count_abs_1,
                count_abs_2=count_abs_2,
                count_abs_3=count_abs_3,
                norm2=(count_abs_1 + 4 * count_abs_2 + 9 * count_abs_3),
                l1=count_abs_1 + 2 * count_abs_2 + 3 * count_abs_3,
            )
            if best is None or (witness.l1, witness.norm2) > (
                best.l1,
                best.norm2,
            ):
                best = witness
    if best is None:  # pragma: no cover - zero is always a feasible witness
        raise AssertionError("no feasible template")
    return best


def lane_audit(name: str, offset: int, delta_log: int, error_bound: int) -> LaneAudit:
    extraction_degree = offset + PROBE_DIM - 1
    source_start = extraction_degree - (PROBE_DIM - 1)
    source_end = extraction_degree
    half_margin = 1 << (delta_log - 1)
    return LaneAudit(
        name=name,
        offset=offset,
        extraction_degree=extraction_degree,
        error_source_start=source_start,
        error_source_end_inclusive=source_end,
        delta_log=delta_log,
        half_slot_margin_torus=half_margin,
        maximum_score_error_torus=error_bound,
        margin_over_error=half_margin / error_bound,
        log2_margin_over_error=math.log2(half_margin / error_bound),
        support_cannot_cross_decode_boundary=error_bound < half_margin,
    )


def report() -> dict[str, object]:
    norm2_limit = maximum_admissible_template_norm2()
    witness = maximum_l1_witness(norm2_limit)
    tuniform_support = 1 << GLWE_TUNIFORM_BOUND_LOG2
    # Score polynomial coefficients are -2*g_i, hence the factor two.
    score_error = 2 * witness.l1 * tuniform_support
    full = lane_audit("full_score", 0, FULL_DELTA_LOG, score_error)
    low = lane_audit("score_mod_16", LOW_LANE_OFFSET, LOW_DELTA_LOG, score_error)
    source_sets_disjoint = (
        full.error_source_end_inclusive < low.error_source_start
        or low.error_source_end_inclusive < full.error_source_start
    )
    return {
        "status": "deterministic_initial_score_support_only",
        "enforced_contract": {
            "probe_dim": PROBE_DIM,
            "coordinate_abs_max": TEMPLATE_COORDINATE_MAX,
            "probe_norm2_max": PROBE_NORM2_MAX,
            "maximum_score_domain_width": MAX_SCORE_DOMAIN_WIDTH,
            "maximum_template_norm2_implied_by_domain": norm2_limit,
            "first_rejected_norm2": norm2_limit + 1,
            "width_at_maximum_norm2": single_template_domain_width(norm2_limit),
            "width_at_first_rejected_norm2": single_template_domain_width(
                norm2_limit + 1
            ),
        },
        "exact_maximum_template_l1": asdict(witness),
        "tuniform": {
            "bound_log2": GLWE_TUNIFORM_BOUND_LOG2,
            "integer_support_min": -tuniform_support,
            "integer_support_max": tuniform_support,
        },
        "score_error": {
            "formula": "2 * ||g||_1 * 2^17",
            "maximum_absolute_torus_integer": score_error,
            "maximum_absolute_normalized": score_error / TORUS_MODULUS,
            "after_largest_full_extractor_shift_2_pow_11_normalized": (
                score_error * (1 << 11) / TORUS_MODULUS
            ),
        },
        "lanes": [asdict(full), asdict(low)],
        "lane_error_source_sets_disjoint": source_sets_disjoint,
        "initial_score_decode_failure_probability_upper": 0.0,
        "scope": (
            "The zero term follows from bounded encryption-noise support for a valid "
            "honestly generated GLWE and the enforced gallery constraints. It ends "
            "before every key switch, programmable bootstrap, modulus switch, and "
            "FFT operation; it also does not prove that a malicious client supplied a "
            "well-formed encryption or that the two plaintext lanes are consistent."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    print(json.dumps(report(), indent=None if args.compact else 2, sort_keys=True))


if __name__ == "__main__":
    main()
