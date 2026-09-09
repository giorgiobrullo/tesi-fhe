#!/usr/bin/env python3
"""Static A49 model: exact high digit and deterministic BCS chunk order.

This module does not compile or execute TFHE.  It models the native-u64
modulus switch, the standard p16 accumulator geometry, public chunk-order
repair, exact first-tie semantics, and source-level operation ledgers.
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
from dataclasses import asdict, dataclass
from typing import Sequence

try:
    from benchmark.a46_blind_top1_delta import (
        GALLERY_SIZE,
        OperationCounts as A46OperationCounts,
        hybrid_selection_audit,
        source_bcs_call_counts,
        source_tournament_rounds,
    )
except ModuleNotFoundError:  # Direct ``python3 benchmark/...py`` execution.
    from a46_blind_top1_delta import (  # type: ignore[no-redef]
        GALLERY_SIZE,
        OperationCounts as A46OperationCounts,
        hybrid_selection_audit,
        source_bcs_call_counts,
        source_tournament_rounds,
    )


TORUS_BITS = 64
TORUS_MODULUS = 1 << TORUS_BITS
TORUS_MASK = TORUS_MODULUS - 1
POLYNOMIAL_SIZE = 2_048
BLIND_ROTATION_MODULUS = 2 * POLYNOMIAL_SIZE
BLIND_ROTATION_LOG = BLIND_ROTATION_MODULUS.bit_length() - 1
P16 = 16
P16_DELTA_LOG = 59
CANONICAL_SCORE_DELTA_LOG = 51
CANONICAL_SCORE_OFFSET = -(257 * (1 << 50))
SCORE_DOMAIN = 1 << 12
RADIX = 16
CURRENT_MAX_NOISE = 5
A44_MAX_NOISE = 15
CURRENT_INITIAL_SCORE_ERROR_BOUND = 178_782_208
HIGH_LANE_OPEN_MARGIN = 1 << 50


@dataclass(frozen=True)
class PrimitiveCounts:
    blind_rotations: int = 0
    classical_key_switches: int = 0
    output_marginals: int = 0

    def scale(self, factor: int) -> "PrimitiveCounts":
        return PrimitiveCounts(
            self.blind_rotations * factor,
            self.classical_key_switches * factor,
            self.output_marginals * factor,
        )


@dataclass(frozen=True)
class HighDigitTrace:
    score: int
    expected_high: int
    ideal_phase: int
    public_offset: int
    perturbed_phase: int
    switched_rotation: int
    output_code: int
    output_torus: int


@dataclass(frozen=True)
class DigitConstructorTrace:
    score: int
    low: int
    mid: int
    high: int
    folded_low: int
    folded_mid: int
    fresh_high: int
    low_to_mid_correction: int
    mid_residual: int


@dataclass(frozen=True)
class TaggedRow:
    score: int
    label: int
    original_position: int


def _u64(value: int) -> int:
    return value & TORUS_MASK


def native_pbs_modulus_switch(phase: int) -> int:
    """Mirror tfhe-rs 0.11.3 native ``pbs_modulus_switch`` for N=2048."""
    rounding = 1 << (TORUS_BITS - BLIND_ROTATION_LOG - 1)
    return _u64(_u64(phase) + rounding) >> (TORUS_BITS - BLIND_ROTATION_LOG)


def standard_p16_identity_accumulator_codes() -> tuple[int, ...]:
    """Mirror ``generate_programmable_bootstrap_glwe_lut(..., 16, f=id)``.

    Values are unscaled signed output codes.  Scaling by ``2^59`` is applied
    only after the negacyclic lookup.
    """
    box_size = POLYNOMIAL_SIZE // P16
    body = [digit for digit in range(P16) for _ in range(box_size)]
    half_box = box_size // 2
    body[:half_box] = [-value for value in body[:half_box]]
    body = body[half_box:] + body[:half_box]
    return tuple(body)


P16_IDENTITY_ACCUMULATOR = standard_p16_identity_accumulator_codes()


def negacyclic_accumulator_code(rotation: int) -> int:
    """Return the degree-zero code after division by X^rotation."""
    rotation %= BLIND_ROTATION_MODULUS
    if rotation < POLYNOMIAL_SIZE:
        return P16_IDENTITY_ACCUMULATOR[rotation]
    return -P16_IDENTITY_ACCUMULATOR[rotation - POLYNOMIAL_SIZE]


def high_digit_trace(score: int, *, torus_error: int = 0) -> HighDigitTrace:
    """Evaluate the proposed fourth-lane high-digit PBS at one clear center.

    The extra isolated lane contains ``score * 2^51``.  Before the PBS the
    server adds ``-257 * 2^50``.  Native modulus switching then maps every
    residue block ``score=256*h+r`` to rotations ``128*h-64 .. 128*h+63``,
    exactly the box of the standard p16 identity accumulator for ``h``.
    """
    if not 0 <= score < SCORE_DOMAIN:
        raise ValueError("score must be in 0..4095")
    ideal_phase = _u64(score << CANONICAL_SCORE_DELTA_LOG)
    phase = _u64(ideal_phase + CANONICAL_SCORE_OFFSET + torus_error)
    rotation = native_pbs_modulus_switch(phase)
    output_code = negacyclic_accumulator_code(rotation) % (2 * P16)
    return HighDigitTrace(
        score=score,
        expected_high=score >> 8,
        ideal_phase=ideal_phase,
        public_offset=_u64(CANONICAL_SCORE_OFFSET),
        perturbed_phase=phase,
        switched_rotation=rotation,
        output_code=output_code,
        output_torus=_u64(output_code << P16_DELTA_LOG),
    )


def exhaustive_high_digit(*, torus_error: int = 0) -> bool:
    return all(
        high_digit_trace(score, torus_error=torus_error).output_code == score >> 8
        for score in range(SCORE_DOMAIN)
    )


def existing_delta60_one_sample_pair_sums() -> tuple[int, ...]:
    """Pair sums required by a direct numeric h: Delta60 -> Delta59 PBS.

    One PBS sample, with any public output offset A, has a constant
    ``Y(h+8)+Y(h)=2A``.  The desired numeric output does not.
    """
    return tuple(
        _u64((h << P16_DELTA_LOG) + ((h + 8) << P16_DELTA_LOG))
        for h in range(8)
    )


def fallback_fold_then_inverse(h: int) -> tuple[int, int, int]:
    """Clear torus semantics of the two-PBS fallback from A45's old residual."""
    if not 0 <= h < 16:
        raise ValueError("h must be in 0..15")
    top_bit = h >> 3
    correction = _u64(15 * top_bit * (1 << P16_DELTA_LOG))
    folded_torus = _u64((h << 60) - correction)
    folded = folded_torus >> P16_DELTA_LOG
    numeric = (folded >> 1) + 8 * (folded & 1)
    return folded, numeric, _u64(numeric << P16_DELTA_LOG)


def fold_full_circle_nibble(nibble: int) -> tuple[int, int]:
    """Fold ``nibble*2^60`` to a standard-p16 code with one correction PBS."""
    if not 0 <= nibble < 16:
        raise ValueError("nibble must be in 0..15")
    top_bit = nibble >> 3
    correction = _u64(15 * top_bit * (1 << P16_DELTA_LOG))
    folded_torus = _u64((nibble << 60) - correction)
    return folded_torus >> P16_DELTA_LOG, correction


def pruned_digit_constructor_trace(score: int) -> DigitConstructorTrace:
    """BCS-only A45/A49 center semantics without A36's individual bit extraction.

    Three score views share one N=2048 GLWE: low modulo 16 at Delta60,
    mid modulo 256 at Delta56, and the canonical full score at Delta51.  The
    low folded state feeds one correction PBS to remove low from the mid lane;
    the high digit is obtained independently by :func:`high_digit_trace`.
    """
    if not 0 <= score < SCORE_DOMAIN:
        raise ValueError("score must be in 0..4095")
    low = score & 0xF
    mid = (score >> 4) & 0xF
    high = score >> 8
    folded_low, _ = fold_full_circle_nibble(low)
    low_to_mid = _u64(low << 56)
    mid_lane = _u64((score & 0xFF) << 56)
    mid_residual = _u64(mid_lane - low_to_mid)
    assert mid_residual == mid << 60
    folded_mid, _ = fold_full_circle_nibble(mid)
    fresh_high = high_digit_trace(score).output_code
    return DigitConstructorTrace(
        score=score,
        low=low,
        mid=mid,
        high=high,
        folded_low=folded_low,
        folded_mid=folded_mid,
        fresh_high=fresh_high,
        low_to_mid_correction=low_to_mid,
        mid_residual=mid_residual,
    )


def first_argmin(rows: Sequence[TaggedRow]) -> TaggedRow:
    if not rows:
        raise ValueError("rows must not be empty")
    return min(rows, key=lambda row: row.score)


def _round_chunks(rows: Sequence[TaggedRow], radix: int = RADIX) -> list[list[TaggedRow]]:
    return [list(rows[start : start + radix]) for start in range(0, len(rows), radix)]


def repaired_round(
    rows: Sequence[TaggedRow],
    *,
    completion_order: Sequence[int] | None = None,
    radix: int = RADIX,
) -> list[TaggedRow]:
    """Model index-tag, unordered completion, public sort-by-index, concatenate."""
    chunks = _round_chunks(rows, radix)
    indexed_results = [(index, first_argmin(chunk)) for index, chunk in enumerate(chunks)]
    if completion_order is not None:
        if tuple(sorted(completion_order)) != tuple(range(len(chunks))):
            raise ValueError("completion_order must permute the public chunk indices")
        indexed_results = [indexed_results[index] for index in completion_order]
    indexed_results.sort(key=lambda item: item[0])
    return [winner for _, winner in indexed_results]


def repaired_tournament(
    rows: Sequence[TaggedRow],
    *,
    reverse_completion_every_round: bool = False,
    radix: int = RADIX,
) -> TaggedRow:
    current = list(rows)
    while len(current) > 1:
        chunk_count = math.ceil(len(current) / radix)
        completion = (
            tuple(reversed(range(chunk_count)))
            if reverse_completion_every_round
            else tuple(range(chunk_count))
        )
        current = repaired_round(current, completion_order=completion, radix=radix)
    return current[0]


def open_set_rows(scores: Sequence[int], threshold: int | None = None) -> list[TaggedRow]:
    if not scores:
        raise ValueError("scores must not be empty")
    rows: list[TaggedRow] = []
    if threshold is not None:
        if not 0 <= threshold < SCORE_DOMAIN - 1:
            raise ValueError("sentinel requires 0 <= threshold < 4095")
        rows.append(TaggedRow(threshold + 1, 0, 0))
    gallery_offset = len(rows)
    rows.extend(
        TaggedRow(score, index + 1, index + gallery_offset)
        for index, score in enumerate(scores)
    )
    return rows


def exact_uniform_open_set(scores: Sequence[int], threshold: int) -> int:
    winner = min(range(len(scores)), key=lambda index: scores[index])
    return winner + 1 if scores[winner] <= threshold else 0


def repaired_sentinel_top1(
    scores: Sequence[int], threshold: int, *, reverse_completion_every_round: bool = False
) -> int:
    return repaired_tournament(
        open_set_rows(scores, threshold),
        reverse_completion_every_round=reverse_completion_every_round,
    ).label


def exact_per_template_open_set(scores: Sequence[int], thresholds: Sequence[int]) -> int:
    if len(scores) != len(thresholds) or not scores:
        raise ValueError("scores and thresholds must have the same nonzero length")
    winner = min(range(len(scores)), key=lambda index: scores[index])
    return winner + 1 if scores[winner] <= thresholds[winner] else 0


def per_template_payload_selector_counts(
    gallery_size: int = GALLERY_SIZE,
) -> A46OperationCounts:
    """Direct eight-lane reuse: score3 + label2 + selected threshold3.

    All eight lanes survive all passes, including the terminal round, because
    the selected score and threshold are both needed by the post-sort compare.
    The comparison and output gate are deliberately not counted here.
    """
    total = A46OperationCounts()
    for chunks in source_tournament_rounds(gallery_size):
        for chunk in chunks:
            for pass_index in range(3):
                total += source_bcs_call_counts(
                    chunk,
                    lanes=8,
                    pack_inputs=pass_index == 0,
                )
    return total


def _high_only_combination(public_sentinel: bool) -> dict[str, object]:
    selector = hybrid_selection_audit(public_sentinel=public_sentinel)
    construction = PrimitiveCounts(1, 1, 1).scale(GALLERY_SIZE)
    return {
        "scope": "A46 selector plus A49 high digit only; low/mid construction excluded",
        "selector": asdict(selector.selection_total),
        "high_digit": asdict(construction),
        "combined_blind_rotations": (
            selector.selection_total.blind_rotations + construction.blind_rotations
        ),
        "packing_keyswitches": selector.selection_total.packing_keyswitches,
        "classical_key_switches": construction.classical_key_switches,
        "output_marginals_from_high_digit": construction.output_marginals,
    }


def _complete_pruned_digit_combination(public_sentinel: bool) -> dict[str, object]:
    selector = hybrid_selection_audit(public_sentinel=public_sentinel)
    # low fold, low-to-mid correction, mid fold, direct high quotient.
    construction = PrimitiveCounts(4, 4, 4).scale(GALLERY_SIZE)
    return {
        "scope": (
            "A46 selector plus the complete pruned A45/A49 three-digit constructor; "
            "labels are public/trivial and post-selection threshold logic is excluded"
        ),
        "selector": asdict(selector.selection_total),
        "digit_construction": asdict(construction),
        "combined_blind_rotations": (
            selector.selection_total.blind_rotations + construction.blind_rotations
        ),
        "packing_keyswitches": selector.selection_total.packing_keyswitches,
        "classical_key_switches": construction.classical_key_switches,
        "output_marginals_from_digit_construction": construction.output_marginals,
    }


def validate() -> dict[str, object]:
    assert len(P16_IDENTITY_ACCUMULATOR) == POLYNOMIAL_SIZE
    assert exhaustive_high_digit()
    assert exhaustive_high_digit(torus_error=HIGH_LANE_OPEN_MARGIN - 1)
    assert exhaustive_high_digit(torus_error=-(HIGH_LANE_OPEN_MARGIN - 1))
    assert not exhaustive_high_digit(torus_error=HIGH_LANE_OPEN_MARGIN)

    # Every high block uses exactly one complete 128-rotation p16 box.
    for high in range(16):
        rotations = [
            high_digit_trace((high << 8) + residue).switched_rotation
            for residue in range(256)
        ]
        signed = [value if value < 2048 else value - 4096 for value in rotations]
        assert min(signed) == 128 * high - 64
        assert max(signed) == 128 * high + 63

    pair_sums = existing_delta60_one_sample_pair_sums()
    assert len(set(pair_sums)) == 8
    for high in range(16):
        folded, numeric, torus = fallback_fold_then_inverse(high)
        assert folded == 2 * (high & 7) + (high >> 3)
        assert numeric == high
        assert torus == high << P16_DELTA_LOG

    for score in range(SCORE_DOMAIN):
        digits = pruned_digit_constructor_trace(score)
        assert digits.folded_low == 2 * (digits.low & 7) + (digits.low >> 3)
        assert digits.folded_mid == 2 * (digits.mid & 7) + (digits.mid >> 3)
        assert digits.fresh_high == digits.high

    # The public chunk tag makes completion order irrelevant at every round.
    ties = [TaggedRow(9, index + 1, index) for index in range(127)]
    ties[1] = TaggedRow(0, 2, 1)
    ties[17] = TaggedRow(0, 18, 17)
    assert repaired_tournament(ties).label == 2
    assert repaired_tournament(ties, reverse_completion_every_round=True).label == 2

    for threshold in range(31):
        for left, right in itertools.product(range(32), repeat=2):
            scores = (left, right)
            expected = exact_uniform_open_set(scores, threshold)
            assert repaired_sentinel_top1(scores, threshold) == expected
            assert (
                repaired_sentinel_top1(
                    scores,
                    threshold,
                    reverse_completion_every_round=True,
                )
                == expected
            )

    without = hybrid_selection_audit(public_sentinel=False)
    with_sentinel = hybrid_selection_audit(public_sentinel=True)
    assert without.selection_total == A46OperationCounts(3_621, 3_891)
    assert with_sentinel.selection_total == A46OperationCounts(3_645, 3_917)
    assert _high_only_combination(False)["combined_blind_rotations"] == 3_748
    assert _high_only_combination(True)["combined_blind_rotations"] == 3_772
    assert _complete_pruned_digit_combination(False)["combined_blind_rotations"] == 4_129
    assert _complete_pruned_digit_combination(True)["combined_blind_rotations"] == 4_153
    assert per_template_payload_selector_counts() == A46OperationCounts(4_860, 5_535)

    # Equal minima can produce different answers under per-template thresholds;
    # no one uniform sentinel can represent this contract.
    thresholds = (4, 6)
    assert exact_per_template_open_set((5, 7), thresholds) == 0
    assert exact_per_template_open_set((7, 5), thresholds) == 2

    return {
        "status": "static_go_for_isolated_materialization_no_fhe",
        "scope": "clear_torus_and_source_control_flow_only",
        "high_digit": {
            "lane_offset": 1_536,
            "lane_value": "x * 2^51",
            "sample_degree": 2_047,
            "public_pre_pbs_offset": CANONICAL_SCORE_OFFSET,
            "public_pre_pbs_offset_formula": "-257 * 2^50",
            "pbs": "standard p16 identity accumulator",
            "output": "fresh (x >> 8) * 2^59",
            "scores_exhausted": SCORE_DOMAIN,
            "open_torus_margin": HIGH_LANE_OPEN_MARGIN,
            "minimum_rotation_margin": 0.25,
            "per_template_cost": asdict(PrimitiveCounts(1, 1, 1)),
            "n127_cost": asdict(PrimitiveCounts(1, 1, 1).scale(GALLERY_SIZE)),
            "current_initial_error_bound": CURRENT_INITIAL_SCORE_ERROR_BOUND,
            "current_initial_margin_ratio": (
                HIGH_LANE_OPEN_MARGIN / CURRENT_INITIAL_SCORE_ERROR_BOUND
            ),
            "current_initial_margin_log2": math.log2(
                HIGH_LANE_OPEN_MARGIN / CURRENT_INITIAL_SCORE_ERROR_BOUND
            ),
            "raw_l1_at_pbs_input": 0,
            "fits_current_max5_locally": True,
            "fits_a44_max15_locally": True,
            "whole_unpruned_a45_still_fits_current_max5": False,
            "whole_unpruned_a45_peak_raw_l1": 8,
        },
        "old_delta60_residual": {
            "one_sample_numeric_output_possible": False,
            "desired_antipodal_pair_sums": list(pair_sums),
            "fallback": "fold correction then inverse PBS",
            "fallback_per_template_cost": asdict(PrimitiveCounts(2, 2, 2)),
            "fallback_raw_l1_inputs": [2, 3],
            "fallback_fits_current_max5_locally": True,
            "fallback_fits_a44_max15_locally": True,
        },
        "a46_high_only_combinations": {
            "without_sentinel": _high_only_combination(False),
            "with_uniform_public_sentinel": _high_only_combination(True),
        },
        "pruned_three_digit_constructor": {
            "per_template_cost": asdict(PrimitiveCounts(4, 4, 4)),
            "stages": [
                "low fold correction",
                "low-to-mid aggregate correction",
                "mid fold correction",
                "direct canonical-lane high quotient",
            ],
            "outputs": "folded low, folded mid, fresh numeric high; all at Delta59",
            "pbs_input_raw_l1": [0, 1, 1, 0],
            "maximum_pbs_input_raw_l1": 1,
            "maximum_selector_input_raw_l1": 2,
            "fits_current_max5_locally": True,
            "fits_a44_max15_locally": True,
            "without_sentinel": _complete_pruned_digit_combination(False),
            "with_uniform_public_sentinel": _complete_pruned_digit_combination(True),
            "noise_and_custom_lut_proof_complete": False,
        },
        "chunk_order_repair": {
            "strategy": (
                "attach the public chunk index to each parallel result, collect in any "
                "order, sort by that public index, then concatenate"
            ),
            "extra_blind_rotations": 0,
            "extra_packing_keyswitches": 0,
            "preserves_parallel_chunk_evaluation": True,
            "clear_barrier_already_required_between_recursive_rounds": True,
            "first_tie_proof": (
                "stable BCS chooses the earliest row inside each chunk; restoring chunk "
                "order preserves original order of survivors, so induction gives global first"
            ),
        },
        "threshold_contract": {
            "uniform_sentinel_exact_for": "one public uniform 0 <= T < 4095",
            "uniform_sentinel_semantics": "prepend (T+1,label0) before gallery",
            "inclusive_accept": True,
            "gallery_first_tie_preserved": True,
            "matches_final_per_template_contract": False,
            "per_template_counterexample": {
                "thresholds": list(thresholds),
                "scores_reject": [5, 7],
                "scores_accept_second": [7, 5],
            },
            "direct_payload_option": {
                "lanes": "score3 + label2 + selected-threshold3 = 8",
                "n127_selector_only": asdict(per_template_payload_selector_counts()),
                "post_winner_compare_and_output_gate_included": False,
            },
        },
        "open_obligations": [
            "materialize the fourth packed lane and quotient accumulator in isolated Rust",
            "validate open-boundary and random-noise FHE fixtures under fresh keys",
            "prove custom packed-lane input validity or retain the honest-client assumption",
            "include low/mid digit construction before calling selector totals complete",
            "implement the permuted bucket traversal and indexed chunk collection",
            "design and count exact selected per-template threshold comparison",
            "establish a composed end-to-end failure bound",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compact", action="store_true")
    arguments = parser.parse_args()
    print(json.dumps(validate(), indent=None if arguments.compact else 2, sort_keys=True))


if __name__ == "__main__":
    main()
