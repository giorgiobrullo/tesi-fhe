#!/usr/bin/env python3
"""Static operation and semantic audit for the A46 RevoLUT top-1 candidate.

This file deliberately models source-level control flow.  It does not execute
TFHE, estimate latency, or claim that the conditional radix construction is a
working circuit.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from typing import Iterable, Sequence


RADIX = 16
GALLERY_SIZE = 127
SCORE_DIGITS = 3
LABEL_DIGITS = 2
TUPLE_LANES = SCORE_DIGITS + LABEL_DIGITS
FOLDED_NIBBLE_BUCKET_ORDER = tuple(
    2 * (digit & 0b111) + (digit >> 3) for digit in range(RADIX)
)

KNN_COMMIT = "4fd244e5a52cfe218a202e3040f8540ef8879251"
REVOLUT_COMMIT = "e93475470c126c4a0fa121f8fae0c6194988b74e"


@dataclass(frozen=True)
class OperationCounts:
    blind_rotations: int = 0
    packing_keyswitches: int = 0

    def __add__(self, other: OperationCounts) -> OperationCounts:
        return OperationCounts(
            blind_rotations=self.blind_rotations + other.blind_rotations,
            packing_keyswitches=(self.packing_keyswitches + other.packing_keyswitches),
        )


@dataclass(frozen=True)
class SourceTop1Audit:
    gallery_size: int
    radix: int
    lanes: int
    rounds: tuple[tuple[int, ...], ...]
    bcs_calls: int
    processed_elements: int
    top1: OperationCounts
    precision_reduction: OperationCounts
    total: OperationCounts


@dataclass(frozen=True)
class PaperCountConvention:
    gallery_size: int
    radix: int
    k: int
    lanes: int
    modeled_prefixes: tuple[tuple[int, ...], ...]
    bcs_calls: int
    modeled_prefix_elements: int
    top1: OperationCounts
    precision_reduction: OperationCounts
    total: OperationCounts


@dataclass(frozen=True)
class HybridAudit:
    input_items: int
    gallery_items: int
    includes_public_sentinel: bool
    rounds: tuple[tuple[int, ...], ...]
    nonterminal: OperationCounts
    terminal: OperationCounts
    selection_total: OperationCounts
    natural_order_inverse_map_pbs: OperationCounts
    selection_plus_natural_order_inverse_map_pbs: OperationCounts


def _validate_problem(size: int, radix: int, k: int = 1) -> None:
    if size <= 0:
        raise ValueError("size must be positive")
    if radix <= 1:
        raise ValueError("radix must be greater than one")
    if not 0 < k < radix:
        raise ValueError("k must satisfy 0 < k < radix")


def source_tournament_rounds(
    size: int, radix: int = RADIX, k: int = 1
) -> tuple[tuple[int, ...], ...]:
    """Mirror ``blind_topk_many_lut_par`` chunk sizes exactly."""
    _validate_problem(size, radix, k)
    rounds: list[tuple[int, ...]] = []
    remaining = size
    while remaining > k:
        chunks = tuple(
            min(radix, remaining - start) for start in range(0, remaining, radix)
        )
        rounds.append(chunks)
        remaining = sum(min(k, chunk) for chunk in chunks)
    return tuple(rounds)


def source_bcs_call_counts(
    chunk_size: int,
    lanes: int,
    radix: int = RADIX,
    *,
    pack_inputs: bool = True,
) -> OperationCounts:
    """Count calls executed by the pinned RevoLUT source for one KV-BCS.

    ``packing_keyswitches`` names the calls to
    ``keyswitch_lwe_ciphertext_into_glwe_ciphertext`` made by ``LUT::from_lwe``.
    The paper calls this PFKS-family work, although the checked-in source uses
    the public packing key-switch key rather than its unused ``pfpksk`` field.

    The implementation does not special-case trivially encrypted operands or
    public rotation indices, so they remain in this source-level count.
    """
    if not 0 < chunk_size <= radix:
        raise ValueError("chunk_size must be in 1..=radix")
    if lanes <= 0:
        raise ValueError("lanes must be positive")

    # BCS: count loop s, public-index prefix loop p-1, rebuild loop
    # s * (decrement + count access + one write per lane).
    blind_rotations = (lanes + 3) * chunk_size + (radix - 1)

    # Each blind_array_increment first turns its value LWE into a LUT.
    bcs_packing = (lanes + 2) * chunk_size + (radix - 1)
    input_packing = lanes * chunk_size if pack_inputs else 0
    return OperationCounts(
        blind_rotations=blind_rotations,
        packing_keyswitches=input_packing + bcs_packing,
    )


def source_scalar_top1_audit(
    gallery_size: int = GALLERY_SIZE,
    *,
    distance_modulus: int = RADIX,
    radix: int = RADIX,
) -> SourceTop1Audit:
    """Count the pinned two-lane distance+label top-1 path."""
    rounds = source_tournament_rounds(gallery_size, radix)
    counts = OperationCounts()
    for round_chunks in rounds:
        for chunk in round_chunks:
            counts += source_bcs_call_counts(chunk, lanes=2, radix=radix)

    # server.rs calls lower_precision once per distance exactly when its
    # distance encoding delta differs from the p16 context delta.
    reductions = 0 if distance_modulus == radix else gallery_size
    precision = OperationCounts(blind_rotations=reductions)
    return SourceTop1Audit(
        gallery_size=gallery_size,
        radix=radix,
        lanes=2,
        rounds=rounds,
        bcs_calls=sum(len(round_chunks) for round_chunks in rounds),
        processed_elements=sum(sum(round_chunks) for round_chunks in rounds),
        top1=counts,
        precision_reduction=precision,
        total=counts + precision,
    )


def paper_modeled_prefixes(
    size: int, radix: int = RADIX, k: int = 1
) -> tuple[tuple[int, ...], ...]:
    """Reproduce the paper's Table-5 tournament-count convention.

    The paper assigns prefix ``radix`` to every full bucket and
    ``min(k, remainder)`` to the final bucket.  This differs from the pinned
    source, which passes the actual ``chunk.len()`` to KV-BCS.
    """
    _validate_problem(size, radix, k)
    rounds: list[tuple[int, ...]] = []
    remaining = size
    while remaining > k:
        full, tail = divmod(remaining, radix)
        prefixes = [radix] * full
        if tail:
            prefixes.append(min(k, tail))
        rounds.append(tuple(prefixes))
        remaining = k * full + min(k, tail)
    return tuple(rounds)


def paper_count_convention(
    gallery_size: int = GALLERY_SIZE,
    *,
    distance_modulus: int = RADIX,
    radix: int = RADIX,
    k: int = 1,
    lanes: int = 2,
) -> PaperCountConvention:
    """Apply Equation 3 plus the paper's two PFKS per KV-BCS call."""
    prefixes = paper_modeled_prefixes(gallery_size, radix, k)
    calls = sum(len(round_prefixes) for round_prefixes in prefixes)
    elements = sum(sum(round_prefixes) for round_prefixes in prefixes)
    top1 = OperationCounts(
        blind_rotations=(3 + lanes) * elements,
        packing_keyswitches=(radix * calls + lanes * elements + lanes * calls),
    )
    reductions = 0 if distance_modulus == radix else gallery_size
    precision = OperationCounts(blind_rotations=reductions)
    return PaperCountConvention(
        gallery_size=gallery_size,
        radix=radix,
        k=k,
        lanes=lanes,
        modeled_prefixes=prefixes,
        bcs_calls=calls,
        modeled_prefix_elements=elements,
        top1=top1,
        precision_reduction=precision,
        total=top1 + precision,
    )


def quantize_distance(distance: int, distance_modulus: int, radix: int = RADIX) -> int:
    """Mirror the clear reference's integer precision reduction."""
    if distance < 0:
        raise ValueError("distance must be non-negative")
    if distance_modulus < radix or distance_modulus % radix:
        raise ValueError("distance_modulus must be a multiple of radix")
    return distance // (distance_modulus // radix)


def first_argmin(values: Sequence[int]) -> int:
    if not values:
        raise ValueError("values must not be empty")
    return min(range(len(values)), key=lambda index: (values[index], index))


def precision_reduced_argmin(
    values: Sequence[int], distance_modulus: int, radix: int = RADIX
) -> int:
    return first_argmin(
        [quantize_distance(value, distance_modulus, radix) for value in values]
    )


def stable_counting_sort(
    rows: Sequence[tuple[int, ...]],
    key_lane: int,
    radix: int = RADIX,
    *,
    bucket_order: Sequence[int] | None = None,
) -> list[tuple[int, ...]]:
    """Clear mirror of BCS, optionally using a public bucket permutation."""
    if not rows:
        return []
    if not 0 <= key_lane < len(rows[0]):
        raise ValueError("key_lane out of range")
    order = tuple(range(radix)) if bucket_order is None else tuple(bucket_order)
    if len(order) != radix or set(order) != set(range(radix)):
        raise ValueError("bucket_order must be a permutation of the radix")
    count = [0] * radix
    for row in rows:
        key = row[key_lane]
        if not 0 <= key < radix:
            raise ValueError("key outside radix")
        count[key] += 1
    running = 0
    for key in order:
        running += count[key]
        count[key] = running
    result: list[tuple[int, ...] | None] = [None] * len(rows)
    for row in reversed(rows):
        key = row[key_lane]
        count[key] -= 1
        result[count[key]] = row
    return [row for row in result if row is not None]


def stable_lsd_sort_score_rows(
    rows: Sequence[tuple[int, ...]],
) -> list[tuple[int, ...]]:
    """Sort rows ``(low, mid, high, label_low, label_high)`` by score."""
    ordered = list(rows)
    for key_lane in range(SCORE_DIGITS):
        ordered = stable_counting_sort(ordered, key_lane)
    return ordered


def fold_nibble(digit: int) -> int:
    """A45's standard-Delta59 fold: u=2*(digit mod 8)+floor(digit/8)."""
    if not 0 <= digit < RADIX:
        raise ValueError("digit outside radix")
    return 2 * (digit & 0b111) + (digit >> 3)


def encode_folded_score_row(score: int, label: int) -> tuple[int, int, int, int, int]:
    canonical = encode_score_row(score, label)
    return (
        fold_nibble(canonical[0]),
        fold_nibble(canonical[1]),
        fold_nibble(canonical[2]),
        canonical[3],
        canonical[4],
    )


def stable_lsd_sort_folded_score_rows(
    rows: Sequence[tuple[int, ...]],
) -> list[tuple[int, ...]]:
    """Sort A45-folded score digits using their public numeric bucket order."""
    ordered = list(rows)
    for key_lane in range(SCORE_DIGITS):
        ordered = stable_counting_sort(
            ordered,
            key_lane,
            bucket_order=FOLDED_NIBBLE_BUCKET_ORDER,
        )
    return ordered


def decode_folded_score_row(row: Sequence[int]) -> tuple[int, int]:
    if len(row) != TUPLE_LANES:
        raise ValueError("row must have five lanes")

    def inverse(value: int) -> int:
        return (value >> 1) + 8 * (value & 1)

    score = inverse(row[0]) + RADIX * inverse(row[1]) + RADIX**2 * inverse(row[2])
    label = row[3] + RADIX * row[4]
    return score, label


def encode_score_row(score: int, label: int) -> tuple[int, int, int, int, int]:
    if not 0 <= score < RADIX**SCORE_DIGITS:
        raise ValueError("score must fit three nibbles")
    if not 0 <= label < RADIX**LABEL_DIGITS:
        raise ValueError("label must fit two nibbles")
    return (
        score & 0xF,
        (score >> 4) & 0xF,
        (score >> 8) & 0xF,
        label & 0xF,
        (label >> 4) & 0xF,
    )


def decode_score_row(row: Sequence[int]) -> tuple[int, int]:
    if len(row) != TUPLE_LANES:
        raise ValueError("row must have five lanes")
    score = row[0] + RADIX * row[1] + RADIX**2 * row[2]
    label = row[3] + RADIX * row[4]
    return score, label


def sentinel_top1(scores: Sequence[int], threshold: int) -> int:
    """Return 0/reject or the one-based first exact gallery identity."""
    if not 0 <= threshold < RADIX**SCORE_DIGITS - 1:
        raise ValueError("sentinel requires 0 <= threshold < 4095")
    rows = [encode_score_row(threshold + 1, 0)]
    rows.extend(
        encode_score_row(score, index + 1) for index, score in enumerate(scores)
    )
    _, label = decode_score_row(stable_lsd_sort_score_rows(rows)[0])
    return label


def folded_radix_tournament_top1(
    scores: Sequence[int],
    *,
    threshold: int | None = None,
    reverse_first_round_chunks: bool = False,
) -> int:
    """Clear model of the conditional folded-digit tournament.

    Reversing first-round chunks models one ordering allowed by ``par_bridge``;
    it is not a claim that a particular execution will choose that order.
    """
    if not scores:
        raise ValueError("scores must not be empty")
    rows: list[tuple[int, ...]] = []
    if threshold is not None:
        if not 0 <= threshold < RADIX**SCORE_DIGITS - 1:
            raise ValueError("sentinel requires 0 <= threshold < 4095")
        rows.append(encode_folded_score_row(threshold + 1, 0))
    rows.extend(
        encode_folded_score_row(score, index + 1) for index, score in enumerate(scores)
    )
    first_round = True
    while len(rows) > 1:
        chunks = [rows[start : start + RADIX] for start in range(0, len(rows), RADIX)]
        if first_round and reverse_first_round_chunks:
            chunks.reverse()
        rows = [stable_lsd_sort_folded_score_rows(chunk)[0] for chunk in chunks]
        first_round = False
    return decode_folded_score_row(rows[0])[1]


def exact_open_set_top1(scores: Sequence[int], threshold: int) -> int:
    winner = first_argmin(scores)
    return winner + 1 if scores[winner] <= threshold else 0


def hybrid_selection_audit(
    gallery_size: int = GALLERY_SIZE,
    *,
    public_sentinel: bool,
    radix: int = RADIX,
) -> HybridAudit:
    """Conditional source-style cost of a three-pass stable nibble selector.

    Each non-terminal block keeps all five lanes for all three LSD passes.
    The terminal block reuses its produced LUTs and may discard the already
    sorted lower key after each pass, giving lane counts 5, 4, 3.  Input LWE
    packing therefore occurs only before the first pass of each block.
    """
    input_items = gallery_size + int(public_sentinel)
    rounds = source_tournament_rounds(input_items, radix)
    nonterminal = OperationCounts()
    terminal = OperationCounts()
    for round_index, chunks in enumerate(rounds):
        is_terminal_round = round_index == len(rounds) - 1
        for chunk in chunks:
            if is_terminal_round:
                for pass_index, lanes in enumerate((5, 4, 3)):
                    terminal += source_bcs_call_counts(
                        chunk,
                        lanes,
                        radix,
                        pack_inputs=pass_index == 0,
                    )
            else:
                for pass_index in range(SCORE_DIGITS):
                    nonterminal += source_bcs_call_counts(
                        chunk,
                        TUPLE_LANES,
                        radix,
                        pack_inputs=pass_index == 0,
                    )
    selection = nonterminal + terminal
    inverse_pbs = OperationCounts(blind_rotations=SCORE_DIGITS * gallery_size)
    return HybridAudit(
        input_items=input_items,
        gallery_items=gallery_size,
        includes_public_sentinel=public_sentinel,
        rounds=rounds,
        nonterminal=nonterminal,
        terminal=terminal,
        selection_total=selection,
        natural_order_inverse_map_pbs=inverse_pbs,
        selection_plus_natural_order_inverse_map_pbs=selection + inverse_pbs,
    )


def _rows_as_lists(rounds: Iterable[Iterable[int]]) -> list[list[int]]:
    return [list(row) for row in rounds]


def report() -> dict[str, object]:
    source_no_reduce = source_scalar_top1_audit(distance_modulus=RADIX)
    source_reduce = source_scalar_top1_audit(distance_modulus=RADIX**SCORE_DIGITS)
    paper_no_reduce = paper_count_convention(distance_modulus=RADIX)
    paper_reduce = paper_count_convention(distance_modulus=RADIX**SCORE_DIGITS)
    hybrid_without = hybrid_selection_audit(public_sentinel=False)
    hybrid_with = hybrid_selection_audit(public_sentinel=True)
    cross_chunk_scores = [9] * GALLERY_SIZE
    cross_chunk_scores[1] = 0
    cross_chunk_scores[17] = 0
    return {
        "status": "static_conditional_no_go_as_drop_in",
        "pinned_prior_art": {
            "paper": ("https://petsymposium.org/popets/2025/popets-2025-0093.pdf"),
            "knn_commit": KNN_COMMIT,
            "revolut_commit": REVOLUT_COMMIT,
        },
        "contract_delta": {
            "prior_art_evaluated_key": (
                "one p16 precision-reduced squared-distance value"
            ),
            "prior_art_output": (
                "k encrypted class labels; client decrypts and performs majority vote"
            ),
            "a38_required": (
                "exact bounded 12-bit first argmin, then the selected winner's "
                "inclusive threshold, returning encrypted 0 or one-based identity"
            ),
            "prior_art_has_open_set_threshold": False,
            "prior_art_has_contractual_global_first_tie": False,
        },
        "pinned_source_top1_n127_p16": {
            "without_precision_reduction": asdict(source_no_reduce),
            "with_p4096_to_p16_precision_reduction": asdict(source_reduce),
            "count_semantics": (
                "literal calls in pinned control flow, including public-index blind "
                "rotations and packing-key calls on trivial operands"
            ),
        },
        "paper_count_convention_n127_p16": {
            "without_precision_reduction": asdict(paper_no_reduce),
            "with_p4096_to_p16_precision_reduction": asdict(paper_reduce),
            "count_semantics": (
                "Equation 3 and the paper's two pre-BCS PFKS convention; this is "
                "not the literal source-call count"
            ),
        },
        "exactness_counterexample": {
            "scores": [255, 1],
            "p4096_to_p16_values": [0, 0],
            "exact_first_index": first_argmin([255, 1]),
            "precision_reduced_first_index": precision_reduced_argmin(
                [255, 1], RADIX**SCORE_DIGITS
            ),
            "conclusion": (
                "monotone quotienting creates ties and can replace the exact minimum "
                "with an earlier, strictly larger score"
            ),
        },
        "tie_audit": {
            "single_bcs_reverse_reconstruction_is_stable": True,
            "lsd_radix_requires_that_stability": True,
            "parallel_chunk_collection_uses_unordered_par_bridge": True,
            "global_first_tie_is_therefore_not_a_pinned_source_contract": True,
            "required_repair": (
                "preserve public chunk indices deterministically before concatenating winners"
            ),
            "allowed_reordering_counterexample": {
                "equal_minimum_zero_based_indices": [1, 17],
                "ordered_one_based_output": folded_radix_tournament_top1(
                    cross_chunk_scores
                ),
                "reversed_first_round_chunk_output": folded_radix_tournament_top1(
                    cross_chunk_scores,
                    reverse_first_round_chunks=True,
                ),
                "sentinel_ordered_output": folded_radix_tournament_top1(
                    [5] * GALLERY_SIZE,
                    threshold=4,
                ),
                "sentinel_reordered_output": folded_radix_tournament_top1(
                    [5] * GALLERY_SIZE,
                    threshold=4,
                    reverse_first_round_chunks=True,
                ),
            },
        },
        "conditional_lsd_hybrid": {
            "without_sentinel_n127": asdict(hybrid_without),
            "with_public_sentinel_n128": asdict(hybrid_with),
            "rounds_without_sentinel": _rows_as_lists(hybrid_without.rounds),
            "rounds_with_sentinel": _rows_as_lists(hybrid_with.rounds),
            "sentinel_contract": (
                "for one public uniform 0 <= T < 4095, prepend (T+1, label 0); "
                "stable exact sorting returns 0 iff every gallery score exceeds T"
            ),
            "a45_interface": {
                "ready_numeric_digits": False,
                "folded_low_mid_state": "u=2*(digit&7)+floor(digit/8) at Delta59",
                "folded_bucket_order": list(FOLDED_NIBBLE_BUCKET_ORDER),
                "high_state": (
                    "numeric h at Delta60 only; no standard-Delta59 folded or numeric "
                    "high digit is emitted"
                ),
            },
            "natural_bucket_order_option": (
                "inverse-map each of three folded digits, conditionally costing one PBS "
                "per digit per gallery item; generation of the missing high folded state "
                "is still excluded"
            ),
            "permuted_bucket_order_option": (
                "change the 15 public prefix steps to visit buckets in folded numeric "
                "order; reconstruction remains stable and the selector BR/PFKS counts "
                "do not change, but this source variant is not implemented"
            ),
            "drop_rule": (
                "all score digits must survive every nonterminal block; only the final "
                "global block may drop low then mid after their stable passes"
            ),
        },
        "blocking_obligations": [
            "materialize the missing exact high folded or numeric p16 digit",
            "prove valid TFHE LUT/negacyclic encodings and noise margins for every digit",
            "implement and validate permuted public bucket traversal or pay inverse-map PBS",
            "replace unordered par_bridge concatenation with deterministic chunk order",
            "handle per-template thresholds or explicitly restrict to one public uniform T",
            "decide whether two returned ID nibbles satisfy the wire contract or pay a fusion cost",
            "validate source-level counts against an instrumented implementation before latency claims",
        ],
        "latency_boundary": {
            "paper_reports_p16_primitive_ms": {
                "blind_rotation": 18,
                "pfks": 3,
            },
            "paper_reports_k1_n127_latency": None,
            "cross_hardware_or_a38_latency_inference_allowed": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    print(json.dumps(report(), indent=None if args.compact else 2, sort_keys=True))


if __name__ == "__main__":
    main()
