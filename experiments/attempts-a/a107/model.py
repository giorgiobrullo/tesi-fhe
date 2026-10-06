"""Static A107 model for a persistent common-mask suffix selector.

This module contains no cryptography and makes no latency or p-fail claim.  It proves the
reachable plaintext states and derives structural operation/key-payload ledgers for the proposed
TFHE-rs 1.7 component gate.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable, Sequence


GALLERY_SIZE = 127
SCORE_MAX = 4095
ALIGNED_THRESHOLD = 1023
CM_WIDTH = 4
CM_REDUCTION_RADIX = 3
A44_REDUCTION_RADIX = 15
SUFFIX_BITS = tuple(range(7, -1, -1))

# The A66 bridge exposes these positive torus weights before A50 applies its signed multipliers.
# Entries are indexed by score-bit position.
A66_WEIGHT_BY_BIT = {
    7: 1,
    6: 1,
    5: 1,
    4: 1,
    3: 1,
    2: 8,
    1: 4,
    0: 2,
}

A44_BOOLEAN_DELTA_LOG = 59
CM_P2_DELTA_LOG = 61

# A66 N=127 frozen anchors.
A66_TOTAL_BLIND_ROTATIONS = 3390
A66_SELECT_BLIND_ROTATIONS = 1603
A66_SUFFIX_ZERO_CANDIDATE_BRS = len(SUFFIX_BITS) * GALLERY_SIZE
A66_SUFFIX_OR_BRS = len(SUFFIX_BITS) * 10
A66_SUFFIX_REFRESH_BRS = 2 * GALLERY_SIZE
A66_SUFFIX_TARGET_BRS = (
    A66_SUFFIX_ZERO_CANDIDATE_BRS + A66_SUFFIX_OR_BRS + A66_SUFFIX_REFRESH_BRS
)
A66_SELECT_UNCHANGED_BRS = A66_SELECT_BLIND_ROTATIONS - A66_SUFFIX_TARGET_BRS

# TFHE-rs 1.7 CM_PARAM_4_2_MINUS_64 and A44 geometry.
CM_SMALL_DIMENSION = 772
CM_GLWE_DIMENSION = 3
CM_POLYNOMIAL_SIZE = 512
CM_BIG_DIMENSION = CM_GLWE_DIMENSION * CM_POLYNOMIAL_SIZE
CM_KS_LEVEL = 5
CM_BS_LEVEL = 1
A44_BIG_DIMENSION = 2048
A44_SMALL_DIMENSION = 859
A44_KS_LEVEL = 5
U64_BYTES = 8
C64_BYTES = 16


@dataclass(frozen=True)
class BitEncoding:
    bit_position: int
    a66_weight: int
    public_multiplier: int
    cm_bit_digit: int
    active_digit: int
    z_target_digit: int


@dataclass(frozen=True)
class RoundTrace:
    bit_position: int
    input_active: tuple[int, ...]
    bits: tuple[int, ...]
    z_codes: tuple[int, ...]
    zero_candidates: tuple[int, ...]
    any_zero: int
    update_codes: tuple[int, ...]
    output_active: tuple[int, ...]


@dataclass(frozen=True)
class BaselineSuffixLedger:
    gallery_size: int
    suffix_levels: int
    a44_zero_candidate_brs: int
    a44_global_or_brs: int
    a44_chunk_refresh_brs: int
    targeted_a44_brs: int
    unchanged_a66_select_brs: int
    complete_a66_select_brs: int


@dataclass(frozen=True)
class HybridSuffixLedger:
    gallery_size: int
    cm_width: int
    groups: int
    suffix_levels: int
    componentwise_reduction_nodes_per_level: int
    cm_packing_calls: int
    cm_keyswitches: int
    cm_blind_rotations: int
    cm_output_lane_marginals: int
    cm_small_ciphertext_additions_or_subtractions: int
    cm_big_ciphertext_additions: int
    cm_root_lane_extractions: int
    final_lane_extractions: int
    total_structural_lane_extractions: int
    lane_to_a44_small_keyswitches: int
    a44_big_to_small_keyswitches: int
    total_classic_keyswitches_in_replacement: int
    a44_blind_rotations_in_replacement: int
    a44_pair_additions: int
    pmk_external_products: int
    unchanged_a66_select_brs: int
    resulting_ordinary_select_brs: int


@dataclass(frozen=True)
class KeyPayloadLedger:
    cm_fourier_bsk_bytes: int
    cm_keyswitch_key_bytes: int
    a44_big_to_cm_small_packing_key_bytes: int
    four_lane_to_a44_small_keyswitch_keys_bytes: int
    new_evaluation_payload_bytes: int
    new_evaluation_payload_mib: float
    cm_small_ciphertext_bytes: int
    cm_big_ciphertext_bytes: int
    cm_accumulator_bytes: int


def _require_bit(value: int) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int) and value in (0, 1):
        return value
    raise ValueError("expected a Boolean 0/1 value")


def bit_encoding(bit_position: int) -> BitEncoding:
    """Map an A66 weighted bit into one of the four p2 CM plaintext digits.

    Delta_CM is four times Delta_A44.  Public integer multiplication is enough for every A66
    suffix weight; no ciphertext division or approximate rescale is used.
    """

    try:
        weight = A66_WEIGHT_BY_BIT[bit_position]
    except KeyError as exc:
        raise ValueError("A107 only models A66 suffix bits 7..0") from exc

    candidates = []
    for multiplier in range(1, 5):
        for cm_digit in (1, 2):
            if weight * multiplier == cm_digit * (
                1 << (CM_P2_DELTA_LOG - A44_BOOLEAN_DELTA_LOG)
            ):
                candidates.append((multiplier, cm_digit))
    if not candidates:
        raise AssertionError("weighted bit has no exact integer A44-to-CM p2 map")
    public_multiplier, cm_bit_digit = min(candidates)
    active_digit = 1 if cm_bit_digit == 2 else 2
    codes = {0, cm_bit_digit, active_digit, active_digit + cm_bit_digit}
    if codes != {0, 1, 2, 3}:
        raise AssertionError(
            "active/bit code is not injective over the four Boolean pairs"
        )
    return BitEncoding(
        bit_position=bit_position,
        a66_weight=weight,
        public_multiplier=public_multiplier,
        cm_bit_digit=cm_bit_digit,
        active_digit=active_digit,
        z_target_digit=active_digit,
    )


def initial_candidates(
    scores: Sequence[int], threshold: int = ALIGNED_THRESHOLD
) -> tuple[int, ...]:
    """Clear meaning of A66's encrypted high-category prefilter.

    This is deliberately restricted to the aligned uniform-threshold fast path.  It does not
    filter with per-template thresholds and therefore must not be reused for that contract.
    """

    if threshold != ALIGNED_THRESHOLD:
        raise ValueError("A107 is restricted to the frozen aligned threshold 1023")
    if not scores:
        raise ValueError("the gallery is empty")
    if any(
        not isinstance(score, int) or not 0 <= score <= SCORE_MAX for score in scores
    ):
        raise ValueError("scores must be integers in 0..4095")
    minimum_category = min(
        (score >> 8 for score in scores if score <= threshold),
        default=None,
    )
    return tuple(
        int(
            minimum_category is not None
            and score <= threshold
            and (score >> 8) == minimum_category
        )
        for score in scores
    )


def selection_round(
    active: Sequence[int], bits: Sequence[int], bit_position: int
) -> RoundTrace:
    """One exact packed suffix round using only p2 reachable states.

    First LUT:
        z_i = [alpha*active_i + beta*bit_i == alpha] = active_i AND NOT bit_i.

    After the exact global OR, the public +1 offset avoids a negative/negacyclic state:
        next_i = [active_i + z_i - any_zero + 1 == 2].
    """

    if len(active) != len(bits) or not active:
        raise ValueError("active and bit vectors must have the same non-zero length")
    canonical_active = tuple(_require_bit(value) for value in active)
    canonical_bits = tuple(_require_bit(value) for value in bits)
    encoding = bit_encoding(bit_position)

    z_codes = tuple(
        encoding.active_digit * candidate + encoding.cm_bit_digit * bit
        for candidate, bit in zip(canonical_active, canonical_bits)
    )
    if any(code not in range(4) for code in z_codes):
        raise AssertionError("z LUT left the p2 domain")
    zero_candidates = tuple(int(code == encoding.z_target_digit) for code in z_codes)
    any_zero = int(any(zero_candidates))
    update_codes = tuple(
        candidate + zero - any_zero + 1
        for candidate, zero in zip(canonical_active, zero_candidates)
    )
    if any(code not in (0, 1, 2) for code in update_codes):
        raise AssertionError("offset update LUT reached an unexpected state")
    output_active = tuple(int(code == 2) for code in update_codes)

    oracle = tuple(
        int(candidate and (not any_zero or not bit))
        for candidate, bit in zip(canonical_active, canonical_bits)
    )
    if output_active != oracle:
        raise AssertionError(
            "p2 recurrence differs from exact lexicographic elimination"
        )

    return RoundTrace(
        bit_position=bit_position,
        input_active=canonical_active,
        bits=canonical_bits,
        z_codes=z_codes,
        zero_candidates=zero_candidates,
        any_zero=any_zero,
        update_codes=update_codes,
        output_active=output_active,
    )


def exact_code(scores: Sequence[int], threshold: int = ALIGNED_THRESHOLD) -> int:
    """Exact A107 clear composition: suffix selector, stable first tie, inclusive reject gate."""

    active = initial_candidates(scores, threshold)
    for bit_position in SUFFIX_BITS:
        bits = tuple((score >> bit_position) & 1 for score in scores)
        active = selection_round(active, bits, bit_position).output_active

    minimum = min(scores)
    expected_active = tuple(
        int(minimum <= threshold and score == minimum) for score in scores
    )
    if active != expected_active:
        raise AssertionError("packed suffix selector changed the global-minimum set")
    return next((index + 1 for index, candidate in enumerate(active) if candidate), 0)


def clear_contract_code(
    scores: Sequence[int], threshold: int = ALIGNED_THRESHOLD
) -> int:
    if threshold != ALIGNED_THRESHOLD:
        raise ValueError("A107 is restricted to the frozen aligned threshold 1023")
    if not scores:
        raise ValueError("the gallery is empty")
    if any(
        not isinstance(score, int) or not 0 <= score <= SCORE_MAX for score in scores
    ):
        raise ValueError("scores must be integers in 0..4095")
    minimum = min(scores)
    winner = scores.index(minimum)
    return winner + 1 if minimum <= threshold else 0


def reduction_nodes(items: int, radix: int) -> int:
    """PBS nodes in a forwarding-singletons reduction tree."""

    if items <= 0 or radix < 2:
        raise ValueError("invalid reduction geometry")
    nodes = 0
    while items > 1:
        full, tail = divmod(items, radix)
        nodes += full + int(tail >= 2)
        items = full + int(tail > 0)
    return nodes


def baseline_suffix_ledger(gallery_size: int = GALLERY_SIZE) -> BaselineSuffixLedger:
    if gallery_size != GALLERY_SIZE:
        raise ValueError("the frozen A66 count comparison is only certified for N=127")
    return BaselineSuffixLedger(
        gallery_size=gallery_size,
        suffix_levels=len(SUFFIX_BITS),
        a44_zero_candidate_brs=A66_SUFFIX_ZERO_CANDIDATE_BRS,
        a44_global_or_brs=A66_SUFFIX_OR_BRS,
        a44_chunk_refresh_brs=A66_SUFFIX_REFRESH_BRS,
        targeted_a44_brs=A66_SUFFIX_TARGET_BRS,
        unchanged_a66_select_brs=A66_SELECT_UNCHANGED_BRS,
        complete_a66_select_brs=A66_SELECT_BLIND_ROTATIONS,
    )


def hybrid_suffix_ledger(gallery_size: int = GALLERY_SIZE) -> HybridSuffixLedger:
    if gallery_size != GALLERY_SIZE:
        raise ValueError("the canonical A107 runtime gate is fixed to N=127")
    groups = gallery_size // CM_WIDTH + int(gallery_size % CM_WIDTH != 0)
    levels = len(SUFFIX_BITS)
    reduction_per_level = reduction_nodes(groups, CM_REDUCTION_RADIX)

    # One initial state pack+identity CM-PBS.  Per level: one bit pack per group and one
    # four-copy broadcast pack; state->small, z, componentwise reduction, and refreshed update.
    cm_packing_calls = groups + levels * (groups + 1)
    cm_keyswitches = levels * (2 * groups + reduction_per_level)
    cm_blind_rotations = groups + levels * (2 * groups + reduction_per_level)

    root_lane_extractions = levels * CM_WIDTH
    final_lane_extractions = gallery_size
    lane_to_a44_small = root_lane_extractions + final_lane_extractions
    a44_big_to_small = levels  # one between the two levels of the four-lane OR tree
    classic_keyswitches = lane_to_a44_small + a44_big_to_small
    a44_blind_rotations = levels * 3 + gallery_size

    return HybridSuffixLedger(
        gallery_size=gallery_size,
        cm_width=CM_WIDTH,
        groups=groups,
        suffix_levels=levels,
        componentwise_reduction_nodes_per_level=reduction_per_level,
        cm_packing_calls=cm_packing_calls,
        cm_keyswitches=cm_keyswitches,
        cm_blind_rotations=cm_blind_rotations,
        cm_output_lane_marginals=CM_WIDTH * cm_blind_rotations,
        cm_small_ciphertext_additions_or_subtractions=levels * 2 * groups,
        cm_big_ciphertext_additions=levels * ((groups - 1) + groups),
        cm_root_lane_extractions=root_lane_extractions,
        final_lane_extractions=final_lane_extractions,
        total_structural_lane_extractions=root_lane_extractions
        + final_lane_extractions,
        lane_to_a44_small_keyswitches=lane_to_a44_small,
        a44_big_to_small_keyswitches=a44_big_to_small,
        total_classic_keyswitches_in_replacement=classic_keyswitches,
        a44_blind_rotations_in_replacement=a44_blind_rotations,
        a44_pair_additions=levels * 3,
        pmk_external_products=0,
        unchanged_a66_select_brs=A66_SELECT_UNCHANGED_BRS,
        resulting_ordinary_select_brs=A66_SELECT_UNCHANGED_BRS + a44_blind_rotations,
    )


def key_payload_ledger() -> KeyPayloadLedger:
    matrix_side = CM_GLWE_DIMENSION + CM_WIDTH
    cm_fourier_bsk = (
        CM_SMALL_DIMENSION
        * CM_BS_LEVEL
        * matrix_side
        * matrix_side
        * (CM_POLYNOMIAL_SIZE // 2)
        * C64_BYTES
    )
    cm_ksk = (
        CM_BIG_DIMENSION * CM_KS_LEVEL * (CM_SMALL_DIMENSION + CM_WIDTH) * U64_BYTES
    )
    packing = (
        CM_WIDTH
        * A44_BIG_DIMENSION
        * CM_KS_LEVEL
        * (CM_SMALL_DIMENSION + CM_WIDTH)
        * U64_BYTES
    )
    egress = (
        CM_WIDTH
        * CM_BIG_DIMENSION
        * A44_KS_LEVEL
        * (A44_SMALL_DIMENSION + 1)
        * U64_BYTES
    )
    total = cm_fourier_bsk + cm_ksk + packing + egress
    return KeyPayloadLedger(
        cm_fourier_bsk_bytes=cm_fourier_bsk,
        cm_keyswitch_key_bytes=cm_ksk,
        a44_big_to_cm_small_packing_key_bytes=packing,
        four_lane_to_a44_small_keyswitch_keys_bytes=egress,
        new_evaluation_payload_bytes=total,
        new_evaluation_payload_mib=total / (1 << 20),
        cm_small_ciphertext_bytes=(CM_SMALL_DIMENSION + CM_WIDTH) * U64_BYTES,
        cm_big_ciphertext_bytes=(CM_BIG_DIMENSION + CM_WIDTH) * U64_BYTES,
        cm_accumulator_bytes=(CM_GLWE_DIMENSION + CM_WIDTH)
        * CM_POLYNOMIAL_SIZE
        * U64_BYTES,
    )


def fixture_report(fixtures: Iterable[Sequence[int]]) -> dict[str, int]:
    checked = 0
    for scores in fixtures:
        if exact_code(scores) != clear_contract_code(scores):
            raise AssertionError("fixture changed exact 0/first-ID semantics")
        checked += 1
    return {"fixtures_checked": checked, "mismatches": 0}


def report() -> dict[str, object]:
    return {
        "status": "STATIC_CANDIDATE_ONLY__NO_FHE_NO_TIMING_NO_PFAIL_CLAIM",
        "scope": "A66 aligned uniform-threshold eight-bit suffix selection at N=127",
        "bit_encodings": [asdict(bit_encoding(bit)) for bit in SUFFIX_BITS],
        "baseline_suffix": asdict(baseline_suffix_ledger()),
        "hybrid_suffix": asdict(hybrid_suffix_ledger()),
        "key_payload": asdict(key_payload_ledger()),
        "semantic_contract": {
            "reject_code": 0,
            "accepted_code": "first_zero_based_minimum_index + 1",
            "tie_policy": "stable first index; all equal minima survive until A53",
            "threshold": "uniform 1023, inclusive, represented by the unchanged A34 prefilter",
            "membership_substitution": False,
        },
    }


if __name__ == "__main__":
    import json

    print(json.dumps(report(), indent=2, sort_keys=True))
