"""Deterministic static model for the A116 p=131 score-encoding bridge audit.

This module performs integer/finite-field bookkeeping only.  It does not build
HElib, generate keys, encrypt, evaluate FHE, or measure cryptographic runtime.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
from math import ceil, comb, isqrt, log2
from typing import Sequence


PLAINTEXT_PRIME = 131
FIELD_DEGREE = 3
COMPARATOR_BASE = (PLAINTEXT_PRIME + 1) // 2
WORD_DIGITS = FIELD_DEGREE
WORD_CAPACITY = COMPARATOR_BASE**WORD_DIGITS
PAPER_SLOTS = 5_764

PROBE_DIM = 512
PROBE_ABS_MAX = 3
PROBE_NORM2_MAX = 1_024
GALLERY_SIZE = 127
SCORE_DOMAIN_WIDTH = 4_096
SCORE_MAX = SCORE_DOMAIN_WIDTH - 1


def ceil_div(numerator: int, denominator: int) -> int:
    if numerator < 0 or denominator <= 0:
        raise ValueError("ceil_div requires numerator >= 0 and denominator > 0")
    return (numerator + denominator - 1) // denominator


def ceil_sqrt(value: int) -> int:
    if value < 0:
        raise ValueError("ceil_sqrt requires a non-negative integer")
    root = isqrt(value)
    return root + int(root * root != value)


def base66_digits(value: int) -> tuple[int, int, int]:
    """Return the exact p=131 univariate-comparator word encoding."""

    if not 0 <= value < WORD_CAPACITY:
        raise ValueError(f"value must lie in [0, {WORD_CAPACITY - 1}]")
    digits: list[int] = []
    rest = value
    for _ in range(WORD_DIGITS):
        digits.append(rest % COMPARATOR_BASE)
        rest //= COMPARATOR_BASE
    return tuple(digits)  # type: ignore[return-value]


def decode_base66(digits: Sequence[int]) -> int:
    if len(digits) != WORD_DIGITS:
        raise ValueError(f"expected {WORD_DIGITS} digits")
    if any(not 0 <= digit < COMPARATOR_BASE for digit in digits):
        raise ValueError(f"digits must lie in [0, {COMPARATOR_BASE - 1}]")
    return sum(digit * COMPARATOR_BASE**index for index, digit in enumerate(digits))


def coefficientwise_field_sum(words: Sequence[Sequence[int]]) -> tuple[int, int, int]:
    """Add encoded words as F_131^3 coefficients, deliberately without carries."""

    if any(len(word) != WORD_DIGITS for word in words):
        raise ValueError(f"every word must contain {WORD_DIGITS} coefficients")
    return tuple(
        sum(word[index] for word in words) % PLAINTEXT_PRIME
        for index in range(WORD_DIGITS)
    )  # type: ignore[return-value]


def squared_norm(vector: Sequence[int]) -> int:
    return sum(value * value for value in vector)


def normalized_affine_score(
    probe: Sequence[int], template: Sequence[int], domain_lower: int
) -> int:
    """Project score: ||g||^2 - lower - 2<g,q>; ||q||^2 is common to all IDs."""

    if len(probe) != len(template):
        raise ValueError("probe and template dimensions must match")
    return (
        squared_norm(template)
        - domain_lower
        - 2 * sum(gallery * query for gallery, query in zip(template, probe))
    )


def template_cauchy_bounds(template: Sequence[int]) -> tuple[int, int]:
    norm2 = squared_norm(template)
    radius = 2 * ceil_sqrt(norm2 * PROBE_NORM2_MAX)
    return norm2 - radius, norm2 + radius


def carry_counterexample() -> dict[str, object]:
    """A project-valid score whose linearly added base-66 terms need a carry."""

    template = [-2] * 8 + [-1] + [0] * (PROBE_DIM - 9)
    probe = [2] * 8 + [1] + [0] * (PROBE_DIM - 9)
    lower, upper = template_cauchy_bounds(template)
    norm2 = squared_norm(template)
    constant = norm2 - lower
    contributions = [-2 * g * q for g, q in zip(template, probe)]
    nonzero_contributions = [value for value in contributions if value]
    score = normalized_affine_score(probe, template, lower)
    correct = base66_digits(score)
    raw = coefficientwise_field_sum(
        [base66_digits(constant)]
        + [base66_digits(value) for value in nonzero_contributions]
    )
    return {
        "template_norm2": norm2,
        "probe_norm2": squared_norm(probe),
        "domain_lower": lower,
        "domain_upper": upper,
        "public_constant": constant,
        "nonzero_contributions": nonzero_contributions,
        "score": score,
        "correct_base66": list(correct),
        "linear_coefficient_sum_mod131": list(raw),
        "linear_result_is_valid_digit_word": all(
            coefficient < COMPARATOR_BASE for coefficient in raw
        ),
        "matches": raw == correct,
    }


def separability_rectangle() -> dict[str, int | bool]:
    """Witness that the low digit is not a sum of per-coordinate lookup terms.

    Group A can contribute 0 or 2.  A disjoint group B can contribute 0 or 64
    using eight legal +8 contributions.  Any additively separable decoder must
    satisfy f(0,0)+f(2,64)=f(2,0)+f(0,64) over F_131; radix normalization does
    not.
    """

    f_00 = 0
    f_2_64 = (2 + 64) % COMPARATOR_BASE
    f_2_0 = 2
    f_0_64 = 64
    left = (f_00 + f_2_64) % PLAINTEXT_PRIME
    right = (f_2_0 + f_0_64) % PLAINTEXT_PRIME
    return {
        "f_0_0": f_00,
        "f_2_64": f_2_64,
        "f_2_0": f_2_0,
        "f_0_64": f_0_64,
        "rectangle_left_mod131": left,
        "rectangle_right_mod131": right,
        "separable": left == right,
    }


def top_boolean_coefficient(subset_size: int) -> int:
    """Top multilinear coefficient for one admissible subset template.

    For a template equal to -1 on a subset S and zero elsewhere, padded with
    126 zero templates to make N=127, the shared Cauchy lower bound makes the
    normalized target score

        2*ceil(sqrt(1024*|S|)) + 2*|S intersect supp(q)|.

    Restricting q to {0,1}^512 keeps every probe valid.  This function returns
    the coefficient of prod_{j in S} q_j in the unique multilinear polynomial
    for the low base-66 digit, reduced modulo 131.
    """

    if not 1 <= subset_size <= PROBE_DIM:
        raise ValueError(f"subset_size must lie in [1, {PROBE_DIM}]")
    radius = 2 * ceil_sqrt(PROBE_NORM2_MAX * subset_size)
    return (
        sum(
            (-1) ** (subset_size - weight)
            * comb(subset_size, weight)
            * ((radius + 2 * weight) % COMPARATOR_BASE)
            for weight in range(subset_size + 1)
        )
        % PLAINTEXT_PRIME
    )


@dataclass(frozen=True)
class LinearDecoderRankWitness:
    nonzero_top_coefficient_sizes: tuple[int, ...]
    zero_top_coefficient_sizes: tuple[int, ...]
    independent_low_digit_functions: int
    affine_client_feature_dimensions_lower_bound: int
    field_dimensions_per_ciphertext: int
    uploaded_ciphertexts_lower_bound: int
    fraction_of_all_boolean_subsets: float
    degree_512_coefficient_mod131: int


def linear_decoder_rank_witness() -> LinearDecoderRankWitness:
    nonzero: list[int] = []
    zero: list[int] = []
    for subset_size in range(1, PROBE_DIM + 1):
        target = nonzero if top_boolean_coefficient(subset_size) else zero
        target.append(subset_size)
    rank = sum(comb(PROBE_DIM, subset_size) for subset_size in nonzero)
    # A server may add one gallery-dependent plaintext constant without using a
    # client feature, hence the conservative rank-1 affine lower bound.
    feature_lower_bound = rank - 1
    field_dimensions = PAPER_SLOTS * FIELD_DEGREE
    return LinearDecoderRankWitness(
        nonzero_top_coefficient_sizes=tuple(nonzero),
        zero_top_coefficient_sizes=tuple(zero),
        independent_low_digit_functions=rank,
        affine_client_feature_dimensions_lower_bound=feature_lower_bound,
        field_dimensions_per_ciphertext=field_dimensions,
        uploaded_ciphertexts_lower_bound=ceil_div(
            feature_lower_bound, field_dimensions
        ),
        fraction_of_all_boolean_subsets=rank / 2**PROBE_DIM,
        degree_512_coefficient_mod131=top_boolean_coefficient(PROBE_DIM),
    )


@dataclass(frozen=True)
class FixedRadixEnvelope:
    minimum_radix: int
    maximum_radix: int
    radices_checked: int
    minimum_rank_radix: int
    minimum_independent_low_digit_functions: int
    minimum_affine_feature_dimensions: int
    minimum_uploaded_ciphertexts: int
    minimum_fraction_of_boolean_subsets: float
    minimum_radix_degree_512_coefficient_mod131: int
    base16_independent_low_digit_functions: int
    base16_degree_512_coefficient_mod131: int
    base66_independent_low_digit_functions: int
    base66_degree_512_coefficient_mod131: int
    complete_envelope_sha256: str


def fixed_radix_envelope() -> FixedRadixEnvelope:
    """Audit every three-digit radix accepted by the univariate digit set.

    A radix below 16 cannot encode all 4,096 scores in three coefficients; a
    radix above 66 leaves the comparator's proven digit domain.  Binomial
    coefficients are reduced modulo 131 while computing the top Boolean
    coefficient, then exact C(512,s) values are used for each rank.
    """

    minimum_radix = ceil(SCORE_DOMAIN_WIDTH ** (1 / WORD_DIGITS))
    while minimum_radix**WORD_DIGITS < SCORE_DOMAIN_WIDTH:
        minimum_radix += 1
    radices = range(minimum_radix, COMPARATOR_BASE + 1)
    nonzero_sizes = {base: [] for base in radices}
    degree_512_coefficients: dict[int, int] = {}
    pascal_row = [1]
    for subset_size in range(1, PROBE_DIM + 1):
        pascal_row = (
            [1]
            + [
                (pascal_row[index - 1] + pascal_row[index]) % PLAINTEXT_PRIME
                for index in range(1, len(pascal_row))
            ]
            + [1]
        )
        radius = 2 * ceil_sqrt(PROBE_NORM2_MAX * subset_size)
        for base in radices:
            coefficient = (
                sum(
                    (-1 if (subset_size - weight) % 2 else 1)
                    * pascal_row[weight]
                    * ((radius + 2 * weight) % base)
                    for weight in range(subset_size + 1)
                )
                % PLAINTEXT_PRIME
            )
            if coefficient:
                nonzero_sizes[base].append(subset_size)
            if subset_size == PROBE_DIM:
                degree_512_coefficients[base] = coefficient

    choose_512 = [comb(PROBE_DIM, size) for size in range(PROBE_DIM + 1)]
    ranks = {
        base: sum(choose_512[size] for size in sizes)
        for base, sizes in nonzero_sizes.items()
    }
    minimum_rank_radix = min(ranks, key=lambda base: (ranks[base], base))
    minimum_rank = ranks[minimum_rank_radix]
    envelope = "\n".join(
        f"{base}:{len(nonzero_sizes[base])}:{degree_512_coefficients[base]}:{ranks[base]}"
        for base in radices
    )
    return FixedRadixEnvelope(
        minimum_radix=minimum_radix,
        maximum_radix=COMPARATOR_BASE,
        radices_checked=len(tuple(radices)),
        minimum_rank_radix=minimum_rank_radix,
        minimum_independent_low_digit_functions=minimum_rank,
        minimum_affine_feature_dimensions=minimum_rank - 1,
        minimum_uploaded_ciphertexts=ceil_div(
            minimum_rank - 1, PAPER_SLOTS * FIELD_DEGREE
        ),
        minimum_fraction_of_boolean_subsets=minimum_rank / 2**PROBE_DIM,
        minimum_radix_degree_512_coefficient_mod131=(
            degree_512_coefficients[minimum_rank_radix]
        ),
        base16_independent_low_digit_functions=ranks[16],
        base16_degree_512_coefficient_mod131=degree_512_coefficients[16],
        base66_independent_low_digit_functions=ranks[COMPARATOR_BASE],
        base66_degree_512_coefficient_mod131=degree_512_coefficients[COMPARATOR_BASE],
        complete_envelope_sha256=sha256(envelope.encode()).hexdigest(),
    )


@dataclass(frozen=True)
class CostLedger:
    pair_comparison_lanes: int
    threshold_comparison_lanes: int
    total_comparison_lanes: int
    comparison_ciphertext_batches: int
    selector_factor_lanes: int
    selector_factor_ciphertext_batches: int
    compact_query_slots: int
    compact_query_upload_ciphertexts: int
    row_replicated_query_slots: int
    row_replicated_query_upload_ciphertexts: int
    row_replicated_score_rotations: int
    row_replicated_reduction_mask_multiplies: int
    row_replicated_plaintext_template_multiplies: int
    one_hot_coordinate_slots: int
    one_hot_coordinate_upload_ciphertexts: int
    one_hot_per_gallery_rotations: int
    one_hot_all_gallery_rotations: int
    one_hot_reduction_mask_multiplies: int
    one_hot_plaintext_lookup_multiplies: int
    carry_save_term_slots: int
    carry_save_term_ciphertexts: int
    bit_slice_slots: int
    bit_slice_upload_ciphertexts: int
    bit_slice_row_aligned_ciphertexts: int
    two_context_crt_compact_ciphertexts: int
    two_context_crt_row_replicated_ciphertexts: int
    two_context_crt_row_replicated_rotations: int
    two_context_crt_row_replicated_mask_multiplies: int
    gallery_dependent_score_one_hot_slots: int
    gallery_dependent_score_one_hot_ciphertexts_minimum: int
    gallery_dependent_score_one_hot_ciphertexts_aligned: int
    gallery_dependent_score_one_hot_rotations: int
    gallery_dependent_score_one_hot_mask_multiplies: int
    degree_1_categorical_feature_slots: int
    degree_2_categorical_feature_slots: int
    degree_2_categorical_feature_ciphertexts: int
    degree_3_categorical_feature_slots: int
    degree_3_categorical_feature_ciphertexts: int
    valid_probe_states_lower_bound: int
    full_query_one_hot_ciphertexts_lower_bound: int


def cost_ledger() -> CostLedger:
    pairs = GALLERY_SIZE * (GALLERY_SIZE - 1) // 2
    comparisons = pairs + GALLERY_SIZE
    factors = GALLERY_SIZE * (GALLERY_SIZE + 1)
    rows_per_ciphertext = PAPER_SLOTS // PROBE_DIM
    row_ciphertexts = ceil_div(GALLERY_SIZE, rows_per_ciphertext)
    row_reduction_rotations = ceil(log2(PROBE_DIM))
    one_hot_slots = PROBE_DIM * (2 * PROBE_ABS_MAX + 1)
    bit_slice_slots = PROBE_DIM * 3
    bit_slice_rows_per_ciphertext = PAPER_SLOTS // bit_slice_slots
    category_degrees = 2 * PROBE_ABS_MAX
    degree_1 = 1 + PROBE_DIM * category_degrees
    degree_2 = degree_1 + comb(PROBE_DIM, 2) * category_degrees**2
    degree_3 = degree_2 + comb(PROBE_DIM, 3) * category_degrees**3
    valid_states_lower = 3**PROBE_DIM
    return CostLedger(
        pair_comparison_lanes=pairs,
        threshold_comparison_lanes=GALLERY_SIZE,
        total_comparison_lanes=comparisons,
        comparison_ciphertext_batches=ceil_div(comparisons, PAPER_SLOTS),
        selector_factor_lanes=factors,
        selector_factor_ciphertext_batches=ceil_div(factors, PAPER_SLOTS),
        compact_query_slots=PROBE_DIM,
        compact_query_upload_ciphertexts=1,
        row_replicated_query_slots=PROBE_DIM * GALLERY_SIZE,
        row_replicated_query_upload_ciphertexts=row_ciphertexts,
        row_replicated_score_rotations=row_ciphertexts * row_reduction_rotations,
        row_replicated_reduction_mask_multiplies=(
            row_ciphertexts * row_reduction_rotations
        ),
        row_replicated_plaintext_template_multiplies=row_ciphertexts,
        one_hot_coordinate_slots=one_hot_slots,
        one_hot_coordinate_upload_ciphertexts=ceil_div(one_hot_slots, PAPER_SLOTS),
        one_hot_per_gallery_rotations=ceil(log2(one_hot_slots)),
        one_hot_all_gallery_rotations=GALLERY_SIZE * ceil(log2(one_hot_slots)),
        one_hot_reduction_mask_multiplies=(GALLERY_SIZE * ceil(log2(one_hot_slots))),
        one_hot_plaintext_lookup_multiplies=GALLERY_SIZE,
        carry_save_term_slots=PROBE_DIM * GALLERY_SIZE,
        carry_save_term_ciphertexts=ceil_div(PROBE_DIM * GALLERY_SIZE, PAPER_SLOTS),
        bit_slice_slots=bit_slice_slots,
        bit_slice_upload_ciphertexts=ceil_div(bit_slice_slots, PAPER_SLOTS),
        bit_slice_row_aligned_ciphertexts=ceil_div(
            GALLERY_SIZE, bit_slice_rows_per_ciphertext
        ),
        two_context_crt_compact_ciphertexts=2,
        two_context_crt_row_replicated_ciphertexts=2 * row_ciphertexts,
        two_context_crt_row_replicated_rotations=2
        * row_ciphertexts
        * row_reduction_rotations,
        two_context_crt_row_replicated_mask_multiplies=(
            2 * row_ciphertexts * row_reduction_rotations
        ),
        gallery_dependent_score_one_hot_slots=GALLERY_SIZE * SCORE_DOMAIN_WIDTH,
        gallery_dependent_score_one_hot_ciphertexts_minimum=ceil_div(
            GALLERY_SIZE * SCORE_DOMAIN_WIDTH, PAPER_SLOTS
        ),
        gallery_dependent_score_one_hot_ciphertexts_aligned=GALLERY_SIZE,
        gallery_dependent_score_one_hot_rotations=(
            GALLERY_SIZE * ceil(log2(SCORE_DOMAIN_WIDTH))
        ),
        gallery_dependent_score_one_hot_mask_multiplies=(
            GALLERY_SIZE * ceil(log2(SCORE_DOMAIN_WIDTH))
        ),
        degree_1_categorical_feature_slots=degree_1,
        degree_2_categorical_feature_slots=degree_2,
        degree_2_categorical_feature_ciphertexts=ceil_div(degree_2, PAPER_SLOTS),
        degree_3_categorical_feature_slots=degree_3,
        degree_3_categorical_feature_ciphertexts=ceil_div(degree_3, PAPER_SLOTS),
        valid_probe_states_lower_bound=valid_states_lower,
        full_query_one_hot_ciphertexts_lower_bound=ceil_div(
            valid_states_lower, PAPER_SLOTS
        ),
    )


def reference_exact_id(scores: Sequence[int], thresholds: Sequence[int]) -> int:
    """Stable-first argmin, inclusive winner threshold, encrypted 0/ID contract."""

    if not scores or len(scores) != len(thresholds):
        raise ValueError("scores and thresholds must be non-empty and aligned")
    if any(not 0 <= score <= SCORE_MAX for score in scores):
        raise ValueError(f"scores must lie in [0, {SCORE_MAX}]")
    winner = min(range(len(scores)), key=lambda index: (scores[index], index))
    return winner + 1 if scores[winner] <= thresholds[winner] else 0


def static_report() -> dict[str, object]:
    rank = linear_decoder_rank_witness()
    radix_envelope = fixed_radix_envelope()
    costs = cost_ledger()
    nonzero_sizes = ",".join(map(str, rank.nonzero_top_coefficient_sizes))
    return {
        "artifact": "A116",
        "status": "PASS_STATIC_AUDIT_LINEAR_BRIDGE_REJECTED",
        "execution": {
            "compiled": False,
            "fhe_run": False,
            "keys_generated": False,
            "timed": False,
        },
        "contract": {
            "D": PROBE_DIM,
            "N": GALLERY_SIZE,
            "score_formula": "||g_i||^2-domain_lower-2<g_i,q>",
            "score_domain": [0, SCORE_MAX],
            "tie": "lowest gallery index wins",
            "threshold": "winner score <= winner threshold",
            "output": "encrypted 0 reject or encrypted index+1 exact ID",
        },
        "published_component": {
            "p": PLAINTEXT_PRIME,
            "d": FIELD_DEGREE,
            "l": 1,
            "base": COMPARATOR_BASE,
            "word_capacity": WORD_CAPACITY,
            "slots": PAPER_SLOTS,
            "input_requirement": "one already-normalized base-66/F_(131^3) word per slot",
        },
        "carry_counterexample": carry_counterexample(),
        "separability_rectangle": separability_rectangle(),
        "linear_decoder_rank_witness": {
            "nonzero_top_coefficient_size_count": len(
                rank.nonzero_top_coefficient_sizes
            ),
            "zero_top_coefficient_sizes": list(rank.zero_top_coefficient_sizes),
            "nonzero_sizes_sha256": sha256(nonzero_sizes.encode()).hexdigest(),
            "independent_low_digit_functions": rank.independent_low_digit_functions,
            "affine_client_feature_dimensions_lower_bound": (
                rank.affine_client_feature_dimensions_lower_bound
            ),
            "field_dimensions_per_ciphertext": rank.field_dimensions_per_ciphertext,
            "uploaded_ciphertexts_lower_bound": rank.uploaded_ciphertexts_lower_bound,
            "fraction_of_all_boolean_subsets": rank.fraction_of_all_boolean_subsets,
            "degree_512_coefficient_mod131": rank.degree_512_coefficient_mod131,
        },
        "fixed_radix_16_through_66_envelope": asdict(radix_envelope),
        "cost_ledger": asdict(costs),
        "verdict": {
            "compact_gallery_independent_linear_bridge": "algebraically rejected",
            "direct_digit_slicing": "linear and compact, but yields invalid uncarried coefficients",
            "per_coordinate_one_hot": "linear and compact, but cannot represent cross-coordinate carries",
            "crt": "linear scoring only; ordered/base-66 reconstruction is nonlinear or cross-context",
            "carry_save": "preserves terms linearly; normalization remains a new nonlinear circuit",
            "bounded_degree_features": "degree < 512 rejected by an admissible Boolean-probe witness",
            "fixed_radix_16_through_66": "all compact affine decoders rejected; radix 43 is the weakest audited rank witness",
            "gallery_dependent_score_one_hot": "exact and linear after upload, but violates gallery independence",
            "full_query_one_hot": "exact in principle, but astronomically impractical",
        },
    }
