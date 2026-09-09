#!/usr/bin/env python3
"""Standalone clear model of the proposed A34 top-category selector.

This module models plaintext semantics and structural primitive counts only.  It
does not execute TFHE and is deliberately disconnected from the live A33 Rust
core.

For the aligned score ``x`` and threshold 1023, let ``h = floor(x / 256)``.  The
extractor retains the exact ciphertext bits b7..b0 and subtracts their
corrections from the full score, leaving ``h`` at Delta=2^60.  A p=16
classifier then emits the signed Z32 code ``C`` below.  A unary p=16 LUT turns
``h in {0, 1, 2}`` into the canonical ordered alphabet ``E = {1, 3, 7}`` and
maps every other category to zero.  A binary PBS tree reduces E to the lowest
present category.  Zero means that none of 0, 1, 2 is present, so the final LUT
selects category 3.  Categories 4 and above are always rejected.

The classifier blind rotation has one output only: C, extracted at polynomial
degree zero.  It neither emits nor overwrites a numeric residual or b7..b0;
the unchanged exact low-bit selector consumes the separately retained bit
ciphertexts.  Consequently there is no multi-coefficient accumulator-layout
constraint between C and a residual.  The anti-periodic C table proves the
plaintext accumulator layout needed for that single degree-zero sample.  The
current generic high extractor takes one additional terminal b8 sample after
performing the b7 correction.  The projected A34 topology uses a tailored
variant that performs the b7 correction and stops before that b8 key switch.

The construction is not a generic TFHE priority-encoder novelty claim.  Generic
priority encoding and multi-value-FBS-aware synthesis are prior art (Yu et al.,
WAHC 2024, DOI 10.1145/3689945.3694803).  The object under study here is the
bounded, anti-coded p=16 construction and its integration with exact-ID argmin.

This is still a clear/structural model, not an FHE validation.  In particular,
it proves reachable LUT phases and fresh-output linear L1 bounds, but does not
certify accumulator generation, cryptographic noise, or measured latency.
Multi-output FBS could still produce a different signed encoding; no generic
lower bound against that route is claimed here.

The earlier exploratory finite search is intentionally not part of this
executable evidence because its enumerator is not checked in.  Its scope was
only a later scalar additive pair phase ``A(left) + B(right)``; it did not rule
out classifier-to-multiple-output constructions such as ``(residual, E)``.
"""

from __future__ import annotations

import argparse
import itertools
import json
import random
from dataclasses import asdict, dataclass
from typing import Iterable, Sequence


MAX_GALLERY_SIZE = 128
SCORE_DOMAIN_SIZE = 4096
ACCEPT_THRESHOLD = 1023
PHASE_MODULUS = 32
P16_INDEPENDENT_PHASES = 16
FULL_SCORE_DELTA_LOG = 52
CLASSIFIER_PUBLIC_OFFSET = 4
CANDIDATE_PUBLIC_OFFSET = 4
DEFAULT_VALIDATION_SEED = 0xA34_2026_0902
CLASSIFIER_INPUT_DELTA_LOG = 60
CLASSIFIER_OUTPUT_DELTA_LOG = 59
CLASSIFIER_EXTRACTION_DEGREE = 0
RETAINED_SCORE_BITS = tuple(range(8))
SUBTRACTED_CORRECTION_BITS = tuple(range(8))
OMITTED_TERMINAL_SAMPLE_BIT = 8
SHORTINT_MAX_NOISE_LEVEL = 5

# Independent values for h=0..7.  Negacyclicity fixes h=8..15 to their
# additive opposites modulo 32.
CLASSIFIER_BASE_CODES = (30, 28, 3, 31, 0, 0, 0, 0)
CLASSIFIER_CODES = CLASSIFIER_BASE_CODES + tuple(
    (-value) % PHASE_MODULUS for value in CLASSIFIER_BASE_CODES
)
CLASSIFIER_ROTATION_STRIDE_SLOTS = 2
CLASSIFIER_DEGREE_ZERO_SLOTS = tuple(range(0, 16, CLASSIFIER_ROTATION_STRIDE_SLOTS))
CLASSIFIER_UNUSED_SLOTS = tuple(range(1, 16, CLASSIFIER_ROTATION_STRIDE_SLOTS))
CLASSIFIER_ACCUMULATOR_SLOTS = tuple(
    CLASSIFIER_BASE_CODES[slot // CLASSIFIER_ROTATION_STRIDE_SLOTS]
    if slot in CLASSIFIER_DEGREE_ZERO_SLOTS
    else 0
    for slot in range(16)
)

CATEGORY_CODES = (1, 3, 7, 0)
CATEGORY_RANK_BY_CODE = {code: rank for rank, code in enumerate(CATEGORY_CODES)}
CANONICAL_CATEGORY_BY_CLASSIFIER_CODE = {30: 1, 28: 3, 3: 7}
CANONICAL_CATEGORY_BY_INPUT_PHASE = {
    (code + CLASSIFIER_PUBLIC_OFFSET) % PHASE_MODULUS: category
    for code, category in CANONICAL_CATEGORY_BY_CLASSIFIER_CODE.items()
}
CANDIDATE_TRUE_PHASES = frozenset((10, 31))
CANDIDATE_TRUE_INPUT_PHASES = frozenset(
    (phase + CANDIDATE_PUBLIC_OFFSET) % PHASE_MODULUS for phase in CANDIDATE_TRUE_PHASES
)


@dataclass(frozen=True)
class CyclicArc:
    start: int
    end: int
    span: int
    cardinality: int


@dataclass(frozen=True)
class PrimitiveCounts:
    blind_rotations: int
    key_switches: int
    output_marginals: int

    def __add__(self, other: "PrimitiveCounts") -> "PrimitiveCounts":
        return PrimitiveCounts(
            self.blind_rotations + other.blind_rotations,
            self.key_switches + other.key_switches,
            self.output_marginals + other.output_marginals,
        )

    def __sub__(self, other: "PrimitiveCounts") -> "PrimitiveCounts":
        return PrimitiveCounts(
            self.blind_rotations - other.blind_rotations,
            self.key_switches - other.key_switches,
            self.output_marginals - other.output_marginals,
        )


A33_WHOLE_N127 = PrimitiveCounts(4_273, 3_892, 4_908)
A33_SCAN_OUTPUT_N127 = PrimitiveCounts(372, 372, 372)
A34_SCAN_OUTPUT_CLEAR_MODEL_N127 = PrimitiveCounts(220, 220, 262)


@dataclass(frozen=True)
class ClassifierExtractionContract:
    retained_score_bits: tuple[int, ...]
    subtracted_correction_bits: tuple[int, ...]
    input_delta_log: int
    output_delta_log: int
    output_names: tuple[str, ...]
    extraction_degrees: tuple[int, ...]
    accumulator_logical_slots: tuple[int, ...]
    rotation_stride_slots: int
    degree_zero_slots: tuple[int, ...]
    unused_slots: tuple[int, ...]
    omitted_terminal_sample_bit: int
    low_bits_retained_before_classifier: bool
    needs_same_rotation_numeric_residual: bool
    fhe_validated: bool


CLASSIFIER_EXTRACTION_CONTRACT = ClassifierExtractionContract(
    retained_score_bits=RETAINED_SCORE_BITS,
    subtracted_correction_bits=SUBTRACTED_CORRECTION_BITS,
    input_delta_log=CLASSIFIER_INPUT_DELTA_LOG,
    output_delta_log=CLASSIFIER_OUTPUT_DELTA_LOG,
    output_names=("C",),
    extraction_degrees=(CLASSIFIER_EXTRACTION_DEGREE,),
    accumulator_logical_slots=CLASSIFIER_ACCUMULATOR_SLOTS,
    rotation_stride_slots=CLASSIFIER_ROTATION_STRIDE_SLOTS,
    degree_zero_slots=CLASSIFIER_DEGREE_ZERO_SLOTS,
    unused_slots=CLASSIFIER_UNUSED_SLOTS,
    omitted_terminal_sample_bit=OMITTED_TERMINAL_SAMPLE_BIT,
    low_bits_retained_before_classifier=True,
    needs_same_rotation_numeric_residual=False,
    fhe_validated=False,
)


@dataclass(frozen=True)
class LutStageContract:
    name: str
    input_modulus: int
    input_delta_log: int
    output_delta_log: int
    reachable_input_arc: CyclicArc
    linear_l1: int
    output_marginals_per_rotation: int


@dataclass(frozen=True)
class TopCategoryStageCounts:
    gallery_size: int
    classifier: PrimitiveCounts
    unary_canonicalizer: PrimitiveCounts
    binary_min_reducer: PrimitiveCounts
    candidate: PrimitiveCounts
    total: PrimitiveCounts
    binary_level_nodes: tuple[int, ...]


@dataclass(frozen=True)
class Base16ScanOutputProjection:
    groups: int
    group_flag_blind_rotations: int
    local_first_blind_rotations: int
    group_prefix_blind_rotations: int
    dual_selector_blind_rotations: int
    two_digit_reduction_blind_rotations: int
    total: PrimitiveCounts
    selector_extraction_degrees: tuple[str, ...]
    selector_disjoint_slot_halves: bool
    digit_reducer_input_modulus: int
    digit_reducer_delta_log: int
    digit_reducer_reachable_arc: CyclicArc
    digit_reducer_linear_l1: int
    fhe_validated: bool


@dataclass(frozen=True)
class A33TopCategoryStageCounts:
    gallery_size: int
    b8_correction: PrimitiveCounts
    sparse_classifier: PrimitiveCounts
    pair_flags: PrimitiveCounts
    pair_flag_reduction: PrimitiveCounts
    b8_zero_test: PrimitiveCounts
    b8_zero_reduction: PrimitiveCounts
    candidate: PrimitiveCounts
    total: PrimitiveCounts


@dataclass(frozen=True)
class TopCategoryTrace:
    h_values: tuple[int, ...]
    classifier_codes: tuple[int, ...]
    canonical_categories: tuple[int, ...]
    reduction_levels: tuple[tuple[int, ...], ...]
    global_category: int
    candidates: tuple[bool, ...]


@dataclass(frozen=True)
class ValidationSummary:
    exhaustive_h_through: int
    exhaustive_h_vectors: int
    gallery_sizes_checked: int
    adversarial_vectors: int
    random_h_vectors: int
    random_score_vectors: int
    seed: int


def _validate_gallery_size(gallery_size: int) -> None:
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError(f"gallery size must be in 1..{MAX_GALLERY_SIZE}")


def _validate_h_values(h_values: Sequence[int]) -> tuple[int, ...]:
    values = tuple(h_values)
    _validate_gallery_size(len(values))
    if any(not 0 <= value < 16 for value in values):
        raise ValueError("every h value must be in 0..15")
    return values


def _validate_scores(scores: Sequence[int]) -> tuple[int, ...]:
    values = tuple(scores)
    _validate_gallery_size(len(values))
    if any(not 0 <= value < SCORE_DOMAIN_SIZE for value in values):
        raise ValueError(
            f"every normalized score must be in 0..{SCORE_DOMAIN_SIZE - 1}"
        )
    return values


def smallest_cyclic_arc(values: Iterable[int]) -> CyclicArc:
    residues = frozenset(value % PHASE_MODULUS for value in values)
    if not residues:
        raise ValueError("a cyclic arc requires at least one residue")
    for span in range(PHASE_MODULUS):
        for start in range(PHASE_MODULUS):
            if all((value - start) % PHASE_MODULUS <= span for value in residues):
                return CyclicArc(
                    start=start,
                    end=(start + span) % PHASE_MODULUS,
                    span=span,
                    cardinality=len(residues),
                )
    raise AssertionError("the full residue circle must contain every finite set")


def assert_p16_half_domain(values: Iterable[int]) -> CyclicArc:
    arc = smallest_cyclic_arc(values)
    if arc.span >= P16_INDEPENDENT_PHASES:
        raise AssertionError(f"reachable phases do not fit a p=16 half-domain: {arc}")
    return arc


def retained_score_bits(score: int) -> tuple[int, ...]:
    """Return the exact pre-classifier b0..b7 values retained for selection."""
    _validate_scores((score,))
    return tuple((score >> bit_index) & 1 for bit_index in RETAINED_SCORE_BITS)


def classifier_residual(score: int) -> int:
    """Clear counterpart of subtracting the captured b0..b7 corrections."""
    bits = retained_score_bits(score)
    low_value = sum(
        bit << bit_index for bit_index, bit in zip(RETAINED_SCORE_BITS, bits)
    )
    return score - low_value


def classifier_input_slot(score: int) -> int:
    """Return the p=16 slot after exact b0..b7 correction subtraction."""
    residual = classifier_residual(score)
    encoded = residual << FULL_SCORE_DELTA_LOG
    slot = encoded >> CLASSIFIER_INPUT_DELTA_LOG
    if encoded != slot << CLASSIFIER_INPUT_DELTA_LOG:
        raise AssertionError("classifier input is not exactly on a p=16 slot")
    return slot


def classifier_code_from_accumulator_layout(h_value: int) -> int:
    """Read C through the degree-zero even-box layout and negacyclic sign."""
    if not 0 <= h_value < 16:
        raise ValueError("h must be in 0..15")
    base_h = h_value % 8
    logical_slot = CLASSIFIER_ROTATION_STRIDE_SLOTS * base_h
    code = CLASSIFIER_ACCUMULATOR_SLOTS[logical_slot]
    return (-code) % PHASE_MODULUS if h_value >= 8 else code


def classifier_code(h_value: int) -> int:
    return classifier_code_from_accumulator_layout(h_value)


def canonicalizer_input_phase(code: int) -> int:
    return (code + CLASSIFIER_PUBLIC_OFFSET) % PHASE_MODULUS


def canonical_category_code(code: int) -> int:
    return CANONICAL_CATEGORY_BY_INPUT_PHASE.get(canonicalizer_input_phase(code), 0)


def _category_rank(code: int) -> int:
    try:
        return CATEGORY_RANK_BY_CODE[code]
    except KeyError as error:
        raise ValueError(f"invalid canonical category code: {code}") from error


def _build_pair_reducer_lut() -> tuple[dict[int, int], dict[int, frozenset[int]]]:
    lut: dict[int, int] = {}
    phases_by_rank = {rank: set() for rank in range(4)}
    for left, right in itertools.product(CATEGORY_CODES, repeat=2):
        output_rank = min(_category_rank(left), _category_rank(right))
        output = CATEGORY_CODES[output_rank]
        phase = (left + right) % PHASE_MODULUS
        previous = lut.setdefault(phase, output)
        if previous != output:
            raise AssertionError(f"ambiguous pair reducer phase {phase}")
        phases_by_rank[output_rank].add(phase)
    return lut, {rank: frozenset(phases) for rank, phases in phases_by_rank.items()}


PAIR_REDUCER_LUT, PAIR_PHASES_BY_OUTPUT_RANK = _build_pair_reducer_lut()


def pair_reduce_categories(left: int, right: int) -> int:
    _category_rank(left)
    _category_rank(right)
    return PAIR_REDUCER_LUT[(left + right) % PHASE_MODULUS]


def candidate_phase(classifier: int, global_category: int) -> int:
    _category_rank(global_category)
    return (classifier + global_category) % PHASE_MODULUS


def candidate_input_phase(classifier: int, global_category: int) -> int:
    return (
        candidate_phase(classifier, global_category) + CANDIDATE_PUBLIC_OFFSET
    ) % PHASE_MODULUS


def candidate_lut(classifier: int, global_category: int) -> bool:
    return (
        candidate_input_phase(classifier, global_category)
        in CANDIDATE_TRUE_INPUT_PHASES
    )


def lut_stage_contracts() -> tuple[LutStageContract, ...]:
    """Describe p=16 reachability and immediate fresh-output L1 bounds.

    ``linear_l1`` counts coefficients in the direct input expression of the
    LUT.  It does not turn the inherited residual-noise path into a formal
    cryptographic proof.
    """
    canonicalizer_inputs = {
        canonicalizer_input_phase(code) for code in CLASSIFIER_CODES
    }
    pair_inputs = set(PAIR_REDUCER_LUT)
    candidate_inputs = {
        candidate_input_phase(code, category)
        for code in CLASSIFIER_CODES
        for category in CATEGORY_CODES
    }
    return (
        LutStageContract(
            name="classifier_C_degree_0",
            input_modulus=16,
            input_delta_log=CLASSIFIER_INPUT_DELTA_LOG,
            output_delta_log=CLASSIFIER_OUTPUT_DELTA_LOG,
            reachable_input_arc=CyclicArc(0, 15, 15, 16),
            linear_l1=1,
            output_marginals_per_rotation=1,
        ),
        LutStageContract(
            name="unary_canonicalizer",
            input_modulus=16,
            input_delta_log=CLASSIFIER_OUTPUT_DELTA_LOG,
            output_delta_log=CLASSIFIER_OUTPUT_DELTA_LOG,
            reachable_input_arc=assert_p16_half_domain(canonicalizer_inputs),
            linear_l1=1,
            output_marginals_per_rotation=1,
        ),
        LutStageContract(
            name="binary_min_reducer",
            input_modulus=16,
            input_delta_log=CLASSIFIER_OUTPUT_DELTA_LOG,
            output_delta_log=CLASSIFIER_OUTPUT_DELTA_LOG,
            reachable_input_arc=assert_p16_half_domain(pair_inputs),
            linear_l1=2,
            output_marginals_per_rotation=1,
        ),
        LutStageContract(
            name="candidate",
            input_modulus=16,
            input_delta_log=CLASSIFIER_OUTPUT_DELTA_LOG,
            output_delta_log=CLASSIFIER_OUTPUT_DELTA_LOG,
            reachable_input_arc=assert_p16_half_domain(candidate_inputs),
            linear_l1=2,
            output_marginals_per_rotation=1,
        ),
    )


def _reduce_categories(
    values: Sequence[int],
) -> tuple[int, tuple[tuple[int, ...], ...]]:
    if not values:
        raise ValueError("category reduction requires at least one value")
    for value in values:
        _category_rank(value)
    level = tuple(values)
    levels = [level]
    while len(level) > 1:
        next_level = []
        for start in range(0, len(level), 2):
            pair = level[start : start + 2]
            if len(pair) == 1:
                next_level.append(pair[0])
            else:
                next_level.append(pair_reduce_categories(pair[0], pair[1]))
        level = tuple(next_level)
        levels.append(level)
    return level[0], tuple(levels)


def reference_top_candidates(h_values: Sequence[int]) -> tuple[bool, ...]:
    values = _validate_h_values(h_values)
    minimum = min(values)
    if minimum >= 4:
        return (False,) * len(values)
    return tuple(value == minimum for value in values)


def evaluate_top_category(h_values: Sequence[int]) -> TopCategoryTrace:
    values = _validate_h_values(h_values)
    classifier_codes = tuple(classifier_code(value) for value in values)
    categories = tuple(canonical_category_code(code) for code in classifier_codes)
    global_category, levels = _reduce_categories(categories)
    candidates = tuple(
        candidate_lut(code, global_category) for code in classifier_codes
    )
    return TopCategoryTrace(
        h_values=values,
        classifier_codes=classifier_codes,
        canonical_categories=categories,
        reduction_levels=levels,
        global_category=global_category,
        candidates=candidates,
    )


def reference_exact_id(scores: Sequence[int]) -> int:
    values = _validate_scores(scores)
    winner = min(range(len(values)), key=lambda index: (values[index], index))
    return winner + 1 if values[winner] <= ACCEPT_THRESHOLD else 0


def evaluate_exact_id(scores: Sequence[int]) -> int:
    """Compose A34 top categories with the unchanged exact b7..b0 selector."""
    values = _validate_scores(scores)
    top = evaluate_top_category([score >> 8 for score in values])
    eligible = [index for index, candidate in enumerate(top.candidates) if candidate]
    if not eligible:
        return 0
    winner = min(eligible, key=lambda index: (values[index], index))
    return winner + 1


def binary_reduction_level_nodes(gallery_size: int) -> tuple[int, ...]:
    _validate_gallery_size(gallery_size)
    items = gallery_size
    levels = []
    while items > 1:
        nodes = items // 2
        levels.append(nodes)
        items = nodes + items % 2
    return tuple(levels)


def a34_top_category_counts(gallery_size: int) -> TopCategoryStageCounts:
    _validate_gallery_size(gallery_size)
    levels = binary_reduction_level_nodes(gallery_size)
    classifier = PrimitiveCounts(gallery_size, gallery_size, gallery_size)
    canonicalizer = PrimitiveCounts(gallery_size, gallery_size, gallery_size)
    reducer_nodes = sum(levels)
    reducer = PrimitiveCounts(reducer_nodes, reducer_nodes, reducer_nodes)
    candidate = PrimitiveCounts(gallery_size, gallery_size, gallery_size)
    total = classifier + canonicalizer + reducer + candidate
    return TopCategoryStageCounts(
        gallery_size=gallery_size,
        classifier=classifier,
        unary_canonicalizer=canonicalizer,
        binary_min_reducer=reducer,
        candidate=candidate,
        total=total,
        binary_level_nodes=levels,
    )


def _or_reduction_blind_rotations(items: int) -> int:
    count = 0
    while items > 1:
        items = (items + 3) // 4
        count += items
    return count


def _radix4_exclusive_prefix_blind_rotations(items: int) -> int:
    if items <= 0:
        raise ValueError("prefix reduction requires at least one item")
    if items <= 2:
        return 0
    if items <= 4:
        return items - 2

    totals = 0
    expansion = 0
    groups = 0
    for start in range(0, items, 4):
        length = min(4, items - start)
        groups += 1
        totals += int(length > 1)
        expansion += max(0, length - 2) if start == 0 else length - 1
    return totals + expansion + _radix4_exclusive_prefix_blind_rotations(groups)


def base16_scan_output_projection_n127() -> Base16ScanOutputProjection:
    """Derive the tentative two-nibble scan/output count for combination only.

    The dual selector uses disjoint logical slots 0..7 and 8..15, sampled at
    degrees 0 and N/2.  Its radix-4 one-hot digit reductions use standard p=16
    identity LUTs over reachable values 0..15 at Delta=2^59 with L1=4.  These
    are structural clear-model facts; the combined circuit is not FHE-tested.
    """
    gallery_size = 127
    group_size = 3
    groups = (gallery_size + group_size - 1) // group_size
    group_nodes = sum(
        min(group_size, gallery_size - start) > 1
        for start in range(0, gallery_size, group_size)
    )
    prefix_nodes = _radix4_exclusive_prefix_blind_rotations(groups)
    selector_nodes = groups
    digit_nodes = 2 * _or_reduction_blind_rotations(groups)
    blind_rotations = 2 * group_nodes + prefix_nodes + selector_nodes + digit_nodes
    selector_marginals = 2 * selector_nodes
    output_marginals = blind_rotations - selector_nodes + selector_marginals
    return Base16ScanOutputProjection(
        groups=groups,
        group_flag_blind_rotations=group_nodes,
        local_first_blind_rotations=group_nodes,
        group_prefix_blind_rotations=prefix_nodes,
        dual_selector_blind_rotations=selector_nodes,
        two_digit_reduction_blind_rotations=digit_nodes,
        total=PrimitiveCounts(blind_rotations, blind_rotations, output_marginals),
        selector_extraction_degrees=("0", "N/2"),
        selector_disjoint_slot_halves=True,
        digit_reducer_input_modulus=16,
        digit_reducer_delta_log=59,
        digit_reducer_reachable_arc=CyclicArc(0, 15, 15, 16),
        digit_reducer_linear_l1=4,
        fhe_validated=False,
    )


A34_SCAN_OUTPUT_BASE16_PROJECTION_N127 = base16_scan_output_projection_n127().total


def a33_top_category_breakdown(gallery_size: int) -> A33TopCategoryStageCounts:
    _validate_gallery_size(gallery_size)
    pairs = (gallery_size + 1) // 2
    pair_reduction_nodes = _or_reduction_blind_rotations(pairs)
    zero_reduction_nodes = _or_reduction_blind_rotations(gallery_size)
    b8_correction = PrimitiveCounts(gallery_size, 0, gallery_size)
    sparse_classifier = PrimitiveCounts(gallery_size, gallery_size, 2 * gallery_size)
    pair_flags = PrimitiveCounts(pairs, pairs, pairs)
    pair_flag_reduction = PrimitiveCounts(
        pair_reduction_nodes, pair_reduction_nodes, pair_reduction_nodes
    )
    b8_zero_test = PrimitiveCounts(gallery_size, gallery_size, gallery_size)
    b8_zero_reduction = PrimitiveCounts(
        zero_reduction_nodes, zero_reduction_nodes, zero_reduction_nodes
    )
    candidate = PrimitiveCounts(gallery_size, gallery_size, gallery_size)
    total = (
        b8_correction
        + sparse_classifier
        + pair_flags
        + pair_flag_reduction
        + b8_zero_test
        + b8_zero_reduction
        + candidate
    )
    return A33TopCategoryStageCounts(
        gallery_size=gallery_size,
        b8_correction=b8_correction,
        sparse_classifier=sparse_classifier,
        pair_flags=pair_flags,
        pair_flag_reduction=pair_flag_reduction,
        b8_zero_test=b8_zero_test,
        b8_zero_reduction=b8_zero_reduction,
        candidate=candidate,
        total=total,
    )


def a33_top_category_counts(gallery_size: int) -> PrimitiveCounts:
    return a33_top_category_breakdown(gallery_size).total


def a34_top_standalone_savings_n127() -> PrimitiveCounts:
    """Savings from replacing only the A33 top network, before extractor trim."""
    return a33_top_category_counts(127) - a34_top_category_counts(127).total


def omitted_terminal_b8_sample_savings(gallery_size: int) -> PrimitiveCounts:
    """Savings from stopping after the b7 correction instead of sampling b8."""
    _validate_gallery_size(gallery_size)
    return PrimitiveCounts(0, gallery_size, 0)


def a34_top_only_n127_projection(
    *, omit_b8_small_keyswitch: bool = True
) -> PrimitiveCounts:
    """Replace A33 top selection in the measured N=127 whole-circuit counts.

    The A34 residual needs corrections through b7 but not the stored b8 sample.
    A tailored extractor can therefore omit one KS per template.  Passing
    ``omit_b8_small_keyswitch=False`` gives the conservative projection if the
    current five-sample extractor is retained unchanged.
    """
    gallery_size = 127
    reference_top = a33_top_category_counts(gallery_size)
    replacement_top = a34_top_category_counts(gallery_size).total
    projection = A33_WHOLE_N127 - reference_top + replacement_top
    if omit_b8_small_keyswitch:
        projection -= omitted_terminal_b8_sample_savings(gallery_size)
    return projection


def combined_n127_projection(scan_output: PrimitiveCounts) -> PrimitiveCounts:
    """Project A34 top selection together with a separate scan/output model."""
    return a34_top_only_n127_projection() - A33_SCAN_OUTPUT_N127 + scan_output


def savings_from_a33_whole(projection: PrimitiveCounts) -> PrimitiveCounts:
    return A33_WHOLE_N127 - projection


def assert_classifier_extraction_contract() -> None:
    """Prove the clear extractor/classifier boundary for every 12-bit score.

    This is deliberately a single-output accumulator contract.  Exact b7..b0
    are retained before the classifier, so no residual sample or coefficient
    sharing is required from its blind rotation.
    """
    contract = CLASSIFIER_EXTRACTION_CONTRACT
    assert contract.retained_score_bits == tuple(range(8))
    assert contract.subtracted_correction_bits == contract.retained_score_bits
    assert contract.input_delta_log == 60
    assert contract.output_delta_log == 59
    assert contract.output_names == ("C",)
    assert contract.extraction_degrees == (0,)
    assert len(contract.accumulator_logical_slots) == 16
    assert contract.rotation_stride_slots == 2
    assert contract.degree_zero_slots == tuple(range(0, 16, 2))
    assert contract.unused_slots == tuple(range(1, 16, 2))
    assert set(contract.degree_zero_slots).isdisjoint(contract.unused_slots)
    assert set(contract.degree_zero_slots).union(contract.unused_slots) == set(
        range(16)
    )
    assert (
        tuple(
            contract.accumulator_logical_slots[slot]
            for slot in contract.degree_zero_slots
        )
        == CLASSIFIER_BASE_CODES
    )
    assert all(
        contract.accumulator_logical_slots[slot] == 0 for slot in contract.unused_slots
    )
    assert contract.omitted_terminal_sample_bit == 8
    assert contract.low_bits_retained_before_classifier
    assert not contract.needs_same_rotation_numeric_residual
    assert not contract.fhe_validated

    for score in range(SCORE_DOMAIN_SIZE):
        bits = retained_score_bits(score)
        low_value = sum(
            bit << bit_index for bit_index, bit in zip(RETAINED_SCORE_BITS, bits)
        )
        residual = classifier_residual(score)
        h_value = score >> 8
        assert low_value == score & 0xFF
        assert residual == h_value << 8
        assert classifier_input_slot(score) == h_value
        assert (
            classifier_code_from_accumulator_layout(h_value)
            == CLASSIFIER_CODES[h_value]
        )
        assert residual + low_value == score

    # A scalar p=16 accumulator sampled at degree zero exists exactly because
    # its second half is the negation of its first half.
    assert all(
        (CLASSIFIER_CODES[h_value] + CLASSIFIER_CODES[h_value + 8]) % PHASE_MODULUS == 0
        for h_value in range(8)
    )


def assert_lut_stage_contracts() -> None:
    contracts = lut_stage_contracts()
    assert tuple(contract.name for contract in contracts) == (
        "classifier_C_degree_0",
        "unary_canonicalizer",
        "binary_min_reducer",
        "candidate",
    )
    assert tuple(contract.reachable_input_arc for contract in contracts) == (
        CyclicArc(0, 15, 15, 16),
        CyclicArc(0, 8, 8, 9),
        CyclicArc(0, 14, 14, 10),
        CyclicArc(0, 15, 15, 16),
    )
    for contract in contracts:
        assert contract.input_modulus == 16
        assert contract.input_delta_log in (59, 60)
        assert contract.output_delta_log == 59
        assert contract.reachable_input_arc.span < P16_INDEPENDENT_PHASES
        assert contract.linear_l1 <= SHORTINT_MAX_NOISE_LEVEL
        assert contract.output_marginals_per_rotation == 1


def assert_truth_tables_and_domains() -> None:
    assert_classifier_extraction_contract()
    assert_lut_stage_contracts()
    assert CLASSIFIER_CODES == (
        30,
        28,
        3,
        31,
        0,
        0,
        0,
        0,
        2,
        4,
        29,
        1,
        0,
        0,
        0,
        0,
    )
    assert all(
        (CLASSIFIER_CODES[h_value + 8] + CLASSIFIER_CODES[h_value]) % PHASE_MODULUS == 0
        for h_value in range(8)
    )
    assert assert_p16_half_domain(CLASSIFIER_CODES) == CyclicArc(28, 4, 8, 9)
    canonicalizer_inputs = {
        canonicalizer_input_phase(code) for code in CLASSIFIER_CODES
    }
    assert canonicalizer_inputs == set(range(9))
    assert assert_p16_half_domain(canonicalizer_inputs) == CyclicArc(0, 8, 8, 9)
    assert CANONICAL_CATEGORY_BY_INPUT_PHASE == {0: 3, 2: 1, 7: 7}

    expected_pair_sets = {
        0: frozenset((1, 2, 4, 8)),
        1: frozenset((3, 6, 10)),
        2: frozenset((7, 14)),
        3: frozenset((0,)),
    }
    assert PAIR_PHASES_BY_OUTPUT_RANK == expected_pair_sets
    pair_inputs = set().union(*PAIR_PHASES_BY_OUTPUT_RANK.values())
    assert assert_p16_half_domain(pair_inputs) == CyclicArc(0, 14, 14, 10)

    candidate_inputs = {
        candidate_phase(classifier_code(h_value), global_category)
        for h_value in range(16)
        for global_category in CATEGORY_CODES
    }
    assert candidate_inputs == set(range(12)).union(range(28, 32))
    assert assert_p16_half_domain(candidate_inputs) == CyclicArc(28, 11, 15, 16)
    candidate_lut_inputs = {
        candidate_input_phase(classifier_code(h_value), global_category)
        for h_value in range(16)
        for global_category in CATEGORY_CODES
    }
    assert candidate_lut_inputs == set(range(16))
    assert CANDIDATE_TRUE_INPUT_PHASES == frozenset((3, 14))


def assert_n127_counts() -> None:
    base16_scan = base16_scan_output_projection_n127()
    assert base16_scan.groups == 43
    assert base16_scan.group_flag_blind_rotations == 42
    assert base16_scan.local_first_blind_rotations == 42
    assert base16_scan.group_prefix_blind_rotations == 53
    assert base16_scan.dual_selector_blind_rotations == 43
    assert base16_scan.two_digit_reduction_blind_rotations == 30
    assert base16_scan.total == PrimitiveCounts(210, 210, 253)
    assert base16_scan.selector_extraction_degrees == ("0", "N/2")
    assert base16_scan.selector_disjoint_slot_halves
    assert base16_scan.digit_reducer_input_modulus == 16
    assert base16_scan.digit_reducer_delta_log == 59
    assert base16_scan.digit_reducer_reachable_arc == CyclicArc(0, 15, 15, 16)
    assert base16_scan.digit_reducer_linear_l1 == 4
    assert base16_scan.digit_reducer_linear_l1 <= SHORTINT_MAX_NOISE_LEVEL
    assert not base16_scan.fhe_validated

    reference_breakdown = a33_top_category_breakdown(127)
    reference = reference_breakdown.total
    replacement = a34_top_category_counts(127)
    assert reference_breakdown.b8_correction == PrimitiveCounts(127, 0, 127)
    assert reference_breakdown.sparse_classifier == PrimitiveCounts(127, 127, 254)
    assert reference_breakdown.pair_flags == PrimitiveCounts(64, 64, 64)
    assert reference_breakdown.pair_flag_reduction == PrimitiveCounts(21, 21, 21)
    assert reference_breakdown.b8_zero_test == PrimitiveCounts(127, 127, 127)
    assert reference_breakdown.b8_zero_reduction == PrimitiveCounts(43, 43, 43)
    assert reference_breakdown.candidate == PrimitiveCounts(127, 127, 127)
    assert reference == PrimitiveCounts(636, 509, 763)
    assert replacement.binary_level_nodes == (63, 32, 16, 8, 4, 2, 1)
    assert replacement.total == PrimitiveCounts(507, 507, 507)
    assert a34_top_standalone_savings_n127() == PrimitiveCounts(129, 2, 256)
    assert omitted_terminal_b8_sample_savings(127) == PrimitiveCounts(0, 127, 0)
    assert a34_top_only_n127_projection(
        omit_b8_small_keyswitch=False
    ) == PrimitiveCounts(4_144, 3_890, 4_652)
    assert a34_top_only_n127_projection() == PrimitiveCounts(4_144, 3_763, 4_652)
    assert savings_from_a33_whole(a34_top_only_n127_projection()) == PrimitiveCounts(
        129, 129, 256
    )
    combined_clear = combined_n127_projection(A34_SCAN_OUTPUT_CLEAR_MODEL_N127)
    assert combined_clear == PrimitiveCounts(3_992, 3_611, 4_542)
    assert savings_from_a33_whole(combined_clear) == PrimitiveCounts(281, 281, 366)
    combined_base16 = combined_n127_projection(A34_SCAN_OUTPUT_BASE16_PROJECTION_N127)
    assert combined_base16 == PrimitiveCounts(3_982, 3_601, 4_533)
    assert savings_from_a33_whole(combined_base16) == PrimitiveCounts(291, 291, 375)


def validate_model(
    *,
    exhaustive_h_through: int = 4,
    random_cases_per_size: int = 8,
    seed: int = DEFAULT_VALIDATION_SEED,
) -> ValidationSummary:
    if not 0 <= exhaustive_h_through <= 5:
        raise ValueError("exhaustive_h_through must be in 0..5")
    if random_cases_per_size < 0:
        raise ValueError("random_cases_per_size must be non-negative")

    assert_truth_tables_and_domains()
    assert_n127_counts()
    exhaustive_vectors = 0
    for gallery_size in range(1, exhaustive_h_through + 1):
        for h_values in itertools.product(range(16), repeat=gallery_size):
            actual = evaluate_top_category(h_values).candidates
            assert actual == reference_top_candidates(h_values)
            exhaustive_vectors += 1

    adversarial_vectors = 0
    random_h_vectors = 0
    random_score_vectors = 0
    rng = random.Random(seed)
    for gallery_size in range(1, MAX_GALLERY_SIZE + 1):
        adversaries = [
            [4] * gallery_size,
            [15] * gallery_size,
            [3] * gallery_size,
            [0] * gallery_size,
            [index % 16 for index in range(gallery_size)],
            [15 - index % 16 for index in range(gallery_size)],
        ]
        for category in range(4):
            for position in {0, gallery_size // 2, gallery_size - 1}:
                values = [min(category + 1, 15)] * gallery_size
                values[position] = category
                adversaries.append(values)
        for h_values in adversaries:
            assert evaluate_top_category(
                h_values
            ).candidates == reference_top_candidates(h_values)
            adversarial_vectors += 1

        for _ in range(random_cases_per_size):
            h_values = [rng.randrange(16) for _ in range(gallery_size)]
            assert evaluate_top_category(
                h_values
            ).candidates == reference_top_candidates(h_values)
            random_h_vectors += 1

            scores = [rng.randrange(SCORE_DOMAIN_SIZE) for _ in range(gallery_size)]
            assert evaluate_exact_id(scores) == reference_exact_id(scores)
            random_score_vectors += 1

    return ValidationSummary(
        exhaustive_h_through=exhaustive_h_through,
        exhaustive_h_vectors=exhaustive_vectors,
        gallery_sizes_checked=MAX_GALLERY_SIZE,
        adversarial_vectors=adversarial_vectors,
        random_h_vectors=random_h_vectors,
        random_score_vectors=random_score_vectors,
        seed=seed,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exhaustive-h-through", type=int, default=4)
    parser.add_argument("--random-cases-per-size", type=int, default=8)
    parser.add_argument("--seed", type=int, default=DEFAULT_VALIDATION_SEED)
    args = parser.parse_args()
    summary = validate_model(
        exhaustive_h_through=args.exhaustive_h_through,
        random_cases_per_size=args.random_cases_per_size,
        seed=args.seed,
    )
    payload = {
        "status": {
            "clear_semantics_validated": True,
            "structural_counts_only": True,
            "fhe_validated": False,
            "measured_latency": False,
        },
        "validation": asdict(summary),
        "classifier_extraction_contract": asdict(CLASSIFIER_EXTRACTION_CONTRACT),
        "lut_stage_contracts": [asdict(contract) for contract in lut_stage_contracts()],
        "a33_top_n127": asdict(a33_top_category_breakdown(127)),
        "a34_top_n127": asdict(a34_top_category_counts(127)),
        "standalone_top_n127_savings": asdict(a34_top_standalone_savings_n127()),
        "terminal_b8_sample_n127_savings": asdict(
            omitted_terminal_b8_sample_savings(127)
        ),
        "top_only_n127_projection": asdict(a34_top_only_n127_projection()),
        "combined_clear_scan_n127_projection": asdict(
            combined_n127_projection(A34_SCAN_OUTPUT_CLEAR_MODEL_N127)
        ),
        "base16_scan_output_n127_projection": asdict(
            base16_scan_output_projection_n127()
        ),
        "combined_base16_scan_n127_projection": asdict(
            combined_n127_projection(A34_SCAN_OUTPUT_BASE16_PROJECTION_N127)
        ),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
