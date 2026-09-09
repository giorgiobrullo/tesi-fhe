#!/usr/bin/env python3
"""Static model for grouping the A33 sparse signed flags without a scale change.

The frozen A33 classifier emits, for every template, a fresh phase in ``Z_32``:

* ``+w`` when ``h == 0``;
* ``-w`` when ``h == 4``;
* ``0`` otherwise.

A direct p=16 Boolean gate cannot combine three such phases.  The construction
modeled here instead uses two p=16 stages at the existing ``Delta=2^59``:

1. each triple uses weights ``(1, 3, 9)`` and one anti-periodic LUT, producing
   ``31`` when no member has ``h == 0`` and ``0`` or ``1`` otherwise;
2. up to five fresh triple summaries are added, offset by their public count,
   and refreshed to a canonical Boolean by one LUT.

Thus the second stage covers up to fifteen templates with linear L1 at most
five.  This module proves clear semantics, finite-search blockers, tail rules,
and structural primitive counts only.  It does not execute TFHE, change the
Rust core, or establish an end-to-end failure probability.
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import random
from dataclasses import asdict, dataclass
from functools import cache
from typing import Sequence


PHASE_MODULUS = 32
P16_INDEPENDENT_PHASES = 16
BOOL_DELTA_LOG = 59
STANDARD_HALF_SLOT_MARGIN_LOG = BOOL_DELTA_LOG - 1
SHORTINT_MAX_NOISE_LEVEL = 5
MAX_GALLERY_SIZE = 128
REDUCTION_RADIX = 4

TRIPLE_WEIGHTS = (1, 3, 9)
TRIPLE_SIZE = len(TRIPLE_WEIGHTS)
SECOND_STAGE_FANIN = SHORTINT_MAX_NOISE_LEVEL
TEMPLATES_PER_SECOND_STAGE = TRIPLE_SIZE * SECOND_STAGE_FANIN

# Independent p=16 coefficients.  Slots 16..31 are their additive opposites.
# The induced reachable outputs are exactly:
#   no h=0 -> {31}; at least one h=0 -> {0, 1}.
STAGE1_BASE_LUT = (31, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 31, 1)

# A common second-stage accumulator handles every public tail length k=1..5.
# After adding +k, all-negative summaries land at 0 and positive summaries at
# one of 1..2k, hence in the independent range 1..10.
STAGE2_BASE_LUT = tuple(int(1 <= phase <= 10) for phase in range(16))

A33_N127 = (4_273, 3_892, 4_908)
A34_TWO_NIBBLE_N127 = (4_111, 3_730, 4_789)
A36_N127_SAVINGS = (254, 254, 254)


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


@dataclass(frozen=True)
class AdmissionCounts:
    gallery_size: int
    first_stage_nodes: int
    second_stage_nodes: int
    final_reduction_nodes: int
    total: PrimitiveCounts


@dataclass(frozen=True)
class SearchAudit:
    direct_triple_weight_vectors: int
    direct_triple_offsets_per_vector: int
    direct_triple_solutions: int
    scalar_quadruple_weight_vectors: int
    scalar_quadruple_label_separable: int
    selected_intermediate_weights: tuple[int, int, int]
    selected_stage1_no_outputs: tuple[int, ...]
    selected_stage1_positive_outputs: tuple[int, ...]


@dataclass(frozen=True)
class ScaleAudit:
    current_flag_delta_log: int
    current_p32_slot_weights: tuple[int, int, int]
    current_p32_direct_offsets: tuple[int, ...]
    retuned_flag_delta_log: int
    retuned_p32_slot_weights: tuple[int, int, int]
    retuned_p32_direct_offsets: tuple[int, ...]
    retuned_half_slot_margin_log: int
    parameter_grid_is_preserved_by_retuning: bool
    p32_n127_nodes_with_radix4: int
    p16_two_stage_n127_nodes_with_radix4: int


@dataclass(frozen=True)
class ValidationSummary:
    signed_flag_cases: int
    stage1_cases: int
    stage2_cases: int
    exhaustive_small_gallery_cases: int
    deterministic_random_gallery_cases: int
    direct_triple_weight_vectors: int
    scalar_quadruple_weight_vectors: int
    seed: int


def _validate_h(h_value: int) -> None:
    if not isinstance(h_value, int) or not 0 <= h_value < 8:
        raise ValueError("h must be an integer in 0..7")


def signed_flag(h_value: int, weight: int) -> int:
    """Return the A33 signed-flag phase at the existing q/32 scale."""
    _validate_h(h_value)
    if not isinstance(weight, int) or weight % PHASE_MODULUS == 0:
        raise ValueError("weight must be nonzero modulo 32")
    reduced = weight % PHASE_MODULUS
    if h_value == 0:
        return reduced
    if h_value == 4:
        return (-reduced) % PHASE_MODULUS
    return 0


def apply_negacyclic_lut(
    base_lut: Sequence[int], phase: int, *, independent_phases: int = 16
) -> int:
    """Evaluate the exact anti-periodic extension of a PBS LUT."""
    if len(base_lut) != independent_phases:
        raise ValueError("base LUT length does not match its independent domain")
    modulus = 2 * independent_phases
    reduced = phase % modulus
    if reduced < independent_phases:
        return base_lut[reduced] % modulus
    return (-base_lut[reduced - independent_phases]) % modulus


def has_positive(h_values: Sequence[int]) -> bool:
    values = tuple(h_values)
    if not values:
        raise ValueError("a group must contain at least one h value")
    for value in values:
        _validate_h(value)
    return 0 in values


def stage1_input_phase(h_values: Sequence[int]) -> int:
    values = tuple(h_values)
    if not 1 <= len(values) <= TRIPLE_SIZE:
        raise ValueError("stage 1 accepts one to three h values")
    return sum(
        signed_flag(h_value, weight)
        for h_value, weight in zip(values, TRIPLE_WEIGHTS)
    ) % PHASE_MODULUS


def stage1_code(h_values: Sequence[int]) -> int:
    """Compress one (possibly short tail) triple to -1, 0, or +1."""
    return apply_negacyclic_lut(STAGE1_BASE_LUT, stage1_input_phase(h_values))


def stage2_input_phase(stage1_codes: Sequence[int]) -> int:
    codes = tuple(stage1_codes)
    if not 1 <= len(codes) <= SECOND_STAGE_FANIN:
        raise ValueError("stage 2 accepts one to five triple summaries")
    if any(code not in (0, 1, 31) for code in codes):
        raise ValueError("stage 2 received an unreachable stage-1 code")
    return (sum(codes) + len(codes)) % PHASE_MODULUS


def stage2_code(stage1_codes: Sequence[int]) -> int:
    """Canonicalize the OR of up to five triple summaries."""
    return apply_negacyclic_lut(STAGE2_BASE_LUT, stage2_input_phase(stage1_codes))


def grouped_admission(h_values: Sequence[int]) -> bool:
    """Evaluate the two-stage network and its final clear OR."""
    values = tuple(h_values)
    if not 1 <= len(values) <= MAX_GALLERY_SIZE:
        raise ValueError(f"gallery size must be in 1..{MAX_GALLERY_SIZE}")
    for value in values:
        _validate_h(value)
    triple_codes = tuple(
        stage1_code(values[start : start + TRIPLE_SIZE])
        for start in range(0, len(values), TRIPLE_SIZE)
    )
    block_flags = tuple(
        stage2_code(triple_codes[start : start + SECOND_STAGE_FANIN])
        for start in range(0, len(triple_codes), SECOND_STAGE_FANIN)
    )
    if any(flag not in (0, 1) for flag in block_flags):
        raise AssertionError("stage 2 did not emit canonical Booleans")
    return bool(any(block_flags))


def or_reduction_nodes(items: int, radix: int = REDUCTION_RADIX) -> int:
    if items <= 0:
        raise ValueError("an OR reduction requires at least one item")
    if radix < 2:
        raise ValueError("OR radix must be at least two")
    nodes = 0
    while items > 1:
        items = (items + radix - 1) // radix
        nodes += items
    return nodes


def a33_admission_counts(gallery_size: int) -> AdmissionCounts:
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError(f"gallery size must be in 1..{MAX_GALLERY_SIZE}")
    pairs = (gallery_size + 1) // 2
    reduction = or_reduction_nodes(pairs)
    total = pairs + reduction
    counts = PrimitiveCounts(total, total, total)
    return AdmissionCounts(gallery_size, pairs, 0, reduction, counts)


def a37_admission_counts(
    gallery_size: int, *, reduction_radix: int = REDUCTION_RADIX
) -> AdmissionCounts:
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError(f"gallery size must be in 1..{MAX_GALLERY_SIZE}")
    triples = (gallery_size + TRIPLE_SIZE - 1) // TRIPLE_SIZE
    blocks = (triples + SECOND_STAGE_FANIN - 1) // SECOND_STAGE_FANIN
    reduction = or_reduction_nodes(blocks, reduction_radix)
    total = triples + blocks + reduction
    counts = PrimitiveCounts(total, total, total)
    return AdmissionCounts(gallery_size, triples, blocks, reduction, counts)


def n127_projections() -> dict[str, PrimitiveCounts]:
    """Project only count-compatible combinations; none are FHE evidence."""
    a33 = PrimitiveCounts(*A33_N127)
    a34_scan = PrimitiveCounts(*A34_TWO_NIBBLE_N127)
    a36_savings = PrimitiveCounts(*A36_N127_SAVINGS)
    admission_savings = (
        a33_admission_counts(127).total - a37_admission_counts(127).total
    )
    return {
        "a37_on_a33": a33 - admission_savings,
        "a37_plus_a34_two_nibble": a34_scan - admission_savings,
        "a37_plus_a36_chunked": a33 - admission_savings - a36_savings,
        "a37_plus_a34_two_nibble_plus_a36_chunked": (
            a34_scan - admission_savings - a36_savings
        ),
    }


def _ternary_phase_labels(weights: Sequence[int], modulus: int) -> dict[int, set[int]]:
    labels: dict[int, set[int]] = {}
    for states in itertools.product((-1, 0, 1), repeat=len(weights)):
        phase = sum(state * weight for state, weight in zip(states, weights)) % modulus
        labels.setdefault(phase, set()).add(int(1 in states))
    return labels


def direct_negacyclic_offsets(
    weights: Sequence[int], *, independent_phases: int = P16_INDEPENDENT_PHASES
) -> tuple[int, ...]:
    """Return every offset allowing one canonical anti-periodic OR LUT."""
    modulus = 2 * independent_phases
    labels = _ternary_phase_labels(weights, modulus)
    if any(len(values) != 1 for values in labels.values()):
        return ()

    feasible = []
    for offset in range(modulus):
        requirements: dict[int, int] = {}
        for phase, values in labels.items():
            target = next(iter(values))
            shifted = (phase + offset) % modulus
            slot = shifted % independent_phases
            base_value = target if shifted < independent_phases else (-target) % modulus
            previous = requirements.setdefault(slot, base_value)
            if previous != base_value:
                break
        else:
            feasible.append(offset)
    return tuple(feasible)


def scalar_label_separable(weights: Sequence[int], *, modulus: int = 32) -> bool:
    """Whether the scalar phase retains the any-positive label at all."""
    return all(
        len(labels) == 1
        for labels in _ternary_phase_labels(weights, modulus).values()
    )


@cache
def search_audit() -> SearchAudit:
    """Exhaust all nonzero Z32 weights, modulo permutation symmetry."""
    residues = range(1, PHASE_MODULUS)
    direct_solutions = sum(
        bool(direct_negacyclic_offsets(weights))
        for weights in itertools.combinations_with_replacement(residues, 3)
    )

    separable_quadruples = sum(
        scalar_label_separable(weights)
        for weights in itertools.combinations_with_replacement(residues, 4)
    )

    selected_outputs = {False: set(), True: set()}
    for h_values in itertools.product(range(8), repeat=3):
        selected_outputs[has_positive(h_values)].add(stage1_code(h_values))

    return SearchAudit(
        direct_triple_weight_vectors=math.comb(31 + 3 - 1, 3),
        direct_triple_offsets_per_vector=PHASE_MODULUS,
        direct_triple_solutions=direct_solutions,
        scalar_quadruple_weight_vectors=math.comb(31 + 4 - 1, 4),
        scalar_quadruple_label_separable=separable_quadruples,
        selected_intermediate_weights=TRIPLE_WEIGHTS,
        selected_stage1_no_outputs=tuple(sorted(selected_outputs[False])),
        selected_stage1_positive_outputs=tuple(sorted(selected_outputs[True])),
    )


def scale_audit() -> ScaleAudit:
    """Compare the rejected direct p32 routes with the p16 construction."""
    current_grid_weights = tuple(2 * weight for weight in TRIPLE_WEIGHTS)
    retuned_weights = TRIPLE_WEIGHTS
    p32_direct_nodes = (
        math.ceil(127 / 3) + or_reduction_nodes(math.ceil(127 / 3))
    )
    p16_nodes = a37_admission_counts(127).total.blind_rotations
    return ScaleAudit(
        current_flag_delta_log=BOOL_DELTA_LOG,
        current_p32_slot_weights=current_grid_weights,
        current_p32_direct_offsets=direct_negacyclic_offsets(
            current_grid_weights, independent_phases=32
        ),
        retuned_flag_delta_log=BOOL_DELTA_LOG - 1,
        retuned_p32_slot_weights=retuned_weights,
        retuned_p32_direct_offsets=direct_negacyclic_offsets(
            retuned_weights, independent_phases=32
        ),
        retuned_half_slot_margin_log=BOOL_DELTA_LOG - 2,
        parameter_grid_is_preserved_by_retuning=False,
        p32_n127_nodes_with_radix4=p32_direct_nodes,
        p16_two_stage_n127_nodes_with_radix4=p16_nodes,
    )


def _validate_stage1() -> int:
    cases = 0
    for length in range(1, TRIPLE_SIZE + 1):
        for h_values in itertools.product(range(8), repeat=length):
            output = stage1_code(h_values)
            expected_domain = (0, 1) if has_positive(h_values) else (31,)
            if output not in expected_domain:
                raise AssertionError(
                    f"stage1 mismatch for {h_values}: {output} not in {expected_domain}"
                )
            cases += 1
    return cases


def _validate_stage2() -> int:
    cases = 0
    labeled_codes = ((31, False), (0, True), (1, True))
    for fanin in range(1, SECOND_STAGE_FANIN + 1):
        for states in itertools.product(labeled_codes, repeat=fanin):
            codes = tuple(code for code, _label in states)
            expected = int(any(label for _code, label in states))
            actual = stage2_code(codes)
            if actual != expected:
                raise AssertionError(
                    f"stage2 mismatch for {states}: expected {expected}, got {actual}"
                )
            cases += 1
    return cases


def validate_model(
    *, exhaustive_through: int = 12, random_per_size: int = 32, seed: int = 0xA37_2026
) -> ValidationSummary:
    if not 0 <= exhaustive_through <= MAX_GALLERY_SIZE:
        raise ValueError("exhaustive gallery bound is outside 0..128")
    if random_per_size < 0:
        raise ValueError("random case count cannot be negative")

    signed_cases = 0
    for weight in TRIPLE_WEIGHTS:
        for h_value in range(8):
            expected = weight if h_value == 0 else -weight if h_value == 4 else 0
            if signed_flag(h_value, weight) != expected % PHASE_MODULUS:
                raise AssertionError("signed classifier semantics diverged")
            signed_cases += 1

    stage1_cases = _validate_stage1()
    stage2_cases = _validate_stage2()

    exhaustive_cases = 0
    for gallery_size in range(1, exhaustive_through + 1):
        for mask in range(1 << gallery_size):
            # Alternate the two semantically negative classes to exercise both
            # -w and zero rather than reducing the gallery to Boolean phases.
            h_values = tuple(
                0 if (mask >> index) & 1 else 4 if index % 2 else 1
                for index in range(gallery_size)
            )
            if grouped_admission(h_values) != bool(mask):
                raise AssertionError(
                    f"exhaustive gallery mismatch N={gallery_size}, mask={mask}"
                )
            exhaustive_cases += 1

    rng = random.Random(seed)
    random_cases = 0
    for gallery_size in range(1, MAX_GALLERY_SIZE + 1):
        for _sample in range(random_per_size):
            h_values = tuple(rng.randrange(8) for _index in range(gallery_size))
            if grouped_admission(h_values) != has_positive(h_values):
                raise AssertionError(f"random gallery mismatch N={gallery_size}")
            random_cases += 1

    audit = search_audit()
    if audit.direct_triple_solutions != 0:
        raise AssertionError("a direct p16 triple unexpectedly became feasible")
    if audit.scalar_quadruple_label_separable != 0:
        raise AssertionError("a scalar four-flag sum unexpectedly retained the label")
    if audit.selected_stage1_no_outputs != (31,):
        raise AssertionError("stage1 negative output alphabet changed")
    if audit.selected_stage1_positive_outputs != (0, 1):
        raise AssertionError("stage1 positive output alphabet changed")

    expected_a33 = PrimitiveCounts(85, 85, 85)
    expected_a37 = PrimitiveCounts(56, 56, 56)
    if a33_admission_counts(127).total != expected_a33:
        raise AssertionError("A33 N=127 admission count changed")
    if a37_admission_counts(127).total != expected_a37:
        raise AssertionError("A37 N=127 admission count changed")
    if n127_projections()["a37_on_a33"] != PrimitiveCounts(4_244, 3_863, 4_879):
        raise AssertionError("A37 N=127 whole-core projection changed")

    scale = scale_audit()
    if scale.current_p32_direct_offsets:
        raise AssertionError("p32 reinterpretation unexpectedly fixed current q/32 flags")
    if not scale.retuned_p32_direct_offsets:
        raise AssertionError("retuned q/64 p32 comparison case is no longer feasible")

    return ValidationSummary(
        signed_flag_cases=signed_cases,
        stage1_cases=stage1_cases,
        stage2_cases=stage2_cases,
        exhaustive_small_gallery_cases=exhaustive_cases,
        deterministic_random_gallery_cases=random_cases,
        direct_triple_weight_vectors=audit.direct_triple_weight_vectors,
        scalar_quadruple_weight_vectors=audit.scalar_quadruple_weight_vectors,
        seed=seed,
    )


def report() -> dict[str, object]:
    validation = validate_model()
    a33 = a33_admission_counts(127)
    a37 = a37_admission_counts(127)
    return {
        "status": "clear_and_structural_only",
        "validation": asdict(validation),
        "search": asdict(search_audit()),
        "scale": asdict(scale_audit()),
        "stage1_base_lut": STAGE1_BASE_LUT,
        "stage2_base_lut": STAGE2_BASE_LUT,
        "noise": {
            "classifier_output_delta_log": BOOL_DELTA_LOG,
            "standard_half_slot_margin_log": STANDARD_HALF_SLOT_MARGIN_LOG,
            "stage1_linear_l1": TRIPLE_SIZE,
            "stage2_max_linear_l1": SECOND_STAGE_FANIN,
            "final_radix4_linear_l1": REDUCTION_RADIX,
            "shortint_max_noise_level": SHORTINT_MAX_NOISE_LEVEL,
        },
        "n127": {
            "a33_admission": asdict(a33),
            "a37_admission": asdict(a37),
            "admission_savings": asdict(a33.total - a37.total),
            "whole_core_projections": {
                name: asdict(counts) for name, counts in n127_projections().items()
            },
        },
        "fhe_validated": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compact", action="store_true", help="emit one-line JSON")
    args = parser.parse_args()
    print(
        json.dumps(
            report(),
            indent=None if args.compact else 2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
