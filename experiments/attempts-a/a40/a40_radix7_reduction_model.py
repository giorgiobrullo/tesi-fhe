#!/usr/bin/env python3
"""Clear and structural audit of the A40 radix-seven A36 reduction.

This model changes only the eight gallery-wide OR trees inside A38's A36
low-byte selector.  Their inputs are fresh step-two flags in ``{0, 2}`` at
``Delta_bool = 2^59``.  A raw p=16 accumulator can therefore accept seven
inputs while retaining the same open ``Delta_bool`` margin used by A36.

Singleton tails are forwarded unchanged.  They are already fresh PBS outputs,
so refreshing them cannot improve the local L1 invariant and only adds a blind
rotation.  No FHE execution, key use, or live-core modification occurs here.
"""

from __future__ import annotations

import argparse
import itertools
import json
import random
from dataclasses import asdict, dataclass
from functools import cache
from typing import Iterable, Sequence


MAX_GALLERY_SIZE = 128
SCORE_DOMAIN_SIZE = 4096
ACCEPT_THRESHOLD = 1023
SCORE_BITS = (7, 6, 5, 4, 3, 2, 1, 0)
A36_BIT_WEIGHTS = (-2, -2, -2, -2, -2, 8, -4, -2)
A36_CHUNK_END_LEVELS = (3, 7)

P16 = 16
SIGNED_PHASE_MODULUS = 2 * P16
POLYNOMIAL_SIZE = 2048
BOX_SIZE = POLYNOMIAL_SIZE // P16
BOOL_DELTA_LOG = 59
ACTIVE_CODE = 2
INACTIVE_CODE = 0
A38_RADIX = 5
A40_RADIX = 7
SHORTINT_MAX_NOISE_LEVEL = 5

A38_N127 = (3655, 3274, 4206)
A38_N127_STAGE_LEDGER = {
    "shared_backbone": (1397, 1016, 1905),
    "top_category": (507, 507, 507),
    "low_selection": (1550, 1550, 1550),
    "scan_output": (201, 201, 244),
}
CLASSIFIER_CODES = (30, 28, 3, 31, 0, 0, 0, 0, 2, 4, 29, 1, 0, 0, 0, 0)
DEFAULT_SEED = 0xA40_2026_0902


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


@dataclass(frozen=True)
class ReductionTopology:
    items: int
    radix: int
    level_widths: tuple[int, ...]
    level_pbs: tuple[int, ...]
    blind_rotations: int
    forwarded_singletons: int


@dataclass(frozen=True)
class RawOrAudit:
    radix: int
    reachable_count_codes: tuple[int, ...]
    plateau_rotation_interval: tuple[int, int]
    open_margin_rotations: int
    normalized_input_l1: float
    within_local_limit: bool
    radix_eight_count_code: int
    radix_eight_observed_output: int
    radix_eight_required_output: int
    radix_eight_impossible: bool


@dataclass(frozen=True)
class A40CountComparison:
    gallery_size: int
    a38_nodes_per_or_tree: int
    radix7_nodes_without_tail_elision: int
    a40_nodes_per_or_tree: int
    radix_change_saving: int
    singleton_elision_saving: int
    total_or_tree_saving: int
    a38_low_selection: PrimitiveCounts
    a40_low_selection: PrimitiveCounts
    a38_total: PrimitiveCounts
    a40_total: PrimitiveCounts
    total_saving: PrimitiveCounts


@dataclass(frozen=True)
class TopArityNegativeAudit:
    alphabets_checked: int
    candidate_compatible: int
    candidate_and_binary_compatible: int
    candidate_binary_and_ternary_compatible: int
    homogeneous_radix_three_exists: bool


@dataclass(frozen=True)
class ValidationSummary:
    raw_or_centers_checked: int
    raw_or_rotation_errors_per_center: int
    exhaustive_or_vectors: int
    gallery_reduction_cases: int
    exhaustive_score_galleries: int
    single_score_cases: int
    boundary_pair_cases: int
    gallery_tie_reject_and_winner_cases: int
    deterministic_random_score_galleries: int
    total_exact_id_cases: int
    seed: int


def _validate_gallery_size(gallery_size: int) -> None:
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError(f"gallery size must be in 1..{MAX_GALLERY_SIZE}")


def _negacyclic_coefficient(body: Sequence[int], degree: int) -> int:
    if len(body) != POLYNOMIAL_SIZE:
        raise ValueError("unexpected accumulator polynomial size")
    cycles, index = divmod(degree, POLYNOMIAL_SIZE)
    return -body[index] if cycles % 2 else body[index]


def _sample_code(body: Sequence[int], code: int, rotation_error: int = 0) -> int:
    return _negacyclic_coefficient(body, code * BOX_SIZE + rotation_error)


@cache
def radix7_or_body() -> tuple[int, ...]:
    """Return the raw p=16 body for sums of up to seven step-two flags."""
    body = [0] * POLYNOMIAL_SIZE
    body[BOX_SIZE : 15 * BOX_SIZE] = [ACTIVE_CODE] * (14 * BOX_SIZE)
    return tuple(body)


@cache
def active_step2_body() -> tuple[int, ...]:
    body = [0] * POLYNOMIAL_SIZE
    body[BOX_SIZE : 3 * BOX_SIZE] = [ACTIVE_CODE] * (2 * BOX_SIZE)
    return tuple(body)


@cache
def final_boolean_body() -> tuple[int, ...]:
    body = [0] * POLYNOMIAL_SIZE
    body[BOX_SIZE : 3 * BOX_SIZE] = [1] * (2 * BOX_SIZE)
    return tuple(body)


def raw_or_audit() -> RawOrAudit:
    body = radix7_or_body()
    reachable = tuple(2 * count for count in range(A40_RADIX + 1))
    for count, code in enumerate(reachable):
        expected = ACTIVE_CODE if count else INACTIVE_CODE
        for error in range(-BOX_SIZE + 1, BOX_SIZE):
            observed = _sample_code(body, code, error)
            if observed != expected:
                raise AssertionError(
                    f"radix-seven OR failed at count={count}, error={error}: {observed}"
                )

    # F(16)=-F(0)=0 for every negacyclic p=16 accumulator.  Eight active
    # step-two inputs sum exactly to code 16, so a radix-eight OR cannot use
    # this scalar layout regardless of how the independent body is filled.
    radix_eight_code = 2 * 8
    radix_eight_observed = _sample_code(body, radix_eight_code)
    return RawOrAudit(
        radix=A40_RADIX,
        reachable_count_codes=reachable,
        plateau_rotation_interval=(BOX_SIZE, 15 * BOX_SIZE),
        open_margin_rotations=BOX_SIZE,
        normalized_input_l1=A40_RADIX / 2,
        within_local_limit=A40_RADIX / 2 <= SHORTINT_MAX_NOISE_LEVEL,
        radix_eight_count_code=radix_eight_code,
        radix_eight_observed_output=radix_eight_observed,
        radix_eight_required_output=ACTIVE_CODE,
        radix_eight_impossible=radix_eight_observed != ACTIVE_CODE,
    )


def reduction_topology(
    items: int, *, radix: int, forward_singletons: bool
) -> ReductionTopology:
    if items <= 0:
        raise ValueError("reduction requires at least one item")
    if radix < 2:
        raise ValueError("radix must be at least two")
    original = items
    widths = [items]
    level_pbs: list[int] = []
    forwarded = 0
    while items > 1:
        full, tail = divmod(items, radix)
        groups = full + int(tail != 0)
        if forward_singletons:
            nodes = full + int(tail >= 2)
            forwarded += int(tail == 1)
        else:
            nodes = groups
        level_pbs.append(nodes)
        items = groups
        widths.append(items)
    return ReductionTopology(
        items=original,
        radix=radix,
        level_widths=tuple(widths),
        level_pbs=tuple(level_pbs),
        blind_rotations=sum(level_pbs),
        forwarded_singletons=forwarded,
    )


def _radix7_or_gate(values: Sequence[int]) -> int:
    if not 2 <= len(values) <= A40_RADIX:
        raise ValueError("a PBS OR node must have fan-in 2..7")
    if any(value not in (INACTIVE_CODE, ACTIVE_CODE) for value in values):
        raise ValueError("OR inputs must be fresh step-two flags")
    return _sample_code(radix7_or_body(), sum(values))


def reduce_step2(values: Sequence[int]) -> int:
    level = list(values)
    if not level or any(value not in (INACTIVE_CODE, ACTIVE_CODE) for value in level):
        raise ValueError("reduction needs non-empty step-two flags")
    while len(level) > 1:
        next_level = []
        for start in range(0, len(level), A40_RADIX):
            chunk = level[start : start + A40_RADIX]
            next_level.append(chunk[0] if len(chunk) == 1 else _radix7_or_gate(chunk))
        level = next_level
    return level[0]


def count_comparison_n127() -> A40CountComparison:
    old = reduction_topology(127, radix=A38_RADIX, forward_singletons=False)
    radix7_regular = reduction_topology(127, radix=A40_RADIX, forward_singletons=False)
    new = reduction_topology(127, radix=A40_RADIX, forward_singletons=True)
    per_tree = old.blind_rotations - new.blind_rotations
    total_saving = PrimitiveCounts(*(8 * per_tree,) * 3)
    ledger = {
        name: PrimitiveCounts(*counts) for name, counts in A38_N127_STAGE_LEDGER.items()
    }
    a38_total = (
        ledger["shared_backbone"]
        + ledger["top_category"]
        + ledger["low_selection"]
        + ledger["scan_output"]
    )
    if a38_total != PrimitiveCounts(*A38_N127):
        raise AssertionError("copied A38 stage ledger does not reconstruct its total")
    a40_low = PrimitiveCounts(*(10 * 127 + 8 * new.blind_rotations,) * 3)
    a40_total = (
        ledger["shared_backbone"]
        + ledger["top_category"]
        + a40_low
        + ledger["scan_output"]
    )
    if (
        PrimitiveCounts(
            a38_total.blind_rotations - a40_total.blind_rotations,
            a38_total.key_switches - a40_total.key_switches,
            a38_total.output_marginals - a40_total.output_marginals,
        )
        != total_saving
    ):
        raise AssertionError("A40 stage replacement and direct saving disagree")
    return A40CountComparison(
        gallery_size=127,
        a38_nodes_per_or_tree=old.blind_rotations,
        radix7_nodes_without_tail_elision=radix7_regular.blind_rotations,
        a40_nodes_per_or_tree=new.blind_rotations,
        radix_change_saving=8 * (old.blind_rotations - radix7_regular.blind_rotations),
        singleton_elision_saving=8
        * (radix7_regular.blind_rotations - new.blind_rotations),
        total_or_tree_saving=total_saving.blind_rotations,
        a38_low_selection=ledger["low_selection"],
        a40_low_selection=a40_low,
        a38_total=a38_total,
        a40_total=a40_total,
        total_saving=total_saving,
    )


def _top_candidates(scores: Sequence[int]) -> tuple[bool, ...]:
    high = tuple(score >> 8 for score in scores)
    minimum = min(high)
    if minimum >= 4:
        return (False,) * len(scores)
    return tuple(value == minimum for value in high)


def _low_byte_candidates(
    candidates: Sequence[bool], suffixes: Sequence[int]
) -> tuple[bool, ...]:
    if len(candidates) != len(suffixes) or not candidates:
        raise ValueError("candidate and suffix vectors must be non-empty and aligned")
    states = tuple(
        ACTIVE_CODE if candidate else INACTIVE_CODE for candidate in candidates
    )
    active_body = active_step2_body()
    final_body = final_boolean_body()
    for level, (bit_index, weight) in enumerate(zip(SCORE_BITS, A36_BIT_WEIGHTS)):
        bits = tuple((suffix >> bit_index) & 1 for suffix in suffixes)
        zero = tuple(
            _sample_code(active_body, state + weight * bit)
            for state, bit in zip(states, bits)
        )
        any_zero = reduce_step2(zero)
        updated = tuple(
            state + zero_flag - any_zero for state, zero_flag in zip(states, zero)
        )
        if level == A36_CHUNK_END_LEVELS[0]:
            states = tuple(_sample_code(active_body, state) for state in updated)
        elif level == A36_CHUNK_END_LEVELS[1]:
            states = tuple(_sample_code(final_body, state) for state in updated)
        else:
            states = updated
    return tuple(state == 1 for state in states)


def reference_exact_id(scores: Sequence[int]) -> int:
    values = tuple(scores)
    _validate_gallery_size(len(values))
    if any(
        not isinstance(value, int) or not 0 <= value < SCORE_DOMAIN_SIZE
        for value in values
    ):
        raise ValueError(f"scores must be integers in 0..{SCORE_DOMAIN_SIZE - 1}")
    winner = min(range(len(values)), key=lambda index: (values[index], index))
    return winner + 1 if values[winner] <= ACCEPT_THRESHOLD else 0


def evaluate_a40_exact_id(scores: Sequence[int]) -> int:
    values = tuple(scores)
    reference_exact_id(values)  # validation is shared with the reference.
    top = _top_candidates(values)
    low = _low_byte_candidates(top, tuple(score & 0xFF for score in values))
    return next((index + 1 for index, candidate in enumerate(low) if candidate), 0)


def _lut_realizable(rows: Iterable[tuple[int, int]]) -> bool:
    table: dict[int, int] = {}
    for phase, output in rows:
        phase %= SIGNED_PHASE_MODULUS
        output %= SIGNED_PHASE_MODULUS
        previous = table.setdefault(phase, output)
        if previous != output:
            return False
    return all(
        (phase ^ P16) not in table
        or table[phase ^ P16] == (-output) % SIGNED_PHASE_MODULUS
        for phase, output in table.items()
    )


def _candidate_compatible(codes: tuple[int, int, int, int]) -> bool:
    rows = []
    for rank, category_code in enumerate(codes):
        for high, classifier_code in enumerate(CLASSIFIER_CODES):
            selected = high == rank if rank < 3 else high == 3
            rows.append((classifier_code + category_code, int(selected)))
    return _lut_realizable(rows)


def _category_compositions(arity: int) -> Iterable[tuple[int, int, int, int]]:
    for first in range(arity + 1):
        for second in range(arity - first + 1):
            for third in range(arity - first - second + 1):
                yield first, second, third, arity - first - second - third


def _homogeneous_min_reducer(codes: tuple[int, int, int, int], arity: int) -> bool:
    rows = []
    for counts in _category_compositions(arity):
        minimum = next(index for index, count in enumerate(counts) if count)
        phase = sum(count * code for count, code in zip(counts, codes))
        rows.append((phase, codes[minimum]))
    return _lut_realizable(rows)


@cache
def top_radix3_negative_audit() -> TopArityNegativeAudit:
    """Exhaust the homogeneous four-code replacement of A34's binary reducer.

    The scope is intentionally narrow: one distinct Z32 code per ordered top
    category, the current classifier C, the current exact candidate predicate,
    and closed binary/ternary min LUTs whose output uses the same alphabet.
    """
    checked = candidate = binary = ternary = 0
    for codes in itertools.permutations(range(SIGNED_PHASE_MODULUS), 4):
        checked += 1
        if not _candidate_compatible(codes):
            continue
        candidate += 1
        if not _homogeneous_min_reducer(codes, 2):
            continue
        binary += 1
        if _homogeneous_min_reducer(codes, 3):
            ternary += 1
    return TopArityNegativeAudit(
        alphabets_checked=checked,
        candidate_compatible=candidate,
        candidate_and_binary_compatible=binary,
        candidate_binary_and_ternary_compatible=ternary,
        homogeneous_radix_three_exists=ternary != 0,
    )


def validate(
    *, seed: int = DEFAULT_SEED, include_top_search: bool = True
) -> ValidationSummary:
    audit = raw_or_audit()
    if not audit.within_local_limit or not audit.radix_eight_impossible:
        raise AssertionError("raw OR contract changed")

    exhaustive_or_vectors = 0
    for size in range(1, 13):
        for bits in itertools.product((0, 1), repeat=size):
            observed = reduce_step2(tuple(2 * bit for bit in bits))
            if observed != 2 * int(any(bits)):
                raise AssertionError(f"OR mismatch for {bits}")
            exhaustive_or_vectors += 1

    rng = random.Random(seed)
    gallery_reduction_cases = 0
    for size in range(1, MAX_GALLERY_SIZE + 1):
        patterns = [
            (0,) * size,
            (1,) * size,
            *((0,) * index + (1,) + (0,) * (size - index - 1) for index in range(size)),
        ]
        patterns.extend(tuple(rng.randrange(2) for _ in range(size)) for _ in range(4))
        for bits in patterns:
            observed = reduce_step2(tuple(2 * bit for bit in bits))
            if observed != 2 * int(any(bits)):
                raise AssertionError(f"gallery OR mismatch at N={size}")
            gallery_reduction_cases += 1

    score_alphabet = (0, 1, 255, 256, 767, 768, 1023, 1024)
    exhaustive_score_galleries = 0
    for size in range(1, 5):
        for scores in itertools.product(score_alphabet, repeat=size):
            if evaluate_a40_exact_id(scores) != reference_exact_id(scores):
                raise AssertionError(f"exhaustive exact-ID mismatch for {scores}")
            exhaustive_score_galleries += 1

    single_score_cases = 0
    for score in range(SCORE_DOMAIN_SIZE):
        if evaluate_a40_exact_id((score,)) != reference_exact_id((score,)):
            raise AssertionError(f"single-score mismatch at {score}")
        single_score_cases += 1

    boundaries = (0, 1, 15, 16, 255, 256, 767, 768, 1023, 1024, 4095)
    boundary_pair_cases = 0
    for scores in itertools.product(boundaries, repeat=2):
        if evaluate_a40_exact_id(scores) != reference_exact_id(scores):
            raise AssertionError(f"boundary-pair mismatch for {scores}")
        boundary_pair_cases += 1

    gallery_cases = 0
    for size in range(1, MAX_GALLERY_SIZE + 1):
        fixtures = [(777,) * size, (1024,) * size]
        fixtures.extend(
            (1000,) * index + (0,) + (1000,) * (size - index - 1)
            for index in range(size)
        )
        for scores in fixtures:
            if evaluate_a40_exact_id(scores) != reference_exact_id(scores):
                raise AssertionError(f"gallery exact-ID mismatch at N={size}")
            gallery_cases += 1

    random_cases = 0
    for _ in range(512):
        size = rng.randrange(1, MAX_GALLERY_SIZE + 1)
        scores = tuple(rng.randrange(SCORE_DOMAIN_SIZE) for _ in range(size))
        if evaluate_a40_exact_id(scores) != reference_exact_id(scores):
            raise AssertionError(f"random exact-ID mismatch at N={size}")
        random_cases += 1

    for size in range(1, MAX_GALLERY_SIZE + 1):
        old = reduction_topology(size, radix=A38_RADIX, forward_singletons=False)
        new = reduction_topology(size, radix=A40_RADIX, forward_singletons=True)
        if new.blind_rotations > old.blind_rotations:
            raise AssertionError(f"A40 reduction regressed at N={size}")

    comparison = count_comparison_n127()
    if comparison.a40_total != PrimitiveCounts(3551, 3170, 4102):
        raise AssertionError(f"A40 N=127 count drift: {comparison.a40_total}")

    if include_top_search:
        top = top_radix3_negative_audit()
        if top != TopArityNegativeAudit(863040, 544, 166, 0, False):
            raise AssertionError(f"top-category search drift: {top}")

    total = (
        exhaustive_score_galleries
        + single_score_cases
        + boundary_pair_cases
        + gallery_cases
        + random_cases
    )
    return ValidationSummary(
        raw_or_centers_checked=A40_RADIX + 1,
        raw_or_rotation_errors_per_center=2 * BOX_SIZE - 1,
        exhaustive_or_vectors=exhaustive_or_vectors,
        gallery_reduction_cases=gallery_reduction_cases,
        exhaustive_score_galleries=exhaustive_score_galleries,
        single_score_cases=single_score_cases,
        boundary_pair_cases=boundary_pair_cases,
        gallery_tie_reject_and_winner_cases=gallery_cases,
        deterministic_random_score_galleries=random_cases,
        total_exact_id_cases=total,
        seed=seed,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-top-search", action="store_true")
    args = parser.parse_args()
    summary = validate(include_top_search=not args.skip_top_search)
    payload = {
        "scope": "clear semantics and structural counts only; no FHE or keys",
        "raw_or": asdict(raw_or_audit()),
        "n127": asdict(count_comparison_n127()),
        "validation": asdict(summary),
    }
    if not args.skip_top_search:
        payload["top_radix3_negative_search"] = asdict(top_radix3_negative_audit())
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
