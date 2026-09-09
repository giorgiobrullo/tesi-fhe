#!/usr/bin/env python3
"""Static composition audit for the proposed post-A33 exact-ID components.

The composed route is:

1. the A34 top-category selector emits fresh Boolean candidates for the
   smallest admissible score category ``h = score >> 8``;
2. the non-fused A36 chunked selector resolves ``b7..b0`` and emits fresh
   ordinary Boolean candidates;
3. the A34 two-nibble scan/output selects the first surviving identity and
   linearly joins its two code-scale roots into the single output LWE;
4. radix five is used only for the surviving Boolean/one-hot reductions.

This module deliberately decomposes the measured A33 count into disjoint
stages before replacing anything.  In particular, it does not add standalone
savings: part of the A33 radix-five saving belongs to top and scan networks
that the other candidates replace.

The result is a clear-semantics, LUT-layout, scale, local-noise and structural
count audit.  It neither modifies nor executes the Rust core, generates keys,
runs FHE, estimates latency, nor establishes an end-to-end p-fail bound.
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import asdict, dataclass
from typing import Sequence

if __package__:
    from benchmark import a34_top_category_model as a34_top
    from benchmark import a34_two_nibble_scan_output_model as two_nibble
    from benchmark import a35_radix5_reduction_model as radix_model
    from benchmark import a36_chunked_candidate_model as a36
else:
    import a34_top_category_model as a34_top
    import a34_two_nibble_scan_output_model as two_nibble
    import a35_radix5_reduction_model as radix_model
    import a36_chunked_candidate_model as a36


MAX_GALLERY_SIZE = 128
SCORE_DOMAIN_SIZE = 4096
ACCEPT_THRESHOLD = 1023
RADIX4 = 4
RADIX5 = 5
GROUP_SIZE = 3
BOOL_DELTA_LOG = 59
CODE_DELTA_LOG = 56
DEFAULT_VALIDATION_SEED = 0xA34_A36_2026_0902


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
        result = PrimitiveCounts(
            self.blind_rotations - other.blind_rotations,
            self.key_switches - other.key_switches,
            self.output_marginals - other.output_marginals,
        )
        if min(asdict(result).values()) < 0:
            raise AssertionError("primitive-count subtraction became negative")
        return result


@dataclass(frozen=True)
class StageLedger:
    gallery_size: int
    radix: int
    shared_backbone: PrimitiveCounts
    top_category: PrimitiveCounts
    low_selection: PrimitiveCounts
    scan_output: PrimitiveCounts
    total: PrimitiveCounts


@dataclass(frozen=True)
class AblationRow:
    name: str
    total: PrimitiveCounts
    incremental_savings: PrimitiveCounts
    cumulative_savings: PrimitiveCounts


@dataclass(frozen=True)
class RadixOverlapAudit:
    a33_standalone_radix5_savings: PrimitiveCounts
    removed_a33_top_reduction_benefit: PrimitiveCounts
    replaced_a33_scan_benefit: PrimitiveCounts
    surviving_a36_low_benefit: PrimitiveCounts
    surviving_two_nibble_scan_benefit: PrimitiveCounts
    composed_radix5_savings: PrimitiveCounts
    naive_overstatement: PrimitiveCounts


@dataclass(frozen=True)
class ScaleContract:
    a34_top_candidate_scale_log: int
    a34_top_candidate_codes: tuple[int, ...]
    a36_initial_clear_multiplier: int
    a36_state_codes: tuple[int, ...]
    a36_final_candidate_scale_log: int
    a36_final_candidate_codes: tuple[int, ...]
    scan_candidate_scale_log: int
    selector_digit_scale_log: int
    final_code_scale_log: int
    fresh_code_roots: int
    wire_output_lwes: int
    compatible: bool


@dataclass(frozen=True)
class NoiseCompositionAudit:
    a34_top_max_local_l1: float
    a36_zero_and_refresh_normalized_l1: float
    a36_radix5_or_normalized_l1: float
    scan_output_max_local_l1: float
    conservative_limit: float
    zero_slack_stages: tuple[str, ...]
    a34_top_inherited_residual_noise_proved: bool
    final_code_scale_decode_pfail_proved: bool
    modulus_switch_half_bin_accounted_in_l1: bool
    shared_noise_paths_present: bool
    end_to_end_pfail_proved: bool
    locally_compatible: bool


@dataclass(frozen=True)
class A36Radix5OrContract:
    radix: int
    polynomial_size: int
    box_size: int
    plateau_start: int
    plateau_end: int
    reachable_input_codes: tuple[int, ...]
    output_codes: tuple[int, ...]
    target_antipode: int
    target_antipode_reachable: bool
    nominal_open_margin_bins: int
    input_l1: int
    normalized_l1: float
    valid: bool


@dataclass(frozen=True)
class CompositionTrace:
    scores: tuple[int, ...]
    top_candidates: tuple[bool, ...]
    low_candidates: tuple[bool, ...]
    radix4_two_nibble_code: int
    selected_radix_code: int
    reference_code: int
    radix: int


@dataclass(frozen=True)
class ValidationSummary:
    gallery_sizes_count_checked: int
    exhaustive_single_scores: int
    representative_pair_cases: int
    all_reject_cases: int
    tie_cases: int
    winner_positions_checked: int
    deterministic_random_cases: int
    boundary_cases: int
    total_semantic_cases: int
    seed: int


def _counts(value: object) -> PrimitiveCounts:
    return PrimitiveCounts(
        int(getattr(value, "blind_rotations")),
        int(getattr(value, "key_switches")),
        int(getattr(value, "output_marginals")),
    )


def _single_output_counts(nodes: int) -> PrimitiveCounts:
    if nodes < 0:
        raise ValueError("node count cannot be negative")
    return PrimitiveCounts(nodes, nodes, nodes)


def _validate_gallery_size(gallery_size: int) -> None:
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError(f"gallery size must be in 1..{MAX_GALLERY_SIZE}")


def _validate_radix(radix: int) -> None:
    if radix not in (RADIX4, RADIX5):
        raise ValueError("only radix four and five are audited")


def reduction_nodes(items: int, radix: int) -> int:
    _validate_radix(radix)
    return radix_model.reduction_topology(items, radix=radix).blind_rotations


def a33_top_counts(gallery_size: int, radix: int) -> PrimitiveCounts:
    """A33 b9/b8 admission/category network, with its own OR reductions."""
    _validate_gallery_size(gallery_size)
    _validate_radix(radix)
    pairs = (gallery_size + 1) // 2
    reduction = reduction_nodes(gallery_size, radix)
    pair_reduction = reduction_nodes(pairs, radix)
    return PrimitiveCounts(
        4 * gallery_size + pairs + reduction + pair_reduction,
        3 * gallery_size + pairs + reduction + pair_reduction,
        5 * gallery_size + pairs + reduction + pair_reduction,
    )


def a33_low_selection_counts(gallery_size: int, radix: int) -> PrimitiveCounts:
    """Eight zero tests, four alternating updates, and eight OR trees."""
    _validate_gallery_size(gallery_size)
    nodes = 12 * gallery_size + 8 * reduction_nodes(gallery_size, radix)
    return _single_output_counts(nodes)


def a36_low_selection_counts(gallery_size: int, radix: int) -> PrimitiveCounts:
    """Eight zero tests, two chunk refreshes, and eight OR trees."""
    _validate_gallery_size(gallery_size)
    a36_radix5_or_contract(radix)
    nodes = 10 * gallery_size + 8 * reduction_nodes(gallery_size, radix)
    return _single_output_counts(nodes)


def a33_ledger(gallery_size: int, radix: int) -> StageLedger:
    """Decompose A33 into disjoint stages instead of summing optimizations."""
    _validate_gallery_size(gallery_size)
    _validate_radix(radix)
    source = radix_model.a33_counts(gallery_size, radix=radix)
    total = _counts(source.whole_core)
    top = a33_top_counts(gallery_size, radix)
    low = a33_low_selection_counts(gallery_size, radix)
    scan = _counts(source.scan_output)
    shared = total - top - low - scan
    return StageLedger(gallery_size, radix, shared, top, low, scan, total)


def a34_top_counts(gallery_size: int) -> PrimitiveCounts:
    return _counts(a34_top.a34_top_category_counts(gallery_size).total)


def two_nibble_scan_counts(gallery_size: int, radix: int) -> PrimitiveCounts:
    _validate_gallery_size(gallery_size)
    _validate_radix(radix)
    modeled = radix_model.a34_counts(
        gallery_size, radix=radix, two_nibble=True
    ).scan_output
    result = _counts(modeled)
    if radix == RADIX4:
        direct = two_nibble.a34_two_nibble_stage_counts(gallery_size)
        assert result == PrimitiveCounts(
            direct.scan_output_blind_rotations,
            direct.scan_output_key_switches,
            direct.scan_output_marginals,
        )
    return result


def composed_ledger(gallery_size: int, radix: int) -> StageLedger:
    """Return the only count projection admitted by the composition audit."""
    _validate_gallery_size(gallery_size)
    _validate_radix(radix)
    baseline_r4 = a33_ledger(gallery_size, RADIX4)
    # A34 retains corrections through b7 and removes only the terminal b8 KS.
    trimmed_shared = baseline_r4.shared_backbone - PrimitiveCounts(0, gallery_size, 0)
    top = a34_top_counts(gallery_size)
    low = a36_low_selection_counts(gallery_size, radix)
    scan = two_nibble_scan_counts(gallery_size, radix)
    total = trimmed_shared + top + low + scan
    return StageLedger(gallery_size, radix, trimmed_shared, top, low, scan, total)


def assert_stage_decomposition(gallery_size: int) -> None:
    """Cross-check every imported component and prove the radix overlap split."""
    _validate_gallery_size(gallery_size)
    baseline_r4 = a33_ledger(gallery_size, RADIX4)
    baseline_r5 = a33_ledger(gallery_size, RADIX5)
    if baseline_r4.shared_backbone != baseline_r5.shared_backbone:
        raise AssertionError("radix changed a stage outside the audited reductions")
    if a33_top_counts(gallery_size, RADIX4) != _counts(
        a34_top.a33_top_category_counts(gallery_size)
    ):
        raise AssertionError("A33 top-category decomposition drifted")

    a36_counts = a36.replacement_counts(gallery_size)
    radix4_or = _single_output_counts(8 * reduction_nodes(gallery_size, RADIX4))
    if a33_low_selection_counts(gallery_size, RADIX4) != (
        _counts(a36_counts.a33_alternating_updates) + radix4_or
    ):
        raise AssertionError("A33/A36 replacement boundary is inconsistent")
    if a36_low_selection_counts(gallery_size, RADIX4) != (
        _counts(a36_counts.a36_chunked_updates) + radix4_or
    ):
        raise AssertionError("A36 count omitted or duplicated the OR reductions")


def staged_ablation_n127() -> tuple[AblationRow, ...]:
    gallery_size = 127
    base = a33_ledger(gallery_size, RADIX4)
    trimmed_shared = base.shared_backbone - PrimitiveCounts(0, gallery_size, 0)
    top_total = (
        trimmed_shared
        + a34_top_counts(gallery_size)
        + base.low_selection
        + base.scan_output
    )
    scan_total = (
        trimmed_shared
        + a34_top_counts(gallery_size)
        + base.low_selection
        + two_nibble_scan_counts(gallery_size, RADIX4)
    )
    chunked_total = composed_ledger(gallery_size, RADIX4).total
    radix5_total = composed_ledger(gallery_size, RADIX5).total
    totals = (
        ("A33 radix-4", base.total),
        ("+ A34 top-category", top_total),
        ("+ A34 two-nibble scan/output", scan_total),
        ("+ A36 chunked low selector", chunked_total),
        ("+ radix-5 on surviving reductions", radix5_total),
    )
    rows = []
    previous = base.total
    for name, total in totals:
        rows.append(
            AblationRow(
                name=name,
                total=total,
                incremental_savings=previous - total
                if total != base.total
                else PrimitiveCounts(0, 0, 0),
                cumulative_savings=base.total - total,
            )
        )
        previous = total
    return tuple(rows)


def standalone_ablation_n127() -> tuple[AblationRow, ...]:
    """Each component alone, useful only as an overlap diagnostic."""
    gallery_size = 127
    base = a33_ledger(gallery_size, RADIX4)
    trimmed_shared = base.shared_backbone - PrimitiveCounts(0, gallery_size, 0)
    alternatives = (
        (
            "A34 top-category only",
            trimmed_shared
            + a34_top_counts(gallery_size)
            + base.low_selection
            + base.scan_output,
        ),
        (
            "A34 two-nibble scan/output only",
            base.shared_backbone
            + base.top_category
            + base.low_selection
            + two_nibble_scan_counts(gallery_size, RADIX4),
        ),
        (
            "A36 chunked low selector only",
            base.shared_backbone
            + base.top_category
            + a36_low_selection_counts(gallery_size, RADIX4)
            + base.scan_output,
        ),
        ("radix-5 only", a33_ledger(gallery_size, RADIX5).total),
    )
    return tuple(
        AblationRow(name, total, base.total - total, base.total - total)
        for name, total in alternatives
    )


def radix_overlap_audit_n127() -> RadixOverlapAudit:
    gallery_size = 127
    base_r4 = a33_ledger(gallery_size, RADIX4)
    base_r5 = a33_ledger(gallery_size, RADIX5)
    top_benefit = base_r4.top_category - base_r5.top_category
    old_scan_benefit = base_r4.scan_output - base_r5.scan_output
    new_scan_benefit = two_nibble_scan_counts(
        gallery_size, RADIX4
    ) - two_nibble_scan_counts(gallery_size, RADIX5)
    replaced_scan_benefit = old_scan_benefit - new_scan_benefit
    low_benefit = a36_low_selection_counts(
        gallery_size, RADIX4
    ) - a36_low_selection_counts(gallery_size, RADIX5)
    composed_benefit = (
        composed_ledger(gallery_size, RADIX4).total
        - composed_ledger(gallery_size, RADIX5).total
    )
    standalone = base_r4.total - base_r5.total
    overstatement = standalone - composed_benefit
    assert overstatement == top_benefit + replaced_scan_benefit
    assert composed_benefit == low_benefit + new_scan_benefit
    return RadixOverlapAudit(
        a33_standalone_radix5_savings=standalone,
        removed_a33_top_reduction_benefit=top_benefit,
        replaced_a33_scan_benefit=replaced_scan_benefit,
        surviving_a36_low_benefit=low_benefit,
        surviving_two_nibble_scan_benefit=new_scan_benefit,
        composed_radix5_savings=composed_benefit,
        naive_overstatement=overstatement,
    )


def scale_contract() -> ScaleContract:
    top_extraction = a34_top.CLASSIFIER_EXTRACTION_CONTRACT
    assert top_extraction.retained_score_bits == tuple(range(8))
    assert top_extraction.subtracted_correction_bits == tuple(range(8))
    assert top_extraction.omitted_terminal_sample_bit == 8
    assert top_extraction.low_bits_retained_before_classifier
    assert a36.A33_SOURCE_WEIGHTS == (1, 1, 1, 1, 1, 8, 4, 2)
    assert a36.A36_BIT_WEIGHTS == (-2, -2, -2, -2, -2, 8, -4, -2)
    candidate_stage = next(
        stage for stage in a34_top.lut_stage_contracts() if stage.name == "candidate"
    )
    contract = ScaleContract(
        a34_top_candidate_scale_log=candidate_stage.output_delta_log,
        a34_top_candidate_codes=(0, 1),
        a36_initial_clear_multiplier=2,
        a36_state_codes=(0, 2),
        a36_final_candidate_scale_log=BOOL_DELTA_LOG,
        a36_final_candidate_codes=(0, 1),
        scan_candidate_scale_log=two_nibble.BOOL_DELTA_LOG,
        selector_digit_scale_log=two_nibble.BOOL_DELTA_LOG,
        final_code_scale_log=two_nibble.CODE_DELTA_LOG,
        fresh_code_roots=two_nibble.FINAL_CODE_OUTPUTS,
        wire_output_lwes=1,
        compatible=True,
    )
    assert contract.a34_top_candidate_scale_log == BOOL_DELTA_LOG
    assert contract.a36_final_candidate_scale_log == contract.scan_candidate_scale_log
    assert contract.selector_digit_scale_log == BOOL_DELTA_LOG
    assert contract.final_code_scale_log == CODE_DELTA_LOG
    return contract


def a36_radix5_or_body(radix: int = RADIX5) -> tuple[int, ...]:
    _validate_radix(radix)
    box = a36.P16_BOX_SIZE
    body = [0] * a36.POLYNOMIAL_SIZE
    body[box : (2 * radix + 1) * box] = [a36.ACTIVE_CODE] * (2 * radix * box)
    return tuple(body)


def a36_radix5_or_contract(radix: int = RADIX5) -> A36Radix5OrContract:
    _validate_radix(radix)
    body = a36_radix5_or_body(radix)
    reachable = tuple(range(0, 2 * radix + 1, 2))
    outputs = tuple(a36.sample_signed_code(body, code) for code in reachable)
    expected = (0,) + (a36.ACTIVE_CODE,) * radix
    if outputs != expected:
        raise AssertionError("A36 step-two OR has incorrect center semantics")
    for code, output in zip(reachable, expected):
        for error in range(-a36.P16_BOX_SIZE + 1, a36.P16_BOX_SIZE):
            if a36.sample_signed_code(body, code, error) != output:
                raise AssertionError(
                    "A36 radix OR lost its nominal open full-slot margin"
                )
    antipode = a36.ACTIVE_CODE + a36.P16
    normalized = radix / 2
    return A36Radix5OrContract(
        radix=radix,
        polynomial_size=a36.POLYNOMIAL_SIZE,
        box_size=a36.P16_BOX_SIZE,
        plateau_start=a36.P16_BOX_SIZE,
        plateau_end=(2 * radix + 1) * a36.P16_BOX_SIZE,
        reachable_input_codes=reachable,
        output_codes=outputs,
        target_antipode=antipode,
        target_antipode_reachable=antipode in reachable,
        nominal_open_margin_bins=a36.P16_BOX_SIZE,
        input_l1=radix,
        normalized_l1=normalized,
        valid=(outputs == expected and antipode not in reachable and normalized <= 5),
    )


def noise_composition_audit() -> NoiseCompositionAudit:
    top_l1 = float(max(stage.linear_l1 for stage in a34_top.lut_stage_contracts()))
    a36_noise = a36.noise_audit()
    a36_or = a36_radix5_or_contract()
    scan_noise = radix_model.noise_audit(RADIX5)
    limit = float(scan_noise.conservative_max_noise_level)
    zero_slack = []
    if a36_noise.worst_normalized_l1 == limit:
        zero_slack.append("A36 b4 zero-test/boundary refresh")
    if scan_noise.maximum_local_l1 == limit:
        zero_slack.append("radix-5 Boolean/prefix/digit/selector inputs")
    locally_compatible = (
        top_l1 <= limit
        and a36_noise.worst_normalized_l1 <= limit
        and a36_or.normalized_l1 <= limit
        and scan_noise.maximum_local_l1 <= limit
    )
    return NoiseCompositionAudit(
        a34_top_max_local_l1=top_l1,
        a36_zero_and_refresh_normalized_l1=a36_noise.worst_normalized_l1,
        a36_radix5_or_normalized_l1=a36_or.normalized_l1,
        scan_output_max_local_l1=float(scan_noise.maximum_local_l1),
        conservative_limit=limit,
        zero_slack_stages=tuple(zero_slack),
        a34_top_inherited_residual_noise_proved=False,
        final_code_scale_decode_pfail_proved=False,
        modulus_switch_half_bin_accounted_in_l1=False,
        shared_noise_paths_present=True,
        end_to_end_pfail_proved=False,
        locally_compatible=locally_compatible,
    )


def _canonical_scores(scores: Sequence[int]) -> tuple[int, ...]:
    values = tuple(scores)
    _validate_gallery_size(len(values))
    if any(
        not isinstance(value, int) or not 0 <= value < SCORE_DOMAIN_SIZE
        for value in values
    ):
        raise ValueError(f"scores must be integers in 0..{SCORE_DOMAIN_SIZE - 1}")
    return values


def reference_code(scores: Sequence[int]) -> int:
    values = _canonical_scores(scores)
    winner = min(range(len(values)), key=lambda index: (values[index], index))
    return winner + 1 if values[winner] <= ACCEPT_THRESHOLD else 0


def two_nibble_code_with_radix(candidates: Sequence[bool], radix: int) -> int:
    """Clear scan/output using the selected radix for prefix and digit trees."""
    _validate_radix(radix)
    canonical = tuple(bool(value) for value in candidates)
    _validate_gallery_size(len(canonical))
    groups = tuple(
        canonical[start : start + GROUP_SIZE]
        for start in range(0, len(canonical), GROUP_SIZE)
    )
    flags = tuple(any(group) for group in groups)
    prefixes = radix_model.exclusive_prefix_or(flags, radix=radix)
    low_digits = []
    high_digits = []
    for group_index, (group, flag, prefix) in enumerate(zip(groups, flags, prefixes)):
        if len(group) == 1:
            local_first = int(flag)
        else:
            c0 = int(group[0])
            c1 = int(group[1])
            local_first = two_nibble.LOCAL_FIRST_LUT[int(flag) + 2 * c0 + c1]
        selector_state = local_first + 4 * int(prefix)
        low, high = two_nibble.selector_lut(
            len(canonical), group_index, len(group)
        ).sample(selector_state)
        low_digits.append(low)
        high_digits.append(high)
    low = radix_model.reduce_one_hot_digits(low_digits, radix=radix)
    high = radix_model.reduce_one_hot_digits(high_digits, radix=radix)
    return low + 16 * high


def evaluate_composition(
    scores: Sequence[int], radix: int = RADIX5
) -> CompositionTrace:
    values = _canonical_scores(scores)
    _validate_radix(radix)
    top = a34_top.evaluate_top_category(tuple(score >> 8 for score in values))
    low = a36.evaluate_a36_chunked_candidates(
        top.candidates, tuple(score & 0xFF for score in values)
    )
    final_candidates = tuple(low.final_candidates)
    radix4_code = two_nibble.evaluate_a34_two_nibble(final_candidates).code
    selected_code = two_nibble_code_with_radix(final_candidates, radix)
    expected = reference_code(values)
    if not radix4_code == selected_code == expected:
        raise AssertionError(
            f"composed exact-ID mismatch: r4={radix4_code}, selected={selected_code}, expected={expected}"
        )
    return CompositionTrace(
        scores=values,
        top_candidates=tuple(top.candidates),
        low_candidates=final_candidates,
        radix4_two_nibble_code=radix4_code,
        selected_radix_code=selected_code,
        reference_code=expected,
        radix=radix,
    )


def validate_model(
    *,
    random_patterns_per_size: int = 2,
    seed: int = DEFAULT_VALIDATION_SEED,
) -> ValidationSummary:
    if random_patterns_per_size < 0:
        raise ValueError("random_patterns_per_size cannot be negative")
    for gallery_size in range(1, MAX_GALLERY_SIZE + 1):
        assert_stage_decomposition(gallery_size)
    scale_contract()
    if not a36_radix5_or_contract().valid:
        raise AssertionError("A36 radix-five OR contract is invalid")
    if not noise_composition_audit().locally_compatible:
        raise AssertionError("a local noise/LUT contract exceeds its audited limit")

    singles = 0
    for score in range(SCORE_DOMAIN_SIZE):
        evaluate_composition((score,), RADIX5)
        singles += 1

    representative_scores = tuple(
        high * 256 + suffix
        for high in range(16)
        for suffix in (0, 1, 127, 128, 254, 255)
    )
    pairs = 0
    for left in representative_scores:
        for right in representative_scores:
            evaluate_composition((left, right), RADIX5)
            pairs += 1

    all_reject = 0
    ties = 0
    winner_positions = 0
    random_cases = 0
    rng = random.Random(seed)
    for gallery_size in range(1, MAX_GALLERY_SIZE + 1):
        evaluate_composition((1024,) * gallery_size, RADIX5)
        all_reject += 1
        evaluate_composition((519,) * gallery_size, RADIX5)
        ties += 1
        for winner in range(gallery_size):
            values = [767] * gallery_size
            values[winner] = 512
            evaluate_composition(values, RADIX5)
            winner_positions += 1
        for _ in range(random_patterns_per_size):
            evaluate_composition(
                tuple(rng.randrange(SCORE_DOMAIN_SIZE) for _ in range(gallery_size)),
                RADIX5,
            )
            random_cases += 1

    boundary_vectors = (
        (1023,),
        (1024,),
        (1024, 1023),
        (1023, 1024),
        (768, 767),
        (767, 768),
        (519, 521, 519),
        tuple([767] * 126 + [766]),
        tuple([767] * 127 + [512]),
    )
    for values in boundary_vectors:
        evaluate_composition(values, RADIX5)

    total = (
        singles
        + pairs
        + all_reject
        + ties
        + winner_positions
        + random_cases
        + len(boundary_vectors)
    )
    return ValidationSummary(
        gallery_sizes_count_checked=MAX_GALLERY_SIZE,
        exhaustive_single_scores=singles,
        representative_pair_cases=pairs,
        all_reject_cases=all_reject,
        tie_cases=ties,
        winner_positions_checked=winner_positions,
        deterministic_random_cases=random_cases,
        boundary_cases=len(boundary_vectors),
        total_semantic_cases=total,
        seed=seed,
    )


def assert_n127_projection() -> None:
    baseline = a33_ledger(127, RADIX4)
    assert baseline.shared_backbone == PrimitiveCounts(1397, 1143, 1905)
    assert baseline.top_category == PrimitiveCounts(636, 509, 763)
    assert baseline.low_selection == PrimitiveCounts(1868, 1868, 1868)
    assert baseline.scan_output == PrimitiveCounts(372, 372, 372)
    assert baseline.total == PrimitiveCounts(4273, 3892, 4908)

    assert composed_ledger(127, RADIX4).total == PrimitiveCounts(3728, 3347, 4279)
    assert composed_ledger(127, RADIX5).total == PrimitiveCounts(3655, 3274, 4206)
    assert baseline.total - composed_ledger(127, RADIX5).total == PrimitiveCounts(
        618, 618, 702
    )

    overlap = radix_overlap_audit_n127()
    assert overlap.a33_standalone_radix5_savings == PrimitiveCounts(107, 107, 107)
    assert overlap.removed_a33_top_reduction_benefit == PrimitiveCounts(12, 12, 12)
    assert overlap.replaced_a33_scan_benefit == PrimitiveCounts(22, 22, 22)
    assert overlap.surviving_a36_low_benefit == PrimitiveCounts(64, 64, 64)
    assert overlap.surviving_two_nibble_scan_benefit == PrimitiveCounts(9, 9, 9)
    assert overlap.composed_radix5_savings == PrimitiveCounts(73, 73, 73)
    assert overlap.naive_overstatement == PrimitiveCounts(34, 34, 34)

    expected_staged = (
        PrimitiveCounts(4273, 3892, 4908),
        PrimitiveCounts(4144, 3763, 4652),
        PrimitiveCounts(3982, 3601, 4533),
        PrimitiveCounts(3728, 3347, 4279),
        PrimitiveCounts(3655, 3274, 4206),
    )
    assert tuple(row.total for row in staged_ablation_n127()) == expected_staged


def report(validation: ValidationSummary | None) -> dict[str, object]:
    assert_n127_projection()
    baseline = a33_ledger(127, RADIX4)
    composed = composed_ledger(127, RADIX5)
    return {
        "schema_version": 1,
        "model": "a34-a36-static-composability",
        "status": "clear/count composable; not built or FHE validated",
        "n127": {
            "a33_baseline": asdict(baseline),
            "composed_radix4": asdict(composed_ledger(127, RADIX4)),
            "composed_radix5": asdict(composed),
            "savings_from_a33": asdict(baseline.total - composed.total),
            "staged_ablation": [asdict(row) for row in staged_ablation_n127()],
            "standalone_ablation": [asdict(row) for row in standalone_ablation_n127()],
            "radix_overlap": asdict(radix_overlap_audit_n127()),
        },
        "contracts": {
            "scales": asdict(scale_contract()),
            "a36_radix5_or": asdict(a36_radix5_or_contract()),
            "noise": asdict(noise_composition_audit()),
            "separate_lut_families": [
                "A34 top-category binary min",
                "Boolean sign OR for radix-5 prefix/reductions",
                "A36 step-two raw OR with plateau [1,11)",
                "two-nibble p16 one-hot identity reduction",
            ],
            "shared_ciphertext_sources": [
                "A34 top retains exact b7..b0 before classifying h",
                "A36 reuses those same weighted ciphertexts without new extraction",
                "A34 top candidate PBS output is scaled 0/1 -> 0/2 for A36",
                "A36 final PBS restores 0/1 for the two-nibble scan",
            ],
            "end_to_end_pfail_proved": False,
        },
        "validation": asdict(validation) if validation is not None else None,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-validate", action="store_true")
    parser.add_argument("--random-patterns-per-size", type=int, default=2)
    parser.add_argument("--seed", type=int, default=DEFAULT_VALIDATION_SEED)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    validation = None
    if not args.no_validate:
        validation = validate_model(
            random_patterns_per_size=args.random_patterns_per_size,
            seed=args.seed,
        )
    print(json.dumps(report(validation), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
