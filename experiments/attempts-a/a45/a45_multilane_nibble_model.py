#!/usr/bin/env python3
"""Static model for the isolated A45 multilane/nibble proposal.

This module performs only integer, torus-layout, clear-semantic, structural-count,
and conservative raw-L1 checks.  It does not import TFHE, compile Rust, generate a
key, execute FHE, or establish an end-to-end probability-of-failure bound.

The proposed honest-client packing uses three disjoint 512-coefficient lanes of a
single N=2048 GLWE:

* full score at Delta=2^52;
* score modulo 16 at Delta=2^60;
* score modulo 256 at Delta=2^56.

A fourth 512-coefficient lane also fits and is included in the isolation proof,
although the clear pipeline does not assign it a meaning.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass


POLYNOMIAL_SIZE = 2_048
PROBE_DIM = 512
LANE_OFFSETS = (0, 512, 1_024, 1_536)
ACTIVE_LANE_OFFSETS = LANE_OFFSETS[:3]
FULL_DELTA_LOG = 52
LOW_DELTA_LOG = 60
MID_DELTA_LOG = 56
STANDARD_P16_DELTA_LOG = 59
TORUS_BITS = 64
TORUS_MODULUS = 1 << TORUS_BITS
TORUS_MASK = TORUS_MODULUS - 1
SCORE_DOMAIN_SIZE = 4_096
MAX_GALLERY_SIZE = 128

CURRENT_PRESET = "V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64"
A44_PRESET = "V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64"
CURRENT_MAX_NOISE = 5
A44_MAX_NOISE = 15
CURRENT_LOG2_P_FAIL = -71.625
A44_LOG2_P_FAIL = -64.088
CURRENT_GLWE_TUNIFORM_BOUND_LOG = 17
A44_GLWE_GAUSSIAN_STD = 2.845267479601915e-15
MAX_TEMPLATE_NORM2 = 1_022
MAX_TEMPLATE_L1 = 682
FROZEN_A38_TOP_CLASSIFIER_MODULUS = 16
OPTIONAL_P8_TOP_CLASSIFIER_MODULUS = 8
A34_TOP_CODE_MODULUS = 32
A34_TOP_CLASSIFIER_CODES = (30, 28, 3, 31, 0, 0, 0, 0, 2, 4, 29, 1, 0, 0, 0, 0)


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

    def scale(self, factor: int) -> "PrimitiveCounts":
        return PrimitiveCounts(
            self.blind_rotations * factor,
            self.key_switches * factor,
            self.output_marginals * factor,
        )


@dataclass(frozen=True)
class LaneIsolationAudit:
    offsets: tuple[int, ...]
    target_degrees: tuple[int, ...]
    contribution_matrix: tuple[tuple[int, ...], ...]
    wrapped_contribution_matrix: tuple[tuple[int, ...], ...]
    diagonal_pairs_are_exact: bool
    selected_input_blocks_disjoint: bool
    all_four_lanes_isolated: bool


@dataclass(frozen=True)
class NoiseInput:
    name: str
    raw_l1: int
    open_margin_rotation_bins: int
    geometry: str

    def fits(self, maximum: int) -> bool:
        return self.raw_l1 <= maximum


@dataclass(frozen=True)
class ClearTrace:
    score: int
    low_nibble: int
    low_fold_bit: int
    low_recoded_u: int
    mid_nibble: int
    mid_fold_bit: int
    mid_recoded_u: int
    high_nibble: int
    bits_0_to_7: tuple[int, ...]
    full_torus: int
    low_torus: int
    mid_torus: int
    mid_residual_torus: int
    top_residual_torus: int
    max5_mid_low3_torus: int
    max5_mid_low3_recoded_torus: int
    max5_mid_recoded_u_torus: int


def torus_encode(value: int, delta_log: int) -> int:
    return (value << delta_log) & TORUS_MASK


def lut_open_half_box_rotation_bins(message_modulus: int) -> int:
    """Return the open center-to-boundary distance of the standard LUT boxes."""
    if (
        message_modulus <= 0
        or message_modulus & (message_modulus - 1)
        or message_modulus > POLYNOMIAL_SIZE
        or POLYNOMIAL_SIZE % message_modulus != 0
    ):
        raise ValueError(
            "message_modulus must be a power of two dividing the polynomial size"
        )
    return POLYNOMIAL_SIZE // message_modulus // 2


def a34_top_codes_are_p8_antiperiodic() -> bool:
    """Check the clear condition needed by an optional Delta=2^60 p8 LUT."""
    return all(
        A34_TOP_CLASSIFIER_CODES[value + 8]
        == (-A34_TOP_CLASSIFIER_CODES[value]) % A34_TOP_CODE_MODULUS
        for value in range(8)
    )


def negacyclic_monomial_div_sample(
    body: tuple[int, ...], monomial_degree: int, sample_degree: int
) -> int:
    """Model one ideal coefficient of ``body / X^monomial_degree`` in X^N+1."""
    size = len(body)
    if size == 0 or not 0 <= sample_degree < size:
        raise ValueError("invalid negacyclic polynomial or sample degree")
    turns, shift = divmod(monomial_degree, size)
    sign = -1 if turns % 2 else 1
    source_degree = sample_degree + shift
    if source_degree >= size:
        source_degree -= size
        sign = -sign
    return (sign * body[source_degree]) & TORUS_MASK


def fused_binary_center_outputs(alpha: int, beta: int, bit: int) -> tuple[int, int]:
    """Model the two ideal samples of the frozen fused-correction layout.

    This proves only center algebra for the public two-half accumulator used by
    A38.  It does not model modulus-switch error, KS/PBS noise, or a Rust call.
    """
    if bit not in (0, 1):
        raise ValueError("bit must be zero or one")
    half = POLYNOMIAL_SIZE // 2
    body = ((-alpha) & TORUS_MASK,) * half + ((-beta) & TORUS_MASK,) * half
    # The existing fused layout adds q/8 before blind rotation.  The two bit
    # centers therefore rotate by N/4 and N+N/4 in the 2N negacyclic domain.
    rotation = POLYNOMIAL_SIZE // 4 + bit * POLYNOMIAL_SIZE
    correction = (
        negacyclic_monomial_div_sample(body, rotation, 0) + alpha
    ) & TORUS_MASK
    boolean = (negacyclic_monomial_div_sample(body, rotation, half) + beta) & TORUS_MASK
    return correction, boolean


def ceil_div(value: int, divisor: int) -> int:
    return (value + divisor - 1) // divisor


def reduction_nodes(items: int, radix: int) -> int:
    nodes = 0
    while items > 1:
        items = ceil_div(items, radix)
        nodes += items
    return nodes


def reduction_nodes_forwarding_singletons(items: int, radix: int) -> int:
    """Count gates when a one-item tail is forwarded instead of refreshed."""
    nodes = 0
    while items > 1:
        full_groups, tail = divmod(items, radix)
        nodes += full_groups + int(tail >= 2)
        items = full_groups + int(tail != 0)
    return nodes


def exclusive_prefix_nodes(items: int, radix: int) -> int:
    if items <= 2:
        return 0
    if items <= radix:
        return items - 2
    totals = 0
    expansion = 0
    groups = 0
    for start in range(0, items, radix):
        length = min(radix, items - start)
        groups += 1
        totals += int(length > 1)
        expansion += max(0, length - 2) if start == 0 else length - 1
    return totals + expansion + exclusive_prefix_nodes(groups, radix)


def output_bit_positions(gallery_size: int) -> tuple[int, ...]:
    return tuple(
        bit
        for bit in range(gallery_size.bit_length())
        if any(((index + 1) >> bit) & 1 for index in range(gallery_size))
    )


def legacy_first_one_scan_nodes(items: int) -> int:
    groups = ceil_div(items, 3)
    group_totals = sum(min(3, items - start) > 1 for start in range(0, items, 3))
    return group_totals + exclusive_prefix_nodes(groups, 4) + items


def legacy_output_nodes(gallery_size: int) -> int:
    bit_nodes = 0
    positions = output_bit_positions(gallery_size)
    for bit in positions:
        contributors = sum(((index + 1) >> bit) & 1 for index in range(gallery_size))
        bit_nodes += max(1, reduction_nodes(contributors, 4))
    return bit_nodes + ceil_div(len(positions), 3)


def a38_counts(gallery_size: int) -> PrimitiveCounts:
    """Reproduce the frozen A38 structural formula."""
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError("gallery_size must be in 1..128")
    n = gallery_size
    old_total = (
        27 * n
        + 8 * reduction_nodes(n, 4)
        + legacy_first_one_scan_nodes(n)
        + legacy_output_nodes(n)
        - 1
    )
    old_low = 12 * n + 8 * reduction_nodes(n, 4)
    old_scan = legacy_first_one_scan_nodes(n) + legacy_output_nodes(n)
    new_low = 10 * n + 8 * reduction_nodes(n, 5)
    groups = ceil_div(n, 3)
    group_nodes = sum(min(3, n - start) > 1 for start in range(0, n, 3))
    prefix_nodes = exclusive_prefix_nodes(groups, 5)
    digit_nodes = 2 * reduction_nodes(groups, 5)
    new_scan = 2 * group_nodes + prefix_nodes + groups + digit_nodes
    blind_rotations = old_total - old_low - old_scan + new_low + new_scan
    return PrimitiveCounts(
        blind_rotations,
        blind_rotations - 3 * n,
        blind_rotations + 4 * n + groups,
    )


def a40_counts(gallery_size: int) -> PrimitiveCounts:
    """Project only the eight A36 OR trees from radix five to radix seven."""
    base = a38_counts(gallery_size)
    saved = 8 * (
        reduction_nodes(gallery_size, 5)
        - reduction_nodes_forwarding_singletons(gallery_size, 7)
    )
    delta = PrimitiveCounts(saved, saved, saved)
    return base - delta


A38_UPSTREAM_PER_TEMPLATE = PrimitiveCounts(12, 9, 16)

# Three low local corrections; a binary b3 fold+Boolean; two aggregate low
# corrections sharing one KS; three fused mid local correction+Boolean rotations;
# a binary b7 fold+Boolean; one aggregate mid correction; A34-top classifier.
A45_MAX15_STAGES = {
    "low_local_extract": PrimitiveCounts(3, 4, 3),
    "low_b3_fold_and_boolean": PrimitiveCounts(1, 0, 2),
    "low_aggregate_full_and_mid_separate_br_shared_ks": PrimitiveCounts(2, 1, 2),
    "mid_local_extract_with_b4_b6_booleans": PrimitiveCounts(3, 4, 6),
    "mid_b7_fold_and_boolean": PrimitiveCounts(1, 0, 2),
    "mid_aggregate_full": PrimitiveCounts(1, 1, 1),
    "a34_top_classifier": PrimitiveCounts(1, 1, 1),
}

# Optional upstream-only remediation for max-noise 5: obtain b7 directly from
# the fresh mid residual, fold it twice, recode m mod 8 to Delta=2^61, and then
# extract only three bits.  This does not repair the separate downstream A36
# raw-L1=10 obligation.
A45_MAX5_STAGES = {
    "low_local_extract": PrimitiveCounts(3, 4, 3),
    "low_b3_fold_and_boolean": PrimitiveCounts(1, 0, 2),
    "low_aggregate_full_and_mid_separate_br_shared_ks": PrimitiveCounts(2, 1, 2),
    "mid_b7_q2_fold_and_boolean_separate_br_shared_ks": PrimitiveCounts(2, 1, 2),
    "mid_low3_recode": PrimitiveCounts(1, 1, 1),
    "mid_low3_extract_with_b4_b5_booleans": PrimitiveCounts(2, 3, 4),
    "mid_b6_boolean": PrimitiveCounts(1, 0, 1),
    "mid_aggregate_full": PrimitiveCounts(1, 1, 1),
    "a34_top_classifier": PrimitiveCounts(1, 1, 1),
}

# Center algebra suggests that the q/2 fold and canonical Boolean in the
# optional max-5 remediation can use the same two-sample blind rotation.  Keep
# this as a separate candidate: no Rust accumulator or noisy FHE result exists.
A45_MAX5_SHARED_BR_CANDIDATE_STAGES = {
    **A45_MAX5_STAGES,
    "mid_b7_q2_fold_and_boolean_separate_br_shared_ks": PrimitiveCounts(1, 1, 2),
}


def sum_counts(stages: dict[str, PrimitiveCounts]) -> PrimitiveCounts:
    total = PrimitiveCounts(0, 0, 0)
    for counts in stages.values():
        total += counts
    return total


A45_MAX15_UPSTREAM_PER_TEMPLATE = sum_counts(A45_MAX15_STAGES)
A45_MAX5_UPSTREAM_PER_TEMPLATE = sum_counts(A45_MAX5_STAGES)
A45_MAX5_SHARED_BR_CANDIDATE_PER_TEMPLATE = sum_counts(
    A45_MAX5_SHARED_BR_CANDIDATE_STAGES
)


def a45_projected_counts(
    gallery_size: int, *, max5_remediation: bool, a40_radix7: bool
) -> PrimitiveCounts:
    baseline = a40_counts(gallery_size) if a40_radix7 else a38_counts(gallery_size)
    replacement = (
        A45_MAX5_UPSTREAM_PER_TEMPLATE
        if max5_remediation
        else A45_MAX15_UPSTREAM_PER_TEMPLATE
    )
    return baseline + (replacement - A38_UPSTREAM_PER_TEMPLATE).scale(gallery_size)


def enumerate_lane_isolation(
    offsets: tuple[int, ...] = LANE_OFFSETS,
) -> LaneIsolationAudit:
    """Enumerate every source-lane/template-coordinate pair for every target.

    A source coefficient is at ``offset+j``.  The reversed public template
    coefficient for coordinate ``i`` is at ``511-i``.  A contribution reaches
    target ``offset_target+511`` iff their raw degree is congruent to that target
    modulo N.  A raw degree >=N carries the usual negacyclic minus sign; the
    audit records such hits separately.
    """
    targets = tuple(offset + PROBE_DIM - 1 for offset in offsets)
    matrix: list[list[int]] = []
    wrapped_matrix: list[list[int]] = []
    diagonal_pairs_are_exact = True

    for target_lane, target_degree in enumerate(targets):
        row = []
        wrapped_row = []
        for source_lane, source_offset in enumerate(offsets):
            hits = 0
            wrapped_hits = 0
            for probe_coordinate in range(PROBE_DIM):
                source_degree = source_offset + probe_coordinate
                for template_coordinate in range(PROBE_DIM):
                    template_degree = PROBE_DIM - 1 - template_coordinate
                    raw_degree = source_degree + template_degree
                    if raw_degree % POLYNOMIAL_SIZE != target_degree:
                        continue
                    hits += 1
                    wrapped_hits += int(raw_degree >= POLYNOMIAL_SIZE)
                    if source_lane == target_lane and (
                        probe_coordinate != template_coordinate
                        or raw_degree != target_degree
                    ):
                        diagonal_pairs_are_exact = False
            row.append(hits)
            wrapped_row.append(wrapped_hits)
        matrix.append(row)
        wrapped_matrix.append(wrapped_row)

    expected = tuple(
        tuple(PROBE_DIM if row == column else 0 for column in range(len(offsets)))
        for row in range(len(offsets))
    )
    contribution_matrix = tuple(tuple(row) for row in matrix)
    wrapped_contribution_matrix = tuple(tuple(row) for row in wrapped_matrix)
    blocks = tuple(frozenset(range(offset, offset + PROBE_DIM)) for offset in offsets)
    disjoint = all(
        blocks[left].isdisjoint(blocks[right])
        for left in range(len(blocks))
        for right in range(left + 1, len(blocks))
    )
    return LaneIsolationAudit(
        offsets=offsets,
        target_degrees=targets,
        contribution_matrix=contribution_matrix,
        wrapped_contribution_matrix=wrapped_contribution_matrix,
        diagonal_pairs_are_exact=diagonal_pairs_are_exact,
        selected_input_blocks_disjoint=disjoint,
        all_four_lanes_isolated=(
            contribution_matrix == expected
            and not any(any(row) for row in wrapped_contribution_matrix)
            and diagonal_pairs_are_exact
            and disjoint
        ),
    )


def decode_folded_nibble(recoded_u: int) -> int:
    """Invert u=2*(nibble mod 8)+floor(nibble/8)."""
    if not 0 <= recoded_u < 16:
        raise ValueError("recoded nibble must be in 0..15")
    return (recoded_u >> 1) + 8 * (recoded_u & 1)


def folded_nibble_code(nibble: int) -> int:
    if not 0 <= nibble < 16:
        raise ValueError("nibble must be in 0..15")
    return 2 * (nibble & 7) + (nibble >> 3)


def clear_trace(score: int) -> ClearTrace:
    if not 0 <= score < SCORE_DOMAIN_SIZE:
        raise ValueError("score must be in 0..4095")

    low = score & 0xF
    mid_byte = score & 0xFF
    mid = (score >> 4) & 0xF
    high = score >> 8
    b3 = low >> 3
    b7 = mid >> 3
    low_u = folded_nibble_code(low)
    mid_u = folded_nibble_code(mid)

    full_torus = torus_encode(score, FULL_DELTA_LOG)
    low_torus = torus_encode(low, LOW_DELTA_LOG)
    mid_torus = torus_encode(mid_byte, MID_DELTA_LOG)

    low_fold = torus_encode(15 * b3, STANDARD_P16_DELTA_LOG)
    low_u_torus = (low_torus - low_fold) & TORUS_MASK
    assert low_u_torus == torus_encode(low_u, STANDARD_P16_DELTA_LOG)
    assert decode_folded_nibble(low_u) == low

    low_full_correction = torus_encode(low, FULL_DELTA_LOG)
    low_mid_correction = torus_encode(low, MID_DELTA_LOG)
    mid_residual = (mid_torus - low_mid_correction) & TORUS_MASK
    assert mid_residual == torus_encode(mid, LOW_DELTA_LOG)

    mid_fold = torus_encode(15 * b7, STANDARD_P16_DELTA_LOG)
    mid_u_torus = (mid_residual - mid_fold) & TORUS_MASK
    assert mid_u_torus == torus_encode(mid_u, STANDARD_P16_DELTA_LOG)
    assert decode_folded_nibble(mid_u) == mid

    mid_full_correction = torus_encode(mid, MID_DELTA_LOG)
    top_residual = (full_torus - low_full_correction - mid_full_correction) & TORUS_MASK
    assert top_residual == torus_encode(high, LOW_DELTA_LOG)

    # Optional max-5 remediation.  Remove b7*q/2, recode the remaining
    # three-bit value at Delta=2^61, and independently form u=2*a+b7 at
    # Delta=2^59 for the aggregate mid-to-full correction LUT.
    b7_q2 = torus_encode(16 * b7, STANDARD_P16_DELTA_LOG)
    b7_boolean = torus_encode(b7, STANDARD_P16_DELTA_LOG)
    mid_low3_torus = (mid_residual - b7_q2) & TORUS_MASK
    assert mid_low3_torus == torus_encode(mid & 7, LOW_DELTA_LOG)
    max5_mid_recoded_u_torus = (mid_residual - b7_q2 + b7_boolean) & TORUS_MASK
    assert max5_mid_recoded_u_torus == torus_encode(mid_u, STANDARD_P16_DELTA_LOG)

    return ClearTrace(
        score=score,
        low_nibble=low,
        low_fold_bit=b3,
        low_recoded_u=low_u,
        mid_nibble=mid,
        mid_fold_bit=b7,
        mid_recoded_u=mid_u,
        high_nibble=high,
        bits_0_to_7=tuple((score >> bit) & 1 for bit in range(8)),
        full_torus=full_torus,
        low_torus=low_torus,
        mid_torus=mid_torus,
        mid_residual_torus=mid_residual,
        top_residual_torus=top_residual,
        max5_mid_low3_torus=mid_low3_torus,
        max5_mid_low3_recoded_torus=torus_encode(mid & 7, 61),
        max5_mid_recoded_u_torus=max5_mid_recoded_u_torus,
    )


def direct_nibble_aggregate_is_antipodally_encodable(delta_log: int) -> bool:
    """Test the necessary affine anti-periodicity of one PBS output.

    With a public post-PBS offset A, a single extracted sample must satisfy
    Y(c+8)+Y(c)=2A for every c.  A varying pair sum rules the map out.
    """
    outputs = tuple(torus_encode(value, delta_log) for value in range(16))
    pair_sums = {
        (outputs[value] + outputs[value + 8]) & TORUS_MASK for value in range(8)
    }
    return len(pair_sums) == 1


def manylut_max_degree(total_plaintext_modulus: int, functions: int) -> int:
    if functions <= 0 or functions > total_plaintext_modulus // 2:
        raise ValueError("invalid number of ManyLUT functions")
    return total_plaintext_modulus // functions - 1


def aligned_shift_reuse_exists(source_delta_log: int, target_delta_log: int) -> bool:
    """Search every slot-aligned reuse of one full-margin degree-15 LUT.

    The search allows an arbitrary public offset on both outputs and every
    cyclic/negacyclic shift of the source table.  Values are represented in
    units of 2^52, so the torus modulus is 4096.  It is deliberately not a
    lower bound against every custom sub-standard-margin accumulator.
    """
    unit_log = min(source_delta_log, target_delta_log)
    modulus = 1 << (TORUS_BITS - unit_log)
    source_scale = 1 << (source_delta_log - unit_log)
    target_scale = 1 << (target_delta_log - unit_log)
    nibble_by_u = tuple(decode_folded_nibble(value) for value in range(16))
    source = tuple((value * source_scale) % modulus for value in nibble_by_u)
    target = tuple((value * target_scale) % modulus for value in nibble_by_u)

    for source_offset in range(modulus):
        lower_raw = tuple((value - source_offset) % modulus for value in source)
        extended = lower_raw + tuple((-value) % modulus for value in lower_raw)
        for shift in range(32):
            shifted = tuple(extended[(value + shift) % 32] for value in range(16))
            target_offset = (target[0] - shifted[0]) % modulus
            if all(
                (candidate + target_offset) % modulus == expected
                for candidate, expected in zip(shifted, target)
            ):
                return True
    return False


MAX15_NOISE_INPUTS = (
    NoiseInput("low_b0_selection", 0, 512, "binary correction plateau"),
    NoiseInput("low_b1_selection", 4, 512, "binary correction plateau"),
    NoiseInput("low_b2_selection", 4, 512, "binary correction plateau"),
    NoiseInput("low_b3_fold_and_boolean", 3, 512, "binary correction plateau"),
    NoiseInput("low_aggregate_full", 1, 64, "degree-15 p16 half-domain"),
    NoiseInput("low_aggregate_mid", 1, 64, "degree-15 p16 half-domain"),
    NoiseInput("mid_b4_selection", 8, 512, "binary correction plateau after shift 8"),
    NoiseInput("mid_b5_selection", 8, 512, "binary correction plateau after shift 4"),
    NoiseInput("mid_b6_selection", 6, 512, "binary correction plateau after shift 2"),
    NoiseInput("mid_b7_fold_and_boolean", 4, 512, "binary correction plateau"),
    NoiseInput("mid_aggregate_full", 2, 64, "degree-15 p16 half-domain"),
    NoiseInput(
        "a34_top_classifier",
        2,
        64,
        "frozen A38 p16 accumulator, even reachable slots",
    ),
)


MAX5_REMEDIATED_NOISE_INPUTS = (
    *MAX15_NOISE_INPUTS[:6],
    NoiseInput("mid_b7_q2_fold", 1, 128, "Delta=2^60 threshold"),
    NoiseInput("mid_b7_boolean", 1, 128, "Delta=2^60 threshold"),
    NoiseInput("mid_low3_recode", 2, 128, "reachable values 0..7 at Delta=2^60"),
    NoiseInput("mid_b4_selection", 4, 512, "Delta=2^61 binary correction plateau"),
    NoiseInput("mid_b5_selection", 4, 512, "Delta=2^61 binary correction plateau"),
    NoiseInput("mid_b6_boolean", 3, 512, "Delta=2^61 binary correction plateau"),
    NoiseInput("mid_aggregate_full", 3, 64, "degree-15 p16 half-domain"),
    NoiseInput(
        "a34_top_classifier",
        2,
        64,
        "frozen A38 p16 accumulator, even reachable slots",
    ),
)


def initial_score_support() -> dict[str, object]:
    current_max_error = 2 * MAX_TEMPLATE_L1 * (1 << CURRENT_GLWE_TUNIFORM_BOUND_LOG)
    radii = {
        "full_2^52": 1 << (FULL_DELTA_LOG - 1),
        "mid_2^56": 1 << (MID_DELTA_LOG - 1),
        "low_2^60": 1 << (LOW_DELTA_LOG - 1),
    }
    current_slack = {
        name: math.log2(radius / current_max_error) for name, radius in radii.items()
    }
    gaussian_sigma = 2 * math.sqrt(MAX_TEMPLATE_NORM2) * A44_GLWE_GAUSSIAN_STD
    gaussian_sigma_ratios = {
        name: (radius / TORUS_MODULUS) / gaussian_sigma
        for name, radius in radii.items()
    }
    return {
        "current_tuniform_max_error_torus_units": current_max_error,
        "current_tuniform_slack_log2": current_slack,
        "a44_gaussian_score_sigma_normalized": gaussian_sigma,
        "a44_gaussian_half_step_sigma_ratios": gaussian_sigma_ratios,
        "a44_gaussian_has_deterministic_support_bound": False,
    }


def validate() -> dict[str, object]:
    lane_audit = enumerate_lane_isolation()
    assert lane_audit.all_four_lanes_isolated
    assert lane_audit.contribution_matrix == (
        (512, 0, 0, 0),
        (0, 512, 0, 0),
        (0, 0, 512, 0),
        (0, 0, 0, 512),
    )

    for score in range(SCORE_DOMAIN_SIZE):
        trace = clear_trace(score)
        assert trace.bits_0_to_7 == tuple((score >> bit) & 1 for bit in range(8))
        assert trace.top_residual_torus == torus_encode(score >> 8, LOW_DELTA_LOG)

    folded_order = tuple(folded_nibble_code(nibble) for nibble in range(16))
    assert folded_order == tuple(range(0, 16, 2)) + tuple(range(1, 16, 2))
    assert folded_order != tuple(range(16))

    assert not direct_nibble_aggregate_is_antipodally_encodable(FULL_DELTA_LOG)
    assert not direct_nibble_aggregate_is_antipodally_encodable(MID_DELTA_LOG)
    assert manylut_max_degree(16, 2) == 7
    assert not aligned_shift_reuse_exists(FULL_DELTA_LOG, MID_DELTA_LOG)
    assert not aligned_shift_reuse_exists(MID_DELTA_LOG, FULL_DELTA_LOG)

    assert A45_MAX15_UPSTREAM_PER_TEMPLATE == PrimitiveCounts(12, 11, 17)
    assert A45_MAX5_UPSTREAM_PER_TEMPLATE == PrimitiveCounts(14, 12, 17)
    assert A45_MAX5_SHARED_BR_CANDIDATE_PER_TEMPLATE == PrimitiveCounts(13, 12, 17)
    assert a38_counts(127) == PrimitiveCounts(3_655, 3_274, 4_206)
    assert a40_counts(127) == PrimitiveCounts(3_551, 3_170, 4_102)
    max15_r5 = a45_projected_counts(127, max5_remediation=False, a40_radix7=False)
    max15_r7 = a45_projected_counts(127, max5_remediation=False, a40_radix7=True)
    max5_r5 = a45_projected_counts(127, max5_remediation=True, a40_radix7=False)
    assert max15_r5 == PrimitiveCounts(3_655, 3_528, 4_333)
    assert max15_r7 == PrimitiveCounts(3_551, 3_424, 4_229)
    assert max5_r5 == PrimitiveCounts(3_909, 3_655, 4_333)

    frozen_top_margin = lut_open_half_box_rotation_bins(
        FROZEN_A38_TOP_CLASSIFIER_MODULUS
    )
    optional_p8_top_margin = lut_open_half_box_rotation_bins(
        OPTIONAL_P8_TOP_CLASSIFIER_MODULUS
    )
    assert frozen_top_margin == 64
    assert optional_p8_top_margin == 128
    assert a34_top_codes_are_p8_antiperiodic()

    direct_fold_alpha = 15 * (1 << (STANDARD_P16_DELTA_LOG - 1))
    boolean_beta = 1 << (STANDARD_P16_DELTA_LOG - 1)
    assert fused_binary_center_outputs(direct_fold_alpha, boolean_beta, 0) == (0, 0)
    assert fused_binary_center_outputs(direct_fold_alpha, boolean_beta, 1) == (
        15 << STANDARD_P16_DELTA_LOG,
        1 << STANDARD_P16_DELTA_LOG,
    )
    q2_fold_alpha = 1 << (TORUS_BITS - 2)
    assert fused_binary_center_outputs(q2_fold_alpha, boolean_beta, 0) == (0, 0)
    assert fused_binary_center_outputs(q2_fold_alpha, boolean_beta, 1) == (
        1 << (TORUS_BITS - 1),
        1 << STANDARD_P16_DELTA_LOG,
    )

    max15_peak = max(item.raw_l1 for item in MAX15_NOISE_INPUTS)
    max5_peak = max(item.raw_l1 for item in MAX5_REMEDIATED_NOISE_INPUTS)
    assert max15_peak == 8
    assert max15_peak > CURRENT_MAX_NOISE
    assert max15_peak <= A44_MAX_NOISE
    assert max5_peak == 4
    assert max5_peak <= CURRENT_MAX_NOISE

    support = initial_score_support()
    assert support["current_tuniform_max_error_torus_units"] == 178_782_208

    conditional_log2_query = A44_LOG2_P_FAIL + math.log2(max15_r7.output_marginals)
    return {
        "status": "PASS",
        "scope": "static_clear_structural_only_no_fhe_no_end_to_end_pfail",
        "lane_isolation": asdict(lane_audit),
        "scores_exhausted": SCORE_DOMAIN_SIZE,
        "anti_periodicity": {
            "direct_low_to_full_single_sample": False,
            "direct_low_to_mid_single_sample": False,
            "folded_u_range": [0, 15],
            "folded_u_delta_log": STANDARD_P16_DELTA_LOG,
        },
        "available_views": {
            "low": {
                "value": "u_l=2*(l&7)+(l>>3)",
                "delta_log": 59,
                "degree": 15,
                "numeric_order_preserving": False,
                "fresh": False,
                "numeric_standard_p16_requires_inverse_pbs": True,
            },
            "mid": {
                "value": "u_m=2*(m&7)+(m>>3)",
                "delta_log": 59,
                "degree": 15,
                "numeric_order_preserving": False,
                "fresh": False,
                "numeric_standard_p16_requires_inverse_pbs": True,
            },
            "high": {
                "value": "h=x>>8",
                "delta_log": 60,
                "numeric_order_preserving": True,
                "fresh": False,
                "numeric_standard_p16_emitted": False,
                "current_consumer": "A34 categorical classifier",
            },
            "folded_order_for_numeric_nibbles_0_to_15": folded_order,
            "inverse": "d=(u>>1)+8*(u&1)",
        },
        "fusion": {
            "official_two_function_manylut_max_degree": manylut_max_degree(16, 2),
            "required_degree": 15,
            "slot_aligned_full_to_mid_reuse": False,
            "slot_aligned_mid_to_full_reuse": False,
            "full_then_clear_mul16_mid_first_shift_raw_l1": 128,
            "viable": "two blind rotations sharing one key switch",
        },
        "top_classifier_geometry": {
            "frozen_a38_message_modulus": FROZEN_A38_TOP_CLASSIFIER_MODULUS,
            "frozen_a38_open_half_box_rotation_bins": frozen_top_margin,
            "optional_p8_message_modulus": OPTIONAL_P8_TOP_CLASSIFIER_MODULUS,
            "optional_p8_open_half_box_rotation_bins": optional_p8_top_margin,
            "optional_p8_clear_antiperiodicity": True,
            "optional_p8_materialized_or_fhe_proved": False,
        },
        "max5_shared_br_hypothesis": {
            "q2_fold_and_boolean_center_algebra": True,
            "candidate_upstream_per_template": asdict(
                A45_MAX5_SHARED_BR_CANDIDATE_PER_TEMPLATE
            ),
            "credited_to_reported_projections": False,
            "rust_accumulator_materialized": False,
            "noisy_fhe_validated": False,
        },
        "upstream_per_template": {
            "a38": asdict(A38_UPSTREAM_PER_TEMPLATE),
            "a45_max15": asdict(A45_MAX15_UPSTREAM_PER_TEMPLATE),
            "a45_max5_remediation": asdict(A45_MAX5_UPSTREAM_PER_TEMPLATE),
        },
        "projected_n127": {
            "a45_max15_radix5": asdict(max15_r5),
            "a45_max15_a40_radix7": asdict(max15_r7),
            "a45_max5_radix5": asdict(max5_r5),
        },
        "raw_l1": {
            "direct_peak": max15_peak,
            "direct_fits_current_max5": False,
            "direct_fits_a44_max15": True,
            "max5_remediation_peak": max5_peak,
            "max5_remediation_fits_current_max5_upstream_only": True,
            "downstream_a36_raw_l1_10_still_open_under_max5": True,
        },
        "initial_score": support,
        "conditional_union_only_not_a_proved_bound": {
            "marginals": max15_r7.output_marginals,
            "per_event_log2_p_fail": A44_LOG2_P_FAIL,
            "query_log2": conditional_log2_query,
            "query_probability": max15_r7.output_marginals * 2.0**A44_LOG2_P_FAIL,
        },
        "open_obligations": [
            "raw_custom_lut_equivalence_to_the_selected_shortint_preset",
            "joint_provenance_for_multi_sample_outputs",
            "gaussian_initial_score_tail_replaces_tuniform_support_zero",
            "honest_client_lane_consistency_or_an_explicit_input_validity_proof",
            "terminal_two_lwe_p16_protocol_preferred_over_a38_delta2^56_decode",
            "component_and_end_to_end_fhe_validation_after_the_active_primary",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args()
    summary = validate()
    if arguments.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(
            "PASS,A45_multilane_nibble_model,"
            "lanes=4x512,scores=4096,"
            "direct_peak_L1=8,max15=true,max5=false,"
            "max5_remediation_peak_L1=4,"
            "N127_max15_radix7=3551/3424/4229,"
            "fused_low_corrections=false,end_to_end_pfail=false"
        )


if __name__ == "__main__":
    main()
