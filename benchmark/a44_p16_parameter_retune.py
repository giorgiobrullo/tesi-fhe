#!/usr/bin/env python3
"""Static audit of p16 TFHE parameter candidates for the A38/A41 graph.

The calculations in this module do not run TFHE.  They distinguish three
layers which must not be conflated:

* exact plaintext geometry and Boole union-bound arithmetic;
* the nominal per-table-lookup contract stated by a TFHE-rs parameter set;
* an end-to-end proof for this project's custom core-crypto graph.

The first layer is established here.  The second is recorded from the pinned
TFHE-rs sources.  The third remains conditional until every custom PBS input
is mapped to the parameter contract (or receives a separate proof).
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass


TORUS_BITS = 64
POLYNOMIAL_SIZE = 2_048
P16 = 16
A38_N127_BLIND_ROTATIONS = 3_655
A38_N127_KEY_SWITCHES = 3_274
A38_N127_OUTPUT_MARGINALS = 4_206


@dataclass(frozen=True)
class ParameterProfile:
    symbol: str
    tfhe_version: str
    bootstrap_kind: str
    lwe_dimension: int
    glwe_dimension: int
    polynomial_size: int
    lwe_noise: str
    glwe_noise: str
    pbs_base_log: int
    pbs_level: int
    ks_base_log: int
    ks_level: int
    message_modulus: int
    carry_modulus: int
    max_noise_level: int
    log2_p_fail: float
    algorithmic_cost: int | None
    grouping_factor: int | None = None
    deterministic_execution: bool | None = None
    modulus_switch: str = "standard"

    @property
    def total_plaintext_modulus(self) -> int:
        return self.message_modulus * self.carry_modulus

    @property
    def standard_delta(self) -> int:
        return (1 << (TORUS_BITS - 1)) // self.total_plaintext_modulus

    @property
    def standard_delta_log2(self) -> int:
        delta = self.standard_delta
        if delta <= 0 or delta & (delta - 1):
            raise ValueError("the standard delta is not a power of two")
        return delta.bit_length() - 1

    @property
    def raw_lut_box_width(self) -> int:
        if self.polynomial_size % self.total_plaintext_modulus:
            raise ValueError("plaintext modulus does not divide polynomial size")
        return self.polynomial_size // self.total_plaintext_modulus


@dataclass(frozen=True)
class CircuitRequirement:
    stage: str
    maximum_raw_l1: int
    contribution_count: int | None
    coefficients_are_unit_magnitude: bool | None
    requires_margin_rescaling_under_current_parameter: bool


@dataclass(frozen=True)
class RequirementCoverage:
    stage: str
    maximum_raw_l1: int
    parameter_max_noise_level: int
    native_headroom: int
    covered_without_margin_rescaling: bool


@dataclass(frozen=True)
class GeometryAudit:
    total_plaintext_modulus_equal: bool
    standard_delta_equal: bool
    raw_lut_box_width_equal: bool
    polynomial_size_equal: bool
    glwe_dimension_equal: bool
    large_lwe_dimension_equal: bool
    small_lwe_dimension_equal: bool
    probe_glwe_word_shape_equal: bool
    response_big_lwe_word_shape_equal: bool
    intermediate_small_lwe_word_shape_equal: bool
    keys_reusable: bool
    ciphertexts_cross_decryptable: bool
    raw_p16_geometry_preserved: bool


@dataclass(frozen=True)
class ConditionalUnionBound:
    event_count: int
    per_event_log2_upper: float
    probability_upper: float
    log2_probability_upper: float
    independence_required: bool
    premise: str


@dataclass(frozen=True)
class MultilaneAudit:
    nibble_code_min: int
    nibble_code_max: int
    nibble_delta_log2: int
    standard_p16_delta_log2: int
    nibble_half_spacing_torus: int
    standard_p16_half_spacing_torus: int
    spacing_ratio_over_standard_p16: int
    antipodal_code_offset: int
    all_nibble_codes_fit_in_standard_p16_half_torus: bool
    arbitrary_nibble_lut_is_negacyclic_compatible: bool
    top_residual_fresh_roots: int
    top_residual_raw_l1: int
    candidate_max_noise_level: int
    candidate_native_headroom: int
    raw_l1_covered_without_margin_rescaling: bool
    extra_delta60_margin_credited_to_noise_level: bool
    nominal_p16_contract_inherited_automatically: bool
    can_use_standard_p16_margin_conservatively_after_equivalence_proof: bool
    required_equivalence_obligations: tuple[str, ...]


CURRENT_TUNIFORM = ParameterProfile(
    symbol="V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64",
    tfhe_version="0.11.3 (pinned)",
    bootstrap_kind="classic KS->PBS",
    lwe_dimension=879,
    glwe_dimension=1,
    polynomial_size=POLYNOMIAL_SIZE,
    lwe_noise="TUniform(46)",
    glwe_noise="TUniform(17)",
    pbs_base_log=23,
    pbs_level=1,
    ks_base_log=3,
    ks_level=5,
    message_modulus=4,
    carry_modulus=4,
    max_noise_level=5,
    log2_p_fail=-71.625,
    algorithmic_cost=None,
)

PINNED_CLASSIC_CANDIDATE = ParameterProfile(
    symbol="V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
    tfhe_version="0.11.3 (pinned)",
    bootstrap_kind="classic KS->PBS",
    lwe_dimension=859,
    glwe_dimension=1,
    polynomial_size=POLYNOMIAL_SIZE,
    lwe_noise="Gaussian(std=2.3088161607134664e-06)",
    glwe_noise="Gaussian(std=2.845267479601915e-15)",
    pbs_base_log=23,
    pbs_level=1,
    ks_base_log=3,
    ks_level=5,
    message_modulus=2,
    carry_modulus=8,
    max_noise_level=15,
    log2_p_fail=-64.088,
    algorithmic_cost=109,
)

GAUSSIAN_M2C2_COST_REFERENCE = ParameterProfile(
    symbol="V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64",
    tfhe_version="0.11.3 (pinned)",
    bootstrap_kind="classic KS->PBS",
    lwe_dimension=834,
    glwe_dimension=1,
    polynomial_size=POLYNOMIAL_SIZE,
    lwe_noise="Gaussian(std=3.5539902359442825e-06)",
    glwe_noise="Gaussian(std=2.845267479601915e-15)",
    pbs_base_log=23,
    pbs_level=1,
    ks_base_log=3,
    ks_level=5,
    message_modulus=4,
    carry_modulus=4,
    max_noise_level=5,
    log2_p_fail=-64.074,
    algorithmic_cost=106,
)

PINNED_MULTI_BIT_GROUP_2 = ParameterProfile(
    symbol="V0_11_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
    tfhe_version="0.11.3 (pinned)",
    bootstrap_kind="multi-bit KS->PBS",
    lwe_dimension=872,
    glwe_dimension=1,
    polynomial_size=POLYNOMIAL_SIZE,
    lwe_noise="Gaussian(std=1.844927811696596e-06)",
    glwe_noise="Gaussian(std=2.845267479601915e-15)",
    pbs_base_log=22,
    pbs_level=1,
    ks_base_log=3,
    ks_level=6,
    message_modulus=2,
    carry_modulus=8,
    max_noise_level=15,
    log2_p_fail=-64.089,
    algorithmic_cost=89,
    grouping_factor=2,
    deterministic_execution=False,
)

PINNED_MULTI_BIT_GROUP_3 = ParameterProfile(
    symbol="V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
    tfhe_version="0.11.3 (pinned)",
    bootstrap_kind="multi-bit KS->PBS",
    lwe_dimension=876,
    glwe_dimension=1,
    polynomial_size=POLYNOMIAL_SIZE,
    lwe_noise="Gaussian(std=1.7218966356934023e-06)",
    glwe_noise="Gaussian(std=2.845267479601915e-15)",
    pbs_base_log=22,
    pbs_level=1,
    ks_base_log=3,
    ks_level=6,
    message_modulus=2,
    carry_modulus=8,
    max_noise_level=15,
    log2_p_fail=-64.242,
    algorithmic_cost=86,
    grouping_factor=3,
    deterministic_execution=False,
)

VERSION_MIGRATION_P128 = ParameterProfile(
    symbol="V1_4_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M128",
    tfhe_version="1.4 preset present in local TFHE-rs 1.7.0 sources (not pinned)",
    bootstrap_kind="classic KS->PBS",
    lwe_dimension=904,
    glwe_dimension=1,
    polynomial_size=POLYNOMIAL_SIZE,
    lwe_noise="Gaussian(std=1.0621869847945622e-06)",
    glwe_noise="Gaussian(std=2.845267479601915e-15)",
    pbs_base_log=23,
    pbs_level=1,
    ks_base_log=3,
    ks_level=6,
    message_modulus=2,
    carry_modulus=8,
    max_noise_level=15,
    log2_p_fail=-128.103,
    algorithmic_cost=119,
    modulus_switch="centered-mean noise reduction",
)


REQUIREMENTS = (
    CircuitRequirement(
        stage="A34 residual classifier",
        maximum_raw_l1=8,
        contribution_count=8,
        coefficients_are_unit_magnitude=True,
        requires_margin_rescaling_under_current_parameter=True,
    ),
    CircuitRequirement(
        stage="A36 current two-chunk path",
        maximum_raw_l1=10,
        contribution_count=None,
        coefficients_are_unit_magnitude=None,
        requires_margin_rescaling_under_current_parameter=True,
    ),
    CircuitRequirement(
        stage="other audited p16 local inputs",
        maximum_raw_l1=5,
        contribution_count=None,
        coefficients_are_unit_magnitude=None,
        requires_margin_rescaling_under_current_parameter=False,
    ),
)


def requirement_coverage(
    profile: ParameterProfile, requirement: CircuitRequirement
) -> RequirementCoverage:
    headroom = profile.max_noise_level - requirement.maximum_raw_l1
    return RequirementCoverage(
        stage=requirement.stage,
        maximum_raw_l1=requirement.maximum_raw_l1,
        parameter_max_noise_level=profile.max_noise_level,
        native_headroom=headroom,
        covered_without_margin_rescaling=headroom >= 0,
    )


def geometry_audit(
    current: ParameterProfile, candidate: ParameterProfile
) -> GeometryAudit:
    same_large_lwe = (
        current.glwe_dimension * current.polynomial_size
        == candidate.glwe_dimension * candidate.polynomial_size
    )
    same_glwe_shape = (
        current.glwe_dimension == candidate.glwe_dimension
        and current.polynomial_size == candidate.polynomial_size
    )
    raw_geometry = (
        current.total_plaintext_modulus == candidate.total_plaintext_modulus
        and current.standard_delta == candidate.standard_delta
        and current.raw_lut_box_width == candidate.raw_lut_box_width
        and current.polynomial_size == candidate.polynomial_size
    )
    return GeometryAudit(
        total_plaintext_modulus_equal=(
            current.total_plaintext_modulus == candidate.total_plaintext_modulus
        ),
        standard_delta_equal=current.standard_delta == candidate.standard_delta,
        raw_lut_box_width_equal=(
            current.raw_lut_box_width == candidate.raw_lut_box_width
        ),
        polynomial_size_equal=current.polynomial_size == candidate.polynomial_size,
        glwe_dimension_equal=current.glwe_dimension == candidate.glwe_dimension,
        large_lwe_dimension_equal=same_large_lwe,
        small_lwe_dimension_equal=current.lwe_dimension == candidate.lwe_dimension,
        probe_glwe_word_shape_equal=same_glwe_shape,
        response_big_lwe_word_shape_equal=same_large_lwe,
        intermediate_small_lwe_word_shape_equal=(
            current.lwe_dimension == candidate.lwe_dimension
        ),
        keys_reusable=False,
        ciphertexts_cross_decryptable=False,
        raw_p16_geometry_preserved=raw_geometry,
    )


def conditional_union_bound(
    event_count: int, per_event_log2_upper: float
) -> ConditionalUnionBound:
    """Apply Boole's inequality without assuming event independence."""
    if event_count <= 0:
        raise ValueError("event_count must be positive")
    if not math.isfinite(per_event_log2_upper) or per_event_log2_upper > 0:
        raise ValueError("per_event_log2_upper must be finite and non-positive")
    probability = min(1.0, event_count * 2.0**per_event_log2_upper)
    return ConditionalUnionBound(
        event_count=event_count,
        per_event_log2_upper=per_event_log2_upper,
        probability_upper=probability,
        log2_probability_upper=math.log2(probability),
        independence_required=False,
        premise=(
            "every counted event must first have a valid per-event upper bound "
            "under the same conditioning"
        ),
    )


def required_per_event_log2(
    event_count: int, target_query_log2_upper: float
) -> float:
    """Largest per-event log2 bound sufficient for a target Boole bound."""
    if event_count <= 0:
        raise ValueError("event_count must be positive")
    if not math.isfinite(target_query_log2_upper) or target_query_log2_upper > 0:
        raise ValueError("target_query_log2_upper must be finite and non-positive")
    return target_query_log2_upper - math.log2(event_count)


def initial_score_gaussian_sensitivity(
    glwe_standard_deviation: float = 2.845267479601915e-15,
    template_norm2_max: int = 1_022,
    full_delta_log2: int = 52,
) -> dict[str, float | int | bool | str]:
    """Gaussian sensitivity only; deliberately not an end-to-end probability proof."""
    if glwe_standard_deviation <= 0:
        raise ValueError("standard deviation must be positive")
    if template_norm2_max <= 0:
        raise ValueError("template norm2 must be positive")
    sigma = 2.0 * math.sqrt(template_norm2_max) * glwe_standard_deviation
    half_step = 2.0 ** (full_delta_log2 - TORUS_BITS - 1)
    sigma_scale = half_step / sigma
    bilateral_chernoff_log2 = 1.0 - sigma_scale**2 / (2.0 * math.log(2.0))
    return {
        "template_norm2_max": template_norm2_max,
        "full_delta_log2": full_delta_log2,
        "normalized_sigma": sigma,
        "normalized_half_step": half_step,
        "sigma_scale": sigma_scale,
        "bilateral_gaussian_chernoff_log2": bilateral_chernoff_log2,
        "is_deterministic_support_bound": False,
        "status": "Gaussian-model sensitivity, not a custom-circuit proof",
    }


def multilane_audit(
    candidate: ParameterProfile = PINNED_CLASSIC_CANDIDATE,
) -> MultilaneAudit:
    """Audit the proposed whole-nibble Delta=2^60 multilane boundary.

    Codes 0..15 at Delta=2^60 occupy the complete torus.  Consequently code
    ``c + 8`` is the negacyclic antipode of code ``c``.  The larger spacing is
    useful geometric slack, but it is not permission to rescale a NoiseLevel
    argument or to apply an arbitrary p16 lookup table.
    """
    nibble_delta_log2 = 60
    standard_delta_log2 = candidate.standard_delta_log2
    nibble_half_spacing = 1 << (nibble_delta_log2 - 1)
    standard_half_spacing = 1 << (standard_delta_log2 - 1)
    top_residual_roots = 2
    top_residual_raw_l1 = top_residual_roots
    headroom = candidate.max_noise_level - top_residual_raw_l1
    return MultilaneAudit(
        nibble_code_min=0,
        nibble_code_max=15,
        nibble_delta_log2=nibble_delta_log2,
        standard_p16_delta_log2=standard_delta_log2,
        nibble_half_spacing_torus=nibble_half_spacing,
        standard_p16_half_spacing_torus=standard_half_spacing,
        spacing_ratio_over_standard_p16=(
            nibble_half_spacing // standard_half_spacing
        ),
        antipodal_code_offset=8,
        all_nibble_codes_fit_in_standard_p16_half_torus=False,
        arbitrary_nibble_lut_is_negacyclic_compatible=False,
        top_residual_fresh_roots=top_residual_roots,
        top_residual_raw_l1=top_residual_raw_l1,
        candidate_max_noise_level=candidate.max_noise_level,
        candidate_native_headroom=headroom,
        raw_l1_covered_without_margin_rescaling=headroom >= 0,
        extra_delta60_margin_credited_to_noise_level=False,
        nominal_p16_contract_inherited_automatically=False,
        can_use_standard_p16_margin_conservatively_after_equivalence_proof=True,
        required_equivalence_obligations=(
            "prove the accumulator on every reachable center and every open boundary margin",
            "prove the negacyclic relation Y(c+8)=-Y(c), or use a proved recoding/offset",
            "show that each raw KS/PBS has the same decomposition and no smaller input margin than the official p16 lookup",
            "keep shared-root provenance; do not assume the two fresh roots are independent",
        ),
    )


def report() -> dict[str, object]:
    current_coverage = [
        requirement_coverage(CURRENT_TUNIFORM, requirement)
        for requirement in REQUIREMENTS
    ]
    candidate_coverage = [
        requirement_coverage(PINNED_CLASSIC_CANDIDATE, requirement)
        for requirement in REQUIREMENTS
    ]
    candidate_query = conditional_union_bound(
        A38_N127_OUTPUT_MARGINALS,
        PINNED_CLASSIC_CANDIDATE.log2_p_fail,
    )
    p128_query = conditional_union_bound(
        A38_N127_OUTPUT_MARGINALS,
        VERSION_MIGRATION_P128.log2_p_fail,
    )

    return {
        "status": "static only: no compile, FHE, key generation, or Docker",
        "verdict": (
            "The pinned classic M1C3 Gaussian preset is a feasible minimal retune "
            "for the local p16 noise-level blocker, but it is not an end-to-end "
            "p-fail certificate for the custom graph."
        ),
        "a38_n127_counts": {
            "blind_rotations": A38_N127_BLIND_ROTATIONS,
            "key_switches": A38_N127_KEY_SWITCHES,
            "output_marginals": A38_N127_OUTPUT_MARGINALS,
        },
        "current": asdict(CURRENT_TUNIFORM),
        "minimal_candidate": asdict(PINNED_CLASSIC_CANDIDATE),
        "p16_geometry": asdict(
            geometry_audit(CURRENT_TUNIFORM, PINNED_CLASSIC_CANDIDATE)
        ),
        "current_requirement_coverage": [
            asdict(coverage) for coverage in current_coverage
        ],
        "candidate_requirement_coverage": [
            asdict(coverage) for coverage in candidate_coverage
        ],
        "conditional_nominal_query_bound": asdict(candidate_query),
        "required_per_event_log2_for_query_targets": {
            "query_2^-64": required_per_event_log2(
                A38_N127_OUTPUT_MARGINALS, -64.0
            ),
            "query_2^-80": required_per_event_log2(
                A38_N127_OUTPUT_MARGINALS, -80.0
            ),
        },
        "cost_reference": {
            "gaussian_m2c2": asdict(GAUSSIAN_M2C2_COST_REFERENCE),
            "candidate_cost_ratio": (
                PINNED_CLASSIC_CANDIDATE.algorithmic_cost
                / GAUSSIAN_M2C2_COST_REFERENCE.algorithmic_cost
            ),
            "warning": (
                "optimizer cost is not a latency measurement and the TUniform "
                "baseline has no directly comparable cost annotation"
            ),
        },
        "deferred_alternatives": {
            "multi_bit_group_2": asdict(PINNED_MULTI_BIT_GROUP_2),
            "multi_bit_group_3": asdict(PINNED_MULTI_BIT_GROUP_3),
            "multi_bit_blocker": (
                "the live core accepts only ShortintBootstrappingKey::Classic; "
                "multi-bit requires a separate core rewrite and benchmark"
            ),
            "version_migration_p128": asdict(VERSION_MIGRATION_P128),
            "version_migration_conditional_query_bound": asdict(p128_query),
        },
        "initial_score_after_distribution_change": initial_score_gaussian_sensitivity(),
        "future_multilane_delta60": asdict(multilane_audit()),
        "formal_boundary": {
            "native_p16_l1_blocker_removed": all(
                coverage.covered_without_margin_rescaling
                for coverage in candidate_coverage
            ),
            "raw_core_equivalence_to_shortint_contract_proved": False,
            "shared_many_lut_output_independence_assumed": False,
            "correlated_extraction_joint_bound_proved": False,
            "current_single_lwe_code56_terminal_closed": False,
            "end_to_end_numeric_upper": None,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit the full audit")
    args = parser.parse_args()
    payload = report()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    candidate = PINNED_CLASSIC_CANDIDATE
    bound = conditional_union_bound(
        A38_N127_OUTPUT_MARGINALS, candidate.log2_p_fail
    )
    print(f"candidate={candidate.symbol}")
    print(
        f"p={candidate.total_plaintext_modulus}, "
        f"delta=2^{candidate.standard_delta_log2}, "
        f"box_width={candidate.raw_lut_box_width}, "
        f"max_noise={candidate.max_noise_level}"
    )
    print(
        "conditional_nominal_query_bound="
        f"2^{bound.log2_probability_upper:.12f}="
        f"{bound.probability_upper:.12e}"
    )
    print("end_to_end_numeric_upper=OPEN")


if __name__ == "__main__":
    main()
