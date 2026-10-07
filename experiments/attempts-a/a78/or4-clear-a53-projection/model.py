#!/usr/bin/env python3
"""Clear/static A78 OR4 model and its A53 N=127 structural projection.

This file deliberately performs no FHE operation.  It materializes the plaintext
semantics of the proposed secure route, keeps unlike cryptographic primitives in
separate ledger columns, and makes every unresolved A53<->CM bridge explicit.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import pathlib
import runpy
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Sequence


GALLERY_SIZE = 127
GROUP_SIZE = 4
A53_PREFIX_RADIX = 15

A53_MODEL_SHA256 = "a03c8753298e0959133b0c915b911172795bafba353d86b75c7cdfb38d31eb9f"
A53_SCAN_RS_SHA256 = "81752a5da894797faeecda02c4fff3ad5aba93efde60a400dd1c36304e4940a5"
A53_FHE_RS_SHA256 = "a4dfbc7cd15bdc65ee699847b46147a0614bceccbdeb5317226103f7ffa68f9e"
A30_MODEL_SHA256 = "29c6945f12268364f308535184d137611d03d2448285fdde81bc7f0ea490ceca"
A30_README_SHA256 = "9eac7a4e01505232a7912a1e38b5403e4bb99892564f9d28a754e931d9924ca9"
A78_PMK_W2_SHA256 = "3d3538d7aa04f0b34de29cdfb4828c76204e23bd60cfd7ceb480e4e201390662"

PINNED_SOURCES = {
    "tmp/a53-radix15-group4-scan-model/a53_radix15_group4_scan_model.py": A53_MODEL_SHA256,
    "tmp/a62-a53-a44-integrated-prototype/src/a53_scan.rs": A53_SCAN_RS_SHA256,
    "tmp/a62-a53-a44-integrated-prototype/src/a53_scan/fhe.rs": A53_FHE_RS_SHA256,
    "tmp/a30-pfks-bridge-microbenchmark-design/model.py": A30_MODEL_SHA256,
    "tmp/a30-pfks-bridge-microbenchmark-design/README.md": A30_README_SHA256,
    "tmp/a78-common-mask-cross-lane-poc/src/bin/pmk_swap_w2.rs": A78_PMK_W2_SHA256,
}


@dataclass(frozen=True)
class CmParameters:
    name: str
    width: int
    glwe_dimension: int
    polynomial_size: int
    lwe_dimension: int
    bootstrap_base_log: int
    bootstrap_level: int
    keyswitch_base_log: int
    keyswitch_level: int

    @property
    def big_lwe_dimension(self) -> int:
        return self.glwe_dimension * self.polynomial_size

    @property
    def pmk_payload_bytes(self) -> int:
        # One standard or Fourier CM-GGSW has the same payload size:
        # level * (g+w)^2 * N u64, or level * (g+w)^2 * N/2 c64.
        return (
            self.bootstrap_level
            * (self.glwe_dimension + self.width) ** 2
            * (self.polynomial_size // 2)
            * 16
        )

    @property
    def fourier_bsk_payload_bytes(self) -> int:
        # One CM-GGSW per coefficient of the small CM-LWE mask.
        return self.lwe_dimension * self.pmk_payload_bytes

    @property
    def cm_keyswitch_payload_bytes(self) -> int:
        # The CM-LWE container has n shared-mask coefficients and w bodies.
        return (
            self.big_lwe_dimension
            * self.keyswitch_level
            * (self.lwe_dimension + self.width)
            * 8
        )


CM_PARAMETERS = {
    2: CmParameters(
        name="CM_PARAM_2_2_MINUS_64",
        width=2,
        glwe_dimension=3,
        polynomial_size=512,
        lwe_dimension=762,
        bootstrap_base_log=17,
        bootstrap_level=1,
        keyswitch_base_log=3,
        keyswitch_level=4,
    ),
    4: CmParameters(
        name="CM_PARAM_4_2_MINUS_64",
        width=4,
        glwe_dimension=3,
        polynomial_size=512,
        lwe_dimension=772,
        bootstrap_base_log=17,
        bootstrap_level=1,
        keyswitch_base_log=3,
        keyswitch_level=5,
    ),
}


@dataclass(frozen=True)
class Or4Trace:
    logical_inputs: tuple[int, ...]
    padded_inputs: tuple[int, int, int, int]
    cm_width: int
    pair_sums: tuple[int, int]
    packed_lanes: tuple[int, ...]
    pbs1_nonzero_lanes: tuple[int, ...]
    pmk_swapped_lanes: tuple[int, ...]
    summed_lanes: tuple[int, ...]
    extracted_lane_zero: int
    cm_keyswitch_value: int
    pbs2_nonzero_lanes: tuple[int, ...]
    retained_flag: int
    reference_flag: int


@dataclass(frozen=True)
class KernelLedger:
    group_length: int
    cm_width: int
    pair_lwe_additions: int
    input_rescales_min: int
    input_rescales_max: int
    cm_pack_invocations: int
    cm_blind_rotations: int
    bsk_external_products_min: int
    bsk_external_products_max: int
    pmk_keys_stored_per_keyset: int
    pmk_payload_bytes: int
    pmk_external_products: int
    cm_glwe_additions: int
    sample_extractions: int
    cm_keyswitches: int
    intermediate_lanes_produced: int
    final_lanes_produced: int
    final_flags_retained: int
    paper_one_over_1000_ratio_used: bool


@dataclass(frozen=True)
class PrefixShape:
    current_prefix_nodes: int
    arity_histogram: tuple[tuple[int, int], ...]
    directly_shape_compatible_nodes: int
    minimum_fanin4_gates_for_all_nodes: int
    minimum_tree_pair_additions_min: int
    minimum_tree_pair_additions_max: int
    minimum_tree_input_slots_min: int
    minimum_tree_input_slots_max: int


@dataclass(frozen=True)
class DagProjection:
    name: str
    ordinary_nodes_removed: int
    cm_or4_kernels: int
    ordinary_blind_rotations_remaining: int
    ordinary_classic_key_switches_remaining: int
    ordinary_marginals_remaining: int
    pair_lwe_additions_min: int
    pair_lwe_additions_max: int
    input_rescales_min: int
    input_rescales_max: int
    cm_pack_invocations: int
    cm_blind_rotations: int
    bsk_external_products_min: int
    bsk_external_products_max: int
    pmk_keys_stored_per_keyset: int
    pmk_payload_bytes: int
    pmk_external_products: int
    cm_glwe_additions: int
    sample_extractions: int
    cm_keyswitches: int
    candidate_direct_egress_key_switches: int
    candidate_total_classic_key_switches: int
    logical_marginals: int
    live_path_marginals: int
    all_physical_lane_marginals: int
    cm_kernel_schedule_waves_min: int | None
    cm_kernel_schedule_waves_max: int | None
    bridge_materialized: bool
    composed_p_fail_bound_available: bool
    latency_projection_available: bool


@dataclass(frozen=True)
class IntegrationLedger:
    a53_tfhe_version: str
    a78_tfhe_version: str
    a53_boolean_delta_log: int
    cm_p2_delta_log: int
    rescale_factor_if_not_absorbed: int
    conditional_ingress_packing_key_bytes: int
    conditional_direct_egress_key_bytes: int
    cm_core_key_payload_bytes: int
    conditional_total_key_payload_bytes: int
    general_egress_adapter_operations_min: int
    general_egress_adapter_operations_max: int | None
    missing_information: tuple[str, ...]


def repository_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[3]


def audit_source_pins(root: pathlib.Path | None = None) -> dict[str, str]:
    root = repository_root() if root is None else root
    observed: dict[str, str] = {}
    for relative, expected in PINNED_SOURCES.items():
        digest = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        if digest != expected:
            raise AssertionError(
                f"source provenance drift for {relative}: {digest}, expected {expected}"
            )
        observed[relative] = digest
    return observed


def _canonical_bits(bits: Sequence[bool | int]) -> tuple[int, ...]:
    if not 1 <= len(bits) <= GROUP_SIZE:
        raise ValueError("OR4 route needs one to four logical inputs")
    canonical = []
    for bit in bits:
        if isinstance(bit, bool):
            canonical.append(int(bit))
        elif isinstance(bit, int) and bit in (0, 1):
            canonical.append(bit)
        else:
            raise ValueError("OR4 logical inputs must be Boolean 0/1 values")
    return tuple(canonical)


def clear_secure_or4(bits: Sequence[bool | int], cm_width: int = 2) -> Or4Trace:
    """Mirror pair-sum -> BR -> PMK swap -> add -> extract/CMKS -> PBS2.

    This is a plaintext functional model, not evidence that the corresponding
    noisy ciphertext circuit compiles or meets a failure-probability bound.
    """

    if cm_width not in CM_PARAMETERS:
        raise ValueError("only the pinned width-2 and width-4 CM parameters are modeled")
    logical = _canonical_bits(bits)
    padded = logical + (0,) * (GROUP_SIZE - len(logical))
    pair_sums = (padded[0] + padded[1], padded[2] + padded[3])
    if cm_width == 2:
        packed = pair_sums
        permutation = (1, 0)
    else:
        packed = pair_sums + pair_sums
        permutation = (1, 0, 3, 2)
    pbs1 = tuple(int(value != 0) for value in packed)
    swapped = tuple(pbs1[source] for source in permutation)
    summed = tuple(left + right for left, right in zip(pbs1, swapped))
    extracted = summed[0]
    after_cmks = extracted
    pbs2 = tuple(int(extracted != 0) for _ in range(cm_width))
    retained = pbs2[0]
    reference = int(any(logical))
    if not all(value == reference for value in pbs2):
        raise AssertionError("clear PMK route disagrees with OR reference")
    return Or4Trace(
        logical_inputs=logical,
        padded_inputs=padded,
        cm_width=cm_width,
        pair_sums=pair_sums,
        packed_lanes=packed,
        pbs1_nonzero_lanes=pbs1,
        pmk_swapped_lanes=swapped,
        summed_lanes=summed,
        extracted_lane_zero=extracted,
        cm_keyswitch_value=after_cmks,
        pbs2_nonzero_lanes=pbs2,
        retained_flag=retained,
        reference_flag=reference,
    )


def kernel_ledger(group_length: int, cm_width: int = 2) -> KernelLedger:
    if not 1 <= group_length <= GROUP_SIZE:
        raise ValueError("group length must be in 1..4")
    params = CM_PARAMETERS[cm_width]
    # A singleton paired with public zero can be forwarded.  For current A53,
    # full groups spend two additions and the final length-three group spends one.
    pair_additions = group_length // 2
    # A53 presently encodes Boolean p16 at 2^59; CM p2 conventionally uses 2^61.
    # Zero is possible if a packing key/LUT absorbs the scale.  Otherwise each
    # occupied pair slot is multiplied by four before packing.
    input_rescales_max = (group_length + 1) // 2
    return KernelLedger(
        group_length=group_length,
        cm_width=cm_width,
        pair_lwe_additions=pair_additions,
        input_rescales_min=0,
        input_rescales_max=input_rescales_max,
        cm_pack_invocations=1,
        cm_blind_rotations=2,
        # tfhe-rs skips the BSK external product when a mask coefficient is zero.
        # Therefore the exact source-level bound is 0..2*n, not unconditionally 2*n.
        bsk_external_products_min=0,
        bsk_external_products_max=2 * params.lwe_dimension,
        pmk_keys_stored_per_keyset=1,
        pmk_payload_bytes=params.pmk_payload_bytes,
        pmk_external_products=1,
        cm_glwe_additions=1,
        sample_extractions=2,
        cm_keyswitches=1,
        intermediate_lanes_produced=cm_width,
        final_lanes_produced=cm_width,
        final_flags_retained=1,
        paper_one_over_1000_ratio_used=False,
    )


def group_lengths(gallery_size: int = GALLERY_SIZE) -> tuple[int, ...]:
    if gallery_size < 1:
        raise ValueError("gallery size must be positive")
    return tuple(
        min(GROUP_SIZE, gallery_size - start)
        for start in range(0, gallery_size, GROUP_SIZE)
    )


def a53_prefix_gate_arities(
    items: int = len(group_lengths()), radix: int = A53_PREFIX_RADIX
) -> tuple[int, ...]:
    """Mirror A53's recursive prefix topology and retain every real OR arity."""

    if items < 1 or radix < 2:
        raise ValueError("invalid prefix shape")
    arities: list[int] = []

    def or_gate(values: Sequence[int]) -> int:
        if len(values) <= 1:
            return values[0] if values else 0
        if len(values) > radix:
            raise AssertionError("prefix gate exceeds radix")
        arities.append(len(values))
        return int(any(values))

    def recurse(current: tuple[int, ...]) -> tuple[int, ...]:
        if len(current) <= radix:
            return tuple(or_gate(current[:index]) for index in range(len(current)))
        blocks = tuple(
            current[start : start + radix]
            for start in range(0, len(current), radix)
        )
        totals = tuple(or_gate(block) for block in blocks)
        block_prefixes = recurse(totals)
        prefixes: list[int] = []
        for index in range(len(current)):
            block = index // radix
            offset = index % radix
            if offset == 0:
                prefixes.append(block_prefixes[block])
                continue
            inputs = list(current[block * radix : index])
            if block > 0:
                inputs.insert(0, block_prefixes[block])
            prefixes.append(or_gate(inputs))
        return tuple(prefixes)

    recurse((0,) * items)
    return tuple(arities)


def minimum_fanin4_gate_count(inputs: int) -> int:
    if inputs < 2:
        return 0
    return math.ceil((inputs - 1) / 3)


def _minimum_tree_profiles(inputs: int) -> tuple[tuple[int, int, int], ...]:
    """All (fan-in 2,3,4) profiles using the minimum number of gates."""

    gates = minimum_fanin4_gate_count(inputs)
    reductions = inputs - 1
    profiles = []
    for fanin2 in range(gates + 1):
        for fanin3 in range(gates - fanin2 + 1):
            fanin4 = gates - fanin2 - fanin3
            if fanin2 + 2 * fanin3 + 3 * fanin4 == reductions:
                profiles.append((fanin2, fanin3, fanin4))
    if inputs >= 2 and not profiles:
        raise AssertionError("minimum fan-in-four tree has no profile")
    return tuple(profiles)


def minimum_tree_cost_interval(inputs: int) -> tuple[int, int, int, int]:
    """Return min/max pair additions and occupied pair slots for minimal trees."""

    if inputs < 2:
        return (0, 0, 0, 0)
    pair_additions = []
    occupied_pair_slots = []
    for fanin2, fanin3, fanin4 in _minimum_tree_profiles(inputs):
        pair_additions.append(fanin2 + fanin3 + 2 * fanin4)
        occupied_pair_slots.append(fanin2 + 2 * fanin3 + 2 * fanin4)
    return (
        min(pair_additions),
        max(pair_additions),
        min(occupied_pair_slots),
        max(occupied_pair_slots),
    )


def prefix_shape() -> PrefixShape:
    arities = a53_prefix_gate_arities()
    histogram = tuple(sorted(Counter(arities).items()))
    compatible = sum(arity <= GROUP_SIZE for arity in arities)
    gate_count = sum(minimum_fanin4_gate_count(arity) for arity in arities)
    intervals = [minimum_tree_cost_interval(arity) for arity in arities]
    return PrefixShape(
        current_prefix_nodes=len(arities),
        arity_histogram=histogram,
        directly_shape_compatible_nodes=compatible,
        minimum_fanin4_gates_for_all_nodes=gate_count,
        minimum_tree_pair_additions_min=sum(row[0] for row in intervals),
        minimum_tree_pair_additions_max=sum(row[1] for row in intervals),
        minimum_tree_input_slots_min=sum(row[2] for row in intervals),
        minimum_tree_input_slots_max=sum(row[3] for row in intervals),
    )


def _projection(
    *,
    name: str,
    ordinary_nodes_removed: int,
    kernels: int,
    pair_additions_min: int,
    pair_additions_max: int,
    rescale_max: int,
    schedule_waves: tuple[int | None, int | None],
) -> DagProjection:
    params = CM_PARAMETERS[2]
    ordinary_br = 3_390 - ordinary_nodes_removed
    ordinary_ks = 3_009 - ordinary_nodes_removed
    ordinary_marginals = 3_930 - ordinary_nodes_removed
    # One explicit candidate adapter maps the retained lane-0 CM-big output to
    # the A44-big interface.  It is countable but not yet implemented/noise-tested.
    candidate_egress = kernels
    return DagProjection(
        name=name,
        ordinary_nodes_removed=ordinary_nodes_removed,
        cm_or4_kernels=kernels,
        ordinary_blind_rotations_remaining=ordinary_br,
        ordinary_classic_key_switches_remaining=ordinary_ks,
        ordinary_marginals_remaining=ordinary_marginals,
        pair_lwe_additions_min=pair_additions_min,
        pair_lwe_additions_max=pair_additions_max,
        input_rescales_min=0,
        input_rescales_max=rescale_max,
        cm_pack_invocations=kernels,
        cm_blind_rotations=2 * kernels,
        bsk_external_products_min=0,
        bsk_external_products_max=2 * params.lwe_dimension * kernels,
        pmk_keys_stored_per_keyset=1,
        pmk_payload_bytes=params.pmk_payload_bytes,
        pmk_external_products=kernels,
        cm_glwe_additions=kernels,
        sample_extractions=2 * kernels,
        cm_keyswitches=kernels,
        candidate_direct_egress_key_switches=candidate_egress,
        candidate_total_classic_key_switches=ordinary_ks + candidate_egress,
        # One logical result per replacement kernel; physical CM paths expose
        # w=2 lanes at stage one and w=2 at stage two.  Only one final flag survives.
        logical_marginals=ordinary_marginals + kernels,
        live_path_marginals=ordinary_marginals + 3 * kernels,
        all_physical_lane_marginals=ordinary_marginals + 4 * kernels,
        cm_kernel_schedule_waves_min=schedule_waves[0],
        cm_kernel_schedule_waves_max=schedule_waves[1],
        bridge_materialized=False,
        composed_p_fail_bound_available=False,
        latency_projection_available=False,
    )


def a53_group_only_projection() -> DagProjection:
    lengths = group_lengths()
    ledgers = tuple(kernel_ledger(length) for length in lengths)
    return _projection(
        name="A53 N=127: replace only 32 group-flag nodes",
        ordinary_nodes_removed=len(lengths),
        kernels=len(lengths),
        pair_additions_min=sum(row.pair_lwe_additions for row in ledgers),
        pair_additions_max=sum(row.pair_lwe_additions for row in ledgers),
        rescale_max=sum(row.input_rescales_max for row in ledgers),
        # A66 launches group flags in parallel.  This is a scheduling bracket,
        # not a seconds estimate; memory contention is not modeled.
        schedule_waves=(1, len(lengths)),
    )


def a53_direct_prefix_projection() -> DagProjection:
    """Also replace the nine existing prefix nodes whose arity is already <=4."""

    lengths = group_lengths()
    arities = tuple(arity for arity in a53_prefix_gate_arities() if arity <= 4)
    pair_additions = sum(length // 2 for length in lengths) + sum(
        arity // 2 for arity in arities
    )
    rescale_max = sum((length + 1) // 2 for length in lengths) + sum(
        (arity + 1) // 2 for arity in arities
    )
    kernels = len(lengths) + len(arities)
    return _projection(
        name="A53 N=127: group flags plus nine shape-compatible prefix nodes",
        ordinary_nodes_removed=kernels,
        kernels=kernels,
        pair_additions_min=pair_additions,
        pair_additions_max=pair_additions,
        rescale_max=rescale_max,
        schedule_waves=(None, None),
    )


def a53_full_prefix_minimum_projection() -> DagProjection:
    """Count a minimum-gate independent expansion of all current prefix calls.

    The 88-kernel prefix count is exact for independently replacing each current
    prefix call by a fan-in<=4 tree.  It is not a globally optimized shared-prefix
    redesign, and the concrete tree profiles remain a range.
    """

    lengths = group_lengths()
    shape = prefix_shape()
    group_pair_additions = sum(length // 2 for length in lengths)
    group_rescale_slots = sum((length + 1) // 2 for length in lengths)
    kernels = len(lengths) + shape.minimum_fanin4_gates_for_all_nodes
    return _projection(
        name="A53 N=127: group flags plus minimum independent fan-in<=4 prefix trees",
        # The 32 old prefix PBS nodes are removed, even though their replacement
        # expands to 88 CM kernels.
        ordinary_nodes_removed=len(lengths) + shape.current_prefix_nodes,
        kernels=kernels,
        pair_additions_min=group_pair_additions
        + shape.minimum_tree_pair_additions_min,
        pair_additions_max=group_pair_additions
        + shape.minimum_tree_pair_additions_max,
        rescale_max=group_rescale_slots + shape.minimum_tree_input_slots_max,
        schedule_waves=(None, None),
    )


def integration_ledger() -> IntegrationLedger:
    params = CM_PARAMETERS[2]
    a53_big_lwe_dimension = 2_048
    ingress = (
        params.width
        * a53_big_lwe_dimension
        * params.keyswitch_level
        * (params.lwe_dimension + params.width)
        * 8
    )
    direct_egress = (
        params.big_lwe_dimension
        * params.keyswitch_level
        * (a53_big_lwe_dimension + 1)
        * 8
    )
    core = (
        params.pmk_payload_bytes
        + params.fourier_bsk_payload_bytes
        + params.cm_keyswitch_payload_bytes
    )
    return IntegrationLedger(
        a53_tfhe_version="0.11.3",
        a78_tfhe_version="1.7.0",
        a53_boolean_delta_log=59,
        cm_p2_delta_log=61,
        rescale_factor_if_not_absorbed=4,
        conditional_ingress_packing_key_bytes=ingress,
        conditional_direct_egress_key_bytes=direct_egress,
        cm_core_key_payload_bytes=core,
        conditional_total_key_payload_bytes=core + ingress + direct_egress,
        general_egress_adapter_operations_min=len(group_lengths()),
        # No finite honest upper bound exists before choosing direct KSK, another
        # CMKS+KSK route, PFKS, or a same-version/parameter redesign.
        general_egress_adapter_operations_max=None,
        missing_information=(
            "a compiled tfhe-rs 1.7 PMK OR4 kernel",
            "a version-compatible A53 ingress packing key",
            "a validated p16-delta to p2-delta scaling/noise contract",
            "a validated CM-big to A44-big retained-lane adapter",
            "a composed noise and failure-probability proof or measured bound",
            "matched component timings and peak-memory measurements",
        ),
    )


def audit_upstream_values(root: pathlib.Path | None = None) -> dict[str, object]:
    """Execute only the pinned clear Python models to guard projected constants."""

    root = repository_root() if root is None else root
    audit_source_pins(root)
    a53 = runpy.run_path(
        str(root / "tmp/a53-radix15-group4-scan-model/a53_radix15_group4_scan_model.py")
    )
    scan = a53["scan_counts"](GALLERY_SIZE)
    full = a53["full_count_row"](GALLERY_SIZE)
    a30 = runpy.run_path(
        str(root / "tmp/a30-pfks-bridge-microbenchmark-design/model.py")
    )
    b0_d2 = a30["primitive_ledger"](GALLERY_SIZE, pfks_variant="D2")
    b0_d1 = a30["primitive_ledger"](GALLERY_SIZE, pfks_variant="D1")
    return {
        "a53_scan": (
            scan.total.blind_rotations,
            scan.total.key_switches,
            scan.total.output_marginals,
        ),
        "a53_full": (
            full.a53_full.blind_rotations,
            full.a53_full.key_switches,
            full.a53_full.output_marginals,
        ),
        "a30_b0_d2": (
            b0_d2.total_pbs,
            b0_d2.total_classic_ks,
            b0_d2.total_marginals,
            b0_d2.pfks_calls,
        ),
        "a30_b0_d1_pfks": b0_d1.pfks_calls,
    }


def exhaustive_clear_audit() -> dict[str, int]:
    checked = 0
    for width in CM_PARAMETERS:
        for length in (3, 4):
            for bits in itertools.product((0, 1), repeat=length):
                trace = clear_secure_or4(bits, width)
                if trace.retained_flag != int(any(bits)):
                    raise AssertionError("exhaustive OR4 clear audit failed")
                checked += 1
    return {"traces_checked": checked, "mismatches": 0}


def report() -> dict[str, object]:
    return {
        "status": "CLEAR_TESTED_ONLY__FHE_AND_BRIDGES_NOT_MATERIALIZED",
        "source_pins": audit_source_pins(),
        "upstream_values": audit_upstream_values(),
        "clear_audit": exhaustive_clear_audit(),
        "kernel_full_w2": asdict(kernel_ledger(4, 2)),
        "kernel_tail3_w2": asdict(kernel_ledger(3, 2)),
        "kernel_full_w4_compatibility": asdict(kernel_ledger(4, 4)),
        "prefix_shape": asdict(prefix_shape()),
        "a53_group_only": asdict(a53_group_only_projection()),
        "a53_group_plus_direct_prefix": asdict(a53_direct_prefix_projection()),
        "a53_group_plus_minimum_prefix_trees": asdict(
            a53_full_prefix_minimum_projection()
        ),
        "integration": asdict(integration_ledger()),
        "non_claims": (
            "no FHE correctness claim",
            "no latency claim",
            "no composed p-fail claim",
            "no transfer of the paper's approximately 1/1000 timing ratio",
        ),
    }


if __name__ == "__main__":
    print(json.dumps(report(), indent=2, sort_keys=True))
