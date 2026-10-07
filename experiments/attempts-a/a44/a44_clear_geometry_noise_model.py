#!/usr/bin/env python3
"""Static clear, p16-geometry, and noise-ledger model for isolated A44.

A44 keeps the A41 two-LWE graph and changes only its pinned TFHE-rs 0.11.3
parameter preset plus explicit protocol binding. This model runs no Cargo,
key generation, or FHE. It proves clear semantics and arithmetic invariants;
it deliberately does not promote the preset's nominal per-PBS ``p-fail`` into
an end-to-end claim for custom raw/ManyLUT paths.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from dataclasses import asdict, dataclass
from itertools import product


MAX_GALLERY_SIZE = 128
SCAN_GROUP_SIZE = 3
REDUCTION_RADIX = 5
LEGACY_REDUCTION_RADIX = 4
OUTPUT_LWES = 2
BOOL_DELTA_LOG = 59
LWE_SIZE_WORDS = 2_049
HEADER_WORDS_WITH_LENGTH_PREFIX = 9
WORD_BYTES = 8

TFHE_VERSION = "0.11.3"
PARAMETER_SYMBOL = "V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64"
PARAMS_ID = "tfhe-rs-0.11.3-v0_11-m1c3-classic-ks-pbs-gaussian-2m64"
PARAMETER_CANONICAL = (
    "tfhe-rs=0.11.3;"
    "symbol=V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;"
    "bootstrap=classic_ks_pbs;"
    "lwe_dimension=859;"
    "glwe_dimension=1;"
    "polynomial_size=2048;"
    "lwe_noise=gaussian_stddev_2.3088161607134664e-6;"
    "glwe_noise=gaussian_stddev_2.845267479601915e-15;"
    "pbs_base_log=23;pbs_level=1;"
    "ks_base_log=3;ks_level=5;"
    "message_modulus=2;carry_modulus=8;"
    "max_noise_level=15;"
    "log2_p_fail=-64.088;"
    "ciphertext_modulus=native;"
    "encryption_key_choice=Big"
)
PARAMETER_FINGERPRINT_SHA256 = (
    "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1"
)

P16 = 16
POLYNOMIAL_SIZE = 2_048
MODULUS_SWITCH_ROTATION_MODULUS = 2 * POLYNOMIAL_SIZE
P16_ROTATION_STEP = POLYNOMIAL_SIZE // P16
P16_CERTIFIED_ERROR_MIN = -(P16_ROTATION_STEP // 2 - 1)
P16_CERTIFIED_ERROR_MAX = P16_ROTATION_STEP // 2 - 1
P16_BOUNDARY_ERROR = P16_ROTATION_STEP // 2
P16_DELTA = 1 << BOOL_DELTA_LOG
P16_HALF_MARGIN_TORUS = P16_DELTA // 2
MAX_NOISE_LEVEL = 15
LOG2_P_FAIL_PER_EVENT = -64.088


@dataclass(frozen=True)
class Counts:
    blind_rotations: int
    key_switches: int
    output_marginals: int


@dataclass(frozen=True)
class ClearResult:
    gallery_size: int
    candidates: tuple[int, ...]
    group_flags: tuple[int, ...]
    local_first: tuple[int, ...]
    group_prefixes: tuple[int, ...]
    low_digits: tuple[int, ...]
    high_digits: tuple[int, ...]
    low_nibble: int
    high_nibble: int
    code: int


@dataclass(frozen=True)
class ParameterBinding:
    params_id: str
    fingerprint_sha256: str


@dataclass(frozen=True)
class ParameterProfile:
    tfhe_version: str
    symbol: str
    bootstrap_kind: str
    lwe_dimension: int
    glwe_dimension: int
    polynomial_size: int
    pbs_base_log: int
    pbs_level: int
    ks_base_log: int
    ks_level: int
    message_modulus: int
    carry_modulus: int
    max_noise_level: int
    log2_p_fail: float
    ciphertext_modulus: str
    encryption_key_choice: str


@dataclass(frozen=True)
class P16Center:
    code: int
    torus_center: int
    modulus_switch_rotation_center: int
    certified_error_min: int
    certified_error_max: int
    uncertified_boundary_minus: int
    uncertified_boundary_plus: int


@dataclass(frozen=True)
class NoiseLedgerEntry:
    node_family: str
    raw_l1: int
    max_noise_level: int
    headroom: int
    margin_rescaling_factor: int
    input_scale: str
    in_materialized_a44_graph: bool
    contract_status: str
    provenance_note: str


PARAMETER_PROFILE = ParameterProfile(
    tfhe_version=TFHE_VERSION,
    symbol=PARAMETER_SYMBOL,
    bootstrap_kind="classic KS->PBS",
    lwe_dimension=859,
    glwe_dimension=1,
    polynomial_size=POLYNOMIAL_SIZE,
    pbs_base_log=23,
    pbs_level=1,
    ks_base_log=3,
    ks_level=5,
    message_modulus=2,
    carry_modulus=8,
    max_noise_level=MAX_NOISE_LEVEL,
    log2_p_fail=LOG2_P_FAIL_PER_EVENT,
    ciphertext_modulus="native",
    encryption_key_choice="Big",
)

EXPECTED_BINDING = ParameterBinding(
    params_id=PARAMS_ID,
    fingerprint_sha256=PARAMETER_FINGERPRINT_SHA256,
)


def validate_parameter_binding(binding: ParameterBinding) -> None:
    """Fail closed on either protocol identifier or canonical fingerprint."""

    if binding.params_id != PARAMS_ID:
        raise ValueError("A44 params_id mismatch")
    if binding.fingerprint_sha256 != PARAMETER_FINGERPRINT_SHA256:
        raise ValueError("A44 parameter fingerprint mismatch")


def ceil_div(value: int, divisor: int) -> int:
    return (value + divisor - 1) // divisor


def reduction_nodes(items: int, radix: int) -> int:
    nodes = 0
    while items > 1:
        items = ceil_div(items, radix)
        nodes += items
    return nodes


def exclusive_prefix_nodes(items: int, radix: int) -> int:
    if items <= 2:
        return 0
    if items <= radix:
        return items - 2
    totals = 0
    expansion = 0
    blocks = 0
    for start in range(0, items, radix):
        length = min(radix, items - start)
        blocks += 1
        totals += int(length > 1)
        expansion += max(0, length - 2) if start == 0 else length - 1
    return totals + expansion + exclusive_prefix_nodes(blocks, radix)


def output_bit_positions(gallery_size: int) -> tuple[int, ...]:
    return tuple(
        bit
        for bit in range(gallery_size.bit_length())
        if any(((index + 1) >> bit) & 1 for index in range(gallery_size))
    )


def legacy_first_one_scan_nodes(items: int) -> int:
    groups = ceil_div(items, SCAN_GROUP_SIZE)
    group_totals = sum(
        min(SCAN_GROUP_SIZE, items - start) > 1
        for start in range(0, items, SCAN_GROUP_SIZE)
    )
    return group_totals + exclusive_prefix_nodes(groups, LEGACY_REDUCTION_RADIX) + items


def legacy_output_nodes(gallery_size: int) -> int:
    positions = output_bit_positions(gallery_size)
    bit_nodes = 0
    for bit in positions:
        contributors = sum(((index + 1) >> bit) & 1 for index in range(gallery_size))
        bit_nodes += max(1, reduction_nodes(contributors, LEGACY_REDUCTION_RADIX))
    return bit_nodes + ceil_div(len(positions), 3)


def a44_counts(gallery_size: int) -> Counts:
    """A44 keeps exactly the A41 graph and therefore its structural counts."""

    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError("gallery_size must be in 1..128")
    n = gallery_size
    old_total = (
        27 * n
        + 8 * reduction_nodes(n, LEGACY_REDUCTION_RADIX)
        + legacy_first_one_scan_nodes(n)
        + legacy_output_nodes(n)
        - 1
    )
    old_low = 12 * n + 8 * reduction_nodes(n, LEGACY_REDUCTION_RADIX)
    old_scan_output = legacy_first_one_scan_nodes(n) + legacy_output_nodes(n)
    new_low = 10 * n + 8 * reduction_nodes(n, REDUCTION_RADIX)
    groups = ceil_div(n, SCAN_GROUP_SIZE)
    group_nodes = sum(
        min(SCAN_GROUP_SIZE, n - start) > 1 for start in range(0, n, SCAN_GROUP_SIZE)
    )
    prefix_nodes = exclusive_prefix_nodes(groups, REDUCTION_RADIX)
    digit_nodes = 2 * reduction_nodes(groups, REDUCTION_RADIX)
    new_scan_output = 2 * group_nodes + prefix_nodes + groups + digit_nodes
    blind_rotations = old_total - old_low - old_scan_output + new_low + new_scan_output
    return Counts(
        blind_rotations=blind_rotations,
        key_switches=blind_rotations - 3 * n,
        output_marginals=blind_rotations + 4 * n + groups,
    )


def evaluate(candidates: tuple[int, ...]) -> ClearResult:
    if not 1 <= len(candidates) <= MAX_GALLERY_SIZE:
        raise ValueError("candidate vector length must be in 1..128")
    if any(value not in (0, 1) for value in candidates):
        raise ValueError("candidates must be Boolean")

    chunks = tuple(
        candidates[start : start + SCAN_GROUP_SIZE]
        for start in range(0, len(candidates), SCAN_GROUP_SIZE)
    )
    group_flags = tuple(int(any(chunk)) for chunk in chunks)
    local_first = tuple(
        next((offset + 1 for offset, bit in enumerate(chunk) if bit), 0)
        for chunk in chunks
    )
    group_prefixes = tuple(
        int(any(group_flags[:group])) for group in range(len(chunks))
    )

    codes = tuple(
        SCAN_GROUP_SIZE * group + state if state and not prefix else 0
        for group, (state, prefix) in enumerate(zip(local_first, group_prefixes))
    )
    low_digits = tuple(code & 0xF for code in codes)
    high_digits = tuple(code >> 4 for code in codes)
    low_nibble = sum(low_digits)
    high_nibble = sum(high_digits)
    code = low_nibble + 16 * high_nibble

    expected = next(
        (index + 1 for index, candidate in enumerate(candidates) if candidate),
        0,
    )
    assert code == expected
    assert 0 <= low_nibble <= 15
    assert 0 <= high_nibble <= 8
    assert sum(value != 0 for value in codes) <= 1
    return ClearResult(
        gallery_size=len(candidates),
        candidates=candidates,
        group_flags=group_flags,
        local_first=local_first,
        group_prefixes=group_prefixes,
        low_digits=low_digits,
        high_digits=high_digits,
        low_nibble=low_nibble,
        high_nibble=high_nibble,
        code=code,
    )


def official_p16_centers() -> tuple[P16Center, ...]:
    return tuple(
        P16Center(
            code=code,
            torus_center=code * P16_DELTA,
            modulus_switch_rotation_center=code * P16_ROTATION_STEP,
            certified_error_min=P16_CERTIFIED_ERROR_MIN,
            certified_error_max=P16_CERTIFIED_ERROR_MAX,
            uncertified_boundary_minus=-P16_BOUNDARY_ERROR,
            uncertified_boundary_plus=P16_BOUNDARY_ERROR,
        )
        for code in range(P16)
    )


def p16_margin_certifies(rotation_error: int) -> bool:
    """The static certificate is open at both half-cell boundaries."""

    return P16_CERTIFIED_ERROR_MIN <= rotation_error <= P16_CERTIFIED_ERROR_MAX


def nearest_p16_slot(center: P16Center, rotation_error: int) -> int:
    """Nearest-cell model used only inside the strict certified interval."""

    if not p16_margin_certifies(rotation_error):
        raise ValueError("rotation error reaches an uncertified p16 boundary")
    position = center.modulus_switch_rotation_center + rotation_error
    return (position + P16_BOUNDARY_ERROR) // P16_ROTATION_STEP


def noise_ledger() -> tuple[NoiseLedgerEntry, ...]:
    """Raw-L1 obligations; no entry receives credit from a widened plateau."""

    specifications = (
        (
            "A34 residual classifier",
            8,
            "custom p16 residual scale",
            True,
            "open_raw_lut_equivalence",
            "maximum eight unit-magnitude correction contributions",
        ),
        (
            "A36 current two-chunk path",
            10,
            "custom raw p16 body",
            True,
            "open_raw_lut_equivalence",
            "maximum raw live-state/five-way OR ledger from A36 audit",
        ),
        (
            "A38/A41 radix-5 scan reductions",
            5,
            "Delta=2^59",
            True,
            "nominal_geometry_manylut_correlation_open",
            "at most five fresh Boolean inputs per reduction",
        ),
        (
            "A41 terminal low/high roots",
            5,
            "Delta=2^59",
            True,
            "nominal_geometry_manylut_correlation_open",
            "two separate p16 roots; no unbootstrapped final addition",
        ),
        (
            "A40 prospective gallery OR fan-in 7",
            7,
            "Delta=2^59",
            False,
            "compatibility_only_not_materialized",
            "A40 is modeled only as a max-noise compatibility check",
        ),
    )
    return tuple(
        NoiseLedgerEntry(
            node_family=name,
            raw_l1=raw_l1,
            max_noise_level=MAX_NOISE_LEVEL,
            headroom=MAX_NOISE_LEVEL - raw_l1,
            margin_rescaling_factor=1,
            input_scale=input_scale,
            in_materialized_a44_graph=in_graph,
            contract_status=contract_status,
            provenance_note=provenance_note,
        )
        for name, raw_l1, input_scale, in_graph, contract_status, provenance_note in specifications
    )


def wire_projection() -> dict[str, int | float]:
    single_bytes = WORD_BYTES * (HEADER_WORDS_WITH_LENGTH_PREFIX + LWE_SIZE_WORDS)
    two_bytes = WORD_BYTES * (HEADER_WORDS_WITH_LENGTH_PREFIX + 2 * LWE_SIZE_WORDS)
    return {
        "single_lwe_bytes": single_bytes,
        "two_lwe_bytes": two_bytes,
        "additional_bytes": two_bytes - single_bytes,
        "size_ratio": two_bytes / single_bytes,
    }


def validate() -> dict[str, object]:
    expected_fingerprint = hashlib.sha256(PARAMETER_CANONICAL.encode()).hexdigest()
    assert expected_fingerprint == PARAMETER_FINGERPRINT_SHA256
    validate_parameter_binding(EXPECTED_BINDING)

    exhaustive_vectors = 0
    for gallery_size in range(1, 17):
        for candidate_tuple in product((0, 1), repeat=gallery_size):
            evaluate(candidate_tuple)
            exhaustive_vectors += 1

    representative_vectors = 0
    for gallery_size in range(1, MAX_GALLERY_SIZE + 1):
        evaluate((0,) * gallery_size)
        representative_vectors += 1
        for first in range(gallery_size):
            prefixes = (
                (0,) * first + (1,) + (0,) * (gallery_size - first - 1),
                (0,) * first + (1,) * (gallery_size - first),
                (0,) * first
                + (1,)
                + tuple(
                    (index - first) % 2 for index in range(first + 1, gallery_size)
                ),
            )
            for candidates in prefixes:
                evaluate(candidates)
                representative_vectors += 1

    selector_states = 0
    for gallery_size in range(1, MAX_GALLERY_SIZE + 1):
        groups = ceil_div(gallery_size, SCAN_GROUP_SIZE)
        for group in range(groups):
            group_len = min(SCAN_GROUP_SIZE, gallery_size - group * SCAN_GROUP_SIZE)
            for state in range(group_len + 1):
                for prefix in (0, 1):
                    code = (
                        SCAN_GROUP_SIZE * group + state if state and not prefix else 0
                    )
                    assert (code & 0xF) + 16 * (code >> 4) == code
                    assert 0 <= (code & 0xF) <= 15
                    assert 0 <= (code >> 4) <= 8
                    selector_states += 1

    centers = official_p16_centers()
    assert len(centers) == P16
    geometry_certified_points = 0
    geometry_uncertified_boundaries = 0
    for center in centers:
        for error in range(P16_CERTIFIED_ERROR_MIN, P16_CERTIFIED_ERROR_MAX + 1):
            assert nearest_p16_slot(center, error) == center.code
            geometry_certified_points += 1
        for boundary in (-P16_BOUNDARY_ERROR, P16_BOUNDARY_ERROR):
            assert not p16_margin_certifies(boundary)
            geometry_uncertified_boundaries += 1

    ledger = noise_ledger()
    assert all(entry.raw_l1 <= entry.max_noise_level for entry in ledger)
    assert all(entry.margin_rescaling_factor == 1 for entry in ledger)
    assert {entry.raw_l1 for entry in ledger} >= {5, 7, 8, 10}
    assert any(
        entry.node_family == "A40 prospective gallery OR fan-in 7"
        and not entry.in_materialized_a44_graph
        for entry in ledger
    )

    counts = a44_counts(127)
    assert counts == Counts(3_655, 3_274, 4_206)
    wire = wire_projection()
    assert wire["single_lwe_bytes"] == 16_464
    assert wire["two_lwe_bytes"] == 32_856
    assert wire["additional_bytes"] == 16_392

    conditional_union_log2 = math.log2(counts.output_marginals) + LOG2_P_FAIL_PER_EVENT
    return {
        "status": "PASS",
        "scope": "static_clear_geometry_noise_only_no_cargo_no_fhe",
        "parameter_profile": asdict(PARAMETER_PROFILE),
        "parameter_binding": asdict(EXPECTED_BINDING),
        "parameter_canonical_sha256_verified": True,
        "serialized_compatible_with_a41": False,
        "exhaustive_binary_vectors_n_le_16": exhaustive_vectors,
        "representative_vectors_n_le_128": representative_vectors,
        "selector_states": selector_states,
        "a44_n127": asdict(counts),
        "wire_output_lwes": OUTPUT_LWES,
        "wire": wire,
        "p16_geometry": {
            "delta_log": BOOL_DELTA_LOG,
            "delta": P16_DELTA,
            "half_margin_torus": P16_HALF_MARGIN_TORUS,
            "rotation_step": P16_ROTATION_STEP,
            "certified_rotation_errors": [
                P16_CERTIFIED_ERROR_MIN,
                P16_CERTIFIED_ERROR_MAX,
            ],
            "uncertified_boundaries": [
                -P16_BOUNDARY_ERROR,
                P16_BOUNDARY_ERROR,
            ],
            "centers": [asdict(center) for center in centers],
            "certified_points_checked": geometry_certified_points,
            "uncertified_boundaries_checked": geometry_uncertified_boundaries,
        },
        "noise_ledger": [asdict(entry) for entry in ledger],
        "all_ledger_raw_l1_le_15": True,
        "margin_rescaling_used": False,
        "conditional_union_bound": {
            "premise": "only if every counted custom marginal inherits preset per-event contract",
            "events": counts.output_marginals,
            "per_event_log2_p_fail": LOG2_P_FAIL_PER_EVENT,
            "query_log2_upper": conditional_union_log2,
            "query_probability_upper": 2**conditional_union_log2,
        },
        "open_obligations": [
            "raw_lut_equivalence",
            "manylut_output_correlation_and_event_accounting",
            "gaussian_initial_score_tail_replacing_tuniform_zero_support_term",
            "authenticated_serialized_parameter_envelopes",
            "end_to_end_pfail",
        ],
        "end_to_end_numeric_upper": None,
        "a40_combination_materialized": False,
        "a41_component_fhe_validated": False,
        "a44_component_fhe_validated": False,
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
            "PASS,A44_clear_geometry_noise_model,"
            "N127=3655/3274/4206,output_lwes=2,max_noise=15,"
            "raw_l1=5/7/8/10,margin_rescaling=false,"
            "component_fhe=false,end_to_end_pfail=false"
        )


if __name__ == "__main__":
    main()
