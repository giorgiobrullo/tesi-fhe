#!/usr/bin/env python3
"""Static integration audit for the A44 max-15 preset and A41 two-LWE output.

This is deliberately a clear/structural model.  It performs no Cargo build,
key generation, encryption, programmable bootstrap, or timing measurement.
In particular, a raw-L1 value below the preset's advertised max-noise level is
recorded as geometry evidence, not promoted to an end-to-end p-fail theorem.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass
from itertools import product
from pathlib import Path


AUDIT_DIR = Path(__file__).resolve().parent
REPO_ROOT = AUDIT_DIR.parents[1]

MAX_GALLERY_SIZE = 128
SCAN_GROUP_SIZE = 3
REDUCTION_RADIX = 5
LEGACY_REDUCTION_RADIX = 4
OUTPUT_LWES = 2

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
OLD_A41_PARAMETER_SYMBOL = "V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64"

MESSAGE_MODULUS = 2
CARRY_MODULUS = 8
PLAINTEXT_MODULUS = MESSAGE_MODULUS * CARRY_MODULUS
MAX_NOISE_LEVEL = 15
LOG2_P_FAIL_PER_EVENT = -64.088
POLYNOMIAL_SIZE = 2_048
P16_DELTA_LOG = 59
P16_DELTA = 1 << P16_DELTA_LOG
P16_ROTATION_STEP = POLYNOMIAL_SIZE // PLAINTEXT_MODULUS
P16_STRICT_ERROR_MIN = -(P16_ROTATION_STEP // 2 - 1)
P16_STRICT_ERROR_MAX = P16_ROTATION_STEP // 2 - 1
P16_UNCERTIFIED_BOUNDARY = P16_ROTATION_STEP // 2

LWE_SIZE_WORDS = POLYNOMIAL_SIZE + 1
HEADER_WORDS_WITH_LENGTH_PREFIX = 9
WORD_BYTES = 8


@dataclass(frozen=True)
class Counts:
    blind_rotations: int
    key_switches: int
    output_marginals: int


@dataclass(frozen=True)
class CountBreakdown:
    gallery_size: int
    groups: int
    unchanged_core_blind_rotations: int
    low_path_blind_rotations: int
    scan_output_blind_rotations: int
    counts: Counts


@dataclass(frozen=True)
class ExactIdResult:
    gallery_size: int
    accepted_candidates: int
    low: int
    high: int
    code: int


@dataclass(frozen=True)
class NoiseLedgerEntry:
    node_family: str
    raw_l1: int
    headroom_below_15: int
    in_a59_path: bool
    transfer_status: str


@dataclass(frozen=True)
class SourceAnchor:
    label: str
    relative_path: str
    expected_sha256: str


SOURCE_ANCHORS = (
    SourceAnchor(
        "A38 frozen combined core",
        "tmp/a38-combined-prototype/src/private_argmin.rs",
        "9fc9013f1b322ad89d4a3902de3d945abf5aec9f335f1fb4088d73b44c151e79",
    ),
    SourceAnchor(
        "A41 two-LWE core",
        "tmp/a41-combined-two-lwe-prototype/src/private_argmin.rs",
        "8c9675e0019e106ad673e16e1a06ceed8ced35256d4b444335708cb87cfdfd35",
    ),
    SourceAnchor(
        "A41 clear/count model",
        "tmp/a41-combined-two-lwe-prototype/a41_clear_and_count_model.py",
        "e2edd204f3ada5fb0730b0213fed435833255b67c205345f311483fcbcd08b43",
    ),
    SourceAnchor(
        "A44 max-15 plus two-LWE core",
        "tmp/a44-p16-retune-prototype/src/private_argmin.rs",
        "d6793b2a5040d39060b561552d976d4718f299d35a051a3304eaa3219bab912c",
    ),
    SourceAnchor(
        "A44 clear/geometry/noise model",
        "tmp/a44-p16-retune-prototype/a44_clear_geometry_noise_model.py",
        "1fc2e3e657e1f75133889aae61df5aa6c10d9441a5b1566f9fc9b26a89140302",
    ),
)


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


def operation_breakdown(gallery_size: int) -> CountBreakdown:
    """Re-derive the unchanged A38/A41/A44 graph count."""

    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError("gallery_size must be in 1..128")

    n = gallery_size
    legacy_total = (
        27 * n
        + 8 * reduction_nodes(n, LEGACY_REDUCTION_RADIX)
        + legacy_first_one_scan_nodes(n)
        + legacy_output_nodes(n)
        - 1
    )
    legacy_low = 12 * n + 8 * reduction_nodes(n, LEGACY_REDUCTION_RADIX)
    legacy_scan_output = legacy_first_one_scan_nodes(n) + legacy_output_nodes(n)
    unchanged_core = legacy_total - legacy_low - legacy_scan_output

    low_path = 10 * n + 8 * reduction_nodes(n, REDUCTION_RADIX)
    groups = ceil_div(n, SCAN_GROUP_SIZE)
    group_nodes = sum(
        min(SCAN_GROUP_SIZE, n - start) > 1 for start in range(0, n, SCAN_GROUP_SIZE)
    )
    prefix_nodes = exclusive_prefix_nodes(groups, REDUCTION_RADIX)
    digit_nodes = 2 * reduction_nodes(groups, REDUCTION_RADIX)
    scan_output = 2 * group_nodes + prefix_nodes + groups + digit_nodes

    blind_rotations = unchanged_core + low_path + scan_output
    counts = Counts(
        blind_rotations=blind_rotations,
        key_switches=blind_rotations - 3 * n,
        output_marginals=blind_rotations + 4 * n + groups,
    )
    return CountBreakdown(
        gallery_size=n,
        groups=groups,
        unchanged_core_blind_rotations=unchanged_core,
        low_path_blind_rotations=low_path,
        scan_output_blind_rotations=scan_output,
        counts=counts,
    )


def split_code(code: int) -> tuple[int, int]:
    if not 0 <= code <= MAX_GALLERY_SIZE:
        raise ValueError("code must be in 0..128")
    return code % PLAINTEXT_MODULUS, code // PLAINTEXT_MODULUS


def reconstruct_code(low: int, high: int) -> int:
    if not 0 <= low < PLAINTEXT_MODULUS:
        raise ValueError("low must be a p16 digit")
    if not 0 <= high <= MAX_GALLERY_SIZE // PLAINTEXT_MODULUS:
        raise ValueError("high must be in 0..8")
    return low + PLAINTEXT_MODULUS * high


def evaluate_candidates(candidates: tuple[int, ...]) -> ExactIdResult:
    """Model A41's first-one scan and two-p16-digit terminal contract."""

    if not 1 <= len(candidates) <= MAX_GALLERY_SIZE:
        raise ValueError("candidate vector length must be in 1..128")
    if any(candidate not in (0, 1) for candidate in candidates):
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
    contributions = tuple(
        SCAN_GROUP_SIZE * group + state if state and not prefix else 0
        for group, (state, prefix) in enumerate(zip(local_first, group_prefixes))
    )
    code = sum(contributions)
    expected = next(
        (index + 1 for index, candidate in enumerate(candidates) if candidate), 0
    )
    assert code == expected
    assert sum(contribution != 0 for contribution in contributions) <= 1
    low, high = split_code(code)
    assert reconstruct_code(low, high) == code
    return ExactIdResult(
        gallery_size=len(candidates),
        accepted_candidates=sum(candidates),
        low=low,
        high=high,
        code=code,
    )


def evaluate_scores(scores: tuple[int, ...], threshold: int) -> ExactIdResult:
    """Bridge the clear distance contract to A41's first-one candidate scan.

    Distances are minimized, threshold equality is accepted, and the first
    identity wins a tie.  The model uses one public uniform threshold, as A44
    does.  The toy threshold values used for exhaustive checking are a clear
    semantic domain: this function does not claim that every value is admitted
    by A44's separate aligned-domain runtime guard.
    """

    if not 1 <= len(scores) <= MAX_GALLERY_SIZE:
        raise ValueError("score vector length must be in 1..128")
    minimum = min(scores)
    accepted = minimum <= threshold
    candidates = tuple(int(accepted and score == minimum) for score in scores)
    result = evaluate_candidates(candidates)
    expected = scores.index(minimum) + 1 if accepted else 0
    assert result.code == expected
    return result


def noise_ledger() -> tuple[NoiseLedgerEntry, ...]:
    """Raw-L1 ledger without widened-margin rescaling."""

    rows = (
        (
            "A34 residual classifier",
            8,
            True,
            "numeric_fit_only_raw_lut_contract_open",
        ),
        (
            "A36 current two-chunk path",
            10,
            True,
            "numeric_fit_only_raw_lut_contract_open",
        ),
        (
            "A38/A41 radix-5 scan reductions",
            5,
            True,
            "nominal_fit_manylut_accounting_open",
        ),
        (
            "A41 terminal low/high p16 roots",
            5,
            True,
            "terminal_conditionally_closed_if_preset_contract_transfers",
        ),
    )
    return tuple(
        NoiseLedgerEntry(
            node_family=name,
            raw_l1=raw_l1,
            headroom_below_15=MAX_NOISE_LEVEL - raw_l1,
            in_a59_path=in_path,
            transfer_status=status,
        )
        for name, raw_l1, in_path, status in rows
    )


def conditional_failure_arithmetic(gallery_size: int) -> dict[str, object]:
    counts = operation_breakdown(gallery_size).counts
    terminal_events = OUTPUT_LWES
    terminal_log2 = math.log2(terminal_events) + LOG2_P_FAIL_PER_EVENT
    all_marginals_log2 = math.log2(counts.output_marginals) + LOG2_P_FAIL_PER_EVENT
    return {
        "premise": (
            "only if every counted custom marginal inherits the official "
            "per-event preset contract"
        ),
        "terminal_events": terminal_events,
        "terminal_log2_upper": terminal_log2,
        "terminal_probability_upper": 2**terminal_log2,
        "all_marginal_events_including_terminal": counts.output_marginals,
        "all_marginals_log2_upper": all_marginals_log2,
        "all_marginals_probability_upper": 2**all_marginals_log2,
        "independence_assumed": False,
        "terminal_already_in_all_marginals": True,
    }


def wire_projection() -> dict[str, int | float]:
    one_lwe = WORD_BYTES * (HEADER_WORDS_WITH_LENGTH_PREFIX + LWE_SIZE_WORDS)
    two_lwe = WORD_BYTES * (
        HEADER_WORDS_WITH_LENGTH_PREFIX + OUTPUT_LWES * LWE_SIZE_WORDS
    )
    return {
        "single_lwe_bytes": one_lwe,
        "two_lwe_bytes": two_lwe,
        "additional_bytes": two_lwe - one_lwe,
        "size_ratio": two_lwe / one_lwe,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_source_anchors() -> list[dict[str, object]]:
    results = []
    for anchor in SOURCE_ANCHORS:
        path = REPO_ROOT / anchor.relative_path
        actual = sha256_file(path)
        results.append(
            {
                "label": anchor.label,
                "relative_path": anchor.relative_path,
                "expected_sha256": anchor.expected_sha256,
                "actual_sha256": actual,
                "matches": actual == anchor.expected_sha256,
            }
        )
    if not all(result["matches"] for result in results):
        raise AssertionError("one or more frozen source anchors changed")
    return results


def verify_a44_materialized_contract() -> dict[str, object]:
    core_path = REPO_ROOT / "tmp/a44-p16-retune-prototype/src/private_argmin.rs"
    core = core_path.read_text()
    canonical_match = re.search(
        r'pub const A44_PARAMETER_CANONICAL: &str = "([^"]+)";', core
    )
    fingerprint_match = re.search(
        r'A44_PARAMETER_FINGERPRINT_SHA256: &str =\s*"([0-9a-f]{64})";', core
    )
    if canonical_match is None or fingerprint_match is None:
        raise AssertionError(
            "A44 parameter binding is absent from the Rust materialization"
        )
    if canonical_match.group(1) != PARAMETER_CANONICAL:
        raise AssertionError("A44 Rust canonical parameter string changed")
    if fingerprint_match.group(1) != PARAMETER_FINGERPRINT_SHA256:
        raise AssertionError("A44 Rust parameter fingerprint changed")

    required_fragments = (
        PARAMETER_SYMBOL,
        "pub type A44OperationCounts = A41OperationCounts;",
        "pub fn private_argmin_two_lwe_a44(",
        "AlignedWireFormat::TwoP16Digits",
        "low_nibble: output.low_nibble",
        "high_nibble: output.high_nibble",
        "validate_a44_parameter_binding(parameter_binding, server_key)?;",
    )
    missing = [fragment for fragment in required_fragments if fragment not in core]
    if missing:
        raise AssertionError(f"A44 Rust contract fragments missing: {missing}")
    if OLD_A41_PARAMETER_SYMBOL in core:
        raise AssertionError("A44 core still references the old A41 parameter preset")
    return {
        "canonical_parameter_string_matches": True,
        "parameter_fingerprint_matches": True,
        "guarded_two_lwe_entrypoint_present": True,
        "old_a41_parameter_absent": True,
    }


def validate() -> dict[str, object]:
    if hashlib.sha256(PARAMETER_CANONICAL.encode()).hexdigest() != (
        PARAMETER_FINGERPRINT_SHA256
    ):
        raise AssertionError("canonical parameter fingerprint mismatch")
    if MESSAGE_MODULUS * CARRY_MODULUS != 16:
        raise AssertionError("A59 requires the unchanged p16 plaintext geometry")

    source_anchors = verify_source_anchors()
    rust_contract = verify_a44_materialized_contract()

    binary_vectors = 0
    for gallery_size in range(1, 17):
        for candidates in product((0, 1), repeat=gallery_size):
            evaluate_candidates(candidates)
            binary_vectors += 1

    representative_vectors = 0
    for gallery_size in range(1, MAX_GALLERY_SIZE + 1):
        evaluate_candidates((0,) * gallery_size)
        representative_vectors += 1
        for first in range(gallery_size):
            patterns = (
                (0,) * first + (1,) + (0,) * (gallery_size - first - 1),
                (0,) * first + (1,) * (gallery_size - first),
                (0,) * first
                + (1,)
                + tuple(
                    (index - first) % 2 for index in range(first + 1, gallery_size)
                ),
            )
            for candidates in patterns:
                evaluate_candidates(candidates)
                representative_vectors += 1

    score_cases = 0
    for gallery_size in range(1, 7):
        for scores in product(range(4), repeat=gallery_size):
            for threshold in range(-1, 5):
                evaluate_scores(scores, threshold)
                score_cases += 1

    digit_codes = 0
    for code in range(MAX_GALLERY_SIZE + 1):
        low, high = split_code(code)
        assert reconstruct_code(low, high) == code
        digit_codes += 1

    p16_points = 0
    for code in range(PLAINTEXT_MODULUS):
        center = code * P16_ROTATION_STEP
        for error in range(P16_STRICT_ERROR_MIN, P16_STRICT_ERROR_MAX + 1):
            decoded = (center + error + P16_UNCERTIFIED_BOUNDARY) // P16_ROTATION_STEP
            assert decoded == code
            p16_points += 1

    ledger = noise_ledger()
    assert all(row.in_a59_path for row in ledger)
    assert all(row.raw_l1 <= MAX_NOISE_LEVEL for row in ledger)
    assert max(row.raw_l1 for row in ledger) == 10

    n127 = operation_breakdown(127)
    n128 = operation_breakdown(128)
    assert n127.counts == Counts(3_655, 3_274, 4_206)
    assert n128.counts == Counts(3_682, 3_298, 4_237)

    wire = wire_projection()
    assert wire["single_lwe_bytes"] == 16_464
    assert wire["two_lwe_bytes"] == 32_856
    assert wire["additional_bytes"] == 16_392

    return {
        "status": "PASS_STATIC_CONDITIONAL",
        "scope": "clear_semantics_structure_and_binding_only_no_build_no_fhe",
        "a59_is_new_graph": False,
        "integration_result": (
            "A44 already materializes the A41 two-LWE graph under the max-15 preset; "
            "A59 independently freezes and audits that combined contract"
        ),
        "parameter": {
            "tfhe_version": TFHE_VERSION,
            "symbol": PARAMETER_SYMBOL,
            "params_id": PARAMS_ID,
            "canonical": PARAMETER_CANONICAL,
            "fingerprint_sha256": PARAMETER_FINGERPRINT_SHA256,
            "message_modulus": MESSAGE_MODULUS,
            "carry_modulus": CARRY_MODULUS,
            "plaintext_modulus": PLAINTEXT_MODULUS,
            "max_noise_level": MAX_NOISE_LEVEL,
            "nominal_log2_p_fail_per_event": LOG2_P_FAIL_PER_EVENT,
            "fresh_keys_required_vs_a41": True,
        },
        "source_anchors": source_anchors,
        "a44_rust_contract": rust_contract,
        "semantic_checks": {
            "exhaustive_binary_vectors_n_le_16": binary_vectors,
            "representative_vectors_n_le_128": representative_vectors,
            "exhaustive_score_threshold_cases_n_le_6": score_cases,
            "all_codes_split_and_reconstructed": digit_codes,
            "observable_contract": "0=reject, i+1=first nearest accepted identity",
            "client_reconstruction": "low + 16*high",
            "server_linear_postprocessing_after_roots": False,
        },
        "counts": {
            "n127": asdict(n127),
            "n128": asdict(n128),
        },
        "wire": wire,
        "p16_geometry": {
            "delta_log": P16_DELTA_LOG,
            "rotation_step": P16_ROTATION_STEP,
            "strict_certified_error_interval": [
                P16_STRICT_ERROR_MIN,
                P16_STRICT_ERROR_MAX,
            ],
            "uncertified_half_cell_boundaries": [
                -P16_UNCERTIFIED_BOUNDARY,
                P16_UNCERTIFIED_BOUNDARY,
            ],
            "strict_points_checked": p16_points,
        },
        "noise_ledger": [asdict(row) for row in ledger],
        "failure_arithmetic": {
            "n127": conditional_failure_arithmetic(127),
            "n128": conditional_failure_arithmetic(128),
        },
        "proved_static": [
            "clear reject/exact-first-ID/tie/threshold-equality semantics",
            "two p16 digits reconstruct every code 0..128",
            "N127 and N128 BR/KS/marginal structural counts",
            "canonical parameter fingerprint and frozen source identities",
            "all listed raw-L1 geometry values are at most 15 without rescaling",
        ],
        "conditional_only": [
            "custom raw LUT and ManyLUT marginals inherit nominal preset p-fail",
            "terminal two-LWE union is at most 2p",
            "whole internal marginal ledger is at most m*p",
        ],
        "open_obligations": [
            "fresh-key A44 component FHE validation",
            "raw core_crypto LUT equivalence to official shortint noise contract",
            "correlated extraction and A34 classifier accounting",
            "Gaussian initial-score tail bound",
            "authenticated serialized parameter/key/ciphertext envelope",
            "end-to-end numeric p-fail bound",
            "service and primary/paired benchmark validation",
        ],
        "component_fhe_validated": False,
        "end_to_end_numeric_p_fail_upper": None,
        "promotion_status": "NO_GO_UNTIL_OPEN_OBLIGATIONS_CLOSE",
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
            "PASS_STATIC_CONDITIONAL,A59_max15_two_lwe,"
            "N127=3655/3274/4206,N128=3682/3298/4237,"
            "output_lwes=2,exact_id=true,max_raw_l1=10,max_noise=15,"
            "component_fhe=false,end_to_end_pfail=false"
        )


if __name__ == "__main__":
    main()
