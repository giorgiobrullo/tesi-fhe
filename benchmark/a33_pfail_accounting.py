#!/usr/bin/env python3
"""Reproduce conditional p-fail arithmetic for the frozen A33 exact-ID evidence.

This generator does not issue an end-to-end correctness certificate. It reconstructs the A33
blind-rotation and structural key-switch counts independently for every gallery size, binds them
to the complete core extracted from the frozen source patch, and evaluates explicitly conditional
union-bound arithmetic. The final unbootstrapped decode term remains unvalued.

The primary 632-query evidence is frozen by canonical path and JSON/CSV hashes below. Normal
generation fails closed if either artifact or any of its exact-ID invariants drifts.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple


GALLERY_SIZE = 127
MAX_GALLERY_SIZE = 128
LOG2_P_FAIL = -71.625
SECURITY_BITS_REPORTED = 132
MULTI_OUTPUT_ROTATIONS_PER_TEMPLATE = 5
MULTI_OUTPUT_ROTATION_CLASSES_PER_TEMPLATE = {
    "low_to_full_fused_bit3": 1,
    "high_fused_bits4_to6": 3,
    "sparse_code_and_signed_flag": 1,
}
EXPECTED_PRIMARY_QUERIES = 632
CONFIDENCE_ALPHA = 0.05
OR_BLOCK = 4
FIRST_ONE_GROUP = 3

FROZEN_CORE_MEMBER = "experiments/14_pipeline_tfhe_rs/src/private_argmin.rs"
PATCH_RELATIVE_PATH = "benchmark/patches/a33_aligned_sparse_source_2026-09-02.patch"
FRONTIER_JSON_RELATIVE_PATH = (
    "benchmark/results/fhe_digiface_exact_frontier_a33_final_2026-09-02.json"
)
FRONTIER_CSV_RELATIVE_PATH = (
    "benchmark/results/fhe_digiface_exact_frontier_a33_final_2026-09-02.csv"
)
DIAGNOSTIC_RELATIVE_PATH = "tmp/a33-aligned-sparse-2026-09-02/a33_full_validation.txt"
CANONICAL_OUTPUT_RELATIVE_PATH = (
    "benchmark/results/exact_id_a33_pfail_accounting_2026-09-02.json"
)

EXPECTED_A33_BINARY_SHA256 = (
    "13a1593be85d8e585bdf48d7d4e8a09a57a82902f6e8da7299a5b02415a3ea59"
)
EXPECTED_STATIC_HASHES = {
    "core": "1d50a2b0e6f98069e0ab2de0eb228133543b5792cf0b34016031593de1e0850d",
    "patch": "6d07077efc52e721399740ef7d443ca87ee0a6c575cd19b7a453d5109224f7f5",
    "frontier_json": "d15933731a313ed82445e03ca37e999178cdf18c2f7953c86e8b38b9d7cd3e15",
    "frontier_csv": "e72dd64db5751ee49ca2016908698f583e1f7d16c33c44d77beb3d9a7e68e98d",
    "diagnostic": "2c3fd446b4f0a2f382a2ec5c939facd427680b0d1e88315c57a474e55a279595",
    "parameter_source": "14a3c8cae508fec1f96e76ed74e186efbd005c0c84292975333dc202a6987bb6",
    "tfhe_readme": "c224297542eff2e6bae585b320144be02b6475dd43656be2c59aaed41d704052",
}

FROZEN_PRIMARY_JSON_RELATIVE_PATH: Optional[str] = (
    "benchmark/results/fhe_digiface_exact_primary_a33_2026-09-02.json"
)
EXPECTED_PRIMARY_JSON_SHA256: Optional[str] = (
    "e3ef7b5ae74c85e883d8ed3b2670fb6efbd20291775752fefe1ec56c0f1a9467"
)
EXPECTED_PRIMARY_CSV_SHA256: Optional[str] = (
    "0d35640d7803969f4fb4781bac3975e367e477447ecbf6ffc9fb6a090669a011"
)

EXPECTED_TIGHT_DOMAIN = {"l": -987, "u": 2329, "larghezza": 3317}
EXPECTED_EXECUTION_DOMAIN = {"l": -1019, "u": 2329, "larghezza": 3349}
EXPECTED_ARGMIN_PATH = "a33_aligned_sparse"
EXPECTED_UNIFORM_THRESHOLD = 4
EXPECTED_EXACT_CONTRACT = {
    "code_delta_log": 56,
    "codice": "0=rifiuto; i+1=identita_accettata",
    "output_mode": 2,
    "un_solo_lwe": True,
}
EXPECTED_FIXTURES = {
    1: (31, 28),
    3: (100, 91),
    64: (2141, 1949),
    127: (4273, 3892),
    128: (4303, 3919),
}

STAGE_FORMULAS = {
    "score_linear": {"blind_rotations": "0", "key_switches": "0"},
    "aligned_extraction_and_sparse_classifier": {
        "blind_rotations": "13*N",
        "key_switches": "10*N",
    },
    "aligned_admission_and_argmin_8_bits": {
        "blind_rotations": "14*N + 9*OR(N) + ceil(N/2) + OR(ceil(N/2))",
        "key_switches": "same as blind rotations",
    },
    "first_minimum_scan": {
        "blind_rotations": "FIRST_ONE_SCAN(N)",
        "key_switches": "same as blind rotations",
    },
    "uniform_threshold_folded_into_admission": {
        "blind_rotations": "0",
        "key_switches": "0",
    },
    "encrypted_id_encoding": {
        "blind_rotations": "OUTPUT_CODE(N)",
        "key_switches": "same as blind rotations",
    },
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_sha256(path: Path, expected: str, label: str) -> str:
    if not path.is_file():
        raise SystemExit("missing {}: {}".format(label, path))
    actual = sha256_file(path)
    if actual != expected:
        raise SystemExit(
            "{} SHA-256 drift: expected {}, got {}".format(label, expected, actual)
        )
    return actual


def extract_new_file_from_patch(patch_path: Path, member: str) -> bytes:
    """Extract a complete file added from ``/dev/null`` by the frozen patch."""

    marker = "diff --git a/{0} b/{0}\n".format(member)
    lines = patch_path.read_text(encoding="utf-8").splitlines(keepends=True)
    try:
        start = lines.index(marker)
    except ValueError as error:
        raise SystemExit("frozen patch does not contain {}".format(member)) from error

    header = lines[start : start + 6]
    if (
        "new file mode " not in "".join(header)
        or "+++ b/{}\n".format(member) not in header
    ):
        raise SystemExit(
            "{} is not a complete new-file member in the frozen patch".format(member)
        )

    content = []
    in_hunk = False
    for line in lines[start + 1 :]:
        if line.startswith("diff --git "):
            break
        if line.startswith("@@ "):
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            content.append(line[1:])
        elif line.startswith("\\ No newline at end of file"):
            if content:
                content[-1] = content[-1].removesuffix("\n")
        else:
            raise SystemExit(
                "unexpected non-addition line while extracting new file {}: {!r}".format(
                    member, line
                )
            )
    if not content:
        raise SystemExit("frozen patch member {} is empty".format(member))
    return "".join(content).encode("utf-8")


def validate_core_contract(frozen_core: bytes) -> Dict[str, Any]:
    text = frozen_core.decode("utf-8")
    required_fragments = (
        "fn aligned_sparse_pbs_count(gallery_size: usize) -> Option<u64>",
        "27 * n",
        "+ 9 * or_reduction_pbs(gallery_size)",
        "+ or_reduction_pbs(pairs)",
        "fn aligned_sparse_ks_count(gallery_size: usize) -> Option<u64>",
        "pbs - 3 * gallery_size as u64",
        "fn private_argmin_aligned_sparse_impl(",
        "let sparse_outputs: Vec<SparseClassifierOutput>",
        "classify_sparse(residual, &aligned_classifier_accumulators[index % 2])",
        "make_correction_accumulators(FULL_DELTA_LOG, LOW_EXTRACTED_BITS, 3..4)",
        "make_correction_accumulators(HIGH_DELTA_LOG, ALIGNED_HIGH_EXTRACTED_BITS - 1, 0..3)",
        "Some(extracted.corrections_lsb_first[3].clone())",
    )
    missing = [fragment for fragment in required_fragments if fragment not in text]
    if missing:
        raise SystemExit(
            "frozen A33 core lacks required structural fragments: {!r}".format(missing)
        )
    return {
        "complete_new_file_member": True,
        "utf8_bytes": len(frozen_core),
        "required_structural_fragments_present": list(required_fragments),
    }


def conditional_union(event_count: int, log2_p_fail: float) -> Dict[str, Any]:
    if event_count <= 0:
        raise ValueError("event_count must be positive")
    if not math.isfinite(log2_p_fail) or log2_p_fail > 0.0:
        raise ValueError("log2_p_fail must be finite and non-positive")
    per_event = 2.0**log2_p_fail
    upper = min(1.0, event_count * per_event)
    return {
        "event_count": event_count,
        "nominal_per_event_probability": per_event,
        "conditional_union_upper": upper,
        "conditional_union_log2": math.log2(upper) if upper else float("-inf"),
    }


def zero_failure_upper(sample_count: int, alpha: float) -> float:
    """One-sided exact binomial upper confidence limit for 0/sample_count."""

    if sample_count <= 0:
        raise ValueError("sample_count must be positive")
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be between zero and one")
    return 1.0 - alpha ** (1.0 / sample_count)


def or_reduction_pbs(items: int) -> int:
    if items <= 0:
        raise ValueError("OR reduction requires at least one item")
    count = 0
    while items > 1:
        items = (items + OR_BLOCK - 1) // OR_BLOCK
        count += items
    return count


def radix4_exclusive_prefix_pbs(items: int) -> int:
    if items <= 0:
        raise ValueError("prefix scan requires at least one item")
    if items <= 2:
        return 0
    if items <= OR_BLOCK:
        return items - 2
    totals = 0
    expansion = 0
    groups = 0
    for start in range(0, items, OR_BLOCK):
        length = min(OR_BLOCK, items - start)
        groups += 1
        totals += int(length > 1)
        expansion += max(0, length - 2) if start == 0 else length - 1
    return totals + expansion + radix4_exclusive_prefix_pbs(groups)


def first_one_scan_pbs(items: int) -> int:
    if items <= 0:
        raise ValueError("first-one scan requires at least one item")
    groups = (items + FIRST_ONE_GROUP - 1) // FIRST_ONE_GROUP
    group_totals = sum(
        min(FIRST_ONE_GROUP, items - start) > 1
        for start in range(0, items, FIRST_ONE_GROUP)
    )
    return group_totals + radix4_exclusive_prefix_pbs(groups) + items


def output_code_pbs(gallery_size: int) -> int:
    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError("gallery size outside 1..128")
    positions = [
        bit
        for bit in range(gallery_size.bit_length())
        if any(((index + 1) >> bit) & 1 for index in range(gallery_size))
    ]
    bit_pbs = sum(
        max(
            1,
            or_reduction_pbs(
                sum(((index + 1) >> bit) & 1 for index in range(gallery_size))
            ),
        )
        for bit in positions
    )
    return bit_pbs + (len(positions) + 2) // 3


def a33_stage_breakdown(gallery_size: int) -> Dict[str, Dict[str, int]]:
    """Reconstruct A33 BR/KS counts independently from the frozen implementation."""

    if not 1 <= gallery_size <= MAX_GALLERY_SIZE:
        raise ValueError("gallery size outside 1..128")
    reduction = or_reduction_pbs(gallery_size)
    pairs = (gallery_size + 1) // 2
    pair_reduction = or_reduction_pbs(pairs)
    selection = 14 * gallery_size + 9 * reduction + pairs + pair_reduction
    scan = first_one_scan_pbs(gallery_size)
    output = output_code_pbs(gallery_size)
    stages = {
        "score_linear": {"blind_rotations": 0, "key_switches": 0},
        "aligned_extraction_and_sparse_classifier": {
            "blind_rotations": 13 * gallery_size,
            "key_switches": 10 * gallery_size,
        },
        "aligned_admission_and_argmin_8_bits": {
            "blind_rotations": selection,
            "key_switches": selection,
        },
        "first_minimum_scan": {
            "blind_rotations": scan,
            "key_switches": scan,
        },
        "uniform_threshold_folded_into_admission": {
            "blind_rotations": 0,
            "key_switches": 0,
        },
        "encrypted_id_encoding": {
            "blind_rotations": output,
            "key_switches": output,
        },
    }
    blind_rotations = sum(stage["blind_rotations"] for stage in stages.values())
    key_switches = sum(stage["key_switches"] for stage in stages.values())
    if key_switches != blind_rotations - 3 * gallery_size:
        raise AssertionError("A33 KS invariant KS=BR-3N failed")
    return stages


def operation_record(gallery_size: int) -> Dict[str, Any]:
    stages = a33_stage_breakdown(gallery_size)
    blind_rotations = sum(stage["blind_rotations"] for stage in stages.values())
    key_switches = sum(stage["key_switches"] for stage in stages.values())
    if (
        sum(MULTI_OUTPUT_ROTATION_CLASSES_PER_TEMPLATE.values())
        != MULTI_OUTPUT_ROTATIONS_PER_TEMPLATE
    ):
        raise AssertionError("A33 multi-output rotation classes no longer sum to 5N")
    multi_output_rotations = MULTI_OUTPUT_ROTATIONS_PER_TEMPLATE * gallery_size
    return {
        "gallery_size": gallery_size,
        "blind_rotations": blind_rotations,
        "key_switches_structural": key_switches,
        "multi_output_rotations": multi_output_rotations,
        "output_marginals_conservative": blind_rotations + multi_output_rotations,
        "stage_breakdown": stages,
    }


def operation_sweep() -> Sequence[Dict[str, Any]]:
    records = [operation_record(size) for size in range(1, MAX_GALLERY_SIZE + 1)]
    if [record["gallery_size"] for record in records] != list(
        range(1, MAX_GALLERY_SIZE + 1)
    ):
        raise AssertionError("A33 gallery sweep is incomplete")
    for size, (expected_br, expected_ks) in EXPECTED_FIXTURES.items():
        record = records[size - 1]
        actual = (record["blind_rotations"], record["key_switches_structural"])
        if actual != (expected_br, expected_ks):
            raise AssertionError(
                "A33 N={} fixture drift: expected {}, got {}".format(
                    size, (expected_br, expected_ks), actual
                )
            )
    return records


def normalized_domain(value: Any, context: str) -> Dict[str, int]:
    if not isinstance(value, Mapping):
        raise SystemExit("{} is not an object".format(context))
    lower = value.get("l")
    upper = value.get("u")
    width = value.get("larghezza")
    if not all(type(item) is int for item in (lower, upper, width)):
        raise SystemExit("{} lacks canonical integer fields".format(context))
    if lower > upper or width != upper - lower + 1:
        raise SystemExit("{} is not a canonical inclusive domain".format(context))
    return {"l": lower, "u": upper, "larghezza": width}


def validate_a33_state(evidence: Mapping[str, Any], context: str) -> Dict[str, Any]:
    server = evidence.get("server_state")
    if not isinstance(server, Mapping):
        raise SystemExit("{} lacks server state".format(context))
    state = server.get("after_enrollment")
    if not isinstance(state, Mapping):
        raise SystemExit("{} lacks enrolled server state".format(context))
    tight = normalized_domain(state.get("dominio"), "{} tight domain".format(context))
    execution = normalized_domain(
        state.get("dominio_esecuzione"), "{} execution domain".format(context)
    )
    path = state.get("percorso_argmin")
    if tight != EXPECTED_TIGHT_DOMAIN:
        raise SystemExit("{} tight domain drifted: {!r}".format(context, tight))
    if execution != EXPECTED_EXECUTION_DOMAIN:
        raise SystemExit("{} execution domain drifted: {!r}".format(context, execution))
    if path != EXPECTED_ARGMIN_PATH:
        raise SystemExit("{} argmin path drifted: {!r}".format(context, path))
    gallery_size = state.get("iscritti")
    revision = state.get("revision")
    names = state.get("nomi")
    thresholds = state.get("soglie")
    if gallery_size != GALLERY_SIZE or revision != GALLERY_SIZE:
        raise SystemExit(
            "{} gallery/revision drifted: gallery={!r}, revision={!r}".format(
                context, gallery_size, revision
            )
        )
    if not isinstance(names, list) or len(names) != GALLERY_SIZE:
        raise SystemExit(
            "{} does not contain exactly 127 enrolled names".format(context)
        )
    if (
        state.get("soglia_default") != EXPECTED_UNIFORM_THRESHOLD
        or not isinstance(thresholds, list)
        or len(thresholds) != GALLERY_SIZE
        or any(
            type(threshold) is not int or threshold != EXPECTED_UNIFORM_THRESHOLD
            for threshold in thresholds
        )
    ):
        raise SystemExit("{} does not bind the uniform A33 threshold".format(context))
    if state.get("chiave") is not True:
        raise SystemExit(
            "{} does not report an enrolled evaluation key".format(context)
        )
    contract = state.get("contratto_esatto")
    if not isinstance(contract, Mapping) or any(
        contract.get(key) != value for key, value in EXPECTED_EXACT_CONTRACT.items()
    ):
        raise SystemExit("{} exact-ID output contract drifted".format(context))
    if server.get("exact_contract_and_query_headers_verified") is not True:
        raise SystemExit("{} did not verify the exact query contract".format(context))
    exit_code = server.get("exit_code")
    if exit_code not in (0, -15):
        raise SystemExit(
            "{} server has unexpected exit code {!r}".format(context, exit_code)
        )
    return {
        "tight_domain": tight,
        "execution_domain": execution,
        "argmin_path": path,
        "gallery_size": gallery_size,
        "uniform_threshold": EXPECTED_UNIFORM_THRESHOLD,
        "exact_contract": dict(EXPECTED_EXACT_CONTRACT),
        "exact_contract_and_query_headers_verified": True,
        "server_exit_code": exit_code,
        "server_termination": "normal_exit" if exit_code == 0 else "validator_sigterm",
    }


def validate_run_results(
    evidence: Mapping[str, Any], expected_queries: int, context: str
) -> Dict[str, Any]:
    results = evidence.get("results")
    if not isinstance(results, Mapping):
        raise SystemExit("{} lacks results".format(context))
    summary = {
        "success": evidence.get("success"),
        "measured_queries": results.get("measured_queries"),
        "rows_recorded": results.get("rows_recorded"),
        "planned_queries": results.get("planned_queries"),
        "operational_errors": results.get("operational_errors"),
        "semantic_discrepancies": results.get(
            "clear_vs_fhe_exact_result_discrepancies"
        ),
        "all_probe_ciphertexts_unique": results.get("all_probe_ciphertexts_unique"),
        "probe_ciphertexts_measured": results.get("probe_ciphertexts_measured"),
        "probe_ciphertexts_unique": results.get("probe_ciphertexts_unique"),
        "expected_authorized": results.get("expected_authorized"),
        "actual_authorized": results.get("actual_authorized"),
        "discrepancy_rows": results.get("discrepancy_rows"),
        "error_rows": results.get("error_rows"),
        "pbs_values": results.get("pbs_values"),
    }
    expected = {
        "success": True,
        "measured_queries": expected_queries,
        "rows_recorded": expected_queries,
        "planned_queries": expected_queries,
        "operational_errors": 0,
        "semantic_discrepancies": 0,
        "all_probe_ciphertexts_unique": True,
        "probe_ciphertexts_measured": expected_queries,
        "probe_ciphertexts_unique": expected_queries,
        "discrepancy_rows": [],
        "error_rows": [],
        "pbs_values": [4273],
    }
    fixed_summary = {
        key: value
        for key, value in summary.items()
        if key not in ("expected_authorized", "actual_authorized")
    }
    if fixed_summary != expected:
        raise SystemExit("{} invariants failed: {!r}".format(context, summary))
    expected_authorized = summary["expected_authorized"]
    actual_authorized = summary["actual_authorized"]
    if (
        type(expected_authorized) is not int
        or not 0 <= expected_authorized <= expected_queries
        or type(actual_authorized) is not int
        or actual_authorized != expected_authorized
    ):
        raise SystemExit(
            "{} authorization totals are inconsistent: expected={!r}, actual={!r}".format(
                context, expected_authorized, actual_authorized
            )
        )
    return summary


def _csv_bool(value: Any, context: str) -> bool:
    if value == "True":
        return True
    if value == "False":
        return False
    raise SystemExit("{} is not a canonical CSV boolean: {!r}".format(context, value))


def _csv_int(value: Any, context: str, *, optional: bool = False) -> Optional[int]:
    if optional and value == "":
        return None
    if not isinstance(value, str) or not value or value.strip() != value:
        raise SystemExit(
            "{} is not a canonical CSV integer: {!r}".format(context, value)
        )
    try:
        parsed = int(value)
    except ValueError as error:
        raise SystemExit(
            "{} is not a canonical CSV integer: {!r}".format(context, value)
        ) from error
    if str(parsed) != value:
        raise SystemExit(
            "{} is not a canonical CSV integer: {!r}".format(context, value)
        )
    return parsed


def validate_csv_evidence(
    path: Path,
    expected_queries: int,
    result_summary: Mapping[str, Any],
    context: str,
) -> Dict[str, Any]:
    required_fields = {
        "sequence",
        "expected_authorized",
        "expected_index",
        "expected_code",
        "actual_authorized",
        "actual_index",
        "actual_code",
        "discrepancy",
        "error",
        "probe_ciphertext_sha256",
        "pbs",
    }
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or ())
        missing = sorted(required_fields - fields)
        if missing:
            raise SystemExit("{} CSV lacks fields: {!r}".format(context, missing))
        rows = list(reader)
    if len(rows) != expected_queries:
        raise SystemExit(
            "{} CSV row count drifted: expected {}, got {}".format(
                context, expected_queries, len(rows)
            )
        )

    expected_authorized_count = 0
    actual_authorized_count = 0
    probe_hashes = []
    for sequence, row in enumerate(rows):
        row_context = "{} CSV row {}".format(context, sequence)
        if _csv_int(row.get("sequence"), row_context + " sequence") != sequence:
            raise SystemExit("{} has a non-contiguous sequence".format(row_context))
        if row.get("error") != "":
            raise SystemExit("{} records an operational error".format(row_context))
        if _csv_bool(row.get("discrepancy"), row_context + " discrepancy"):
            raise SystemExit("{} records a semantic discrepancy".format(row_context))

        expected_authorized = _csv_bool(
            row.get("expected_authorized"), row_context + " expected_authorized"
        )
        actual_authorized = _csv_bool(
            row.get("actual_authorized"), row_context + " actual_authorized"
        )
        expected_index = _csv_int(
            row.get("expected_index"), row_context + " expected_index", optional=True
        )
        actual_index = _csv_int(
            row.get("actual_index"), row_context + " actual_index", optional=True
        )
        expected_code = _csv_int(
            row.get("expected_code"), row_context + " expected_code"
        )
        actual_code = _csv_int(row.get("actual_code"), row_context + " actual_code")
        if (
            actual_authorized != expected_authorized
            or actual_index != expected_index
            or actual_code != expected_code
        ):
            raise SystemExit(
                "{} expected/actual result columns disagree".format(row_context)
            )
        if expected_authorized:
            if (
                expected_index is None
                or not 0 <= expected_index < GALLERY_SIZE
                or expected_code != expected_index + 1
            ):
                raise SystemExit(
                    "{} has an invalid accepted exact-ID code".format(row_context)
                )
        elif expected_index is not None or expected_code != 0:
            raise SystemExit(
                "{} has an invalid rejected exact-ID code".format(row_context)
            )
        if _csv_int(row.get("pbs"), row_context + " pbs") != 4273:
            raise SystemExit("{} has a non-A33 PBS count".format(row_context))

        probe_hash = row.get("probe_ciphertext_sha256")
        if (
            not isinstance(probe_hash, str)
            or len(probe_hash) != 64
            or any(character not in "0123456789abcdef" for character in probe_hash)
        ):
            raise SystemExit("{} has an invalid probe SHA-256".format(row_context))
        probe_hashes.append(probe_hash)
        expected_authorized_count += int(expected_authorized)
        actual_authorized_count += int(actual_authorized)

    csv_summary = {
        "rows_recorded": len(rows),
        "expected_authorized": expected_authorized_count,
        "actual_authorized": actual_authorized_count,
        "probe_ciphertexts_measured": len(probe_hashes),
        "probe_ciphertexts_unique": len(set(probe_hashes)),
    }
    expected_summary = {key: result_summary.get(key) for key in csv_summary}
    if csv_summary != expected_summary:
        raise SystemExit(
            "{} CSV/JSON summaries disagree: csv={!r}, json={!r}".format(
                context, csv_summary, expected_summary
            )
        )
    return csv_summary


def validate_a33_provenance(
    evidence: Mapping[str, Any], context: str
) -> Dict[str, Any]:
    provenance = evidence.get("provenance")
    if not isinstance(provenance, Mapping):
        raise SystemExit("{} lacks provenance".format(context))
    before = provenance.get("inputs_before")
    after = provenance.get("inputs_after")
    unchanged = provenance.get("inputs_unchanged_during_run")
    if not all(isinstance(value, Mapping) for value in (before, after, unchanged)):
        raise SystemExit(
            "{} lacks before/after/unchanged input provenance".format(context)
        )
    expected_hashes = {
        "exact_argmin_core": EXPECTED_STATIC_HASHES["core"],
        "rust_binary": EXPECTED_A33_BINARY_SHA256,
    }
    for name, expected_hash in expected_hashes.items():
        before_record = before.get(name)
        after_record = after.get(name)
        if not isinstance(before_record, Mapping) or not isinstance(
            after_record, Mapping
        ):
            raise SystemExit("{} lacks {} input records".format(context, name))
        before_hash = before_record.get("sha256")
        after_hash = after_record.get("sha256")
        if before_hash != expected_hash or after_hash != expected_hash:
            raise SystemExit(
                "{} does not bind frozen {} before and after the run".format(
                    context, name
                )
            )
        if unchanged.get(name) is not True:
            raise SystemExit(
                "{} reports {} changed during the run".format(context, name)
            )
    server_process = provenance.get("server_process")
    if (
        not isinstance(server_process, Mapping)
        or server_process.get("binary_sha256_at_launch") != EXPECTED_A33_BINARY_SHA256
        or server_process.get("exact_path_verified") is not True
    ):
        raise SystemExit("{} does not bind the launched A33 binary".format(context))
    return {
        "inputs_before_after_match": True,
        "inputs_unchanged_during_run": True,
        "server_binary_at_launch": EXPECTED_A33_BINARY_SHA256,
    }


def validate_frontier_evidence(path: Path, csv_path: Path) -> Dict[str, Any]:
    evidence = json.loads(path.read_text(encoding="utf-8"))
    summary = validate_run_results(evidence, 80, "clean A33 frontier evidence")
    state = validate_a33_state(evidence, "clean A33 frontier evidence")
    provenance = validate_a33_provenance(evidence, "clean A33 frontier evidence")
    csv_summary = validate_csv_evidence(
        csv_path, 80, summary, "clean A33 frontier evidence"
    )
    return {
        "results": summary,
        "server_state": state,
        "provenance": provenance,
        "csv": csv_summary,
    }


def validate_diagnostic_transcript(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    required = (
        "RESULT,case=n1_accept_1023,n=1,code=1,pbs=31",
        "RESULT,case=n1_reject_1024,n=1,code=0,pbs=31",
        "RESULT,case=n3_odd_tail_last_identity,n=3,code=3,pbs=100",
        "RESULT,case=n3_tie_first_replay,n=3,code=1,pbs=100,replay_verified=true",
        "RESULT,case=n3_all_reject_no_resurrection,n=3,code=0,pbs=100",
        "RESULT,case=n127_boundary_tail_identity,n=127,code=127,pbs=4273",
        "SUMMARY,cases=6,evaluations=7,small_only=false,ephemeral_key=true,"
        "secret_material_persisted=false",
    )
    missing = [fragment for fragment in required if fragment not in text]
    key_lines = [line for line in lines if line.startswith("KEY,")]
    ephemeral_key_bound = (
        len(key_lines) == 1
        and "ephemeral=true,secret_material_persisted=false" in key_lines[0]
    )
    if missing or "correct=false" in text or not ephemeral_key_bound:
        raise SystemExit(
            "A33 diagnostic transcript invariants failed; missing={!r}, "
            "ephemeral_key_bound={!r}".format(missing, ephemeral_key_bound)
        )
    return {
        "cases": 6,
        "evaluations": 7,
        "n127_pbs": 4273,
        "exact_tail_identity_code": 127,
        "replay_verified": True,
        "all_correct": True,
        "ephemeral_key": True,
    }


def find_tfhe_source(explicit: Optional[Path]) -> Path:
    if explicit is not None:
        candidates = [explicit]
    else:
        cargo_base = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
        candidates = sorted((cargo_base / "registry" / "src").glob("*/tfhe-0.11.3"))
    valid = [candidate.resolve() for candidate in candidates if candidate.is_dir()]
    if len(valid) != 1:
        raise SystemExit(
            "expected exactly one tfhe-0.11.3 source tree; pass --tfhe-source-root explicitly"
        )
    return valid[0]


def collect_static_evidence(repo_root: Path, tfhe_root: Path) -> Dict[str, Any]:
    patch_path = repo_root / PATCH_RELATIVE_PATH
    frontier_json_path = repo_root / FRONTIER_JSON_RELATIVE_PATH
    frontier_csv_path = repo_root / FRONTIER_CSV_RELATIVE_PATH
    diagnostic_path = repo_root / DIAGNOSTIC_RELATIVE_PATH
    parameter_path = (
        tfhe_root
        / "src/shortint/parameters/classic/tuniform/p_fail_2_minus_64/ks_pbs.rs"
    )
    tfhe_readme_path = tfhe_root / "README.md"

    hashes = {
        "patch": checked_sha256(
            patch_path, EXPECTED_STATIC_HASHES["patch"], "frozen A33 patch"
        ),
        "frontier_json": checked_sha256(
            frontier_json_path,
            EXPECTED_STATIC_HASHES["frontier_json"],
            "clean A33 frontier JSON",
        ),
        "frontier_csv": checked_sha256(
            frontier_csv_path,
            EXPECTED_STATIC_HASHES["frontier_csv"],
            "clean A33 frontier CSV",
        ),
        "diagnostic": checked_sha256(
            diagnostic_path,
            EXPECTED_STATIC_HASHES["diagnostic"],
            "A33 diagnostic transcript",
        ),
        "parameter_source": checked_sha256(
            parameter_path,
            EXPECTED_STATIC_HASHES["parameter_source"],
            "TFHE-rs parameter source",
        ),
        "tfhe_readme": checked_sha256(
            tfhe_readme_path,
            EXPECTED_STATIC_HASHES["tfhe_readme"],
            "TFHE-rs README",
        ),
    }
    frozen_core = extract_new_file_from_patch(patch_path, FROZEN_CORE_MEMBER)
    hashes["core"] = sha256_bytes(frozen_core)
    if hashes["core"] != EXPECTED_STATIC_HASHES["core"]:
        raise SystemExit(
            "A33 core extracted from frozen patch drifted: expected {}, got {}".format(
                EXPECTED_STATIC_HASHES["core"], hashes["core"]
            )
        )
    parameter_text = parameter_path.read_text(encoding="utf-8")
    if "// security = 132 bits, p-fail = 2^-71.625" not in parameter_text:
        raise SystemExit(
            "TFHE-rs parameter source no longer states the pinned security/p-fail"
        )
    if "log2_p_fail: -71.625" not in parameter_text:
        raise SystemExit(
            "TFHE-rs parameter source no longer contains log2_p_fail=-71.625"
        )
    return {
        "hashes": hashes,
        "core_contract": validate_core_contract(frozen_core),
        "frontier": validate_frontier_evidence(frontier_json_path, frontier_csv_path),
        "diagnostic": validate_diagnostic_transcript(diagnostic_path),
    }


def primary_freeze() -> Tuple[str, str, str]:
    values = (
        FROZEN_PRIMARY_JSON_RELATIVE_PATH,
        EXPECTED_PRIMARY_JSON_SHA256,
        EXPECTED_PRIMARY_CSV_SHA256,
    )
    if all(value is None for value in values):
        raise SystemExit(
            "primary evidence not frozen: set the canonical A33 primary path and JSON/CSV hashes"
        )
    if any(value is None for value in values):
        raise SystemExit(
            "primary evidence not frozen: path and JSON/CSV hashes must be frozen together"
        )
    relative_path, json_hash, csv_hash = values
    if (
        not isinstance(relative_path, str)
        or not relative_path
        or Path(relative_path).is_absolute()
        or ".." in Path(relative_path).parts
        or Path(relative_path).suffix != ".json"
    ):
        raise SystemExit(
            "primary evidence path must be a relative JSON path inside the repo"
        )
    for label, value in (("JSON", json_hash), ("CSV", csv_hash)):
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise SystemExit("primary {} SHA-256 is not canonical".format(label))
    return relative_path, json_hash, csv_hash


def primary_is_frozen() -> bool:
    try:
        primary_freeze()
    except SystemExit:
        return False
    return True


def load_primary_evidence(path: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    evidence = json.loads(path.read_text(encoding="utf-8"))
    summary = validate_run_results(
        evidence, EXPECTED_PRIMARY_QUERIES, "A33 primary evidence"
    )
    state = validate_a33_state(evidence, "A33 primary evidence")
    provenance = validate_a33_provenance(evidence, "A33 primary evidence")
    csv_summary = validate_csv_evidence(
        path.with_suffix(".csv"),
        EXPECTED_PRIMARY_QUERIES,
        summary,
        "A33 primary evidence",
    )
    return evidence, {
        "results": summary,
        "server_state": state,
        "provenance": provenance,
        "csv": csv_summary,
    }


def conditional_accounting(record: Mapping[str, Any]) -> Dict[str, Any]:
    blind_rotations = int(record["blind_rotations"])
    marginals = int(record["output_marginals_conservative"])
    return {
        "nominal_log2_p_fail": LOG2_P_FAIL,
        "blind_rotation_event_accounting": conditional_union(
            blind_rotations, LOG2_P_FAIL
        ),
        "output_marginal_accounting": conditional_union(marginals, LOG2_P_FAIL),
        "final_unbootstrapped_decode_failure": {
            "status": "unvalued",
            "probability_upper": None,
            "reason": (
                "The final code is a linear sum at Delta=2^56 with no trailing PBS. The pinned "
                "TFHE-rs per-PBS value does not by itself bound its decryption error."
            ),
        },
        "end_to_end_numeric_upper": None,
        "status": "conditional_arithmetic_incomplete_until_final_decode_is_bounded",
    }


def build_payload(
    script_path: Path,
    static: Mapping[str, Any],
    primary_summary: Mapping[str, Any],
    primary_hashes: Mapping[str, str],
) -> Dict[str, Any]:
    sweep = operation_sweep()
    n127 = sweep[GALLERY_SIZE - 1]
    hashes = dict(static["hashes"])
    hashes.update(primary_hashes)
    return {
        "schema_version": 1,
        "status": "conditional_accounting_not_end_to_end_certificate",
        "evidence_snapshot": {
            "configuration": "a33_n127_uniform_aligned_sparse",
            "gallery_size": GALLERY_SIZE,
            "clean_frontier": static["frontier"],
            "diagnostic_full_fhe": static["diagnostic"],
            "primary_suite": primary_summary,
        },
        "parameter": {
            "name": "V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64",
            "tfhe_rs": "0.11.3",
            "security_bits_reported": SECURITY_BITS_REPORTED,
            "log2_p_fail": LOG2_P_FAIL,
            "value_source": "frozen_tfhe_rs_parameter_source_not_overridden",
        },
        "operation_accounting": {
            "derivation": {
                "method": (
                    "independent reconstruction from the frozen A33 control flow, checked "
                    "against the complete extracted core and five exact fixtures"
                ),
                "stage_formulas": STAGE_FORMULAS,
                "multi_output_rotation_classes_per_template": {
                    **MULTI_OUTPUT_ROTATION_CLASSES_PER_TEMPLATE,
                    "total": MULTI_OUTPUT_ROTATIONS_PER_TEMPLATE,
                },
                "multi_output_dependency": (
                    "Each two-output pair shares one blind rotation and is one BR event, not two "
                    "independent trials. The conservative marginal count adds one extra output "
                    "per such rotation without asserting independence."
                ),
                "canonicalizer_output_marginal_effect": (
                    "Zero. Global bit 7 is canonicalized by reusing the existing correction "
                    "ciphertext; the assignment performs no blind rotation or additional sample "
                    "extraction, so it adds neither a BR event nor an output marginal."
                ),
                "fixtures": {
                    str(size): {
                        "blind_rotations": values[0],
                        "key_switches_structural": values[1],
                    }
                    for size, values in EXPECTED_FIXTURES.items()
                },
                "frozen_core_contract": static["core_contract"],
            },
            "gallery_sizes_1_to_128": sweep,
            "a33_n127_uniform_aligned_sparse": n127,
        },
        "conditional_arithmetic": conditional_accounting(n127),
        "empirical_primary_suite": {
            **dict(primary_summary["results"]),
            "observed_wrong_outputs": primary_summary["results"][
                "semantic_discrepancies"
            ],
            "confidence": 1.0 - CONFIDENCE_ALPHA,
            "iid_binomial_one_sided_upper": zero_failure_upper(
                EXPECTED_PRIMARY_QUERIES, CONFIDENCE_ALPHA
            ),
            "warning": (
                "The confidence limit assumes iid Bernoulli queries; one empirical campaign "
                "cannot resolve probabilities near the nominal cryptographic tail."
            ),
        },
        "conditional_model": {
            "assumption_A": [
                "honest bounded client plaintext",
                "valid clear templates and public domain",
                "honestly generated and correctly matched secret/evaluation keys",
                "honest evaluator/server execution",
                "correct software, hardware, serialization and transport",
            ],
            "claimed_form_only": (
                "P(wrong output | A) <= sum_i P(F_i | A, correct prefix) + "
                "P(final decode failure | A, all BR/PBS events correct)"
            ),
            "outside_A": (
                "No probability guarantee is claimed. P(A^c) requires a separately justified "
                "model for assumption violations."
            ),
        },
        "interpretation": {
            "key_switches_not_added_as_independent_events": (
                "In the intended shortint KS-to-PBS path, key-switch noise enters the following "
                "PBS input. Structural KS counts are reported, but adding them again as nominal "
                "failure trials is not justified."
            ),
            "independence_required_for_union_bound": False,
            "score_lane_noise": (
                "Initial encryption noise and the GLWE/plaintext score product require no "
                "separate discrete event only if covered by the reachable-input argument for "
                "the first downstream PBS; that formal proof remains open."
            ),
            "marginal_scope": (
                "The N=127 conservative count is BR+5N=4908 output marginals. It does not count "
                "linear score-lane sample extractions as nominal PBS events."
            ),
            "missing_obligations": [
                "Prove a conditional marginal bound for every reachable custom PBS input.",
                "Cover initial and score-lane noise in the first reachable PBS-input proof.",
                "Justify the nominal bound for both correlated outputs of multi-output rotations.",
                "Bound the final unbootstrapped Delta=2^56 code-sum decode error.",
                "Keep assumption violations and implementation faults outside the noise union.",
            ],
        },
        "provenance": {
            "generator": "benchmark/a33_pfail_accounting.py",
            "generator_sha256": sha256_file(script_path),
            "python_compatibility_tested": ["3.9", "3.12"],
            "canonical_command": [
                "uv",
                "run",
                "--python",
                "3.12",
                "python",
                "benchmark/a33_pfail_accounting.py",
                "--output",
                CANONICAL_OUTPUT_RELATIVE_PATH,
            ],
            "inputs": {
                PATCH_RELATIVE_PATH + "::" + FROZEN_CORE_MEMBER: hashes["core"],
                PATCH_RELATIVE_PATH: hashes["patch"],
                FRONTIER_JSON_RELATIVE_PATH: hashes["frontier_json"],
                FRONTIER_CSV_RELATIVE_PATH: hashes["frontier_csv"],
                DIAGNOSTIC_RELATIVE_PATH: hashes["diagnostic"],
                str(FROZEN_PRIMARY_JSON_RELATIVE_PATH): hashes["primary_json"],
                str(
                    Path(str(FROZEN_PRIMARY_JSON_RELATIVE_PATH)).with_suffix(".csv")
                ): hashes["primary_csv"],
                "tfhe-0.11.3/src/shortint/parameters/classic/tuniform/"
                "p_fail_2_minus_64/ks_pbs.rs": hashes["parameter_source"],
                "tfhe-0.11.3/README.md": hashes["tfhe_readme"],
            },
            "byte_reproducibility": (
                "No generation timestamp, host state, or runtime version is embedded. Sorted "
                "JSON over pinned inputs produces identical bytes on tested Python 3.9/3.12."
            ),
        },
    }


def render_payload(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tfhe-source-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--check-static",
        action="store_true",
        help="validate frozen non-primary inputs and operation counts without generating output",
    )
    return parser.parse_args()


def main() -> int:
    script_path = Path(__file__).resolve()
    repo_root = script_path.parents[1]
    args = parse_args()
    tfhe_root = find_tfhe_source(args.tfhe_source_root)

    if args.check_static:
        static = collect_static_evidence(repo_root, tfhe_root)
        sweep = operation_sweep()
        primary_frozen = primary_is_frozen()
        summary = {
            "status": "static_inputs_and_a33_counts_valid_primary_{}".format(
                "frozen" if primary_frozen else "pending"
            ),
            "hashes": static["hashes"],
            "fixtures": {str(size): sweep[size - 1] for size in EXPECTED_FIXTURES},
            "primary_frozen": primary_frozen,
            "output_written": False,
        }
        print(render_payload(summary), end="")
        return 0

    primary_relative, primary_json_hash, primary_csv_hash = primary_freeze()
    static = collect_static_evidence(repo_root, tfhe_root)
    primary_json_path = repo_root / primary_relative
    primary_csv_path = primary_json_path.with_suffix(".csv")
    artifact_primary_hashes = {
        "primary_json": checked_sha256(
            primary_json_path, primary_json_hash, "A33 primary JSON"
        ),
        "primary_csv": checked_sha256(
            primary_csv_path, primary_csv_hash, "A33 primary CSV"
        ),
    }
    _primary, primary_summary = load_primary_evidence(primary_json_path)
    payload = build_payload(
        script_path, static, primary_summary, artifact_primary_hashes
    )
    rendered = render_payload(payload)
    if args.output is None:
        print(rendered, end="")
        return 0

    output = args.output.resolve()
    if output.exists():
        raise SystemExit(
            "refusing to overwrite existing accounting artifact: {}".format(output)
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    if temporary.exists():
        raise SystemExit(
            "refusing to replace pre-existing temporary path: {}".format(temporary)
        )
    temporary.write_text(rendered, encoding="utf-8")
    temporary.replace(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
