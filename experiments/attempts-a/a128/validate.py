#!/usr/bin/env python3
"""Validate preserved A124 logs without trusting PASS flags or running FHE.

Reconstruct the frozen scene/schedule, validate every query and key-block record,
and keep schedule completeness separate from saved pre/post CPU-guard evidence.
Even a complete result does not prove absence of within-cell contention.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import statistics
import sys
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
A124 = ROOT / "tmp/a124-a66-thread-sweep"
COUNTS = {64: (1713, 1521, 1985), 127: (3390, 3009, 3930), 128: (3415, 3031, 3959)}
STAGE_COUNTS = {64: (832, 815, 66), 127: (1651, 1603, 136), 128: (1664, 1615, 136)}
STAGES = ("setup", "score", "extract", "select", "scan", "threshold", "output")
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
# Nine-decimal serialized query timers; tolerate at most one microsecond in
# sums of independently rounded fields, not a percentage of the runtime.
TIMING_TOLERANCE_S = 1e-6


class EvidenceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exact_fields(record: dict[str, Any], expected: dict[str, Any], label: str) -> None:
    for field, value in expected.items():
        actual = record.get(field)
        require(
            type(actual) is type(value) and actual == value, f"{label} {field} mismatch"
        )


def finite(value: Any, label: str, maximum: float | None = None) -> float:
    require(type(value) in (int, float), f"non-numeric {label}")
    require(math.isfinite(value) and value >= 0, f"invalid {label}")
    if maximum is not None:
        require(value <= maximum, f"out-of-range {label}")
    return float(value)


def load_driver() -> tuple[Any, dict[str, str]]:
    pins = json.loads((HERE / "source-pins.json").read_text())
    for relative, expected in pins.items():
        require(sha256(ROOT / relative) == expected, f"source drift: {relative}")
    spec = importlib.util.spec_from_file_location(
        "_a128_frozen_driver", A124 / "a124_driver.py"
    )
    require(spec is not None and spec.loader is not None, "cannot load pinned driver")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.verify_frozen_inputs()
    return module, pins


def validate_cell(
    records: list[dict[str, Any]], driver: Any, pins: dict[str, str]
) -> dict[str, Any]:
    require(bool(records), "empty cell")
    require(records[0].get("record") == "meta", "meta must be first")
    require(records[-1].get("record") == "summary", "summary must be last")
    kinds = [r.get("record") for r in records]
    require(kinds.count("meta") == kinds.count("summary") == 1, "duplicate envelope")
    require(
        set(kinds) <= {"meta", "key_block", "query", "rss", "summary"},
        "unexpected record",
    )
    meta, summary = records[0], records[-1]
    size, threads = meta.get("gallery_size"), meta.get("threads")
    require((size, threads) in driver.cells_for("sweep"), "unregistered cell")
    scene, expected_scenes, _ = driver.scene_payload(size)
    schedule, expected_schedule, _ = driver.schedule_payload("sweep", size, threads)
    br, ks, marginals = COUNTS[size]
    expected_meta = {
        "variant": "a124_a66_thread_sweep",
        "circuit": "a66",
        "stage": "sweep",
        "dimension": 512,
        "threshold": 4,
        "binary_sha256": pins[str(driver.DEFAULT_BINARY.relative_to(ROOT))],
        "scene_sha256": hashlib.sha256(scene).hexdigest(),
        "schedule_sha256": hashlib.sha256(schedule).hexdigest(),
        "params_fingerprint_sha256": "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1",
        "expected_br": br,
        "expected_ks": ks,
        "expected_marginals": marginals,
        "execution_domain_lower": -1019,
        "execution_domain_upper": 2317 if size == 64 else 2329,
        "aligned_fast_path": True,
        "decrypt_policy": "after_all_timings_in_key_block",
    }
    exact_fields(meta, expected_meta, "meta")
    queries = [r for r in records if r["record"] == "query"]
    require(len(queries) == len(expected_schedule), "query count mismatch")
    hashes: set[str] = set()
    for query, expected in zip(queries, expected_schedule, strict=True):
        exact_fields(query, expected, "schedule")
        source = expected_scenes[expected["probe_slot"]]
        expected_query = {
            "gallery_size": size,
            "threads": threads,
            "probe_source_index": source.source_index,
            "expected_min_score": source.expected_min_score,
            "expected_argmin": source.expected_argmin,
            "expected_code": source.expected_code,
            "code": source.expected_code,
            "low": source.expected_code % 15,
            "high": source.expected_code // 15,
            "pbs": br,
            "expected_br": br,
            "expected_ks": ks,
            "expected_marginals": marginals,
            "result_bytes": 32848,
        }
        exact_fields(query, expected_query, "query")
        for field in ("semantics_pass", "counts_pass", "query_pass"):
            require(query.get(field) is True, f"query flag {field} failed")
        for field in ("input_ciphertext_sha256", "result_sha256"):
            require(bool(HEX256.fullmatch(query.get(field, ""))), f"invalid {field}")
        cipher_hash = query["input_ciphertext_sha256"]
        require(cipher_hash not in hashes, "duplicate input ciphertext digest")
        hashes.add(cipher_hash)
        for field in ("wall_s", "internal_total_s", *(f"{s}_s" for s in STAGES)):
            finite(query.get(field), field)
        require(query["wall_s"] > 0, "zero wall time")
        require(
            query["wall_s"] + TIMING_TOLERANCE_S >= query["internal_total_s"],
            "wall timer does not contain internal timer",
        )
        stage_total = sum(query[f"{stage}_s"] for stage in STAGES)
        require(
            query["internal_total_s"] + TIMING_TOLERANCE_S >= stage_total,
            "internal timer does not contain sequential stages",
        )
        counts = [query.get(f"{stage}_pbs") for stage in STAGES]
        require(all(type(c) is int and c >= 0 for c in counts), "invalid stage count")
        require(sum(counts) == br, "stage counts do not sum to ledger")
        stage_expected = dict.fromkeys((f"{s}_pbs" for s in STAGES), 0)
        stage_expected.update(
            zip(
                ("extract_pbs", "select_pbs", "scan_pbs"),
                STAGE_COUNTS[size],
                strict=True,
            )
        )
        exact_fields(query, stage_expected, "stage")

    blocks = [r for r in records if r["record"] == "key_block"]
    require([r.get("block") for r in blocks] == [0, 1], "key-block coverage mismatch")
    for block in blocks:
        require(
            block.get("gallery_size") == size and block.get("threads") == threads,
            "key-block cell mismatch",
        )
        require(block.get("queries_pre_encrypted") == 7, "pre-encrypted count mismatch")
        require(
            block.get("key_ephemeral") is True
            and block.get("secret_persisted") is False,
            "key policy mismatch",
        )
        finite(block.get("keygen_and_prepare_s"), "key preparation")
        position = records.index(block)
        first_query = next(
            i
            for i, r in enumerate(records)
            if r.get("record") == "query" and r.get("block") == block["block"]
        )
        require(position < first_query, "query precedes its key block")
    expected_summary = {
        "status": "PASS",
        "stage": "sweep",
        "gallery_size": size,
        "threads": threads,
        "measured_queries": 10,
        "excluded_warmup_queries": 4,
        "total_queries": 14,
        "passed_queries": 14,
        "failed_queries": 0,
        "key_blocks": 2,
        "keys_ephemeral": True,
        "secret_material_persisted": False,
        "promotion_allowed": False,
    }
    exact_fields(summary, expected_summary, "summary")
    return {
        "gallery_size": size,
        "threads": threads,
        "scene_sha256": meta["scene_sha256"],
        "schedule_sha256": meta["schedule_sha256"],
        "measured_queries": 10,
        "exact_query_records": 14,
        "query_wall_s_sum": sum(q["wall_s"] for q in queries),
        "key_preparation_s_sum": sum(block["keygen_and_prepare_s"] for block in blocks),
        "wall_s_median": statistics.median(
            q["wall_s"] for q in queries if q["included_in_analysis"]
        ),
    }


def validate_guard(cell: dict[str, Any], record: dict[str, Any]) -> str:
    for field in ("gallery_size", "threads", "scene_sha256", "schedule_sha256"):
        require(record.get(field) == cell[field], f"guard {field} mismatch")
    guard = record.get("idle_guard")
    require(isinstance(guard, dict), "missing idle guard")
    metric = guard.get("guard")
    require(metric in ("cpu", "load"), "unknown guard metric")
    limit = finite(
        guard.get("cpu_busy_max" if metric == "cpu" else "load_max"), "guard threshold"
    )
    require(limit <= (0.15 if metric == "cpu" else 4.0), "relaxed idle guard")
    require(guard.get("polls_required") == 2, "guard needs two polls")
    samples = guard.get("samples")
    require(isinstance(samples, list) and len(samples) >= 2, "missing guard samples")
    key = "cpu_busy" if metric == "cpu" else "load1"
    for sample in samples[-2:]:
        require(finite(sample.get(key), key) <= limit, "pre-cell guard failed")
    before = guard.get(
        "cpu_busy_before_cell" if metric == "cpu" else "load_before_cell"
    )
    require(before == samples[-1][key], "before-cell metric differs from last poll")
    finite(guard.get("waited_s"), "guard wait")
    child_wall = finite(record.get("child_wall_s"), "driver child wall")
    timed_work = cell["query_wall_s_sum"] + cell["key_preparation_s_sum"]
    require(
        child_wall > 0 and child_wall + 16 * TIMING_TOLERANCE_S >= timed_work,
        "driver timer does not contain query and key preparation timers",
    )
    if "cpu_busy_after_cell" not in record:
        return "MISSING_POST_CPU_SAMPLE"
    after = finite(record["cpu_busy_after_cell"], "post-cell CPU", 1.0)
    return (
        "PRE_POST_GUARD_VALIDATED" if after <= 0.15 else "POST_CELL_CPU_ABOVE_THRESHOLD"
    )


def validate_files(
    paths: list[Path], metadata_paths: list[Path], driver: Any, pins: dict[str, str]
) -> dict[str, Any]:
    metadata: dict[Path, dict[str, Any]] = {}
    for path in metadata_paths:
        document = json.loads(path.read_text())
        require(
            document.get("record") == "driver" and document.get("stage") == "sweep",
            "not sweep driver metadata",
        )
        require(
            document.get("binary_sha256")
            == pins[str(driver.DEFAULT_BINARY.relative_to(ROOT))],
            "driver binary mismatch",
        )
        require(
            document.get("input_manifest_sha256")
            == pins[str(driver.INPUT_MANIFEST.relative_to(ROOT))],
            "driver input manifest mismatch",
        )
        for cell in document.get("cells", []):
            output = Path(cell["output"])
            output = (
                output.resolve() if output.is_absolute() else (ROOT / output).resolve()
            )
            require(output not in metadata, "duplicate guard record")
            metadata[output] = cell
    results = []
    seen: set[tuple[int, int]] = set()
    for path in paths:
        records = [
            json.loads(line) for line in path.read_text().splitlines() if line.strip()
        ]
        cell = validate_cell(records, driver, pins)
        identity = (cell["gallery_size"], cell["threads"])
        require(
            identity not in seen,
            "duplicate cell: select an explicit run before analysis",
        )
        seen.add(identity)
        cell["guard_status"] = (
            validate_guard(cell, metadata[path.resolve()])
            if path.resolve() in metadata
            else "MISSING_DRIVER_METADATA"
        )
        cell.update(path=str(path.resolve()), sha256=sha256(path))
        results.append(cell)
    require(bool(results), "no cells")
    missing = sorted(set(driver.cells_for("sweep")) - seen)
    guarded = all(c["guard_status"] == "PRE_POST_GUARD_VALIDATED" for c in results)
    status = (
        "COMPLETE_PRE_POST_GUARDED_LOGS"
        if not missing and guarded
        else "INCOMPLETE_EVIDENCE"
    )
    return {
        "status": status,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "cells": results,
        "missing_cells": missing,
        "planned_cells": 21,
        "complete_schedule": not missing,
        "all_pre_post_guards_validated": guarded,
        "final_scaling_analysis_allowed": not missing and guarded,
        "within_cell_contention_excluded": False,
        "cryptographic_promotion_allowed": False,
        "scope": "Preserved log consistency, exact-oracle checks and saved pre/post guard evidence; no runtime attestation or new FHE",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--driver-metadata", nargs="*", type=Path, default=[])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    driver, pins = load_driver()
    result = validate_files(args.paths, args.driver_metadata, driver, pins)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as output:
        json.dump(result, output, indent=2, allow_nan=False)
        output.write("\n")
    print(json.dumps({k: v for k, v in result.items() if k != "cells"}, sort_keys=True))
    return 0 if result["final_scaling_analysis_allowed"] else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (EvidenceError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(
            json.dumps({"status": "INVALID_EVIDENCE", "error": str(error)}),
            file=sys.stderr,
        )
        sys.exit(1)
