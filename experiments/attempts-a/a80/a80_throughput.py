#!/usr/bin/env python3
"""Source-pinned diagnostic of A62/A66 stage throughput from the clean A73 smoke."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RESULTS = ROOT / "experiments/14_pipeline_tfhe_rs/results"
A73 = RESULTS / "exact_id_a73_a62_a66_clean_smoke_analysis_2026-09-02.json"
A77 = RESULTS / "exact_id_a77_pbs_buffer_reuse_combined_2026-09-02.json"
A30 = ROOT / "tmp/a30-pfks-bridge-microbenchmark-design/model.py"
PINS = {
    A73: "16bc5fa6df41e2dcfe33d1f91d58926b097caf99d38b7168b717990cc1801797",
    A77: "7754021cb2cf7f23258f2cb67a4dea5a49bfeca47111c2264960bdf9b8496627",
    A30: "29c6945f12268364f308535184d137611d03d2448285fdde81bc7f0ea490ceca",
}
COUNTED_STAGES = ("extract", "select", "scan")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_pin(path: Path) -> None:
    actual = sha256_file(path)
    if actual != PINS[path]:
        raise RuntimeError(f"input drift: {path}: {actual} != {PINS[path]}")


def load_pinned_json(path: Path) -> dict[str, Any]:
    verify_pin(path)
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise RuntimeError(f"input is not an object: {path}")
    return payload


def load_a30_model() -> ModuleType:
    verify_pin(A30)
    spec = importlib.util.spec_from_file_location("_a80_pinned_a30", A30)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pinned A30 model")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def equivalent_parallelism(pbs_count: int, scalar_seconds: float, wall_seconds: float) -> float:
    """Scalar-PBS work divided by wall time; this is not a physical core count."""

    if pbs_count <= 0 or scalar_seconds <= 0 or wall_seconds <= 0:
        raise ValueError("throughput inputs must be positive")
    return pbs_count * scalar_seconds / wall_seconds


def make_diagnostic() -> dict[str, Any]:
    a73 = load_pinned_json(A73)
    a77 = load_pinned_json(A77)
    a30 = load_a30_model()
    if a73.get("status") != "PASS_PAIRED_ANALYSIS":
        raise RuntimeError("A73 input is not a passing paired analysis")
    stratum = a73["thread_strata"].get("16")
    if not isinstance(stratum, dict):
        raise RuntimeError("A73 clean smoke has no 16-thread stratum")
    if stratum["overall"]["pairs"] != 2 or stratum["bootstrap"]["inferentially_valid"]:
        raise RuntimeError("A80 expects the two-pair, one-key provisional smoke")
    scalar_seconds = a77["pbs"]["combined"]["wrapper_median_ns"] / 1_000_000_000
    rows: dict[str, dict[str, Any]] = {}
    for stage in COUNTED_STAGES:
        source = stratum["by_stage"][stage]
        a62_pbs = source["a62_pbs_values"]
        a66_pbs = source["a66_pbs_values"]
        if len(a62_pbs) != 1 or a62_pbs != a66_pbs:
            raise RuntimeError(f"unexpected count support for {stage}")
        count = int(a62_pbs[0])
        a62_seconds = float(source["a62_seconds_median"])
        a66_seconds = float(source["a66_seconds_median"])
        rows[stage] = {
            "pbs": count,
            "a62_wall_seconds": a62_seconds,
            "a66_wall_seconds": a66_seconds,
            "a62_pbs_per_second": count / a62_seconds,
            "a66_pbs_per_second": count / a66_seconds,
            "a62_scalar_equivalent_parallelism": equivalent_parallelism(
                count, scalar_seconds, a62_seconds
            ),
            "a66_scalar_equivalent_parallelism": equivalent_parallelism(
                count, scalar_seconds, a66_seconds
            ),
            "a66_stage_reduction_percent": 100 * (1 - a66_seconds / a62_seconds),
        }

    a66_parallelism = [
        rows[stage]["a66_scalar_equivalent_parallelism"] for stage in COUNTED_STAGES
    ]
    center = sum(a66_parallelism) / len(a66_parallelism)
    relative_spread = (max(a66_parallelism) - min(a66_parallelism)) / center
    total_pbs = 3390
    a62_total = float(stratum["overall"]["a62_wall_s_median"])
    a66_total = float(stratum["overall"]["a66_wall_s_median"])
    best_stage_parallelism = max(a66_parallelism)
    best_stage_ceiling_seconds = total_pbs * scalar_seconds / best_stage_parallelism
    a30_d2 = a30.primitive_ledger(127, pfks_variant="D2")
    a30_d1 = a30.primitive_ledger(127, pfks_variant="D1")
    if a30_d2.total_pbs != a30_d1.total_pbs:
        raise RuntimeError("A30 D1/D2 PBS ledgers diverged")
    a30_removed_pbs = total_pbs - a30_d2.total_pbs
    a30_d2_pfks = a30_d2.pfks_calls
    a30_d1_pfks = a30_d1.pfks_calls
    observed_a66_seconds_per_pbs = a66_total / total_pbs
    removed_pbs_budget_seconds = a30_removed_pbs * observed_a66_seconds_per_pbs

    return {
        "artifact": "A80 provisional runtime-throughput ceiling diagnostic",
        "status": "PASS_DIAGNOSTIC_NOT_INFERENTIAL",
        "input_pins": {str(path.relative_to(ROOT)): PINS[path] for path in PINS},
        "evidence_scope": {
            "a73_measured_pairs": 2,
            "a73_independent_key_blocks": 1,
            "threads": 16,
            "host_physical_cores": 16,
            "performance_cores": 12,
            "scalar_reference_pairs": a77["pbs"]["pairs"],
            "scalar_reference_runs": a77["run_count"],
            "inferential_claim_allowed": False,
        },
        "scalar_reference_pbs_seconds": scalar_seconds,
        "stages": rows,
        "a66_stage_equivalent_parallelism_mean": center,
        "a66_stage_equivalent_parallelism_relative_range": relative_spread,
        "whole_query": {
            "pbs": total_pbs,
            "a62_wall_seconds": a62_total,
            "a66_wall_seconds": a66_total,
            "a62_scalar_equivalent_parallelism": equivalent_parallelism(
                total_pbs, scalar_seconds, a62_total
            ),
            "a66_scalar_equivalent_parallelism": equivalent_parallelism(
                total_pbs, scalar_seconds, a66_total
            ),
            "time_at_best_observed_a66_stage_rate_seconds": best_stage_ceiling_seconds,
            "a66_gap_above_best_stage_rate_percent": 100
            * (a66_total / best_stage_ceiling_seconds - 1),
        },
        "a30_runtime_gate_from_current_rate": {
            "removed_pbs": a30_removed_pbs,
            "wall_time_budget_before_pfks_seconds": removed_pbs_budget_seconds,
            "d2_pfks_calls": a30_d2_pfks,
            "d2_break_even_mean_wall_seconds_per_pfks": removed_pbs_budget_seconds
            / a30_d2_pfks,
            "d1_pfks_calls_conditional": a30_d1_pfks,
            "d1_break_even_mean_wall_seconds_per_pfks_conditional": removed_pbs_budget_seconds
            / a30_d1_pfks,
            "warning": "projection assumes removed PBS retain current average throughput and ignores integration effects",
        },
        "interpretation": {
            "a62_scan_has_scheduler_gap": rows["scan"]["a62_scalar_equivalent_parallelism"]
            < 2,
            "a66_scan_reaches_other_stage_band": min(a66_parallelism)
            >= 0.85 * max(a66_parallelism),
            "candidate_bottleneck_class": "primitive_count_or_shared_hardware_throughput",
            "not_established": [
                "memory bandwidth is the causal ceiling",
                "six physical cores are used",
                "A66 has a statistically established speedup",
                "the A30 projection includes measured PFKS cost",
            ],
        },
        "next_discriminating_measurements": [
            "replace the smoke with A73 initial and preregistered extension evidence",
            "run a small 1/2/4/6/8/12/16 thread sweep only after the primary paired benchmark",
            "measure hardware bandwidth/cache counters if a supported local profiler is available",
            "prioritize fewer PBS, common-mask batching, and smaller evaluation-key traffic over more scan scheduling",
        ],
    }


def main() -> None:
    print(json.dumps(make_diagnostic(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
