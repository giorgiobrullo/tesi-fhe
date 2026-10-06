#!/usr/bin/env python3
"""Combine independent A77 runs without discarding the paired sample structure."""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path
from typing import Any


OPERATIONS = {
    "pbs": ("pbs_convenience_wrapper", "pbs_mem_optimized_reuse"),
    "blind_rotate": (
        "blind_rotate_convenience_wrapper",
        "blind_rotate_mem_optimized_reuse",
    ),
}


def median_low(values: list[int]) -> int:
    return int(statistics.median_low(values))


def summarize_operation(runs: list[dict[str, Any]], operation: str) -> dict[str, Any]:
    wrapper_name, reuse_name = OPERATIONS[operation]
    all_wrapper: list[int] = []
    all_reuse: list[int] = []
    per_run = []
    wrapper_allocations: set[int] = set()
    reuse_allocations: set[int] = set()
    wrapper_reallocations: set[int] = set()
    reuse_reallocations: set[int] = set()
    wrapper_deallocations: set[int] = set()
    reuse_deallocations: set[int] = set()
    wrapper_bytes: set[int] = set()
    reuse_bytes: set[int] = set()

    for run_index, run in enumerate(runs, start=1):
        wrapper = run["samples"][wrapper_name]
        reuse = run["samples"][reuse_name]
        wrapper_ns = [int(value) for value in wrapper["nanoseconds"]]
        reuse_ns = [int(value) for value in reuse["nanoseconds"]]
        if len(wrapper_ns) != len(reuse_ns):
            raise ValueError(f"run {run_index} {operation}: unpaired samples")
        deltas = [left - right for left, right in zip(wrapper_ns, reuse_ns)]
        wrapper_median = median_low(wrapper_ns)
        reuse_median = median_low(reuse_ns)
        per_run.append(
            {
                "run": run_index,
                "source_file": run["_source_file"],
                "pairs": len(deltas),
                "wrapper_median_ns": wrapper_median,
                "reuse_median_ns": reuse_median,
                "independent_median_reduction_percent": 100
                * (wrapper_median - reuse_median)
                / wrapper_median,
                "paired_median_wrapper_minus_reuse_ns": median_low(deltas),
                "reuse_wins": sum(delta > 0 for delta in deltas),
            }
        )
        all_wrapper.extend(wrapper_ns)
        all_reuse.extend(reuse_ns)
        wrapper_allocations.update(int(value) for value in wrapper["alloc_calls"])
        reuse_allocations.update(int(value) for value in reuse["alloc_calls"])
        wrapper_reallocations.update(int(value) for value in wrapper["realloc_calls"])
        reuse_reallocations.update(int(value) for value in reuse["realloc_calls"])
        wrapper_deallocations.update(int(value) for value in wrapper["dealloc_calls"])
        reuse_deallocations.update(int(value) for value in reuse["dealloc_calls"])
        wrapper_bytes.update(int(value) for value in wrapper["allocated_bytes"])
        reuse_bytes.update(int(value) for value in reuse["allocated_bytes"])

    deltas = [left - right for left, right in zip(all_wrapper, all_reuse)]
    wrapper_median = median_low(all_wrapper)
    reuse_median = median_low(all_reuse)
    reductions = [entry["independent_median_reduction_percent"] for entry in per_run]
    return {
        "pairs": len(deltas),
        "per_run": per_run,
        "combined": {
            "wrapper_median_ns": wrapper_median,
            "reuse_median_ns": reuse_median,
            "independent_median_reduction_percent": 100
            * (wrapper_median - reuse_median)
            / wrapper_median,
            "paired_median_wrapper_minus_reuse_ns": median_low(deltas),
            "paired_median_reduction_percent_of_wrapper_median": 100
            * median_low(deltas)
            / wrapper_median,
            "paired_mean_wrapper_minus_reuse_ns": statistics.fmean(deltas),
            "reuse_wins": sum(delta > 0 for delta in deltas),
        },
        "allocation_observations": {
            "wrapper_alloc_calls_unique": sorted(wrapper_allocations),
            "reuse_alloc_calls_unique": sorted(reuse_allocations),
            "wrapper_realloc_calls_unique": sorted(wrapper_reallocations),
            "reuse_realloc_calls_unique": sorted(reuse_reallocations),
            "wrapper_dealloc_calls_unique": sorted(wrapper_deallocations),
            "reuse_dealloc_calls_unique": sorted(reuse_deallocations),
            "wrapper_allocated_bytes_unique": sorted(wrapper_bytes),
            "reuse_allocated_bytes_unique": sorted(reuse_bytes),
        },
        "timing_sign_consistent_across_runs": all(value > 0 for value in reductions)
        or all(value < 0 for value in reductions),
        "at_least_one_percent_gain_in_every_run": all(value >= 1 for value in reductions),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("runs", type=Path, nargs="+")
    args = parser.parse_args()
    runs = []
    for path in args.runs:
        run = json.loads(path.read_text(encoding="utf-8"))
        run["_source_file"] = path.name
        runs.append(run)
    for index, run in enumerate(runs, start=1):
        if run.get("status") != "PASS_SCALAR_CAUSAL_MICROBENCH":
            raise ValueError(f"run {index} did not pass")
        if not run.get("bit_exact_outputs_equal"):
            raise ValueError(f"run {index} lacks bit-exact equality")

    pbs = summarize_operation(runs, "pbs")
    blind_rotate = summarize_operation(runs, "blind_rotate")
    material_gain = all(
        operation["at_least_one_percent_gain_in_every_run"]
        for operation in (pbs, blind_rotate)
    )
    summary = {
        "artifact": "A77 combined scalar PBS buffer-reuse evidence",
        "status": (
            "PASS_CORRECTNESS_MATERIAL_SCALAR_LATENCY_GAIN"
            if material_gain
            else "PASS_CORRECTNESS_NO_MATERIAL_SCALAR_LATENCY_GAIN"
        ),
        "run_count": len(runs),
        "input_run_files": [run["_source_file"] for run in runs],
        "total_pairs_per_operation": sum(
            int(run["iterations_per_path"]) for run in runs
        ),
        "pbs": pbs,
        "blind_rotate": blind_rotate,
        "decision": {
            "remove_per_call_allocation_confirmed": True,
            "scalar_latency_integration_gate": (
                "GO_DESIGN_A66_ADAPTER" if material_gain else "NO_GO"
            ),
            "reason": (
                "both operations deliver at least 1 percent reuse gain in every run"
                if material_gain
                else "at least one operation fails to deliver a 1 percent reuse gain in every run"
            ),
            "next_bounded_test": "per-worker reusable buffers under controlled parallel primitive load, before A66 integration",
        },
        "claim_limit": "two scalar host runs; no exact-ID or parallel performance claim",
    }
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
