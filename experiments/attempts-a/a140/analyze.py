"""Conditional stage sensitivity from validated saved timings; no new benchmark."""

from pathlib import Path
import hashlib
import json
import statistics

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
VALIDATION = (
    ROOT
    / "tmp/a128-a124-evidence-validation/artifacts/partial-validation-2026-09-05-r5.json"
)
STAGES = ("setup", "score", "extract", "select", "scan", "threshold", "output")
SCENARIOS = {
    "halve_scan_only": {"scan": 0.5},
    "reduce_extraction_25pct": {"extract": 0.25},
    "reduce_selection_25pct": {"select": 0.25},
    "reduce_extraction_and_selection_10pct": {"extract": 0.1, "select": 0.1},
    "remove_score_only": {"score": 1.0},
}


def collect():
    validation_bytes = VALIDATION.read_bytes()
    validation = json.loads(validation_bytes)
    assert validation["status"] == "INCOMPLETE_EVIDENCE"
    assert len(validation["cells"]) == 12
    output = []
    for cell in validation["cells"]:
        if cell["threads"] != 16:
            continue
        path = Path(cell["path"])
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == cell["sha256"]
        records = [json.loads(line) for line in raw.splitlines()]
        queries = [
            r for r in records if r["record"] == "query" and r["included_in_analysis"]
        ]
        assert len(queries) == 10 and all(q["query_pass"] for q in queries)
        assert all(
            sum(q[f"{s}_s"] for s in STAGES) <= q["wall_s"] + 1e-6 for q in queries
        )
        fractions = {
            stage: statistics.median(q[f"{stage}_s"] / q["wall_s"] for q in queries)
            for stage in STAGES
        }
        scenarios = {}
        for label, changes in SCENARIOS.items():
            # Recompute each query first; the median of separate stage medians
            # need not yield the median counterfactual wall time.
            saved = [
                sum(q[f"{s}_s"] * cut for s, cut in changes.items()) for q in queries
            ]
            remaining = [
                q["wall_s"] - reduction for q, reduction in zip(queries, saved)
            ]
            assert all(t > 0 for t in remaining)
            scenarios[label] = {
                "assumed_fractional_stage_reductions": changes,
                "median_query_latency_reduction_pct": statistics.median(
                    100 * reduction / q["wall_s"]
                    for q, reduction in zip(queries, saved)
                ),
                "median_counterfactual_seconds": statistics.median(remaining),
            }
        output.append(
            {
                "n": cell["gallery_size"],
                "threads": 16,
                "measured_queries": 10,
                "observed_wall_median_seconds": statistics.median(
                    q["wall_s"] for q in queries
                ),
                "median_per_query_stage_fraction": fractions,
                "scenario_models": scenarios,
                "source": str(path.relative_to(ROOT)),
                "source_sha256": cell["sha256"],
            }
        )
    assert sorted(c["n"] for c in output) == [64, 127, 128]
    return {
        "status": "DESCRIPTIVE_STAGE_SENSITIVITY_ONLY",
        "cells": sorted(output, key=lambda c: c["n"]),
        "validation": str(VALIDATION.relative_to(ROOT)),
        "validation_sha256": hashlib.sha256(validation_bytes).hexdigest(),
        "model_assumption": "Only specified stage duration changes; all other stages and wall overhead fixed for each saved query",
        "final_cpu_guard_metadata_available": False,
        "causal_or_predictive_speedup_claim": False,
        "pbs_count_to_runtime_conversion": False,
        "new_benchmark_run": False,
    }


if __name__ == "__main__":
    result = collect()
    (HERE / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    for cell in result["cells"]:
        print(
            json.dumps(
                {
                    "n": cell["n"],
                    "stage_pct": {
                        k: round(100 * v, 3)
                        for k, v in cell["median_per_query_stage_fraction"].items()
                    },
                    "modeled_latency_reduction_pct": {
                        k: round(v["median_query_latency_reduction_pct"], 3)
                        for k, v in cell["scenario_models"].items()
                    },
                }
            )
        )
