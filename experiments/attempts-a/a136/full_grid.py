#!/usr/bin/env python3
"""Materialized preregistered full grid; no execution without an explicit --run.

The currently live sweep is refused, never interrupted. Existing output
directories are never resumed or overwritten; retain any partial observations.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

import study

HERE = Path(__file__).resolve().parent


def arms():
    yield "baseline_g3_p3", 3, 3, None
    for gmax in (1, 3):
        for cap in (None, 480, 350, 250, 180):
            yield f"g{gmax}_p1_cap{cap}", gmax, 1, cap


def no_sweep() -> None:
    pins = json.loads((HERE / "FULL_GRID_PINS.json").read_text())
    for relative, expected in pins.items():
        if study.sha(study.ROOT / relative) != expected:
            raise ValueError(f"full-grid source drift: {relative}")
    path = study.ROOT / "tmp/a129-durable-sweep-driver/driver.py"
    spec = importlib.util.spec_from_file_location("_a136_sweep_preflight", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.require_no_other_sweep()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    cells = [
        (seed, n, frames) for seed in range(7) for n in (64, 128) for frames in (1, 3)
    ]
    if not args.run:
        print(
            json.dumps(
                {
                    "status": "PLAN_ONLY_FULL_GRID_NOT_EXECUTED",
                    "cells": cells,
                    "arms_per_cell": len(list(arms())),
                    "total_arm_cells": len(cells) * len(list(arms())),
                    "aggregate_independent_trials_claim": False,
                }
            )
        )
        return 0
    if args.output is None or args.output.resolve().parent != HERE:
        parser.error("output must name a new directory directly inside A136")
    no_sweep()
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())
    for relative, expected in pins.items():
        if study.sha(study.ROOT / relative) != expected:
            raise ValueError(f"study source drift: {relative}")
    output = args.output.resolve()
    output.mkdir()
    study.save(
        output / "plan.json",
        {
            "cells": cells,
            "arms": list(arms()),
            "pid": os.getpid(),
            "full_grid_sha256": study.sha(Path(__file__)),
            "study_pins": pins,
            "fhe_run": False,
            "thread_limit": 1,
            "automatic_retry": False,
        },
    )
    rows = []
    started = time.monotonic()
    with study.threadpool_limits(limits=1):
        if any(p["num_threads"] != 1 for p in study.threadpool_info()):
            raise ValueError("threadpool not limited")
        with study.np.load(study.CACHE, allow_pickle=False) as cache:
            labels = cache["y"]
            raw = cache["rn100"].astype(study.np.float32)
        if raw.shape != (len(labels), 512) or not study.np.isfinite(raw).all():
            raise ValueError("invalid embedding array")
        if not study.np.issubdtype(labels.dtype, study.np.integer) or study.np.any(
            study.np.linalg.norm(raw, axis=1) == 0
        ):
            raise ValueError("invalid labels or zero embedding")
        embeddings = study.normalize(raw)
        for seed in range(7):
            split = study.plan(labels, seed)
            study.save(output / f"split-{seed}.json", split)
            for n in (64, 128):
                for frames in (1, 3):
                    no_sweep()
                    cell = output / f"seed{seed}-n{n}-frames{frames}"
                    cell.mkdir()
                    fitted, values = study.floats(embeddings, split, n, frames)
                    baseline = None
                    for name, gmax, qmax, cap in arms():
                        row, correct = study.evaluate(
                            values,
                            fitted,
                            gmax,
                            qmax,
                            cap,
                            split,
                            n,
                            frames,
                            cell,
                            name,
                        )
                        if baseline is None:
                            baseline = correct
                        row["paired_genuine_improvements_vs_baseline"] = int(
                            study.np.count_nonzero(correct & ~baseline)
                        )
                        row["paired_genuine_regressions_vs_baseline"] = int(
                            study.np.count_nonzero(~correct & baseline)
                        )
                        rows.append(row)
                    study.save(
                        cell / "completed.json",
                        {
                            "completed_arm_cells": len(rows),
                            "rows": rows[-len(list(arms())) :],
                        },
                    )
        study.save(
            output / "result.json",
            {
                "status": "CLEAR_FULL_GRID_COMPLETE",
                "rows": rows,
                "full_grid_complete": True,
                "expected_arm_cells": 308,
                "elapsed_s_for_workload_accounting_only": time.monotonic() - started,
                "pooling_as_independent_trials_allowed": False,
                "fhe_or_latency_claim_allowed": False,
            },
        )
    print(
        json.dumps(
            {
                "status": "CLEAR_FULL_GRID_COMPLETE",
                "arm_cells": len(rows),
                "output": str(output),
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
