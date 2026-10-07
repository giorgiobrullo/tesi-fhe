#!/usr/bin/env python3
"""Analyze A124 thread-sweep JSONL records: medians, speedups, bootstrap CIs, figure.

Only ``record == "query"`` rows with ``included_in_analysis`` and ``query_pass`` enter the
analysis. Every cell is one (gallery size, thread count). Speedup is the ratio of the
single-thread median to the cell median for the same gallery size; the confidence interval
resamples key blocks first and then rows within blocks.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import random
import statistics
import sys
from typing import Any, Iterable


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
STAGES = ("setup", "score", "extract", "select", "scan", "threshold", "output")
# Scalar PBS median measured by A77 on this host (12.444375 ms, 480 clean pairs). Used only to
# express throughput as "concurrent scalar PBS equivalents"; it is not a core count.
A77_SCALAR_PBS_MS = 12.444375
PHYSICAL_PERFORMANCE_CORES = 12
PHYSICAL_EFFICIENCY_CORES = 4


class A124AnalysisError(RuntimeError):
    """The JSONL records do not form a consistent A124 sweep."""


def load_records(paths: Iterable[pathlib.Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    queries: list[dict[str, Any]] = []
    metas: list[dict[str, Any]] = []
    for path in paths:
        summary_seen = False
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            kind = record.get("record")
            if kind == "meta":
                record["_source"] = str(path)
                metas.append(record)
            elif kind == "query":
                record["_source"] = str(path)
                queries.append(record)
            elif kind == "query_error":
                raise A124AnalysisError(f"query_error present in {path}")
            elif kind == "summary":
                summary_seen = True
                if record.get("status") != "PASS":
                    raise A124AnalysisError(f"non-PASS summary in {path}")
        if not summary_seen:
            raise A124AnalysisError(f"missing summary in {path}")
    if not queries:
        raise A124AnalysisError("no query records")
    return queries, metas


def measured(queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = [row for row in queries if row.get("included_in_analysis")]
    for row in rows:
        if not row.get("query_pass"):
            raise A124AnalysisError("a measured query did not pass")
    return rows


def cell_key(row: dict[str, Any]) -> tuple[int, int]:
    return int(row["gallery_size"]), int(row["threads"])


def group_cells(rows: list[dict[str, Any]]) -> dict[tuple[int, int], list[dict[str, Any]]]:
    cells: dict[tuple[int, int], list[dict[str, Any]]] = {}
    for row in rows:
        cells.setdefault(cell_key(row), []).append(row)
    return cells


def median(values: Iterable[float]) -> float:
    return float(statistics.median(list(values)))


def _resample_cell(rows: list[dict[str, Any]], rng: random.Random) -> list[dict[str, Any]]:
    # A key block is identified by its source file too, so that two runs of the same cell
    # (for example a resumed sweep) never merge blocks that used different keys.
    by_block: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for row in rows:
        by_block.setdefault((str(row.get("_source", "")), int(row["block"])), []).append(row)
    blocks = list(by_block)
    sampled: list[dict[str, Any]] = []
    for _ in blocks:
        block = rng.choice(blocks)
        block_rows = by_block[block]
        sampled.extend(rng.choice(block_rows) for _ in block_rows)
    return sampled


def bootstrap_median_ci(
    rows: list[dict[str, Any]], field: str, replicates: int, seed: int
) -> tuple[float, float]:
    rng = random.Random(seed)
    medians = [
        median(float(row[field]) for row in _resample_cell(rows, rng)) for _ in range(replicates)
    ]
    medians.sort()
    low = medians[int(0.025 * (replicates - 1))]
    high = medians[int(0.975 * (replicates - 1))]
    return low, high


def bootstrap_speedup_ci(
    base_rows: list[dict[str, Any]],
    cell_rows: list[dict[str, Any]],
    replicates: int,
    seed: int,
) -> tuple[float, float]:
    rng = random.Random(seed)
    ratios: list[float] = []
    for _ in range(replicates):
        base = median(float(row["wall_s"]) for row in _resample_cell(base_rows, rng))
        cell = median(float(row["wall_s"]) for row in _resample_cell(cell_rows, rng))
        ratios.append(base / cell)
    ratios.sort()
    return ratios[int(0.025 * (replicates - 1))], ratios[int(0.975 * (replicates - 1))]


def analyze(
    queries: list[dict[str, Any]], replicates: int = 20_000, seed: int = 124_062_026
) -> dict[str, Any]:
    rows = measured(queries)
    cells = group_cells(rows)
    sizes = sorted({size for size, _ in cells})
    result: dict[str, Any] = {
        "status": "PASS_ANALYSIS",
        "variant": "a124_a66_thread_sweep",
        "replicates": replicates,
        "seed": seed,
        "a77_scalar_pbs_ms": A77_SCALAR_PBS_MS,
        "host_cores": {
            "performance": PHYSICAL_PERFORMANCE_CORES,
            "efficiency": PHYSICAL_EFFICIENCY_CORES,
        },
        "cells": [],
    }
    for index, (size, threads) in enumerate(sorted(cells)):
        cell_rows = cells[(size, threads)]
        walls = [float(row["wall_s"]) for row in cell_rows]
        pbs = {int(row["pbs"]) for row in cell_rows}
        if len(pbs) != 1:
            raise A124AnalysisError(f"PBS count not constant in cell {size}/{threads}")
        pbs_count = pbs.pop()
        wall_median = median(walls)
        low, high = bootstrap_median_ci(cell_rows, "wall_s", replicates, seed + index)
        entry: dict[str, Any] = {
            "gallery_size": size,
            "threads": threads,
            "measured_queries": len(cell_rows),
            "key_blocks": len({(str(row.get("_source", "")), int(row["block"])) for row in cell_rows}),
            "source_files": sorted({str(row.get("_source", "")) for row in cell_rows}),
            "pbs": pbs_count,
            "wall_s_median": wall_median,
            "wall_s_min": min(walls),
            "wall_s_max": max(walls),
            "wall_s_ci95": [low, high],
            "scalar_pbs_equivalents": pbs_count * A77_SCALAR_PBS_MS / 1000.0 / wall_median,
            "stages_s_median": {
                stage: median(float(row[f"{stage}_s"]) for row in cell_rows) for stage in STAGES
            },
            "stages_pbs": {stage: int(cell_rows[0][f"{stage}_pbs"]) for stage in STAGES},
        }
        base_rows = cells.get((size, 1))
        if base_rows is not None:
            base_median = median(float(row["wall_s"]) for row in base_rows)
            speedup = base_median / wall_median
            s_low, s_high = bootstrap_speedup_ci(base_rows, cell_rows, replicates, seed + 500 + index)
            entry["speedup_vs_1_thread"] = speedup
            entry["speedup_ci95"] = [s_low, s_high]
            entry["parallel_efficiency"] = speedup / threads
            entry["stage_speedups"] = {
                stage: (
                    median(float(row[f"{stage}_s"]) for row in base_rows)
                    / entry["stages_s_median"][stage]
                    if entry["stages_s_median"][stage] > 0
                    else None
                )
                for stage in STAGES
            }
        result["cells"].append(entry)
    result["gallery_sizes"] = sizes
    result["thread_levels"] = sorted({threads for _, threads in cells})
    result["cell_count"] = len(cells)
    result["measured_queries_total"] = len(rows)
    return result


def markdown_table(analysis: dict[str, Any]) -> str:
    lines = [
        "| N | thread | query | PBS | mediana wall | CI95 | speedup vs 1 | efficienza | PBS scalari equiv. |",
        "|---:|---:|---:|---:|---:|---|---:|---:|---:|",
    ]
    for cell in analysis["cells"]:
        speedup = cell.get("speedup_vs_1_thread")
        efficiency = cell.get("parallel_efficiency")
        ci = cell["wall_s_ci95"]
        lines.append(
            "| {n} | {t} | {q} | {pbs} | {w:.3f} s | [{lo:.3f}, {hi:.3f}] | {s} | {e} | {eq:.2f} |".format(
                n=cell["gallery_size"],
                t=cell["threads"],
                q=cell["measured_queries"],
                pbs=cell["pbs"],
                w=cell["wall_s_median"],
                lo=ci[0],
                hi=ci[1],
                s=f"{speedup:.2f}x" if speedup is not None else "-",
                e=f"{efficiency:.0%}" if efficiency is not None else "-",
                eq=cell["scalar_pbs_equivalents"],
            )
        )
    return "\n".join(lines)


def render_figure(analysis: dict[str, Any], png: pathlib.Path, svg: pathlib.Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    sizes = analysis["gallery_sizes"]
    levels = analysis["thread_levels"]
    by_cell = {(c["gallery_size"], c["threads"]): c for c in analysis["cells"]}
    colors = {64: "#1f77b4", 127: "#7f7f7f", 128: "#d62728"}
    fig, (ax_wall, ax_speed) = plt.subplots(1, 2, figsize=(13, 5.2), dpi=300)

    # N=127 and N=128 differ by <4%: draw 127 as a thin unlabeled line so labels stay legible.
    labeled = {size for size in sizes if not (size == 127 and 128 in sizes)}
    for size in sizes:
        xs = [t for t in levels if (size, t) in by_cell]
        ys = [by_cell[(size, t)]["wall_s_median"] for t in xs]
        thin = size not in labeled
        ax_wall.plot(xs, ys, marker="o" if not thin else None, color=colors.get(size, None),
                     linewidth=0.9 if thin else 1.6, alpha=0.7 if thin else 1.0,
                     label=f"N={size}" + (" (senza etichette)" if thin else ""))
        if thin:
            continue
        for x, y in zip(xs, ys):
            ax_wall.annotate(f"{y:.2f} s", (x, y), textcoords="offset points",
                             xytext=(0, 6 if size == 128 else -12), ha="center", fontsize=7,
                             color=colors.get(size, "black"))
    ax_wall.set_xscale("log", base=2)
    ax_wall.set_yscale("log", base=2)
    ax_wall.set_xticks(levels)
    ax_wall.set_xticklabels([str(t) for t in levels])
    ax_wall.set_xlabel("thread Rayon")
    ax_wall.set_ylabel("mediana wall per query (s)")
    ax_wall.set_title("(a) Latenza exact-ID A66 al crescere dei thread")
    ax_wall.axhline(10, color="black", linestyle=":", linewidth=0.8)
    ax_wall.annotate("10 s (relatore)", (levels[0], 10), textcoords="offset points",
                     xytext=(3, 3), fontsize=7)
    ax_wall.axhline(5, color="black", linestyle="--", linewidth=0.8)
    ax_wall.annotate("5 s (accettabile)", (levels[0], 5), textcoords="offset points",
                     xytext=(3, 3), fontsize=7)
    ax_wall.grid(True, which="both", alpha=0.25)
    ax_wall.legend(frameon=False)

    ideal = [t for t in levels]
    ax_speed.plot(levels, ideal, color="black", linestyle=":", linewidth=0.8, label="ideale")
    ax_speed.axhline(PHYSICAL_PERFORMANCE_CORES, color="black", linestyle="--", linewidth=0.8)
    ax_speed.annotate(f"{PHYSICAL_PERFORMANCE_CORES} core prestazionali", (levels[0], PHYSICAL_PERFORMANCE_CORES),
                      textcoords="offset points", xytext=(3, 3), fontsize=7)
    for size in sizes:
        xs = [t for t in levels if (size, t) in by_cell and "speedup_vs_1_thread" in by_cell[(size, t)]]
        ys = [by_cell[(size, t)]["speedup_vs_1_thread"] for t in xs]
        thin = size not in labeled
        ax_speed.plot(xs, ys, marker="s" if not thin else None, color=colors.get(size, None),
                      linewidth=0.9 if thin else 1.6, alpha=0.7 if thin else 1.0,
                      label=f"N={size}" + (" (senza etichette)" if thin else ""))
        if thin:
            continue
        for x, y in zip(xs, ys):
            ax_speed.annotate(f"{y:.1f}x", (x, y), textcoords="offset points",
                              xytext=(0, 6 if size == 128 else -12), ha="center", fontsize=7,
                              color=colors.get(size, "black"))
    ax_speed.set_xscale("log", base=2)
    ax_speed.set_xticks(levels)
    ax_speed.set_xticklabels([str(t) for t in levels])
    ax_speed.set_xlabel("thread Rayon")
    ax_speed.set_ylabel("speedup rispetto a 1 thread (mediane)")
    ax_speed.set_title("(b) Scaling del parallelismo CPU")
    ax_speed.grid(True, which="both", alpha=0.25)
    ax_speed.legend(frameon=False)

    fig.suptitle("A124: stesso circuito exact-ID (A66), da seriale a 16 thread, N=64/127/128",
                 fontsize=11)
    fig.text(0.5, 0.005,
             "Perché: il relatore ha chiesto di mostrare il miglioramento dal seriale al parallelismo CPU. "
             "Ogni PBS della stessa fase è indipendente, quindi lo speedup segue i core fisici finché la banda "
             "di memoria regge; oltre i 12 core prestazionali restano solo i 4 efficienti. Mediane su chiavi "
             "fresche per blocco, macchina scarica (guardia sul carico), stessi 5 probe di frontiera.",
             ha="center", fontsize=7, wrap=True)
    fig.tight_layout(rect=(0, 0.06, 1, 0.95))
    fig.savefig(png, dpi=300)
    fig.savefig(svg)
    plt.close(fig)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=pathlib.Path)
    parser.add_argument("--replicates", type=int, default=20_000)
    parser.add_argument("--seed", type=int, default=124_062_026)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--markdown", type=pathlib.Path)
    parser.add_argument("--figure", type=pathlib.Path, help="PNG path; SVG written alongside")
    args = parser.parse_args(argv)
    queries, _metas = load_records(args.inputs)
    analysis = analyze(queries, args.replicates, args.seed)
    analysis["generated_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    analysis["inputs"] = [str(path) for path in args.inputs]
    payload = json.dumps(analysis, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload)
    else:
        sys.stdout.write(payload)
    if args.markdown:
        args.markdown.write_text(markdown_table(analysis) + "\n")
    if args.figure:
        render_figure(analysis, args.figure, args.figure.with_suffix(".svg"))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except A124AnalysisError as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}), file=sys.stderr)
        raise SystemExit(2) from error
