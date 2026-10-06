#!/usr/bin/env python3
"""Validate and analyze A73 JSONL outputs with a paired hierarchical bootstrap."""

from __future__ import annotations

import argparse
import json
import math
import pathlib
import random
import statistics
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from typing import Any


ORDERS = ("A62_A66", "A66_A62")
STAGES = ("setup", "score", "extract", "select", "scan", "threshold", "output")


class AnalysisError(RuntimeError):
    """The paired result set is incomplete or violates its preregistration."""


def geometric_mean(values: Sequence[float]) -> float:
    if not values or any(value <= 0 for value in values):
        raise AnalysisError("geometric mean requires positive values")
    return math.exp(statistics.fmean(math.log(value) for value in values))


def quantile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise AnalysisError("empty quantile")
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def load_jsonl(paths: Iterable[pathlib.Path]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in paths:
        for line_number, line in enumerate(path.read_text().splitlines(), 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise AnalysisError(f"{path}:{line_number}: record is not an object")
            value["_source"] = str(path)
            records.append(value)
    return records


def _validate_pairs(rows: Sequence[Mapping[str, Any]]) -> None:
    if not rows:
        raise AnalysisError("no measured pairs")
    identities: set[tuple[Any, ...]] = set()
    by_cell: dict[tuple[int, int, int], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        identity = (
            row.get("threads"),
            row.get("block"),
            row.get("pair_sequence"),
        )
        if identity in identities:
            raise AnalysisError(f"duplicate pair {identity}")
        identities.add(identity)
        if not row.get("pair_pass") or not row.get("semantics_pass") or not row.get("counts_pass"):
            raise AnalysisError(f"failed pair {identity}")
        for flag in (
            "same_server_key_object",
            "same_gallery_backing",
            "same_packed_ciphertext_object",
        ):
            if row.get(flag) is not True:
                raise AnalysisError(f"{identity}: {flag} is not true")
        if row.get("a62_pbs") != 3390 or row.get("a66_pbs") != 3390:
            raise AnalysisError(f"{identity}: PBS count drift")
        for variant in ("a62", "a66"):
            stage_pbs = []
            for stage in STAGES:
                seconds_key = f"{variant}_{stage}_s"
                pbs_key = f"{variant}_{stage}_pbs"
                if seconds_key not in row or pbs_key not in row:
                    raise AnalysisError(f"{identity}: missing {variant}/{stage} telemetry")
                if float(row[seconds_key]) < 0 or int(row[pbs_key]) < 0:
                    raise AnalysisError(f"{identity}: invalid {variant}/{stage} telemetry")
                stage_pbs.append(int(row[pbs_key]))
            if sum(stage_pbs) != int(row[f"{variant}_pbs"]):
                raise AnalysisError(f"{identity}: {variant} stage PBS sum drift")
        if row.get("pair_order") not in ORDERS:
            raise AnalysisError(f"{identity}: invalid order")
        if float(row["a62_wall_s"]) <= 0 or float(row["a66_wall_s"]) <= 0:
            raise AnalysisError(f"{identity}: non-positive timing")
        by_cell[(int(row["threads"]), int(row["block"]), int(row["probe_slot"]))].append(row)
    for cell, members in by_cell.items():
        counts = {order: sum(row["pair_order"] == order for row in members) for order in ORDERS}
        if len(set(counts.values())) != 1 or not next(iter(counts.values())):
            raise AnalysisError(f"unbalanced measured cell {cell}: {counts}")


def _summary(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    ratios = [float(row["a66_wall_s"]) / float(row["a62_wall_s"]) for row in rows]
    reductions = [100 * (1 - ratio) for ratio in ratios]
    ratio = geometric_mean(ratios)
    return {
        "pairs": len(rows),
        "geometric_mean_ratio_a66_over_a62": ratio,
        "geometric_mean_reduction_pct": 100 * (1 - ratio),
        "median_paired_reduction_pct": statistics.median(reductions),
        "wins": {
            "a66_faster": sum(value > 0 for value in reductions),
            "a62_faster": sum(value < 0 for value in reductions),
            "ties": sum(value == 0 for value in reductions),
        },
        "a62_wall_s_median": statistics.median(float(row["a62_wall_s"]) for row in rows),
        "a66_wall_s_median": statistics.median(float(row["a66_wall_s"]) for row in rows),
    }


def _stage_summaries(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    summaries: dict[str, Any] = {}
    for stage in STAGES:
        left = [float(row[f"a62_{stage}_s"]) for row in rows]
        right = [float(row[f"a66_{stage}_s"]) for row in rows]
        reduction = None
        if all(value > 0 for value in left) and all(value > 0 for value in right):
            reduction = 100 * (
                1 - geometric_mean([candidate / baseline for baseline, candidate in zip(left, right)])
            )
        summaries[stage] = {
            "a62_seconds_median": statistics.median(left),
            "a66_seconds_median": statistics.median(right),
            "geometric_mean_reduction_pct": reduction,
            "a62_pbs_values": sorted({int(row[f"a62_{stage}_pbs"]) for row in rows}),
            "a66_pbs_values": sorted({int(row[f"a66_{stage}_pbs"]) for row in rows}),
        }
    return summaries


def hierarchical_bootstrap(
    rows: Sequence[Mapping[str, Any]], *, seed: int, replicates: int
) -> dict[str, Any]:
    by_block: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        by_block[int(row["block"])].append(row)
    blocks = sorted(by_block)
    if not blocks:
        raise AnalysisError("bootstrap has no blocks")
    if len(blocks) < 2:
        return {
            "method": "resample key blocks, then rows within probe-by-order strata",
            "seed": seed,
            "replicates": replicates,
            "blocks": len(blocks),
            "inferentially_valid": False,
            "reason": "at least two independent fresh-key blocks are required for an interval",
            "geometric_mean_reduction_pct_ci95": None,
            "ci95_width_percentage_points": None,
        }
    rng = random.Random(seed)
    estimates: list[float] = []
    for _ in range(replicates):
        sampled_ratios: list[float] = []
        for _position in blocks:
            selected = rng.choice(blocks)
            strata: dict[tuple[int, str], list[Mapping[str, Any]]] = defaultdict(list)
            for row in by_block[selected]:
                strata[(int(row["probe_slot"]), str(row["pair_order"]))].append(row)
            for stratum in sorted(strata):
                members = strata[stratum]
                sampled_ratios.extend(
                    float(sampled["a66_wall_s"]) / float(sampled["a62_wall_s"])
                    for sampled in (rng.choice(members) for _ in members)
                )
        estimates.append(100 * (1 - geometric_mean(sampled_ratios)))
    lower = quantile(estimates, 0.025)
    upper = quantile(estimates, 0.975)
    return {
        "method": "resample key blocks, then rows within probe-by-order strata",
        "seed": seed,
        "replicates": replicates,
        "blocks": len(blocks),
        "inferentially_valid": True,
        "geometric_mean_reduction_pct_ci95": [lower, upper],
        "ci95_width_percentage_points": upper - lower,
    }


def analyze_records(
    records: Sequence[Mapping[str, Any]], *, seed: int = 73_062_027, replicates: int = 10_000
) -> dict[str, Any]:
    if any(record.get("record") == "pair_error" for record in records):
        raise AnalysisError("pair_error record present")
    rows = [
        record
        for record in records
        if record.get("record") == "pair" and record.get("included_in_analysis") is True
    ]
    _validate_pairs(rows)
    by_threads: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        by_threads[int(row["threads"])].append(row)

    analyses: dict[str, Any] = {}
    extension_recommended = False
    for threads, thread_rows in sorted(by_threads.items()):
        overall = _summary(thread_rows)
        by_order = {
            order: _summary([row for row in thread_rows if row["pair_order"] == order])
            for order in ORDERS
        }
        order_difference = abs(
            by_order[ORDERS[0]]["geometric_mean_reduction_pct"]
            - by_order[ORDERS[1]]["geometric_mean_reduction_pct"]
        )
        bootstrap = hierarchical_bootstrap(thread_rows, seed=seed + threads, replicates=replicates)
        if (
            not bootstrap["inferentially_valid"]
            or bootstrap["ci95_width_percentage_points"] > 2
            or order_difference > 2
        ):
            extension_recommended = True
        analyses[str(threads)] = {
            "overall": overall,
            "by_order": by_order,
            "by_stage": _stage_summaries(thread_rows),
            "pair_order_reduction_difference_pp": order_difference,
            "bootstrap": bootstrap,
        }
    rss = [
        int(record["peak_rss_bytes_after_all_pair_timings"])
        for record in records
        if record.get("record") == "rss"
        and record.get("peak_rss_bytes_after_all_pair_timings") is not None
    ]
    return {
        "status": "PASS_PAIRED_ANALYSIS",
        "primary_estimand": "100*(1-geometric_mean(a66_wall_s/a62_wall_s))",
        "thread_strata": analyses,
        "measured_pairs": len(rows),
        "extension_policy": {
            "recommended": extension_recommended,
            "triggers": (
                "fewer than 2 independent key blocks, CI95 width >2pp, "
                "or AB/BA difference >2pp"
            ),
            "maximum_combined_measured_pairs_per_thread": 120,
        },
        "rss": {
            "scope": "process high-water only; not attributable to one variant",
            "maximum_observed_bytes": max(rss) if rss else None,
        },
        "promotion_allowed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=pathlib.Path, nargs="+")
    parser.add_argument("--replicates", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=73_062_027)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    result = analyze_records(
        load_jsonl(args.inputs), seed=args.seed, replicates=args.replicates
    )
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(rendered, end="")
    else:
        with args.output.open("x", encoding="utf-8") as handle:
            handle.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
