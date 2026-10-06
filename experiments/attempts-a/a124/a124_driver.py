#!/usr/bin/env python3
"""Prepare and run the frozen A66 thread sweep at N=64, 127 and 128.

The default mode is a read-only dry plan. ``--run`` never compiles: it validates an already-built
binary, materializes the frozen DigiFace scenes and schedules in a temporary directory, waits for
the host to be idle, and runs one child process per (gallery size, thread count) cell.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
from types import ModuleType
from typing import Any, Iterable


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
INPUT_MANIFEST = HERE / "frozen-inputs.sha256"
VALIDATION_PATH = ROOT / "benchmark" / "fhe_digiface_validation.py"
DEFAULT_BINARY = HERE / "target-a124-only" / "release" / "a124_a66_thread_sweep"
DEFAULT_RESULTS = ROOT / "experiments" / "14_pipeline_tfhe_rs" / "results"

FRONTIER: tuple[int, ...] = (265, 758, 211, 1943, 407)
FRONTIER_N127_MINIMA: tuple[int, ...] = (2, 3, 4, 5, 7)
GALLERY_SIZES: tuple[int, ...] = (64, 127, 128)
THREAD_LEVELS: tuple[int, ...] = (1, 2, 4, 6, 8, 12, 16)
CELL_ORDER_THREADS: tuple[int, ...] = (16, 12, 8, 6, 4, 2, 1)
CELL_ORDER_SIZES: tuple[int, ...] = (128, 64, 127)
EXTRA_TEMPLATE_SOURCE = 413
BASE_GALLERY_SIZE = 127
DIMENSION = 512
THRESHOLD = 4
STAGES = ("smoke", "sweep")
SMOKE_CELLS: tuple[tuple[int, int], ...] = ((64, 16),)


class A124Error(RuntimeError):
    """A frozen input, schedule, binary, host state, or child output violated the A124 contract."""


@dataclasses.dataclass(frozen=True)
class SceneRecord:
    slot: int
    source_index: int
    expected_min_score: int
    expected_argmin: int
    expected_code: int


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _manifest_records() -> dict[str, str]:
    records: dict[str, str] = {}
    for line_number, line in enumerate(INPUT_MANIFEST.read_text().splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\0]+)", line)
        if match is None:
            raise A124Error(f"malformed input manifest line {line_number}")
        digest, relative = match.groups()
        candidate = pathlib.PurePosixPath(relative)
        if candidate.is_absolute() or ".." in candidate.parts or relative in records:
            raise A124Error(f"unsafe or duplicate manifest path: {relative!r}")
        records[relative] = digest
    return records


def verify_frozen_inputs() -> dict[str, str]:
    records = _manifest_records()
    for relative, expected in records.items():
        path = ROOT.joinpath(*pathlib.PurePosixPath(relative).parts).resolve()
        path.relative_to(ROOT)
        if not path.is_file():
            raise A124Error(f"missing frozen input: {relative}")
        actual = sha256_file(path)
        if actual != expected:
            raise A124Error(f"frozen input drift: {relative}: {actual} != {expected}")
    return records


def _load_validation_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_a124_frozen_validation", VALIDATION_PATH)
    if spec is None or spec.loader is None:
        raise A124Error(f"cannot import {VALIDATION_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_SCENE_CACHE: dict[str, Any] = {}


def _base_scene() -> tuple[Any, Any, dict[str, Any]]:
    """Load the frozen DigiFace gallery and probe pool once."""

    if "base" not in _SCENE_CACHE:
        validation = _load_validation_module()
        gallery, probes, _names, config, scene = validation.load_scene()
        if gallery.shape != (BASE_GALLERY_SIZE, DIMENSION):
            raise A124Error(f"unexpected gallery shape: {gallery.shape}")
        if int(config["T"]) != THRESHOLD:
            raise A124Error("DigiFace threshold drifted")
        _SCENE_CACHE["base"] = (gallery, probes, scene)
    return _SCENE_CACHE["base"]


def gallery_for(gallery_size: int) -> Any:
    """Return the integer gallery used for one sweep size.

    ``N<=127`` takes the first ``N`` frozen DigiFace templates. ``N=128`` appends probe
    ``EXTRA_TEMPLATE_SOURCE`` as the last template: its squared norm equals the largest gallery
    norm, so the Cauchy score domain and the aligned fast path do not change; it is not one of the
    frontier probes and it is not a duplicate of any gallery row.
    """

    import numpy as np

    gallery, probes, _scene = _base_scene()
    gallery = np.asarray(gallery, dtype=np.int64)
    probes = np.asarray(probes, dtype=np.int64)
    if gallery_size not in GALLERY_SIZES:
        raise A124Error(f"unsupported gallery size: {gallery_size}")
    if gallery_size <= BASE_GALLERY_SIZE:
        return gallery[:gallery_size]
    extra = probes[EXTRA_TEMPLATE_SOURCE]
    gallery_norms = (gallery * gallery).sum(axis=1)
    extra_norm = int((extra * extra).sum())
    if EXTRA_TEMPLATE_SOURCE in FRONTIER:
        raise A124Error("extra template collides with a frontier probe")
    if extra_norm != int(gallery_norms.max()):
        raise A124Error(
            f"extra template norm {extra_norm} != max gallery norm {int(gallery_norms.max())}"
        )
    if bool((gallery == extra).all(axis=1).any()):
        raise A124Error("extra template duplicates a gallery row")
    if int(np.count_nonzero(extra)) == 0:
        raise A124Error("extra template is trivial")
    return np.vstack([gallery, extra[None, :]])


def scene_payload(gallery_size: int) -> tuple[bytes, list[SceneRecord], dict[str, Any]]:
    """Return a deterministic whitespace scene consumed by the Rust harness."""

    import numpy as np

    _gallery, probes, base = _base_scene()
    probes = np.asarray(probes, dtype=np.int64)
    gallery = gallery_for(gallery_size)
    norms = (gallery * gallery).sum(axis=1)

    lines = [f"A124SCENE1 {gallery_size} {DIMENSION} {THRESHOLD} {len(FRONTIER)}"]
    for row in gallery:
        lines.append(" ".join(str(int(value)) for value in row))

    records: list[SceneRecord] = []
    for slot, source_index in enumerate(FRONTIER):
        vector = probes[source_index]
        if int(np.count_nonzero(vector)) == 0:
            raise A124Error(f"frontier probe {source_index} is trivial")
        scores = norms - 2 * (gallery @ vector)
        expected_argmin = int(np.argmin(scores))
        expected_minimum = int(scores[expected_argmin])
        if gallery_size == BASE_GALLERY_SIZE:
            frozen_minimum = FRONTIER_N127_MINIMA[slot]
            cached = int(base["all_scores"][source_index][expected_argmin])
            if expected_minimum != frozen_minimum or cached != expected_minimum:
                raise A124Error(
                    f"frontier minimum drift at {source_index}: "
                    f"{expected_minimum} != {frozen_minimum}"
                )
        expected_code = expected_argmin + 1 if expected_minimum <= THRESHOLD else 0
        record = SceneRecord(
            slot=slot,
            source_index=source_index,
            expected_min_score=expected_minimum,
            expected_argmin=expected_argmin,
            expected_code=expected_code,
        )
        records.append(record)
        lines.append(
            f"{record.slot} {record.source_index} {record.expected_min_score} "
            f"{record.expected_argmin} {record.expected_code}"
        )
        lines.append(" ".join(str(int(value)) for value in vector))

    payload = ("\n".join(lines) + "\n").encode("ascii")
    summary = {
        "kind": "frozen_nontrivial_digiface_frontier",
        "gallery_size": gallery_size,
        "dimension": DIMENSION,
        "threshold": THRESHOLD,
        "extra_template_source": EXTRA_TEMPLATE_SOURCE if gallery_size > BASE_GALLERY_SIZE else None,
        "max_gallery_norm2": int(norms.max()),
        "frontier": [dataclasses.asdict(record) for record in records],
        "accepted_probes": sum(record.expected_code != 0 for record in records),
        "rejected_probes": sum(record.expected_code == 0 for record in records),
        "payload_sha256": sha256_bytes(payload),
        "cache_scene_sha256": base["clear_summary"]["scene_sha256"],
    }
    return payload, records, summary


def _stage_shape(stage: str) -> tuple[tuple[int, ...], tuple[int, ...], int, int]:
    if stage == "smoke":
        return (0,), (0, 1), 1, 1
    if stage == "sweep":
        return (0, 1), tuple(range(len(FRONTIER))), 1, 2
    raise A124Error(f"unknown stage: {stage}")


def schedule_rows(stage: str) -> list[dict[str, Any]]:
    """Deterministic schedule: warm-ups first, then every probe slot once per block, in slot order.

    The sweep measures one circuit, so no order randomization is needed inside a cell; the order
    across cells is fixed by ``cells_for``.
    """

    blocks, probe_slots, repetitions, warmups = _stage_shape(stage)
    rows: list[dict[str, Any]] = []
    sequence = 0
    for block in blocks:
        for position in range(warmups):
            rows.append(
                {
                    "sequence": sequence,
                    "stage": stage,
                    "block": block,
                    "phase": "warmup",
                    "included_in_analysis": False,
                    "phase_position": position,
                    "probe_slot": probe_slots[position % len(probe_slots)],
                    "repetition": position // len(probe_slots),
                }
            )
            sequence += 1
        position = 0
        for repetition in range(repetitions):
            for probe_slot in probe_slots:
                rows.append(
                    {
                        "sequence": sequence,
                        "stage": stage,
                        "block": block,
                        "phase": "measured",
                        "included_in_analysis": True,
                        "phase_position": position,
                        "probe_slot": probe_slot,
                        "repetition": repetition,
                    }
                )
                sequence += 1
                position += 1
    validate_schedule(rows, stage)
    return rows


def validate_schedule(rows: list[dict[str, Any]], stage: str) -> dict[str, Any]:
    blocks, probe_slots, repetitions, warmups = _stage_shape(stage)
    observed_blocks = tuple(sorted({int(row["block"]) for row in rows}))
    if observed_blocks != blocks:
        raise A124Error(f"schedule blocks drift: {observed_blocks} != {blocks}")
    if [int(row["sequence"]) for row in rows] != list(range(len(rows))):
        raise A124Error("sequence is not contiguous")
    for block in blocks:
        block_rows = [row for row in rows if int(row["block"]) == block]
        warm = [row for row in block_rows if row["phase"] == "warmup"]
        measured = [row for row in block_rows if row["phase"] == "measured"]
        if len(warm) != warmups:
            raise A124Error(f"block {block} warm-up count drift")
        if len(measured) != len(probe_slots) * repetitions:
            raise A124Error(f"block {block} measured count drift")
        for probe_slot in probe_slots:
            cell = [row for row in measured if int(row["probe_slot"]) == probe_slot]
            if len(cell) != repetitions:
                raise A124Error(f"block/probe cell drift: {block}/{probe_slot}")
    return {
        "stage": stage,
        "blocks": list(blocks),
        "queries": len(rows),
        "measured_queries": sum(bool(row["included_in_analysis"]) for row in rows),
        "excluded_warmup_queries": sum(not bool(row["included_in_analysis"]) for row in rows),
    }


def schedule_payload(
    stage: str, gallery_size: int, threads: int
) -> tuple[bytes, list[dict[str, Any]], dict[str, Any]]:
    rows = schedule_rows(stage)
    lines = [f"A124SCHED1 {stage} {gallery_size} {threads} {len(rows)}"]
    for row in rows:
        lines.append(
            "{sequence} {block} {phase} {phase_position} {probe_slot} {repetition}".format(**row)
        )
    payload = ("\n".join(lines) + "\n").encode("ascii")
    summary = validate_schedule(rows, stage)
    summary["gallery_size"] = gallery_size
    summary["threads"] = threads
    summary["payload_sha256"] = sha256_bytes(payload)
    return payload, rows, summary


def cells_for(
    stage: str,
    gallery_sizes: Iterable[int] | None = None,
    threads: Iterable[int] | None = None,
) -> tuple[tuple[int, int], ...]:
    """Preregistered cell order: fast thread levels first so partial runs stay informative."""

    if stage == "smoke":
        return SMOKE_CELLS
    sizes = tuple(gallery_sizes) if gallery_sizes is not None else CELL_ORDER_SIZES
    levels = tuple(threads) if threads is not None else CELL_ORDER_THREADS
    for size in sizes:
        if size not in GALLERY_SIZES:
            raise A124Error(f"gallery size outside the preregistered set: {size}")
    for level in levels:
        if level not in THREAD_LEVELS:
            raise A124Error(f"thread level outside the preregistered set: {level}")
    ordered_levels = tuple(level for level in CELL_ORDER_THREADS if level in levels)
    ordered_sizes = tuple(size for size in CELL_ORDER_SIZES if size in sizes)
    return tuple((size, level) for level in ordered_levels for size in ordered_sizes)


def host_load() -> tuple[float, float, float]:
    return os.getloadavg()


_CPU_USAGE = re.compile(r"CPU usage:\s*([0-9.]+)% user,\s*([0-9.]+)% sys,\s*([0-9.]+)% idle")


def parse_top_busy_fraction(text: str) -> float:
    """Return the mean busy fraction over all but the first ``CPU usage`` sample of ``top``.

    The first sample of ``top -l`` is cumulative since boot and is discarded.
    """

    matches = _CPU_USAGE.findall(text)
    if len(matches) < 2:
        raise A124Error("top did not report at least two CPU usage samples")
    busy = [1.0 - float(idle) / 100.0 for _user, _sys, idle in matches[1:]]
    return sum(busy) / len(busy)


def host_busy_fraction(samples: int = 3, interval_s: int = 2) -> float:
    """Instantaneous CPU busy fraction of the whole host from ``top`` samples.

    Unlike the load average this has no lag and is not inflated by multithreaded daemons
    that are mostly waiting on I/O.
    """

    completed = subprocess.run(
        ["top", "-l", str(samples), "-s", str(interval_s), "-n", "0"],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise A124Error(f"top failed: {completed.stderr[-300:]}")
    return parse_top_busy_fraction(completed.stdout)


def wait_for_idle(
    load_max: float,
    wait_seconds: float,
    poll_seconds: float,
    guard: str = "cpu",
    cpu_busy_max: float = 0.15,
) -> dict[str, Any]:
    """Block until the host is idle for two consecutive polls.

    ``guard="load"`` uses the one-minute load average against ``load_max``;
    ``guard="cpu"`` uses the instantaneous busy fraction from ``top`` against
    ``cpu_busy_max`` (0.15 means at most 15% of all logical cores busy). Both values are
    recorded for every poll so the choice is auditable afterwards.
    """

    if guard not in ("cpu", "load"):
        raise A124Error(f"unknown guard: {guard}")
    started = time.monotonic()
    consecutive = 0
    needed = 2 if wait_seconds > 0 else 1
    samples: list[dict[str, float]] = []
    while True:
        load1 = host_load()[0]
        busy = host_busy_fraction() if guard == "cpu" else float("nan")
        samples.append({"load1": load1, "cpu_busy": busy})
        idle = (busy <= cpu_busy_max) if guard == "cpu" else (load1 <= load_max)
        consecutive = consecutive + 1 if idle else 0
        if consecutive >= needed:
            return {
                "guard": guard,
                "load_max": load_max,
                "cpu_busy_max": cpu_busy_max,
                "polls_required": needed,
                "waited_s": time.monotonic() - started,
                "samples": samples[-8:],
                "load_before_cell": load1,
                "cpu_busy_before_cell": busy,
            }
        remaining = wait_seconds - (time.monotonic() - started)
        if remaining <= 0:
            raise A124Error(
                f"host never became idle: last load1={load1:.2f}, cpu_busy={busy:.3f} after "
                f"{wait_seconds:.0f}s"
            )
        time.sleep(min(poll_seconds, remaining))


def completed_cells(output_dir: pathlib.Path, stage: str) -> dict[tuple[int, int], pathlib.Path]:
    """Cells of ``stage`` already recorded in ``output_dir`` with a PASS summary."""

    done: dict[tuple[int, int], pathlib.Path] = {}
    pattern = re.compile(rf"a124_a66_{stage}_n(\d+)_threads(\d+)_.*\.jsonl$")
    for path in sorted(output_dir.glob(f"a124_a66_{stage}_n*_threads*_*.jsonl")):
        match = pattern.match(path.name)
        if match is None:
            continue
        lines = [line for line in path.read_text().splitlines() if line.strip()]
        if not lines:
            continue
        last = json.loads(lines[-1])
        if last.get("record") == "summary" and last.get("status") == "PASS":
            done[(int(match.group(1)), int(match.group(2)))] = path
    return done


def dry_plan() -> dict[str, Any]:
    inputs = verify_frozen_inputs()
    scenes = {str(size): scene_payload(size)[2] for size in GALLERY_SIZES}
    schedules = {stage: schedule_payload(stage, 127, 16)[2] for stage in STAGES}
    sweep_cells = cells_for("sweep")
    return {
        "status": "PASS_DRY_PLAN_NO_CARGO_NO_FHE",
        "variant": "a124_a66_thread_sweep",
        "circuit": "a66",
        "input_manifest_sha256": sha256_file(INPUT_MANIFEST),
        "pinned_inputs": len(inputs),
        "scenes": scenes,
        "schedules": schedules,
        "sweep_cells": [list(cell) for cell in sweep_cells],
        "sweep_queries_total": len(sweep_cells) * schedules["sweep"]["queries"],
        "smoke_cells": [list(cell) for cell in SMOKE_CELLS],
        "same_key_within_block": True,
        "decrypt_policy": "after_all_timings_in_key_block",
        "idle_guard": "instantaneous_cpu_busy_fraction_or_load1_under_threshold_for_two_polls_before_each_cell",
        "run_requires_prebuilt_hash_pinned_binary": True,
        "promotion_allowed": False,
    }


def _write_new(path: pathlib.Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        handle.write(payload)


def _parse_int_list(value: str | None) -> tuple[int, ...] | None:
    if value is None:
        return None
    return tuple(int(item) for item in value.split(",") if item.strip())


def _run_stage(args: argparse.Namespace) -> list[pathlib.Path]:
    if not re.fullmatch(r"[0-9a-f]{64}", args.expected_binary_sha256 or ""):
        raise A124Error("--run requires --expected-binary-sha256")
    binary = args.binary.resolve()
    if not binary.is_file():
        raise A124Error(f"prebuilt binary missing: {binary}")
    actual_binary_sha = sha256_file(binary)
    if actual_binary_sha != args.expected_binary_sha256:
        raise A124Error(f"binary hash mismatch: {actual_binary_sha}")
    verify_frozen_inputs()

    cells = cells_for(
        args.stage, _parse_int_list(args.gallery_sizes), _parse_int_list(args.threads)
    )
    skipped: list[dict[str, Any]] = []
    if args.skip_done:
        done = completed_cells(args.output_dir, args.stage)
        skipped = [
            {"gallery_size": size, "threads": threads, "existing": str(done[(size, threads)])}
            for size, threads in cells
            if (size, threads) in done
        ]
        cells = tuple(cell for cell in cells if cell not in done)
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H%M%S.%fZ")
    outputs: list[pathlib.Path] = []
    cell_records: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="a124-a66-thread-sweep-") as temporary:
        temp = pathlib.Path(temporary)
        for gallery_size, threads in cells:
            scene, _records, scene_summary = scene_payload(gallery_size)
            schedule, _rows, schedule_summary = schedule_payload(args.stage, gallery_size, threads)
            scene_sha = sha256_bytes(scene)
            schedule_sha = sha256_bytes(schedule)
            scene_path = temp / f"scene_n{gallery_size}.txt"
            schedule_path = temp / f"schedule_{args.stage}_n{gallery_size}_t{threads}.txt"
            scene_path.write_bytes(scene)
            schedule_path.write_bytes(schedule)
            idle = wait_for_idle(
                args.load_max,
                args.wait_for_idle_seconds,
                args.poll_seconds,
                args.guard,
                args.cpu_busy_max,
            )
            command = [
                str(binary),
                "--run",
                f"--scene={scene_path}",
                f"--schedule={schedule_path}",
                f"--expected-scene-sha256={scene_sha}",
                f"--expected-schedule-sha256={schedule_sha}",
                f"--expected-binary-sha256={actual_binary_sha}",
                f"--threads={threads}",
            ]
            started = time.monotonic()
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=args.timeout,
            )
            elapsed = time.monotonic() - started
            if completed.returncode != 0:
                raise A124Error(
                    f"child failed for N={gallery_size} threads={threads}: "
                    f"rc={completed.returncode}; stderr={completed.stderr[-2000:]}"
                )
            records = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
            if not records or records[-1].get("record") != "summary":
                raise A124Error(f"truncated output for N={gallery_size} threads={threads}")
            if records[-1].get("status") != "PASS":
                raise A124Error(f"child did not pass for N={gallery_size} threads={threads}")
            output = args.output_dir / (
                f"a124_a66_{args.stage}_n{gallery_size}_threads{threads}_{timestamp}.jsonl"
            )
            _write_new(output, completed.stdout)
            outputs.append(output)
            cell_records.append(
                {
                    "gallery_size": gallery_size,
                    "threads": threads,
                    "scene_sha256": scene_sha,
                    "schedule_sha256": schedule_sha,
                    "scene_summary": scene_summary,
                    "schedule_summary": schedule_summary,
                    "idle_guard": idle,
                    "load_after_cell": host_load()[0],
                    "cpu_busy_after_cell": host_busy_fraction(samples=2, interval_s=1),
                    "child_wall_s": elapsed,
                    "output": str(output),
                }
            )
    metadata = {
        "record": "driver",
        "variant": "a124_a66_thread_sweep",
        "stage": args.stage,
        "binary": str(binary),
        "binary_sha256": actual_binary_sha,
        "input_manifest_sha256": sha256_file(INPUT_MANIFEST),
        "guard": args.guard,
        "load_max": args.load_max,
        "cpu_busy_max": args.cpu_busy_max,
        "skipped_existing_cells": skipped,
        "cells": cell_records,
        "outputs": [str(path) for path in outputs],
    }
    metadata_path = args.output_dir / f"a124_a66_{args.stage}_{timestamp}.driver.json"
    _write_new(metadata_path, json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    outputs.append(metadata_path)
    return outputs


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="execute an already-built binary")
    parser.add_argument("--stage", choices=STAGES, default="sweep")
    parser.add_argument("--gallery-sizes", help="comma list, subset of 64,127,128")
    parser.add_argument("--threads", help="comma list, subset of 1,2,4,6,8,12,16")
    parser.add_argument("--binary", type=pathlib.Path, default=DEFAULT_BINARY)
    parser.add_argument("--expected-binary-sha256")
    parser.add_argument("--output-dir", type=pathlib.Path, default=DEFAULT_RESULTS)
    parser.add_argument("--guard", choices=("cpu", "load"), default="cpu")
    parser.add_argument("--cpu-busy-max", type=float, default=0.15)
    parser.add_argument("--load-max", type=float, default=4.0)
    parser.add_argument("--wait-for-idle-seconds", type=float, default=0.0)
    parser.add_argument("--poll-seconds", type=float, default=30.0)
    parser.add_argument("--skip-done", action="store_true",
                        help="skip cells that already have a PASS JSONL for this stage")
    parser.add_argument("--timeout", type=float, default=14_400.0)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.run:
        outputs = _run_stage(args)
        print(json.dumps({"status": "PASS_RUN", "outputs": [str(path) for path in outputs]}))
    else:
        print(json.dumps(dry_plan(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except A124Error as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}), file=sys.stderr)
        raise SystemExit(2) from error
