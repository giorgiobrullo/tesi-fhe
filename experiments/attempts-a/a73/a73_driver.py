#!/usr/bin/env python3
"""Prepare and run the frozen A62/A66 component-paired experiment.

The default mode is a read-only dry plan. ``--run`` never compiles: it validates an already-built
binary, materializes the frozen DigiFace scene and schedule in a temporary directory, and runs the
same paired design once with one Rayon thread and once with the declared production thread count.
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
import random
import re
import subprocess
import sys
import tempfile
from types import ModuleType
from typing import Any, Iterable


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
INPUT_MANIFEST = HERE / "frozen-inputs.sha256"
VALIDATION_PATH = ROOT / "benchmark" / "fhe_digiface_validation.py"
DEFAULT_BINARY = HERE / "target-a73-only" / "release" / "a73_a62_a66_paired"
DEFAULT_RESULTS = HERE / "results"

FRONTIER: tuple[tuple[int, int], ...] = (
    (265, 2),
    (758, 3),
    (211, 4),
    (1943, 5),
    (407, 7),
)
GALLERY_SIZE = 127
DIMENSION = 512
THRESHOLD = 4
BASE_SEED = 73_062_026
ORDERS = ("A62_A66", "A66_A62")
PHASES = ("warmup", "measured")
THREAD_MODES = ("both", "single-only", "production-only")


class A73Error(RuntimeError):
    """A frozen input, schedule, binary, or child output violated the A73 contract."""


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
            raise A73Error(f"malformed input manifest line {line_number}")
        digest, relative = match.groups()
        candidate = pathlib.PurePosixPath(relative)
        if candidate.is_absolute() or ".." in candidate.parts or relative in records:
            raise A73Error(f"unsafe or duplicate manifest path: {relative!r}")
        records[relative] = digest
    return records


def verify_frozen_inputs() -> dict[str, str]:
    records = _manifest_records()
    for relative, expected in records.items():
        path = ROOT.joinpath(*pathlib.PurePosixPath(relative).parts).resolve()
        path.relative_to(ROOT)
        if not path.is_file():
            raise A73Error(f"missing frozen input: {relative}")
        actual = sha256_file(path)
        if actual != expected:
            raise A73Error(f"frozen input drift: {relative}: {actual} != {expected}")
    return records


def _load_validation_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_a73_frozen_validation", VALIDATION_PATH)
    if spec is None or spec.loader is None:
        raise A73Error(f"cannot import {VALIDATION_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def frozen_scene_payload() -> tuple[bytes, list[SceneRecord], dict[str, Any]]:
    """Return a deterministic whitespace scene consumed by the Rust harness."""

    import numpy as np

    validation = _load_validation_module()
    gallery, probes, _names, config, scene = validation.load_scene()
    if gallery.shape != (GALLERY_SIZE, DIMENSION):
        raise A73Error(f"unexpected gallery shape: {gallery.shape}")
    if int(config["T"]) != THRESHOLD:
        raise A73Error("DigiFace threshold drifted")

    lines = [f"A73SCENE1 {GALLERY_SIZE} {DIMENSION} {THRESHOLD} {len(FRONTIER)}"]
    for row in gallery:
        lines.append(" ".join(str(int(value)) for value in row))

    records: list[SceneRecord] = []
    all_scores = scene["all_scores"]
    for slot, (source_index, frozen_minimum) in enumerate(FRONTIER):
        vector = probes[source_index]
        if int(np.count_nonzero(vector)) == 0:
            raise A73Error(f"frontier probe {source_index} is trivial")
        scores = all_scores[source_index]
        expected_argmin = int(np.argmin(scores))
        expected_minimum = int(scores[expected_argmin])
        if expected_minimum != frozen_minimum:
            raise A73Error(
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
        "gallery_size": GALLERY_SIZE,
        "dimension": DIMENSION,
        "threshold": THRESHOLD,
        "frontier": [dataclasses.asdict(record) for record in records],
        "payload_sha256": sha256_bytes(payload),
        "cache_scene_sha256": scene["clear_summary"]["scene_sha256"],
        "all_probes_nontrivial": True,
    }
    return payload, records, summary


def _stage_shape(stage: str) -> tuple[range, tuple[int, ...], int, int]:
    if stage == "smoke":
        return range(0, 1), (0,), 2, 1
    if stage == "initial":
        return range(0, 3), tuple(range(len(FRONTIER))), 4, 4
    if stage == "extension":
        return range(3, 6), tuple(range(len(FRONTIER))), 4, 4
    raise A73Error(f"unknown stage: {stage}")


def schedule_rows(stage: str, seed: int = BASE_SEED) -> list[dict[str, Any]]:
    blocks, probe_slots, repetitions, warmup_pairs = _stage_shape(stage)
    rows: list[dict[str, Any]] = []
    pair_sequence = 0
    for block in blocks:
        block_seed = seed + block * 1_000_003
        for position in range(warmup_pairs):
            rows.append(
                {
                    "pair_sequence": pair_sequence,
                    "stage": stage,
                    "block": block,
                    "block_seed": block_seed,
                    "phase": "warmup",
                    "included_in_analysis": False,
                    "phase_position": position,
                    "probe_slot": probe_slots[position % len(probe_slots)],
                    "repetition": position // len(probe_slots),
                    "pair_order": ORDERS[(block + position) % 2],
                }
            )
            pair_sequence += 1

        rng = random.Random(block_seed)
        measured: list[dict[str, Any]] = []
        per_order = repetitions // 2
        for probe_slot in probe_slots:
            directions = [ORDERS[0]] * per_order + [ORDERS[1]] * per_order
            rng.shuffle(directions)
            for repetition, pair_order in enumerate(directions):
                measured.append(
                    {
                        "stage": stage,
                        "block": block,
                        "block_seed": block_seed,
                        "phase": "measured",
                        "included_in_analysis": True,
                        "probe_slot": probe_slot,
                        "repetition": repetition,
                        "pair_order": pair_order,
                    }
                )
        rng.shuffle(measured)
        for position, row in enumerate(measured):
            row["pair_sequence"] = pair_sequence
            row["phase_position"] = position
            pair_sequence += 1
            rows.append(row)
    validate_schedule(rows, stage)
    return rows


def validate_schedule(rows: list[dict[str, Any]], stage: str) -> dict[str, Any]:
    blocks, probe_slots, repetitions, warmup_pairs = _stage_shape(stage)
    expected_blocks = list(blocks)
    observed_blocks = sorted({int(row["block"]) for row in rows})
    if observed_blocks != expected_blocks:
        raise A73Error(f"schedule blocks drift: {observed_blocks} != {expected_blocks}")
    if [int(row["pair_sequence"]) for row in rows] != list(range(len(rows))):
        raise A73Error("pair sequence is not contiguous")
    balance: dict[str, dict[str, int]] = {}
    for block in blocks:
        block_rows = [row for row in rows if int(row["block"]) == block]
        warmups = [row for row in block_rows if row["phase"] == "warmup"]
        measured = [row for row in block_rows if row["phase"] == "measured"]
        if len(warmups) != warmup_pairs:
            raise A73Error(f"block {block} warm-up count drift")
        if len(measured) != len(probe_slots) * repetitions:
            raise A73Error(f"block {block} measured count drift")
        for probe_slot in probe_slots:
            cell = [row for row in measured if int(row["probe_slot"]) == probe_slot]
            counts = {
                order: sum(row["pair_order"] == order for row in cell) for order in ORDERS
            }
            if set(counts.values()) != {repetitions // 2}:
                raise A73Error(f"unbalanced block/probe cell: {block}/{probe_slot}")
            balance[f"{block}:{probe_slot}"] = counts
    return {
        "stage": stage,
        "blocks": expected_blocks,
        "pairs": len(rows),
        "measured_pairs": sum(bool(row["included_in_analysis"]) for row in rows),
        "excluded_warmup_pairs": sum(not bool(row["included_in_analysis"]) for row in rows),
        "balance_by_block_probe": balance,
    }


def schedule_payload(stage: str) -> tuple[bytes, list[dict[str, Any]], dict[str, Any]]:
    rows = schedule_rows(stage)
    lines = [f"A73SCHED1 {stage} {len(rows)}"]
    for row in rows:
        lines.append(
            "{pair_sequence} {block} {phase} {phase_position} {probe_slot} "
            "{repetition} {pair_order}".format(**row)
        )
    payload = ("\n".join(lines) + "\n").encode("ascii")
    summary = validate_schedule(rows, stage)
    summary["payload_sha256"] = sha256_bytes(payload)
    return payload, rows, summary


def thread_strata(production_threads: int, thread_mode: str) -> tuple[int, ...]:
    if production_threads <= 1:
        raise A73Error("--production-threads must be greater than one")
    if thread_mode == "both":
        return (1, production_threads)
    if thread_mode == "single-only":
        return (1,)
    if thread_mode == "production-only":
        return (production_threads,)
    raise A73Error(f"unknown thread mode: {thread_mode}")


def dry_plan(production_threads: int, thread_mode: str = "both") -> dict[str, Any]:
    inputs = verify_frozen_inputs()
    _payload, _records, scene = frozen_scene_payload()
    schedules = {stage: schedule_payload(stage)[2] for stage in ("smoke", "initial", "extension")}
    return {
        "status": "PASS_DRY_PLAN_NO_CARGO_NO_FHE",
        "variant": "a73_a62_vs_a66_component_paired",
        "baseline": "a62",
        "candidate": "a66",
        "input_manifest_sha256": sha256_file(INPUT_MANIFEST),
        "pinned_inputs": len(inputs),
        "scene": scene,
        "schedules": schedules,
        "combined_initial_plus_extension": {
            "measured_pairs": schedules["initial"]["measured_pairs"]
            + schedules["extension"]["measured_pairs"],
            "excluded_warmup_pairs": schedules["initial"]["excluded_warmup_pairs"]
            + schedules["extension"]["excluded_warmup_pairs"],
        },
        "thread_mode": thread_mode,
        "thread_strata": list(thread_strata(production_threads, thread_mode)),
        "same_key_within_pair": True,
        "same_gallery_object_within_pair": True,
        "same_packed_ciphertext_object_within_pair": True,
        "decrypt_policy": "after_both_variants_and_after_all_pair_timings_in_key_block",
        "rss_scope": "process_high_water_only_not_variant_attributable",
        "run_requires_prebuilt_hash_pinned_binary": True,
        "promotion_allowed": False,
    }


def _write_new(path: pathlib.Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        handle.write(payload)


def _run_stage(args: argparse.Namespace) -> list[pathlib.Path]:
    strata = thread_strata(args.production_threads, args.thread_mode)
    if args.stage != "smoke" and args.thread_mode != "both":
        raise A73Error("partial thread strata are allowed only for bounded smoke reruns")
    if not re.fullmatch(r"[0-9a-f]{64}", args.expected_binary_sha256 or ""):
        raise A73Error("--run requires --expected-binary-sha256")
    binary = args.binary.resolve()
    if not binary.is_file():
        raise A73Error(f"prebuilt binary missing: {binary}")
    actual_binary_sha = sha256_file(binary)
    if actual_binary_sha != args.expected_binary_sha256:
        raise A73Error(f"binary hash mismatch: {actual_binary_sha}")
    if args.stage == "extension" and not args.extension_ack:
        raise A73Error("extension requires --extension-ack after analyzing the initial stage")

    scene, _records, _scene_summary = frozen_scene_payload()
    schedule, _rows, _schedule_summary = schedule_payload(args.stage)
    scene_sha = sha256_bytes(scene)
    schedule_sha = sha256_bytes(schedule)
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H%M%S.%fZ")
    outputs: list[pathlib.Path] = []
    with tempfile.TemporaryDirectory(prefix="a73-a62-a66-paired-") as temporary:
        temp = pathlib.Path(temporary)
        scene_path = temp / "scene.txt"
        schedule_path = temp / "schedule.txt"
        scene_path.write_bytes(scene)
        schedule_path.write_bytes(schedule)
        for threads in strata:
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
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=args.timeout,
            )
            if completed.returncode != 0:
                raise A73Error(
                    f"paired child failed for threads={threads}: rc={completed.returncode}; "
                    f"stderr={completed.stderr[-2000:]}"
                )
            records = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
            if not records or records[-1].get("record") != "summary":
                raise A73Error(f"truncated paired output for threads={threads}")
            if records[-1].get("status") != "PASS":
                raise A73Error(f"paired child did not pass for threads={threads}")
            output = args.output_dir / (
                f"a73_a62_a66_{args.stage}_threads{threads}_{timestamp}.jsonl"
            )
            _write_new(output, completed.stdout)
            outputs.append(output)
    metadata = {
        "record": "driver",
        "stage": args.stage,
        "binary": str(binary),
        "binary_sha256": actual_binary_sha,
        "scene_sha256": scene_sha,
        "schedule_sha256": schedule_sha,
        "thread_mode": args.thread_mode,
        "thread_strata": list(strata),
        "outputs": [str(path) for path in outputs],
        "extension_ack": bool(args.extension_ack),
    }
    metadata_path = args.output_dir / f"a73_a62_a66_{args.stage}_{timestamp}.driver.json"
    _write_new(metadata_path, json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    outputs.append(metadata_path)
    return outputs


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="execute an already-built binary")
    parser.add_argument("--stage", choices=("smoke", "initial", "extension"), default="initial")
    parser.add_argument("--production-threads", type=int, default=max(2, os.cpu_count() or 2))
    parser.add_argument("--thread-mode", choices=THREAD_MODES, default="both")
    parser.add_argument("--binary", type=pathlib.Path, default=DEFAULT_BINARY)
    parser.add_argument("--expected-binary-sha256")
    parser.add_argument("--extension-ack", action="store_true")
    parser.add_argument("--output-dir", type=pathlib.Path, default=DEFAULT_RESULTS)
    parser.add_argument("--timeout", type=float, default=14_400.0)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.run:
        outputs = _run_stage(args)
        print(json.dumps({"status": "PASS_RUN", "outputs": [str(path) for path in outputs]}))
    else:
        print(
            json.dumps(
                dry_plan(args.production_threads, args.thread_mode), indent=2, sort_keys=True
            )
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except A73Error as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}), file=sys.stderr)
        raise SystemExit(2) from error
