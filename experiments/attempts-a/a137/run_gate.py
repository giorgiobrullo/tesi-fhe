#!/usr/bin/env python3
"""Run prebuilt A137 only in a separately authorized exclusive workload window; preserve records."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from static_audit import audit
from validate import validate_process

HERE = Path(__file__).resolve().parent


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".partial")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument(
        "--binary",
        type=Path,
        default=HERE / "target-a137-only/release/a137_pfks_runtime_error_observer",
    )
    parser.add_argument("--expected-binary-sha256")
    parser.add_argument("--processes", type=int, choices=[1, 3], default=1)
    args = parser.parse_args()
    static = audit()
    if not args.run:
        print(
            json.dumps(
                {
                    "status": "PLAN_NO_FHE",
                    "static": static,
                    "processes": args.processes,
                },
                indent=2,
            )
        )
        return 0
    if (
        not args.expected_binary_sha256
        or sha256(args.binary) != args.expected_binary_sha256
    ):
        parser.error("missing/mismatched --expected-binary-sha256")
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H%M%S.%fZ")
    destination = HERE / "artifacts" / timestamp
    destination.mkdir(parents=True, exist_ok=False)
    metadata = {
        "artifact": "A137",
        "status": "RUNNING",
        "binary": str(args.binary.resolve()),
        "binary_sha256": args.expected_binary_sha256,
        "preregistration_sha256": static["preregistration_sha256"],
        "started_utc": timestamp,
        "runner_pid": os.getpid(),
        "processes": [],
        "source_static": static,
        "source_sha256": sha256(HERE / "src/main.rs"),
        "timing_claim": "snapshot instrumentation invalidates latency/RSS comparisons",
    }
    write_json(destination / "run.json", metadata)
    for offset in range(args.processes):
        stdout = destination / f"process-{offset}.jsonl"
        stderr = destination / f"process-{offset}.stderr.txt"
        environment = dict(
            os.environ,
            RAYON_NUM_THREADS="1",
            A137_ORDER_OFFSET=str(offset),
            A137_RUN_FHE="I_ACKNOWLEDGE_A137_DIRECT_WINDOW_PFKS_FHE",
            A137_PREREGISTRATION_SHA256=static["preregistration_sha256"],
        )
        record = {
            "order_offset": offset,
            "status": "RUNNING",
            "load_before": list(os.getloadavg()),
            "stdout": str(stdout),
            "stderr": str(stderr),
        }
        metadata["processes"].append(record)
        with stdout.open("x") as output, stderr.open("x") as error:
            process = subprocess.Popen(
                [
                    "/usr/bin/time",
                    "-l",
                    str(args.binary.resolve()),
                    "--run-authorized",
                    "--pfks",
                    "24x1",
                ],
                env=environment,
                stdout=output,
                stderr=error,
            )
            record["time_wrapper_pid"] = process.pid
            write_json(destination / "run.json", metadata)
            record["exit_code"] = process.wait()
        record["status"] = "TERMINAL"
        record["load_after"] = list(os.getloadavg())
        record["stdout_sha256"] = sha256(stdout)
        record["stderr_sha256"] = sha256(stderr)
        try:
            record["summary"] = validate_process(stdout)
        except (ValueError, KeyError) as error:
            record["validation_error"] = str(error)
        write_json(destination / "run.json", metadata)
        print(json.dumps(record), flush=True)
    valid = all(
        p.get("exit_code") == 0 and p.get("summary", {}).get("direct_passed") == 8
        for p in metadata["processes"]
    )
    pids = {p.get("summary", {}).get("process_id") for p in metadata["processes"]}
    valid = valid and len(pids) == args.processes and None not in pids
    if valid:
        metadata["status"] = (
            "PASS_8_OF_8_SINGLE_KEY_SMOKE"
            if args.processes == 1
            else "PASS_24_OF_24_DIRECT_COMPONENT"
        )
    else:
        metadata["status"] = "FAIL_OR_INVALID_PRESERVED"
    metadata["full_three_process_gate_complete"] = valid and args.processes == 3
    metadata["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    write_json(destination / "run.json", metadata)
    print(
        json.dumps(
            {"status": metadata["status"], "artifact": str(destination / "run.json")}
        ),
        flush=True,
    )
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
