#!/usr/bin/env python3
"""Run the prebuilt A127 binary sequentially and preserve raw records after each process."""
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

HERE = Path(__file__).resolve().parent


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".partial")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def validate_process(path: Path) -> dict:
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    summaries = [r for r in rows if r.get("record") == "summary"]
    if len(summaries) != 1:
        raise ValueError(f"expected exactly one summary: {path}")
    cases = [r for r in rows if r.get("record") == "case"]
    lanes = [r for r in rows if r.get("record") == "lane"]
    if len(cases) != 8 or len(lanes) != 32:
        raise ValueError(f"incomplete fixed fixture schedule: {path}")
    if {r["fixture_index"] for r in cases} != set(range(8)):
        raise ValueError("duplicated or missing fixture")
    for case in cases:
        fixture_lanes = [r for r in lanes if r["fixture"] == case["fixture"]]
        if sorted(r["lane"] for r in fixture_lanes) != [0, 1, 2, 3]:
            raise ValueError("duplicated or missing lane")
        if case["direct_class"] == "pass":
            if not all(case[k] for k in ["support_ok", "prerequisites_ok", "direct_counters_pass"]):
                raise ValueError("PASS contradicts support/prerequisite/counter")
            for row in fixture_lanes:
                for arm in ["direct", "scalar"]:
                    if not all(row[arm][k] for k in ["decode_pass", "half_slot_pass", "nontrivial"]):
                        raise ValueError("PASS contradicts consumed output")
                    if row[arm]["decoded"] != row["expected"]:
                        raise ValueError("PASS contradicts expected decode")
    summary = summaries[0]
    if summary["direct_passed"] != sum(c["direct_class"] == "pass" for c in cases):
        raise ValueError("summary contradicts cases")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--binary", type=Path, default=HERE / "target-a127-only/release/a127_direct_window_pfks_runtime")
    parser.add_argument("--expected-binary-sha256")
    args = parser.parse_args()
    static = audit()
    if not args.run:
        print(json.dumps({"status":"PLAN_NO_FHE", "static":static, "processes":3}, indent=2))
        return 0
    if not args.expected_binary_sha256 or sha256(args.binary) != args.expected_binary_sha256:
        parser.error("missing/mismatched --expected-binary-sha256")
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H%M%S.%fZ")
    destination = HERE / "artifacts" / timestamp
    destination.mkdir(parents=True, exist_ok=False)
    metadata = {
        "artifact":"A127", "status":"RUNNING", "binary":str(args.binary.resolve()),
        "binary_sha256":args.expected_binary_sha256, "preregistration_sha256":static["preregistration_sha256"],
        "started_utc":timestamp, "runner_pid":os.getpid(), "processes":[], "source_static":static,
        "source_sha256":sha256(HERE / "src/main.rs"), "timing_claim":"diagnostic only; not a paired speedup benchmark",
    }
    write_json(destination / "run.json", metadata)
    for offset in range(3):
        stdout = destination / f"process-{offset}.jsonl"
        stderr = destination / f"process-{offset}.stderr.txt"
        environment = dict(os.environ, RAYON_NUM_THREADS="1", A127_ORDER_OFFSET=str(offset),
            A127_RUN_FHE="I_ACKNOWLEDGE_A127_DIRECT_WINDOW_PFKS_FHE",
            A127_PREREGISTRATION_SHA256=static["preregistration_sha256"])
        record = {"order_offset":offset, "status":"RUNNING", "load_before":list(os.getloadavg()),
            "stdout":str(stdout), "stderr":str(stderr)}
        metadata["processes"].append(record)
        with stdout.open("x") as output, stderr.open("x") as error:
            process = subprocess.Popen(["/usr/bin/time", "-l", str(args.binary.resolve()), "--run-authorized", "--pfks", "24x1"],
                env=environment, stdout=output, stderr=error)
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
    valid = all(p.get("exit_code") == 0 and p.get("summary",{}).get("direct_passed") == 8 for p in metadata["processes"])
    pids = {p.get("summary",{}).get("process_id") for p in metadata["processes"]}
    valid = valid and len(pids) == 3 and None not in pids
    metadata["status"] = "PASS_24_OF_24_DIRECT_COMPONENT" if valid else "FAIL_OR_INVALID_PRESERVED"
    metadata["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    write_json(destination / "run.json", metadata)
    print(json.dumps({"status":metadata["status"], "artifact":str(destination / "run.json")}), flush=True)
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
