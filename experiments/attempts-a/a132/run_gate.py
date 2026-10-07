#!/usr/bin/env python3
"""Future exclusive-window launcher. Never builds, signals, or manages another experiment."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import static_audit

HERE = Path(__file__).resolve().parent
ACK = "A132_EXCLUSIVE_NOISY_DIAGNOSTIC_AUTHORIZED"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-authorized", action="store_true")
    parser.add_argument("--suite", choices=["witness", "smoke", "n4-exhaustive", "n127"], default="witness")
    parser.add_argument("--key-id")
    parser.add_argument("--binary-sha256")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.run_authorized:
        print(json.dumps({"status": "PLAN_ONLY_NO_KEYGEN", "suite": args.suite,
                          "fresh_keys_per_process": 1, "smallest": "witness N4",
                          "exclusive_window_and_explicit_authorization_required": True}))
        return 0
    if os.environ.get("A132_RUN_ACK") != ACK:
        parser.error("missing A132_RUN_ACK; the token itself does not confer permission")
    if not args.key_id or not args.binary_sha256 or not args.output:
        parser.error("--key-id, --binary-sha256 and --output are required")
    static_audit.verify_pins()
    static_audit.verify_digest()
    binary = HERE / "target-a132-only/release/a132-common-mask-round-gate"
    binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    if binary_sha != args.binary_sha256:
        parser.error("binary SHA-256 differs from acknowledged build")
    output = args.output.resolve()
    if output.parent != HERE or output.suffix != ".jsonl":
        parser.error("output must be a new .jsonl directly inside the isolated A132 directory")
    metadata = output.with_suffix(".driver.json")
    child_metadata = output.with_suffix(".child.json")
    exit_metadata = output.with_suffix(".exit.json")
    stderr_path = output.with_suffix(".stderr.log")
    if any(path.exists() for path in (output, metadata, child_metadata, exit_metadata, stderr_path)):
        parser.error("refusing to overwrite existing evidence")
    digest = (HERE / "SOURCE_DIGEST.txt").read_text().strip()
    env = dict(os.environ, RAYON_NUM_THREADS="1", A132_SOURCE_SHA256=digest)
    command = [str(binary), "--run-authorized", "--suite", args.suite, "--key-id", args.key_id]
    record = {"schema": "a132-driver-v1", "status": "LAUNCH_PREPARED", "command": command,
              "binary_sha256": binary_sha, "source_sha256": digest,
              "fresh_keys_per_process": 1, "rayon_threads": 1,
              "timed_benchmark": False, "scheduler_manipulated": False,
              "prepared_at_utc": utc_now(), "driver_pid": os.getpid(),
              "stdout_path": str(output), "stderr_path": str(stderr_path)}
    with metadata.open("x") as out:
        json.dump(record, out, indent=2)
        out.write("\n")
    with output.open("x") as out, stderr_path.open("x") as err, child_metadata.open("x") as child_out, exit_metadata.open("x") as exit_out:
        started_at = utc_now()
        child = subprocess.Popen(command, cwd=HERE, env=env, stdout=out, stderr=err)
        json.dump(dict(record, status="CHILD_STARTED", child_pid=child.pid, started_at_utc=started_at), child_out, indent=2)
        child_out.write("\n")
        child_out.flush()
        returncode = child.wait()
        json.dump(dict(record, status="COMPLETE" if returncode == 0 else "FAILED",
                       child_pid=child.pid, started_at_utc=started_at, exited_at_utc=utc_now(),
                       exit_code=returncode), exit_out, indent=2)
        exit_out.write("\n")
    return returncode


if __name__ == "__main__":
    sys.exit(main())
