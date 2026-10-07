"""Private one-child launcher; does not establish isolation, build, retry, inspect or signal processes."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import audit

HERE = Path(__file__).resolve().parent
ACK = "A155_EXCLUSIVE_NOISY_DIAGNOSTIC_AUTHORIZED"


def private_file(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w")


def utc():
    return datetime.now(timezone.utc).isoformat()


def record(path, value):
    with private_file(path) as f:
        json.dump(value, f, indent=2)
        f.write("\n")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run-authorized", action="store_true")
    p.add_argument("--suite", choices=["stock", "witness"], default="witness")
    p.add_argument("--run-id")
    p.add_argument("--key-id")
    p.add_argument("--binary-sha256")
    args = p.parse_args()
    if not args.run_authorized:
        print(
            json.dumps(
                dict(
                    status="PLAN_ONLY_NO_CHILD_NO_PROCESS_PROBES",
                    suite=args.suite,
                    fresh_keys=1,
                    first_gate="witness: original A150 graph plus finite egress margin controls",
                    egress_margin_probes=16 if args.suite == "witness" else 0,
                    additional_ordinary_pbs=16 if args.suite == "witness" else 0,
                    additional_public_body_additions=16 if args.suite == "witness" else 0,
                    additional_key_switches=0,
                    original_a150_outcome_preserved=True,
                    isolation_must_be_established_by_root=True,
                )
            )
        )
        return 0
    if os.environ.get("A155_RUN_ACK") != ACK:
        p.error("missing A155_RUN_ACK; a token alone does not grant workload clearance")
    if not args.run_id or not re.fullmatch(
        r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}", args.run_id
    ):
        p.error("safe unique --run-id required")
    if not args.key_id or not args.binary_sha256:
        p.error("--key-id and --binary-sha256 required")
    manifest = audit.verify_freeze()
    binary = HERE / "target-a155-only/release/a155-common-mask-egress-margin-control"
    actual = audit.sha(binary)
    if actual != args.binary_sha256:
        p.error("actual binary SHA256 differs")
    source = audit.digest()
    runs = HERE / "runs"
    runs.mkdir(mode=0o700, exist_ok=True)
    output = runs / args.run_id
    output.mkdir(mode=0o700)
    command = [
        str(binary),
        "--run-authorized",
        "--suite",
        args.suite,
        "--key-id",
        args.key_id,
    ]
    env = dict(
        os.environ,
        RAYON_NUM_THREADS="1",
        A155_SOURCE_SHA256=source,
        A155_BINARY_SHA256=actual,
    )
    record(
        output / "prepared.json",
        dict(
            status="PREPARED",
            utc=utc(),
            command=command,
            suite=args.suite,
            key_id=args.key_id,
            binary_sha256=actual,
            source_sha256=source,
            manifest_sha256=manifest,
            workload_reservation=False,
            root_clearance_required=True,
            client_local_key_sensitive=True,
        ),
    )
    child = None
    try:
        with (
            private_file(output / "stdout.jsonl") as out,
            private_file(output / "stderr.log") as err,
        ):
            child = subprocess.Popen(command, cwd=HERE, env=env, stdout=out, stderr=err)
            record(
                output / "started.json",
                dict(status="STARTED", child_pid=child.pid, utc=utc()),
            )
            rc = child.wait()
            record(
                output / "exit.json",
                dict(
                    status="EXITED",
                    child_pid=child.pid,
                    returncode=rc,
                    utc=utc(),
                    correctness_independently_validated=False,
                ),
            )
            return rc
    except BaseException as exc:
        record(
            output / "interrupted.json",
            dict(
                status="INTERRUPTED",
                utc=utc(),
                error=repr(exc),
                child_pid=None if child is None else child.pid,
                child_may_still_be_running=child is not None,
                automatic_restart=False,
                signals_sent=False,
            ),
        )
        raise


if __name__ == "__main__":
    sys.exit(main())
