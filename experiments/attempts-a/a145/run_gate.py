"""Local diagnostic launcher: preserve outputs and refuse visible sweep overlap."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

HERE = Path(__file__).resolve().parent


def now():
    return datetime.now(timezone.utc).isoformat()


def blockers():
    output = subprocess.check_output(["ps", "-axo", "pid=,ppid=,args="], text=True)
    found = []
    for line in output.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) != 3 or int(parts[0]) in (os.getpid(), os.getppid()):
            continue
        try:
            words = shlex.split(parts[2])
        except ValueError:
            continue
        if any(
            Path(w).name in ("a124_driver.py", "a124_a66_thread_sweep")
            or "a129-durable-sweep-driver/" in w
            for w in words
        ):
            found.append(line.strip())
    return found


def write_record(path, data):
    with path.open("x") as output:
        json.dump(data, output, indent=2)
        output.write("\n")
    path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--keysets", type=int, choices=(1, 2, 3), default=1)
    parser.add_argument(
        "--binary",
        type=Path,
        default=HERE / "target-a145-only/release/a145_padding_flag_ingress_gate",
    )
    parser.add_argument("--binary-sha256")
    parser.add_argument("--run-id")
    args = parser.parse_args()
    live = blockers()
    if not args.run:
        print(
            json.dumps(
                dict(
                    status="PLAN_ONLY",
                    observed_at_utc=now(),
                    blockers=live,
                    suite="full8" if args.full else "single2",
                    keys=args.keysets,
                    extra_resource_clearance_required=True,
                    fhe_started=False,
                )
            )
        )
        return
    if live:
        raise SystemExit("Visible protected sweep workload: " + json.dumps(live))
    if not args.run_id or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,64}", args.run_id
    ):
        parser.error("a fresh --run-id is required")
    if not args.binary_sha256 or not re.fullmatch("[0-9a-f]{64}", args.binary_sha256):
        parser.error("independently recorded --binary-sha256 is required")
    binary = args.binary.resolve(strict=True)
    if (
        binary
        != (HERE / "target-a145-only/release/a145_padding_flag_ingress_gate").resolve()
    ):
        parser.error("requires this artifact's isolated release binary")
    if hashlib.sha256(binary.read_bytes()).hexdigest() != args.binary_sha256:
        parser.error("binary hash mismatch")
    manifest = json.loads((HERE / "MANIFEST.json").read_text())
    for path, expected in manifest["files"].items():
        if hashlib.sha256((HERE / path).read_bytes()).hexdigest() != expected:
            raise SystemExit("source/artifact drift: " + path)
    directory = HERE / "runs" / args.run_id
    directory.parent.mkdir(exist_ok=True, mode=0o700)
    directory.mkdir(mode=0o700)
    command = [
        str(binary),
        "--run",
        f"--keysets={args.keysets}",
        "--expected-binary-sha256=" + args.binary_sha256,
    ]
    if args.full:
        command.append("--full")
    write_record(
        directory / "prepared.json",
        dict(
            command=command,
            utc=now(),
            binary_sha256=args.binary_sha256,
            blockers_observed=live,
            manifest_sha256=hashlib.sha256(
                (HERE / "MANIFEST.json").read_bytes()
            ).hexdigest(),
            timing_allowed=False,
            preflight_is_not_exclusive_reservation=True,
        ),
    )
    child = None
    try:
        with (
            (directory / "stdout.jsonl").open("x") as out,
            (directory / "stderr.txt").open("x") as err,
        ):
            (directory / "stdout.jsonl").chmod(0o600)
            (directory / "stderr.txt").chmod(0o600)
            child = subprocess.Popen(command, cwd=HERE, stdout=out, stderr=err)
            write_record(directory / "started.json", dict(pid=child.pid, utc=now()))
            code = child.wait()
        write_record(
            directory / "terminal.json",
            dict(
                returncode=code,
                utc=now(),
                status="CHILD_EXITED",
                results_independently_validated=False,
            ),
        )
    except BaseException as error:
        write_record(
            directory / "interrupted.json",
            dict(
                utc=now(),
                error=repr(error),
                child_pid=None if child is None else child.pid,
                child_returncode=None if child is None else child.poll(),
                next_action="Inspect actual child liveness; no automatic signal or restart",
            ),
        )
        raise
    raise SystemExit(code)


if __name__ == "__main__":
    main()
