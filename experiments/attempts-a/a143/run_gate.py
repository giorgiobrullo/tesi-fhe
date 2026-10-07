"""One diagnostic run; exclusive owner-only artifacts, no builds/retries/signals."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess

from materialize import rendered_files, verify_sources
from replay import write_private_json

HERE = Path(__file__).resolve().parent


def live_a124(process_text):
    matches = []
    for line in process_text.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) == 3 and "a124" in parts[2].lower():
            matches.append(
                dict(pid=int(parts[0]), ppid=int(parts[1]), command=parts[2])
            )
    return matches


def private_directory(base):
    name = datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%S.%fZ")
    path = base / name
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    return path


def private_stream(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(fd, "wb")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--stage", choices=("smoke", "full"), default="smoke")
    parser.add_argument("--keysets", type=int, choices=(1, 2, 3), default=1)
    args = parser.parse_args()
    verify_sources()
    processes = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,command="],
        capture_output=True,
        text=True,
        check=True,
    )
    active = live_a124(processes.stdout)
    if active:
        print(json.dumps({"status": "REFUSE_A124_OVERLAP", "processes": active}))
        raise SystemExit(2)
    for name, source in rendered_files().items():
        assert (HERE / "candidate" / name).read_text() == source, name
    binary = (
        HERE / "candidate/target-a143-only/release/a143_nibble_coefficient_observer"
    )
    actual_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    if actual_hash != args.expected_binary_sha256:
        parser.error("binary hash mismatch")
    base = HERE / "artifacts"
    base.mkdir(mode=0o700, exist_ok=True)
    output = private_directory(base)
    command = [
        str(binary),
        "--run",
        f"--stage={args.stage}",
        f"--keysets={args.keysets}",
        f"--expected-binary-sha256={actual_hash}",
    ]
    write_private_json(
        output / "launch.json",
        dict(
            command=command,
            binary_sha256=actual_hash,
            utc=datetime.now(timezone.utc).isoformat(),
            key_sensitive_client_local_only=True,
            preflight="No a124 command observed; point-in-time check, not host reservation",
            stage=args.stage,
            keysets=args.keysets,
        ),
    )
    with (
        private_stream(output / "stdout.jsonl") as stdout,
        private_stream(output / "stderr.log") as stderr,
    ):
        child = subprocess.Popen(
            command, cwd=HERE / "candidate", stdout=stdout, stderr=stderr
        )
        write_private_json(
            output / "child_started.json",
            dict(pid=child.pid, utc=datetime.now(timezone.utc).isoformat()),
        )
        print(
            json.dumps(
                {"status": "STARTED", "pid": child.pid, "artifacts": str(output)}
            ),
            flush=True,
        )
        code = child.wait()
    write_private_json(
        output / "exit.json",
        dict(
            exit_code=code,
            utc=datetime.now(timezone.utc).isoformat(),
            stdout_sha256=hashlib.sha256(
                (output / "stdout.jsonl").read_bytes()
            ).hexdigest(),
            stderr_sha256=hashlib.sha256(
                (output / "stderr.log").read_bytes()
            ).hexdigest(),
        ),
    )
    print(json.dumps({"status": "EXITED", "exit_code": code, "artifacts": str(output)}))
    raise SystemExit(code)


if __name__ == "__main__":
    main()
