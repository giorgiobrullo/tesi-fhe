#!/usr/bin/env python3
"""Future A124 sweep controller: durable evidence, explicit selection, no auto-retry.

The frozen A124 binary and scenes are unchanged. Default mode only prints a plan.
No running experiment is stopped or modified. A124/A129 processes must be absent
before --run; the check detects overlap but cannot reserve the entire host.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import shlex
import subprocess
import sys
import time
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


class RunError(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path: Path, payload: bytes) -> None:
    """An existing artifact is never replaced; interrupted writes remain visible."""
    with path.open("xb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())
    sync_directory(path.parent)


def save(path: Path, value: Any) -> None:
    write_new(path, (json.dumps(value, indent=2, allow_nan=False) + "\n").encode())


class Journal:
    def __init__(self, path: Path) -> None:
        self.path = path
        write_new(path, b"")
        self.sequence = 0

    def emit(self, kind: str, **fields: Any) -> None:
        record = {"sequence": self.sequence, "utc": utc(), "event": kind, **fields}
        with self.path.open("a") as output:
            output.write(json.dumps(record, allow_nan=False) + "\n")
            output.flush()
            os.fsync(output.fileno())
        self.sequence += 1


def dependencies() -> tuple[Any, Any, dict[str, str]]:
    pins = json.loads((HERE / "source-pins.json").read_text())
    for relative, expected in pins.items():
        if digest(ROOT / relative) != expected:
            raise RunError(f"source drift: {relative}")
    spec = importlib.util.spec_from_file_location(
        "_a129_validator", ROOT / "tmp/a128-a124-evidence-validation/validate.py"
    )
    assert spec is not None and spec.loader is not None
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    frozen, frozen_pins = validator.load_driver()
    return validator, frozen, frozen_pins


def conflicts(process_text: str, own_pid: int) -> list[dict[str, Any]]:
    found = []
    for line in process_text.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) != 3 or not fields[0].isdigit():
            continue
        pid, state, command = fields
        if int(pid) == own_pid or state.startswith("Z"):
            continue
        try:
            words = shlex.split(command)
        except ValueError:
            words = command.split()
        executable = Path(words[0]).name if words else ""
        is_python = executable.lower().startswith(("python", "pypy"))
        is_driver = (
            is_python
            and "--run" in words
            and any(
                word.endswith(
                    ("/a124_driver.py", "/a129-durable-sweep-driver/driver.py")
                )
                or word == "a124_driver.py"
                for word in words[1:]
            )
        )
        is_binary = executable == "a124_a66_thread_sweep" and "--run" in words
        if is_driver or is_binary:
            found.append({"pid": int(pid), "state": state, "command": command})
    return found


def require_no_other_sweep() -> None:
    result = subprocess.run(
        ["ps", "-axo", "pid=,state=,command="],
        text=True,
        capture_output=True,
        check=True,
        timeout=10,
    )
    found = conflicts(result.stdout, os.getpid())
    if found:
        raise RunError(f"existing sweep processes; leave untouched: {found}")


def sample_cpu(frozen: Any) -> dict[str, float]:
    sample = {"load1": frozen.host_load()[0], "cpu_busy": frozen.host_busy_fraction()}
    if not all(math.isfinite(x) and x >= 0 for x in sample.values()):
        raise RunError("nonfinite or negative guard sample")
    if sample["cpu_busy"] > 1:
        raise RunError("CPU busy fraction exceeds one")
    return sample


def wait_idle(
    journal: Journal,
    frozen: Any,
    wait_seconds: float,
    poll_seconds: float,
    cpu_limit: float,
) -> dict[str, Any]:
    start = time.monotonic()
    consecutive = 0
    last = []
    while True:
        require_no_other_sweep()
        sample = sample_cpu(frozen)
        idle = sample["cpu_busy"] <= cpu_limit
        consecutive = consecutive + 1 if idle else 0
        elapsed = time.monotonic() - start
        journal.emit(
            "guard_sample", **sample, waited_s=elapsed, consecutive=consecutive
        )
        last = (last + [sample])[-8:]
        # A sample completing after the deadline is recorded but cannot authorize launch.
        if elapsed > wait_seconds:
            raise RunError("idle deadline expired; samples preserved")
        if consecutive >= 2:
            return {
                "guard": "cpu",
                "cpu_busy_max": cpu_limit,
                "load_max": 4.0,
                "polls_required": 2,
                "samples": last,
                "waited_s": elapsed,
                "load_before_cell": sample["load1"],
                "cpu_busy_before_cell": sample["cpu_busy"],
            }
        time.sleep(min(poll_seconds, wait_seconds - elapsed))


def run_child(
    command: list[str], directory: Path, journal: Journal, timeout: float
) -> dict:
    """The pinned Rust harness launches threads, not subprocess descendants.

    On a handled interruption only this controller's child is killed/reaped.
    SIGKILL/power loss can leave an uncertain run; there is no automatic retry.
    """
    stdout_path, stderr_path = directory / "stdout.jsonl", directory / "stderr.log"
    journal.emit(
        "child_intent",
        command=command,
        stdout=str(stdout_path),
        stderr=str(stderr_path),
    )
    started = time.monotonic()
    outcome: dict[str, Any] = {}
    child = None
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        sync_directory(directory)
        try:
            # A signal between Popen and assigning the returned object would lose
            # ownership. Defer handled signals until the child handle is recorded.
            pending = []
            old_handlers = {
                s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)
            }

            def defer_signal(signum: int, _frame: Any) -> None:
                pending.append(signum)

            for signum in old_handlers:
                signal.signal(signum, defer_signal)
            try:
                child = subprocess.Popen(
                    command, stdout=stdout, stderr=stderr, start_new_session=True
                )
            finally:
                for signum, handler in old_handlers.items():
                    signal.signal(signum, handler)
            if pending:
                raise RunError(f"interrupted while starting child: {pending}")
            journal.emit("child_started", pid=child.pid)
            outcome["returncode"] = child.wait(timeout=timeout)
        except BaseException as error:
            outcome.update(error_type=type(error).__name__, error=str(error))
            raise
        finally:
            old_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM}
            )
            try:
                if child is not None and child.poll() is None:
                    child.kill()
                    child.wait()
                outcome.update(
                    pid=child.pid if child is not None else None,
                    returncode=child.returncode if child is not None else None,
                    child_wall_s=time.monotonic() - started,
                )
                for output in (stdout, stderr):
                    output.flush()
                    os.fsync(output.fileno())
                outcome.update(
                    stdout_sha256=digest(stdout_path), stderr_sha256=digest(stderr_path)
                )
                save(directory / "child-exit.json", outcome)
                journal.emit("child_exit", **outcome)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
    return outcome


def run_cell(
    directory: Path,
    size: int,
    threads: int,
    args: Any,
    validator: Any,
    frozen: Any,
    pins: dict,
    journal: Journal,
) -> Path:
    directory.mkdir()
    sync_directory(directory.parent)
    scene, _, scene_summary = frozen.scene_payload(size)
    schedule, _, schedule_summary = frozen.schedule_payload("sweep", size, threads)
    scene_path, schedule_path = directory / "scene.txt", directory / "schedule.txt"
    write_new(scene_path, scene)
    write_new(schedule_path, schedule)
    record = {
        "gallery_size": size,
        "threads": threads,
        "scene_sha256": digest(scene_path),
        "schedule_sha256": digest(schedule_path),
        "scene_summary": scene_summary,
        "schedule_summary": schedule_summary,
        "output": str(directory / "stdout.jsonl"),
    }
    save(directory / "planned.json", record)
    journal.emit(
        "cell_planned", directory=str(directory), gallery_size=size, threads=threads
    )
    idle = wait_idle(
        journal, frozen, args.wait_seconds, args.poll_seconds, args.cpu_busy_max
    )
    record["idle_guard"] = idle
    save(directory / "pre-cell.json", record)
    # Recheck the frozen executable and source immediately before launch.
    dependencies()
    require_no_other_sweep()
    command = [
        str(frozen.DEFAULT_BINARY),
        "--run",
        f"--scene={scene_path}",
        f"--schedule={schedule_path}",
        f"--expected-scene-sha256={record['scene_sha256']}",
        f"--expected-schedule-sha256={record['schedule_sha256']}",
        f"--expected-binary-sha256={args.expected_binary_sha256}",
        f"--threads={threads}",
    ]
    outcome = run_child(command, directory, journal, args.timeout)
    record["child_wall_s"] = outcome["child_wall_s"]
    if outcome["returncode"] != 0:
        raise RunError(
            f"child failed with status {outcome['returncode']}; raw output preserved"
        )
    try:
        post = sample_cpu(frozen)
        record.update(
            load_after_cell=post["load1"], cpu_busy_after_cell=post["cpu_busy"]
        )
        journal.emit("post_cell_sample", **post)
    except Exception as error:
        record["post_sample_error"] = str(error)
        journal.emit("post_cell_sample_failed", error=str(error))
    metadata_path = directory / "cell.driver.json"
    save(
        metadata_path,
        {
            "record": "driver",
            "variant": "a124_a66_thread_sweep",
            "stage": "sweep",
            "controller": "a129_durable_sweep_driver",
            "binary": str(frozen.DEFAULT_BINARY),
            "binary_sha256": args.expected_binary_sha256,
            "input_manifest_sha256": digest(frozen.INPUT_MANIFEST),
            "cells": [record],
            "outputs": [record["output"]],
        },
    )
    result = validator.validate_files(
        [Path(record["output"])], [metadata_path], frozen, pins
    )
    save(directory / "validation.json", result)
    guard_status = result["cells"][0]["guard_status"]
    journal.emit(
        "cell_validated", guard_status=guard_status, metadata=str(metadata_path)
    )
    if guard_status != "PRE_POST_GUARD_VALIDATED":
        raise RunError(f"{guard_status}; keep result, no automatic replacement")
    return metadata_path


def parse_selection(value: str) -> tuple[int, ...]:
    result = tuple(int(x) for x in value.split(","))
    if not result or len(result) != len(set(result)):
        raise argparse.ArgumentTypeError(
            "selection must be nonempty without duplicates"
        )
    return result


def interrupted(signum: int, _frame: Any) -> None:
    raise RunError(f"controller received signal {signum}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--run-directory", type=Path)
    parser.add_argument("--expected-binary-sha256")
    parser.add_argument("--ack-exclusive-window", action="store_true")
    parser.add_argument("--gallery-sizes", type=parse_selection, default=(64, 127, 128))
    parser.add_argument(
        "--threads", type=parse_selection, default=(1, 2, 4, 6, 8, 12, 16)
    )
    parser.add_argument("--wait-seconds", type=float, default=43200)
    parser.add_argument("--poll-seconds", type=float, default=30)
    parser.add_argument("--timeout", type=float, default=14400)
    parser.add_argument("--cpu-busy-max", type=float, default=0.15)
    args = parser.parse_args(argv)
    validator, frozen, pins = dependencies()
    cells = frozen.cells_for("sweep", args.gallery_sizes, args.threads)
    expected_sha = pins[str(frozen.DEFAULT_BINARY.relative_to(ROOT))]
    plan = {
        "controller": "a129_durable_sweep_driver",
        "cells": cells,
        "binary_sha256": expected_sha,
        "new_fhe_executed": False,
        "existing_experiments_modified": False,
        "automatic_retry": False,
        "within_cell_contention_excluded": False,
    }
    if not args.run:
        print(json.dumps({"status": "DRY_PLAN", **plan}, indent=2))
        return 0
    if not args.ack_exclusive_window or args.run_directory is None:
        raise RunError("--run requires --run-directory and --ack-exclusive-window")
    if args.expected_binary_sha256 != expected_sha:
        raise RunError("--run requires the exact frozen binary hash")
    for field in ("wait_seconds", "poll_seconds", "timeout", "cpu_busy_max"):
        value = getattr(args, field)
        if not math.isfinite(value) or value <= 0:
            raise RunError(f"{field} must be positive and finite")
    if args.cpu_busy_max > 0.15:
        raise RunError("CPU guard cannot be relaxed above 0.15")
    require_no_other_sweep()
    # Advisory lock excludes cooperating A129 controllers, not the old driver.
    with (HERE / ".controller.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require_no_other_sweep()
        directory = args.run_directory.resolve()
        directory.mkdir(parents=False, exist_ok=False)
        sync_directory(directory.parent)
        journal = Journal(directory / "events.jsonl")
        save(
            directory / "plan.json",
            {
                **plan,
                "created_utc": utc(),
                "controller_sha256": digest(Path(__file__)),
                "arguments": vars(args) | {"run_directory": str(directory)},
            },
        )
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        journal.emit("run_started", pid=os.getpid())
        metadata = []
        try:
            for size, threads in cells:
                path = run_cell(
                    directory / f"n{size}_t{threads}",
                    size,
                    threads,
                    args,
                    validator,
                    frozen,
                    pins,
                    journal,
                )
                metadata.append(path)
            outputs = [
                Path(json.loads(path.read_text())["outputs"][0]) for path in metadata
            ]
            validation = validator.validate_files(outputs, metadata, frozen, pins)
            save(directory / "sweep-validation.json", validation)
            terminal = {
                "status": "SELECTED_CELLS_VALIDATED",
                "new_fhe_executed": True,
                "validation": str(directory / "sweep-validation.json"),
                "final_scaling_analysis_allowed": validation[
                    "final_scaling_analysis_allowed"
                ],
            }
        except BaseException as error:
            terminal = {
                "status": "STOPPED_WITH_EVIDENCE",
                "error_type": type(error).__name__,
                "error": str(error),
                "completed_metadata": [str(p) for p in metadata],
            }
            save(directory / "terminal.json", terminal)
            journal.emit("run_stopped", **terminal)
            raise
        save(directory / "terminal.json", terminal)
        journal.emit("run_completed", **terminal)
        print(json.dumps(terminal))
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RunError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(
            json.dumps({"status": "REFUSED_OR_STOPPED", "error": str(error)}),
            file=sys.stderr,
        )
        sys.exit(2)
