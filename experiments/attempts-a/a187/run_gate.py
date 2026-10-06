"""One fixed A187 first fixture, with saved root clearance and terminal checkpoint."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = HERE
BINARY = SOURCE / "target-a187-only/release/a149_padding_coefficient_gate"
RUN = HERE / "runs/first-precision"


def environment():
    return {
        "RAYON_NUM_THREADS": "1",
        "A187_RUN_ACK": "A187_FIRST_N4_AUTHORIZED",
        "A187_SOURCE_SHA256": (HERE / "SOURCE_DIGEST.txt").read_text().strip(),
    }


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(value, reason):
    if not value:
        raise ValueError(reason)


def private(path, directory=False):
    for part in [path, *path.parents]:
        require(not part.is_symlink(), "symlink ancestry")
    require(path.is_dir() if directory else path.is_file(), "file type")
    require(
        path.stat().st_mode & 0o777 == (0o700 if directory else 0o600),
        "private permissions",
    )
    require(path.stat().st_uid == os.getuid(), "private file owner")
    if not directory:
        require(path.stat().st_nlink == 1, "private hardlinks refused")


def save(path, value):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def source_check():
    import replay

    replay.source_check()
    origins = json.loads((HERE / "SOURCE_ORIGINS.json").read_text())
    for name, expected in origins["files"].items():
        require(digest(Path(name)) == expected, "frozen origin " + name)
    for name, expected in json.loads((HERE / "SOURCE_PINS.json").read_text())[
        "files"
    ].items():
        require(digest(Path(name)) == expected, "primary API " + name)
    return digest(HERE / "MANIFEST.json")


def finish(run, started, code, handles=(), check_source=source_check, hash_file=digest):
    terminal = dict(started, exit_code=code, exited_at_utc=now())
    # Known direct-child termination is saved before log flush/hash/source checks.
    save(run / "wait-complete.json", terminal)
    errors = []
    for name, handle in handles:
        try:
            handle.flush()
            os.fsync(handle.fileno())
        except Exception as error:
            errors.append(dict(check=name + "_fsync", error=repr(error)))
    for name, operation in {
        "source_unchanged": lambda: check_source()
        == started["launcher_manifest_sha256"],
        "binary_unchanged": lambda: hash_file(BINARY) == started["binary_sha256"],
        "stdout_sha256": lambda: hash_file(run / "stdout.jsonl"),
        "stderr_sha256": lambda: hash_file(run / "stderr.log"),
    }.items():
        try:
            terminal[name] = operation()
            require(terminal[name] is not False, name + " mismatch")
        except Exception as error:
            terminal[name] = None
            errors.append(dict(check=name, error=repr(error)))
    terminal.update(postcheck_errors=errors, postchecks_complete=not errors)
    save(run / "exit.json", terminal)
    return terminal


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--binary-sha256")
    parser.add_argument("--artifact-sha256")
    parser.add_argument("--clearance", type=Path)
    parser.add_argument("--clearance-sha256")
    args = parser.parse_args()
    if not args.run:
        print(
            json.dumps(
                dict(
                    status="PLAN_ONLY_NO_CHILD",
                    suite="first-precision",
                    keysets=1,
                    fixture=[255, 256, 254, 4095],
                    arms=3,
                    coefficient_events=205,
                    raw_records=211,
                    actual_fhe=False,
                    retry=False,
                    automatic_expansion=False,
                )
            )
        )
        return 0
    require(
        args.binary_sha256
        and args.artifact_sha256
        and args.clearance
        and args.clearance_sha256,
        "explicit source/binary clearance",
    )
    binding = source_check()
    require(binding == args.artifact_sha256, "explicit artifact hash")
    require(digest(BINARY) == args.binary_sha256, "actual binary hash")
    private(args.clearance)
    clearance_bytes = args.clearance.read_bytes()
    require(
        hashlib.sha256(clearance_bytes).hexdigest() == args.clearance_sha256,
        "clearance hash",
    )
    from replay import parse

    clearance = parse(clearance_bytes)
    observed = datetime.fromisoformat(clearance["observed_at_utc"])
    require(
        observed.utcoffset() is not None and observed.utcoffset().total_seconds() == 0,
        "UTC clearance",
    )
    require(clearance["matching_workloads"] == [], "root workload clear")
    require(
        0 <= (datetime.now(timezone.utc) - observed).total_seconds() <= 120,
        "fresh clearance",
    )
    os.umask(0o077)
    RUN.parent.mkdir(mode=0o700, exist_ok=True)
    private(RUN.parent, True)
    RUN.mkdir(mode=0o700, exist_ok=False)
    fd = os.open(RUN / "preflight.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(clearance_bytes)
        handle.flush()
        os.fsync(handle.fileno())
    command = [str(BINARY), "--run", "--expected-binary-sha256=" + args.binary_sha256]
    prepared = dict(
        schema="a187.a187.first.v1",
        driver_pid=os.getpid(),
        command=command,
        cwd=str(SOURCE),
        environment=environment(),
        binary_sha256=args.binary_sha256,
        source_manifest_sha256=digest(HERE / "SOURCE_MANIFEST.json"),
        launcher_manifest_sha256=binding,
        prepared_at_utc=now(),
        clearance_sha256=args.clearance_sha256,
        timing_allowed=False,
    )
    save(RUN / "prepared.json", prepared)
    with (RUN / "stdout.jsonl").open("x") as out, (RUN / "stderr.log").open("x") as err:
        try:
            child = subprocess.Popen(
                command,
                cwd=SOURCE,
                env=environment(),
                stdout=out,
                stderr=err,
                start_new_session=True,
            )
        except Exception as error:
            save(
                RUN / "launch-failure.json",
                dict(status="NO_CHILD", error=repr(error), observed_at_utc=now()),
            )
            raise
        started = dict(prepared, child_pid=child.pid, started_at_utc=now())
        try:
            save(RUN / "child.json", started)
            print(
                json.dumps({k: started[k] for k in ("child_pid", "started_at_utc")}),
                flush=True,
            )
            code = child.wait()
        except BaseException as error:
            save(
                RUN / "interrupted.json",
                dict(started, error=repr(error), child_state="UNKNOWN_NO_SIGNAL_SENT"),
            )
            raise
        terminal = finish(RUN, started, code, (("stdout", out), ("stderr", err)))
    print(
        json.dumps(
            {
                k: terminal[k]
                for k in (
                    "child_pid",
                    "exit_code",
                    "exited_at_utc",
                    "postchecks_complete",
                )
            }
        ),
        flush=True,
    )
    return code or (0 if terminal["postchecks_complete"] else 2)


if __name__ == "__main__":
    raise SystemExit(main())
