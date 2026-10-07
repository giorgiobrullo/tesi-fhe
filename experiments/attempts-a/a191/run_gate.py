"""One fixed A191 first fixture, with saved root clearance and terminal checkpoint."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = HERE / "candidate"
BINARY = HERE / "target-a191-only/release/a191_pfks_actual_comparator"
RUN = HERE / "runs/first-composition"


def environment():
    return {
        "RAYON_NUM_THREADS": "1",
        "A191_RUN_ACK": "A191_FIRST_COMPARATOR_AUTHORIZED",
        "A191_SOURCE_SHA256": (HERE / "SOURCE_DIGEST.txt").read_text().strip(),
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
    sync_directory(path.parent)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def source_check():
    import replay

    replay.source_check()
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
                    suite="first-composition",
                    keysets=1,
                    fixture_index=7,
                    left=[0, 1, 0, 126],
                    right=[0, 0, 15, 127],
                    selector_arms=3,
                    comparator_stages=4,
                    raw_records=48,
                    pfks=20,
                    ks=10,
                    br=10,
                    samples=16,
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
    require(
        BINARY.is_file() and not any(p.is_symlink() for p in [BINARY, *BINARY.parents]),
        "regular binary without symlink ancestry",
    )
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
    require(
        shutil.disk_usage(HERE).free >= 2 * (1 << 30), "two GiB free disk prerequisite"
    )
    RUN.mkdir(mode=0o700, exist_ok=False)
    sync_directory(RUN.parent)
    fd = os.open(RUN / "preflight.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(clearance_bytes)
        handle.flush()
        os.fsync(handle.fileno())
    sync_directory(RUN)
    command = [str(BINARY), "--run", "--expected-binary-sha256=" + args.binary_sha256]
    prepared = dict(
        schema="a191.first_composition.v1",
        run_directory=str(RUN),
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
    return (code if code in (0, 1) else 2) if terminal["postchecks_complete"] else 2


if __name__ == "__main__":
    try:
        result = main()
    except Exception as error:
        print(
            json.dumps(
                dict(status="INVALID_OR_INCOMPLETE_A191_LAUNCH", error=str(error))
            ),
            flush=True,
        )
        result = 2
    raise SystemExit(result)
