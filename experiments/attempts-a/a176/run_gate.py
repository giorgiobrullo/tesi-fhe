"""One explicit private C1 stage; no build, probe, signal, retry or automatic progression."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import audit as a
import oracle as o

BINARY = a.HERE / "target-a176-only/release/a176-common-mask-c1-expansion-gate"
ACK = "A176_FIXED_THREE_KEY_C1_AUTHORIZED"


def utc():
    return datetime.now(timezone.utc).isoformat()


def timepoint(value):
    x = datetime.fromisoformat(value)
    a.need(x.tzinfo is not None and x.utcoffset().total_seconds() == 0, "UTC required")
    return x


def no_links(path):
    for p in (path, *path.parents):
        a.need(not p.is_symlink(), "symlink path")


def private(path, directory=False):
    no_links(path)
    a.need(path.is_dir() if directory else path.is_file(), "private path absent")
    a.same(path.stat().st_mode & 0o777, 0o700 if directory else 0o600, "private mode")


def save(path, value):
    no_links(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    private(path.parent, True)
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
    ) as f:
        json.dump(value, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())


def digest_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def environment(source, binary):
    return dict(
        RAYON_NUM_THREADS="1",
        A176_RUN_ACK=ACK,
        A176_SOURCE_SHA256=source,
        A176_BINARY_SHA256=binary,
    )


def command(stage):
    return [str(BINARY), "--run-authorized", "--stage", stage]


def run_path(stage):
    a.need(stage in o.STAGES, "stage")
    return a.HERE / "runs" / stage


def prior(stage):
    index = o.STAGES.index(stage)
    if not index:
        return None
    previous = o.STAGES[index - 1]
    fresh = verify(previous)
    a.same(fresh["gate_pass"], True, "preceding stage must pass")
    path = a.HERE / "artifacts" / f"{previous}-validation.json"
    private(path.parent, True)
    private(path)
    raw = path.read_bytes()
    a.same(a.parse(raw), fresh, "saved prior equals fresh replay")
    return dict(
        stage=previous,
        report_sha256=hashlib.sha256(raw).hexdigest(),
        exited_at_utc=fresh["binding"]["exited_at_utc"],
    )


def finish(prepared, pid, started, code, run):
    # Persist known termination before all fallible log/source/binary checks.
    terminal = dict(
        prepared,
        child_pid=pid,
        started_at_utc=started,
        exit_code=code,
        exited_at_utc=utc(),
    )
    save(run / "wait-complete.json", dict(terminal, status="WAIT_COMPLETED"))
    errors = []
    try:
        a.same(a.freeze_check(), prepared["freeze"], "postrun freeze")
    except Exception as e:
        errors.append("source:" + type(e).__name__)
    try:
        a.same(digest_file(BINARY), prepared["binary_sha256"], "postrun binary")
    except Exception as e:
        errors.append("binary:" + type(e).__name__)
    hashes = {}
    for name in ("stdout.jsonl", "stderr.log"):
        try:
            hashes[name] = digest_file(run / name)
        except Exception as e:
            errors.append(name + ":" + type(e).__name__)
    save(
        run / "exit.json",
        dict(
            terminal,
            status="EXITED",
            postchecks_complete=not errors,
            postcheck_errors=errors,
            files_sha256=hashes,
        ),
    )
    return code if not errors else 3


def verify(stage):
    import replay

    freeze = a.freeze_check()
    predecessor = prior(stage)
    run = run_path(stage)
    private(run, True)
    for marker in ("interrupted.json", "launch-failure.json"):
        no_links(run / marker)
        a.need(not (run / marker).exists(), "failure marker prevents acceptance")
    values = {}
    captured_hashes = {}
    for name in (
        "prepared.json",
        "child.json",
        "wait-complete.json",
        "exit.json",
        "clearance.json",
    ):
        private(run / name)
        captured = (run / name).read_bytes()
        captured_hashes[name] = hashlib.sha256(captured).hexdigest()
        values[name] = a.parse(captured)
    p = values["prepared.json"]
    child = values["child.json"]
    wait = values["wait-complete.json"]
    ex = values["exit.json"]
    cl = values["clearance.json"]
    a.fields(
        p,
        dict(
            schema="a176-root-driver-v1",
            status="PREPARED",
            run_id=stage,
            stage=stage,
            cwd=str(a.HERE),
            command=command(stage),
            binary=str(BINARY),
            freeze=freeze,
            environment=environment(freeze["source_sha256"], p["binary_sha256"]),
            prior=predecessor,
            timed_benchmark=False,
            stdout=str(run / "stdout.jsonl"),
            stderr=str(run / "stderr.log"),
        ),
    )
    a.same(digest_file(BINARY), p["binary_sha256"], "actual binary")
    a.need(type(p["driver_pid"]) is int and p["driver_pid"] > 0, "driver PID")
    a.need(
        type(child["child_pid"]) is int
        and child["child_pid"] > 0
        and child["child_pid"] != p["driver_pid"],
        "direct child PID",
    )
    a.same(
        child,
        dict(
            p,
            status="CHILD_STARTED",
            child_pid=child["child_pid"],
            started_at_utc=child["started_at_utc"],
        ),
        "prepared/child continuity",
    )
    base = dict(
        p,
        child_pid=child["child_pid"],
        started_at_utc=child["started_at_utc"],
        exit_code=ex["exit_code"],
        exited_at_utc=ex["exited_at_utc"],
    )
    a.same(wait, dict(base, status="WAIT_COMPLETED"), "wait terminal binding")
    a.same(
        ex,
        dict(
            base,
            status="EXITED",
            postchecks_complete=True,
            postcheck_errors=[],
            files_sha256=ex["files_sha256"],
        ),
        "complete exit binding",
    )
    a.same(set(ex["files_sha256"]), {"stdout.jsonl", "stderr.log"}, "exact log keys")
    a.need(
        type(ex["exit_code"]) is int and ex["exit_code"] in (0, 2),
        "registered complete exit",
    )
    a.need(
        timepoint(p["prepared_at_utc"])
        <= timepoint(child["started_at_utc"])
        <= timepoint(ex["exited_at_utc"]),
        "UTC order",
    )
    a.same(cl["matching_workloads"], [], "root clearance")
    a.same(captured_hashes["clearance.json"], p["clearance_sha256"], "clearance bytes")
    age = (
        timepoint(p["prepared_at_utc"]) - timepoint(cl["observed_at_utc"])
    ).total_seconds()
    a.need(0 <= age <= 120, "fresh root observation")
    if predecessor:
        a.need(
            timepoint(cl["observed_at_utc"]) >= timepoint(predecessor["exited_at_utc"]),
            "clearance after predecessor",
        )
    for name in ("stdout.jsonl", "stderr.log"):
        private(run / name)
    stderr = (run / "stderr.log").read_bytes()
    a.same(stderr, b"", "stderr must be empty")
    a.same(
        hashlib.sha256(stderr).hexdigest(),
        ex["files_sha256"]["stderr.log"],
        "stderr hash",
    )
    h = hashlib.sha256()

    def records():
        with (run / "stdout.jsonl").open("rb") as f:
            for line in f:
                h.update(line)
                a.need(bool(line.strip()), "blank raw line")
                yield a.parse(line)

    result = replay.inspect(
        records(),
        stage,
        freeze["source_sha256"],
        p["binary_sha256"],
        child["child_pid"],
    )
    a.same(h.hexdigest(), ex["files_sha256"]["stdout.jsonl"], "exact parsed raw hash")
    a.same(ex["exit_code"], 0 if result["gate_pass"] else 2, "exit/outcome binding")
    result["binding"] = dict(
        freeze,
        child_pid=child["child_pid"],
        started_at_utc=child["started_at_utc"],
        exited_at_utc=ex["exited_at_utc"],
        exit_code=ex["exit_code"],
        stdout_sha256=h.hexdigest(),
        envelope_sha256=captured_hashes,
        prior=predecessor,
    )
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run-authorized", action="store_true")
    p.add_argument("--stage", choices=o.STAGES, default="n4-smoke")
    p.add_argument("--binary-sha256")
    p.add_argument("--clearance-json", type=Path)
    p.add_argument("--clearance-sha256")
    args = p.parse_args()
    if not args.run_authorized:
        print(
            json.dumps(
                dict(
                    status="PLAN_ONLY_NO_CHILD",
                    plan=o.plan(args.stage),
                    requires_separate_root_clearance=True,
                )
            )
        )
        return 0
    a.need(
        args.binary_sha256 and args.clearance_json and args.clearance_sha256,
        "explicit hashes/clearance required",
    )
    freeze = a.freeze_check()
    predecessor = prior(args.stage)
    a.same(digest_file(BINARY), args.binary_sha256, "binary acknowledgement")
    private(args.clearance_json)
    raw = args.clearance_json.read_bytes()
    a.same(
        hashlib.sha256(raw).hexdigest(),
        args.clearance_sha256,
        "clearance acknowledgement",
    )
    cl = a.parse(raw)
    a.same(cl["matching_workloads"], [], "root clearance")
    now = utc()
    a.need(
        0 <= (timepoint(now) - timepoint(cl["observed_at_utc"])).total_seconds() <= 120,
        "fresh clearance",
    )
    if predecessor:
        a.need(
            timepoint(cl["observed_at_utc"]) >= timepoint(predecessor["exited_at_utc"]),
            "clearance after prior",
        )
    run = run_path(args.stage)
    no_links(run)
    run.parent.mkdir(mode=0o700, exist_ok=True)
    private(run.parent, True)
    run.mkdir(mode=0o700)
    with os.fdopen(
        os.open(run / "clearance.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
        "wb",
    ) as f:
        f.write(raw)
    prepared = dict(
        schema="a176-root-driver-v1",
        status="PREPARED",
        run_id=args.stage,
        stage=args.stage,
        prepared_at_utc=now,
        driver_pid=os.getpid(),
        command=command(args.stage),
        cwd=str(a.HERE),
        binary=str(BINARY),
        binary_sha256=args.binary_sha256,
        freeze=freeze,
        prior=predecessor,
        environment=environment(freeze["source_sha256"], args.binary_sha256),
        clearance_sha256=args.clearance_sha256,
        timed_benchmark=False,
        stdout=str(run / "stdout.jsonl"),
        stderr=str(run / "stderr.log"),
    )
    save(run / "prepared.json", prepared)
    child = None
    try:
        with (
            os.fdopen(
                os.open(
                    run / "stdout.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                ),
                "wb",
                buffering=0,
            ) as out,
            os.fdopen(
                os.open(
                    run / "stderr.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                ),
                "wb",
                buffering=0,
            ) as err,
        ):
            started = utc()
            child = subprocess.Popen(
                prepared["command"],
                cwd=a.HERE,
                env=prepared["environment"],
                stdout=out,
                stderr=err,
            )
            save(
                run / "child.json",
                dict(
                    prepared,
                    status="CHILD_STARTED",
                    child_pid=child.pid,
                    started_at_utc=started,
                ),
            )
            code = child.wait()
            return finish(prepared, child.pid, started, code, run)
    except BaseException as e:
        marker = "launch-failure.json" if child is None else "interrupted.json"
        save(
            run / marker,
            dict(
                error_type=type(e).__name__,
                child_pid=None if child is None else child.pid,
                observed_at_utc=utc(),
                no_signal_sent=True,
            ),
        )
        raise


if __name__ == "__main__":
    raise SystemExit(main())
