"""Private local source/terminal evidence helpers; no native API/process probes."""

import hashlib
import json
import os
from pathlib import Path
from datetime import datetime, timezone
import replay as r

HERE = Path(__file__).resolve().parent
BINARY = HERE / "target-a190-only/release/a190-common-mask-persistent-core"
RUN = HERE / "runs/first-n4"
ACK = "A190_FIXED_N4_PERSISTENT_AUTHORIZED"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def utc(x):
    r.need(type(x) is str, "UTC string")
    v = datetime.fromisoformat(x)
    r.need(v.tzinfo is not None and v.utcoffset().total_seconds() == 0, "aware UTC")
    return v


def no_links(path):
    r.need(path.is_absolute(), "absolute path")
    for x in (path, *path.parents):
        r.need(not x.is_symlink(), "symlink ancestry")


def private(path, directory=False):
    no_links(path)
    info = path.stat()
    r.need(path.is_dir() if directory else path.is_file(), "private type")
    r.same(info.st_mode & 0o777, 0o700 if directory else 0o600)
    r.same(info.st_uid, os.getuid())
    if not directory:
        r.same(info.st_nlink, 1)


def read(path):
    private(path.parent, True)
    private(path)
    return path.read_bytes()


def parse(raw):
    return json.loads(
        raw,
        object_pairs_hook=r.pairs,
        parse_constant=lambda x: (_ for _ in ()).throw(ValueError("nonfinite JSON")),
    )


def save(path, value):
    no_links(path)
    private(path.parent, True)
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w"
    ) as out:
        json.dump(value, out, indent=2)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def source():
    raw = (HERE / "SOURCE_MANIFEST.json").read_bytes()
    identity = sha(raw)
    r.same((HERE / "SOURCE_DIGEST.txt").read_text(), identity + "\n")
    m = parse(raw)
    seen = set()
    for row in m["files"]:
        r.same(set(row), {"path", "sha256"})
        name = row["path"]
        r.need(
            name not in seen
            and not Path(name).is_absolute()
            and ".." not in Path(name).parts,
            "source leaf",
        )
        seen.add(name)
        path = HERE / name
        no_links(path)
        r.same(sha(path.read_bytes()), row["sha256"], "source hash")
    pins = parse((HERE / "SOURCE_PINS.json").read_bytes())
    for row in pins["inputs"]:
        r.same(sha(Path(row["path"]).read_bytes()), row["sha256"], "upstream pin")
    return identity


def environment(source_id, binary):
    return dict(
        RAYON_NUM_THREADS="1",
        A190_RUN_ACK=ACK,
        A190_SOURCE_SHA256=source_id,
        A190_BINARY_SHA256=binary,
    )


def command():
    return [str(BINARY), "--run-first"]


def clearance(path, source_id, binary):
    raw = read(path)
    value = parse(raw)
    r.same(
        set(value),
        {
            "schema",
            "observed_at_utc",
            "active_workload_count",
            "exclusive_root_authorization",
            "source_sha256",
            "binary_sha256",
            "process_snapshot_path",
            "process_snapshot_sha256",
        },
    )
    r.same(value["schema"], "a190.root-clearance.v1")
    r.same(value["active_workload_count"], 0)
    r.same(value["exclusive_root_authorization"], True)
    r.same(value["source_sha256"], source_id)
    r.same(value["binary_sha256"], binary)
    age = (datetime.now(timezone.utc) - utc(value["observed_at_utc"])).total_seconds()
    r.need(0 <= age <= 120, "fresh root clearance")
    snapshot = Path(value["process_snapshot_path"])
    no_links(snapshot)
    data = snapshot.read_bytes()
    r.same(sha(data), value["process_snapshot_sha256"])
    return value, raw


def verify_run():
    source_id = source()
    no_links(BINARY)
    binary = sha(BINARY.read_bytes())
    private(RUN, True)
    for name in ("interrupted.json", "validation-rejected.json"):
        p = RUN / name
        r.need(not p.is_symlink() and not p.exists(), "interrupted/rejected marker")
    names = (
        "prepared.json",
        "child.json",
        "wait-complete.json",
        "exit.json",
        "stdout.jsonl",
        "stderr.log",
        "clearance.json",
    )
    blobs = {n: read(RUN / n) for n in names}
    p, c, w, e = (parse(blobs[n]) for n in names[:4])
    clear = parse(blobs["clearance.json"])
    r.same(
        set(p),
        {
            "schema",
            "source",
            "binary",
            "command",
            "environment",
            "driver_pid",
            "prepared_utc",
            "clearance_sha256",
            "run_path",
            "cwd",
            "os_membership_attested",
        },
    )
    r.same(p["schema"], "a190.prepared.v1")
    r.same(p["source"], source_id)
    r.same(p["binary"], binary)
    r.same(p["command"], command())
    r.same(p["cwd"], str(HERE))
    r.same(p["environment"], environment(source_id, binary))
    r.same(p["run_path"], str(RUN))
    r.same(p["os_membership_attested"], False)
    r.integer(p["driver_pid"])
    r.need(p["driver_pid"] > 0, "driver pid")
    r.same(p["clearance_sha256"], sha(blobs["clearance.json"]))
    r.same(
        set(clear),
        {
            "schema",
            "observed_at_utc",
            "active_workload_count",
            "exclusive_root_authorization",
            "source_sha256",
            "binary_sha256",
            "process_snapshot_path",
            "process_snapshot_sha256",
        },
    )
    r.same(clear["schema"], "a190.root-clearance.v1")
    r.same(clear["source_sha256"], source_id)
    r.same(clear["binary_sha256"], binary)
    r.same(clear["active_workload_count"], 0)
    r.same(clear["exclusive_root_authorization"], True)
    snapshot = Path(clear["process_snapshot_path"])
    no_links(snapshot)
    r.same(sha(snapshot.read_bytes()), clear["process_snapshot_sha256"])
    r.same(set(c), {"schema", "source", "binary", "pid", "started_utc"})
    r.same(c["schema"], "a190.child.v1")
    r.same(c["source"], source_id)
    r.same(c["binary"], binary)
    r.integer(c["pid"])
    r.need(c["pid"] > 0 and c["pid"] != p["driver_pid"], "actual child identity")
    r.same(set(w), {"schema", "source", "binary", "pid", "exit_code", "reaped_utc"})
    r.same(w["schema"], "a190.wait-complete.v1")
    r.same(w["source"], source_id)
    r.same(w["binary"], binary)
    r.same(w["pid"], c["pid"])
    r.need(
        type(w["exit_code"]) is int and w["exit_code"] in (0, 1),
        "native expected terminal exit",
    )
    r.same(
        set(e),
        {
            "schema",
            "source",
            "binary",
            "pid",
            "exit_code",
            "terminal_utc",
            "source_unchanged",
            "binary_unchanged",
            "errors",
        },
    )
    r.same(e["schema"], "a190.exit.v1")
    r.same(e["source"], source_id)
    r.same(e["binary"], binary)
    r.same(e["pid"], c["pid"])
    r.same(e["exit_code"], w["exit_code"])
    r.same(e["source_unchanged"], True)
    r.same(e["binary_unchanged"], True)
    r.same(e["errors"], [])
    stamps = [
        utc(clear["observed_at_utc"]),
        utc(p["prepared_utc"]),
        utc(c["started_utc"]),
        utc(w["reaped_utc"]),
        utc(e["terminal_utc"]),
    ]
    r.need(
        stamps == sorted(stamps)
        and 0 <= (stamps[1] - stamps[0]).total_seconds() <= 120
        and stamps[-1] <= datetime.now(timezone.utc),
        "terminal chronology",
    )
    r.same(blobs["stderr.log"], b"")
    result = r.verify(r.parse(blobs["stdout.jsonl"]), source_id, binary, c["pid"])
    r.same(w["exit_code"], 0 if result["native_gate_pass"] else 1)
    return dict(
        result,
        binding=dict(
            source=source_id,
            binary=binary,
            child_pid=c["pid"],
            exit_code=w["exit_code"],
            file_sha256={k: sha(v) for k, v in blobs.items()},
        ),
        os_membership_attested=False,
    )
