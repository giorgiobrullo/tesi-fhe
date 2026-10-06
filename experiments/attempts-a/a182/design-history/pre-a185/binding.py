"""A182 private source/I/O bindings for the frozen A184 implementation of A175."""

import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
if not __debug__:
    raise RuntimeError(
        "A182 requires assertions enabled, including imported frozen replay"
    )
HERE = Path(__file__).resolve().parent
BASE = HERE.parent / "a184-a175-json-recursion-successor"
SCHEMA = "a182-a184-direct-child-envelope-v1"
SOURCE_ID = "3b1a7c4f4cc0452debd1c5e1a32ec43b53dc75d004e09179f56fbeb2a45d9064"
ARTIFACT_HASH = "bb6ea5e0a572afcb948063a6a3f40ed7870b9be21ab47c95d15ac5f744f3b65a"
REPLAY_HASH = "26695177af7b9832d69b814d50152f40661a2d342558173115979ce0ae003ae6"
MODEL_HASH = "477af56b6bab7703f863f947aa9419514a7d3127fd87f31c80d38b89e70de3cb"
RUN_ID = "first-key1"
BINARY_REL = (
    "candidate/target-a184-json-recursion-only/release/a125_low_extraction_gate"
)
ENV = {
    "RAYON_NUM_THREADS": "1",
    "A184_RUN_ACK": "A184_ACTUAL_CONSUMER_AUTHORIZED",
    "A184_SOURCE_SHA256": SOURCE_ID,
}
MIN_FREE_BYTES = 2**31
NEGATIVE_STDERR = b"A175_ERROR: A175 complete first-key gate failed; preserve every producer/consumer outcome without retry\n"
NAMES = (
    "preflight.json",
    "prepared.json",
    "child.json",
    "wait-complete.json",
    "exit.json",
    "stdout.jsonl",
    "stderr.log",
)


def need(value, reason):
    if not value:
        raise ValueError(reason)


def eq(actual, expected, reason):
    need(type(actual) is type(expected), reason + " type")
    if isinstance(expected, dict):
        need(actual.keys() == expected.keys(), reason + " keys")
        for key in expected:
            eq(actual[key], expected[key], reason + "/" + str(key))
    elif isinstance(expected, (list, tuple)):
        need(len(actual) == len(expected), reason + " length")
        for index, (left, right) in enumerate(zip(actual, expected)):
            eq(left, right, reason + "/" + str(index))
    else:
        need(actual == expected, reason)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            result.update(chunk)
    return result.hexdigest()


def bytes_hash(data):
    return hashlib.sha256(data).hexdigest()


def hexhash(value):
    need(
        type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "canonical SHA256"
    )
    return value


def no_symlinks(path):
    path = Path(path).absolute()
    for item in [path, *path.parents]:
        need(not item.is_symlink(), "symbolic path: " + str(item))
    return path


def private(path, directory=False):
    path = no_symlinks(path)
    st = path.stat()
    need(
        stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode),
        "private path kind",
    )
    eq(stat.S_IMODE(st.st_mode), 0o700 if directory else 0o600, "private mode")
    eq(st.st_uid, os.getuid(), "current owner")
    if not directory:
        eq(st.st_nlink, 1, "no hardlinked private record")
    return path


def parse(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "duplicate JSON field")
            result[key] = value
        return result

    def reject(_):
        raise ValueError("nonfinite JSON")

    return json.loads(text, object_pairs_hook=unique, parse_constant=reject)


def load(path):
    return parse(Path(path).read_bytes())


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def utc(value):
    need(type(value) is str, "UTC string")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    need(
        parsed.tzinfo is not None and parsed.utcoffset() == dt.timedelta(0),
        "UTC offset",
    )
    return parsed


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save_bytes(path, payload):
    path = Path(path)
    private(path.parent, directory=True)
    no_symlinks(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    fsync_dir(path.parent)


def save(path, value):
    save_bytes(path, (json.dumps(value, indent=2, allow_nan=False) + "\n").encode())


def import_path(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def frozen_replay():
    # Preserve the frozen replay's sibling model import without leaking aliases.
    names = ("model", "a182_frozen_a184_replay")
    previous = {name: sys.modules.get(name) for name in names}
    try:
        import_path("model", BASE / "model.py")
        return import_path(names[1], BASE / "replay.py")
    finally:
        for name, old in previous.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old


def source_check(expected_manifest=None):
    eq(
        digest(BASE / "ARTIFACT_MANIFEST.json"),
        ARTIFACT_HASH,
        "frozen A184 artifact manifest",
    )
    eq(digest(BASE / "SOURCE_MANIFEST.json"), SOURCE_ID, "actual A184 source identity")
    eq(digest(BASE / "replay.py"), REPLAY_HASH, "unchanged A175 replay")
    eq(digest(BASE / "model.py"), MODEL_HASH, "unchanged A175 word arithmetic")
    artifact = load(BASE / "ARTIFACT_MANIFEST.json")
    eq(artifact["source_id"], SOURCE_ID, "artifact source binding")
    for name, expected in artifact["files"].items():
        path = no_symlinks(BASE / name)
        need(path.is_relative_to(BASE), "A184 artifact containment")
        eq(digest(path), expected, "A184 artifact " + name)
    source_id, files = frozen_replay().source_check()
    eq(source_id, SOURCE_ID, "frozen A184 source check")
    own_id = digest(HERE / "MANIFEST.json")
    if expected_manifest is not None:
        eq(own_id, hexhash(expected_manifest), "acknowledged A182 manifest")
    own = load(HERE / "MANIFEST.json")
    for name, expected in own["files"].items():
        path = no_symlinks(HERE / name)
        need(path.is_relative_to(HERE), "A182 source containment")
        eq(digest(path), expected, "A182 source " + name)
    for name, expected in load(HERE / "SOURCE_PINS.json")["files"].items():
        eq(digest(no_symlinks(name)), expected, "frozen input " + name)
    return dict(
        implementation="A184",
        preserved_semantic_contract="A175",
        source_sha256=SOURCE_ID,
        artifact_manifest_sha256=ARTIFACT_HASH,
        source_files_sha256=files,
        replay_sha256=REPLAY_HASH,
        model_sha256=MODEL_HASH,
        execution_manifest_sha256=own_id,
        execution_files_sha256=own["files"],
    )


def fixed_paths(base=None, run_base=None):
    base = BASE if base is None else base
    run_base = HERE if run_base is None else run_base
    return base / BINARY_REL, base / "candidate", run_base / "runs" / RUN_ID


def command(binary, binary_sha):
    return [
        str(binary),
        "--run",
        "--stage=smoke",
        "--keysets=1",
        "--expected-binary-sha256=" + hexhash(binary_sha),
    ]


def clearance_check(value, prepared_at):
    eq(value["matching_workloads"], [], "root reported workload clearance")
    age = (utc(prepared_at) - utc(value["observed_at_utc"])).total_seconds()
    need(0 <= age <= 120, "root clearance at most120seconds before preparation")


def disk_check(value, parent, prepared_at):
    eq(
        set(value),
        {
            "path",
            "observed_at_utc",
            "free_bytes",
            "minimum_free_bytes",
            "passed",
            "reservation_guaranteed",
        },
        "disk fields",
    )
    eq(value["path"], str(parent), "same output filesystem path")
    need(
        type(value["free_bytes"]) is int and value["free_bytes"] >= MIN_FREE_BYTES,
        "disk free floor",
    )
    eq(value["minimum_free_bytes"], MIN_FREE_BYTES, "registered free floor")
    eq(value["passed"], True, "disk preflight pass")
    eq(value["reservation_guaranteed"], False, "free space is not reserved")
    age = (utc(prepared_at) - utc(value["observed_at_utc"])).total_seconds()
    need(0 <= age <= 120, "disk observation before preparation within120seconds")
