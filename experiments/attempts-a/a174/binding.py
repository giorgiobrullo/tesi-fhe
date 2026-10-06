"""Pinned A171 inputs and private I/O; no launch or process inspection."""

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
    raise RuntimeError("A171 verification requires assertions enabled")
HERE = Path(__file__).resolve().parent
BASE = HERE.parent / "a171-pfks-d1-runtime-gate"
SCHEMA = "a174-a171-progression-envelope-v1"
SOURCE_ID = "44613def7387d3a24f9d5633664e76c4376247870d3b0a3e7e8ab41c1bd54022"
ARTIFACT_HASH = "60d9faf3f2af7591935c261804a71cd0f257a0aaa22ecd68ea3fcc60c62f1b7c"
REPLAY_HASH = "d1b51f2a87f82edc1c30611b313fdfe3e4a49af8e2b6af84f87f0f7466c4c918"
PREREG_HASH = "d7d0566ce494c3eece3fe1c862a0dcb2bfa6e838a489d39fa82ba3e5183611ee"
RUN_IDS = {1: "offset1-key2", 2: "offset2-key3"}
BINARY_HASH = "03405436a6d9412ac42b31bc0c556d8b99c97500ce148a8444bdc79650ec2cc5"
FIRST_MANIFEST_HASH = "4b7aa7267fd8ddb4a4331f472e549057053d8f8fe83c8946f6e81a5da64f2c5c"
FIRST_VALIDATION_HASH = (
    "c0e2d4f51eb428eaa7e7bad3fe2f32f0d4e4c1f5e5e4c2eaa6026174635fcf5c"
)
BINARY_REL = "target-a171-only/release/a171_pfks_d1_component"
ENV = {
    "RAYON_NUM_THREADS": "1",
    "A171_ORDER_OFFSET": "0",
    "A171_RUN_FHE": "I_ACKNOWLEDGE_A171_DIRECT_WINDOW_PFKS_FHE",
    "A171_PREREGISTRATION_SHA256": PREREG_HASH,
}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def strictly_equal(actual, expected):
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        if not strictly_equal(set(actual), set(expected)):
            return False
        return all(
            strictly_equal(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, (list, tuple)):
        return len(actual) == len(expected) and all(
            strictly_equal(a, e) for a, e in zip(actual, expected)
        )
    if isinstance(expected, set):
        return len(actual) == len(expected) and all(
            any(strictly_equal(a, e) for a in actual) for e in expected
        )
    return actual == expected


def eq(actual, expected, reason):
    need(strictly_equal(actual, expected), reason)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            result.update(chunk)
    return result.hexdigest()


def hexhash(value):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "SHA256")
    return value


def no_symlinks(path):
    path = Path(path).absolute()
    for item in [path, *path.parents]:
        need(not item.is_symlink(), "symbolic path: " + str(item))
    return path


def private(path, directory=False):
    path = no_symlinks(path)
    mode = path.stat().st_mode
    need(stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode), "private path kind")
    need(stat.S_IMODE(mode) == (0o700 if directory else 0o600), "private path mode")
    return path


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def parse(text):
    def reject_constant(_):
        raise ValueError("nonfinite JSON")

    return json.loads(
        text, object_pairs_hook=unique_object, parse_constant=reject_constant
    )


def load(path):
    return parse(Path(path).read_text())


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


def save(path, value):
    path = Path(path)
    private(path.parent, directory=True)
    no_symlinks(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(value, handle, indent=2, allow_nan=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def import_path(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_check():
    eq(digest(BASE / "ARTIFACT_MANIFEST.json"), ARTIFACT_HASH, "frozen A171 artifact")
    manifest = load(BASE / "ARTIFACT_MANIFEST.json")
    eq(manifest["source_id"], SOURCE_ID, "A171 source identity")
    for name, expected in manifest["files"].items():
        path = no_symlinks(BASE / name)
        need(path.is_relative_to(BASE), "artifact containment")
        eq(digest(path), expected, "A171 artifact " + name)
    eq(digest(BASE / "SOURCE_SHA256SUMS"), SOURCE_ID, "seven-leaf producer identity")
    eq(digest(BASE / "replay.py"), REPLAY_HASH, "frozen arithmetic replay")
    for line in (BASE / "SOURCE_SHA256SUMS").read_text().splitlines():
        expected, name = line.split("  ", 1)
        eq(digest(BASE / name), expected, "producer leaf " + name)
    import_path("a171_bound_replay_source", BASE / "replay.py").source_check()
    first = load(HERE / "FIRST_PINS.json")
    for name, expected in first["files"].items():
        eq(digest(no_symlinks(BASE / name)), expected, "actual first-gate pin " + name)
    eq(
        digest(BASE / "execution-readiness/MANIFEST.json"),
        FIRST_MANIFEST_HASH,
        "frozen first envelope",
    )
    first_binding = import_path(
        "a174_first_binding", BASE / "execution-readiness/binding.py"
    )
    first_binding.source_check()
    own = load(HERE / "MANIFEST.json")
    for name, expected in own["files"].items():
        eq(digest(no_symlinks(HERE / name)), expected, "execution source " + name)
    return {
        "first_gate_pins_sha256": digest(HERE / "FIRST_PINS.json"),
        "source_sha256": SOURCE_ID,
        "artifact_manifest_sha256": ARTIFACT_HASH,
        "artifact_files_sha256": manifest["files"],
        "replay_sha256": REPLAY_HASH,
        "execution_manifest_sha256": digest(HERE / "MANIFEST.json"),
        "execution_files_sha256": own["files"],
    }


def fixed_paths(offset, base=BASE, run_base=HERE):
    need(type(offset) is int and offset in RUN_IDS, "registered later offset1 or2")
    return (base / BINARY_REL, base / "candidate", run_base / "runs" / RUN_IDS[offset])


def environment(offset):
    fixed_paths(offset)
    return dict(ENV, A171_ORDER_OFFSET=str(offset))


def report_path(offset):
    return HERE / "artifacts" / (RUN_IDS[offset] + "-validation.json")


def first_verifier():
    old_binding = import_path(
        "a174_first_bound_binding", BASE / "execution-readiness/binding.py"
    )
    previous = sys.modules.get("binding")
    sys.modules["binding"] = old_binding
    try:
        return import_path(
            "a174_first_bound_verifier", BASE / "execution-readiness/verify.py"
        )
    finally:
        if previous is None:
            sys.modules.pop("binding", None)
        else:
            sys.modules["binding"] = previous


def clearance_check(value, prepared_at):
    eq(value["matching_workloads"], [], "root reported workload clearance")
    age = (utc(prepared_at) - utc(value["observed_at_utc"])).total_seconds()
    need(
        0 <= age <= 120,
        "root clearance must precede preparation by at most 120 seconds",
    )
