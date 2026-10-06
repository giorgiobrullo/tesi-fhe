"""A160 source/lock binding. No build, process or cryptographic execution."""

import hashlib
import json
from pathlib import Path
import sys

if not __debug__:
    raise RuntimeError("A160 checks require assertions")
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
UPSTREAM = ROOT / "tmp/a158-first-ks-trace-plan"
sys.path.insert(0, str(UPSTREAM))
import schema as a158  # noqa: E402

SOURCE_FILES = [
    "freeze.py",
    "audit.py",
    "replay.py",
    "run_gate.py",
    "test_gate.py",
    "SOURCE_PINS.json",
    "candidate/Cargo.toml",
    "candidate/Cargo.lock",
    "candidate/.cargo/config.toml",
    "candidate/src/main.rs",
    "candidate/src/observe.rs",
    "candidate/FIXTURE.json",
    "candidate/fixtures.tsv",
    "candidate/PARAMETER_CANONICAL.txt",
]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_origins():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())["sources"]
    for path, digest in pins.items():
        assert sha(path) == digest, path
    a158.verify_sources()
    parent = ROOT / "tmp/u10-standard-import-gate/candidate"
    assert (HERE / "candidate/Cargo.lock").read_bytes() == (
        parent / "Cargo.lock"
    ).read_bytes()
    expected = (
        (parent / "Cargo.toml")
        .read_text()
        .replace('name = "u6_standard_score_gate"', 'name = "a160_first_ks_prefix"')
        .replace('path = "src/bin/u6_standard_score_gate.rs"', 'path = "src/main.rs"')
    )
    assert (HERE / "candidate/Cargo.toml").read_text() == expected
    assert json.loads((HERE / "candidate/FIXTURE.json").read_text()) == a158.fixture()
    assert sha(HERE / "candidate/PARAMETER_CANONICAL.txt") == a158.FINGERPRINT
    return len(pins)


def source_manifest():
    return {name: sha(HERE / name) for name in SOURCE_FILES}


def source_id(manifest):
    return hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def verify_source():
    verify_origins()
    manifest = json.loads((HERE / "SOURCE_MANIFEST.json").read_text())
    assert manifest == source_manifest()
    digest = source_id(manifest)
    assert (HERE / "candidate/SOURCE_DIGEST.txt").read_text().strip() == digest
    return digest
