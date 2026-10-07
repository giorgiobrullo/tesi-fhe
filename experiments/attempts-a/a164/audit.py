"""A164 source/lock binding. No build, process or cryptographic execution."""

import hashlib
import json
from pathlib import Path
import sys

if not __debug__:
    raise RuntimeError("A164 checks require assertions")
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
UPSTREAM = ROOT / "tmp/a158-first-ks-trace-plan"
sys.path.insert(0, str(UPSTREAM))
import schema as a158  # noqa: E402

SOURCE_FILES = [
    "ORIGIN_PINS.json",
    "IMPORT_ONLY.patch",
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
    verify_import_only_successor()
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
        .replace('name = "u6_standard_score_gate"', 'name = "a164_first_ks_prefix"')
        .replace('path = "src/bin/u6_standard_score_gate.rs"', 'path = "src/main.rs"')
    )
    assert (HERE / "candidate/Cargo.toml").read_text() == expected
    assert json.loads((HERE / "candidate/FIXTURE.json").read_text()) == a158.fixture()
    assert sha(HERE / "candidate/PARAMETER_CANONICAL.txt") == a158.FINGERPRINT
    return len(pins)


def verify_import_only_successor():
    import difflib

    origins = json.loads((HERE / "ORIGIN_PINS.json").read_text())["files"]
    for path, digest in origins.items():
        assert sha(path) == digest, path
    old = ROOT / "tmp/a160-first-ks-runtime-prefix"

    def normalized(name):
        return (HERE / name).read_text().replace("A164", "A160").replace("a164", "a160")

    import_line = "use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;\n"
    main = normalized("candidate/src/main.rs")
    assert main.count(import_line) == 1
    assert main.replace(import_line, "") == (old / "candidate/src/main.rs").read_text()
    for name in (
        "candidate/src/observe.rs",
        "run_gate.py",
        "replay.py",
        "candidate/Cargo.toml",
        "candidate/.cargo/config.toml",
    ):
        assert normalized(name) == (old / name).read_text(), name
    for name in (
        "candidate/Cargo.lock",
        "candidate/FIXTURE.json",
        "candidate/fixtures.tsv",
        "candidate/PARAMETER_CANONICAL.txt",
        "SOURCE_PINS.json",
    ):
        assert (HERE / name).read_bytes() == (old / name).read_bytes(), name
    expected_patch = "".join(
        difflib.unified_diff(
            (old / "candidate/src/main.rs").read_text().splitlines(True),
            main.splitlines(True),
            fromfile="A160/candidate/src/main.rs",
            tofile="A164/candidate/src/main.rs (task labels normalized)",
        )
    )
    assert (HERE / "IMPORT_ONLY.patch").read_text() == expected_patch
    return len(origins)


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
