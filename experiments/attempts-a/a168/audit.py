"""A168 observer-free origin/source equivalence, no compile or FHE."""

import hashlib
import importlib.util
import json
import re
from pathlib import Path
import sys

if not __debug__:
    raise RuntimeError("A168 requires assertions")
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE_FILES = [
    "audit.py",
    "run_gate.py",
    "validate.py",
    "test_gate.py",
    "freeze.py",
    "README.md",
    "PREREGISTRATION.md",
    "PILOT.json",
    "SOURCE_PINS.json",
    "candidate/Cargo.toml",
    "candidate/Cargo.lock",
    "candidate/.cargo/config.toml",
    "candidate/src/main.rs",
    "candidate/src/lib.rs",
    "candidate/src/private_argmin.rs",
    "candidate/src/a53_scan.rs",
    "candidate/src/a53_scan/fhe.rs",
    "candidate/artifacts/fused_candidate_zero_body.u64le",
]


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_origins():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())["sources"]
    for name, digest in pins.items():
        assert sha(name) == digest, name
    a126 = ROOT / "tmp/a126-refresh-schedule-gate"
    a133 = ROOT / "tmp/a133-a126-runtime-noise-witness"
    for name in (
        "src/lib.rs",
        "src/private_argmin.rs",
        "src/a53_scan.rs",
        "src/a53_scan/fhe.rs",
        "artifacts/fused_candidate_zero_body.u64le",
    ):
        assert (HERE / "candidate" / name).read_bytes() == (a126 / name).read_bytes(), (
            name
        )
    spec = importlib.util.spec_from_file_location(
        "a168_a133_origin", a133 / "materialize.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert (
        module.transformed_core((a126 / "src/private_argmin.rs").read_text())
        == (a133 / "src/private_argmin.rs").read_text()
    )
    expected = (
        (a133 / "Cargo.toml")
        .read_text()
        .replace(
            'name = "a133_a126_runtime_noise_witness"\npath = "src/bin/a133_a126_runtime_noise_witness.rs"\nrequired-features = ["diagnostic-trace"]',
            'name = "a168_refresh_pair_pilot"\npath = "src/main.rs"',
        )
    )
    assert (HERE / "candidate/Cargo.toml").read_text() == expected
    assert (HERE / "candidate/Cargo.lock").read_bytes() == (
        a133 / "Cargo.lock"
    ).read_bytes()
    source = (HERE / "candidate/src/main.rs").read_text()
    assert '#[cfg(feature = "diagnostic-trace")]' in source
    assert 'compile_error!("A168 timing refuses diagnostic-trace")' in source
    assert "with_trace" not in source
    timer = source[
        source.index("    let start = Instant::now();") : source.index(
            "    let end = Instant::now();"
        )
    ]
    assert timer.count("pool.install") == 1 and "evaluator(" in timer
    for forbidden in (
        "decrypt_",
        "word_hash(",
        "emit(",
        "println!",
        "fs::",
        "clone()",
        "keygen",
    ):
        assert forbidden not in timer, forbidden
    assert source.index("let evaluator = if fused") < source.index(
        "let start = Instant::now();"
    )
    assert source.index("results.push((baseline, fused));") < source.index(
        "decrypt_lwe_ciphertext(&big"
    )
    assert (
        len(re.findall(r"timed\(\s*first_fused,", source))
        == len(re.findall(r"timed\(\s*!first_fused,", source))
        == 1
    )
    assert '"UNQUALIFIED_NO_ALIGNED_OS_COLLECTOR"' in source
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
