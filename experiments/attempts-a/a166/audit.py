"""A166 source binding and preserved P0 origin checks; no execution."""

import difflib
import hashlib
import json
from pathlib import Path
import re
import sys

if not __debug__:
    raise RuntimeError("A166 requires assertions enabled")
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OLD = ROOT / "tmp/a164-first-ks-import-gate"
sys.path.insert(0, str(ROOT / "tmp/a158-first-ks-trace-plan"))
import schema as a158  # noqa: E402

SOURCE_FILES = [
    "audit.py",
    "replay.py",
    "p0_replay.py",
    "synthetic_p0.py",
    "run_gate.py",
    "test_gate.py",
    "freeze.py",
    "README.md",
    "SOURCE_PINS.json",
    "ORIGIN_PINS.json",
    "P0_SUCCESSOR.patch",
    "P1_CONTRACT.json",
    "candidate/Cargo.toml",
    "candidate/Cargo.lock",
    "candidate/.cargo/config.toml",
    "candidate/src/main.rs",
    "candidate/src/observe.rs",
    "candidate/src/consumer.rs",
    "candidate/FIXTURE.json",
    "candidate/fixtures.tsv",
    "candidate/PARAMETER_CANONICAL.txt",
]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def normalize(source):
    return source.replace("A166", "A164").replace("a166", "a164")


def compact(source):
    return re.sub(r"\s+", "", source)


def verify_origins():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())["sources"]
    origins = json.loads((HERE / "ORIGIN_PINS.json").read_text())["files"]
    for name, digest in {**pins, **origins}.items():
        assert sha(name) == digest, name
    a158.verify_sources()
    for name in (
        "candidate/Cargo.lock",
        "candidate/src/observe.rs",
        "candidate/FIXTURE.json",
        "candidate/fixtures.tsv",
        "candidate/PARAMETER_CANONICAL.txt",
    ):
        assert (HERE / name).read_bytes() == (OLD / name).read_bytes(), name
    for name in ("candidate/Cargo.toml", "candidate/.cargo/config.toml"):
        assert normalize((HERE / name).read_text()) == (OLD / name).read_text(), name
    assert (
        normalize((HERE / "p0_replay.py").read_text())
        == (OLD / "replay.py").read_text()
    )
    source = (HERE / "candidate/src/main.rs").read_text()
    previous = (OLD / "candidate/src/main.rs").read_text()
    normalized = normalize(source)
    # The entire frozen P0 trace construction remains unchanged, including its
    # counts0 BR and membership/tail limits. The producer ID is the sole normalization.
    start, end = "    let record = object(&[", "    // Preserve full evidence"
    old_trace = previous[previous.index(start) : previous.index(end)]
    new_trace = normalized[normalized.index(start) : normalized.index(end)]
    assert compact(old_trace) == compact(new_trace), "frozen P0 trace"
    old_helper = (
        (OLD / "test_gate.py")
        .read_text()
        .split("def synthetic_chain(", 1)[1]
        .split("\n\nclass Prefix", 1)[0]
    )
    new_helper = (
        normalize((HERE / "synthetic_p0.py").read_text())
        .split("def synthetic_chain(", 1)[1]
        .rstrip()
    )
    assert compact(old_helper) == compact(new_helper), "frozen synthetic P0 helper"
    expected_patch = "".join(
        difflib.unified_diff(
            previous.splitlines(True),
            normalized.splitlines(True),
            fromfile="A164/candidate/src/main.rs",
            tofile="A166/candidate/src/main.rs (IDs normalized)",
        )
    )
    assert (HERE / "P0_SUCCESSOR.patch").read_text() == expected_patch
    assert source.count("keyswitch_lwe_ciphertext(ksk, &input, &mut post);") == 1
    assert source.count(".lwe_ciphertext_modulus_switch::<usize, _>") == 1
    assert source.count("encrypt_glwe_ciphertext(") == 1
    assert source.index("measure_before_ks(ksk") < source.index(
        "keyswitch_lwe_ciphertext(ksk"
    )
    assert source.index('"p1-key-binding.json"') < source.index(
        "encrypt_glwe_ciphertext("
    )
    assert source.index('"p0-completed.json"') < source.index("consumer::consume_p1(")
    assert "&switched," in source[source.index("consumer::consume_p1(") :]
    consumer = (HERE / "candidate/src/consumer.rs").read_text()
    assert consumer.count("blind_rotate_assign(switched, &mut rotated, bsk);") == 1
    assert consumer.count("extract_lwe_sample_from_glwe_ciphertext(") == 1
    assert "keyswitch_lwe_ciphertext(" not in consumer
    assert "lwe_ciphertext_modulus_switch" not in consumer
    assert "MonomialDegree(0)" in consumer
    assert source.count("counts.ks += 1;") == source.count("counts.ms += 1;") == 1
    assert consumer.count("counts.br += 1;") == 1
    assert (
        "Plaintext(ALPHA)" in consumer and "const ALPHA: u64 = 1u64 << 59;" in consumer
    )
    return dict(upstream_pins=len(pins), origin_pins=len(origins))


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
