"""Read-only frozen-source verification; no Rust or process execution."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE_FILES = [
    "src/main.rs",
    "src/row_observer.rs",
    "Cargo.toml",
    "Cargo.lock",
    "PARAMETERS.json",
    "window.u64le",
    "SOURCE_PINS.json",
    "run_gate.py",
    "validate.py",
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_id():
    return hashlib.sha256(
        "".join(f"{name}\t{sha(ROOT / name)}\n" for name in SOURCE_FILES).encode()
    ).hexdigest()


def check():
    pins = json.loads((ROOT / "SOURCE_PINS.json").read_text())
    for pin in pins:
        assert sha(Path(pin["path"])) == pin["sha256"], pin["path"]
    parent = ROOT.parent / "a147-pfks-key-row-witness/src/lib.rs"
    assert (ROOT / "src/row_observer.rs").read_bytes() == parent.read_bytes()
    source = (ROOT / "src/main.rs").read_text()
    assert (
        source.count(
            "private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext("
        )
        == 1
    )
    assert "ServerKey::new(" not in source and "blind_rotate_assign(" not in source
    measure = source.index("let samples = rows::measure_key_rows(")
    encrypt = source.index("encrypt_lwe_ciphertext(")
    predict = source.index("let before = rows::predict(")
    evaluate = source.index(
        "private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext("
    )
    compare = source.index("let positive = rows::compare_payload(")
    negative = source.index("let negative = rows::compare_payload(")
    assert measure < encrypt < predict < evaluate < compare < negative
    assert "original_body.wrapping_add(1)" in source
    assert "assert_eq!(actual_parameters, expected);" in source
    assert "create_new(true)" in source and ".mode(0o600)" in source
    assert "args.len() == 5" in source
    raw = (ROOT / "window.u64le").read_bytes()
    body = [int.from_bytes(raw[j : j + 8], "little") for j in range(0, len(raw), 8)]
    expected_body = [0] * 2048
    for degree in range(-63, 64):
        expected_body[degree % 2048] = (-1 if degree < 0 else 1) % (1 << 64)
    assert body == expected_body
    params = json.loads((ROOT / "PARAMETERS.json").read_text())
    parent_plan = json.loads(
        (
            ROOT.parent / "a137-pfks-runtime-error-observer/PREREGISTRATION.json"
        ).read_text()
    )
    fixture = parent_plan["fixture_specs"][2]
    assert (
        fixture["name"] == params["fixture_name"]
        and fixture["left"][0] == params["payload_message"] == 3
    )
    assert (ROOT / "source-id.txt").read_text().strip() == source_id()
    return {
        "status": "STATIC_SOURCE_READY_NOT_COMPILED",
        "source_pins": len(pins),
        "source_id": source_id(),
        "params_sha256": sha(ROOT / "PARAMETERS.json"),
        "observer_sha256": sha(parent),
        "function_sha256": sha(ROOT / "window.u64le"),
        "kernel_sha256": hashlib.sha256(
            (1).to_bytes(8, "little") + bytes(2047 * 8)
        ).hexdigest(),
    }


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
