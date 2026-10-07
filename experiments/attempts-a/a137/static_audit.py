"""Light source binding only; never compiles or launches the FHE binary."""

from pathlib import Path
import hashlib
import json
import re
import subprocess
from materialize import transform

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def function(source, name):
    start = re.search(r"fn " + re.escape(name) + r"[<(]", source).start()
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def normalized(source):
    return re.sub(r"\s+", "", source)


def audit():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())["sources"]
    for item in pins:
        assert sha256(ROOT / item["path"]) == item["sha256"], item["path"]
    original = (ROOT / "tmp/a127-direct-window-pfks-runtime/src/main.rs").read_text()
    expected = subprocess.run(
        [
            "rustfmt",
            "--edition",
            "2021",
            "--emit",
            "stdout",
            "--config",
            "skip_children=true",
        ],
        input=transform(original),
        text=True,
        capture_output=True,
        check=True,
    ).stdout
    actual = (HERE / "src/main.rs").read_text()
    assert expected == actual, (
        "main.rs must equal the exact registered snapshot-only transformation"
    )
    formatted_original = subprocess.run(
        [
            "rustfmt",
            "--edition",
            "2021",
            "--emit",
            "stdout",
            "--config",
            "skip_children=true",
        ],
        input=original,
        text=True,
        capture_output=True,
        check=True,
    ).stdout
    reference_names = [
        "signed_cell_mask",
        "packed_selector_masks",
        "a30_scalar_selector_masks",
        "polynomial_fft_wrapping_mul",
        "spread_glwe",
        "scalar_d2_select_tuple",
        "effective_rotation_degree",
    ]
    for name in reference_names:
        assert normalized(function(formatted_original, name)) == normalized(
            function(actual, name)
        ), name
    operations = [
        "private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(",
        "keyswitch_lwe_ciphertext(",
        "blind_rotate_assign(",
        "extract_lwe_sample_from_glwe_ciphertext(",
    ]
    for operation in operations:
        assert original.count(operation) == actual.count(operation), operation
    observer = (HERE / "src/observer.rs").read_text()
    assert all(operation not in observer for operation in operations)
    for name in ["packed_d2_select", "direct_window_d2_select"]:
        part = function(actual, name)
        assert part.count("pfks_outputs.push(") == 1
        assert part.count("let pre_br_accumulator = accumulator.clone();") == 1
        assert part.index("let pre_br_accumulator = accumulator.clone();") < part.index(
            "blind_rotate_assign("
        )
    loop = function(actual, "run")
    assert loop.index("observer::observe_arm(") > loop.index("scalar.expect(")
    for filename in ["Cargo.toml", "Cargo.lock"]:
        copied = (
            (ROOT / "tmp/a127-direct-window-pfks-runtime" / filename)
            .read_text()
            .replace(
                "a127_direct_window_pfks_runtime", "a137_pfks_runtime_error_observer"
            )
        )
        assert copied == (HERE / filename).read_text()
    return {
        "status": "PASS_SOURCE_STATIC_ONLY",
        "artifact": "A137",
        "source_pins": len(pins),
        "unchanged_reference_functions": reference_names,
        "unchanged_server_crypto_call_sites": True,
        "exact_main_transformation": True,
        "preregistration_sha256": sha256(HERE / "PREREGISTRATION.json"),
        "main_sha256": sha256(HERE / "src/main.rs"),
        "observer_sha256": sha256(HERE / "src/observer.rs"),
        "lockfile_sha256": sha256(HERE / "Cargo.lock"),
        "cargo_or_fhe_executed": False,
        "primitive_row_tails": "OPEN",
        "performance_interpretation_allowed": False,
    }


if __name__ == "__main__":
    print(json.dumps(audit(), indent=2))
