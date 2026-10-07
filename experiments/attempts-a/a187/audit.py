"""Read-only source/static binding, never Cargo or cryptography."""

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify():
    origins = json.loads((HERE / "SOURCE_ORIGINS.json").read_text())
    for path, expected in origins["files"].items():
        assert sha(path) == expected, path
    old = HERE.parent / "a149-padding-coefficient-gate"
    prefix = (old / "src/main.rs").read_text().split("\nfn main() {")[0]
    current = (HERE / "src/main.rs").read_text()
    assert (
        current
        == '#![recursion_limit = "256"]\n'
        + prefix
        + '\nmod precision;\ninclude!("gate.rs");\n'
    )
    for file in [
        "Cargo.toml",
        "Cargo.lock",
        "src/a34_tables.rs",
        "src/coefficient_observer.rs",
        "graph.py",
        "regions.py",
        "a138_model.py",
        "a135_model.py",
        "coefficients.py",
    ]:
        assert (HERE / file).read_bytes() == (old / file).read_bytes(), file
    origin = origins["scalar_model_origin"]
    assert sha(origin["path"]) == sha(HERE / "precision_model.py") == origin["sha256"]
    source = (old / "src/main.rs").read_text()
    start = source.index("            // One real, nontrivial encrypted packed probe")
    end = source.index("            let evaluations: Vec<_>", start)
    block = "\n".join(
        line[12:] if line.startswith("            ") else line
        for line in source[start:end].splitlines()
    )
    expected = (
        "// A149 packed input construction block, byte-preserving apart from indentation.\n{\n"
        + block
        + "\n(full, low)\n}\n"
    )
    assert (HERE / "src/input_construction.rs").read_text() == expected
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())["files"]
    for path, expected in pins.items():
        assert sha(path) == expected, path
    return dict(
        status="SOURCE_PREFIX_INPUT_MODEL_API_PINS_PASS",
        origin_files=len(origins["files"]),
        primary_pins=len(pins),
        original_evaluator_prefix_byte_identical=True,
        source_only=True,
        compiled=False,
        actual_fhe=False,
    )


if __name__ == "__main__":
    print(json.dumps(verify()))
