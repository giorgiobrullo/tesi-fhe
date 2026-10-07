#!/usr/bin/env python3
"""Copy/patch only the isolated A133 core; no Cargo or cryptographic operations."""

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
A126 = ROOT / "tmp/a126-refresh-schedule-gate"


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"source pattern cardinality: {old[:80]}")
    return text.replace(old, new, 1)


def transformed_core(source):
    # Keep all public A126 names/counts: A133 is an observer successor of that circuit.
    source = replace_once(
        source,
        "    pub a126_fusion_inputs: Vec<Lwe>,",
        "    pub a126_fusion_inputs: Vec<Lwe>,\n"
        "    /// A133: exact post-KS ciphertext consumed by this fusion's blind rotation.\n"
        "    pub a133_fusion_post_ks: Vec<Lwe>,",
    )
    source = replace_once(
        source,
        "let apply_a126_fusion = |input: &Lwe| -> (Lwe, Lwe) {",
        "let apply_a126_fusion = |input: &Lwe| -> (Lwe, Lwe, Lwe) {",
    )
    source = replace_once(
        source,
        "        (candidate, zero_candidate)\n    };",
        "        (candidate, zero_candidate, switched)\n    };",
    )
    old_start = "            let pairs: Vec<(Lwe, Lwe)> = inputs.par_iter().map(apply_a126_fusion).collect();"
    start = source.index(old_start)
    end = source.index("        } else {", start)
    block = source[start:end]
    block = block.replace("Vec<(Lwe, Lwe)>", "Vec<(Lwe, Lwe, Lwe)>")
    block = block.replace(
        "trace.a126_fusion_inputs = inputs;",
        "trace.a126_fusion_inputs = inputs;\n"
        "                trace.a133_fusion_post_ks = pairs.iter().map(|(_, _, switched)| switched.clone()).collect();",
    )
    block = block.replace("|(candidate, _)|", "|(candidate, _, _)|")
    block = block.replace("|(_, zero)|", "|(_, zero, _)|")
    return source[:start] + block + source[end:]


def main():
    core = (A126 / "src/private_argmin.rs").read_bytes()
    assert (
        hashlib.sha256(core).hexdigest()
        == "6e4e83c8c3cd6133fd5df519c4aa1011c1ca9c826e0d4302cbbd6913d3bb1782"
    )
    paths = [
        *sorted((A126 / "src").rglob("*.rs")),
        A126 / "Cargo.toml",
        A126 / "Cargo.lock",
        A126 / "artifacts/fused_candidate_zero_body.u64le",
        *sorted((ROOT / "tmp/a131-a126-noise-margin").rglob("*")),
    ]
    pins = [
        {
            "path": str(p.relative_to(ROOT)),
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
        }
        for p in paths
        if p.is_file()
    ]
    pin_path = HERE / "SOURCE_PINS.json"
    if pin_path.exists():
        if json.loads(pin_path.read_text())["sources"] != pins:
            raise ValueError("upstream source drift")
    else:
        pin_path.write_text(
            json.dumps({"schema": "a133.sources.v1", "sources": pins}, indent=2) + "\n"
        )
    for name in (
        "src/lib.rs",
        "src/a53_scan.rs",
        "src/a53_scan/fhe.rs",
        "artifacts/fused_candidate_zero_body.u64le",
    ):
        destination = HERE / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((A126 / name).read_bytes())
    (HERE / "src/private_argmin.rs").write_text(transformed_core(core.decode()))
    manifest = (
        (A126 / "Cargo.toml")
        .read_text()
        .replace("a126_refresh_schedule_gate", "a133_a126_runtime_noise_witness")
    )
    manifest = manifest.replace(
        'edition = "2021"', 'edition = "2021"\nautobins = false'
    )
    manifest = manifest.replace(
        'sha2 = "0.10"', 'sha2 = "0.10"\nserde_json = "=1.0.150"'
    )
    (HERE / "Cargo.toml").write_text(manifest)
    print(
        "A133 isolated core materialized; original A126/A131 remain unchanged; no lock/build/FHE."
    )


if __name__ == "__main__":
    main()
