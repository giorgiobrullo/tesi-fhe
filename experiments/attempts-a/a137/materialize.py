"""Create the A137 snapshot-only successor; never modifies A127."""

from pathlib import Path
import hashlib
import json
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OLD = ROOT / "tmp/a127-direct-window-pfks-runtime"


def transform(source):
    source = source.replace("A127", "A137").replace("a127", "a137")
    source = source.replace("//! A137:", "//! A137 snapshot-only successor of A127:")
    source = source.replace(
        "use serde_json::json;", "mod observer;\n\nuse serde_json::json;"
    )
    old = "2bbc55173731fd3f79b91e4bfa3dc3eed3ede835850634cab07b1a490acd27d4"
    prereg = hashlib.sha256((HERE / "PREREGISTRATION.json").read_bytes()).hexdigest()
    source = source.replace(old, prereg)
    for name, next_name, metrics, control in [
        ("packed_d2_select", "hash_lwe", "SelectorMetrics", "small_control"),
        (
            "direct_window_d2_select",
            "effective_rotation_degree",
            "DirectMetrics",
            "control",
        ),
    ]:
        start = source.index("fn " + name + "(")
        end = source.index("fn " + next_name + "(", start)
        part = source[start:end]
        part = part.replace(
            f") -> ([Lwe; OUTPUTS], Lwe, {metrics}) {{",
            f") -> ([Lwe; OUTPUTS], Lwe, {metrics}, observer::PackedTrace) {{",
        )
        part = part.replace(
            "let mut accumulator: Option<Glwe> = None;",
            "let mut accumulator: Option<Glwe> = None;\n    let mut pfks_outputs = Vec::with_capacity(PACKED_TERMS);",
        )
        if name == "packed_d2_select":
            part = part.replace(
                "metrics.pfks_calls += 1;",
                "metrics.pfks_calls += 1;\n        pfks_outputs.push(constant_glwe.clone());",
            )
        else:
            part = part.replace(
                "metrics.pfks_calls += 1;",
                "metrics.pfks_calls += 1;\n        pfks_outputs.push(term.clone());",
            )
        call = f"blind_rotate_assign(&{control}, &mut accumulator, bsk);"
        part = part.replace(
            call, "let pre_br_accumulator = accumulator.clone();\n    " + call
        )
        part = part.replace(
            f"(outputs, {control}, metrics)",
            f"(outputs, {control}, metrics, observer::PackedTrace {{ pfks_outputs, pre_br_accumulator }})",
        )
        source = source[:start] + part + source[end:]
    source = source.replace(
        "direct_control, direct_metrics) =",
        "direct_control, direct_metrics, direct_trace) =",
    )
    source = source.replace(
        "convolution_control, convolution_metrics) =",
        "convolution_control, convolution_metrics, convolution_trace) =",
    )
    source = source.replace(
        "let mut direct_passed = 0;",
        "let mut observer_failures = 0;\n    let mut direct_passed = 0;",
    )
    marker = "        let prerequisites = ingress_ok && control_ok && scalar_ok && scalar_metrics.counters_pass();"
    assert marker in source
    source = source.replace(
        marker,
        """        let direct_observer_ok = observer::observe_arm(
            "direct_window", true, fixture, &left, &right, &control, &direct_control,
            &direct_outputs, &direct_trace, &glwe_secret, &small_secret.as_view(), parameters,
        );
        let convolution_observer_ok = observer::observe_arm(
            "convolution_a108", false, fixture, &left, &right, &control, &convolution_control,
            &convolution_outputs, &convolution_trace, &glwe_secret, &small_secret.as_view(), parameters,
        );
        let observer_ok = direct_observer_ok && convolution_observer_ok;
        observer_failures += usize::from(!observer_ok);
"""
        + marker,
    )
    source = source.replace(
        '"record": "case", "fixture":',
        '"observer_identity_pass": observer_ok,\n            "record": "case", "fixture":',
    )
    source = source.replace(
        "let pass = direct_passed == FIXTURES.len();",
        "let pass = direct_passed == FIXTURES.len() && observer_failures == 0;",
    )
    source = source.replace(
        '"fixture_cases": FIXTURES.len(), "direct_passed": direct_passed,',
        '"observer_failures": observer_failures,\n        "fixture_cases": FIXTURES.len(), "direct_passed": direct_passed,',
    )
    source = source.replace(
        '"secret_material_persisted": false, "timing_scope": "diagnostic single observation per fixture"',
        '''"secret_key_bytes_persisted": false, "contains_secret_derived_observations": true,
        "ciphertext_words_persisted": false, "phase_polynomial_words_persisted": false,
        "timing_scope": "observer snapshots invalidate performance inference",
        "main_source_sha256": observer::hash_bytes(include_bytes!("main.rs")),
        "observer_source_sha256": observer::hash_bytes(include_bytes!("observer.rs")),
        "lockfile_sha256": observer::hash_bytes(include_bytes!("../Cargo.lock")),
        "key_family_ids": {"constant": observer::hash_words(constant_key.as_ref()),
                           "window": observer::hash_words(window_key.as_ref())},
        "peak_live_counts_scope": "frozen datapath counters exclude retained observer clones",
        "phase_trust": "local client observations; not execution attestation or independent secret-key proof"''',
    )
    return source


def main():
    original = (OLD / "src/main.rs").read_text()
    assert (
        hashlib.sha256(original.encode()).hexdigest()
        == "5972a447549ce8d1fbc4cbf33152c0fcc516ddc624af5d41e2bf57e9ae8d377c"
    )
    specs = []
    fixture_region = original[
        original.index("const FIXTURES:") : original.index("enum Action")
    ]
    for match in re.finditer(
        r'name: "([^"]+)".*?left: \[([^]]+)\],.*?right: \[([^]]+)\],.*?control: (LEFT_CONTROL|RIGHT_CONTROL),',
        fixture_region,
        re.S,
    ):
        name, left, right, control = match.groups()
        specs.append(
            {
                "name": name,
                "left": [int(x) for x in left.split(",")],
                "right": [int(x) for x in right.split(",")],
                "control": 4 if control == "LEFT_CONTROL" else 12,
            }
        )
    assert len(specs) == 8
    prereg = json.loads((OLD / "PREREGISTRATION.json").read_text())
    prereg["fixture_specs"] = specs
    prereg.update(
        artifact="A137",
        predecessor="A127",
        observer="eight pre-spread PFKS GLWEs and pre-BR accumulator for direct/convolution only",
        observation_scope="client-local phase aggregates and hashes after all arm timers; no timing claim",
        support_gate="unchanged actual coefficientwise effective BR degree",
        tail_status="OPEN; no independent primitive-key-row noise measurements",
    )
    (HERE / "PREREGISTRATION.json").write_text(
        json.dumps(prereg, indent=2, sort_keys=True) + "\n"
    )
    (HERE / "src/main.rs").write_text(transform((OLD / "src/main.rs").read_text()))
    for filename in ["Cargo.toml", "Cargo.lock"]:
        (HERE / filename).write_text(
            (OLD / filename)
            .read_text()
            .replace(
                "a127_direct_window_pfks_runtime", "a137_pfks_runtime_error_observer"
            )
        )
    paths = [
        "tmp/a127-direct-window-pfks-runtime/src/main.rs",
        "tmp/a127-direct-window-pfks-runtime/Cargo.toml",
        "tmp/a127-direct-window-pfks-runtime/Cargo.lock",
        "tmp/a127-direct-window-pfks-runtime/PREREGISTRATION.json",
        "tmp/a134-pfks-error-provenance/model.py",
        "tmp/a134-pfks-error-provenance/README.md",
    ]
    inherited = json.loads(
        (ROOT / "tmp/a134-pfks-error-provenance/SOURCE_PINS.json").read_text()
    )["sources"]
    paths += [p["path"] for p in inherited]
    cache = "/opt/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-0.11.3/src/core_crypto/"
    paths += [
        cache + "fft_impl/fft64/crypto/bootstrap.rs",
        cache + "fft_impl/common.rs",
    ]
    pins = [
        {"path": str(p), "sha256": hashlib.sha256((ROOT / p).read_bytes()).hexdigest()}
        for p in dict.fromkeys(paths)
    ]
    (HERE / "SOURCE_PINS.json").write_text(
        json.dumps({"schema": "a137.source-pins.v1", "sources": pins}, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
