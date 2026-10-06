#!/usr/bin/env python3
"""Source-only A137 successor. No resolver, builds, key generation, or execution."""

import hashlib
import json
import subprocess
import difflib
from pathlib import Path

if not __debug__:
    raise RuntimeError("A171 source materialization requires assertions enabled")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ORIGIN = ROOT / "tmp/a137-pfks-runtime-error-observer"
DEST = HERE / "candidate"


def replace_one(text, old, new):
    assert text.count(old) == 1, old[:90]
    return text.replace(old, new)


def materialize():
    assert __debug__
    main = (ORIGIN / "src/main.rs").read_text()
    assert (
        hashlib.sha256(main.encode()).hexdigest()
        == "3665d47ccc3fb243a04d179e64ae061fd228536577559da6295b168849dc9ecc"
    )
    observer = (ORIGIN / "src/observer.rs").read_text()
    assert (
        hashlib.sha256(observer.encode()).hexdigest()
        == "5c0e8b07ec2d1ddadb443a6cb564061ea2329dd99a8daa1fa401539c22561797"
    )
    plan = json.loads((HERE / "PREREGISTRATION.json").read_text())
    plan_hash = hashlib.sha256((HERE / "PREREGISTRATION.json").read_bytes()).hexdigest()
    main = main.replace("A137", "A171")
    main = replace_one(main, "mod observer;", "mod observer;\nmod d1;")
    main = replace_one(
        main,
        "9c807249e563b91d62fc023353dd73478870bf5b2d506617eb605bca00b09d03",
        plan_hash,
    )
    main = replace_one(
        main,
        '"ciphertext_words_persisted": false',
        '"ciphertext_words_persisted": true',
    )
    main = replace_one(
        main,
        '"observer_source_sha256": observer::hash_bytes(include_bytes!("observer.rs")),',
        '"observer_source_sha256": observer::hash_bytes(include_bytes!("observer.rs")),\n        "d1_source_sha256": observer::hash_bytes(include_bytes!("d1.rs")),\n        "d1_shares_actual_window_key": true,',
    )
    main = replace_one(
        main,
        "let mut direct_passed = 0;",
        "let mut direct_passed = 0;\n    let mut d1_passed = 0;",
    )
    main = replace_one(
        main,
        "let order = arm_order(fixture_index, order_offset);",
        "let order = d1::arm_order(fixture_index, order_offset);",
    )
    main = replace_one(
        main,
        "let mut direct = None;",
        "let mut direct = None;\n        let mut difference_arm = None;",
    )
    marker = "                _ => unreachable!(),\n            }\n        }\n        let (direct_outputs"
    main = replace_one(
        main,
        marker,
        "                3 => { difference_arm = Some(d1::select(&left, &right, &control, &window_key, &server.key_switching_key, bsk)); }\n"
        + marker,
    )
    main = replace_one(
        main,
        "// No secret-key diagnostic, hash, or result output ran until all three arm timers stopped.",
        'let (d1_outputs, d1_control, d1_metrics, d1_trace) = difference_arm.expect("D1 arm executed");\n        // All four server arms complete before client diagnostics; timing is invalid.',
    )
    main = replace_one(
        main,
        "let mut direct_ok = true;",
        "let mut direct_ok = true;\n        let mut d1_ok = true;",
    )
    main = replace_one(
        main,
        "direct_ok &= lane_pass(d, &direct_outputs[lane]) && d.decoded == s.decoded;",
        "let delta_audit = phase_audit(&big_secret, &d1_outputs[lane], expected[lane], delta);\n            d1_ok &= lane_pass(delta_audit, &d1_outputs[lane]) && delta_audit.decoded == s.decoded;\n            direct_ok &= lane_pass(d, &direct_outputs[lane]) && d.decoded == s.decoded;",
    )
    main = replace_one(
        main,
        '"direct": audit_json(d, &direct_outputs[lane], delta),',
        '"direct": audit_json(d, &direct_outputs[lane], delta),\n                "direct_d1": audit_json(delta_audit, &d1_outputs[lane], delta),',
    )
    main = replace_one(
        main,
        "let observer_ok = direct_observer_ok && convolution_observer_ok;",
        "let d1_control_equal = lwe_bitwise_equal(&d1_control, &direct_control);\n        let d1_observer_ok = d1::observe(fixture, &left, &right, &control, &d1_control, &d1_outputs, &d1_trace, &glwe_secret, &small_secret.as_view(), parameters);\n        let observer_ok = direct_observer_ok && convolution_observer_ok && d1_observer_ok;",
    )
    main = replace_one(
        main,
        'direct_passed += usize::from(direct_class == "pass");',
        'let d1_class = classify_case(support_ok, prerequisites && direct_class == "pass" && d1_control_equal && d1_metrics.pass() && d1_observer_ok, d1_ok);\n        d1_passed += usize::from(d1_class == "pass");\n        direct_passed += usize::from(direct_class == "pass");',
    )
    main = replace_one(
        main,
        '"direct_class": direct_class, "convolution_class": convolution_class,',
        '"direct_class": direct_class, "convolution_class": convolution_class,\n            "d1_class":d1_class,"d1_ok":d1_ok,"d1_control_bitwise_equal":d1_control_equal,\n            "d1_observer_pass":d1_observer_ok,"d1_counters":d1_metrics.json(),',
    )
    main = replace_one(
        main,
        "let pass = direct_passed == FIXTURES.len() && observer_failures == 0;",
        "let pass = direct_passed == FIXTURES.len() && d1_passed == FIXTURES.len() && observer_failures == 0;",
    )
    main = main.replace(
        "PASS_DIRECT_SINGLE_KEY_COMPONENT", "PASS_D1_SINGLE_KEY_COMPONENT"
    ).replace("FAIL_DIRECT_COMPONENT", "FAIL_D1_COMPONENT")
    main = replace_one(
        main,
        '"fixture_cases": FIXTURES.len(), "direct_passed": direct_passed,',
        '"fixture_cases": FIXTURES.len(), "direct_passed": direct_passed,"d1_passed":d1_passed,\n        "primitives_per_fixture":{"pfks":28,"ks":7,"br":7,"samples":16},',
    )
    main = replace_one(
        main,
        '"direct arm passed {direct_passed}/{} cases",',
        '"D1 arm passed {d1_passed}/{} cases; D2 direct passed {direct_passed}",',
    )
    main = replace_one(
        main,
        '"arms": ["direct_window", "convolution_a108", "scalar_d2"],',
        '"arms": ["direct_window", "convolution_a108", "scalar_d2", "direct_d1"],',
    )
    main = replace_one(
        main,
        '"direct_counters": {"pfks":8',
        '"d1_counters":{"pfks":4,"ks":1,"br":1,"extract":4,"glwe_add":3,"lwe_sub":4,"lwe_addback":4},\n            "direct_counters": {"pfks":8',
    )
    main = main.replace(
        "//! A171 snapshot-only successor of A127: direct-window PFKS versus frozen convolution and scalar D2 controls.",
        "//! A171 D1 successor: same-window difference PFKS plus exact original-left add-back.",
    )
    main = main.replace(
        "//! A171 adds direct-window PFKS and coefficientwise modulus-switch support audit.",
        "//! D2/scalar/convolution server functions and observer are frozen A137 controls.",
    )
    helpers = observer[
        observer.index("/// Extend coefficients") : observer.index("fn center(")
    ]
    helpers += observer[
        observer.index("fn glwe_phase(") : observer.index("fn public_statistics(")
    ]
    d1 = (
        "//! A171 local client observer; native ring identities, no tail or key-membership proof.\nuse super::*;\n\n"
        + helpers
        + (HERE / "d1_body.rs.in").read_text()
    )
    (DEST / "src").mkdir(parents=True, exist_ok=True)
    (DEST / ".cargo").mkdir(exist_ok=True)
    for name, data in [
        ("src/main.rs", main),
        ("src/observer.rs", observer),
        ("src/d1.rs", d1),
    ]:
        (DEST / name).write_text(data)
    for name in ["Cargo.toml", "Cargo.lock"]:
        data = (
            (ORIGIN / name)
            .read_text()
            .replace("a137_pfks_runtime_error_observer", "a171_pfks_d1_component")
        )
        (DEST / name).write_text(data)
    (DEST / ".cargo/config.toml").write_text(
        '[build]\ntarget-dir = "../target-a171-only"\njobs = 1\n\n[net]\noffline = true\n'
    )
    # Syntax/format only. Skip children so the frozen A137 observer bytes stay exact.
    subprocess.run(
        [
            "rustfmt",
            "--edition",
            "2021",
            "--config",
            "skip_children=true",
            str(DEST / "src/main.rs"),
            str(DEST / "src/d1.rs"),
        ],
        check=True,
    )
    assert plan["all_four_arms_per_fixture"] == {
        "pfks": 28,
        "ks": 7,
        "br": 7,
        "samples": 16,
    }
    control_path = (
        ROOT / "tmp/a167-a137-execution-readiness/runtime-validation/verify.py"
    )
    control = control_path.read_text()
    assert (
        hashlib.sha256(control.encode()).hexdigest()
        == "38bac960a9dedf44ab671d963c8b9afdc4703a1713441ab499f71f1553b01611"
    )
    successor = replace_one(
        control,
        "HERE = Path(__file__).resolve().parent",
        'HERE = Path(__file__).resolve().parents[2] / "tmp/a167-a137-execution-readiness/runtime-validation"',
    )
    successor = replace_one(
        successor, "-(1<<23),(1<<23)-1,'body digit'", "-(1<<23),(1<<23),'body digit'"
    )
    (HERE / "control_oracle.py").write_text(successor)
    arithmetic = (ORIGIN / "validate.py").read_text()
    modified = replace_one(
        arithmetic,
        "def validate_process(path):\n    rows = [\n        json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()\n    ]",
        "def validate_rows(rows):",
    )
    # Disable inherited CLI, which still refers to the original path-taking API.
    modified = modified[: modified.index('\n\nif __name__ == "__main__":')] + "\n"
    (HERE / "control_arithmetic.py").write_text(modified)
    patch = "".join(
        difflib.unified_diff(
            control.splitlines(True),
            successor.splitlines(True),
            fromfile=str(control_path.relative_to(ROOT)),
            tofile="control_oracle.py",
        )
    )
    patch += "".join(
        difflib.unified_diff(
            arithmetic.splitlines(True),
            modified.splitlines(True),
            fromfile="A137/validate.py",
            tofile="control_arithmetic.py",
        )
    )
    (HERE / "CONTROL_ORACLE.patch").write_text(patch)


if __name__ == "__main__":
    materialize()
