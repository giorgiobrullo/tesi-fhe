"""Source-pinned, light static gate. Does not launch Rust or FHE."""

import hashlib
import json
from pathlib import Path
import unittest

import model

HERE = Path(__file__).resolve().parent


def check_sources():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())["files"]
    for item in pins:
        assert (
            hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest()
            == item["sha256"]
        ), item["path"]
    root = HERE.parents[1]
    source = (
        root / "tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs"
    ).read_text()
    first = source.index("fn a34_top_classifier_slot_lut(")
    last = source.index("fn boolean_and_lut(", first)
    assert (HERE / "src/a34_tables.rs").read_text().endswith(source[first:last])
    assert (HERE / "a135_model.py").read_bytes() == (
        root / "tmp/a135-nibble-selector-feasibility/model.py"
    ).read_bytes()
    lock = (root / "tmp/a130-a125-independent-audit/candidate/Cargo.lock").read_text()
    assert (HERE / "Cargo.lock").read_text() == lock.replace(
        'name = "a125_low_extraction_gate"', 'name = "a138_nibble_ingress_gate"', 1
    )
    return len(pins)


def main():
    count = check_sources()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.discover(str(HERE), "test_model.py")
    )
    if not result.wasSuccessful():
        raise SystemExit(1)
    report = dict(
        status="STATIC_PASS_UNCOMPILED_NO_FHE",
        source_pins=count,
        tests=result.testsRun,
        score_centers_both_arms=8192,
        nibble_address_checks_both_arms=4064,
        actual_a34_n4_category_states=2401,
        composed_n4_score_fixtures_both_arms=480,
        helper_counterexample=model.helper_counterexample(),
        original_msb_only_counterexample=model.shared_error_counterexample(),
        joint_composed_counterexample=model.composed_error_counterexample(),
        first_n4_runtime_br_ks_per_fixture=[55, 63, 55],
        next_gate="Compile isolated source, then eight N4 fixtures with actual noisy packed inputs and both adapters; no service or tail claim.",
    )
    (HERE / "STATIC_RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("status", "source_pins", "tests")}))


if __name__ == "__main__":
    main()
