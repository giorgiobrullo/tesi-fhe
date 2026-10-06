"""Read source pins and exact profile strings; no collector or workload import."""

import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_pins():
    rows = json.loads((HERE / "SOURCE_PINS.json").read_text())["files"]
    for row in rows:
        if sha(Path(row["path"])) != row["sha256"]:
            raise ValueError("source drift: " + row["path"])
    return len(rows)


def profile(path):
    match = re.search(r'A44_PARAMETER_CANONICAL: &str = "([^"]+)";', path.read_text())
    if not match:
        raise ValueError("canonical profile absent")
    return dict(field.split("=", 1) for field in match.group(1).split(";"))


def derive():
    count = verify_pins()
    old = profile(ROOT / "tmp/a62-a53-a44-integrated-prototype/src/private_argmin.rs")
    new = profile(
        ROOT / "tmp/u8-large-gallery-score-gate/candidate/src/private_argmin.rs"
    )
    if old.pop("tfhe-rs") != "0.11.3" or new.pop("tfhe-rs") != "1.7.0":
        raise ValueError("unexpected version")
    if new.pop("modulus_switch") != "standard" or old != new:
        raise ValueError("numeric profile mismatch")
    report = json.loads(
        (
            ROOT / "docs/research-state/2026-09-05/a124-final-guard-audit/REPORT.json"
        ).read_text()
    )
    expected = {
        "PRE_POST_GUARD_VALIDATED": 8,
        "POST_CELL_CPU_ABOVE_THRESHOLD": 12,
        "MISSING_DRIVER_METADATA": 1,
    }
    if report["a128_guard_status_counts"] != expected:
        raise ValueError("A124 preserved audit classification changed")
    if (
        report["within_cell_monitor_saved"]
        or report["original_a124_enforced_post_threshold"]
    ):
        raise ValueError("A124 scope drift")
    return dict(
        status="LOCAL_SOURCE_STATIC_AUDIT_ONLY",
        source_pins=count,
        numeric_A44_profile_equal=True,
        numeric_profile=old,
        protocol_version_fingerprints_equal=False,
        graph_equivalence_proved_by_this_check=False,
        a124_guard_classification_preserved=expected,
        a124_within_cell_evidence_recovered=False,
        os_collector_implemented=False,
        eligible_timing_binary_identified=False,
        execution_authorized=False,
        new_fhe_or_runtime_measurements=0,
    )


if __name__ == "__main__":
    print(json.dumps(derive(), indent=2))
