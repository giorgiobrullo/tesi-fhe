#!/usr/bin/env python3
"""Validate and summarize the frozen A115 HElib context-envelope result."""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULT = HERE / "artifacts/a115_context_envelope_2026-09-03.json"
BUILD = HERE / "artifacts/BUILD_REPORT.json"
SECURITY_FLOOR = 128.0
EXPECTED_REQUESTED_PREFIX = [300, 400, 500, 600, 800, 1000]
EXPECTED_BINARY_SHA256 = (
    "727f8177d9592834cb7fbe298563ba22424e185b2db531946057563e0bb18516"
)


def analyze() -> dict[str, object]:
    result = json.loads(RESULT.read_text())
    build = json.loads(BUILD.read_text())
    if result["binary_sha256"] != EXPECTED_BINARY_SHA256:
        raise AssertionError("result binary hash drift")
    if build["binary"]["sha256"] != EXPECTED_BINARY_SHA256:
        raise AssertionError("build binary hash drift")
    if result["keygen"] or result["fhe_eval"]:
        raise AssertionError("A115 must remain context-only")
    if result["candidate"] != {
        "m": 81920,
        "ord_p": 2,
        "p": 8191,
        "phi_m": 32768,
        "slots": 16384,
    }:
        raise AssertionError("candidate geometry drift")

    rows = result["rows"]
    requested = [row["requested_bits"] for row in rows]
    if requested != EXPECTED_REQUESTED_PREFIX:
        raise AssertionError("executed sweep is not the preregistered prefix")

    consecutive_fails = 0
    first_fail_index = None
    for index, row in enumerate(rows):
        expected = (
            "SECURITY_ENVELOPE_PASS"
            if row["security_bits_helib"] >= SECURITY_FLOOR
            else "SECURITY_ENVELOPE_FAIL"
        )
        if row["classification"] != expected:
            raise AssertionError(f"classification drift at row {index}")
        if not 0.0 < row["observed_load_1m"] <= 24.0:
            raise AssertionError(f"load gate drift at row {index}")
        if row["classification"] == "SECURITY_ENVELOPE_FAIL":
            if first_fail_index is None:
                first_fail_index = index
            consecutive_fails += 1
        else:
            consecutive_fails = 0

    if first_fail_index is None or consecutive_fails != 2:
        raise AssertionError("stopping rule was not reached")
    if not result["stopping_rule"]["triggered"]:
        raise AssertionError("stopping-rule record drift")
    if result["stopping_rule"]["stopped_after_requested_bits"] != requested[-1]:
        raise AssertionError("stopping point drift")

    passing = [row for row in rows if row["classification"].endswith("PASS")]
    failing = [row for row in rows if row["classification"].endswith("FAIL")]
    max_pass = max(passing, key=lambda row: row["ctxt_prime_bits"])
    min_fail = min(failing, key=lambda row: row["ctxt_prime_bits"])

    return {
        "artifact": "A115",
        "status": result["status"],
        "rows": len(rows),
        "geometry": result["candidate"],
        "max_observed_passing_context": max_pass,
        "min_observed_failing_context": min_fail,
        "unresolved_ctxt_prime_bit_interval": [
            max_pass["ctxt_prime_bits"],
            min_fail["ctxt_prime_bits"],
        ],
        "stopping_rule_pass": True,
        "interpretation": (
            "A security envelope exists, but comparison-circuit capacity/noise remains unknown"
        ),
    }


if __name__ == "__main__":
    print(json.dumps(analyze(), indent=2, sort_keys=True))
