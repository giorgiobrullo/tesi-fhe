#!/usr/bin/env python3
"""Read-only source and differential clear-ring checks; never invokes a compiler or FHE."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REFERENCE_FUNCTIONS = (
    "signed_cell_mask", "packed_selector_masks", "a30_scalar_selector_masks",
    "polynomial_fft_wrapping_mul", "spread_glwe", "scalar_d2_select_tuple", "packed_d2_select",
)


def function(source: str, name: str) -> str:
    match = re.search(r"^fn " + re.escape(name) + r"[\s\S]*?^}", source, re.MULTILINE)
    if match is None:
        raise ValueError(f"missing function {name}")
    return match.group(0)


def verify_pins() -> int:
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())
    for name, record in pins.items():
        path = Path(record["path"])
        if not path.is_absolute():
            path = ROOT / path
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != record["sha256"]:
            raise ValueError(f"frozen source drift: {name}")
    return len(pins)


def audit() -> dict:
    source = (HERE / "src/main.rs").read_text()
    parent = (ROOT / "tmp/a120-packed-pfks-interior-margin-gate/src/main.rs").read_text()
    for name in REFERENCE_FUNCTIONS:
        if function(source, name) != function(parent, name):
            raise ValueError(f"reference datapath changed: {name}")
    prereg_hash = hashlib.sha256((HERE / "PREREGISTRATION.json").read_bytes()).hexdigest()
    if prereg_hash not in source:
        raise ValueError("preregistration digest is not embedded")
    direct = function(source, "direct_window_d2_select")
    if "spread_glwe(" in direct or "fft" in direct.lower():
        raise ValueError("direct arm still performs post-PFKS convolution")
    for fragment in ["polynomial_wrapping_monic_monomial_mul_assign", "private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext", "MonomialDegree(lane * BOX_SIZE)"]:
        if fragment not in direct:
            raise ValueError(f"missing direct arm operation {fragment}")
    support = function(source, "effective_rotation_degree")
    if support.count("pbs_modulus_switch(") != 2 or "secret.as_ref()" not in support:
        raise ValueError("support classification lost coefficientwise modulus switch")
    path = ROOT / "tmp/a121-direct-window-pfks/model.py"
    spec = importlib.util.spec_from_file_location("a127_reference_a121", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    left = (0, 15 * module.SCORE_DELTA, 7 * module.SCORE_DELTA, 127 * module.ID_DELTA)
    right = (4 * module.SCORE_DELTA, 0, 15 * module.SCORE_DELTA, module.ID_DELTA)
    body = module.assemble_direct(left, right)
    assert body == module.assemble_a108(left, right)
    checked = 0
    for control, expected in [(4, left), (12, right)]:
        for error in range(-63, 64):
            assert module.select(body, control, error) == expected
            checked += 4
    return {
        "status": "PASS_STATIC_SOURCE_DIFFERENTIAL_GATE",
        "source_pins": verify_pins(), "unchanged_reference_functions": len(REFERENCE_FUNCTIONS),
        "mixed_scale_words_checked": checked, "preregistration_sha256": prereg_hash,
        "cargo_run": False, "rustc_run": False, "fhe_run": False,
        "next": "exclusive workload window; offline compile then three noisy processes",
    }


if __name__ == "__main__":
    print(json.dumps(audit(), indent=2, sort_keys=True))
