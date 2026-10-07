#!/usr/bin/env python3
"""Read-only static gate for the A124 A66 thread-sweep harness."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import sys
from types import ModuleType


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
HARNESS_FILES = (
    "Cargo.toml",
    ".cargo/config.toml",
    "src/main.rs",
    "a124_driver.py",
    "a124_analyze.py",
    "a124_static_audit.py",
    "tests/test_a124_static.py",
    "frozen-inputs.sha256",
)


def _load(name: str, path: pathlib.Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_guard_audit() -> dict[str, object]:
    """The Rust binary embeds A66 source hashes; they must equal the frozen manifest."""

    main_rs = (HERE / "src" / "main.rs").read_text()
    embedded = dict(
        re.findall(r'"(a66_[a-z]+)",\s*A66_[A-Z]+,\s*"([0-9a-f]{64})"', main_rs)
    )
    manifest = dict(
        (line.split("  ", 1)[1], line.split("  ", 1)[0])
        for line in (HERE / "frozen-inputs.sha256").read_text().splitlines()
        if line.strip()
    )
    prefix = "tmp/a66-a62-latency-ready-prototype/"
    expected = {
        "a66_private": manifest[prefix + "src/private_argmin.rs"],
        "a66_fhe": manifest[prefix + "src/a53_scan/fhe.rs"],
        "a66_scan": manifest[prefix + "src/a53_scan.rs"],
        "a66_lock": manifest[prefix + "Cargo.lock"],
    }
    mismatches = {key: (embedded.get(key), value) for key, value in expected.items()
                  if embedded.get(key) != value}
    return {"embedded": embedded, "mismatches": mismatches, "pass": not mismatches}


def summary() -> dict[str, object]:
    driver = _load("_a124_driver_audit", HERE / "a124_driver.py")
    pinned = driver.verify_frozen_inputs()
    plan = driver.dry_plan()
    guards = source_guard_audit()
    harness = {name: sha256_file(HERE / name) for name in HARNESS_FILES}
    scene_128 = plan["scenes"]["128"]
    checks = {
        "manifest_pinned_inputs": len(pinned),
        "source_guards_match_manifest": guards["pass"],
        "n127_frontier_minima_frozen": [r["expected_min_score"] for r in plan["scenes"]["127"]["frontier"]] == [2, 3, 4, 5, 7],
        "n128_extra_template_source": scene_128["extra_template_source"],
        "n128_keeps_max_norm": scene_128["max_gallery_norm2"] == plan["scenes"]["127"]["max_gallery_norm2"],
        "n128_frontier_unchanged_vs_127": [r["expected_code"] for r in scene_128["frontier"]]
        == [r["expected_code"] for r in plan["scenes"]["127"]["frontier"]],
        "n64_has_accept_and_reject": plan["scenes"]["64"]["accepted_probes"] > 0
        and plan["scenes"]["64"]["rejected_probes"] > 0,
        "sweep_cells": len(plan["sweep_cells"]),
        "sweep_queries_total": plan["sweep_queries_total"],
        "smoke_queries": plan["schedules"]["smoke"]["queries"],
    }
    passed = (
        guards["pass"]
        and checks["n127_frontier_minima_frozen"]
        and checks["n128_keeps_max_norm"]
        and checks["n128_frontier_unchanged_vs_127"]
        and checks["n64_has_accept_and_reject"]
        and checks["sweep_cells"] == 21
    )
    return {
        "status": "PASS_STATIC_NO_BUILD_OR_FHE_CLAIM" if passed else "FAIL_STATIC",
        "variant": "a124_a66_thread_sweep",
        "checks": checks,
        "source_guards": guards,
        "harness_sha256": harness,
        "promotion_allowed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result = summary()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result["status"])
    return 0 if result["status"].startswith("PASS") else 2


if __name__ == "__main__":
    raise SystemExit(main())
