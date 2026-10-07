"""Freeze the bounded A168 pilot source and synthetic evidence; no builds/crypto."""

import io
import json
import os
import unittest

import audit
from audit import HERE, sha
from run_gate import write_new


def write_source(name, value):
    with os.fdopen(
        os.open(HERE / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
    ) as f:
        f.write(value)
        f.flush()
        os.fsync(f.fileno())


def main():
    for name in (
        "SOURCE_MANIFEST.json",
        "candidate/SOURCE_DIGEST.txt",
        "READINESS.json",
        "ARTIFACT_MANIFEST.json",
        "static-artifacts",
    ):
        assert not (HERE / name).exists(), "preserve frozen artifact"
    pins = audit.verify_origins()
    manifest = audit.source_manifest()
    source = audit.source_id(manifest)
    write_source(
        "SOURCE_MANIFEST.json", json.dumps(manifest, sort_keys=True, indent=2) + "\n"
    )
    write_source("candidate/SOURCE_DIGEST.txt", source + "\n")
    assert audit.verify_source() == source
    out = io.StringIO()
    result = unittest.TextTestRunner(stream=out, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromName("test_gate")
    )
    artifacts = HERE / "static-artifacts"
    artifacts.mkdir(mode=0o700)
    write_source("static-artifacts/unit-tests.log", out.getvalue())
    assert result.wasSuccessful(), out.getvalue()
    from test_gate import synthetic_records
    from validate import inspect_records

    records = synthetic_records()
    observed = inspect_records(records, "1" * 64, "2" * 64, "synthetic")
    write_new(
        artifacts / "synthetic.json",
        dict(
            evidence_kind="SYNTHETIC_INTEGER_DURATIONS_NO_KEYS_OR_TIMERS",
            records=records,
            validation=observed,
        ),
    )
    ready = dict(
        status="RUNNABLE_SOURCE_PILOT_READY_GUARD_UNQUALIFIED",
        source_sha256=source,
        source_files=len(manifest),
        upstream_source_pins=pins,
        synthetic_tests=result.testsRun,
        rustfmt_parse_only=True,
        ruff_pass=True,
        cargo_invoked=False,
        actual_keys=False,
        actual_timing_runs=0,
        actual_speedup=None,
        guard_status="UNQUALIFIED_NO_ALIGNED_OS_COLLECTOR",
        speedup_promotion_allowed=False,
        exact_remaining_controlled_trial_blocker="source-backed OS collector qualification and shared monotonic arm alignment, then a separately frozen multi-key confirmation plan",
        first_command="cargo check --offline --locked --no-default-features --bin a168_refresh_pair_pilot -j 1 (candidate directory; root exclusive build)",
    )
    write_source("READINESS.json", json.dumps(ready, sort_keys=True, indent=2) + "\n")
    leaves = {
        str(p.relative_to(HERE)): sha(p) for p in sorted(HERE.rglob("*")) if p.is_file()
    }
    write_source(
        "ARTIFACT_MANIFEST.json", json.dumps(leaves, sort_keys=True, indent=2) + "\n"
    )
    print(
        json.dumps(
            dict(
                source_sha256=source,
                tests=result.testsRun,
                files=len(leaves),
                artifact_manifest_sha256=sha(HERE / "ARTIFACT_MANIFEST.json"),
            )
        )
    )


if __name__ == "__main__":
    main()
