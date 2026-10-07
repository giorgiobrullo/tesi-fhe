"""Freeze A166 source and bounded synthetic evidence once; never build or run FHE."""

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
    ) as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    for name in (
        "SOURCE_MANIFEST.json",
        "candidate/SOURCE_DIGEST.txt",
        "STATIC_RESULT.json",
        "ARTIFACT_MANIFEST.json",
        "static-artifacts",
    ):
        assert not (HERE / name).exists(), "never overwrite frozen evidence"
    pins = audit.verify_origins()
    manifest = audit.source_manifest()
    source = audit.source_id(manifest)
    write_source(
        "SOURCE_MANIFEST.json", json.dumps(manifest, sort_keys=True, indent=2) + "\n"
    )
    write_source("candidate/SOURCE_DIGEST.txt", source + "\n")
    assert audit.verify_source() == source
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromName("test_gate")
    )
    artifacts = HERE / "static-artifacts"
    artifacts.mkdir(mode=0o700)
    write_source("static-artifacts/unit-tests.log", stream.getvalue())
    assert result.wasSuccessful(), stream.getvalue()
    from test_gate import synthetic_p1
    from synthetic_p0 import synthetic_chain
    from replay import ALPHA, verify_p1

    cases = []
    chain = synthetic_chain()
    for label, error in (
        ("zero_error", 0),
        ("lower_endpoint", -ALPHA),
        ("upper_first_bad", ALPHA),
    ):
        args = synthetic_p1(chain, error)
        observed = verify_p1(*args)
        write_new(
            artifacts / f"{label}.json",
            dict(
                evidence_kind="SYNTHETIC_NO_KEYS_NO_FHE",
                record=args[0],
                replay=observed,
            ),
        )
        cases.append(
            dict(
                name=label,
                p1_selected_consumer_gate_pass=observed[
                    "p1_selected_consumer_gate_pass"
                ],
            )
        )
    summary = dict(
        status="SOURCE_AND_SYNTHETIC_READY_NO_BUILD_OR_FHE",
        source_sha256=source,
        source_files=len(manifest),
        **pins,
        tests_run=result.testsRun,
        cases=cases,
        rustfmt_parse_only=True,
        ruff_check_pass=True,
        cargo_invoked=False,
        typecheck=False,
        actual_fhe_execution=False,
        inherited_runtime_success=False,
        actual_sampler_p_fail=None,
        fixed_key_p_fail=None,
        pipeline_p_fail=None,
        unit_tests_log_sha256=sha(artifacts / "unit-tests.log"),
        next_gate="Root exclusive offline selected-bin check/release then one new fresh-key P1 run; inspect independent P0+P1 replay before expansion.",
    )
    write_source(
        "STATIC_RESULT.json", json.dumps(summary, sort_keys=True, indent=2) + "\n"
    )
    files = {
        str(p.relative_to(HERE)): sha(p) for p in sorted(HERE.rglob("*")) if p.is_file()
    }
    write_source(
        "ARTIFACT_MANIFEST.json", json.dumps(files, sort_keys=True, indent=2) + "\n"
    )
    print(
        json.dumps(
            dict(
                source_sha256=source,
                artifact_files=len(files),
                tests=result.testsRun,
                manifest_sha256=sha(HERE / "ARTIFACT_MANIFEST.json"),
            )
        )
    )


if __name__ == "__main__":
    main()
