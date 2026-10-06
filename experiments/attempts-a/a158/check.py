"""Preserve the bounded synthetic schema gate; no child, build or encryption."""

import hashlib
import io
import json
import os
from pathlib import Path
import unittest

from schema import U, verify, verify_sources
from synthetic import make_record

HERE = Path(__file__).resolve().parent


def write_new(path, value):
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
    ) as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")


def main():
    artifacts = HERE / "artifacts"
    assert not artifacts.exists(), (
        "Preserve evidence; rerun test_schema.py for verification"
    )
    count = verify_sources()
    log = io.StringIO()
    tests = unittest.TextTestRunner(stream=log, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromName("test_schema")
    )
    if not tests.wasSuccessful():
        print(log.getvalue())
        raise SystemExit(1)
    artifacts.mkdir(mode=0o700)
    scenarios = []
    for name, args in [
        ("safe", {}),
        ("native_pass_ms_fail", dict(error=1000 * U, displacement64=True)),
        ("coherent_impossible_key", dict(impossible_small_aggregate=True)),
    ]:
        record, expected = make_record(**args)
        result = verify(record, expected)
        write_new(artifacts / f"{name}.record.json", record)
        write_new(artifacts / f"{name}.expected-bindings.json", expected)
        write_new(
            artifacts / f"{name}.a156-public-input.json",
            result.pop("a156_public_input"),
        )
        write_new(artifacts / f"{name}.result.json", result)
        scenarios.append(dict(name=name, **result))
    final = dict(
        status="STATIC_SCHEMA_AND_SOURCE_PLAN_PASS",
        source_pins=count,
        tests_run=tests.testsRun,
        test_output=log.getvalue(),
        scenarios=scenarios,
        actual_rust_typecheck=False,
        actual_fhe_execution=False,
        actual_input_records=False,
        actual_sampler_p_fail=None,
        artifacts_sha256={
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(artifacts.iterdir())
        },
    )
    write_new(HERE / "STATIC_RESULT.json", final)
    print(
        json.dumps(
            {
                key: value
                for key, value in final.items()
                if key not in ("test_output", "artifacts_sha256")
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
