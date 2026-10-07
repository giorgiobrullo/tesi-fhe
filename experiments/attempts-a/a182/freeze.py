"""Freeze A182 source/readiness only; no child, native probe, build or network."""

import json
from pathlib import Path
import binding as b


def write(name, value):
    (b.HERE / name).write_text(json.dumps(value, indent=2) + "\n")


def main():
    b.need(not (b.HERE / "MANIFEST.json").exists(), "A182 already frozen")
    b.eq(
        b.digest(b.BASE / "ARTIFACT_MANIFEST.json"),
        b.ARTIFACT_HASH,
        "A185 frozen artifact",
    )
    source, files = b.frozen_replay().source_check()
    b.eq(source, b.SOURCE_ID, "actual A185 source")
    paths = [
        b.BASE / "ARTIFACT_MANIFEST.json",
        b.BASE / "SOURCE_MANIFEST.json",
        b.BASE / "SOURCE_PINS.json",
    ]
    paths += [
        b.BASE / name for name in b.load(b.BASE / "ARTIFACT_MANIFEST.json")["files"]
    ]
    paths += [Path(name) for name in b.load(b.BASE / "SOURCE_PINS.json")["files"]]
    for base, names in [
        (
            b.HERE.parent / "a171-pfks-d1-runtime-gate/execution-readiness",
            ("binding.py", "run_gate.py", "verify.py", "MANIFEST.json"),
        ),
        (
            b.HERE.parent / "a174-a171-three-process-readiness",
            ("binding.py", "run_gate.py", "verify.py", "MANIFEST.json"),
        ),
    ]:
        paths += [base / name for name in names]
    write(
        "SOURCE_PINS.json",
        dict(
            schema="a182-source-input-pins-v1",
            files={str(p): b.digest(p) for p in sorted(set(paths))},
            actual_new_runtime_logs_read=False,
        ),
    )
    plan = b.load(b.BASE / "EXECUTION_PLAN.json")
    write(
        "EXECUTION_PLAN.json",
        dict(
            schema="a182-fixed-first-key-v1",
            implementation="A185",
            semantic_contract="A175",
            source_sha256=b.SOURCE_ID,
            artifact_manifest_sha256=b.ARTIFACT_HASH,
            producer_execution_plan=plan,
            outer_schema=b.SCHEMA,
            run_id=b.RUN_ID,
            run_dir=str(b.fixed_paths()[2]),
            exact_environment=b.ENV,
            minimum_free_bytes=b.MIN_FREE_BYTES,
            records=17703,
            scores=28,
            consumers=1568,
            ledger=dict(BR=5124, KS=3360, samples=6020),
            actual_binary_sha256=None,
            actual_binary_hash_supplied_only_after_root_build=True,
            first_key_no_retry=True,
            automatic_expansion=False,
            timed_benchmark=False,
            required_successor_helper_equivalence=True,
            actual_execution=False,
        ),
    )
    names = [
        "binding.py",
        "run_gate.py",
        "verify.py",
        "test_envelope.py",
        "test_semantics.py",
        "freeze.py",
        "README.md",
        "SOURCE_PINS.json",
        "EXECUTION_PLAN.json",
        "DESIGN_HISTORY.json",
        "PEER_REVIEW.json",
        "STATIC_TESTS.log",
        "STATIC_RESULT.json",
        "LINT.log",
        "ENVELOPE_TESTS.log",
    ]
    names += [
        str(p.relative_to(b.HERE))
        for p in (b.HERE / "design-history").rglob("*")
        if p.is_file()
    ]
    write(
        "MANIFEST.json",
        dict(
            schema="a182-source-static-freeze-v1",
            implementation="A185",
            source_sha256=b.SOURCE_ID,
            files={n: b.digest(b.HERE / n) for n in sorted(names)},
            excluded=[
                "MANIFEST.json",
                "runs/",
                "artifacts/",
                "test-artifacts/",
                "__pycache__/",
                ".ruff_cache/",
            ],
            actual_fhe=False,
        ),
    )
    print(
        json.dumps(
            dict(
                manifest_sha256=b.digest(b.HERE / "MANIFEST.json"),
                leaves=len(names),
                source_pins=len(set(paths)),
                actual_binary_sha256=None,
                actual_execution=False,
            )
        )
    )


if __name__ == "__main__":
    main()
