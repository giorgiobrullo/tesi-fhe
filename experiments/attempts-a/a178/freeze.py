"""Freeze only local source/pins; performs no native compilation or process probe."""

import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(name, value):
    (HERE / name).write_text(json.dumps(value, indent=2) + "\n")


def main():
    if (HERE / "ARTIFACT_MANIFEST.json").exists():
        raise SystemExit("Already frozen; preserve this source")
    origins = {
        "collector.c": "a170-darwin-cpu-collector/collector.c",
        "raw_check.py": "a170-darwin-cpu-collector/check.py",
        "arm_clock.h": "a170-darwin-cpu-collector/arm_clock.h",
        **{
            name: "a172-darwin-collector-lifecycle-fixture/" + name
            for name in (
                "fixture.c",
                "replay.py",
                "run.py",
                "test_replay.py",
                "test_runner.py",
            )
        },
    }
    upstream = [HERE.parent / name for name in origins.values()]
    upstream += [
        HERE.parent / directory / name
        for directory, names in {
            "a170-darwin-cpu-collector": [
                "SOURCE_MANIFEST.json",
                "SOURCE_PINS.json",
                "QUALIFICATION.md",
            ],
            "a172-darwin-collector-lifecycle-fixture": [
                "SOURCE_MANIFEST.json",
                "SOURCE_PINS.json",
                "ARTIFACT_MANIFEST.json",
                "PREREGISTRATION.json",
            ],
            "a177-native-lifecycle-independent-audit": [
                "DIAGNOSIS.md",
                "DIAGNOSIS.json",
                "ARTIFACT_MANIFEST.json",
            ],
        }.items()
        for name in names
    ]
    # Include exactly the already pinned public SDK inputs; no new lookup or sampling.
    inherited = json.loads(
        (
            HERE.parent / "a172-darwin-collector-lifecycle-fixture/SOURCE_PINS.json"
        ).read_text()
    )
    upstream += [
        Path(row["path"])
        for row in inherited["inputs"]
        if "/MacOSX.sdk/" in row["path"]
    ]
    write(
        "SOURCE_PINS.json",
        dict(
            schema="a178.source-pins.v1",
            inputs=[dict(path=str(path), sha256=sha(path)) for path in upstream],
        ),
    )
    patch = []
    for name, original in origins.items():
        old = HERE.parent / original
        patch.extend(
            difflib.unified_diff(
                old.read_text().splitlines(True),
                (HERE / name).read_text().splitlines(True),
                fromfile=original,
                tofile="a178/" + name,
            )
        )
    (HERE / "SOURCE_CHANGES.patch").write_text("".join(patch))
    source_names = [
        "collector.c",
        "fixture.c",
        "arm_clock.h",
        "raw_check.py",
        "replay.py",
        "run.py",
        "test_replay.py",
        "test_runner.py",
        "test_changed_rules.py",
        "freeze.py",
        "README.md",
        "PREREGISTRATION.json",
        "SOURCE_PINS.json",
        "SOURCE_CHANGES.patch",
    ]
    write(
        "SOURCE_MANIFEST.json",
        dict(
            schema="a178.source-manifest.v1",
            files=[dict(path=name, sha256=sha(HERE / name)) for name in source_names],
        ),
    )
    source = sha(HERE / "SOURCE_MANIFEST.json")
    (HERE / "SOURCE_DIGEST.txt").write_text(source + "\n")
    (HERE / "source_identity.h").write_text('#define A178_SOURCE_ID "' + source + '"\n')
    write(
        "READINESS.json",
        dict(
            schema="a178.readiness.v1",
            source_id=source,
            source_only=True,
            native_fixture_compiled=False,
            native_collector_compiled=False,
            native_execution_performed=False,
            synthetic_tests=22,
            original_a172="FAILED_PRESERVED",
            changed_terminal_rule=True,
            whole_terminal_read_after_wnowait_required=True,
            cpu_units_justified=False,
            settled_accounting_proven=False,
            collector_qualified=False,
            next_gate="Root compile both new binaries and safe CLI gates; then one fresh order-12; stop on first negative.",
        ),
    )
    leaves = sorted(path for path in HERE.iterdir() if path.is_file())
    write(
        "ARTIFACT_MANIFEST.json",
        dict(
            schema="a178.artifact-manifest.v1",
            files=[dict(path=path.name, sha256=sha(path)) for path in leaves],
        ),
    )
    print(
        json.dumps(
            dict(
                source_id=source,
                source_leaves=len(source_names),
                pins=len(upstream),
                artifact_leaves=len(leaves),
                manifest_sha256=sha(HERE / "ARTIFACT_MANIFEST.json"),
            )
        )
    )


if __name__ == "__main__":
    main()
