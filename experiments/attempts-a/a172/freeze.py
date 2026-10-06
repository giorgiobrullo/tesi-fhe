"""Freeze A172 source without invoking C, a native worker, or any OS probe."""

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SDK = Path(
    "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(name, value):
    (HERE / name).write_text(json.dumps(value, indent=2) + "\n")


def main():
    if (HERE / "ARTIFACT_MANIFEST.json").exists():
        raise SystemExit("Frozen artifact: do not rewrite")
    upstream = [
        "tmp/a170-darwin-cpu-collector/" + name
        for name in (
            "collector.c",
            "arm_clock.h",
            "check.py",
            "SOURCE_MANIFEST.json",
            "SOURCE_PINS.json",
            "ARTIFACT_MANIFEST.json",
            "QUALIFICATION.md",
            "README.md",
            "build-artifacts/compile-r1/a170-collector",
        )
    ]
    sdk = [
        "usr/include/" + name
        for name in (
            "libproc.h",
            "sys/resource.h",
            "sys/proc_info.h",
            "sys/wait.h",
            "sys/signal.h",
            "sys/_types.h",
            "pthread.h",
            "poll.h",
            "mach/mach_time.h",
            "mach/host_info.h",
        )
    ]
    files = [ROOT / p for p in upstream] + [SDK / p for p in sdk]
    write(
        "SOURCE_PINS.json",
        dict(
            schema="a172.source-pins.v1",
            inputs=[
                dict(path=str(p), resolved_path=str(p.resolve()), sha256=sha(p))
                for p in files
            ],
        ),
    )
    source_files = [
        "fixture.c",
        "replay.py",
        "run.py",
        "test_replay.py",
        "test_runner.py",
        "freeze.py",
        "PREREGISTRATION.json",
        "SOURCE_PINS.json",
        "README.md",
    ]
    write(
        "SOURCE_MANIFEST.json",
        dict(
            schema="a172.source-manifest.v1",
            files=[dict(path=p, sha256=sha(HERE / p)) for p in source_files],
        ),
    )
    source_id = sha(HERE / "SOURCE_MANIFEST.json")
    (HERE / "SOURCE_DIGEST.txt").write_text(source_id + "\n")
    (HERE / "source_identity.h").write_text(
        '#define A172_SOURCE_ID "' + source_id + '"\n'
    )
    write(
        "READINESS.json",
        dict(
            schema="a172.readiness.v1",
            source_id=source_id,
            source_only=True,
            fixture_compiled=False,
            native_fixture_executed=False,
            synthetic_tests=14,
            a170_compile_is_prior_separate_evidence=True,
            collector_qualified=False,
            settled_accounting_proven=False,
            cpu_units_justified=False,
            next_gate="root native compile and noargs, then first order-12 lifecycle case",
        ),
    )
    leaves = sorted(p for p in HERE.iterdir() if p.is_file())
    write(
        "ARTIFACT_MANIFEST.json",
        dict(
            schema="a172.artifacts.v1",
            files=[dict(path=p.name, sha256=sha(p)) for p in leaves],
        ),
    )
    print(
        json.dumps(
            dict(
                source_id=source_id,
                pins=len(files),
                leaves=len(leaves),
                manifest_sha256=sha(HERE / "ARTIFACT_MANIFEST.json"),
            )
        )
    )


if __name__ == "__main__":
    main()
