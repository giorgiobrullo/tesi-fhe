"""Freeze this source-only artifact; no CPU/process probes or native compilation."""

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SDK = Path(
    "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/"
    "Developer/SDKs/MacOSX.sdk"
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(name, data):
    (HERE / name).write_text(json.dumps(data, indent=2) + "\n")


def main():
    if (HERE / "ARTIFACT_MANIFEST.json").exists():
        raise SystemExit("Already frozen; do not rewrite evidence")
    sdk_files = [
        "usr/include/libproc.h",
        "usr/include/sys/resource.h",
        "usr/include/sys/proc_info.h",
        "usr/include/mach/host_info.h",
        "usr/include/mach/mach_time.h",
        "usr/include/mach/clock_types.h",
        "usr/include/mach/machine.h",
        "usr/include/time.h",
        "usr/include/sys/wait.h",
        "usr/share/man/man3/clock_gettime.3",
        "usr/share/man/man3/sysconf.3",
        "usr/share/man/man3/times.3",
        "usr/share/man/man2/getrusage.2",
        "usr/share/man/man2/wait.2",
        "System/Library/Frameworks/Kernel.framework/Headers/kern/clock.h",
        "System/Library/Frameworks/Kernel.framework/Headers/kern/processor.h",
        "System/Library/Frameworks/Kernel.framework/Headers/sys/resource.h",
    ]
    upstream = [
        "tmp/a157-controlled-runtime-protocol/protocol.py",
        "tmp/a157-controlled-runtime-protocol/PREREGISTRATION.md",
        "tmp/a129-durable-sweep-driver/driver.py",
        "tmp/a129-durable-sweep-driver/README.md",
        "tmp/a168-a133-paired-runtime-readiness/candidate/src/main.rs",
        "tmp/a168-a133-paired-runtime-readiness/PREREGISTRATION.md",
        "tmp/a168-a133-paired-runtime-readiness/run_pilot.py",
        "tmp/a168-a133-paired-runtime-readiness/LAUNCHER_MANIFEST.json",
    ]
    files = [SDK / x for x in sdk_files] + [ROOT / x for x in upstream]
    write(
        "SOURCE_PINS.json",
        {
            "schema": "a170.source-pins.v1",
            "inputs": [
                {"path": str(p), "resolved_path": str(p.resolve()), "sha256": sha(p)}
                for p in files
            ],
        },
    )
    source = [
        "collector.c",
        "arm_clock.h",
        "check.py",
        "test_check.py",
        "freeze.py",
        "SOURCE_PINS.json",
        "QUALIFICATION.md",
    ]
    manifest = {
        "schema": "a170.source-manifest.v1",
        "files": [{"path": p, "sha256": sha(HERE / p)} for p in source],
    }
    write("SOURCE_MANIFEST.json", manifest)
    source_id = sha(HERE / "SOURCE_MANIFEST.json")
    (HERE / "SOURCE_DIGEST.txt").write_text(source_id + "\n")
    write(
        "READINESS.json",
        {
            "schema": "a170.readiness.v1",
            "source_sha256": source_id,
            "status": "SOURCE_AND_SYNTHETIC_ONLY",
            "unit_tests": 9,
            "native_compiled": False,
            "os_sampling_performed": False,
            "collector_qualified": False,
            "normalized_attribution": None,
            "next_gate": "root isolated native build and tiny lifecycle qualification",
        },
    )
    leaves = sorted(p for p in HERE.iterdir() if p.is_file())
    write(
        "ARTIFACT_MANIFEST.json",
        {
            "schema": "a170.artifacts.v1",
            "files": [{"path": p.name, "sha256": sha(p)} for p in leaves],
        },
    )
    print(
        json.dumps(
            {
                "source_sha256": source_id,
                "source_pins": len(files),
                "artifact_leaves": len(leaves),
                "manifest_sha256": sha(HERE / "ARTIFACT_MANIFEST.json"),
            }
        )
    )


if __name__ == "__main__":
    main()
