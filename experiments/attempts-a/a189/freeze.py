"""Pin only local declarations/design and this pure calculator; no native calls."""

from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
SDK = Path(
    "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
)


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def write(name, value):
    (HERE / name).write_text(json.dumps(value, indent=2) + "\n")


def main():
    if (HERE / "MANIFEST.json").exists():
        raise SystemExit("Frozen; preserve first package")
    inputs = {
        "usr/include/mach/mach_time.h": [(36, 60)],
        "usr/include/mach/host_info.h": [(116, 127), (248, 255)],
        "usr/include/mach/machine.h": [(74, 79)],
        "usr/include/libproc.h": [(105, 110)],
        "usr/include/sys/resource.h": [(184, 232)],
        "usr/include/sys/_types/_timeval.h": [(34, 38)],
        "usr/include/_time.h": [(90, 98)],
        "usr/share/man/man3/clock_gettime.3": [(78, 94), (121, 123)],
        "usr/share/man/man3/sysconf.3": [(71, 72)],
        "usr/share/man/man3/times.3": [(100, 108)],
        "usr/share/man/man2/wait.2": [(135, 140)],
        "usr/share/man/man2/getrusage.2": [(65, 68), (87, 93)],
        "System/Library/Frameworks/Kernel.framework/Headers/kern/clock.h": [(80, 125)],
        "System/Library/Frameworks/Kernel.framework/Headers/kern/processor.h": [],
        "System/Library/Frameworks/Kernel.framework/Headers/sys/resource.h": [],
    }
    rows = []
    for name, ranges in inputs.items():
        path = SDK / name
        lines = path.read_text().splitlines()
        rows.append(
            dict(
                path=str(path),
                resolved_path=str(path.resolve()),
                sha256=sha(path),
                intervals=[
                    dict(first=a, last=b, text="\n".join(lines[a - 1 : b]))
                    for a, b in ranges
                ],
            )
        )
    source_names = {
        "a170-darwin-cpu-collector": [
            "README.md",
            "QUALIFICATION.md",
            "SOURCE_PINS.json",
        ],
        "a172-darwin-collector-lifecycle-fixture": [
            "PREREGISTRATION.json",
            "SOURCE_MANIFEST.json",
        ],
        "a178-darwin-zombie-identity-successor": [
            "PREREGISTRATION.json",
            "SOURCE_MANIFEST.json",
        ],
        "a181-native-parent-handshake-gate": [
            "arm_clock.h",
            "collector.c",
            "fixture.c",
            "README.md",
            "PREREGISTRATION.json",
            "SOURCE_MANIFEST.json",
            "SOURCE_DIGEST.txt",
            "raw_check.py",
            "run.py",
        ],
    }
    rows += [
        dict(
            path=str(HERE.parent / d / n),
            resolved_path=str(HERE.parent / d / n),
            sha256=sha(HERE.parent / d / n),
            intervals=[],
        )
        for d, names in source_names.items()
        for n in names
    ]
    write(
        "SOURCE_EVIDENCE.json",
        dict(
            schema="a189.local-source-evidence.v1",
            running_kernel_source_attested=False,
            inputs=rows,
        ),
    )
    write(
        "READINESS.json",
        dict(
            schema="a189.readiness.v1",
            actual_a181_records_read=False,
            native_calls_performed=False,
            source_only=True,
            synthetic_tests=7,
            python_required="3.12 project .venv",
            selected_cpu_scale=None,
            normalized_occupancy=None,
            cpu_units_justified=False,
            counter_errors_justified=False,
            settlement_proven=False,
            collector_qualified=False,
            next_gate="Only after complete frozen A181 native/envelope/replay sequence: apply fixed exact hypothesis calculations to both positive orders; preserve all gaps and discrepancies. No runtime adapter included.",
        ),
    )
    files = sorted(x for x in HERE.iterdir() if x.is_file())
    write(
        "MANIFEST.json",
        dict(
            schema="a189.manifest.v1",
            files=[dict(path=x.name, sha256=sha(x)) for x in files],
        ),
    )
    print(
        json.dumps(
            dict(
                files=len(files),
                source_pins=len(rows),
                manifest_sha256=sha(HERE / "MANIFEST.json"),
                calculator_sha256=sha(HERE / "calculate.py"),
            )
        )
    )


if __name__ == "__main__":
    main()
