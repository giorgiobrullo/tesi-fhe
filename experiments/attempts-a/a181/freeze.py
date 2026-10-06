"""Source-only local freeze. No compilation, process probe or native execution."""

from pathlib import Path
import difflib
import hashlib
import json

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(name, value):
    (HERE / name).write_text(json.dumps(value, indent=2) + "\n")


def main():
    if (HERE / "ARTIFACT_MANIFEST.json").exists():
        raise SystemExit("Frozen; use a separate successor")
    old = HERE.parent / "a178-darwin-zombie-identity-successor"
    origins = {
        name: old / name
        for name in [
            "collector.c",
            "fixture.c",
            "arm_clock.h",
            "raw_check.py",
            "run.py",
            "test_runner.py",
        ]
    }
    origins["lifecycle_core.py"] = old / "replay.py"
    inherited = json.loads((old / "SOURCE_PINS.json").read_text())
    pins = [Path(x["path"]) for x in inherited["inputs"]]
    pins += list(origins.values()) + [
        old / "test_replay.py",
        old / "SOURCE_MANIFEST.json",
        old / "SOURCE_DIGEST.txt",
        old / "PREREGISTRATION.json",
        old / "ARTIFACT_MANIFEST.json",
    ]
    pins += [
        HERE.parent / "a180-native-parent-handshake-design" / name
        for name in ["DESIGN.md", "MANIFEST.json", "SOURCE_PINS.json"]
    ]
    pins.append(
        Path(
            "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h"
        )
    )
    pins = sorted(set(pins))
    write(
        "SOURCE_PINS.json",
        dict(
            schema="a181.source-pins.v1",
            inputs=[dict(path=str(x), sha256=sha(x)) for x in pins],
        ),
    )
    patch = []
    for name, path in origins.items():
        patch.extend(
            difflib.unified_diff(
                path.read_text().splitlines(True),
                (HERE / name).read_text().splitlines(True),
                fromfile="frozen-a178/" + path.name,
                tofile="a181/" + name,
            )
        )
    (HERE / "SOURCE_CHANGES.patch").write_text("".join(patch))
    names = [
        "collector.c",
        "fixture.c",
        "ipc.h",
        "arm_clock.h",
        "raw_check.py",
        "lifecycle_core.py",
        "protocol.py",
        "replay.py",
        "run.py",
        "ipc_model.py",
        "synthetic.py",
        "synthetic_base.py",
        "test_replay.py",
        "test_runner.py",
        "test_source.py",
        "freeze.py",
        "README.md",
        "PREREGISTRATION.json",
        "PEER_REVIEW.json",
        "SOURCE_PINS.json",
        "SOURCE_CHANGES.patch",
    ]
    write(
        "SOURCE_MANIFEST.json",
        dict(
            schema="a181.source-manifest.v1",
            files=[dict(path=n, sha256=sha(HERE / n)) for n in names],
        ),
    )
    source = sha(HERE / "SOURCE_MANIFEST.json")
    (HERE / "SOURCE_DIGEST.txt").write_text(source + "\n")
    (HERE / "source_identity.h").write_text('#define A181_SOURCE_ID "' + source + '"\n')
    write(
        "READINESS.json",
        dict(
            schema="a181.readiness.v1",
            source_id=source,
            source_only=True,
            native_fixture_compiled=False,
            native_collector_compiled=False,
            native_execution_performed=False,
            synthetic_mock_tests=23,
            upstream_evidence_unchanged=True,
            new_two_barrier_protocol=True,
            raw_units_only=True,
            cpu_units_justified=False,
            settled_accounting_proven=False,
            collector_qualified=False,
            speedup_promotion_allowed=False,
            next_gate="Root compile both binaries with exact hashes and safe CLI gates; fresh clearance then first order-12; stop on first unexpected negative.",
        ),
    )
    leaves = sorted(x for x in HERE.iterdir() if x.is_file())
    write(
        "ARTIFACT_MANIFEST.json",
        dict(
            schema="a181.artifact-manifest.v1",
            files=[dict(path=x.name, sha256=sha(x)) for x in leaves],
        ),
    )
    print(
        json.dumps(
            dict(
                source_id=source,
                source_leaves=len(names),
                pins=len(pins),
                artifact_leaves=len(leaves),
                manifest_sha256=sha(HERE / "ARTIFACT_MANIFEST.json"),
            )
        )
    )


if __name__ == "__main__":
    main()
