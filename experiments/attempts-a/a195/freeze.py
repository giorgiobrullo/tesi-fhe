"""One-time static freeze; never invokes a compiler, process probe or native gate."""

from pathlib import Path
import hashlib
import json
import os
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(name, value):
    path = HERE / name
    with path.open("x") as output:
        json.dump(value, output, indent=2)
        output.write("\n")
    os.chmod(path, 0o600)


def main():
    if (HERE / "SOURCE_MANIFEST.json").exists() or (HERE / "MANIFEST.json").exists():
        raise ValueError("already frozen; no overwrite")
    import origin
    import audit

    result = dict(origin=origin.verify(), inherited_audit=audit.verify())
    write("artifacts/AUDIT.json", result)
    sources = sorted(
        p.relative_to(HERE).as_posix()
        for p in HERE.rglob("*")
        if p.is_file()
        and not any(
            part.startswith("target-")
            or part in {"artifacts", "runs", "build-artifacts", "__pycache__"}
            for part in p.relative_to(HERE).parts
        )
    )
    write(
        "SOURCE_MANIFEST.json",
        dict(schema="a195.source.v1", files={p: digest(HERE / p) for p in sources}),
    )
    identity = digest(HERE / "SOURCE_MANIFEST.json")
    with (HERE / "SOURCE_DIGEST.txt").open("x") as output:
        output.write(identity + "\n")
    write(
        "READINESS.json",
        dict(
            schema="a195.source_readiness.v1",
            status="SOURCE_READY_NO_CARGO_OR_NATIVE_EXECUTION",
            source_id=identity,
            source_leaves=len(sources),
            mapped_a192_files=30,
            byte_identical_mapped_files=20,
            tests=20,
            test_seconds=4.914,
            tests_log="artifacts/tests-r1.log",
            ruff_pass=True,
            rustfmt_pass=True,
            actual_runtime=False,
            cargo_invoked=False,
            diagnostic_label_repair_only=True,
            relaxed_checker=False,
            old_invalid_result_preserved=True,
            fresh_a195_smoke_required=True,
            full_requires_bound_fresh_smoke=True,
            target="target-a195-only",
            binary="a149_padding_coefficient_gate",
            actual_p_fail=None,
            speed_claim=False,
            n127_claim=False,
        ),
    )
    artifacts = {}
    for path in sorted(HERE.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(HERE)
        if any(
            x.startswith("target-") or x in {"runs", "build-artifacts", "__pycache__"}
            for x in rel.parts
        ):
            raise ValueError("unexpected execution or cache artifact at source freeze")
        os.chmod(path, 0o600)
        artifacts[rel.as_posix()] = digest(path)
    write(
        "MANIFEST.json",
        dict(schema="a195.artifact.v1", source_id=identity, files=artifacts),
    )
    import replay

    replay.source_check()
    for name, expected in artifacts.items():
        if digest(HERE / name) != expected:
            raise ValueError("artifact mismatch " + name)
    print(
        json.dumps(
            dict(
                source_id=identity,
                source_leaves=len(sources),
                artifact_manifest_sha256=digest(HERE / "MANIFEST.json"),
                artifact_leaves=len(artifacts),
                all_hashes_match=True,
            )
        )
    )


if __name__ == "__main__":
    main()
