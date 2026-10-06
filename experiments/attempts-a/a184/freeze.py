"""Freeze source pins and artifact identity, no compilation or native execution."""

from pathlib import Path
import json
import audit

HERE, OLD = audit.HERE, audit.OLD


def write(name, value):
    (HERE / name).write_text(json.dumps(value, indent=2) + "\n")


def main():
    assert not (HERE / "ARTIFACT_MANIFEST.json").exists(), "frozen"
    proof = audit.check()
    paths = [
        OLD / "ARTIFACT_MANIFEST.json",
        OLD / "SOURCE_MANIFEST.json",
        OLD / "SOURCE_PINS.json",
    ]
    paths += [
        OLD / n
        for n in json.loads((OLD / "ARTIFACT_MANIFEST.json").read_text())["files"]
    ]
    paths += [
        Path(n) for n in json.loads((OLD / "SOURCE_PINS.json").read_text())["files"]
    ]
    paths += list((OLD / "build-artifacts/check-r1").iterdir())
    paths += [
        HERE.parents[1] / "docs/research-state/2026-09-05/a175-build-driver-r1.py"
    ]
    pins = {str(p): audit.sha(p) for p in sorted(set(paths)) if p.is_file()}
    write("SOURCE_PINS.json", dict(schema="a184-preserved-inputs-v1", files=pins))
    write(
        "ORIGIN.json",
        dict(
            predecessor=str(OLD),
            predecessor_source_sha256=audit.sha(OLD / "SOURCE_MANIFEST.json"),
            predecessor_artifact_manifest_sha256=audit.sha(
                OLD / "ARTIFACT_MANIFEST.json"
            ),
            original_build_label_source_manifest_is_artifact_hash=True,
            failure_files_sha256={
                str(p): audit.sha(p)
                for p in sorted((OLD / "build-artifacts/check-r1").iterdir())
                if p.is_file()
            },
            original_failure_child_pid=22666,
            original_failure_exit_code=101,
            new_build_performed=False,
            new_fhe_performed=False,
        ),
    )
    write("SOURCE_PRESERVATION.json", proof)
    excluded = {
        "SOURCE_MANIFEST.json",
        "ARTIFACT_MANIFEST.json",
        "STATIC_TESTS.log",
        "STATIC_RESULT.json",
        "LINT.log",
        "candidate/SOURCE_DIGEST.txt",
    }
    names = sorted(
        str(p.relative_to(HERE))
        for p in HERE.rglob("*")
        if p.is_file()
        and str(p.relative_to(HERE)) not in excluded
        and "__pycache__" not in p.parts
        and ".ruff_cache" not in p.parts
    )
    write(
        "SOURCE_MANIFEST.json",
        dict(
            schema="a184-source-freeze-v1",
            files={n: audit.sha(HERE / n) for n in names},
            frozen_raw_schema="a175.actual_extraction_consumer.v1",
            actual_runtime=False,
        ),
    )
    source = audit.sha(HERE / "SOURCE_MANIFEST.json")
    (HERE / "candidate/SOURCE_DIGEST.txt").write_text(source + "\n")
    names += [
        "SOURCE_MANIFEST.json",
        "candidate/SOURCE_DIGEST.txt",
        "STATIC_TESTS.log",
        "STATIC_RESULT.json",
        "LINT.log",
    ]
    write(
        "ARTIFACT_MANIFEST.json",
        dict(
            schema="a184-source-static-freeze-v1",
            source_id=source,
            files={n: audit.sha(HERE / n) for n in sorted(names)},
        ),
    )
    print(
        json.dumps(
            dict(
                source_id=source,
                artifact_manifest_sha256=audit.sha(HERE / "ARTIFACT_MANIFEST.json"),
                source_files=len(names) - 5,
                artifact_files=len(names),
                pins=len(pins),
            )
        )
    )


if __name__ == "__main__":
    main()
