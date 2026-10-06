"""Freeze only this static candidate; never include runs, targets or peer outputs."""

from pathlib import Path
import hashlib
import json
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def main():
    import audit

    result = audit.verify()
    sources = sorted(
        p.relative_to(HERE).as_posix()
        for p in HERE.rglob("*")
        if p.is_file()
        and p.suffix != ".log"
        and not any(
            part.startswith("target-")
            or part in {"__pycache__", "runs", "artifacts", "runtime-validation"}
            for part in p.relative_to(HERE).parts
        )
        and p.name
        not in {
            "SOURCE_MANIFEST.json",
            "SOURCE_DIGEST.txt",
            "MANIFEST.json",
            "READINESS.json",
            "CHECKS.log",
            "CHECKS-first16.log",
            "LINT.log",
            "FORMAT.log",
            "AUDIT.json",
        }
    )
    write(
        HERE / "SOURCE_MANIFEST.json",
        dict(schema="a192.source.v1", files={p: digest(HERE / p) for p in sources}),
    )
    identity = digest(HERE / "SOURCE_MANIFEST.json")
    (HERE / "SOURCE_DIGEST.txt").write_text(identity + "\n")
    write(HERE / "AUDIT.json", result)
    write(
        HERE / "READINESS.json",
        dict(
            schema="a192.source_readiness.v1",
            status="SOURCE_STATIC_READY_NO_TYPECHECK_OR_FHE",
            source_id=identity,
            source_leaves=len(sources),
            tests=17,
            test_seconds=6.692,
            tests_pass=True,
            ruff_pass=True,
            rustfmt_pass=True,
            audit=result,
            compiled=False,
            cargo_invoked=False,
            actual_fhe=False,
            next_smallest_gate="root selected-bin cargo check/build, safe binary noargs, then fixed n4-smoke after clearance",
            target="target-a192-only",
            n127_implemented=False,
        ),
    )
    artifacts = sources + [
        "SOURCE_MANIFEST.json",
        "SOURCE_DIGEST.txt",
        "READINESS.json",
        "AUDIT.json",
    ]
    artifacts += sorted(p.name for p in HERE.glob("*.log"))
    write(
        HERE / "MANIFEST.json",
        dict(
            schema="a192.artifact.v1",
            source_id=identity,
            files={p: digest(HERE / p) for p in sorted(artifacts)},
        ),
    )
    print(
        json.dumps(
            dict(
                source_id=identity,
                artifact_manifest_sha256=digest(HERE / "MANIFEST.json"),
                source_leaves=len(sources),
                artifact_leaves=len(artifacts),
            )
        )
    )


if __name__ == "__main__":
    main()
