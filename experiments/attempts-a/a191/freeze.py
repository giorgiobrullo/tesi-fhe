"""One local source-only freeze, invoked only after reviews/tests; no execution."""

from pathlib import Path
import hashlib
import json
import difflib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def write(name, value):
    with (HERE / name).open("x") as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")


def main():
    assert not (HERE / "MANIFEST.json").exists(), "frozen evidence is immutable"
    origins = json.loads((HERE / "ORIGINS.json").read_text())["files"]
    for p, h in origins.items():
        assert sha(ROOT / p) == h, p
    old = ROOT / "tmp/a171-pfks-d1-runtime-gate"
    pins = {
        x["path"]: x["sha256"]
        for x in json.loads((old / "SOURCE_PINS.json").read_text())["sources"]
    }
    extra = [
        "tmp/a171-pfks-d1-runtime-gate/test_gate.py",
        "tmp/a167-a137-execution-readiness/runtime-validation/test_verify.py",
        "tmp/a167-a137-execution-readiness/runtime-validation/verify.py",
        "tmp/a137-pfks-runtime-error-observer/tests/test_observer.py",
        "tmp/a137-pfks-runtime-error-observer/static_audit.py",
        "tmp/a137-pfks-runtime-error-observer/validate.py",
        "tmp/a134-pfks-error-provenance/model.py",
        "tmp/a186-pfks-comparator-composition-gate/MANIFEST.json",
        "tmp/a186-pfks-comparator-composition-gate/model.py",
        "tmp/a186-pfks-comparator-composition-gate/INTERFACE.md",
        "tmp/a186-pfks-comparator-composition-gate/NOISE_IDENTITY.md",
        "tmp/a186-pfks-comparator-composition-gate/COUNTEREXAMPLES.json",
        "tmp/a186-pfks-comparator-composition-gate/artifacts/frontier-review/RESULT.json",
        "tmp/a186-pfks-comparator-composition-gate/artifacts/frontier-review/README.md",
        "tmp/a187-padding-precision-runtime-gate/run_gate.py",
        "tmp/a187-padding-precision-runtime-gate/verify.py",
        "tmp/a174-a171-three-process-readiness/MANIFEST.json",
        "tmp/a174-a171-three-process-readiness/artifacts/three-process-independent-review/MANIFEST.json",
        "tmp/a174-a171-three-process-readiness/artifacts/three-process-independent-review/RESULT.json",
        "tmp/a182-a175-first-runtime-envelope/artifacts/failure-diagnosis-first-key1/MANIFEST.json",
    ]
    for p in extra:
        pins[p] = sha(ROOT / p)
    for p, h in pins.items():
        assert sha(ROOT / p) == h, p
    write(
        "SOURCE_PINS.json",
        dict(schema="a191.source-pins.v1", files=dict(sorted(pins.items()))),
    )
    diffs = []
    for name in (
        "candidate/src/main.rs",
        "candidate/Cargo.toml",
        "candidate/Cargo.lock",
        "candidate/.cargo/config.toml",
    ):
        diffs.extend(
            difflib.unified_diff(
                (old / name).read_text().splitlines(True),
                (HERE / name).read_text().splitlines(True),
                fromfile="frozen-A171/" + name,
                tofile="A191/" + name,
            )
        )
    (HERE / "A171_TO_A191.patch").write_text("".join(diffs))
    for name in ("run_gate.py", "verify.py"):
        orig = ROOT / "tmp/a187-padding-precision-runtime-gate" / name
        with (HERE / ("A187_" + name + ".patch")).open("x") as f:
            f.writelines(
                difflib.unified_diff(
                    orig.read_text().splitlines(True),
                    (HERE / name).read_text().splitlines(True),
                    fromfile="frozen-A187/" + name,
                    tofile="A191/" + name,
                )
            )
    source_names = sorted(
        str(p.relative_to(HERE)) for p in (HERE / "candidate").rglob("*") if p.is_file()
    )
    source_names += [
        "model.py",
        "replay.py",
        "run_gate.py",
        "verify.py",
        "PREREGISTRATION.json",
        "EXECUTION_PLAN.json",
        "ORIGINS.json",
        "SOURCE_PINS.json",
    ]
    write(
        "SOURCE_MANIFEST.json",
        dict(
            schema="a191.source-manifest.v1",
            files={p: sha(HERE / p) for p in sorted(source_names)},
        ),
    )
    source = sha(HERE / "SOURCE_MANIFEST.json")
    (HERE / "SOURCE_DIGEST.txt").write_text(source + "\n")
    leaves = {
        str(p.relative_to(HERE)): sha(p)
        for p in HERE.rglob("*")
        if p.is_file()
        and "__pycache__" not in p.parts
        and not any(
            x.startswith(".") and x != ".cargo" for x in p.relative_to(HERE).parts
        )
    }
    write(
        "MANIFEST.json",
        dict(
            schema="a191.artifact-manifest.v1",
            source_id=source,
            files=dict(sorted(leaves.items())),
        ),
    )
    print(
        json.dumps(
            dict(
                source_id=source,
                manifest_sha256=sha(HERE / "MANIFEST.json"),
                leaves=len(leaves),
                source_leaves=len(source_names),
                upstream_pins=len(pins),
                actual_fhe=False,
            )
        )
    )


if __name__ == "__main__":
    main()
