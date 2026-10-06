"""A184 isolated A175 recursion-budget successor; no build, crypto or network."""

from pathlib import Path
import difflib
import json

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / "a175-extraction-actual-consumer-gate"
CHANGES = {
    "A175_ACTUAL_CONSUMER_AUTHORIZED": "A184_ACTUAL_CONSUMER_AUTHORIZED",
    "A175_RUN_ACK": "A184_RUN_ACK",
    "A175_SOURCE_SHA256": "A184_SOURCE_SHA256",
    "target-a175-actual-consumer-only": "target-a184-json-recursion-only",
}
COPIES = [
    "candidate/Cargo.toml",
    "candidate/Cargo.lock",
    "candidate/LICENSE.tfhe-rs-BSD-3-Clause-Clear",
    "candidate/src/frozen_extract.rs",
    "candidate/src/actual_consumer.rs",
    "candidate/src/retained_br.rs",
    "model.py",
    "replay.py",
    "synthetic.py",
    "test_gate.py",
    "test_structure.py",
    "COUNTEREXAMPLE.json",
]


def materialize():
    if (HERE / "ARTIFACT_MANIFEST.json").exists():
        raise ValueError("A184 frozen; use a separately identified successor")
    for name in COPIES:
        path = HERE / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((OLD / name).read_bytes())
    patches = []
    for name in (
        "candidate/src/main.rs",
        "candidate/src/diagnostic.rs",
        "candidate/.cargo/config.toml",
    ):
        before = (OLD / name).read_text()
        after = before
        if name.endswith("main.rs"):
            after = '#![recursion_limit = "256"]\n\n' + before
        else:
            for old, new in CHANGES.items():
                after = after.replace(old, new)
        path = HERE / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(after)
        patches.extend(
            difflib.unified_diff(
                before.splitlines(True),
                after.splitlines(True),
                fromfile="frozen-a175/" + name,
                tofile="a184/" + name,
            )
        )
    (HERE / "RECURSION_AND_IDENTITY.patch").write_text("".join(patches))
    prereg = json.loads((OLD / "PREREGISTRATION.json").read_text())
    prereg.update(
        schema="a184-a175-recursion-successor-preregistration-v1",
        implementation_identity="A184",
        frozen_semantic_schema="a175.actual_extraction_consumer.v1",
        preserved_first_a175_compile_failure=True,
        recursion_limit=256,
        cryptographic_or_record_semantic_change=False,
    )
    (HERE / "PREREGISTRATION.json").write_text(json.dumps(prereg, indent=2) + "\n")
    plan = json.loads((OLD / "EXECUTION_PLAN.json").read_text())
    plan = json.loads(
        json.dumps(plan)
        .replace(str(OLD), str(HERE))
        .replace("target-a175-actual-consumer-only", "target-a184-json-recursion-only")
        .replace("A175_RUN_ACK", "A184_RUN_ACK")
        .replace("A175_SOURCE_SHA256", "A184_SOURCE_SHA256")
        .replace("A175_ACTUAL_CONSUMER_AUTHORIZED", "A184_ACTUAL_CONSUMER_AUTHORIZED")
    )
    plan.update(
        schema="a184-source-execution-plan-v1",
        successor="A184",
        frozen_raw_schema="a175.actual_extraction_consumer.v1",
        predecessor_compile_failed=True,
    )
    (HERE / "EXECUTION_PLAN.json").write_text(json.dumps(plan, indent=2) + "\n")


if __name__ == "__main__":
    materialize()
