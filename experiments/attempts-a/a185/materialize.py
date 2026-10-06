"""A185 local copy of the exact cached TFHE0.11.3 private helper; no compilation."""

from pathlib import Path
import difflib
import json

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / "a184-a175-json-recursion-successor"
UPSTREAM = Path(
    "/opt/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-0.11.3/src/core_crypto/algorithms/polynomial_algorithms.rs"
)
COPIES = [
    "candidate/Cargo.toml",
    "candidate/Cargo.lock",
    "candidate/LICENSE.tfhe-rs-BSD-3-Clause-Clear",
    "candidate/src/main.rs",
    "candidate/src/frozen_extract.rs",
    "candidate/src/actual_consumer.rs",
    "model.py",
    "replay.py",
    "synthetic.py",
    "test_gate.py",
    "test_structure.py",
    "COUNTEREXAMPLE.json",
]
CHANGES = {
    "A184_ACTUAL_CONSUMER_AUTHORIZED": "A185_ACTUAL_CONSUMER_AUTHORIZED",
    "A184_RUN_ACK": "A185_RUN_ACK",
    "A184_SOURCE_SHA256": "A185_SOURCE_SHA256",
    "target-a184-json-recursion-only": "target-a185-private-helper-only",
}
IMPORT = "use tfhe::core_crypto::algorithms::polynomial_algorithms::{\n    polynomial_wrapping_monic_monomial_div, polynomial_wrapping_monic_monomial_mul_and_subtract,\n};"
REPLACEMENT = 'use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_monic_monomial_div;\ninclude!("private_polynomial_helper.rs");'


def helper_source():
    text = UPSTREAM.read_text()
    start = text.index(
        "pub(crate) fn polynomial_wrapping_monic_monomial_mul_and_subtract<"
    )
    brace = text.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end] + "\n"


def materialize():
    if (HERE / "ARTIFACT_MANIFEST.json").exists():
        raise ValueError("frozen A185; separate successor required")
    for name in COPIES:
        path = HERE / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((OLD / name).read_bytes())
    patches = []
    for name in (
        "candidate/src/diagnostic.rs",
        "candidate/.cargo/config.toml",
        "candidate/src/retained_br.rs",
    ):
        before = (OLD / name).read_text()
        after = before
        if name.endswith("retained_br.rs"):
            assert before.count(IMPORT) == 1
            after = before.replace(IMPORT, REPLACEMENT, 1)
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
                fromfile="frozen-a184/" + name,
                tofile="a185/" + name,
            )
        )
    (HERE / "HELPER_AND_IDENTITY.patch").write_text("".join(patches))
    (HERE / "candidate/src/private_polynomial_helper.rs").write_text(helper_source())
    prereg = json.loads((OLD / "PREREGISTRATION.json").read_text())
    prereg.update(
        schema="a185-a175-private-helper-successor-preregistration-v1",
        implementation_identity="A185",
        preserved_first_a184_compile_failure=True,
        local_helper_exact_upstream_copy=True,
        cryptographic_or_record_semantic_change=False,
    )
    (HERE / "PREREGISTRATION.json").write_text(json.dumps(prereg, indent=2) + "\n")
    plan = json.loads(
        json.dumps(json.loads((OLD / "EXECUTION_PLAN.json").read_text()))
        .replace(str(OLD), str(HERE))
        .replace("target-a184-json-recursion-only", "target-a185-private-helper-only")
        .replace("A184_RUN_ACK", "A185_RUN_ACK")
        .replace("A184_SOURCE_SHA256", "A185_SOURCE_SHA256")
        .replace("A184_ACTUAL_CONSUMER_AUTHORIZED", "A185_ACTUAL_CONSUMER_AUTHORIZED")
    )
    plan.update(
        schema="a185-source-execution-plan-v1",
        successor="A185",
        predecessor_compile_failed=True,
    )
    (HERE / "EXECUTION_PLAN.json").write_text(json.dumps(plan, indent=2) + "\n")


if __name__ == "__main__":
    materialize()
