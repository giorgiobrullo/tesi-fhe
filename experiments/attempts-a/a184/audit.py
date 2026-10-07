"""Exact additive recursion attribute and noncryptographic launch-identity audit."""

from pathlib import Path
import hashlib
import json
import sys
import materialize as recipe

sys.dont_write_bytecode = True
if not __debug__:
    raise RuntimeError("A184 requires assertions enabled")
HERE, OLD = recipe.HERE, recipe.OLD


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check():
    parent = json.loads((OLD / "ARTIFACT_MANIFEST.json").read_text())
    assert (
        sha(OLD / "ARTIFACT_MANIFEST.json")
        == "ff599ded423ccf5ffdf5d30e77c3bf9a35ca0c5042a35abe721717daff15926d"
    )
    for name, expected in parent["files"].items():
        assert sha(OLD / name) == expected, name
    for name in recipe.COPIES:
        assert (HERE / name).read_bytes() == (OLD / name).read_bytes(), name
    assert (
        HERE / "candidate/src/main.rs"
    ).read_text() == '#![recursion_limit = "256"]\n\n' + (
        OLD / "candidate/src/main.rs"
    ).read_text()
    for name in ("candidate/src/diagnostic.rs", "candidate/.cargo/config.toml"):
        text = (HERE / name).read_text()
        for before, after in recipe.CHANGES.items():
            text = text.replace(after, before)
        assert text == (OLD / name).read_text(), name
    prior = json.loads((OLD / "PREREGISTRATION.json").read_text())
    current = json.loads((HERE / "PREREGISTRATION.json").read_text())
    for name in ("raw_plan", "fixture_order", "sample_ledger"):
        assert current[name] == prior[name], name
    failure = json.loads((OLD / "build-artifacts/check-r1/exit.json").read_text())
    assert failure["exit_code"] == 101 and failure["child_pid"] == 22666
    assert failure["postcheck_errors"] == []
    assert failure["stderr_sha256"] == sha(OLD / "build-artifacts/check-r1/stderr.log")
    assert (
        "recursion limit reached"
        in (OLD / "build-artifacts/check-r1/stderr.log").read_text()
    )
    return dict(
        status="PASS_STATIC_A184_RECURSION_AND_IDENTITY_ONLY",
        copied_identical_files=len(recipe.COPIES),
        old_artifact_leaves=len(parent["files"]),
        crypto_or_observer_change=False,
        raw_arithmetic_replay_identical=True,
        original_check_exit=101,
        compiled=False,
        actual_fhe=False,
    )


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
