"""Source equivalence and frozen failure binding; no Rust/build/native execution."""

from pathlib import Path
import hashlib
import json
import sys
import materialize as recipe

sys.dont_write_bytecode = True
if not __debug__:
    raise RuntimeError("A185 requires assertions enabled")
HERE, OLD = recipe.HERE, recipe.OLD


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check():
    assert (
        sha(OLD / "ARTIFACT_MANIFEST.json")
        == "bb6ea5e0a572afcb948063a6a3f40ed7870b9be21ab47c95d15ac5f744f3b65a"
    )
    parent = json.loads((OLD / "ARTIFACT_MANIFEST.json").read_text())
    for name, expected in parent["files"].items():
        assert sha(OLD / name) == expected, name
    for name in recipe.COPIES:
        assert (HERE / name).read_bytes() == (OLD / name).read_bytes(), name
    for name in ("candidate/src/diagnostic.rs", "candidate/.cargo/config.toml"):
        text = (HERE / name).read_text()
        for before, after in recipe.CHANGES.items():
            text = text.replace(after, before)
        assert text == (OLD / name).read_text(), name
    retained = (HERE / "candidate/src/retained_br.rs").read_text()
    assert retained.count(recipe.REPLACEMENT) == 1
    assert (
        retained.replace(recipe.REPLACEMENT, recipe.IMPORT, 1)
        == (OLD / "candidate/src/retained_br.rs").read_text()
    )
    assert (
        HERE / "candidate/src/private_polynomial_helper.rs"
    ).read_text() == recipe.helper_source()
    original = json.loads((OLD / "PREREGISTRATION.json").read_text())
    current = json.loads((HERE / "PREREGISTRATION.json").read_text())
    for name in ("raw_plan", "fixture_order", "sample_ledger"):
        assert current[name] == original[name]
    failure = json.loads((OLD / "build-artifacts/check-r1/exit.json").read_text())
    assert failure["exit_code"] == 101 and failure["child_pid"] == 34436
    assert failure["postcheck_errors"] == []
    assert failure["stderr_sha256"] == sha(OLD / "build-artifacts/check-r1/stderr.log")
    stderr = (OLD / "build-artifacts/check-r1/stderr.log").read_text()
    assert "error[E0603]" in stderr and "is private" in stderr
    return dict(
        status="PASS_STATIC_A185_EXACT_HELPER_AND_IDENTITY",
        copied_identical_files=len(recipe.COPIES),
        old_artifact_leaves=len(parent["files"]),
        upstream_helper_sha256=sha(HERE / "candidate/src/private_polynomial_helper.rs"),
        upstream_whole_file_sha256=sha(recipe.UPSTREAM),
        exact_original_helper_definition=True,
        retained_loop_and_callsite_unchanged=True,
        crypto_or_record_semantics_changed=False,
        raw_arithmetic_replay_identical=True,
        original_check_exit=101,
        compiled=False,
        actual_fhe=False,
    )


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
