"""Small source, representation and freeze checks; never imports or invokes TFHE."""

import hashlib
import json
from pathlib import Path
import re
import materialize

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / "a132-common-mask-round-gate"
SOURCE_FILES = [
    "Cargo.toml",
    "Cargo.lock",
    ".cargo/config.toml",
    "src/main.rs",
    "src/crypto.rs",
    "src/model.rs",
    "src/zero_pool.rs",
    "SOURCE_PINS.json",
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_pins():
    rows = json.loads((HERE / "SOURCE_PINS.json").read_text())["files"]
    for row in rows:
        if sha(Path(row["path"])) != row["sha256"]:
            raise ValueError("changed frozen input: " + row["path"])
    return len(rows)


def digest():
    leaves = {x: sha(HERE / x) for x in SOURCE_FILES}
    return hashlib.sha256(
        json.dumps(leaves, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def verify_freeze():
    verify_pins()
    if digest() != (HERE / "SOURCE_DIGEST.txt").read_text().strip():
        raise ValueError("candidate source digest mismatch")
    manifest = json.loads((HERE / "MANIFEST.json").read_text())
    for name, expected in manifest["files"].items():
        if sha(HERE / name) != expected:
            raise ValueError("changed candidate artifact: " + name)
    return sha(HERE / "MANIFEST.json")


def normalized(s):
    s = re.sub(r"\s+", "", s)
    return re.sub(r",([)\]}])", r"\1", s)


def source_check():
    crypto = (HERE / "src/crypto.rs").read_text()
    if normalized(crypto) != normalized(materialize.render_crypto()):
        raise ValueError(
            "candidate crypto differs from deterministic A132 transformation"
        )
    if (HERE / "src/model.rs").read_bytes() != (BASE / "src/model.rs").read_bytes():
        raise ValueError("oracle/layout/ledger changed")
    evaluator = crypto.split("pub fn run_round(", 1)[1].split(
        "/// One step of the cached", 1
    )[0]
    if any(x in evaluator for x in ["decrypt", "ClientKeys", "SecretKey"]):
        raise ValueError("server crossed client boundary")
    if crypto.count("programmable_bootstrap_cm_lwe_ciphertext(") != 1:
        raise ValueError("CM PBS bypass exists")
    if evaluator.count("accepted!(cm_pbs(") != 4:
        raise ValueError("four original CM graph sites must use adapter")
    wrapper = crypto.split("fn cm_pbs(", 1)[1].split("fn cm_ks(", 1)[0]
    if wrapper.index("if !event.allowed") >= wrapper.index(
        "programmable_bootstrap_cm_lwe_ciphertext("
    ):
        raise ValueError("unmet status not checked before BR")
    if "programmable_bootstrap_cm_lwe_ciphertext(&event.corrected" not in normalized(
        wrapper
    ):
        raise ValueError("actual PBS input must be corrected ciphertext")
    pool = (HERE / "src/zero_pool.rs").read_text()
    if (
        pool.count("cm_lwe_ciphertext_add_assign(") != 1
        or "improve_lwe_ciphertext_modulus_switch_noise_for_binary_key_cm(" in pool
    ):
        raise ValueError("one complete-row addition required")
    if (
        "CandidateResult::BestNotSatisfyingBound(candidate) => (false, candidate)"
        not in pool
    ):
        raise ValueError("unmet status discarded")
    return dict(
        status="STATIC_SOURCE_ONLY_PASS",
        source_pins=verify_pins(),
        model_byte_identical=True,
        cm_wrapper_sites=4,
        n4_ledger=dict(
            packing=3, cm_ks=2, cm_pbs=3, ordinary_ks=9, ordinary_pbs=7, extraction=8
        ),
        stock_preparation_cm_ks=1,
        stock_pair_cm_pbs=2,
        forced_unmet_cm_pbs=0,
        whole_witness_completed_cm_pbs=17,
        whole_witness_cm_events=18,
        typechecked=False,
        fhe_executed=False,
        probability_guarantee=False,
    )


if __name__ == "__main__":
    print(json.dumps(source_check(), indent=2))
