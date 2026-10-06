"""Source/freeze checks only. No crypto, process probes, network or compilation."""

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / "a150-common-mask-zero-pool-gate"
MARKER = b"\n// A155_APPEND_ONLY_EGRESS_MARGIN"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_origins():
    records = json.loads((HERE / "A150_ORIGINS.json").read_text())["files"]
    for row in records:
        if sha(Path(row["path"])) != row["sha256"]:
            raise ValueError("changed frozen A150 origin: " + row["path"])
    return len(records)


def verify_pins():
    records = json.loads((HERE / "SOURCE_PINS.json").read_text())["files"]
    records += json.loads((HERE / "PRIMITIVE_ADDITIONS.json").read_text())["files"]
    for row in records:
        if sha(Path(row["path"])) != row["sha256"]:
            raise ValueError("changed cached source: " + row["path"])
    return len(records)


def digest():
    return sha(HERE / "SOURCE_MANIFEST.json")


def verify_freeze():
    verify_origins()
    verify_pins()
    if digest() != (HERE / "SOURCE_DIGEST.txt").read_text().strip():
        raise ValueError("source digest mismatch")
    for name, expected in json.loads((HERE / "SOURCE_MANIFEST.json").read_text())[
        "files"
    ].items():
        if sha(HERE / name) != expected:
            raise ValueError("source changed: " + name)
    for name, expected in json.loads((HERE / "MANIFEST.json").read_text())[
        "files"
    ].items():
        if sha(HERE / name) != expected:
            raise ValueError("artifact changed: " + name)
    return sha(HERE / "MANIFEST.json")


def source_check():
    crypto = (HERE / "src/crypto.rs").read_bytes()
    if crypto.split(MARKER)[0] != (BASE / "src/crypto.rs").read_bytes():
        raise ValueError("original cryptographic graph changed")
    for name in [
        "src/model.rs",
        "src/zero_pool.rs",
        "PROFILE.json",
        "SOURCE_PINS.json",
    ]:
        if (HERE / name).read_bytes() != (BASE / name).read_bytes():
            raise ValueError("frozen model/profile/CM wrapper changed")
    lock = (
        (HERE / "Cargo.lock")
        .read_text()
        .replace(
            "a155-common-mask-egress-margin-control", "a150-common-mask-zero-pool-gate"
        )
    )
    if lock != (BASE / "Cargo.lock").read_text():
        raise ValueError("dependency lock changed beyond package name")
    helper = crypto.split(MARKER)[1].decode()
    if (
        helper.count("lwe_ciphertext_plaintext_add_assign(") != 1
        or helper.count("ordinary_pbs(key,") != 1
    ):
        raise ValueError("one body-add and PBS required per helper call")
    if (
        "keyswitch_lwe_ciphertext(" in helper
        or "decrypt" in helper.split("pub fn egress_margin_probe(")[1]
    ):
        raise ValueError("unexpected KS/client operation in helper")
    return {
        "status": "SOURCE_STATIC_ONLY",
        "original_crypto_byte_identical_prefix": True,
        "a150_origins": verify_origins(),
        "cached_source_pins": verify_pins(),
        "additional_margin_operations": {
            "body_additions": 16,
            "ordinary_pbs": 16,
            "ordinary_ks": 0,
        },
        "typechecked": False,
        "fhe_executed": False,
    }


if __name__ == "__main__":
    print(json.dumps(source_check(), indent=2))
