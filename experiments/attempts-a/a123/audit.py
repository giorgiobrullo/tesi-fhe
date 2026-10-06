#!/usr/bin/env python3
"""Fail-closed local source audit for the PFPKS core across TFHE-rs versions."""

from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path
from typing import Any


REGISTRY = Path.home() / ".cargo/registry/src/index.crates.io-1949cf8c6b5b557f"
OLD = REGISTRY / "tfhe-0.11.3/src"
NEW = REGISTRY / "tfhe-1.7.0/src"
ALGORITHM = "core_crypto/algorithms/lwe_private_functional_packing_keyswitch.rs"
KEYGEN = (
    "core_crypto/algorithms/lwe_private_functional_packing_keyswitch_key_generation.rs"
)
ENTITY = "core_crypto/entities/lwe_private_functional_packing_keyswitch_key.rs"
EXPECTED_IDENTICAL_SHA256 = {
    ALGORITHM: "a3f8aa8c0323b20f1d612f0adc3e565496d81f62200ef53483036298bff0a193",
    KEYGEN: "954f35c38a50656179df086e51c720c14937361dd1bda25032de5c37044aba2a",
}
EXPECTED_ENTITY_SHA256 = {
    "0.11.3": "cddc77115df8024282e513646ee510e37d72c3d3605002839c4c4ee57bd63d45",
    "1.7.0": "defc38344613cb1d3093f976e48b08bd53a1d85bc77aaa51b2763aa491b04f18",
}


class AuditError(ValueError):
    """The installed source no longer matches the frozen comparison."""


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def checked_read(root: Path, relative: str) -> bytes:
    path = root / relative
    if not path.is_file():
        raise AuditError(f"missing source: {path}")
    return path.read_bytes()


def audit() -> dict[str, Any]:
    identical: dict[str, Any] = {}
    for relative, expected_hash in EXPECTED_IDENTICAL_SHA256.items():
        old = checked_read(OLD, relative)
        new = checked_read(NEW, relative)
        if old != new:
            raise AuditError(f"PFPKS core drift across versions: {relative}")
        observed = digest(old)
        if observed != expected_hash:
            raise AuditError(f"unexpected common digest: {relative}: {observed}")
        identical[relative] = {
            "byte_identical": True,
            "bytes": len(old),
            "sha256": observed,
        }

    old_entity = checked_read(OLD, ENTITY)
    new_entity = checked_read(NEW, ENTITY)
    observed_entity = {
        "0.11.3": digest(old_entity),
        "1.7.0": digest(new_entity),
    }
    if observed_entity != EXPECTED_ENTITY_SHA256:
        raise AuditError(f"entity source drift: {observed_entity}")
    old_text = old_entity.decode("utf-8")
    new_text = new_entity.decode("utf-8")
    required = (
        "pub struct LwePrivateFunctionalPackingKeyswitchKey",
        "decomp_level_count",
        "output_glwe_size",
        "output_polynomial_size",
        "ciphertext_modulus",
        "pub fn new(",
    )
    if any(
        fragment not in old_text or fragment not in new_text for fragment in required
    ):
        raise AuditError("PFPKS entity geometry/API fragment missing")
    entity_diff = tuple(
        difflib.unified_diff(
            old_text.splitlines(),
            new_text.splitlines(),
            fromfile="tfhe-0.11.3",
            tofile="tfhe-1.7.0",
            lineterm="",
        )
    )
    if len(entity_diff) != 20:
        raise AuditError(f"unexpected entity diff length: {len(entity_diff)}")
    if "is_multiple_of" not in "\n".join(entity_diff):
        raise AuditError("expected divisibility-assertion modernization missing")

    return {
        "schema": "a123.pfks-cross-version-static.v1",
        "status": "PASS_PFPKS_ALGORITHM_AND_KEYGEN_BYTE_IDENTICAL",
        "versions": ["0.11.3", "1.7.0"],
        "identical_core_sources": identical,
        "entity": {
            "sha256": observed_entity,
            "byte_identical": False,
            "unified_diff_lines": len(entity_diff),
            "required_geometry_api_fragments_equal": True,
            "difference_class": "container divisibility assertion syntax/style",
        },
        "claims": {
            "upgrade_alone_changes_pfpks_kernel": False,
            "upgrade_alone_fixes_a108_noise": False,
            "compiled_performance_identical": False,
            "compile_or_fhe_executed": False,
        },
    }


def main() -> None:
    print(json.dumps(audit(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
