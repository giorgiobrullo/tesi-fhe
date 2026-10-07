#!/usr/bin/env python3
"""Non-compiling, non-FHE static gate for A101.

This script verifies pinned inputs, exact entity-payload formulas, the
independent automorphism mapping, dependency locks, fail-closed source markers,
and the deliberately narrow claim boundary. It invokes standalone rustfmt in
check-only mode, but never invokes Cargo, rustc, key generation, or FHE.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
N = 2048
DEGREES = (3, 5, 9, 33, 65, 129, 257, 513, 1025, 2049)
CONFIGS = ((23, 1), (8, 5), (7, 6))


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_source_pins() -> int:
    checked = 0
    for line_number, raw in enumerate(
        (ROOT / "SOURCE_PINS").read_text().splitlines(), 1
    ):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        assert match, f"SOURCE_PINS:{line_number}: malformed pin"
        expected, path_text = match.groups()
        path = pathlib.Path(path_text)
        if not path.is_absolute():
            path = ROOT / path
        assert path.is_file(), f"SOURCE_PINS:{line_number}: missing {path}"
        actual = sha256(path)
        assert actual == expected, (
            f"SOURCE_PINS:{line_number}: hash mismatch for {path}: "
            f"expected {expected}, got {actual}"
        )
        checked += 1
    assert checked >= 10, f"expected at least ten source pins, got {checked}"
    return checked


def inverse_mod_2n(degree: int) -> int:
    return pow(degree, -1, 2 * N)


def forward_location(source: int, degree: int) -> tuple[int, int]:
    product = source * degree
    destination = product % N
    sign = 1 if (product // N) % 2 == 0 else -1
    return destination, sign


def inverse_source(destination: int, degree: int) -> tuple[int, int]:
    source_lift = destination * inverse_mod_2n(degree) % (2 * N)
    if source_lift < N:
        return source_lift, 1
    return source_lift - N, -1


def verify_automorphisms() -> int:
    pairs = 0
    for degree in range(1, 2 * N, 2):
        forward = [None] * N
        for source in range(N):
            destination, sign = forward_location(source, degree)
            assert forward[destination] is None, (degree, source, destination)
            forward[destination] = (source, sign)
        for destination in range(N):
            assert forward[destination] == inverse_source(destination, degree), (
                degree,
                destination,
                forward[destination],
                inverse_source(destination, degree),
            )
            pairs += 1
    for degree in DEGREES:
        inverse = inverse_mod_2n(degree)
        for source in range(N):
            destination, sign_one = forward_location(source, degree)
            recovered, sign_two = forward_location(destination, inverse)
            assert recovered == source
            assert sign_one * sign_two == 1
            pairs += 1
    return pairs


def verify_sizes() -> int:
    checked = 0
    for base_log, levels in CONFIGS:
        assert base_log * levels < 64
        full_standard = levels * 2 * 2 * N * 8
        full_fourier = levels * 2 * 2 * (N // 2) * 16
        pseudo_standard = levels * 1 * 2 * N * 8
        pseudo_fourier = levels * 1 * 2 * (N // 2) * 16
        assert full_standard == full_fourier == 65_536 * levels
        assert pseudo_standard == pseudo_fourier == 32_768 * levels
        assert full_standard == 2 * pseudo_standard
        assert full_fourier == 2 * pseudo_fourier
        checked += 4
    return checked


def require_tokens(path: pathlib.Path, tokens: tuple[str, ...]) -> None:
    source = path.read_text()
    for token in tokens:
        assert token in source, f"{path.name}: missing required token {token!r}"


def verify_materialized_gate() -> int:
    main = ROOT / "src/main.rs"
    require_tokens(
        main,
        (
            "encrypt_polynomial_ggsw",
            "encrypt_pseudo_ggsw_ciphertext",
            "glwe_fast_keyswitch(",
            "add_external_product_assign_mem_optimized(",
            "automorphism_oracle_inverse",
            "expected_from_actual_input",
            "full_incremental_max",
            "pseudo_incremental_max",
            "cross_arm_decode_mismatches",
            "full_arm_runs_first",
            "degree_index",
            "order_basis=keyset_plus_config_index_plus_degree_index_plus_iteration",
            "--ack-component-only",
            "speedup_claimed=false",
            "pfail_claimed=false",
            "grouped_trace_proven=false",
            "promotion=false",
        ),
    )
    require_tokens(
        ROOT / "README.md",
        (
            "deliberately not compiled or run",
            "Exact container payload sizes",
            "Runtime is fail-closed",
            "single-EvalAuto",
            "does not establish a speedup",
        ),
    )
    cargo_toml = (ROOT / "Cargo.toml").read_text()
    assert 'tfhe = { version = "=0.11.3"' in cargo_toml
    assert 'features = ["integer", "experimental"]' in cargo_toml
    assert 'aligned-vec = "=0.6.4"' in cargo_toml
    cargo_lock = (ROOT / "Cargo.lock").read_text()
    assert 'name = "a101_pseudo_ggsw_evalauto_preflight"' in cargo_lock
    assert 'name = "tfhe"\nversion = "0.11.3"' in cargo_lock
    assert (
        "ebacd6973a20d4967a64bac147ad6890182fd8ce910ce841ecbb3cae47bdf5ff" in cargo_lock
    )
    provenance = json.loads((ROOT / "PROVENANCE.json").read_text())
    assert provenance["status"] == "static_only_not_compiled_not_run"
    claims = provenance["claim_boundary"]
    assert claims["component_only"] is True
    assert all(
        value is False for key, value in claims.items() if key != "component_only"
    )
    return 4


def verify_rustfmt() -> str:
    rustfmt = shutil.which("rustfmt")
    assert rustfmt is not None, "standalone rustfmt is required for the static gate"
    version = subprocess.run(
        [rustfmt, "--version"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    check = subprocess.run(
        [rustfmt, "--edition", "2021", "--check", str(ROOT / "src/main.rs")],
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, (
        "rustfmt --check failed:\n" + check.stdout + check.stderr
    )
    return version


def main() -> int:
    source_pins = verify_source_pins()
    automorphism_pairs = verify_automorphisms()
    size_assertions = verify_sizes()
    materialized_checks = verify_materialized_gate()
    rustfmt_version = verify_rustfmt()
    print(
        "STATIC_PASS,"
        f"source_pins={source_pins},"
        f"automorphism_pairs={automorphism_pairs},"
        f"size_assertions={size_assertions},"
        f"materialized_groups={materialized_checks},"
        f"rustfmt={rustfmt_version.replace(' ', '_')},"
        "rustfmt_check=true,cargo_invoked=false,rustc_invoked=false,"
        "keygen_invoked=false,fhe_invoked=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"STATIC_FAIL,{error}", file=sys.stderr)
        raise SystemExit(1)
