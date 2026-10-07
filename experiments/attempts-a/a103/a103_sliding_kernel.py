#!/usr/bin/env python3
"""Exact anti-periodic sliding-window oracle for A99's width-127 kernel."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "tmp/a103-width127-sliding-kernel"
WORD_MODULUS = 1 << 64
POLYNOMIAL_SIZE = 2048
RADIUS = 63
WIDTH = 2 * RADIUS + 1
GLWE_COMPONENTS = 2

INPUT_PINS = {
    ROOT / "tmp/a99-chen-grouped-runtime/src/main.rs": (
        "3c563d728be8b634c02d47802c0a2289675683d40c68139420688e1745bf342b"
    ),
    ROOT / "tmp/a92-chen-partial-trace-packing/a92_chen_partial_trace.py": (
        "3c6c8e2cc39de5c03c027837a03c98a62b7dbd04b3b56171788e8cc6a81c814b"
    ),
}


class StaticGateError(RuntimeError):
    """Raised when an exact invariant or source pin fails."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_input_pins() -> dict[str, str]:
    observed: dict[str, str] = {}
    for path, expected in INPUT_PINS.items():
        actual = sha256(path)
        if actual != expected:
            raise StaticGateError(f"input drift: {path}: {actual} != {expected}")
        observed[str(path.relative_to(ROOT))] = actual
    return observed


def anti_periodic_at(polynomial: Sequence[int], exponent: int) -> int:
    """Read X^exponent with X^N=-1 from one canonical coefficient vector."""
    cycles, index = divmod(exponent, POLYNOMIAL_SIZE)
    value = polynomial[index]
    return value if cycles % 2 == 0 else (-value) % WORD_MODULUS


def naive_width127(polynomial: Sequence[int]) -> tuple[int, ...]:
    """Literal source-oriented loop used by frozen A99."""
    if len(polynomial) != POLYNOMIAL_SIZE:
        raise StaticGateError("wrong polynomial size")
    output = [0] * POLYNOMIAL_SIZE
    for index, value in enumerate(polynomial):
        for offset in range(-RADIUS, RADIUS + 1):
            exponent = index + offset
            cycles, target = divmod(exponent, POLYNOMIAL_SIZE)
            signed = value if cycles % 2 == 0 else -value
            output[target] = (output[target] + signed) % WORD_MODULUS
    return tuple(output)


def sliding_width127(polynomial: Sequence[int]) -> tuple[int, ...]:
    """Same negacyclic convolution using an anti-periodic sliding sum."""
    if len(polynomial) != POLYNOMIAL_SIZE:
        raise StaticGateError("wrong polynomial size")
    window = 0
    for exponent in range(-RADIUS, RADIUS + 1):
        window = (window + anti_periodic_at(polynomial, exponent)) % WORD_MODULUS
    output = [window]
    for destination in range(POLYNOMIAL_SIZE - 1):
        outgoing = anti_periodic_at(polynomial, destination - RADIUS)
        incoming = anti_periodic_at(polynomial, destination + RADIUS + 1)
        window = (window - outgoing + incoming) % WORD_MODULUS
        output.append(window)
    return tuple(output)


def expected_basis(index: int, word: int) -> tuple[int, ...]:
    output = [0] * POLYNOMIAL_SIZE
    for offset in range(-RADIUS, RADIUS + 1):
        exponent = index + offset
        cycles, target = divmod(exponent, POLYNOMIAL_SIZE)
        signed = word if cycles % 2 == 0 else -word
        output[target] = (output[target] + signed) % WORD_MODULUS
    return tuple(output)


def xorshift64(state: int) -> int:
    state ^= state << 13 & (WORD_MODULUS - 1)
    state ^= state >> 7
    state ^= state << 17 & (WORD_MODULUS - 1)
    return state & (WORD_MODULUS - 1)


def exact_gate(random_trials: int = 32) -> dict[str, int | bool]:
    basis_word = 0xD3A5_C7E9_1020_3041
    coefficient_checks = 0
    for index in range(POLYNOMIAL_SIZE):
        basis = [0] * POLYNOMIAL_SIZE
        basis[index] = basis_word
        observed = sliding_width127(basis)
        expected = expected_basis(index, basis_word)
        if observed != expected:
            raise StaticGateError(f"basis mismatch at source coefficient {index}")
        coefficient_checks += POLYNOMIAL_SIZE

    state = 0xA103_1270_5EED_C0DE
    random_coefficient_checks = 0
    for trial in range(random_trials):
        polynomial = []
        for _ in range(POLYNOMIAL_SIZE):
            state = xorshift64(state)
            polynomial.append(state)
        if sliding_width127(polynomial) != naive_width127(polynomial):
            raise StaticGateError(f"random polynomial mismatch at trial {trial}")
        random_coefficient_checks += POLYNOMIAL_SIZE

    naive_additions_per_glwe = GLWE_COMPONENTS * POLYNOMIAL_SIZE * WIDTH
    sliding_updates_per_glwe = GLWE_COMPONENTS * (WIDTH + 2 * (POLYNOMIAL_SIZE - 1))
    return {
        "all_checks_pass": True,
        "basis_vectors": POLYNOMIAL_SIZE,
        "basis_coefficient_checks": coefficient_checks,
        "random_trials": random_trials,
        "random_coefficient_checks": random_coefficient_checks,
        "naive_word_updates_per_glwe": naive_additions_per_glwe,
        "sliding_word_updates_per_glwe": sliding_updates_per_glwe,
        "n127_naive_word_updates": 127 * naive_additions_per_glwe,
        "n127_sliding_word_updates": 127 * sliding_updates_per_glwe,
    }


def build_report(random_trials: int = 32) -> dict[str, object]:
    ledger = exact_gate(random_trials)
    naive = int(ledger["naive_word_updates_per_glwe"])
    sliding = int(ledger["sliding_word_updates_per_glwe"])
    return {
        "schema": "a103.width127-sliding-kernel.static.v1",
        "status": "PASS_EXACT_CLEAR_RING_KERNEL_NO_RUNTIME_CLAIM",
        "parameters": {
            "word_modulus": "2^64",
            "polynomial_modulus": "X^2048+1",
            "radius": RADIUS,
            "width": WIDTH,
            "glwe_components": GLWE_COMPONENTS,
            "selector_nodes_n127": 127,
        },
        "input_pins": verify_input_pins(),
        "exact_gate": ledger,
        "structural_reduction": {
            "word_update_ratio_naive_over_sliding": naive / sliding,
            "word_updates_removed_n127": int(ledger["n127_naive_word_updates"])
            - int(ledger["n127_sliding_word_updates"]),
            "complexity_before": "O((k+1)*N*width)",
            "complexity_after": "O((k+1)*(N+width))",
        },
        "claim_boundary": {
            "exact_public_linear_map": True,
            "ciphertext_noise_changed": False,
            "rust_port_exists": False,
            "runtime_measured": False,
            "a99_speedup_claimed": False,
            "end_to_end_speedup_claimed": False,
        },
    }


def canonical_bytes(report: dict[str, object]) -> bytes:
    return json.dumps(report, sort_keys=True, separators=(",", ":")).encode()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--expected-canonical-sha256")
    parser.add_argument("--random-trials", type=int, default=32)
    args = parser.parse_args()
    if args.random_trials < 1:
        raise StaticGateError("random-trials must be positive")
    report = build_report(args.random_trials)
    digest = hashlib.sha256(canonical_bytes(report)).hexdigest()
    if args.expected_canonical_sha256 and digest != args.expected_canonical_sha256:
        raise StaticGateError(
            f"canonical digest mismatch: {digest} != {args.expected_canonical_sha256}"
        )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.verify:
        if args.output.read_text(encoding="utf-8") != rendered:
            raise StaticGateError("frozen report differs from exact reconstruction")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(f"canonical_sha256={digest}")
    print(report["status"])


if __name__ == "__main__":
    main()
