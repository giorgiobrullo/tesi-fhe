#!/usr/bin/env python3
"""Small deterministic checks only. No Cargo, Rust compilation, keygen, FHE, or process signals."""
import hashlib
import itertools
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
SOURCE_FILES = ["Cargo.toml", "Cargo.lock", ".cargo/config.toml", "src/main.rs", "src/crypto.rs", "src/model.rs",
                "run_gate.py", "static_audit.py", "test_static_audit.py", "SOURCE_PINS.json",
                "API_AUDIT.json", "README.md", "PREREGISTRATION.md"]
LAYOUTS = [(7, 1, 4, 2, 1), (6, 1, 4, 2, 1), (5, 1, 4, 2, 1), (4, 1, 4, 2, 1),
           (3, 1, 4, 2, 1), (2, 8, 1, 1, 2), (1, 4, 1, 2, 1), (0, 2, 2, 2, 1)]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_digest():
    leaves = {name: sha(HERE / name) for name in SOURCE_FILES}
    return hashlib.sha256(json.dumps(leaves, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify_digest():
    assert source_digest() == (HERE / "SOURCE_DIGEST.txt").read_text().strip(), "A132 source digest changed"


def verify_pins():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())
    for pin in pins["files"]:
        assert sha(Path(pin["path"])) == pin["sha256"], f"source pin changed: {pin['path']}"
    return len(pins["files"])


def reduction_nodes(groups):
    nodes = 0
    while groups > 1:
        nodes += groups // 3 + (groups % 3 == 2)
        groups = (groups + 2) // 3
    return nodes


def ledger(n):
    groups = (n + 3) // 4
    reductions = reduction_nodes(groups)
    return dict(packing=2*groups+1, cm_ks=2*groups+reductions, cm_pbs=3*groups+reductions,
                ordinary_ks=n+5, ordinary_pbs=n+3, extraction=n+4)


def circuit(active, bits, alpha, beta, omit_offset=False):
    n = len(active)
    groups = (n + 3) // 4
    aa = active + [0] * (groups * 4 - n)
    bb = bits + [0] * (groups * 4 - n)
    z = [int(alpha*a + beta*b == alpha) for a, b in zip(aa, bb)]
    roots = [z[i:i+4] for i in range(0, len(z), 4)]
    while len(roots) > 1:
        next_roots = []
        for i in range(0, len(roots), 3):
            chunk = roots[i:i+3]
            next_roots.append([int(sum(row[lane] for row in chunk) != 0) for lane in range(4)])
        roots = next_roots
    pair = [int(sum(roots[0][i:i+2]) != 0) for i in (0, 2)]
    any_zero = int(sum(pair) != 0)
    codes = [a + zz - any_zero + (not omit_offset) for a, zz in zip(aa, z)]
    return [int(code == 2) for code in codes], codes


def direct_oracle(active, bits):
    any_zero = any(a and not b for a, b in zip(active, bits))
    return [int(a and (not any_zero or not b)) for a, b in zip(active, bits)]


def modulus_switch(word, poly):
    shift = 64 - (2*poly).bit_length() + 1
    return ((word + (1 << (shift-1))) % (1 << 64)) >> shift


def lut(poly, modulus, delta, function):
    block = poly // modulus
    data = [function(i) * delta % (1 << 64) for i in range(modulus) for _ in range(block)]
    data[:block//2] = [(-word) % (1 << 64) for word in data[:block//2]]
    return data[block//2:] + data[:block//2]


def lookup(data, degree):
    degree %= 2 * len(data)
    return data[degree] if degree < len(data) else (-data[degree-len(data)]) % (1 << 64)


def main():
    checked = 0
    for _, weight, rescale, alpha, beta in LAYOUTS:
        assert weight * rescale * (1 << 59) == beta * (1 << 61)
        for booleans in itertools.product((0, 1), repeat=8):
            active, bits = list(booleans[:4]), list(booleans[4:])
            got, codes = circuit(active, bits, alpha, beta)
            assert got == direct_oracle(active, bits)
            assert all(0 <= code <= 2 for code in codes)
            checked += 1
    tail_checks = 0
    for n in (4, 5, 12, 13, 127):
        for zero in range(n):
            active, bits = [1]*n, [1]*n
            bits[zero] = 0
            got, _ = circuit(active, bits, 2, 1)
            assert got[:n] == direct_oracle(active, bits)
            assert not any(got[n:])
            tail_checks += 1
    source = (HERE / "src/crypto.rs").read_text()
    server = source.split("pub fn run_round(", 1)[1]
    assert "decrypt" not in server and "ClientKeys" not in server and "SecretKey" not in server
    evaluator = source.split("pub struct EvaluationKeys {", 1)[1].split("\n}", 1)[0]
    assert "SecretKey" not in evaluator
    assert re.search(r"let\s+lane_to_a44:\s*Vec<_>\s*=\s*cm_big\s*\.iter", source)
    assert "cm_lwe_ciphertext_plaintext_add_assign(&mutsmall,Plaintext(CM_DELTA))" in re.sub(r"\s+", "", source)
    assert "coefficientwise_degree" in (HERE / "src/main.rs").read_text()
    pins = verify_pins()
    verify_digest()
    report = {"status": "STATIC_ONLY_PASS", "rust_compiled": False, "fhe_run": False,
              "n4_clear_rounds": checked, "group_tail_cases": tail_checks,
              "source_pins": pins, "n4_ledger": ledger(4), "n127_one_round_ledger": ledger(127),
              "source_sha256": source_digest()}
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    main()
