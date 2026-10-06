"""Check pinned sources, bodies, scope and syntactic routing; never invoke Cargo/FHE."""

import hashlib
import json
from pathlib import Path
from model import witness

ROOT = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_id():
    names = [
        "Cargo.toml",
        "Cargo.lock",
        "src/main.rs",
        "src/bridge.rs",
        "source-pins.json",
        "artifacts/dual_lut_delta52.u64le",
        "artifacts/dual_lut_delta60.u64le",
    ]
    blob = "".join(f"{name}\t{digest(ROOT / name)}\n" for name in names)
    return hashlib.sha256(blob.encode()).hexdigest()


def main():
    pins = json.loads((ROOT / "source-pins.json").read_text())
    for pin in pins:
        path = Path(pin["path"])
        assert digest(path) == pin["sha256"], path
        lines = path.read_text().splitlines()
        for fragment in pin["fragments"]:
            assert fragment["text"] in "\n".join(
                lines[fragment["start_line"] - 1 : fragment["end_line"]]
            ), fragment
    bridge = (ROOT / "src/bridge.rs").read_text()
    main_rs = (ROOT / "src/main.rs").read_text()
    assert bridge.count("keyswitch_lwe_ciphertext_with_scalar_change(") == 1
    assert bridge.count("blind_rotate_assign(") == 1
    assert "programmable_bootstrap_lwe_ciphertext(" not in bridge
    assert "lwe_ciphertext_modulus_switch::<usize, _>" in bridge
    assert "blind_rotate_assign(&switched, &mut rotated, bsk)" in bridge
    assert "LweCiphertextOwned<u32>" in bridge and "GlweCiphertextOwned<u64>" in bridge
    assert "1 << 29, &accumulator, &[0, 1024]" in main_rs
    assert main_rs.index("*coefficient <<= 63 - delta") < main_rs.index(
        "bridge::switch_large("
    )
    assert "all_correct && all_support" in main_rs
    assert "actual_ms_error_signed_u32" in main_rs
    bodies = []
    for delta in (52, 60):
        path = ROOT / f"artifacts/dual_lut_delta{delta}.u64le"
        raw = path.read_bytes()
        assert len(raw) == 16384
        words = [
            int.from_bytes(raw[j : j + 8], "little") for j in range(0, len(raw), 8)
        ]
        assert words[:1024] == [(-(1 << (delta - 1))) % (1 << 64)] * 1024
        assert words[1024:] == [(-(1 << 58)) % (1 << 64)] * 1024
        bodies.append({"delta": delta, "sha256": digest(path), "coefficients": 2048})
    assert (ROOT / "source-id.txt").read_text().strip() == source_id()
    result = {
        "status": "SOURCE_AND_EXACT_SYNTHETIC_ONLY",
        "source_pins_passed": len(pins),
        "bodies": bodies,
        "source_id": source_id(),
        "integer_witnesses": witness(),
        "linked_library_run": "NOT_RUN",
        "fresh_key_gate": "NOT_RUN",
        "typecheck": "NOT_RUN",
        "raw_tails": "OPEN",
        "a62_stock_max5_compatibility": "OPEN",
    }
    (ROOT / "artifacts/static-result.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
