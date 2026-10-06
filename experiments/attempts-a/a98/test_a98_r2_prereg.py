#!/usr/bin/env python3
"""Read-only pre-FHE checks for the frozen A98 R2 preregistration and release binary."""

from __future__ import annotations

import hashlib
import json
import struct
import unittest
from pathlib import Path


A98 = Path(__file__).resolve().parent
REPO = A98.parent.parent
PREREG = A98 / "R2_PREREGISTRATION.json"
RUNTIME_SOURCE = A98 / "runtime-gate/src/main.rs"
RUNTIME_MANIFEST = A98 / "runtime-gate/Cargo.toml"
RUNTIME_LOCK = A98 / "runtime-gate/Cargo.lock"
BINARY = Path("/tmp/a98-r2-target.J3CTcB/release/a98-head-start-exact-adapter-r2")
TFHE_ROOT = Path(
    "/opt/cargo/registry/src/"
    "index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0"
)
TFHE_ARCHIVE = Path(
    "/opt/cargo/registry/cache/"
    "index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0.crate"
)

EXPECTED = {
    PREREG: "2fe4fe948a0d734b50aa66c4723f1562bb6fb9062f9b75f999efe3e04df3088d",
    A98
    / "src/lib.rs": "a750dc4eebef73238ae80fcfde90c8b0fa6995d150c5b9120a1adbb37f9dfce4",
    A98
    / "STATIC_REPORT.json": "003f32e547dc376bea2fdb7d2d6dc10174ccc14ae456596c3ea5dfecbfc60e86",
    A98
    / "compile-gate/Cargo.lock": "f080b69b592f6d741a03c282afe1d6168d4e96071f9e24da17be311ef36b7242",
    RUNTIME_SOURCE: "527e6c29370a705500194dfded899a299abf7f2a0744093c32b0a32083363175",
    RUNTIME_MANIFEST: "5b416241704bd9ea9965243501e9acfa9ba084531c26180320fe21f2bd61e5a8",
    RUNTIME_LOCK: "5a06cb6acb31a924f87676964ffa385d52f41addb29acedb9c1686949bc64696",
    BINARY: "383d42ac18b896e8ae32c995acb65a30234589485cf770c7be4732dafe53384d",
    REPO
    / "tmp/a89-centered-ms-adapter-preflight/a89_centered_ms.py": "50943b7fd7b2fa9073497ea2e6ba37c36b836fe5a3bfc06b01fb8fb6e4643df6",
    REPO
    / "tmp/pdfs/head-start.patch": "d19b72f6257d3db93e3651d87779816be4f210f60bf274cea5799b50743368cc",
    TFHE_ROOT
    / "src/core_crypto/algorithms/lwe_programmable_bootstrapping/fft64_pbs.rs": "21c8009e0999c78401dea57a1d7bcbe91c47b80b231357b42eab9552a20abd71",
    TFHE_ROOT
    / "src/core_crypto/algorithms/lwe_bootstrap_key_generation.rs": "efb3b96b252f8d17907bb94cadbe15a807a6156ef37693fe06c40507705345fd",
    TFHE_ROOT
    / "src/core_crypto/entities/modulus_switched_lwe_ciphertext.rs": "68b692b3e941b98a4a0290e67979733f82a0449e95856f7d1f821140159f562d",
    TFHE_ARCHIVE: "f341a7a6fe90bf813ecb2b098f04c0e5bca82436ddd1b256e6f1ec68be58da52",
    REPO
    / "experiments/14_pipeline_tfhe_rs/results/ritaratura_soglia.txt": "e490b7431e3531b532d4a383e6d0d1231bb4537126ec2ec4e01eb9202f0db3ab",
    REPO
    / "ultimo-meeting-transcription.md": "01e08d541287aa057441f3861e549408ec8bf1448f20ae6193fc1be8b1e87745",
    REPO
    / "tmp/a38-combined-prototype/README.md": "156a35f3407a5914ea6712ad2c5e76f413f1f125bc275371e8fe6d4f7dcd4d37",
}

WORD_MASK = (1 << 64) - 1
DIMENSION = 859
SHIFT = 52
STEP = 1 << SHIFT
HALF_STEP = STEP // 2
BOUNDARY = 63 * STEP + HALF_STEP


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_u64(values: list[int]) -> str:
    return hashlib.sha256(
        b"".join(struct.pack("<Q", value) for value in values)
    ).hexdigest()


def cycle(values: list[int]) -> list[int]:
    return [values[index % len(values)] for index in range(DIMENSION)]


def xorshift_mask() -> tuple[list[int], int]:
    state = 0xA980000000000004
    mask: list[int] = []
    for _ in range(DIMENSION):
        state ^= (state << 13) & WORD_MASK
        state ^= state >> 7
        state ^= (state << 17) & WORD_MASK
        state &= WORD_MASK
        mask.append(state)
    mask[:8] = [
        0,
        1,
        HALF_STEP - 1,
        HALF_STEP,
        HALF_STEP + 1,
        STEP - 1,
        WORD_MASK,
        WORD_MASK - (HALF_STEP - 1),
    ]
    return mask, state


def signed_u64(value: int) -> int:
    value &= WORD_MASK
    return value - (1 << 64) if value >= 1 << 63 else value


def oracle(mask: list[int]) -> tuple[int, int, int, int]:
    d_sum = 0
    h_sum = 0
    for value in mask:
        rounded = (((value + HALF_STEP) & WORD_MASK) >> SHIFT) << SHIFT
        d = signed_u64(rounded - value)
        half = abs(d) // 2 * (-1 if d < 0 else 1)
        d_sum += d
        h_sum += 2 * half - d
    tie = int(h_sum < 0 and h_sum % 2 != 0)
    correction = -((-d_sum) // 2)
    return d_sum, h_sum, tie, correction


def generated_cases() -> list[tuple[str, list[int], int]]:
    zero = [0] * DIMENSION
    single_pos = [STEP - 1, *([0] * (DIMENSION - 1))]
    single_neg = [1, *([0] * (DIMENSION - 1))]
    cancel = [STEP - 1, 1, *([0] * (DIMENSION - 2))]
    edge = [
        0,
        1,
        HALF_STEP - 1,
        HALF_STEP,
        HALF_STEP + 1,
        STEP - 1,
        WORD_MASK,
        WORD_MASK - (HALF_STEP - 1),
    ]
    wrap = [
        WORD_MASK,
        WORD_MASK - 1,
        WORD_MASK - HALF_STEP + 1,
        WORD_MASK - HALF_STEP,
        WORD_MASK - HALF_STEP - 1,
        STEP - 1,
        1,
        0,
    ]
    xorshift, final_state = xorshift_mask()
    if final_state != 0x3B7CEC6A75DC728D:
        raise AssertionError("xorshift final-state drift")
    return [
        ("c00_zero_anchor", zero, 63 * STEP),
        ("c01_single_pos_anchor", single_pos, 63 * STEP),
        ("c02_single_pos_below", single_pos, BOUNDARY - 1),
        ("c03_single_pos_at", single_pos, BOUNDARY),
        ("c04_single_pos_above", single_pos, BOUNDARY + 1),
        ("c05_single_neg_at", single_neg, BOUNDARY),
        ("c06_cancel_pair_at", cancel, BOUNDARY),
        ("c07_all_pos_hits_boundary", [STEP - 1] * DIMENSION, BOUNDARY - 430),
        ("c08_all_neg_hits_boundary", [1] * DIMENSION, BOUNDARY + 429),
        (
            "c09_alternating_pos_hits_boundary",
            [STEP - 1 if index % 2 == 0 else 1 for index in range(DIMENSION)],
            BOUNDARY - 1,
        ),
        (
            "c10_alternating_neg_at",
            [1 if index % 2 == 0 else STEP - 1 for index in range(DIMENSION)],
            BOUNDARY,
        ),
        ("c11_edge_cycle_wrap_body", cycle(edge), WORD_MASK),
        ("c12_xorshift_edge_injected", xorshift, WORD_MASK),
        ("c13_wrap_cycle_low_body", cycle(wrap), 1),
    ]


class A98R2PreregTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.prereg = json.loads(PREREG.read_text())

    def test_all_frozen_hashes(self) -> None:
        for path, expected in EXPECTED.items():
            with self.subTest(path=path):
                self.assertTrue(path.is_file())
                self.assertEqual(sha256_file(path), expected)

    def test_case_ledger_is_exact(self) -> None:
        generated = generated_cases()
        recorded = self.prereg["cases"]
        self.assertEqual(len(generated), 14)
        self.assertEqual(len(recorded), 14)
        for index, ((case_id, mask, body), row) in enumerate(zip(generated, recorded)):
            with self.subTest(case_id=case_id):
                self.assertEqual(row["index"], index)
                self.assertEqual(row["id"], case_id)
                self.assertEqual(int(row["body"], 16), body)
                self.assertEqual(sha256_u64(mask), row["mask_sha256"])
                self.assertEqual(sha256_u64([*mask, body]), row["input_sha256"])
                d_sum, h_sum, tie, correction = oracle(mask)
                self.assertEqual(d_sum, row["expected_D"])
                self.assertEqual(h_sum, row["expected_H"])
                self.assertEqual(tie, row["expected_tie"])
                self.assertEqual(correction, row["expected_reference_correction"])

    def test_lut_hash(self) -> None:
        lut = [index * STEP for index in range(2048)]
        self.assertEqual(
            sha256_u64(lut),
            self.prereg["shared_lut"]["body_sha256_little_endian_u64"],
        )

    def test_dependency_lock_is_pinned(self) -> None:
        lock = RUNTIME_LOCK.read_text()
        self.assertIn('name = "tfhe"\nversion = "1.7.0"', lock)
        self.assertIn(
            'checksum = "f341a7a6fe90bf813ecb2b098f04c0e5bca82436ddd1b256e6f1ec68be58da52"',
            lock,
        )

    def test_runtime_source_is_fail_closed(self) -> None:
        source = RUNTIME_SOURCE.read_text()
        for needle in (
            "--run-authorized-r2",
            "A98_R2_AUTHORIZED",
            "A98_R2_RUNTIME_SOURCE_SHA256",
            "A98_R2_RUNTIME_MANIFEST_SHA256",
            "A98_R2_RUNTIME_LOCK_SHA256",
            "A98_R2_EXECUTABLE_SHA256",
            "RAYON_NUM_THREADS",
            "PASS_COMPONENT_FHE_SMOKE",
            "test_only_reproducible_public_seed_not_a_real_secret",
        ):
            self.assertIn(needle, source)
        self.assertNotIn("write_all(&standard_bsk", source)
        self.assertNotIn("serialize(&standard_bsk", source)

    def test_scope_is_r2_only(self) -> None:
        authorization = self.prereg["authorization"]
        self.assertEqual(authorization["stage"], "R2_ONLY")
        self.assertEqual(authorization["fresh_key_count"], 1)
        self.assertIn("R3 corrected key switch", authorization["forbidden"])
        self.assertIn("2048-mask campaign", authorization["forbidden"])


if __name__ == "__main__":
    unittest.main()
