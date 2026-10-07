"""Small independent algebra/provenance gates; no Rust or FHE invoked."""

import hashlib
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parents[1]
ROOT = HERE.parents[1]
MASK = (1 << 64) - 1


class StaticGate(unittest.TestCase):
    def test_frozen_inputs_and_verbatim_helpers(self):
        pins = json.loads((HERE / "SOURCE_PINS.json").read_text())
        for relative, expected in pins["inputs"].items():
            self.assertEqual(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), expected)
        source = (ROOT / pins["extracted_region"]["source"]).read_text()
        start = source.index("#[derive(Clone)]\nstruct CapturedExtractedBits")
        end = source.index("\nfn compact_or<", start)
        region = source[start:end]
        self.assertEqual(hashlib.sha256(region.encode()).hexdigest(), pins["extracted_region"]["sha256"])
        self.assertEqual((HERE / "src/frozen_extract.rs").read_text().split("\n", 1)[1], region)

    def test_all_centers_and_weighted_selection_interface(self):
        for x in range(4096):
            full = x << 52
            low = (x << 60) & MASK
            self.assertEqual((full << 8) & MASK, low)
            residual = full
            corrections = []
            for bit in range(8):
                shifted = (residual << (11 - bit)) & MASK
                expected_bit = (x >> bit) & 1
                self.assertEqual(shifted, expected_bit << 63)
                correction = expected_bit << (52 + bit)
                residual = (residual - correction) & MASK
                corrections.append(correction)
            self.assertEqual(residual, (x >> 8) << 60)
            for bit, weight in enumerate([2, 4, 8]):
                self.assertEqual((corrections[bit] << 8) & MASK, ((x >> bit) & 1) * weight * (1 << 59))

    def test_initial_noise_and_correction_noise_are_distinct(self):
        # Affine torus equivalence includes arbitrary correction errors; equal plaintext does
        # not imply the shifted error is small. The first two terms must both be retained.
        initial_error = 1 << 20
        correction_error = 1 << 53
        full_residual_error = initial_error - correction_error
        shifted_residual_error = (full_residual_error << 8) & MASK
        initial_only = (initial_error << 8) & MASK
        self.assertNotEqual(shifted_residual_error, initial_only)
        self.assertEqual(shifted_residual_error, ((initial_error << 8) - (correction_error << 8)) & MASK)

    def test_negative_controls_discriminate(self):
        # With x=3, omitting b0 correction changes the next shifted phase; missing x256
        # causes b0's weighted decoder to return zero at a noiseless center.
        x = 3
        uncorrected_shift = (x << 52 << 10) & MASK
        corrected_shift = ((x - 1) << 52 << 10) & MASK
        self.assertNotEqual(uncorrected_shift, corrected_shift)
        self.assertEqual(((1 << 52) + (1 << 59)) >> 60, 0)


if __name__ == "__main__":
    unittest.main()
