from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import a41_clear_and_count_model as model  # noqa: E402


class A41ClearAndCountModelTests(unittest.TestCase):
    def test_reject_and_boundary_identities(self) -> None:
        self.assertEqual(model.evaluate((0,) * 128).code, 0)
        first = model.evaluate((1,) + (0,) * 127)
        self.assertEqual((first.low_nibble, first.high_nibble, first.code), (1, 0, 1))
        id_127 = model.evaluate((0,) * 126 + (1, 0))
        self.assertEqual((id_127.low_nibble, id_127.high_nibble, id_127.code), (15, 7, 127))
        id_128 = model.evaluate((0,) * 127 + (1,))
        self.assertEqual((id_128.low_nibble, id_128.high_nibble, id_128.code), (0, 8, 128))

    def test_first_tie_semantics(self) -> None:
        result = model.evaluate((0,) * 63 + (1,) + (0,) * 62 + (1,))
        self.assertEqual(result.code, 64)
        tail = model.evaluate((0,) * 126 + (1, 1))
        self.assertEqual(tail.code, 127)

    def test_terminal_only_and_prudent_counts_are_separate(self) -> None:
        self.assertEqual(model.a41_counts(127), model.Counts(3_655, 3_274, 4_206))
        self.assertEqual(
            model.prudent_raw_l1_counts(127),
            model.Counts(3_909, 3_528, 4_460),
        )

    def test_wire_projection_matches_current_container_geometry(self) -> None:
        wire = model.wire_projection()
        self.assertEqual(wire["single_lwe_bytes"], 16_464)
        self.assertEqual(wire["two_lwe_bytes"], 32_856)
        self.assertEqual(wire["additional_bytes"], 16_392)

    def test_rust_source_materializes_two_p16_roots_without_final_sum(self) -> None:
        source = (ROOT / "src" / "private_argmin.rs").read_text()
        harness = (
            ROOT / "src" / "bin" / "a41_combined_two_lwe_prototype.rs"
        ).read_text()
        self.assertIn("AlignedWireFormat::TwoP16Digits => bool_delta", source)
        self.assertIn("AlignedWireFormat::TwoP16Digits if slot <= 8 => slot", source)
        self.assertIn("debug_assert!(output.code.is_none())", source)
        self.assertIn("trace.final_code = code.clone()", source)
        self.assertIn("private_argmin_two_lwe_with_trace", harness)
        self.assertIn("linear_postprocessing=false", harness)

    def test_full_static_validation(self) -> None:
        self.assertEqual(model.validate()["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
