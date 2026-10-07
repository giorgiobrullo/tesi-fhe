from __future__ import annotations

import hashlib
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import a44_clear_geometry_noise_model as model  # noqa: E402


class A44ClearGeometryNoiseModelTests(unittest.TestCase):
    def test_reject_and_boundary_identities_keep_a41_two_lwe_semantics(self) -> None:
        self.assertEqual(model.evaluate((0,) * 128).code, 0)
        first = model.evaluate((1,) + (0,) * 127)
        self.assertEqual((first.low_nibble, first.high_nibble, first.code), (1, 0, 1))
        id_127 = model.evaluate((0,) * 126 + (1, 0))
        self.assertEqual(
            (id_127.low_nibble, id_127.high_nibble, id_127.code), (15, 7, 127)
        )
        id_128 = model.evaluate((0,) * 127 + (1,))
        self.assertEqual(
            (id_128.low_nibble, id_128.high_nibble, id_128.code), (0, 8, 128)
        )

    def test_first_tie_semantics_are_unchanged(self) -> None:
        result = model.evaluate((0,) * 63 + (1,) + (0,) * 62 + (1,))
        self.assertEqual(result.code, 64)
        tail = model.evaluate((0,) * 126 + (1, 1))
        self.assertEqual(tail.code, 127)

    def test_counts_and_wire_shape_are_exactly_a41(self) -> None:
        self.assertEqual(model.a44_counts(127), model.Counts(3_655, 3_274, 4_206))
        self.assertEqual(model.OUTPUT_LWES, 2)
        wire = model.wire_projection()
        self.assertEqual(wire["single_lwe_bytes"], 16_464)
        self.assertEqual(wire["two_lwe_bytes"], 32_856)
        self.assertEqual(wire["additional_bytes"], 16_392)

    def test_parameter_binding_matches_canonical_text_and_fails_closed(self) -> None:
        self.assertEqual(
            hashlib.sha256(model.PARAMETER_CANONICAL.encode()).hexdigest(),
            model.PARAMETER_FINGERPRINT_SHA256,
        )
        model.validate_parameter_binding(model.EXPECTED_BINDING)
        with self.assertRaisesRegex(ValueError, "params_id mismatch"):
            model.validate_parameter_binding(
                model.ParameterBinding(
                    params_id="wrong",
                    fingerprint_sha256=model.PARAMETER_FINGERPRINT_SHA256,
                )
            )
        with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
            model.validate_parameter_binding(
                model.ParameterBinding(
                    params_id=model.PARAMS_ID,
                    fingerprint_sha256="00",
                )
            )

    def test_all_official_p16_centers_have_strict_63_step_certificate(self) -> None:
        centers = model.official_p16_centers()
        self.assertEqual(len(centers), 16)
        self.assertEqual(model.P16_ROTATION_STEP, 128)
        self.assertEqual(model.P16_HALF_MARGIN_TORUS, 1 << 58)
        for center in centers:
            self.assertEqual(center.torus_center, center.code << 59)
            self.assertEqual(center.modulus_switch_rotation_center, center.code * 128)
            for error in range(-63, 64):
                self.assertTrue(model.p16_margin_certifies(error))
                self.assertEqual(model.nearest_p16_slot(center, error), center.code)
            for boundary in (-64, 64):
                self.assertFalse(model.p16_margin_certifies(boundary))
                with self.assertRaisesRegex(ValueError, "uncertified p16 boundary"):
                    model.nearest_p16_slot(center, boundary)

    def test_noise_ledger_uses_raw_l1_without_margin_rescaling(self) -> None:
        ledger = {entry.node_family: entry for entry in model.noise_ledger()}
        self.assertEqual(ledger["A34 residual classifier"].raw_l1, 8)
        self.assertEqual(ledger["A36 current two-chunk path"].raw_l1, 10)
        self.assertEqual(ledger["A40 prospective gallery OR fan-in 7"].raw_l1, 7)
        self.assertFalse(
            ledger["A40 prospective gallery OR fan-in 7"].in_materialized_a44_graph
        )
        for entry in ledger.values():
            self.assertLessEqual(entry.raw_l1, 15)
            self.assertEqual(entry.margin_rescaling_factor, 1)
            self.assertEqual(entry.headroom, 15 - entry.raw_l1)

    def test_rust_materialization_pins_only_a44_parameter_and_guarded_api(self) -> None:
        core = (ROOT / "src" / "private_argmin.rs").read_text()
        library = (ROOT / "src" / "lib.rs").read_text()
        harness = (ROOT / "src" / "bin" / "a44_p16_retune_prototype.rs").read_text()
        expected_symbol = "V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64"
        self.assertIn(expected_symbol, core)
        self.assertIn(expected_symbol, harness)
        self.assertNotIn("MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM", core)
        self.assertNotIn("MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM", harness)
        self.assertIn("private_argmin_two_lwe_a44_with_trace", harness)
        self.assertIn("validate_a44_parameter_binding", core)
        self.assertIn("A44ParameterGeometryMismatch", core)
        self.assertIn("private_argmin_two_lwe_a44", library)
        self.assertNotIn("private_argmin_two_lwe,", library)
        self.assertIn("const A38_REDUCTION_RADIX: usize = 5", core)
        self.assertIn("const OR_BLOCK: usize = 4", core)
        rust_canonical = re.search(
            r'pub const A44_PARAMETER_CANONICAL: &str = "([^"]+)";', core
        )
        rust_fingerprint = re.search(
            r'A44_PARAMETER_FINGERPRINT_SHA256: &str =\s*"([0-9a-f]+)";', core
        )
        self.assertIsNotNone(rust_canonical)
        self.assertIsNotNone(rust_fingerprint)
        self.assertEqual(rust_canonical.group(1), model.PARAMETER_CANONICAL)
        self.assertEqual(rust_fingerprint.group(1), model.PARAMETER_FINGERPRINT_SHA256)

    def test_open_cryptographic_obligations_are_not_promoted(self) -> None:
        summary = model.validate()
        self.assertIsNone(summary["end_to_end_numeric_upper"])
        self.assertFalse(summary["a41_component_fhe_validated"])
        self.assertFalse(summary["a44_component_fhe_validated"])
        self.assertFalse(summary["a40_combination_materialized"])
        self.assertIn("raw_lut_equivalence", summary["open_obligations"])
        self.assertIn(
            "manylut_output_correlation_and_event_accounting",
            summary["open_obligations"],
        )
        premise = summary["conditional_union_bound"]["premise"]
        self.assertIn("only if", premise)

    def test_full_static_validation(self) -> None:
        summary = model.validate()
        self.assertEqual(summary["status"], "PASS")
        self.assertEqual(summary["p16_geometry"]["certified_points_checked"], 2_032)
        self.assertEqual(summary["p16_geometry"]["uncertified_boundaries_checked"], 32)
        self.assertTrue(summary["all_ledger_raw_l1_le_15"])
        self.assertFalse(summary["margin_rescaling_used"])


if __name__ == "__main__":
    unittest.main()
