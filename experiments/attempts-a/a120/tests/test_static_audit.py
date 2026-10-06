from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE.parent / "static_audit.py"
SPEC = importlib.util.spec_from_file_location("a120_static_audit", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


class StaticAuditTests(unittest.TestCase):
    def test_source_pins(self) -> None:
        evidence = AUDIT.audit_source_pins()
        self.assertGreaterEqual(len(evidence), 10)

    def test_exact_geometry_small_independent_sample(self) -> None:
        result = AUDIT.audit_geometry(random_trials=32)
        self.assertEqual(result["status"], "PASS_INDEPENDENT_EXACT_K4_RING_GEOMETRY")
        self.assertEqual(result["nonzero_mask_terms"], 1_016)
        self.assertEqual(result["distinct_nonzero_mask_indices"], 1_016)

    def test_every_exact_support_error(self) -> None:
        left = (1, 2, 3, 4)
        right = (11, 12, 13, 14)
        body = AUDIT.assemble_d2(left, right)
        for control, expected in (
            (AUDIT.LEFT_CONTROL, left),
            (AUDIT.RIGHT_CONTROL, right),
        ):
            for error in range(-AUDIT.STRICT_RADIUS, AUDIT.STRICT_RADIUS + 1):
                self.assertEqual(AUDIT.select_tuple(body, control, error), expected)
                self.assertEqual(
                    AUDIT.select_scalar_d2(left, right, control, error), expected
                )

    def test_outside_support_is_not_silently_claimed(self) -> None:
        body = AUDIT.assemble_d2((1, 2, 3, 4), (11, 12, 13, 14))
        for control, expected in (
            (AUDIT.LEFT_CONTROL, (1, 2, 3, 4)),
            (AUDIT.RIGHT_CONTROL, (11, 12, 13, 14)),
        ):
            for error in (-64, 64):
                self.assertNotEqual(AUDIT.select_tuple(body, control, error), expected)

    def test_mixed_scale_torus_words(self) -> None:
        left = (0, 15, 7, 127)
        right = (4, 0, 15, 0)
        encoded_left = tuple(value * delta for value, delta in zip(left, AUDIT.DELTAS))
        encoded_right = tuple(
            value * delta for value, delta in zip(right, AUDIT.DELTAS)
        )
        body = AUDIT.assemble_d2(encoded_left, encoded_right)
        for control, expected in (
            (AUDIT.LEFT_CONTROL, encoded_left),
            (AUDIT.RIGHT_CONTROL, encoded_right),
        ):
            self.assertEqual(AUDIT.select_tuple(body, control, -63), expected)
            self.assertEqual(AUDIT.select_tuple(body, control, 63), expected)

    def test_interior_margin_tie_reject_contract(self) -> None:
        result = AUDIT.audit_contract()
        self.assertEqual(result["fixture_count"], 8)
        self.assertEqual(result["requested_offset_set"], [-48, 0, 48])
        self.assertEqual(result["guard_band_degrees"], 15)
        self.assertIn("does not implement", result["warning"])

    def test_outcome_classification_truth_table(self) -> None:
        result = AUDIT.audit_outcome_classification()
        self.assertTrue(result["support_invalid_precedes_all_payload_interpretation"])
        self.assertTrue(result["packed_only_attribution_requires_prerequisites"])
        self.assertEqual(
            AUDIT.classify_case(True, True, False),
            "packed_semantic_failure_inside_support",
        )
        self.assertEqual(AUDIT.classify_case(True, True, True), "pass")

    def test_sign_and_wrap_mutations_are_detected(self) -> None:
        result = AUDIT.audit_negative_controls()
        self.assertTrue(result["k4_selected_cell_sign_flip_detected"])
        self.assertTrue(result["folded_cell_wrong_positive_sign_detected"])

    def test_preregistration_is_finite_and_frozen(self) -> None:
        result = AUDIT.audit_preregistration()
        self.assertEqual(result["primary_parameter"], "24x1")
        self.assertEqual(result["minimum_fresh_processes"], 3)
        self.assertEqual(result["fixed_fixture_count"], 8)

    def test_a108_datapath_is_byte_identical(self) -> None:
        result = AUDIT.audit_a108_datapath_equivalence()
        self.assertEqual(result["status"], "PASS_EXACT_A108_DATAPATH_FUNCTION_IDENTITY")
        self.assertEqual(len(result["identical_functions"]), 7)
        self.assertFalse(result["window_pfpks_rotation_lead_incorporated"])

    def test_rust_scaffold_shape(self) -> None:
        result = AUDIT.audit_rust_scaffold()
        self.assertTrue(result["guard_precedes_keygen"])
        self.assertEqual(result["println_format_records_checked"], 9)
        self.assertFalse(result["compile_attested"])
        self.assertFalse(result["fhe_attested"])

    def test_exact_container_ledger(self) -> None:
        result = AUDIT.pfpks_container_ledger()
        self.assertEqual(len(result["entries"]), 1)
        self.assertEqual(result["entries"][0]["label"], "24x1")
        self.assertEqual(result["entries"][0]["pfpks_bytes"], 67_141_632)
        self.assertEqual(
            result["source_level_logical_peak_live_dynamic_glwe_ciphertexts"], 3
        )

    def test_invalid_inputs_fail_closed(self) -> None:
        with self.assertRaises(AUDIT.AuditError):
            AUDIT.assemble_d2((1, 2, 3), (4, 5, 6))
        with self.assertRaises(AUDIT.AuditError):
            AUDIT.select_tuple((0,) * AUDIT.POLYNOMIAL_SIZE, 7, 0)
        with self.assertRaises(AUDIT.AuditError):
            AUDIT.interval_oracle((1,) * 4, (2,) * 4, AUDIT.LEFT_CONTROL, 64)


if __name__ == "__main__":
    unittest.main()
