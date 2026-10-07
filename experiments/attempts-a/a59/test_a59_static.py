from __future__ import annotations

import hashlib
import runpy
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import a59_max15_two_lwe_static as model  # noqa: E402


class A59Max15TwoLweStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary = model.validate()

    def test_a59_freezes_an_existing_a44_a41_combination(self) -> None:
        self.assertFalse(self.summary["a59_is_new_graph"])
        self.assertIn("A44 already materializes", self.summary["integration_result"])
        self.assertEqual(
            self.summary["scope"],
            "clear_semantics_structure_and_binding_only_no_build_no_fhe",
        )

    def test_parameter_fingerprint_and_a44_guard_match(self) -> None:
        self.assertEqual(
            hashlib.sha256(model.PARAMETER_CANONICAL.encode()).hexdigest(),
            model.PARAMETER_FINGERPRINT_SHA256,
        )
        self.assertEqual(model.MESSAGE_MODULUS * model.CARRY_MODULUS, 16)
        self.assertEqual(model.MAX_NOISE_LEVEL, 15)
        self.assertTrue(
            self.summary["a44_rust_contract"]["guarded_two_lwe_entrypoint_present"]
        )
        self.assertTrue(self.summary["a44_rust_contract"]["old_a41_parameter_absent"])

    def test_all_frozen_source_anchors_match(self) -> None:
        anchors = self.summary["source_anchors"]
        self.assertEqual(len(anchors), 5)
        self.assertTrue(all(anchor["matches"] for anchor in anchors))

    def test_exact_id_reject_threshold_equality_and_first_tie(self) -> None:
        reject = model.evaluate_scores((9, 1, 2), threshold=0)
        self.assertEqual((reject.low, reject.high, reject.code), (0, 0, 0))

        equality = model.evaluate_scores((9, 1, 2), threshold=1)
        self.assertEqual((equality.low, equality.high, equality.code), (2, 0, 2))

        tie = model.evaluate_scores((7, 2, 9, 2), threshold=2)
        self.assertEqual((tie.low, tie.high, tie.code), (2, 0, 2))

        id_127 = model.evaluate_candidates((0,) * 126 + (1, 0))
        self.assertEqual((id_127.low, id_127.high, id_127.code), (15, 7, 127))
        id_128 = model.evaluate_candidates((0,) * 127 + (1,))
        self.assertEqual((id_128.low, id_128.high, id_128.code), (0, 8, 128))

    def test_every_protocol_code_round_trips_through_two_p16_digits(self) -> None:
        for code in range(129):
            low, high = model.split_code(code)
            self.assertLess(low, 16)
            self.assertLessEqual(high, 8)
            self.assertEqual(model.reconstruct_code(low, high), code)

    def test_n127_and_n128_counts_include_stage_breakdown(self) -> None:
        n127 = model.operation_breakdown(127)
        self.assertEqual(n127.groups, 43)
        self.assertEqual(
            (
                n127.unchanged_core_blind_rotations,
                n127.low_path_blind_rotations,
                n127.scan_output_blind_rotations,
            ),
            (1_904, 1_550, 201),
        )
        self.assertEqual(n127.counts, model.Counts(3_655, 3_274, 4_206))

        n128 = model.operation_breakdown(128)
        self.assertEqual(n128.groups, 43)
        self.assertEqual(
            (
                n128.unchanged_core_blind_rotations,
                n128.low_path_blind_rotations,
                n128.scan_output_blind_rotations,
            ),
            (1_919, 1_560, 203),
        )
        self.assertEqual(n128.counts, model.Counts(3_682, 3_298, 4_237))

    def test_counts_match_a41_and_a44_models_for_every_supported_n(self) -> None:
        a41 = runpy.run_path(
            model.REPO_ROOT
            / "tmp/a41-combined-two-lwe-prototype/a41_clear_and_count_model.py",
            run_name="a41_cross_check",
        )
        a44 = runpy.run_path(
            model.REPO_ROOT
            / "tmp/a44-p16-retune-prototype/a44_clear_geometry_noise_model.py",
            run_name="a44_cross_check",
        )
        for gallery_size in range(1, 129):
            ours = model.operation_breakdown(gallery_size).counts
            a41_counts = a41["a41_counts"](gallery_size)
            a44_counts = a44["a44_counts"](gallery_size)
            expected = (
                ours.blind_rotations,
                ours.key_switches,
                ours.output_marginals,
            )
            self.assertEqual(
                expected,
                (
                    a41_counts.blind_rotations,
                    a41_counts.key_switches,
                    a41_counts.output_marginals,
                ),
            )
            self.assertEqual(
                expected,
                (
                    a44_counts.blind_rotations,
                    a44_counts.key_switches,
                    a44_counts.output_marginals,
                ),
            )

    def test_raw_l1_fits_numerically_but_does_not_close_transfer(self) -> None:
        ledger = {row.node_family: row for row in model.noise_ledger()}
        self.assertEqual(ledger["A34 residual classifier"].raw_l1, 8)
        self.assertEqual(ledger["A36 current two-chunk path"].raw_l1, 10)
        self.assertEqual(ledger["A38/A41 radix-5 scan reductions"].raw_l1, 5)
        self.assertEqual(ledger["A41 terminal low/high p16 roots"].raw_l1, 5)
        self.assertTrue(all(row.raw_l1 <= 15 for row in ledger.values()))
        self.assertTrue(
            all(
                "open" in row.transfer_status or "conditionally" in row.transfer_status
                for row in ledger.values()
            )
        )

    def test_failure_numbers_are_explicitly_conditional_and_not_double_counted(
        self,
    ) -> None:
        n127 = model.conditional_failure_arithmetic(127)
        self.assertEqual(n127["terminal_events"], 2)
        self.assertAlmostEqual(n127["terminal_log2_upper"], -63.088, places=12)
        self.assertEqual(n127["all_marginal_events_including_terminal"], 4_206)
        self.assertAlmostEqual(
            n127["all_marginals_log2_upper"], -52.04976686526821, places=12
        )
        self.assertFalse(n127["independence_assumed"])
        self.assertTrue(n127["terminal_already_in_all_marginals"])
        self.assertIn("only if", n127["premise"])

        n128 = model.conditional_failure_arithmetic(128)
        self.assertEqual(n128["all_marginal_events_including_terminal"], 4_237)
        self.assertAlmostEqual(
            n128["all_marginals_log2_upper"], -52.039172586636106, places=12
        )

    def test_geometry_is_strict_at_half_cell_boundaries(self) -> None:
        geometry = self.summary["p16_geometry"]
        self.assertEqual(geometry["rotation_step"], 128)
        self.assertEqual(geometry["strict_certified_error_interval"], [-63, 63])
        self.assertEqual(geometry["uncertified_half_cell_boundaries"], [-64, 64])
        self.assertEqual(geometry["strict_points_checked"], 2_032)

    def test_wire_projection_and_promotion_gate_are_unambiguous(self) -> None:
        self.assertEqual(self.summary["wire"]["single_lwe_bytes"], 16_464)
        self.assertEqual(self.summary["wire"]["two_lwe_bytes"], 32_856)
        self.assertEqual(self.summary["wire"]["additional_bytes"], 16_392)
        self.assertFalse(self.summary["component_fhe_validated"])
        self.assertIsNone(self.summary["end_to_end_numeric_p_fail_upper"])
        self.assertEqual(
            self.summary["promotion_status"], "NO_GO_UNTIL_OPEN_OBLIGATIONS_CLOSE"
        )


if __name__ == "__main__":
    unittest.main()
