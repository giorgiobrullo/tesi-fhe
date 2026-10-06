"""Deterministic regressions for the static A38 failure-budget audit."""

from __future__ import annotations

import math
import unittest

import a38_failure_budget as audit


class FrozenInputsTest(unittest.TestCase):
    def test_hashes_and_parameter_contract(self) -> None:
        self.assertEqual(audit.verify_sources(), audit.EXPECTED_SHA256)
        audit.verify_frozen_contract_fragments()
        parameter = audit.extract_parameter_contract()
        self.assertEqual(parameter["tfhe_rs"], "0.11.3")
        self.assertEqual(parameter["total_plaintext_modulus"], 16)
        self.assertEqual(parameter["max_noise_level"], 5)
        self.assertEqual(parameter["log2_p_fail"], -71.625)


class OperationAccountingTest(unittest.TestCase):
    def test_exact_source_fixtures(self) -> None:
        expected = {
            1: (25, 22, 30),
            2: (60, 54, 69),
            3: (85, 76, 98),
            64: (1835, 1643, 2113),
            127: (3655, 3274, 4206),
            128: (3682, 3298, 4237),
        }
        for gallery_size, values in expected.items():
            result = audit.a38_operation_counts(gallery_size)
            self.assertEqual(
                (
                    result["blind_rotations"],
                    result["key_switches"],
                    result["output_marginals_conservative"],
                ),
                values,
            )

    def test_n127_extra_marginals_and_key_switch_gap(self) -> None:
        result = audit.a38_operation_counts(127)
        self.assertEqual(result["scan_groups"], 43)
        self.assertEqual(result["multi_output_extra_marginals"], 4 * 127 + 43)
        self.assertEqual(
            result["blind_rotations_without_distinct_key_switch"], 3 * 127
        )


class ProbabilityArithmeticTest(unittest.TestCase):
    def test_union_bound_requires_no_independence(self) -> None:
        for events in (2, 3655, 4206, 4460, 4908):
            result = audit.conditional_union(events, audit.NOMINAL_LOG2_P_FAIL)
            self.assertFalse(result["independence_required"])
            self.assertAlmostEqual(
                result["probability_upper"],
                events * 2.0**audit.NOMINAL_LOG2_P_FAIL,
            )
            self.assertAlmostEqual(
                result["log2_probability_upper"],
                audit.NOMINAL_LOG2_P_FAIL + math.log2(events),
            )

    def test_current_and_strict_a36_schedules_are_not_confused(self) -> None:
        current = audit.current_a36_noise_schedule()
        self.assertEqual(current["zero_test_input_raw_l1"], (4, 6, 8, 10, 3, 4, 6, 8))
        self.assertEqual(current["maximum_raw_l1"], 10)
        self.assertTrue(current["uses_unproved_double_margin_rescaling"])

        strict = audit.strict_a36_projection(audit.a38_operation_counts(127))
        self.assertEqual(strict["zero_test_input_raw_l1"], (3, 5, 3, 5, 3, 4, 2, 4))
        self.assertEqual(strict["maximum_raw_l1"], 5)
        self.assertEqual(strict["extra_blind_rotations"], 254)
        self.assertEqual(
            (
                strict["blind_rotations"],
                strict["key_switches"],
                strict["output_marginals_conservative"],
            ),
            (3909, 3528, 4460),
        )

    def test_zero_failure_empirical_limit_is_not_crypto_pfail(self) -> None:
        self.assertAlmostEqual(audit.zero_failure_upper(632), 0.004728866248583152)

    def test_report_refuses_end_to_end_number(self) -> None:
        result = audit.report()
        self.assertIsNone(result["conditional_arithmetic"]["end_to_end_numeric_upper"])
        self.assertIsNone(result["current_terminal"]["failure_probability_upper"])
        self.assertFalse(
            result["current_a36"]["nominal_parameter_precondition_established"]
        )
        self.assertFalse(
            result["conditional_arithmetic"]["blind_rotation_only"]
            ["sufficient_for_a38_multi_output_graph"]
        )
        self.assertTrue(
            result["two_lwe_p16_terminal_option"]
            ["closes_terminal_under_nominal_contract"]
        )
        self.assertFalse(
            result["two_lwe_p16_terminal_option"]["closes_end_to_end"]
        )


if __name__ == "__main__":
    unittest.main()
