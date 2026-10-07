#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import epfl_priority_audit as audit  # noqa: E402


class A82PriorityAuditTests(unittest.TestCase):
    def test_pinned_official_rtl_passes_sample_and_symbolic_gates(self) -> None:
        result = audit.audit_official_rtl(HERE / "official_priority.v")
        self.assertEqual(result["rtl"]["assignments"], 978)
        self.assertEqual(result["rtl"]["tested_patterns"], 258)
        self.assertEqual(
            result["formal_reversed_exact_contract"]["status"],
            "UNSAT_NO_COUNTEREXAMPLE",
        )
        self.assertEqual(
            result["rtl"]["reversed_one_hot_exact_codes"],
            list(range(1, 129)),
        )

    def test_expression_parser_obeys_verilog_precedence(self) -> None:
        environment = {"a": 0, "b": 1, "c": 0}
        self.assertEqual(audit.ExpressionParser("~a & b | c", environment).evaluate(), 1)
        self.assertEqual(audit.ExpressionParser("~(a | b) & ~c", environment).evaluate(), 0)

    def test_assignment_replay_rejects_a_missing_producer(self) -> None:
        with self.assertRaisesRegex(audit.AuditError, "missing producer"):
            audit.evaluate_assignments((("out", "a & missing"),), {"a": 1})

    def test_a53_n128_count_is_source_pinned(self) -> None:
        comparison = audit.structural_comparison()
        self.assertEqual(comparison.input_flags, 128)
        self.assertEqual(comparison.a53_blind_rotations, 136)
        self.assertEqual(comparison.a53_key_switches, 136)
        self.assertEqual(comparison.a53_marginals, 168)

    def test_structural_ratio_is_arithmetic_not_runtime(self) -> None:
        comparison = audit.structural_comparison()
        self.assertAlmostEqual(comparison.operation_count_ratio_a53_br_over_bolt_gate, 136 / 686)
        self.assertAlmostEqual(
            comparison.arithmetic_count_complement_percent,
            100 * (1 - 136 / 686),
        )
        self.assertAlmostEqual(comparison.bolt_gate_nodes_per_a53_blind_rotation, 686 / 136)

    def test_escaped_ports_are_normalized_narrowly(self) -> None:
        source = "  assign \\P[0]  = ~\\A[0]  & \\A[1] ;\n"
        self.assertEqual(
            audit.parse_assignments(source),
            (("P[0]", "~A[0] & A[1]"),),
        )

    def test_parser_rejects_unsupported_tokens(self) -> None:
        with self.assertRaisesRegex(audit.AuditError, "unsupported expression token"):
            audit.ExpressionParser("a ^ b", {"a": 0, "b": 1})

    def test_reversed_output_decode_is_exact_zero_or_id(self) -> None:
        self.assertEqual(audit.decode_reversed_exact_code(audit.Output(0, 0)), 0)
        self.assertEqual(audit.decode_reversed_exact_code(audit.Output(127, 1)), 1)
        self.assertEqual(audit.decode_reversed_exact_code(audit.Output(64, 1)), 64)
        self.assertEqual(audit.decode_reversed_exact_code(audit.Output(0, 1)), 128)

    def test_small_symbolic_priority_contract_and_counterexample(self) -> None:
        correct = (
            ("F", "A[0] | A[1] | A[2] | A[3]"),
            ("P[0]", "A[3] | (~A[3] & ~A[2] & A[1])"),
            ("P[1]", "A[3] | (~A[3] & A[2])"),
        )
        proof = audit.formally_prove_reversed_exact_contract(
            correct,
            input_flags=4,
            output_bits=2,
        )
        self.assertEqual(proof["status"], "UNSAT_NO_COUNTEREXAMPLE")

        wrong = correct[:-1] + (("P[1]", "A[2]"),)
        with self.assertRaisesRegex(audit.AuditError, "counterexample"):
            audit.formally_prove_reversed_exact_contract(
                wrong,
                input_flags=4,
                output_bits=2,
            )


if __name__ == "__main__":
    unittest.main()
