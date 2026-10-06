#!/usr/bin/env python3
"""Pure-Python regression tests for the A60 static audit."""

from __future__ import annotations

import math
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import a60_raw_pfail_audit as audit  # noqa: E402


class A60RawPfailAuditTests(unittest.TestCase):
    def test_sources_are_hash_locked_and_fragments_located(self) -> None:
        evidence = audit.verify_sources()
        self.assertEqual(set(evidence), set(audit.SOURCES))
        for record in evidence.values():
            self.assertEqual(len(record["sha256"]), 64)
            self.assertTrue(record["fragment_lines"])
            self.assertTrue(all(line > 0 for line in record["fragment_lines"].values()))

    def test_independent_operation_ledger_matches_all_frozen_cores(self) -> None:
        self.assertEqual(
            audit.operation_counts(127),
            {
                "gallery_size": 127,
                "blind_rotations": 3655,
                "key_switches": 3274,
                "conservative_output_marginals": 4206,
            },
        )
        for label in ("a38_core", "a41_core", "a44_core"):
            source = audit.SOURCES[label].path.read_text(encoding="utf-8")
            self.assertIn("(127, 3655, 3274, 4206),", source)

    def test_conditional_union_arithmetic(self) -> None:
        p16 = audit.conditional_union(4206, -71.625)
        self.assertAlmostEqual(p16["union_probability"], 1.155036820341737e-18)
        self.assertAlmostEqual(p16["union_log2_probability"], -59.586766865268224)

        a44 = audit.conditional_union(4206, -64.088)
        self.assertAlmostEqual(a44["union_probability"], 2.145156127493913e-16)
        self.assertAlmostEqual(a44["union_log2_probability"], -52.04976686526822)

    def test_two_output_union_needs_no_independence_assumption(self) -> None:
        terminal = audit.conditional_union(2, -71.625)
        self.assertAlmostEqual(terminal["union_log2_probability"], -70.625)
        self.assertEqual(terminal["events"], 2)

    def test_no_nontrivial_current_e2e_bound_is_emitted(self) -> None:
        report = audit.make_report()
        for variant in report["variants"].values():
            self.assertFalse(variant["nontrivial_numeric_bound_established"])
            self.assertEqual(variant["current_formal_e2e_p_fail_upper"], 1.0)
            self.assertEqual(variant["current_formal_e2e_log2_upper"], 0.0)

    def test_a41_closes_only_the_terminal_obligation(self) -> None:
        variants = audit.make_report()["variants"]
        self.assertIn("conditionally closed", variants["A41"]["terminal"])
        self.assertIn("open", variants["A41"]["upstream"])
        self.assertIn("without a final PBS", variants["A38"]["terminal"])

    def test_a44_gaussian_is_unbounded_in_primary_source(self) -> None:
        source = audit.SOURCES["dynamic_distribution"].path.read_text(encoding="utf-8")
        self.assertGreaterEqual(
            source.count("Self::Gaussian(_) => Bound::Unbounded"), 2
        )
        report = audit.make_report()
        self.assertIn(
            "Gaussian fresh noise is unbounded", report["variants"]["A44"]["upstream"]
        )

    def test_noise_squashing_cannot_close_an_invalid_prefix(self) -> None:
        report = audit.make_report()["noise_squashing"]
        self.assertFalse(report["available_in_pinned_tfhe_0_11_3"])
        self.assertFalse(report["closes_prior_wrong_branch"])

    def test_probabilities_are_valid_only_under_explicit_premise(self) -> None:
        report = audit.make_report()
        conditional = report["variants"]["A41"]["conditional_4206_marginal_union"]
        self.assertLess(conditional["union_probability"], 1.0)
        self.assertTrue(math.isfinite(conditional["union_log2_probability"]))
        self.assertFalse(
            report["minimum_change"]["wrapping_raw_lwe_as_nominal_is_sufficient"]
        )


if __name__ == "__main__":
    unittest.main()
