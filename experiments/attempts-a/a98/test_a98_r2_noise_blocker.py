#!/usr/bin/env python3
"""Tests for the additive A98 R2 no-run blocker evidence."""

from __future__ import annotations

import importlib.util
import math
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("a98_r2_noise_blocker.py")
SPEC = importlib.util.spec_from_file_location("a98_r2_noise_blocker", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load blocker module")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class A98R2NoiseBlockerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = MODULE.report()

    def test_frozen_artifacts_and_sources_match(self) -> None:
        self.assertEqual(len(self.result["pins"]), 7)

    def test_official_formula_reproduction(self) -> None:
        formula = self.result["formula"]
        self.assertTrue(
            math.isclose(
                formula["predicted_variance_normalized"],
                9.2724864996007785e-10,
                rel_tol=1e-15,
            )
        )
        self.assertTrue(
            math.isclose(
                formula["minimum_secure_glwe_stddev"],
                2.8452674796019012e-15,
                rel_tol=1e-15,
            )
        )
        self.assertTrue(formula["precondition_matches_to_source_rounding"])
        self.assertTrue(
            math.isclose(
                formula["predicted_sigma_u64"],
                561717335795024.25,
                rel_tol=1e-15,
            )
        )
        self.assertTrue(
            math.isclose(
                formula["predicted_sigma_u64_log2"],
                48.996837656672646,
                rel_tol=1e-15,
            )
        )

    def test_compiled_cap_is_not_parameter_grounded(self) -> None:
        cap = self.result["invalid_frozen_cap"]
        self.assertLess(cap["cap_in_predicted_sigma"], 0.002)
        self.assertGreater(cap["predicted_sigma_over_cap"], 500.0)
        self.assertLess(
            cap["normal_marginal_probability_abs_error_inside_cap_diagnostic"],
            0.002,
        )

    def test_no_independence_or_pfail_overclaim(self) -> None:
        logic = self.result["logic"]
        self.assertFalse(logic["independence_assumed"])
        self.assertIn("not a certified tail bound", logic["normal_probability_scope"])
        self.assertIn("not a bound", logic["p_fail_scope"])

    def test_current_run_remains_unconsumed(self) -> None:
        self.assertEqual(self.result["status"], "BLOCKED_BEFORE_FHE_RUN")
        self.assertEqual(self.result["fhe_invocations_consumed"], 0)
        self.assertFalse(self.result["decision"]["run_current_binary"])
        self.assertFalse(self.result["decision"]["reuse_current_binary_for_r2b"])


if __name__ == "__main__":
    unittest.main()
