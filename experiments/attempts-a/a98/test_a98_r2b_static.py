#!/usr/bin/env python3
"""Unit tests for the A98-R2B static, no-runtime gate."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("a98_r2b_static_gate.py")
SPEC = importlib.util.spec_from_file_location("a98_r2b_static_gate", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load A98-R2B static gate")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class A98R2BStaticTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = MODULE.report()

    def test_status_is_static_only(self) -> None:
        self.assertEqual(self.result["status"], "PASS_STATIC_R2B_NOT_BUILT_NOT_RUN")
        self.assertEqual(self.result["cargo_or_rustc_invocations"], 0)
        self.assertEqual(self.result["keygen_or_fhe_invocations"], 0)

    def test_all_static_checks_pass(self) -> None:
        self.assertEqual(len(self.result["checks"]), 13)
        self.assertEqual(set(self.result["checks"].values()), {"PASS"})

    def test_inherited_case_ledger(self) -> None:
        self.assertEqual(self.result["case_count"], 14)
        self.assertEqual(self.result["tie_zero_cases"], 6)
        self.assertEqual(self.result["tie_one_cases"], 8)

    def test_no_runtime_claim(self) -> None:
        boundary = self.result["claim_boundary"]
        for term in ("no lockfile", "runtime", "p_fail", "exact-ID"):
            self.assertIn(term, boundary)


if __name__ == "__main__":
    unittest.main()
