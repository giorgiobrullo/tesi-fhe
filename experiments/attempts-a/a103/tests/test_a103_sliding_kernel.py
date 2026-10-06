from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "a103_sliding_kernel.py"
SPEC = importlib.util.spec_from_file_location("a103_sliding_kernel", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
A103 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A103)


class A103SlidingKernelTests(unittest.TestCase):
    def test_source_pins(self) -> None:
        self.assertEqual(len(A103.verify_input_pins()), 2)

    def test_anti_periodic_boundary(self) -> None:
        polynomial = list(range(A103.POLYNOMIAL_SIZE))
        self.assertEqual(A103.anti_periodic_at(polynomial, 0), 0)
        self.assertEqual(A103.anti_periodic_at(polynomial, -1), -2047 % 2**64)
        self.assertEqual(A103.anti_periodic_at(polynomial, 2048), 0)
        self.assertEqual(A103.anti_periodic_at(polynomial, 2049), -1 % 2**64)

    def test_sparse_wrap_cases_match_literal_kernel(self) -> None:
        for index in (0, 1, 62, 63, 64, 1983, 1984, 1985, 2046, 2047):
            polynomial = [0] * A103.POLYNOMIAL_SIZE
            polynomial[index] = 0xFFFF_FFFF_FFFF_FFC5
            self.assertEqual(
                A103.sliding_width127(polynomial), A103.naive_width127(polynomial)
            )

    def test_full_static_gate(self) -> None:
        report = A103.build_report(random_trials=4)
        self.assertEqual(
            report["status"], "PASS_EXACT_CLEAR_RING_KERNEL_NO_RUNTIME_CLAIM"
        )
        ledger = report["exact_gate"]
        self.assertEqual(ledger["basis_vectors"], 2048)
        self.assertTrue(ledger["all_checks_pass"])


if __name__ == "__main__":
    unittest.main()
