from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


MODULE_PATH = Path(__file__).parents[1] / "a117_static_gate.py"
SPEC = importlib.util.spec_from_file_location("a117_static_gate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
A117 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = A117
SPEC.loader.exec_module(A117)


class A117StaticGateTests(unittest.TestCase):
    def test_full_static_gate(self) -> None:
        result = A117.validate()
        self.assertEqual(result["status"], "STATIC_SOURCE_AND_PREREGISTRATION_ONLY")
        self.assertTrue(result["future_gate"]["no_feasibility_claim"])

    def test_boundary_prefix_and_strict_equality(self) -> None:
        pairs = A117.fixture()
        self.assertEqual(
            [(x - y, int(x < y)) for x, y in pairs[:6]],
            [(-4095, 1), (-1, 1), (0, 0), (0, 0), (1, 0), (4095, 0)],
        )

    def test_fixture_is_frozen_and_broad(self) -> None:
        pairs = A117.fixture()
        self.assertEqual(len(pairs), 16384)
        self.assertEqual(A117.fixture_fnv1a64(pairs), "0x6729df79f38554e2")
        self.assertEqual(len({x for x, _ in pairs}), 4096)
        self.assertEqual(len({y for _, y in pairs}), 4096)

    def test_context_geometry(self) -> None:
        self.assertEqual(A117.euler_phi(A117.M), 32768)
        self.assertEqual(A117.multiplicative_order(A117.P, A117.M), 2)
        self.assertEqual(A117.euler_phi(A117.M) // 2, A117.SLOTS)


if __name__ == "__main__":
    unittest.main()
