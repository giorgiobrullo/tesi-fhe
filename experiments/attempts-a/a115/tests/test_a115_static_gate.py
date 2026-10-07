from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "a115_static_gate", ROOT / "a115_static_gate.py"
)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class A115StaticGateTests(unittest.TestCase):
    def test_exact_candidate_geometry(self) -> None:
        self.assertEqual(GATE.euler_phi(GATE.M), 32768)
        self.assertEqual(GATE.multiplicative_order(GATE.P, GATE.M), 2)
        self.assertEqual(GATE.euler_phi(GATE.M) // 2, 16384)
        self.assertEqual((GATE.P - 1) // 2, GATE.SCORE_MAX)

    def test_n127_lane_capacity(self) -> None:
        self.assertEqual(GATE.PAIR_LANES, 8001)
        self.assertEqual(GATE.PAIR_LANES + GATE.THRESHOLD_LANES, 8128)
        self.assertEqual(GATE.FACTOR_LANES, 16256)
        self.assertLessEqual(GATE.FACTOR_LANES, 16384)

    def test_q_sweep_is_bounded_and_ordered(self) -> None:
        self.assertEqual(tuple(sorted(set(GATE.REQUESTED_BITS))), GATE.REQUESTED_BITS)
        self.assertGreaterEqual(GATE.REQUESTED_BITS[0], 100)
        self.assertLessEqual(GATE.REQUESTED_BITS[-1], 2400)

    def test_probe_is_context_only_and_load_guarded(self) -> None:
        source = (ROOT / "src/main.cpp").read_text()
        for forbidden in ("SecKey", "GenSecKey", ".Encrypt(", ".Decrypt("):
            self.assertNotIn(forbidden, source)
        self.assertIn("getloadavg", source)
        self.assertIn("kHardLoadCeiling = 24.0", source)

    def test_full_static_gate(self) -> None:
        result = GATE.validate()
        self.assertEqual(result["status"], "STATIC_SOURCE_GATE_PASS")
        self.assertTrue(result["claims"]["no_keygen"])
        self.assertTrue(result["claims"]["no_frontier_promotion"])


if __name__ == "__main__":
    unittest.main()
