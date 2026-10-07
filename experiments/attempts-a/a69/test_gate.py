from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest


PATH = pathlib.Path(__file__).with_name("run_gate.py")


def load_gate():
    spec = importlib.util.spec_from_file_location("_a69_gate", PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load A69 gate")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class A69EvidenceGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.gate = load_gate()

    def test_suite_cardinalities_are_frozen(self) -> None:
        self.assertEqual(len(self.gate.SUITES["small"].cases), 22)
        self.assertEqual(len(self.gate.SUITES["focused_one"].cases), 6)
        self.assertEqual(len(self.gate.SUITES["focused_three"].cases), 6)
        self.assertEqual(len(self.gate.SUITES["full"].cases), 32)

    def test_base15_boundaries(self) -> None:
        expected = {60: (0, 4), 64: (4, 4), 127: (7, 8), 128: (8, 8)}
        for code, digits in expected.items():
            case = self.gate.Case("boundary", 128, code)
            self.assertEqual((case.low, case.high), digits)
            self.assertEqual(case.low + 15 * case.high, code)

    def test_runtime_count_anchors(self) -> None:
        self.assertEqual(self.gate.COUNTS[1], (25, 22, 30))
        self.assertEqual(self.gate.COUNTS[127], (3390, 3009, 3930))
        self.assertEqual(self.gate.COUNTS[128], (3415, 3031, 3959))

    def test_actual_bundle_passes_and_totals_142(self) -> None:
        result = self.gate.validate_bundle(self.gate.DEFAULT_PATHS)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["total_fhe_evaluations"], 142)
        self.assertEqual(result["key_block_declarations"], 8)
        self.assertTrue(result["component_fhe_validated"])
        self.assertFalse(result["promotion_allowed"])

    def test_tampered_base15_digit_fails_closed(self) -> None:
        suite = self.gate.SUITES["focused_one"]
        text = self.gate.read_result(self.gate.DEFAULT_PATHS["focused_one"])
        changed = text.replace("code=127,low=7,high=8", "code=127,low=8,high=8", 1)
        with self.assertRaisesRegex(RuntimeError, "mismatch"):
            self.gate.validate_suite(changed, suite)

    def test_tampered_count_and_truncated_full_fail_closed(self) -> None:
        suite = self.gate.SUITES["focused_one"]
        text = self.gate.read_result(self.gate.DEFAULT_PATHS["focused_one"])
        changed = text.replace("pbs=3390", "pbs=3389", 1)
        with self.assertRaisesRegex(RuntimeError, "mismatch"):
            self.gate.validate_suite(changed, suite)

        full = self.gate.read_result(self.gate.DEFAULT_PATHS["full"])
        truncated = "\n".join(full.splitlines()[:-1]) + "\n"
        with self.assertRaisesRegex(RuntimeError, "record count"):
            self.gate.validate_suite(truncated, self.gate.SUITES["full"])

    def test_canonical_json(self) -> None:
        self.assertEqual(
            self.gate.canonical_json({"z": 1, "a": {"y": 2, "x": 3}}),
            '{"a":{"x":3,"y":2},"z":1}',
        )


if __name__ == "__main__":
    unittest.main()
