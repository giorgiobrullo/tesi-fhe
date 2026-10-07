"""Semantic and negative controls for the clear gate; no FHE work."""

import importlib.util
import itertools
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("a126_gate", HERE / "gate.py")
gate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gate
spec.loader.exec_module(gate)


class RefreshGateTests(unittest.TestCase):
    def test_source_drift_rejected(self):
        original = Path.read_bytes
        pinned = gate.ROOT / "tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs"

        def modified(path):
            raw = original(path)
            return raw + b" " if path == pinned else raw

        with patch.object(Path, "read_bytes", modified):
            with self.assertRaisesRegex(ValueError, "source hash mismatch"):
                gate.source_texts()

    def test_negacyclic_extension_is_not_mod16(self):
        self.assertEqual(gate.sample(gate.target_body(), 1), 1)
        self.assertEqual(gate.sample(gate.target_body(), -15), -1)

    def test_lone_level6_breaks_actual_scan(self):
        trace = gate.gallery_trace((False, True), (0, 0), (6,))
        self.assertEqual(trace["actual"], (-1, 1))
        self.assertEqual(trace["expected"], (0, 1))
        actual = gate.scan_group(trace["actual"])
        self.assertEqual((actual["flag"], actual["local"]), (0, 0))

    def test_final_only_fixes_semantics_but_exceeds_nominal_l1(self):
        result = gate.schedule_gate((7,))
        self.assertTrue(result["final_canonical"])
        self.assertEqual(result["semantic_errors"], [])
        self.assertEqual(
            result["noise_inputs_above_15"],
            [("zero_or_fusion:7", 16), ("refresh:7", 17)],
        )

    def test_two_refresh_repair_preserves_both_interfaces(self):
        self.assertTrue(gate.schedule_gate((6, 7))["conditional_unchanged_scan_gate"])

    def test_unchanged_input_cannot_emit_both_values(self):
        requirements = []
        for state, bit in itertools.product(range(-4, 2), (0, 1)):
            requirements.append((state - bit, 0, int(state == 1)))
        self.assertIsNone(gate.assign_requirements(requirements))

    def test_fusion_has_margin_for_all_tuples_and_both_outputs(self):
        for phase, degree, desired in gate.fusion_requirements(6, 768):
            for error in range(-63, 64):
                self.assertEqual(
                    gate.sample(gate.fusion_body(), phase, degree, error), desired
                )

    def test_wrong_sample_degree_rejected(self):
        self.assertIsNone(gate.assign_requirements(gate.fusion_requirements(6, 1024)))

    def test_margin_not_extrapolated_to_closed_radius64(self):
        self.assertEqual(gate.sample(gate.fusion_body(), 1, 0, 63), 1)
        self.assertNotEqual(gate.sample(gate.fusion_body(), 1, 0, 64), 1)

    def test_fusion_resets_candidate_and_retains_final_refresh(self):
        result = gate.schedule_gate((7,), fused=True)
        self.assertTrue(result["conditional_unchanged_scan_gate"])
        self.assertEqual(result["rows"][4]["input_l1"], 15)
        self.assertEqual(result["rows"][4]["linear_candidate_l1"], 3)
        self.assertEqual(result["rows"][7]["linear_candidate_l1"], 9)

    def test_shared_noise_cancels_but_independent_labels_do_not(self):
        self.assertEqual(gate.combine((1, {"same": 1}), (-1, {"same": 1})), {})
        self.assertEqual(gate.l1(gate.combine((1, {"a": 1}), (-1, {"b": 1}))), 2)

    def test_all_suffix_values_with_mixed_eligibility_and_ties(self):
        for byte in range(256):
            suffixes = (byte, byte ^ 8, byte, 255 - byte)
            for initial in itertools.product((False, True), repeat=4):
                trace = gate.gallery_trace(initial, suffixes, (7,), fused=True)
                self.assertTrue(trace["pass"], (initial, suffixes, trace))
                scanned = gate.scan_group(trace["actual"])
                expected = next(
                    (i + 1 for i, alive in enumerate(trace["expected"]) if alive), 0
                )
                self.assertEqual(scanned["local"], expected)


if __name__ == "__main__":
    unittest.main()
