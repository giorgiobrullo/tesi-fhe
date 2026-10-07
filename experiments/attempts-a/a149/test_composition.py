"""Tests of the composition boundary, not repeated A145 algebra or real FHE."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from coefficients import verify_event
from materialize import HERE, OBSERVER, PADDING, verify_sources
from private_io import private_text
from replay import replay
from synthetic import BINARY, stream


class Composition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = stream(nonzero_errors=True)

    def test_server_evaluator_and_observer_are_frozen(self):
        self.assertEqual(verify_sources(), 16)
        main = (HERE / "src/main.rs").read_text()
        old = (PADDING / "src/main.rs").read_text()
        self.assertEqual(
            main.split("fn main()", 1)[0].replace("mod coefficient_observer;\n", ""),
            old.split("fn main()", 1)[0],
        )
        self.assertEqual(
            (HERE / "src/coefficient_observer.rs").read_bytes(),
            (OBSERVER / "candidate/src/coefficient_observer.rs").read_bytes(),
        )
        self.assertEqual(
            (HERE / "coefficients.py").read_bytes(),
            (OBSERVER / "coefficients.py").read_bytes(),
        )
        for name in [
            "graph.py",
            "regions.py",
            "a135_model.py",
            "a138_model.py",
            "src/a34_tables.rs",
        ]:
            self.assertEqual(
                (HERE / name).read_bytes(), (PADDING / name).read_bytes(), name
            )
        self.assertEqual(main.count("coefficient_observer::observe("), 1)
        self.assertGreater(
            main.index("coefficient_observer::observe("),
            main.index("let evaluations: Vec<_>"),
        )

    def test_full_declared_six_arm_stream_with_nonzero_errors(self):
        result = replay(self.records, BINARY)
        self.assertTrue(result["coefficient_gate_pass"])
        self.assertTrue(result["joint_witness_pass"])
        self.assertEqual(result["events_checked"], 346)
        self.assertEqual(result["cases_checked"], 6)
        self.assertEqual(result["negative_arm_failures_detected_by_key"], [[1, 1]])
        self.assertEqual(result["status"], "SYNTHETIC_REPLAY")
        self.assertFalse(result["secret_aggregate_key_membership_attested"])
        self.assertFalse(result["noise_improvement_established"])

    def test_both_padding_arms_have_realized_public_coefficient_witnesses(self):
        for arm, count in [(2, 55), (3, 63)]:
            events = [
                r
                for r in self.records
                if r.get("record") == "event" and r["arm"] == arm
            ]
            self.assertEqual(len(events), count)
            for event in events:
                report = verify_event(event)
                self.assertTrue(report["coefficient_closure_pass"])
                self.assertEqual(report["observed_ms_displacement"], 1)

    def test_composition_mutations_fail_before_promotion(self):
        for kind in [
            "missing_observer",
            "word",
            "aggregate",
            "summary_count",
            "observer_hash",
            "missing_padding_arm",
            "full_scope",
            "final_scale",
        ]:
            changed = copy.deepcopy(self.records)
            event = next(r for r in changed if r["record"] == "event")
            case = next(r for r in changed if r["record"] == "case")
            if kind == "missing_observer":
                del event["coefficient_observer"]
            elif kind == "word":
                event["coefficient_observer"]["post_ks_words_hex"][0] = (
                    "0000000000000001"
                )
            elif kind == "aggregate":
                event["coefficient_observer"][
                    "client_weighted_mask_residues_decimal"
                ] = "123"
            elif kind == "summary_count":
                changed[-1]["coefficient_events"] -= 1
            elif kind == "observer_hash":
                changed[1]["observer_sha256"] = "f" * 64
            elif kind == "missing_padding_arm":
                changed = [r for r in changed if r.get("arm") != 3]
            elif kind == "full_scope":
                changed[0]["suite"] = "full8"
            else:
                case["required_final_output_log"] = 63
            with self.assertRaises((AssertionError, KeyError), msg=kind):
                replay(changed, BINARY)

    def test_private_exclusive_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            with private_text(path) as output:
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                json.dump({"synthetic": True}, output)
            with self.assertRaises(FileExistsError):
                private_text(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
