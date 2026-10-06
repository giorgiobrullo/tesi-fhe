"""Offline fixtures only: no service, native commands, key loading or sockets."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("prepared_paired_http", Path(__file__).with_name("paired_http.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class HarnessTests(unittest.TestCase):
    def test_spec_rejects_wrong_schedule_and_missing_pair_receipt(self):
        fixture = json.loads(Path(__file__).with_name("spec.template.json").read_text())
        driver.validate_spec(fixture)
        broken = copy.deepcopy(fixture)
        broken["warmups_total"] = 9
        with self.assertRaises(RuntimeError):
            driver.validate_spec(broken)
        broken = copy.deepcopy(fixture)
        del broken["families"][2]["arms"][1]["keygen_receipt"]
        with self.assertRaises(RuntimeError):
            driver.validate_spec(broken)

    def test_schedule_is_balanced_and_bounded(self):
        steps = driver.schedule()
        self.assertEqual(len(steps), 24)
        for family in range(3):
            orders = [[role for f, b, _, role in steps if (f, b) == (family, block)] for block in range(4)]
            self.assertEqual(orders, [[0, 1], [1, 0], [0, 1], [1, 0]])

    def test_plain_oracle_first_tie_and_winner_threshold(self):
        zero = [0] * 512
        entries = [{"vettore": zero, "soglia": -1}, {"vettore": zero, "soglia": 1}]
        value = driver.oracle(entries, zero)
        self.assertEqual(value["winner_id"], 1)
        self.assertEqual(value["selected_id"], 0)
        entries[0]["soglia"] = 0
        self.assertEqual(driver.oracle(entries, zero)["selected_id"], 1)

    def test_summary_keeps_family_ratios_and_rejects_missing_or_bad_samples(self):
        rows = []
        for family, block, position, role in driver.schedule():
            for phase, repetitions in (("warmup", 1), ("measured", 2)):
                for repetition in range(repetitions):
                    for scene in driver.SCENES:
                        baseline = (10, 100, 1000)[family] + block
                        elapsed = baseline * ((.8, 1, 1.2)[family] if role else 1)
                        rows.append({"family": f"family{family}", "block": block, "position": position,
                                     "arm": ("baseline", "candidate")[role], "phase": phase,
                                     "repetition": repetition, "scene": scene, "elapsed_ms": elapsed,
                                     "http_elapsed_ns": int((elapsed + 2) * 1e6), "correct": True})
        result = driver.summarize(rows, ["baseline", "candidate"])
        self.assertEqual(result["measured_calls"], 144)
        self.assertEqual(result["warmup_calls"], 72)
        self.assertAlmostEqual(result["scenes"]["curie"]["median_family_ratio"], 1)
        with self.assertRaises(RuntimeError):
            driver.summarize(rows[:-1], ["baseline", "candidate"])
        broken = copy.deepcopy(rows)
        broken[0]["correct"] = False
        with self.assertRaises(RuntimeError):
            driver.summarize(broken, ["baseline", "candidate"])

    def test_cleanup_kills_only_owned_stub_and_closes_logs(self):
        class OwnedStub:
            pid, returncode = 123, None
            def __init__(self):
                self.calls = []
            def poll(self):
                return self.returncode
            def terminate(self):
                self.calls.append("terminate")
            def wait(self, timeout):
                self.calls.append("wait")
                if "kill" not in self.calls:
                    raise subprocess.TimeoutExpired("stub", timeout)
                self.returncode = -9
            def kill(self):
                self.calls.append("kill")
        pilot = object.__new__(driver.Pilot)
        owned = OwnedStub()
        log = io.StringIO()
        pilot.process, pilot.logs, pilot.event = owned, [log], lambda value: None
        pilot.stop()
        self.assertEqual(owned.calls, ["terminate", "wait", "kill", "wait"])
        self.assertIsNone(pilot.process)
        self.assertTrue(log.closed)
        pilot.stop()


if __name__ == "__main__":
    unittest.main()
