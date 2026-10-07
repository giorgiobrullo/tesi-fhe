import copy
import unittest
from run_gate import busy_lines, validate
from model import body_at


class LauncherTests(unittest.TestCase):
    def synthetic(self):
        return [
            {"type": "meta", "arm": "synthetic", "source_id": "frozen"},
            {
                "type": "synthetic_library_ks32",
                "difference_u32": 65536,
                "direct": [0, 65536],
                "wrong_prerounded": [0, 0],
            },
            {"type": "summary", "arm": "synthetic", "synthetic_pass": True},
        ]

    def fresh(self):
        rows = [{"type": "meta", "arm": "fresh-key", "source_id": "frozen"}]
        for channel, delta in [("full", 52), ("low", 60)]:
            body = [(-(1 << (delta - 1))) % (1 << 64)] * 1024 + [
                (-(1 << 58)) % (1 << 64)
            ] * 1024
            for x in [512, 513]:
                outputs = []
                for degree, out_delta in [(0, delta), (1024, 59)]:
                    ideal = body_at(body, 512 + 2048 * (x & 1), degree)
                    outputs.append(
                        {
                            "degree": degree,
                            "output_delta_log": out_delta,
                            "correct": True,
                            "support_correct": True,
                            "decoded": x & 1,
                            "expected_bit": x & 1,
                            "raw_phase": ideal,
                            "ideal_body_at_actual_address": ideal,
                            "raw_error_signed": "0",
                            "semantic_error_signed": "0",
                        }
                    )
                rows.append(
                    {
                        "type": "fresh_key_bridge",
                        "source_id": "frozen",
                        "channel": channel,
                        "translated_score": x,
                        "input_delta_log": delta,
                        "actual_address": 512 + 2048 * (x & 1),
                        "post_ks_u32": [0] * 919,
                        "centered_small_u32": [0] * 919,
                        "switched_mask": [0] * 918,
                        "outputs": outputs,
                    }
                )
        rows.append(
            {
                "type": "summary",
                "arm": "fresh-key",
                "ks32_calls": 4,
                "cmnr_br_calls": 4,
                "marginals": 8,
                "all_outputs_correct": True,
                "all_support_correct": True,
            }
        )
        return rows

    def test_full_fresh_record_shape_and_negatives(self):
        rows = self.fresh()
        self.assertIn("PASS", validate(rows, "fresh-key", "frozen"))
        broken = copy.deepcopy(rows)
        broken[1]["outputs"][0]["raw_error_signed"] = "1"
        with self.assertRaises(AssertionError):
            validate(broken, "fresh-key", "frozen")
        broken = copy.deepcopy(rows)
        broken[1]["actual_address"] += 2048
        with self.assertRaises(AssertionError):
            validate(broken, "fresh-key", "frozen")
        broken = copy.deepcopy(rows)
        broken[1]["channel"] = "low"
        with self.assertRaises(AssertionError):
            validate(broken, "fresh-key", "frozen")

    def test_live_a124_refused_from_supplied_snapshot(self):
        self.assertTrue(
            busy_lines(
                "45916 45914 python tmp/a124-a66-thread-sweep/a124_driver.py --guard cpu"
            )
        )
        self.assertFalse(busy_lines("42 1 /usr/bin/ordinary-process"))

    def test_complete_synthetic_accepts(self):
        self.assertIn("PASS", validate(self.synthetic(), "synthetic", "frozen"))

    def test_truncated_duplicate_or_wrong_arm_rejects(self):
        rows = self.synthetic()
        for bad in [
            rows[:-1],
            rows + rows[-1:],
            [dict(rows[0], arm="fresh-key")] + rows[1:],
        ]:
            with self.assertRaises(AssertionError):
                validate(bad, "synthetic", "frozen")

    def test_wrong_binary_source_or_difference_rejects(self):
        rows = self.synthetic()
        with self.assertRaises(AssertionError):
            validate(rows, "synthetic", "different")
        broken = copy.deepcopy(rows)
        broken[1]["direct"][-1] += 1
        with self.assertRaises(AssertionError):
            validate(broken, "synthetic", "frozen")


if __name__ == "__main__":
    unittest.main()
