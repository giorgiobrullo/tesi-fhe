import unittest
import replay
import audit


class Tests(unittest.TestCase):
    def test_unchanged_baseline_and_cached_api_sources(self):
        self.assertTrue(audit.verify()["original_evaluator_prefix_byte_identical"])

    def test_independent_stage_enumeration_and_centered_reference(self):
        reference = replay.nominal_reference()
        for arm, expected in enumerate(
            ([24, 15, 12, 12], [32, 15, 12, 12], [32, 15, 12, 12])
        ):
            names = [x["stage"] for x in reference["arms"][arm]["events"]]
            self.assertEqual(
                [
                    sum(n.startswith(prefix) for n in names)
                    for prefix in ("ingress/", "a34.", "middle_round.", "low_round.")
                ],
                expected,
            )
            self.assertEqual(len(names), len(set(names)))
        # The exact reference includes all public offset effects through its model.
        for arm in (1, 2):
            names = {e["stage"]: e for e in reference["arms"][arm]["events"]}
            self.assertIn("ingress/0/low.consumer_msb", names)
            self.assertEqual(
                int(names["ingress/0/low.consumer_msb"]["expected_lut_word"]), 1 << 56
            )


if __name__ == "__main__":
    unittest.main()
