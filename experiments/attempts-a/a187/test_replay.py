import copy
import unittest
import replay as r
import synthetic as s


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.code = s.records()

    def check(self, rows, code=None):
        return r.replay(
            rows, s.BINARY, self.code if code is None else code, verify_source=False
        )

    def test_complete_three_arm_scalar_gate(self):
        result = self.check(self.rows)
        self.assertTrue(result["gate_pass"])
        self.assertEqual(
            [x["old_a149_functional_pass"] for x in result["reports"]],
            [True, None, None],
        )
        self.assertEqual(result["events"], 205)

    def test_old_negative_does_not_relabel_new_positive(self):
        rows, code = s.records(old_changes={"ingress/0/low.low3": {"error": 1 << 51}})
        result = self.check(rows, code)
        self.assertFalse(result["reports"][0]["old_a149_functional_pass"])
        self.assertTrue(result["gate_pass"])

    def test_complete_new_negative_preserved(self):
        rows, code = s.records(
            new_changes={"ingress/0/low.correction_low3": {"error": 1 << 56}}
        )
        result = self.check(rows, code)
        self.assertEqual(code, 1)
        self.assertFalse(result["gate_pass"])
        self.assertEqual(result["status"], "VALID_A187_COMPLETE_NEGATIVE")
        with self.assertRaises(ValueError):
            self.check(rows, 0)

    def test_native_high_without_preimages_cannot_pass(self):
        rows, code = s.records(new_changes={"middle_round.mask/2": {"ks": 1 << 59}})
        result = self.check(rows, code)
        self.assertTrue(result["reports"][1]["low_native_pass"])
        self.assertTrue(result["reports"][1]["middle_native_pass"])
        self.assertFalse(result["reports"][1]["all_preimages_pass"])
        self.assertFalse(result["gate_pass"])

    def test_shape_order_and_outcome_mutations(self):
        mutations = [
            lambda x: x.pop(10),
            lambda x: x.insert(10, copy.deepcopy(x[10])),
            lambda x: x[2].update(arm=1),
            lambda x: x[-1].update(gate_pass=False),
            lambda x: x[2].update(expected_lut_word="0"),
            lambda x: x[2].update(body_sha256="a" * 64),
            lambda x: x[2].update(stock_degree_formula_match=False),
            lambda x: x[2].update(exact_preimage_pass=False),
            lambda x: x[0].update(input_sample_extractions=9),
        ]
        for mutate in mutations:
            rows = copy.deepcopy(self.rows)
            mutate(rows)
            with self.assertRaises((ValueError, AssertionError)):
                self.check(rows)

    def test_coefficient_and_carried_phase_mutations(self):
        def aggregate(x):
            x[2]["coefficient_observer"]["client_weighted_mask_words_hex"] = "f" * 16

        def phase(x):
            x[2]["big_phase_word"] = str((int(x[2]["big_phase_word"]) + 1) % (1 << 64))

        def offset(x):
            case = next(a for a in x if a.get("record") == "case" and a["arm"] == 1)
            case["correction_low_words"][0] = str(
                int(case["correction_low_words"][0]) + 1
            )

        for mutate in [aggregate, phase, offset]:
            rows = copy.deepcopy(self.rows)
            mutate(rows)
            with self.assertRaises((ValueError, AssertionError)):
                self.check(rows)

    def test_key_source_pid_hash_mutations(self):
        for field, value in [
            ("child_pid", True),
            ("binary_sha256", "e" * 64),
            ("source_id", "e" * 64),
            ("reference_sha256", "f" * 64),
            ("small_key_sha256", False),
        ]:
            rows = copy.deepcopy(self.rows)
            rows[1][field] = value
            with self.assertRaises(ValueError):
                self.check(rows)

    def test_strict_json_and_nested_booleans(self):
        for text in ['{"x":1,"x":2}', '{"x":1e999}', '{"x":NaN}']:
            with self.assertRaises(ValueError):
                r.parse(text)
        rows = copy.deepcopy(self.rows)
        rows[0]["pbs_ks_per_arm"][0] = True
        with self.assertRaises(ValueError):
            self.check(rows)


if __name__ == "__main__":
    unittest.main()
