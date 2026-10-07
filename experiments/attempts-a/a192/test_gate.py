import copy
import unittest
from unittest.mock import patch
import component as c
import replay as r
import synthetic as s


class Tests(unittest.TestCase):
    def test_fixed16_domain_ties_threshold_and_independent_counts(self):
        fs = r.fixtures()
        self.assertEqual(len(fs), 16)
        self.assertEqual(fs[0]["scores"], [255, 256, 254, 4095])
        self.assertEqual(c.m.oracle(fs[7]["scores"]), [1, 1, 0, 0])
        self.assertEqual(c.m.oracle(fs[8]["scores"]), [1, 1, 1, 1])
        for i in [9, 13, 14]:
            self.assertEqual(c.m.oracle(fs[i]["scores"]), [0, 0, 0, 0])
        self.assertEqual(c.m.oracle(fs[15]["scores"]), [0, 1, 0, 1])
        for f in fs:
            nominal = c.nominal_reference(f["scores"])
            for arm, expected in enumerate(
                ([24, 15, 12, 12], [32, 15, 12, 12], [32, 15, 12, 12])
            ):
                names = [e["stage"] for e in nominal["arms"][arm]["events"]]
                self.assertEqual(
                    [
                        sum(x.startswith(p) for x in names)
                        for p in ("ingress/", "a34.", "middle_round.", "low_round.")
                    ],
                    expected,
                )
            ev = c.Precision()
            result = ev.evaluate(f["scores"])
            self.assertTrue(result["final_flags_pass"])
            self.assertTrue(all(e["exact_preimage_pass"] for e in ev.events))
        self.assertEqual(r.plan("n4-smoke")["raw_records_if_pass"], 1268)
        self.assertEqual(r.plan("n4-full")["raw_records_if_pass"], 10130)

    def component(self, fixture=0, **kwargs):
        rows, code = s.records(
            r.fixtures()[fixture]["scores"], fixture_index=fixture, **kwargs
        )
        result = c.replay(
            rows,
            s.BINARY,
            code,
            r.fixtures()[fixture]["scores"],
            0,
            fixture,
            "SYNTHETIC_SOURCE",
        )
        return rows, code, result

    def test_real_arithmetic_component_and_diagnostic_old_failure(self):
        _, code, result = self.component(
            old_changes={"ingress/0/low.low3": {"error": 1 << 51}}
        )
        self.assertEqual(code, 0)
        self.assertFalse(result["reports"][0]["old_a149_functional_pass"])
        self.assertTrue(result["gate_pass"])

    def test_six_component_smoke_with_real_synthetic_coefficient_arithmetic(self):
        rows = [r.plan("n4-smoke")]
        for key in range(3):
            for fixture in range(2):
                block, code = s.records(
                    r.fixtures()[fixture]["scores"], keyset=key, fixture_index=fixture
                )
                self.assertEqual(code, 0)
                rows.extend(block)
        rows.append(r.summary("n4-smoke", 6, True))
        result = r.replay(rows, s.BINARY, 0, "n4-smoke", verify_source=False)
        self.assertTrue(result["gate_pass"])
        self.assertEqual(result["records"], 1268)
        self.assertEqual(len({h for pair in result["key_hashes"] for h in pair}), 6)

    def test_allzero_wrongscale_not_universal_requirement(self):
        _, code, result = self.component(8)
        self.assertEqual(code, 0)
        self.assertFalse(result["reports"][2]["wrong_scale_detected"])
        self.assertTrue(result["gate_pass"])

    def test_new_negative_retained_and_no_native_only_promotion(self):
        rows, code, result = self.component(
            new_changes={"middle_round.mask/2": {"ks": 1 << 59}}
        )
        self.assertEqual(code, 1)
        self.assertTrue(result["reports"][1]["low_native_pass"])
        self.assertFalse(result["reports"][1]["all_preimages_pass"])
        self.assertFalse(result["gate_pass"])
        with self.assertRaises(ValueError):
            c.replay(
                rows, s.BINARY, 0, r.fixtures()[0]["scores"], 0, 0, "SYNTHETIC_SOURCE"
            )

    def stage_rows(self, stage="n4-smoke", completed=None, negative=False):
        # Schedule-only synthetic records; component arithmetic is independently
        # covered above, explicitly mocked in these outer-envelope mutations.
        n = r.STAGES[stage]
        count = 3 * n if completed is None else completed
        rows = [r.plan(stage)]
        for i in range(count):
            key, fixture = divmod(i, n)
            gate = not (negative and i == count - 1)
            block = [
                dict(record="plan", fixture_index=fixture, keyset=key),
                dict(
                    record="provenance",
                    child_pid=123,
                    big_key_sha256=r.sha_bytes(f"big/{key}".encode()),
                    small_key_sha256=r.sha_bytes(f"small/{key}".encode()),
                ),
            ]
            block += [dict(record="SYNTHETIC_COMPONENT_MOCK") for _ in range(208)]
            block += [dict(record="summary", gate_pass=gate)]
            rows += block
        rows += [r.summary(stage, count, not negative)]
        return rows

    def check_stage(self, rows, stage="n4-smoke", code=0, forbidden_keys=()):
        def stub(block, binary, status, scores, key, fixture, source):
            r.eq(block[0], dict(record="plan", fixture_index=fixture, keyset=key))
            r.eq(status, 0 if block[-1]["gate_pass"] else 1)
            return dict(
                gate_pass=block[-1]["gate_pass"], child_pid=block[1]["child_pid"]
            )

        with patch.object(c, "replay", side_effect=stub):
            return r.replay(
                rows,
                s.BINARY,
                code,
                stage,
                verify_source=False,
                forbidden_keys=forbidden_keys,
            )

    def test_staged_shape_positive_and_every_negative_prefix(self):
        for stage in r.STAGES:
            result = self.check_stage(self.stage_rows(stage), stage)
            self.assertTrue(result["gate_pass"])
            self.assertEqual(result["generated_keysets"], 3)
            for count in range(1, 3 * r.STAGES[stage] + 1):
                result = self.check_stage(self.stage_rows(stage, count, True), stage, 1)
                self.assertFalse(result["gate_pass"])
                self.assertEqual(result["events"], count * 205)
                self.assertEqual(result["records"], count * 211 + 2)

    def test_order_missing_duplicate_early_negative_and_key_mutations(self):
        def negative_early(x):
            x[211]["gate_pass"] = False

        def changed_key(x):
            x[213]["big_key_sha256"] = "e" * 64

        def reused_key(x):
            x[424]["big_key_sha256"] = x[2]["big_key_sha256"]

        for mutate in [
            lambda x: x.pop(3),
            lambda x: x.insert(3, x[3]),
            lambda x: x[1].update(fixture_index=True),
            negative_early,
            changed_key,
            reused_key,
            lambda x: x[-1].update(pbs=1),
            lambda x: x[-1].update(gate_pass=False),
        ]:
            rows = self.stage_rows()
            mutate(rows)
            with self.assertRaises((ValueError, KeyError)):
                self.check_stage(rows)
        rows = self.stage_rows()
        with self.assertRaises(ValueError):
            self.check_stage(rows, forbidden_keys=[rows[2]["big_key_sha256"]])
        rows = self.stage_rows(completed=2)
        with self.assertRaises(ValueError):
            self.check_stage(rows)

    def test_actual_phase_hash_preimage_and_outcome_mutations(self):
        rows, _, _ = self.component()
        for mutate in [
            lambda x: x[2].update(expected_lut_word="0"),
            lambda x: x[2].update(big_phase_word="0"),
            lambda x: x[2].update(stock_degree_formula_match=False),
            lambda x: x[2].update(keyset=True),
            lambda x: x[0].update(control_required=False),
            lambda x: x[-1].update(gate_pass=False),
        ]:
            bad = copy.deepcopy(rows)
            mutate(bad)
            with self.assertRaises((ValueError, AssertionError)):
                c.replay(
                    bad,
                    s.BINARY,
                    0,
                    r.fixtures()[0]["scores"],
                    0,
                    0,
                    "SYNTHETIC_SOURCE",
                )


if __name__ == "__main__":
    unittest.main()
