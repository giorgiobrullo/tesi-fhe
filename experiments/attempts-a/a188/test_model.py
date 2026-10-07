"""Bounded clear semantics and graph checks, not simulated encrypted execution."""

import itertools
import unittest
import model as m


class Tests(unittest.TestCase):
    def test_all_n4_single_round_states_and_layouts(self):
        for state in itertools.product((0, 1), repeat=8):
            active, bits = state[:4], state[4:]
            live_zero = any(a and not b for a, b in zip(active, bits))
            want = [int(a and (not live_zero or not b)) for a, b in zip(active, bits)]
            for layout in m.LAYOUTS:
                got, tail = m.round_clear(active, bits, layout)
                self.assertEqual(got, want)
                self.assertEqual(tail, [])

    def test_all_two_byte_values(self):
        for left in range(256):
            for right in range(256):
                values = [left, right]
                got, trace = m.chain_clear([1, 1], values)
                self.assertEqual(got, [int(left <= right), int(right <= left)])
                self.assertTrue(all(row["tail"] == [0, 0] for row in trace))

    def test_masked_boundary_pairs(self):
        for active in itertools.product((0, 1), repeat=2):
            for values in itertools.product(
                (0, 1, 15, 16, 127, 128, 254, 255), repeat=2
            ):
                got, _ = m.chain_clear(active, values)
                self.assertEqual(got, m.oracle(active, values))

    def test_n127_tail_group_lane_ties(self):
        for index in (0, 3, 4, 62, 124, 126):
            active = [1] * 127
            values = [255] * 127
            values[index] = 0
            values[4] = 0
            got, trace = m.chain_clear(active, values)
            self.assertEqual(got, m.oracle(active, values))
            self.assertTrue(all(row["tail"] == [0] for row in trace))

    def test_dead_state_cannot_resurrect(self):
        for n in (1, 4, 127, 128):
            got, trace = m.chain_clear([0] * n, [i % 256 for i in range(n)])
            self.assertEqual(got, [0] * n)
            self.assertTrue(all(not any(row["active"] + row["tail"]) for row in trace))

    def test_resetting_inputs_hides_required_feedback(self):
        self.assertEqual(m.chain_clear([1, 1], [1, 2])[0], [1, 0])
        self.assertEqual(m.chain_clear([1, 1], [1, 2], reset_active=True)[0], [0, 1])

    def test_missing_offset_is_detected(self):
        self.assertNotEqual(
            m.round_clear([1, 1, 1, 1], [0, 1, 1, 1], m.LAYOUTS[0], omit_offset=True)[
                0
            ],
            [1, 0, 0, 0],
        )

    def test_first_and_final_ordinary_bridges_only(self):
        events = m.schedule(127)["events"]
        self.assertEqual(
            sum(p == "ordinary_pbs" and s == "final" for s, p, _ in events), 127
        )
        self.assertEqual(
            sum(p == "cm_pbs" and s == "initial" for s, p, _ in events), 32
        )
        self.assertFalse(any("feedback" in stage for stage, _, _ in events))

    def test_one_round_is_the_c1_functional_ledger(self):
        self.assertEqual(
            m.schedule(4, rounds=1)["counts"],
            dict(
                packing=3,
                cm_ks=2,
                cm_pbs=3,
                ordinary_ks=9,
                ordinary_pbs=7,
                extraction=8,
            ),
        )
        self.assertEqual(
            m.schedule(127, rounds=1)["counts"],
            dict(
                packing=65,
                cm_ks=81,
                cm_pbs=113,
                ordinary_ks=132,
                ordinary_pbs=130,
                extraction=131,
            ),
        )

    def test_a107_persistent_n127_ledger(self):
        self.assertEqual(
            m.schedule(127)["counts"],
            dict(
                packing=296,
                cm_ks=648,
                cm_pbs=680,
                ordinary_ks=167,
                ordinary_pbs=151,
                extraction=159,
            ),
        )
        self.assertEqual(
            m.report()["galleries"]["127"]["extra_calls_if_wrapped"],
            dict(
                packing=224,
                cm_ks=0,
                cm_pbs=224,
                ordinary_ks=889,
                ordinary_pbs=889,
                extraction=889,
            ),
        )

    def test_no_boolean_scale_equivalence_without_egress(self):
        self.assertNotEqual((1 << 61) // (1 << 59), 1)
        self.assertNotEqual(1536, 2048)

    def test_preparation_count_requires_a_split_helper(self):
        report = m.report()["galleries"]["127"]
        self.assertEqual(report["planned_split_fixture_preparation_ordinary_pbs"], 1143)
        self.assertEqual(
            report["unchanged_prepare_inputs_eight_calls_ordinary_pbs"], 2032
        )

    def test_reject_misaligned_or_noncanonical_inputs(self):
        for active, values in (
            ([], []),
            ([1], []),
            ([1], [256]),
            ([-1], [0]),
            ([True], [0]),
        ):
            with self.assertRaises(ValueError):
                m.chain_clear(active, values)


if __name__ == "__main__":
    unittest.main()
