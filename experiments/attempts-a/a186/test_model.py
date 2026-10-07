"""Bounded exact clear preimages/composition checks; no noisy primitive execution."""

import itertools
import unittest
import model as m


class CompositionTests(unittest.TestCase):
    def test_all_reachable_digit_difference_centers(self):
        count = 0
        for ds in itertools.product(range(-4, 5), range(-15, 16), range(-15, 16)):
            actual = tuple(
                m.raw_coefficient("ternary", m.round_degree(d * m.DELTA)) for d in ds
            )
            self.assertEqual(actual, tuple(m.sign(d) for d in ds))
            t = sum(w * s for w, s in zip(m.WEIGHTS, actual))
            control = 8 + m.raw_coefficient(
                "control", m.round_degree(t * m.DELTA - m.DELTA // 2)
            )
            oracle = next((s for s in actual if s), 0)
            self.assertEqual(control, 12 if oracle > 0 else 4)
            count += 1
        self.assertEqual(count, 8649)

    def test_all_ternary_patterns_and_tie_left(self):
        for signs in itertools.product((-1, 0, 1), repeat=3):
            t = sum(w * s for w, s in zip(m.WEIGHTS, signs))
            oracle = next((s for s in signs if s), 0)
            self.assertEqual(m.sign(t), oracle)
        self.assertEqual(m.compare((0, 0, 0, 1), (0, 0, 0, 127))["control"], 4)

    def test_raw_degree_and_integer_rounding_preimage_endpoints(self):
        checked = 0
        for kind, coefficients in (("ternary", (-1, 0, 1)), ("control", (-4, 4))):
            for expected in coefficients:
                intervals = m.phase_islands(kind, expected)
                for degree in range(m.M):
                    for word in (
                        (degree * m.U - m.U // 2) % m.Q,
                        (degree * m.U + m.U // 2 - 1) % m.Q,
                    ):
                        member = any(a <= word <= b for a, b in intervals)
                        self.assertEqual(
                            member,
                            m.raw_coefficient(kind, m.round_degree(word)) == expected,
                        )
                        checked += 1
        self.assertEqual(checked, 40960)

    def test_original_eight_fixtures_with_derived_not_supplied_selector(self):
        for name, left, right in m.FIXTURES:
            selected = m.compare(left, right)
            self.assertEqual(
                selected["output"], left if left[:3] <= right[:3] else right
            )
            one, two = m.select_arms(left, right, selected["control"] * 128)
            expected = m.payload_words(selected["output"])
            self.assertEqual(one, expected, name)
            self.assertEqual(two, expected, name)

    def test_same_lut_compatible_d1_d2_at_every_conditional_support_degree(self):
        for name, left, right in m.FIXTURES:
            result = m.compare(left, right)
            control = result["control"]
            lw, rw = m.payload_words(left), m.payload_words(right)
            acc1 = m.D1.assemble_delta(lw, rw)
            acc2 = m.D2.assemble_direct(lw, rw)
            wanted = m.payload_words(result["output"])
            for err in range(-63, 64):
                degree = 128 * control + err
                one = tuple(
                    (w + m.D1.negacyclic_sample(acc1, degree + 128 * j)) % m.Q
                    for j, w in enumerate(lw)
                )
                two = tuple(
                    m.D2.negacyclic_sample(acc2, degree + 128 * j) for j in range(4)
                )
                self.assertEqual(one, wanted, name)
                self.assertEqual(two, wanted, name)

    def test_three_exact_ms_counterexamples_despite_correct_native_phase(self):
        ternary = m.ms_counterexample(0)
        self.assertEqual(ternary["phase_only_degree"], 0)
        self.assertEqual(ternary["actual_degree"], 64)
        self.assertEqual(m.raw_coefficient("ternary", ternary["actual_degree"]), 1)
        final = m.ms_counterexample(-m.DELTA // 2)
        self.assertEqual(final["phase_only_degree"], 4032)
        self.assertEqual(final["actual_degree"], 0)
        self.assertEqual(8 + m.raw_coefficient("control", final["actual_degree"]), 12)
        selector = m.ms_counterexample(12 * m.DELTA)
        self.assertEqual(selector["phase_only_degree"], 1536)
        self.assertEqual(selector["actual_degree"], 1600)
        _, left, right = m.FIXTURES[7]
        one, two = m.select_arms(left, right, selector["actual_degree"])
        self.assertEqual(one, m.payload_words(left))
        self.assertNotEqual(one, m.payload_words(right))
        self.assertNotEqual(two, m.payload_words(right))

    def test_inclusive1023_threshold_and_sentinel_must_precede_gallery(self):
        sentinel = (4, 0, 0, 0)
        for score in (0, 1, 1023, 1024, 1025, 1280, 4095):
            gallery = m.bridge_design(score, 127)
            self.assertEqual(
                m.compare(sentinel, gallery)["output"][3], 127 if score <= 1023 else 0
            )
        self.assertEqual(
            m.compare(m.bridge_design(1024, 127), sentinel)["output"][3], 127
        )

    def test_first_fixture_detects_low_priority_override_and_final_offset_detects_tie(
        self,
    ):
        _, left, right = m.FIXTURES[7]
        result = m.compare(left, right)
        self.assertEqual(result["signs"], (0, 1, -1))
        self.assertEqual(result["control"], 12)
        wrong_t = sum(w * s for w, s in zip((1, 2, 4), result["signs"]))
        self.assertEqual(
            8
            + m.raw_coefficient(
                "control", m.round_degree(wrong_t * m.DELTA - m.DELTA // 2)
            ),
            4,
        )
        self.assertEqual(8 + m.raw_coefficient("control", m.round_degree(0)), 12)

    def test_exact_nonoverlapping_ledger_and_id_passthrough(self):
        self.assertEqual(m.ledger()["total"], dict(PFKS=20, KS=10, BR=10, samples=16))
        self.assertEqual(
            m.ledger("all_original_four")["total"],
            dict(PFKS=28, KS=11, BR=11, samples=20),
        )
        self.assertEqual(
            m.ledger("minimal_three_plus_supplied_control")["total"],
            dict(PFKS=40, KS=16, BR=16, samples=28),
        )
        for lid, rid in ((0, 127), (1, 2), (127, 1)):
            self.assertEqual(
                m.compare((0, 0, 0, lid), (0, 0, 1, rid))["output"][3], lid
            )


if __name__ == "__main__":
    unittest.main()
