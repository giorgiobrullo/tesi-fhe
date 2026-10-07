from fractions import Fraction as F
import unittest

from audit import check

from model import (
    Exhausted,
    ScriptedTape,
    centered_cosh_control,
    conditional_support_proxy,
    mgf_at_ln2,
    paired_fill,
    scalar_fill,
    tiny_accepted_coordinate_law,
    weighted_law,
)


class CallGraphControls(unittest.TestCase):
    def test_source_pins_and_actual_scalar_routes(self):
        result = check()
        self.assertEqual(result["source_files"], 27)
        self.assertEqual(result["query_accepted_pairs_per_encryption"], 2048)
        self.assertEqual(result["ksk_rows"], 10240)
        self.assertEqual(result["source_formula_noise_bytes_reserved_per_row"], 928)
        self.assertFalse(result["actual_sampler_executed"])
        self.assertIsNone(result["actual_pipeline_p_fail"])

    def test_actual_scalar_fill_discards_every_second_component(self):
        tape = ScriptedTape((False, True, True, False, True))
        self.assertEqual(scalar_fill(tape, 3), [(1, 0), (2, 0), (4, 0)])
        self.assertEqual(tape.position, 80)
        self.assertEqual(len(tape.events), 5)
        self.assertEqual(sum(x["accepted"] for x in tape.events), 3)
        self.assertEqual([x["bytes"] for x in tape.events], [16] * 5)

    def test_specialized_pair_fill_is_a_different_call_graph(self):
        tape = ScriptedTape((False, True, True, False, True))
        self.assertEqual(paired_fill(tape, 3), [(1, 0), (1, 1), (2, 0)])
        self.assertEqual(tape.position, 48)
        # The unused (2,1) is not cached for another call, including odd fills.
        self.assertEqual(paired_fill(tape, 1), [(4, 0)])

    def test_scalar_odd_lengths_and_chunking_do_not_reuse_spares(self):
        whole, split = ScriptedTape((True,) * 7), ScriptedTape((True,) * 7)
        self.assertEqual(
            scalar_fill(whole, 7), scalar_fill(split, 3) + scalar_fill(split, 4)
        )
        paired_whole, paired_split = (
            ScriptedTape((True,) * 7),
            ScriptedTape((True,) * 7),
        )
        self.assertNotEqual(
            paired_fill(paired_whole, 7),
            paired_fill(paired_split, 3) + paired_fill(paired_split, 4),
        )

    def test_forks_reserve_fixed_nonoverlapping_segments_and_skip_unused_tail(self):
        parent = ScriptedTape((True, False, False, True, True, True))
        left, right = parent.fork(2, 48)
        self.assertEqual(parent.position, 96)
        self.assertEqual(scalar_fill(left, 1), [(0, 0)])
        self.assertEqual(scalar_fill(right, 1), [(3, 0)])
        self.assertEqual(left.position, 16)
        self.assertEqual(right.position, 64)
        with self.assertRaises(Exhausted):
            scalar_fill(parent, 1)
        # Per-child rejection exhaustion cannot consume a sibling's next bytes.
        with self.assertRaises(Exhausted):
            scalar_fill(left, 1)
        self.assertEqual(scalar_fill(right, 1), [(4, 0)])

    def test_malformed_geometries_and_exhaustion_are_not_retries(self):
        with self.assertRaises(ValueError):
            ScriptedTape((1, True))
        with self.assertRaises(ValueError):
            scalar_fill(ScriptedTape((True,)), True)
        with self.assertRaises(Exhausted):
            scalar_fill(ScriptedTape((False, False)), 1)
        with self.assertRaises(Exhausted):
            ScriptedTape((True,)).fork(2, 16)

    def test_finite_accepted_pair_is_symmetric_but_not_product(self):
        law = tiny_accepted_coordinate_law(2)
        self.assertEqual(len(law), 8)
        self.assertEqual(sum(u * p for (u, _), p in law.items()), 0)
        self.assertEqual(sum(v * p for (_, v), p in law.items()), 0)
        self.assertEqual(sum(u * v * p for (u, v), p in law.items()), 0)
        px0 = sum(p for (u, _), p in law.items() if u == 0)
        py0 = sum(p for (_, v), p in law.items() if v == 0)
        p00 = law.get((0, 0), 0)
        self.assertEqual((px0, py0, p00), (F(1, 4), F(1, 4), 0))
        self.assertNotEqual(p00, px0 * py0)
        for u, v in law:
            self.assertEqual(law[u, v], law[-u, v])
            self.assertEqual(law[u, v], law[u, -v])

    def test_centered_scalar_and_dependent_block_support_controls(self):
        law = tiny_accepted_coordinate_law(2)
        for weights in ((1, 0), (1, 1), (2, -3), (-3, 2)):
            summed = weighted_law(law, weights)
            self.assertTrue(centered_cosh_control(summed, sum(map(abs, weights))))
        # Mean zero is required; support alone cannot give the centered cosh bound.
        with self.assertRaises(ValueError):
            centered_cosh_control({1: F(1)}, 1)
        self.assertGreater(mgf_at_ln2({1: F(1)}), (F(2) + F(1, 2)) / 2)

    def test_pair_independence_and_stream_independence_are_separate_premises(self):
        # A deliberately bad one-bit finite generator repeats its seed at disjoint
        # byte positions. This is not a claim about AES, only a logical negative.
        correlated = {(-1, -1): F(1, 2), (1, 1): F(1, 2)}
        independent = {(x, y): F(1, 4) for x in (-1, 1) for y in (-1, 1)}
        corr = mgf_at_ln2(weighted_law(correlated, (1, 1)))
        indep = mgf_at_ln2(weighted_law(independent, (1, 1)))
        self.assertEqual((corr, indep), (F(17, 8), F(25, 16)))
        self.assertGreater(corr, indep)
        independent_proxy = conditional_support_proxy(
            [("a", 1), ("b", 1)], {"a": 1, "b": 1}, [["a"], ["b"]]
        )
        joint_proxy = conditional_support_proxy(
            [("a", 1), ("b", 1)], {"a": 1, "b": 1}, [["a", "b"]]
        )
        self.assertEqual(independent_proxy["lifted_subgaussian_proxy"], 2)
        self.assertEqual(joint_proxy["lifted_subgaussian_proxy"], 4)

    def test_alias_cancellation_before_any_independence_factorization(self):
        result = conditional_support_proxy(
            [("row0", 3), ("row0", -3), ("query0", 2)],
            {"row0": 10, "query0": 1},
            [["row0"], ["query0"]],
        )
        self.assertEqual(result["combined_coefficients"]["row0"], 0)
        self.assertEqual(result["lifted_subgaussian_proxy"], 4)
        self.assertIsNone(result["actual_pipeline_p_fail"])
        self.assertFalse(result["modular_variance_transfer"])
        with self.assertRaises(ValueError):
            conditional_support_proxy([("a", 1)], {"a": 1}, [["a"], ["a"]])
        with self.assertRaises(ValueError):
            conditional_support_proxy([("a", 1)], {"a": 1}, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
