from fractions import Fraction as F
from itertools import product
import json
import unittest

from examples import (
    EXPRESSION,
    a126_law,
    a126_result,
    correlation_result,
    wrapping_result,
)
from model import (
    Expression,
    coefficient_witness,
    moments,
    nearest_bad,
    conditional_bound,
    exact_law,
    rounding_support,
    first_failure_union,
)
from sources import ROOT, Q, U, DEGREES, a126_safe_residues, load, verify_sources


class TailGate(unittest.TestCase):
    def test_frozen_sources_and_actual_a126_lut_geometry(self):
        self.assertEqual(len(verify_sources()), 9)
        source = load("tmp/a131-a126-noise-margin/gate.py", "frozen_a131_a148")
        body = source.read_body()
        for c in (-4, 0, 1):
            for bit in (0, 1):
                safe = a126_safe_residues(c, bit)
                self.assertEqual(
                    safe, {r for r in range(4096) if source.joint_safe(body, c, bit, r)}
                )

    def test_existing_a143_words_close_same_ms64_lift(self):
        record = json.loads(
            (
                ROOT
                / "tmp/a143-nibble-coefficient-observer/synthetic-evidence/zero-phase-ms64.json"
            ).read_text()
        )["event"]
        words = [
            int(x, 16) for x in record["coefficient_observer"]["post_ks_words_hex"]
        ]
        witness = coefficient_witness(words[:-1], words[-1], [1] * 859, 0, Q, DEGREES)
        self.assertEqual(witness["phase_error"], 0)
        self.assertEqual(witness["lifted_displacement"], 64)
        self.assertEqual(witness["actual_address"], record["actual_ms_address"])

    def test_small_coefficients_integer_identity_and_support(self):
        count = 0
        for mask in product(range(8), repeat=2):
            for secret in product((0, 1), repeat=2):
                for error in (-31, -8, 0, 7, 31):
                    body = (error + sum(a * s for a, s in zip(mask, secret))) % 64
                    w = coefficient_witness(list(mask), body, list(secret), 0, 64, 8)
                    lo, hi = rounding_support(8, sum(secret), (error, error))
                    self.assertTrue(lo <= w["lifted_displacement"] <= hi)
                    count += 1
        self.assertEqual(count, 1280)
        self.assertEqual(rounding_support(U, 859, (0, 0)), (-429, 429))
        self.assertEqual(rounding_support(U, 859, (-Q // 2, Q // 2 - 1)), (-2477, 2477))

    def test_periodic_nearest_bad_matches_enumeration(self):
        for safe in ({0}, {0, 1, 7}, {0, 3, 4, 7}, set(range(8)), set()):
            for mean in (F(-35, 2), F(-1, 2), F(0), F(7, 2), F(16), F(67, 2)):
                for support in ([(-23, 19)], [(-40, -31), (16, 40)], [(0, 0)]):
                    candidates = {
                        (abs(F(x) - mean), x)
                        for lo, hi in support
                        for x in range(lo, hi + 1)
                        if x % 8 not in safe
                    }
                    self.assertEqual(
                        nearest_bad(mean, 8, safe, support),
                        min(candidates) if candidates else None,
                    )
                candidates = {
                    (abs(F(x) - mean), x) for x in range(-64, 65) if x % 8 not in safe
                }
                self.assertEqual(
                    nearest_bad(mean, 8, safe), min(candidates) if candidates else None
                )

    def test_same_all_atom_marginals_different_joint_failure(self):
        reports = [correlation_result(F(p)) for p in (0, F(1, 4), 1)]
        self.assertEqual(
            [r["actual_failure_probability"] for r in reports], [0, F(1, 4), 1]
        )
        for r in reports:
            self.assertEqual(
                r["conditional_bound"]["failure_bound"], r["actual_failure_probability"]
            )
            self.assertTrue(all(mean == 0 for mean in r["means"].values()))
        diagonals = [
            {a: v for (a, b), v in r["covariance"].items() if a == b} for r in reports
        ]
        self.assertEqual(diagonals[0], diagonals[1])
        self.assertEqual(diagonals[0], diagonals[2])
        self.assertEqual(
            reports[-1]["false_diagonal_premise_bound"]["failure_bound"], F(1, 4)
        )
        self.assertTrue(reports[-1]["false_premise_contradicted_by_exact_failure"])

    def test_actual_lut_conditional_bound_saturation_and_45_laws(self):
        report = a126_result()
        self.assertEqual(report["conditional_bound"]["nearest_bad_distance"], 64)
        self.assertEqual(report["lifted_moments"]["variance"], 16)
        self.assertEqual(report["actual_failure_probability"], F(1, 256))
        self.assertEqual(report["conditional_bound"]["failure_bound"], F(1, 256))
        safe = a126_safe_residues()
        count = 0
        for left in range(9):
            for right in range(9 - left):
                weights = tuple(F(x, 8) for x in (left, 8 - left - right, right))
                exact_law(EXPRESSION, U, a126_law(weights), DEGREES, safe)
                count += 1
        self.assertEqual(count, 45)

    def test_lifted_vs_centered_variance_are_distinct(self):
        report = wrapping_result()
        self.assertEqual(report["lifted_moments"]["variance"], 25)
        self.assertEqual(report["centered_variance"], 9)
        self.assertEqual(sorted(x for _, x in report["lifts"]), [-5, 5])

    def test_alias_cancellation_bias_and_zero_distance(self):
        cancelled = Expression.combine([("same", 512), ("same", -512)], offset=3 * 8)
        m = moments(cancelled, 1, {}, {}, "exact identity", "same atom aliases cancel")
        self.assertEqual(m["variance"], 0)
        self.assertEqual(conditional_bound(m, 8, {0})["failure_bound"], 0)
        biased = moments(Expression({}, 1), 1, {}, {}, "constant", "deterministic bias")
        self.assertEqual(conditional_bound(biased, 8, {0})["failure_bound"], 1)
        self.assertEqual(
            conditional_bound(biased, 8, set(range(8)))["failure_bound"], 0
        )
        self.assertEqual(
            conditional_bound(
                m, 8, {0}, [(24, 24)], "constant support proved by cancellation"
            )["failure_bound"],
            0,
        )
        with self.assertRaises(AssertionError):
            moments(Expression({}, 1), 2, {}, {}, "bad", "not integer-valued")

    def test_half_quantum_semantic_center_retains_reference_offset(self):
        # Nominal phase4 is half a degree for U8. Referencing degree0 leaves a
        # deterministic offset4; body residue-4 supplies the other half.
        w = coefficient_witness([], 4, [], 0, 64, 8)
        self.assertEqual(w["lifted_displacement"], 1)
        self.assertEqual(w["body_residue"], -4)
        expression = Expression.combine(
            [("semantic_error", 1), ("body_residue", -1)], offset=4
        )
        r = exact_law(
            expression, 8, [(F(1), {"semantic_error": 0, "body_residue": -4})], 8, {1}
        )
        self.assertEqual(r["actual_failure_probability"], 0)

    def test_missing_false_covariance_and_support_not_promoted(self):
        expression = Expression.combine([("a", 1), ("b", 1)])
        missing = moments(
            expression,
            1,
            {"a": 0, "b": 0},
            {("a", "a"): 1, ("b", "b"): 1},
            "H",
            "marginal only",
        )
        self.assertIsNone(conditional_bound(missing, 8, {0})["failure_bound"])
        with self.assertRaises(AssertionError):
            moments(
                expression,
                1,
                {"a": 0, "b": 0},
                {("a", "a"): 1, ("b", "b"): 1, ("a", "b"): 2, ("b", "a"): 2},
                "H",
                "impossible covariance",
            )
        report = a126_result()
        with self.assertRaises(AssertionError):
            conditional_bound(
                report["lifted_moments"], DEGREES, a126_safe_residues(), [(0, 0)]
            )
        with self.assertRaises(AssertionError):
            exact_law(
                EXPRESSION, U, a126_law(), DEGREES, a126_safe_residues(), [(0, 0)]
            )

    def test_first_failure_union_keeps_missing_tail_open(self):
        one = a126_result()["conditional_bound"]
        combined = first_failure_union([one, one], F(1, 128))
        self.assertEqual(combined["failure_bound"], F(1, 64))
        self.assertFalse(combined["independence_assumed"])
        self.assertIsNone(
            first_failure_union([one, {"failure_bound": None}])["failure_bound"]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
