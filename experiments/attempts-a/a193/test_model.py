"""Bounded synthetic checks; no native API or actual A193 data."""

from dataclasses import replace
from fractions import Fraction
import unittest

from model import Clock, Usage, compare_live, stage_cpu


class ReferenceTests(unittest.TestCase):
    def setUp(self):
        self.before = Clock(7, 100, 110, 0, 1000)
        self.after = Clock(7, 150, 160, 0, 1200)
        self.reads = [
            Usage(7, 9, 0, 120, 125, 600, 500),
            Usage(7, 9, 0, 130, 135, 600, 550),
        ]

    def result(self, before=None, reads=None, after=None, numer=125, denom=3):
        return compare_live(
            7,
            9,
            self.before if before is None else before,
            self.reads if reads is None else reads,
            self.after if after is None else after,
            numer,
            denom,
        )

    def test_exact_in_interval_does_not_qualify_unit(self):
        result = self.result()
        h = result["read_observations"][0]["hypotheses"]["raw_nanoseconds"]
        self.assertEqual(
            h["signed_zero_error_interval_residual_ns"], [[-100, 1], [100, 1]]
        )
        self.assertTrue(h["zero_error_compatible"])
        self.assertFalse(h["unit_qualified"])
        self.assertIsNone(result["selected_scale"])

    def test_mach_fraction_preserved_and_not_native_failure(self):
        h = self.result()["read_observations"][0]["hypotheses"]["raw_mach_ticks"]
        self.assertEqual(h["converted_total_ns"], [137500, 3])
        self.assertEqual(h["minimum_additive_accounting_error_needed_ns"], [133900, 3])
        self.assertFalse(h["zero_error_compatible"])

    def test_below_and_exact_edges(self):
        for value, distance, fits in [
            (999, 1, False),
            (1000, 0, True),
            (1200, 0, True),
            (1201, 1, False),
        ]:
            reads = [replace(r, user_raw=value, system_raw=0) for r in self.reads]
            h = self.result(reads=reads)["read_observations"][0]["hypotheses"][
                "raw_nanoseconds"
            ]
            self.assertEqual(
                h["minimum_additive_accounting_error_needed_ns"], [distance, 1]
            )
            self.assertEqual(h["zero_error_compatible"], fits)

    def test_wrong_clock_caller_and_worker_identity(self):
        with self.assertRaises(ValueError):
            self.result(before=replace(self.before, caller_pid=8))
        for field, value in [("pid", 8), ("birth_abs", 10), ("exit_abs", 1)]:
            with self.assertRaises(ValueError):
                self.result(
                    reads=[replace(self.reads[0], **{field: value}), self.reads[1]]
                )

    def test_causal_boundaries_cannot_overlap(self):
        for reads in (
            [replace(self.reads[0], begin_abs=109), self.reads[1]],
            [replace(self.reads[0], end_abs=131), self.reads[1]],
            [self.reads[0], replace(self.reads[1], end_abs=151)],
        ):
            with self.assertRaises(ValueError):
                self.result(reads=reads)

    def test_failed_calls_bad_types_and_moduli(self):
        for before in [
            replace(self.before, status=-1),
            replace(self.before, status=True),
            replace(self.before, nanoseconds=10**9),
            replace(self.before, seconds=-1),
        ]:
            with self.assertRaises(ValueError):
                self.result(before=before)
        with self.assertRaises(ValueError):
            self.result(denom=0)
        with self.assertRaises(ValueError):
            self.result(reads=[replace(self.reads[0], status=-1), self.reads[1]])
        with self.assertRaises(ValueError):
            self.result(reads=[])
        with self.assertRaises(ValueError):
            self.result(reads=[self.reads[0], replace(self.reads[1], user_raw=599)])

    def test_posix_zero_is_valid_and_stage_scope_is_explicit(self):
        before = replace(self.before, seconds=0, nanoseconds=0)
        result = stage_cpu(7, before, self.after)
        self.assertEqual(result["represented_worker_process_cpu_ns"], 1200)
        self.assertIsNone(result["clock_call_overhead_bound_ns"])
        self.assertFalse(result["exclusive_work_function_cpu_proven"])
        with self.assertRaises(ValueError):
            stage_cpu(7, self.after, self.before)

    def test_grid_residuals_match_interval_distance(self):
        for raw in range(13):
            reads = [replace(r, user_raw=raw, system_raw=0) for r in self.reads]
            before = replace(self.before, nanoseconds=7)
            after = replace(self.after, nanoseconds=11)
            h = self.result(before, reads, after, 5, 3)["read_observations"][0][
                "hypotheses"
            ]["raw_mach_ticks"]
            value = Fraction(5 * raw, 3)
            distance = min(abs(value - Fraction(x, 3)) for x in range(21, 34))
            expected = h["minimum_additive_accounting_error_needed_ns"]
            self.assertEqual(Fraction(*expected), distance)


if __name__ == "__main__":
    unittest.main()
