"""Synthetic-only tests: no native processes, observations or A172 run artifacts."""

import copy
import unittest

import audit


def snapshot():
    return dict(host_rc=[0, 0, 0], host_counts=[12, 4, 12],
                capacity_before=8, capacity_after=8, rusage_rc=[0, 0],
                first=dict(birth_abs=100, user_raw=4, system_raw=2),
                last=dict(birth_abs=100, user_raw=5, system_raw=3),
                carried_final=False, bsd_bytes=136, bsd_pid=42)


class SyntheticTests(unittest.TestCase):
    def test_each_raw_clause_discriminates(self):
        base = snapshot()
        start = dict(expected_birth_abs=100, pid=42)
        self.assertTrue(all(audit.raw_obligations(base, start).values()))
        for field, value, clause in (
            ("host_rc", [0, 1, 0], "host_calls"),
            ("host_counts", [12, 3, 12], "host_sizes"),
            ("capacity_after", 4, "positive_stable_capacity"),
            ("rusage_rc", [0, -1], "rusage_calls"),
            ("bsd_bytes", 0, "bsd_or_retained_final"),
        ):
            row = copy.deepcopy(base)
            row[field] = value
            self.assertEqual([k for k, v in audit.raw_obligations(row, start).items() if not v], [clause])
        for side, field, value, clause in (
            ("first", "birth_abs", 101, "first_birth"),
            ("last", "birth_abs", 101, "last_birth"),
            ("last", "user_raw", 3, "within_read_user_monotonic"),
            ("last", "system_raw", 1, "within_read_system_monotonic"),
        ):
            row = copy.deepcopy(base)
            row[side][field] = value
            self.assertEqual([k for k, v in audit.raw_obligations(row, start).items() if not v], [clause])

    def test_retention_skips_only_bsd(self):
        row = snapshot()
        row.update(carried_final=True, bsd_bytes=0, bsd_pid=0)
        start = dict(expected_birth_abs=100, pid=42)
        self.assertTrue(all(audit.raw_obligations(row, start).values()))
        row["last"]["birth_abs"] = 101
        self.assertFalse(audit.raw_obligations(row, start)["last_birth"])

    def test_expected_wrong_birth_is_not_raw_pass(self):
        clauses = audit.raw_obligations(snapshot(), dict(expected_birth_abs=101, pid=42))
        self.assertEqual([k for k, v in clauses.items() if not v], ["first_birth", "last_birth"])

    def test_native_bool_integer_alias_is_refused(self):
        row = snapshot()
        row["host_rc"][0] = False
        with self.assertRaises(ValueError):
            audit.raw_obligations(row, dict(expected_birth_abs=100, pid=42))

    def test_recursive_types(self):
        for actual, expected in (([False], [0]), ({"x": [True]}, {"x": [1]}), ((True,), (1,))):
            with self.assertRaises(ValueError):
                audit.same(actual, expected)

    def test_duplicate_nonfinite_and_incomplete_json(self):
        for data, lines in ((b'{"x":0,"x":1}', False), (b'{"x":NaN}', False), (b'{}', True)):
            with self.assertRaises(ValueError):
                audit.decode(data, lines)

    def test_exact_case_counts(self):
        self.assertEqual(audit.COUNTS, {"order-12": (16, 14), "order-21": (16, 14),
                                      "wrong-birth": (12, 3), "early-reap": (12, 3),
                                      "descendant": (13, 14)})


if __name__ == "__main__":
    unittest.main()
