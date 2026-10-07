"""Synthetic-only mutation gates; never execute C or observe processes."""

import copy
import json
import unittest
import replay
from synthetic import fixture, SID


def one(rows, kind):
    return next(x for x in rows if x["kind"] == kind)


class Replay(unittest.TestCase):
    def rejects(self, rows, raw, case="order-12"):
        with self.assertRaises((ValueError, KeyError, IndexError)):
            replay.verify(rows, raw, case, SID)

    def test_all_five_synthetic_cases(self):
        for case, count, rawcount in [
            ("order-12", 27, 16),
            ("order-21", 27, 16),
            ("wrong-birth", 15, 4),
            ("early-reap", 15, 4),
            ("descendant", 24, 12),
        ]:
            rows, raw = fixture(case)
            out = replay.verify(rows, raw, case, SID)
            self.assertEqual((len(rows), len(raw)), (count, rawcount))
            self.assertFalse(out["collector_qualified"])
            self.assertFalse(out["settled_accounting_proven"])
            self.assertIsNone(out["nonbenchmark_occupancy"])
            if case.startswith("order-"):
                self.assertTrue(out["protocol_barriers_consistent"])
                self.assertTrue(out["paused_interval"]["coverage_gap"])
                self.assertEqual(
                    out["raw_replay"]["coverage_issues"],
                    ["CONTROLLED_PARENT_BARRIER_GAP"],
                )

    def test_full_path_identity_and_sequences(self):
        for key in [
            "magic",
            "version",
            "kind",
            "sequence",
            "parent_pid",
            "worker_pid",
            "collector_pid",
            "birth_abs",
            "related_seq",
            "sent_abs",
            "status",
        ]:
            rows, raw = fixture()
            next(r for r in rows if r["kind"] == "protocol")["message"][key] += 1
            self.rejects(rows, raw)
        rows, raw = fixture()
        one(raw, "protocol")["message"]["status"] = True
        self.rejects(rows, raw)

    def test_duplicate_partial_missing_eof_and_trailing_records(self):
        rows, raw = fixture()
        for mutated in [
            rows[:-1],
            rows + [copy.deepcopy(rows[-1])],
            rows[:3] + rows[4:],
            rows + [{"kind": "protocol_failure"}],
        ]:
            self.rejects(mutated, raw)
        for mutated in [
            raw[:-1],
            raw + [raw[-1]],
            raw[:3] + [raw[2]] + raw[3:],
            raw[:3] + raw[4:],
        ]:
            self.rejects(rows, mutated)
        rows, raw = fixture()
        one(rows, "collector_reply_eof")["eof"] = False
        self.rejects(rows, raw)
        rows, raw = fixture()
        one(rows, "protocol")["message"].pop("birth_abs")
        self.rejects(rows, raw)

    def test_protocol_deadline(self):
        rows, raw = fixture()
        one(rows, "protocol")["begin_abs"] = 0
        one(rows, "protocol")["end_abs"] = 16_000_000_000
        self.rejects(rows, raw)

    def test_exit_release_before_paused(self):
        rows, raw = fixture()
        control = [r for r in rows if r["kind"] == "worker_control"][1]
        control["begin_abs"] = control["message"]["sent_abs"] = 1
        self.rejects(rows, raw)

    def test_capture_before_parent_reads_or_terminal_before_token(self):
        rows, raw = fixture()
        cap = [r for r in rows if r["kind"] == "protocol"][3]
        cap["begin_abs"] = cap["message"]["sent_abs"] = 1
        self.rejects(rows, raw)
        rows, raw = fixture()
        term = next(r for r in raw if r.get("acquisition_stage") == "terminal")
        term["begin_abs"] -= 1000
        self.rejects(rows, raw)

    def test_no_acquisition_while_paused_no_stale_retained(self):
        rows, raw = fixture()
        term = next(r for r in raw if r.get("acquisition_stage") == "terminal")
        term["acquisition_stage"] = "retained"
        term["carried_final"] = True
        self.rejects(rows, raw)
        rows, raw = fixture()
        i = next(
            i for i, r in enumerate(raw) if r.get("acquisition_stage") == "terminal"
        )
        raw.insert(i, copy.deepcopy(raw[i - 2]))
        self.rejects(rows, raw)

    def test_mixed_terminal_unstable_and_conflicting_bsd(self):
        for mutation in ("mixed", "unstable", "conflict"):
            rows, raw = fixture()
            term = next(r for r in raw if r.get("acquisition_stage") == "terminal")
            if mutation == "mixed":
                term["first"]["exit_abs"] = 0
                term["stable_terminal_pair"] = False
            if mutation == "unstable":
                term["first"]["user_raw"] -= 1
                term["stable_terminal_pair"] = False
            if mutation == "conflict":
                term.update(bsd_bytes=136, bsd_pid=999, bsd_positive_conflict=True)
            self.rejects(rows, raw)

    def test_fsync_ack_matching_and_reap_order(self):
        for kind, key, value in [
            ("collector_final_capture", "matches_parent_reads", False),
            ("collector_final_capture", "snapshot_seq", 0),
            ("capture_ack", "stable_observed", False),
            ("reaped", "ack_committed_abs", 0),
            ("capture_ack", "settled_accounting_proven", True),
            ("waitable", "pid", 999),
            ("waitable", "si_status", 1),
        ]:
            rows, raw = fixture()
            one(rows, kind)[key] = value
            self.rejects(rows, raw)

    def test_stage_coverage_and_wrong_case(self):
        rows, raw = fixture()
        one(rows, "stage")["threads"] = 1
        self.rejects(rows, raw)
        rows, raw = fixture()
        self.rejects(rows, raw, "order-21")
        rows, raw = fixture()
        raw[1]["host_ticks"][0] = 2**32 - 1
        self.rejects(rows, raw)

    def test_json_duplicate_type_and_truncation_helpers(self):
        with self.assertRaises(ValueError):
            json.loads('{"a":1,"a":2}', object_pairs_hook=replay.raw_check.pairs)
        for a, b in [([True], [1]), ({"a": False}, {"a": 0})]:
            with self.assertRaises(ValueError):
                replay.eq(a, b)


if __name__ == "__main__":
    unittest.main()
