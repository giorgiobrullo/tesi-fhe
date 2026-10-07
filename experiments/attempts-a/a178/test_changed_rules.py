"""New exact synthetic controls only; no native compilation or process sampling."""

import copy
from pathlib import Path
import unittest

import replay
from test_replay import SID, fixture


def absent_terminal():
    life, raw = fixture()
    terminal = raw[6]
    terminal.update(
        bsd_bytes=0,
        bsd_errno=3,
        bsd_pid=0,
        ppid=0,
        bsd_birth=[0, 0],
        bsd_identity_available=False,
    )
    return life, raw


def framing_model(text):
    """Independent Python transcription of the bounded first-line C helper."""
    lines = text.split("\n")
    if len(lines) < 3:
        return False, False
    line = lines[1]
    if not line.startswith('{"kind":"snapshot","seq":0,'):
        return False, False
    for flag in (True, False):
        tail = '"raw_ok":' + str(flag).lower() + "}"
        if line.endswith(tail) and line.find('"raw_ok":') == len(line) - len(tail):
            return True, flag
    return False, False


class ChangedRules(unittest.TestCase):
    def test_terminal_bsd_absence_remains_observed(self):
        life, raw = absent_terminal()
        before = copy.deepcopy(raw)
        result = replay.verify(life, raw, "order-12", SID)
        self.assertTrue(result["terminal_parent_lifecycle_consistent"])
        self.assertFalse(result["collector_qualified"])
        self.assertEqual(raw, before)
        self.assertEqual(raw[6]["bsd_bytes"], 0)
        self.assertEqual(raw[6]["bsd_errno"], 3)

    def test_mixed_live_exit_and_unstable_terminal_refused(self):
        for mutation in ("mixed", "user", "exit"):
            life, raw = absent_terminal()
            row = raw[6]
            if mutation == "mixed":
                row["first"]["exit_abs"] = 0
            elif mutation == "user":
                row["first"]["user_raw"] -= 1
            else:
                row["first"]["exit_abs"] -= 1
            row["stable_terminal_pair"] = False
            with self.assertRaises(ValueError):
                replay.verify(life, raw, "order-12", SID)

    def test_no_prior_live_identity_cannot_enter_terminal(self):
        _, raw = fixture()
        first = raw[1]
        first["first"] = dict(first["first"], exit_abs=first["begin_abs"] - 1)
        first["last"] = first["first"].copy()
        first.update(stable_terminal_pair=True, identity_mode="stable_terminal_rusage")
        with self.assertRaisesRegex(ValueError, "lacks prior live identity"):
            replay.raw_check.replay(raw)

    def test_positive_conflicting_bsd_refused(self):
        for field in ("bsd_pid", "ppid", "bsd_birth", "bsd_bytes"):
            life, raw = fixture()
            row = raw[6]
            row[field] = [1_000_001, 123456] if field == "bsd_birth" else row[field] + 1
            row["bsd_identity_available"] = (
                row["bsd_bytes"] == 136 and row["bsd_pid"] == raw[0]["pid"]
            )
            row["bsd_positive_conflict"] = True
            with self.assertRaisesRegex(ValueError, "positive BSD identity conflicts"):
                replay.verify(life, raw, "order-12", SID)

    def test_live_missing_bsd_and_forged_terminal_flags_refused(self):
        life, raw = absent_terminal()
        row = raw[2]
        row.update(
            bsd_bytes=0,
            bsd_errno=3,
            bsd_pid=0,
            ppid=0,
            bsd_birth=[0, 0],
            bsd_identity_available=False,
        )
        with self.assertRaisesRegex(ValueError, "live read requires"):
            replay.verify(life, raw, "order-12", SID)
        life, raw = absent_terminal()
        raw[6]["prior_live_identity"] = False
        with self.assertRaises(ValueError):
            replay.verify(life, raw, "order-12", SID)

    def test_parent_waitable_bracket_is_a_separate_gate(self):
        life, raw = absent_terminal()
        waiting = next(x for x in life if x["kind"] == "waitable")
        # Move the whole parent capture chain after the first terminal sample,
        # while retaining correct identity/values and before the later ACK/reap.
        shift = raw[6]["end_abs"] - waiting["begin_abs"] + 1
        for row in life:
            if row["kind"] in ("waitable", "zombie_read"):
                row["begin_abs"] += shift
                row["end_abs"] += shift
            elif row["kind"] == "collector_final_capture":
                row["abs"] += shift
            elif row["kind"] == "reaped":
                for field in ("begin_abs", "end_abs", "ack_committed_abs"):
                    row[field] += shift
        with self.assertRaisesRegex(ValueError, "whole terminal acquisition"):
            replay.verify(life, raw, "order-12", SID)

    def test_first_snapshot_exact_framing_and_later_flag_control(self):
        start = '{"kind":"start"}\n'
        good = '{"kind":"snapshot","seq":0,"raw_ok":true}\n'
        bad = '{"kind":"snapshot","seq":0,"raw_ok":false}\n'
        self.assertEqual(framing_model(start + good), (True, True))
        self.assertEqual(framing_model(start + bad + good), (True, False))
        for text in (
            start + good[:-1],
            start + good[1:],
            start + good.replace('"seq":0', '"seq":1'),
            start + good.replace("true}", "true}trailing"),
            start + good.replace('"raw_ok":true', '"raw_ok":false,"raw_ok":true'),
        ):
            self.assertEqual(framing_model(text), (False, False))

    def test_native_source_form_contains_changed_rules(self):
        here = Path(__file__).resolve().parent
        collector = (here / "collector.c").read_text()
        fixture_source = (here / "fixture.c").read_text()
        for fragment in (
            "bool stable_terminal_pair = r0.ri_proc_exit_abstime != 0 && same_usage(&r0, &r1);",
            "bool terminal_identity_ok = !carried && prior_live && stable_terminal_pair && !bsd_conflict;",
            "if (raw_ok && terminal_identity_ok)",
            "live_identity = bsd; have_live_identity = true;",
        ):
            self.assertIn(fragment, collector)
        self.assertIn(
            'const char *prefix = "{\\"kind\\":\\"snapshot\\",\\"seq\\":0,";',
            fixture_source,
        )
        self.assertIn("*end = 0;", fixture_source)
        self.assertIn("return first_snapshot_line(line + 1, raw_ok);", fixture_source)


if __name__ == "__main__":
    unittest.main()
