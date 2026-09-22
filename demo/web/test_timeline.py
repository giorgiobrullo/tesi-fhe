"""Deterministic timeline checks; no models, keys, processes or network."""
import copy
import unittest
from unittest.mock import patch

from .timeline import Timeline


class TimelineTests(unittest.TestCase):
    def setUp(self):
        self.base = 1 << 60
        self.now = self.base
        self.clock = patch("demo.web.timeline.clock_ns", side_effect=lambda: self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.timeline = Timeline()

    def at(self, milliseconds):
        return self.base + int(milliseconds * 1_000_000)

    def parent(self):
        self.timeline.end("queue", self.at(2))
        self.timeline.begin("prepare", "prepare", "job", self.at(2))
        self.timeline.end("prepare", self.at(5))
        self.timeline.begin("a28", "engine", "job", self.at(8), engine="a28")
        self.timeline.end("a28", self.at(40))

    def phase(self, kind, start, end):
        return {"kind": kind, "start_ns": self.at(start), "end_ns": self.at(end)}

    def test_open_snapshots_advance_but_completed_timeline_is_fixed_and_detached(self):
        self.now = self.at(1)
        first = self.timeline.snapshot()
        self.now = self.at(3)
        second = self.timeline.snapshot()
        self.assertEqual((first["elapsed_ms"], second["elapsed_ms"]), (1, 3))
        self.assertTrue(all(span["end_ms"] is None for span in second["spans"]))
        self.parent()
        self.timeline.add_phases("a28", [self.phase("encryption", 9.25, 11.5),
                                         self.phase("fhe", 14, 30), self.phase("decryption", 31, 32)])
        self.now = self.at(50)
        self.timeline.finish()
        complete = self.timeline.snapshot()
        self.now = self.at(500)
        self.assertEqual(self.timeline.snapshot(), complete)
        spans = {span["id"]: span for span in complete["spans"]}
        self.assertEqual((spans["a28/encryption"]["start_ms"], spans["a28/encryption"]["end_ms"]),
                         (9.25, 11.5))
        self.assertEqual(spans["a28/fhe"]["start_ms"], 14)  # Measured gap remains a gap.
        self.assertEqual(spans["a28/fhe"]["parent_id"], "a28")
        self.assertEqual(spans["a28/fhe"]["engine"], "a28")
        self.assertEqual(complete["elapsed_ms"], 50)
        self.assertTrue(all(not {"start_ns", "end_ns", "origin_ns", "spans_ns"} & span.keys()
                            for span in complete["spans"]))
        complete["spans"][0]["kind"] = "changed"
        self.assertEqual(self.timeline.snapshot()["spans"][0]["kind"], "job")

    def test_error_closes_only_open_spans_without_changing_completed_work(self):
        self.timeline.end("queue", self.at(2))
        self.timeline.begin("prepare", "prepare", "job", self.at(2))
        self.timeline.end("prepare", self.at(5))
        self.timeline.begin("attuale", "engine", "job", self.at(5), engine="attuale")
        self.now = self.at(10)
        self.timeline.finish(error=True)
        complete = self.timeline.snapshot()
        spans = {span["id"]: span for span in complete["spans"]}
        self.assertEqual(spans["queue"]["end_ms"], 2)
        self.assertEqual(spans["prepare"]["end_ms"], 5)
        self.assertNotIn("status", spans["prepare"])
        self.assertEqual(spans["job"]["status"], "error")
        self.assertEqual(spans["attuale"]["status"], "error")
        self.assertTrue(all(span["end_ms"] is not None for span in spans.values()))
        self.now = self.at(999)
        self.timeline.finish(error=True)
        self.assertEqual(self.timeline.snapshot(), complete)

    def test_invalid_phase_batch_leaves_no_partial_import(self):
        self.parent()
        before = copy.deepcopy(self.timeline.spans)
        for invalid in (self.phase("fhe", 7, 10), self.phase("fhe", 20, 41),
                        self.phase("fhe", 20, 19), self.phase("fhe", 10, 25),
                        self.phase("unknown", 20, 25),
                        self.phase("fhe", 20, 25) | {"start_ns": True},
                        self.phase("fhe", 20, 25) | {"end_ns": float("nan")}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.timeline.add_phases("a28", [self.phase("encryption", 9, 11), invalid])
            self.assertEqual(self.timeline.spans, before)

    def test_phase_order_is_semantic_and_not_only_chronological(self):
        self.parent()
        before = copy.deepcopy(self.timeline.spans)
        with self.assertRaises(ValueError):
            self.timeline.add_phases("a28", [self.phase("fhe", 9, 11),
                                             self.phase("encryption", 12, 14)])
        self.assertEqual(self.timeline.spans, before)

    def test_existing_phase_cannot_be_overwritten_by_a_later_import(self):
        self.parent()
        self.timeline.add_phases("a28", [self.phase("fhe", 15, 20)])
        before = copy.deepcopy(self.timeline.spans)
        with self.assertRaises(ValueError):
            self.timeline.add_phases("a28", [self.phase("fhe", 21, 25)])
        self.assertEqual(self.timeline.spans, before)


if __name__ == "__main__":
    unittest.main()
