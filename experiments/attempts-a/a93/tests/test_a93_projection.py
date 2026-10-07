from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import a93_projection as projection  # noqa: E402


class A93ProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (
            cls.corrected,
            cls.records,
            cls.mismatches,
            cls.events,
            cls.a79_manifest,
        ) = projection.expected_objects()

    def test_frozen_artifacts_reconstruct_and_actual_a79_replays(self):
        result = projection.verify()
        self.assertEqual(result["status"], projection.STATUS)
        self.assertEqual(
            result["projection_manifest_sha256"],
            projection.EXPECTED_PROJECTION_MANIFEST_SHA256,
        )
        self.assertEqual(
            result["a79_replay_status"],
            "PASS_DECLARATIVE_MANIFEST_DIGEST_BOUND_OPEN_OBLIGATIONS",
        )
        self.assertFalse(result["runtime_execution_attested"])
        self.assertFalse(result["runtime_public_offset_execution_attested"])
        self.assertFalse(result["runtime_gate_ready"])

    def test_g00_projection_distinguishes_raw_and_post_offset_sets(self):
        views = self.records["a53.selector.g00.len4"]["sample_views"]
        self.assertEqual(
            views,
            [
                {
                    "sample_degree": 0,
                    "public_offset": 2,
                    "raw_reachable_overapprox": [0, 1, 2, 30, 31],
                    "post_offset_reachable_overapprox": [0, 1, 2, 3, 4],
                    "linear_event_required": True,
                },
                {
                    "sample_degree": 1024,
                    "public_offset": 30,
                    "raw_reachable_overapprox": [2],
                    "post_offset_reachable_overapprox": [0],
                    "linear_event_required": True,
                },
            ],
        )
        self.assertEqual(len(self.mismatches), 55)
        self.assertEqual(
            projection.canonical_json_sha256(self.mismatches),
            projection.EXPECTED_MISMATCH_SHA256,
        )

    def test_trace_has_35_raw_pbs_and_64_explicit_selector_offsets(self):
        pbs_events = [event for event in self.events if event["op"] == "pbs"]
        linear_events = [event for event in self.events if event["op"] == "linear"]
        self.assertEqual(len(self.events), 136)
        self.assertEqual(len(pbs_events), 35)
        self.assertEqual(sum(len(event["outputs"]) for event in pbs_events), 67)
        self.assertEqual(len(linear_events), 64)
        self.assertTrue(
            all(
                event["terms"][0]["coefficient"] == 1
                and len(event["terms"]) == 1
                and "public_offset" in event
                for event in linear_events
            )
        )
        zero_offset_events = [
            event for event in linear_events if event["public_offset"] == 0
        ]
        self.assertEqual(len(zero_offset_events), 9)

    def test_actual_a79_parser_accepts_exact_corrected_contract_count(self):
        _, replay = projection.load_a79_modules()
        parsed = replay._manifest_accumulators(self.corrected, 2048)
        self.assertEqual(len(parsed), 35)
        self.assertEqual(sum(len(item.samples) for item in parsed.values()), 67)
        g00 = parsed["a53.selector.g00.len4"]
        self.assertEqual(g00.samples[0].reachable_overapprox, frozenset({0, 1, 2, 30, 31}))

    def test_actual_a79_replay_rejects_post_offset_set_used_as_raw(self):
        changed = copy.deepcopy(self.events)
        target = next(
            event
            for event in changed
            if event.get("op") == "pbs"
            and event.get("accumulator_id") == "a53.selector.g00.len4"
        )
        target["outputs"][0]["reachable_overapprox"] = [0, 1, 2, 3, 4]
        _, replay = projection.load_a79_modules()
        with self.assertRaisesRegex(
            replay.TraceReplayError, "linear reachable-set declaration does not replay"
        ):
            replay.replay_events(changed)

    def test_verifier_rejects_artifact_and_expected_digest_mutations(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact_dir = Path(directory)
            projection.build(artifact_dir)
            accumulator_path = artifact_dir / projection.ACCUMULATOR_FILE
            accumulator_path.write_bytes(accumulator_path.read_bytes() + b" ")
            with self.assertRaisesRegex(
                projection.ProjectionError, "differs from reconstruction"
            ):
                projection.verify(artifact_dir)
        with self.assertRaisesRegex(
            projection.ProjectionError, "independent digest"
        ):
            projection.verify(expected_projection_sha256="0" * 64)


if __name__ == "__main__":
    unittest.main()
