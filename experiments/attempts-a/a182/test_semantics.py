"""Full17703 order binding using original synthetic producer, mocked NEW word payloads.

A175/A185 test_gate exercises real small-word arithmetic separately. These tests
never construct large/noisy ciphertexts, start a process, or read actual run logs.
"""

import contextlib
import copy
import io
import json
import sys
import unittest
from unittest.mock import patch
import binding as b
import verify as v
import test_envelope as envelope_fixture


class SemanticTests(unittest.TestCase):
    setUp = envelope_fixture.EnvelopeTests.setUp
    tearDown = envelope_fixture.EnvelopeTests.tearDown
    prepare = envelope_fixture.EnvelopeTests.prepare
    fixture = envelope_fixture.EnvelopeTests.fixture
    envelope = envelope_fixture.EnvelopeTests.envelope

    def make_rows(self):
        replay = b.frozen_replay()
        previous = {
            name: sys.modules.get(name)
            for name in ("model", "replay", "a182_frozen_synthetic_structure")
        }
        try:
            sys.modules.update(model=replay.m, replay=replay)
            factory = b.import_path(
                "a182_frozen_synthetic_structure", b.BASE / "test_structure.py"
            )
        finally:
            for name, old in previous.items():
                if old is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = old
        factory.SOURCE = b.SOURCE_ID
        factory.BINARY = self.binary_sha
        factory.FILES = self.binding["source_files_sha256"]
        return replay, factory.fixture()

    def verify_full(self, replay):
        with (
            patch.object(b, "source_check", return_value=self.binding),
            patch.object(
                b, "fixed_paths", return_value=(self.binary, self.cwd, self.run)
            ),
            patch.object(b, "frozen_replay", return_value=replay),
            patch.object(
                replay.m,
                "check_consumer",
                side_effect=lambda row, *_: tuple(row["gates"]),
            ),
            patch.object(replay, "bind_observation_aliases", return_value=None),
        ):
            return v.verify(self.binary_sha, "a" * 64)

    def test_complete_synthetic_projection_with_real_frozen_producer_oracle(self):
        replay, rows = self.make_rows()
        self.fixture(raw=("\n".join(json.dumps(row) for row in rows) + "\n").encode())
        result = self.verify_full(replay)
        self.assertTrue(result["complete_gate_pass"])
        self.assertEqual(result["records"], 17703)
        self.assertEqual(result["arithmetic"]["source_id"], b.SOURCE_ID)
        self.assertEqual(result["implementation"], "A185")
        self.assertFalse(result["arithmetic"]["launch_envelope_independently_verified"])
        self.assertTrue(result["launch_envelope_independently_verified"])
        self.assertFalse(result["retry_or_expansion_authorized"])

    def test_completed_consumer_negative_and_old_producer_gate_remain_separate(self):
        replay, rows = self.make_rows()
        first = 580
        self.assertEqual(rows[first]["record"], "actual_consumer")
        rows[first]["gates"][4] = False
        case = 636
        self.assertEqual(rows[case]["record"], "consumer_case")
        rows[case]["failure_counts"][0][4] = 1
        rows[case]["all_consumer_gates_pass"] = False
        rows[-1].update(
            status="FAIL_A175_ACTUAL_CONSUMER",
            actual_consumer_gate_pass=False,
            complete_gate_pass=False,
        )
        rows[-1]["failure_counts"][0][4] = 1
        rows[-1]["case_failures"][0] = 1
        self.fixture(
            code=1, raw=("\n".join(json.dumps(row) for row in rows) + "\n").encode()
        )
        result = self.verify_full(replay)
        self.assertEqual(result["status"], "VALID_BOUND_COMPLETED_A185_A175_NEGATIVE")
        self.assertTrue(result["producer_gate_pass"])
        self.assertFalse(result["actual_consumer_gate_pass"])
        self.assertEqual(result["arithmetic"]["consumer_failure_counts"][0][4], 1)
        self.assertEqual(
            result["arithmetic"]["failed_consumers"][0]["failed_gates"],
            ["stock_equivalence"],
        )

    def test_semantic_identity_counts_pid_exit_and_conjunction_mutations(self):
        replay, rows = self.make_rows()
        self.fixture(raw=("\n".join(json.dumps(row) for row in rows) + "\n").encode())
        report = self.verify_full(replay)
        semantic, envelope = report["arithmetic"], report["launch_binding"]
        for key, value in (
            ("records", 17702),
            ("source_id", "f" * 64),
            ("reported_child_pid", 124),
            ("expected_exit_code", 1),
            ("complete_gate_pass", 1),
            ("actual_consumer_gate_pass", False),
            ("producer_gate_pass", False),
            ("launch_envelope_independently_verified", True),
            (
                "ledger",
                {
                    "BR": 5124,
                    "KS": True,
                    "samples": 6020,
                    "client_lwe_encryptions": 784,
                    "client_glwe_encryptions": 28,
                },
            ),
        ):
            mutant = copy.deepcopy(semantic)
            mutant[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                v.bind_semantics(mutant, envelope)

    def test_raw_count_blank_truncation_and_json_ambiguity_reject_before_semantics(
        self,
    ):
        replay, rows = self.make_rows()
        raw = ("\n".join(json.dumps(row) for row in rows) + "\n").encode()
        self.fixture(raw=raw)
        envelope, _ = self.envelope()
        for mutant in (
            raw[:-1],
            b"{}\n" * 17702,
            b"{}\n" * 17702 + b"\n",
            b"{}\n" * 17702 + b'{"a":1,"a":2}\n',
        ):
            with (
                patch.object(b, "source_check", return_value=self.binding),
                patch.object(v, "verify_envelope", return_value=(envelope, mutant)),
                patch.object(
                    b,
                    "frozen_replay",
                    side_effect=AssertionError("must reject before arithmetic"),
                ),
            ):
                with self.assertRaises(ValueError):
                    v.verify(self.binary_sha, "a" * 64)

    def test_frozen_model_import_restores_aliases(self):
        old = sys.modules.get("model")
        sentinel = object()
        sys.modules["model"] = sentinel
        try:
            replay = b.frozen_replay()
            self.assertIs(sys.modules["model"], sentinel)
            self.assertEqual(replay.m.__file__, str(b.BASE / "model.py"))
            self.assertEqual(replay.HERE, b.BASE)
            self.assertEqual(replay.plan_record()["total_br"], 5124)
        finally:
            if old is None:
                sys.modules.pop("model", None)
            else:
                sys.modules["model"] = old

    def test_cli_invalid_evidence_report_is_saved_once_and_not_completed_negative(self):
        output = self.runbase / "artifacts/first-key1-validation.json"
        with (
            patch.object(b, "HERE", self.runbase),
            patch.object(
                v, "verify", side_effect=ValueError("synthetic missing checkpoint")
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            args = [
                "--verify",
                "--binary-sha256",
                self.binary_sha,
                "--envelope-manifest-sha256",
                "a" * 64,
                "--output",
                str(output),
            ]
            self.assertEqual(v.main(args), 2)
            report = b.load(output)
            self.assertEqual(
                report["status"], "INVALID_OR_INCOMPLETE_A185_A175_EVIDENCE"
            )
            self.assertFalse(report["completed_negative_established"])
            with self.assertRaises(ValueError):
                v.main(args)


if __name__ == "__main__":
    unittest.main()
