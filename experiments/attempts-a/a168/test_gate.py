"""Synthetic timing/record tests; no actual timers, processes, keys or crypto."""

from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

import audit
from audit import HERE, sha
import validate as v
import run_gate


def synthetic_records():
    plan = json.loads((HERE / "PILOT.json").read_text())
    canonical = re.search(
        r'pub const A44_PARAMETER_CANONICAL: &str = "([^"]+)";',
        (HERE / "candidate/src/private_argmin.rs").read_text(),
    ).group(1)
    header = dict(
        record="run_start",
        schema="a168.pilot.v1",
        run_id="synthetic",
        source_sha256="1" * 64,
        binary_sha256="2" * 64,
        pid=1,
        plan_sha256=sha(HERE / "PILOT.json"),
        core_sha256=sha(HERE / "candidate/src/private_argmin.rs"),
        parameter_canonical=canonical,
        threads_requested=8,
        trace_feature=False,
        guard_status=v.GUARD,
        timer="std::time::Instant around pool.install + complete untraced endpoint",
        timer_epoch="process-local Instant; not aligned to OS collector",
        observer_policy="durable timing-only record after each pair; outputs retained and inspected after all pairs",
        speedup_promotion_allowed=False,
        actual_p_fail=None,
    )
    inputs = [
        hashlib.sha256(f"synthetic input{i}".encode()).hexdigest() for i in range(6)
    ]
    key = "3" * 64
    prepared = dict(
        record="prepared_block",
        key_id=key,
        fresh_keys=1,
        key_id_definition="SHA256 public native KSK u64LE; shared server object",
        input_hashes=inputs,
        ciphertexts_pre_encrypted=6,
        gallery="A133 n127_last_id",
        domain=[-1024, 1962],
        expected_code=127,
        secret_key_bytes_persisted=False,
    )
    timings = []
    validations = []
    cursor = 100
    for row, b, input_hash in zip(
        plan["pairs"], [1000, 1000, 900, 1100, 750, 1000], inputs
    ):
        if row["order"] == "AB":
            ast = cursor
            ae = ast + 1000
            bs = ae + 1
            be = bs + b
        else:
            bs = cursor
            be = bs + b
            ast = be + 1
            ae = ast + 1000
        cursor = max(ae, be) + 100
        timings.append(
            dict(
                record="pair_timing",
                **row,
                key_id=key,
                input_sha256=input_hash,
                same_key_gallery_input_source_binding=True,
                baseline_start_ns=ast,
                baseline_end_ns=ae,
                fused_start_ns=bs,
                fused_end_ns=be,
                baseline_wall_ns=1000,
                fused_wall_ns=b,
                outputs_inspected=False,
                guard_status=v.GUARD,
            )
        )
        arms = [
            {
                "arm": label,
                "evaluation_ok": True,
                "low": 7,
                "high": 8,
                "code": 127,
                "total_br": br,
                "stage_br": stage,
                "low_sha256": "4" * 64,
                "high_sha256": "5" * 64,
                "pass": True,
            }
            for label, br, stage in (
                ("A", 3390, [1651, 1603, 136]),
                ("B", 3263, [1651, 1476, 136]),
            )
        ]
        validations.append(
            {
                "record": "pair_validation",
                "sequence": row["sequence"],
                "input_sha256": input_hash,
                "arms": arms,
                "pass": True,
            }
        )
    summary = dict(
        record="summary",
        status="PILOT_COMPLETE",
        pairs=6,
        warmup_pairs=2,
        measured_pairs=4,
        evaluations=12,
        pairs_pass=6,
        all_correct=True,
        guard_status=v.GUARD,
        speedup_promotion_allowed=False,
        confidence_interval=None,
        actual_p_fail=None,
    )
    return [header, prepared, *timings, *validations, summary]


class Gate(unittest.TestCase):
    def test_origins_and_untraced_single_timer(self):
        self.assertGreater(audit.verify_origins(), 10)

    def test_fixed_balanced_plan_and_independent_oracle(self):
        plan = json.loads((HERE / "PILOT.json").read_text())
        self.assertEqual(
            [x["order"] for x in plan["pairs"]], ["AB", "BA", "AB", "BA", "BA", "AB"]
        )
        scores = [-512 + 4 * k for k in plan["gallery_flip_counts"]]
        winner = min(range(127), key=lambda i: (scores[i], i))
        self.assertEqual(winner + 1, 127)
        self.assertEqual(scores[winner], -512)
        self.assertTrue(scores[winner] <= -1)
        self.assertEqual(sum(x * x for x in [1] * 512), 512)
        self.assertEqual(
            [plan["expected_code"] % 15, plan["expected_code"] // 15], [7, 8]
        )

    def test_exact_paired_summary_keeps_negative_pair(self):
        result = v.inspect_records(synthetic_records(), "1" * 64, "2" * 64, "synthetic")
        self.assertEqual(result["median_paired_fractional_reduction"], "1/20")
        self.assertEqual(result["baseline_median_ns"], "1000")
        self.assertEqual(result["fused_median_ns"], "950")
        self.assertIn(
            "-1/10",
            [r["paired_fractional_reduction"] for r in result["raw_measured_pairs"]],
        )
        self.assertFalse(result["speedup_promotion_allowed"])
        self.assertIsNone(result["confidence_interval"])

    def test_missing_duplicate_reordered_rows_refused(self):
        records = synthetic_records()
        for candidate in (
            records[:-1],
            records + [records[-1]],
            records[:2] + [records[3], records[2]] + records[4:],
        ):
            with self.assertRaises(AssertionError):
                v.inspect_records(candidate, "1" * 64, "2" * 64, "synthetic")

    def test_timing_identity_and_nested_type_mutations(self):
        mutations = [
            (2, "baseline_wall_ns", 999),
            (3, "order", "AB"),
            (4, "input_sha256", "f" * 64),
            (5, "key_id", "f" * 64),
            (2, "outputs_inspected", True),
        ]
        for i, key, value in mutations:
            records = synthetic_records()
            records[i][key] = value
            with self.assertRaises(AssertionError):
                v.inspect_records(records, "1" * 64, "2" * 64, "synthetic")
        records = synthetic_records()
        records[8]["arms"][0]["stage_br"][0] = True
        with self.assertRaises(AssertionError):
            v.inspect_records(records, "1" * 64, "2" * 64, "synthetic")

    def test_no_false_correctness_guard_or_inference_promotion(self):
        for i, key, value in (
            (0, "trace_feature", True),
            (0, "speedup_promotion_allowed", True),
            (14, "guard_status", "PASS"),
            (14, "confidence_interval", [0, 1]),
            (14, "all_correct", False),
        ):
            records = synthetic_records()
            records[i][key] = value
            with self.assertRaises(AssertionError):
                v.inspect_records(records, "1" * 64, "2" * 64, "synthetic")
        records = synthetic_records()
        records[8]["arms"][0]["code"] = 126
        with self.assertRaises(AssertionError):
            v.inspect_records(records, "1" * 64, "2" * 64, "synthetic")

    def test_fresh_explicit_root_assertion_is_not_guard_qualification(self):
        current = datetime(2026, 9, 5, tzinfo=timezone.utc)
        record = dict(
            schema="a168.root-preflight.v1",
            run_id="synthetic",
            source_sha256="1" * 64,
            binary_sha256="2" * 64,
            root_verified_existing_workloads_clear=True,
            root_owns_exclusive_launch=True,
            no_competing_builds_or_crypto=True,
            collector_qualified=False,
            guard_status="ROOT_ASSERTION_ONLY_NOT_ALIGNED_CPU_EVIDENCE",
            observed_utc=current.isoformat(),
            evidence_sha256="3" * 64,
        )
        run_gate.check_preflight(record, "synthetic", "1" * 64, "2" * 64, current)
        for key, value in (
            ("collector_qualified", True),
            ("root_verified_existing_workloads_clear", False),
            ("observed_utc", "2026-09-04T00:00:00+00:00"),
        ):
            bad = deepcopy(record)
            bad[key] = value
            with self.assertRaises(AssertionError):
                run_gate.check_preflight(bad, "synthetic", "1" * 64, "2" * 64, current)

    def test_noargs_and_missing_ack_never_launch(self):
        with (
            patch(
                "run_gate.subprocess.Popen", side_effect=AssertionError("no process")
            ),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(run_gate.main([]), 0)
            with (
                patch.dict("os.environ", {}, clear=True),
                patch("sys.stderr", io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                run_gate.main(["--run-pilot"])

    def test_json_and_private_exclusive_io(self):
        for text in ('{"a":1,"a":1}', '{"a":1.0}', '{"a":NaN}'):
            with self.assertRaises(AssertionError):
                v.loads(text)
        with tempfile.TemporaryDirectory(dir=HERE) as directory:
            path = Path(directory) / "record.json"
            run_gate.write_new(path, {"a": 1})
            self.assertEqual(v.read_json(path), {"a": 1})
            with self.assertRaises(FileExistsError):
                run_gate.write_new(path, {})
            path.chmod(0o644)
            with self.assertRaises(AssertionError):
                v.read_json(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
