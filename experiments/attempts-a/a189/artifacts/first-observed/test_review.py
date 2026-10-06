"""Synthetic in-memory/envelope tests; no actual A181 run or native API is read."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import review as r

REPLAY, CALCULATE = r.frozen_functions()
SYNTHETIC = r.module("a189_source_synthetic", r.A181 / "synthetic.py")


def encoded(value):
    return (json.dumps(value) + "\n").encode()


def data_for(case, index=0, zero_gap=False):
    rows, raw = SYNTHETIC.fixture(case)

    def replace(x):
        if type(x) is dict:
            return {k: replace(v) for k, v in x.items()}
        if type(x) is list:
            return [replace(v) for v in x]
        if type(x) is int and x in (99, 123, 987):
            return x + index * 10000
        if x == "a" * 64:
            return r.A181_SOURCE
        return x

    rows, raw = replace(rows), replace(raw)
    if zero_gap:
        snaps = [x for x in raw if x["kind"] == "snapshot"]
        terminal = next(
            i for i, x in enumerate(snaps) if x["acquisition_stage"] == "terminal"
        )
        snaps[terminal]["host_ticks"] = snaps[terminal - 1]["host_ticks"].copy()
    pid = rows[0]["parent_pid"]
    run = r.A181 / "runs" / case
    command = [str(r.FIXTURE), "--run", case, str(r.COLLECTOR), str(run / "native")]

    def stamp(second):
        return f"2026-01-01T00:{index:02d}:{second:02d}+00:00"

    launch = dict(
        schema="a181.launch.v1",
        case=case,
        command=command,
        source_id=r.A181_SOURCE,
        binary_sha256=r.FIXTURE_HASH,
        collector_binary_sha256=r.COLLECTOR_HASH,
        prepared_utc=stamp(0),
        root_exclusive_assertion=True,
        os_membership_attested=False,
    )
    child = dict(
        schema="a181.child.v1",
        pid=pid,
        started_utc=stamp(1),
        command=command,
        source_id=r.A181_SOURCE,
    )
    reaped = dict(
        schema="a181.parent-reaped.v1",
        pid=pid,
        ended_utc=stamp(2),
        exit_code=0,
        source_id=r.A181_SOURCE,
    )
    terminal = dict(
        schema="a181.exit.v1",
        pid=pid,
        ended_utc=stamp(3),
        exit_code=0,
        source_id=r.A181_SOURCE,
        binary_sha256=r.FIXTURE_HASH,
        collector_binary_sha256=r.COLLECTOR_HASH,
        fixture_binary_unchanged=True,
        collector_binary_unchanged=True,
        source_unchanged=True,
        errors=[],
    )
    data = {name: b"" for name in r.NAMES}
    data.update(
        {
            name: encoded(value)
            for name, value in zip(r.NAMES[:4], (launch, child, reaped, terminal))
        }
    )
    data["native/lifecycle.jsonl"] = b"".join(encoded(x) for x in rows)
    data["native/raw.jsonl"] = b"".join(encoded(x) for x in raw)
    fresh = REPLAY(rows, raw, case, r.A181_SOURCE)
    fresh.update(
        fixture_binary_sha256=r.FIXTURE_HASH,
        collector_binary_sha256=r.COLLECTOR_HASH,
        parent_pid=pid,
        parent_exit_code=0,
        lifecycle_sha256=r.sha(data["native/lifecycle.jsonl"]),
        raw_sha256=r.sha(data["native/raw.jsonl"]),
        source_id=r.A181_SOURCE,
        launch_sha256=r.sha(data["launch.json"]),
        child_sha256=r.sha(data["child.json"]),
        exit_sha256=r.sha(data["exit.json"]),
        parent_reaped_sha256=r.sha(data["parent-reaped.json"]),
    )
    data["validation.json"] = encoded(fresh)
    return data


class Tests(unittest.TestCase):
    def test_all_five_synthetic_envelopes_and_unchanged_replay(self):
        data = {case: data_for(case, i) for i, case in enumerate(r.CASES)}
        summaries, bound = r.bind_sequence(data, REPLAY)
        self.assertEqual(sum(x["lifecycle_records"] for x in summaries), 108)
        self.assertEqual(tuple(bound), r.CASES)
        self.assertTrue(all(x["collector_qualified"] is False for x in summaries))

    def test_missing_case_order_or_reused_identity_refused(self):
        data = {case: data_for(case, i) for i, case in enumerate(r.CASES)}
        for changed in (
            dict(list(data.items())[:-1]),
            dict(reversed(list(data.items()))),
        ):
            with self.assertRaises(ValueError):
                r.bind_sequence(changed, REPLAY)
        data = {case: data_for(case, 0) for case in r.CASES}
        with self.assertRaises(ValueError):
            r.bind_sequence(data, REPLAY)

    def test_exits_source_pid_hash_and_types(self):
        for name, key, value in [
            ("exit.json", "exit_code", 1),
            ("exit.json", "source_unchanged", 1),
            ("child.json", "pid", True),
            ("child.json", "source_id", "0" * 64),
            ("launch.json", "binary_sha256", "0" * 64),
            ("exit.json", "ended_utc", "2025-01-01T00:00:00+00:00"),
        ]:
            data = data_for("order-12")
            record = r.parse(data[name])
            record[key] = value
            data[name] = encoded(record)
            with self.assertRaises(ValueError):
                r.check_case("order-12", data, REPLAY)

    def test_exact_log_bytes_and_saved_validation(self):
        for name in (
            "stdout.log",
            "stderr.log",
            "native/collector.stdout",
            "native/collector.stderr",
        ):
            data = data_for("order-12")
            data[name] = b"extra\n"
            with self.assertRaises(ValueError):
                r.check_case("order-12", data, REPLAY)
        data = data_for("order-12")
        data["native/raw.jsonl"] = data["native/raw.jsonl"][:-1]
        with self.assertRaises(ValueError):
            r.check_case("order-12", data, REPLAY)
        data = data_for("order-12")
        record = r.parse(data["validation.json"])
        record["collector_qualified"] = True
        data["validation.json"] = encoded(record)
        with self.assertRaises(ValueError):
            r.check_case("order-12", data, REPLAY)

    def test_duplicate_json_and_boolean_alias(self):
        with self.assertRaises(ValueError):
            r.parse(b'{"pid":1,"pid":1}')
        with self.assertRaises(ValueError):
            r.eq([True], [1])

    def test_noargs_read_no_actual_files(self):
        with (
            patch("sys.argv", ["review.py"]),
            patch.object(r, "review", side_effect=AssertionError("no read")),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(r.main(), 0)

    def test_unchanged_zero_gap_refusal_preserves_bound_sequence(self):
        with tempfile.TemporaryDirectory() as temporary:
            here = Path(temporary).resolve()
            here.chmod(0o700)
            fixture = here / "fixture"
            fixture.write_bytes(b"fake-fixture")
            collector = here / "collector"
            collector.write_bytes(b"fake-collector")
            with (
                patch.object(r, "HERE", here),
                patch.object(r, "FIXTURE", fixture),
                patch.object(r, "COLLECTOR", collector),
                patch.object(r, "FIXTURE_HASH", r.sha(b"fake-fixture")),
                patch.object(r, "COLLECTOR_HASH", r.sha(b"fake-collector")),
            ):
                data = {
                    case: data_for(case, i, case == "order-12")
                    for i, case in enumerate(r.CASES)
                }
                with (
                    patch.object(r, "manifest", return_value=(b"{}", {})),
                    patch.object(r, "source_binding", return_value={"synthetic": True}),
                    patch.object(
                        r, "collect_case", side_effect=lambda case: data[case]
                    ),
                    patch.object(
                        r, "frozen_functions", return_value=(REPLAY, CALCULATE)
                    ),
                    patch(
                        "sys.argv",
                        [
                            "review.py",
                            "--review",
                            "--expected-adapter-sha256",
                            "a" * 64,
                            "--frontier-pass-ack",
                            "A189_ROOT_CONFIRMED_FRONTIER_PASS",
                        ],
                    ),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(r.main(), 1)
                self.assertTrue((here / "BOUND_SEQUENCE.json").exists())
                self.assertTrue((here / "CAPTURED_INPUT_BYTES.json").exists())
                self.assertTrue((here / "REJECTED.json").exists())
                self.assertFalse((here / "ACTUAL_REPORT.json").exists())
                self.assertFalse((here / "order-21-calculation-started.json").exists())
                self.assertIn(
                    "non-discriminating zero host increment",
                    (here / "REJECTED.json").read_text(),
                )
                self.assertEqual(
                    (here / "BOUND_SEQUENCE.json").stat().st_mode & 0o777, 0o600
                )


if __name__ == "__main__":
    unittest.main()
