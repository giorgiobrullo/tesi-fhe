"""Future existing-binary launcher only. Never builds, resumes, pauses or restarts a workload."""

import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import time
import check_static
from model import body_at, signed

ROOT = Path(__file__).resolve().parent


def busy_lines(snapshot):
    # A prelaunch snapshot is a refusal gate, not an exclusive-resource reservation.
    needles = (
        "a124_driver.py",
        "a124_a66_thread_sweep",
        "a129-durable-sweep-driver/driver.py",
        "u4_nontrivial_score_gate",
        "u5_nontrivial_score_gate",
        "cargo build",
        "cargo check",
    )
    return [line for line in snapshot.splitlines() if any(n in line for n in needles)]


def validate(rows, arm, source_id):
    assert len(rows) == (3 if arm == "synthetic" else 6), "missing or extra record"
    assert rows[0]["type"] == "meta" and rows[0]["arm"] == arm
    assert rows[0]["source_id"] == source_id, "compiled source differs"
    summary = rows[-1]
    assert summary["type"] == "summary" and summary["arm"] == arm
    if arm == "synthetic":
        assert rows[1]["type"] == "synthetic_library_ks32"
        assert rows[1]["difference_u32"] == 1 << 16
        assert (rows[1]["direct"][-1] - rows[1]["wrong_prerounded"][-1]) % (
            1 << 32
        ) == 1 << 16
        assert summary["synthetic_pass"] is True
    else:
        assert (
            summary["ks32_calls"],
            summary["cmnr_br_calls"],
            summary["marginals"],
        ) == (4, 4, 8)
        assert (
            summary["all_outputs_correct"] is True
            and summary["all_support_correct"] is True
        )
        assert {(r["channel"], r["translated_score"]) for r in rows[1:-1]} == {
            ("full", 512),
            ("full", 513),
            ("low", 512),
            ("low", 513),
        }
        for row in rows[1:-1]:
            assert row["type"] == "fresh_key_bridge" and row["source_id"] == source_id
            assert row["input_delta_log"] == {"full": 52, "low": 60}[row["channel"]]
            assert 0 <= row["actual_address"] < 4096
            assert len(row["post_ks_u32"]) == len(row["centered_small_u32"]) == 919
            assert len(row["switched_mask"]) == 918
            assert len(row["outputs"]) == 2
            assert [o["degree"] for o in row["outputs"]] == [0, 1024]
            assert [o["output_delta_log"] for o in row["outputs"]] == [
                row["input_delta_log"],
                59,
            ]
            raw_body = (
                ROOT / f"artifacts/dual_lut_delta{row['input_delta_log']}.u64le"
            ).read_bytes()
            body = [
                int.from_bytes(raw_body[j : j + 8], "little")
                for j in range(0, len(raw_body), 8)
            ]
            for out in row["outputs"]:
                delta = out["output_delta_log"]
                offset = 1 << (delta - 1)
                ideal = body_at(body, row["actual_address"], out["degree"])
                expected = (row["translated_score"] & 1) << delta
                corrected = (out["raw_phase"] + offset) % (1 << 64)
                assert out["ideal_body_at_actual_address"] == ideal
                assert (ideal + offset) % (1 << 64) == expected, (
                    "actual address outside support"
                )
                assert out["raw_error_signed"] == str(
                    signed(out["raw_phase"] - ideal, 64)
                )
                assert out["semantic_error_signed"] == str(
                    signed(corrected - expected, 64)
                )
                assert (
                    out["decoded"]
                    == ((corrected + (1 << (delta - 1))) % (1 << 64)) >> delta
                )
                assert out["correct"] is True and out["support_correct"] is True
                assert (
                    out["decoded"] == out["expected_bit"] == row["translated_score"] & 1
                )
    return "DIAGNOSTIC_RECORD_GATE_PASS_NOT_TAIL_OR_BENCHMARK"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm", required=True, choices=["synthetic", "fresh-key"])
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    args = parser.parse_args()
    binary = args.binary.resolve()
    assert binary.is_relative_to(ROOT / "target-a144-only"), (
        "only the isolated target is accepted"
    )
    assert args.timeout_seconds > 0
    assert check_static.digest(binary) == args.expected_binary_sha256
    source_id = check_static.source_id()
    assert source_id == (ROOT / "source-id.txt").read_text().strip()
    for pin in json.loads((ROOT / "source-pins.json").read_text()):
        assert check_static.digest(Path(pin["path"])) == pin["sha256"]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output = ROOT / "artifacts" / f"run-{stamp}-{args.arm}"
    output.mkdir()
    snapshot = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,command="],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    (output / "prelaunch-processes.txt").write_text(snapshot)
    state = {
        "arm": args.arm,
        "binary": str(binary),
        "binary_sha256": args.expected_binary_sha256,
        "source_id": source_id,
        "status": "PREPARED",
        "started_utc": stamp,
        "evidence_scope": "diagnostic source/binary/record binding; snapshot is not a resource lease",
    }
    state_path = output / "state.json"

    def persist():
        temp = output / "state.pending"
        temp.write_text(json.dumps(state, indent=2) + "\n")
        temp.replace(state_path)

    persist()
    blockers = busy_lines(snapshot)
    if blockers:
        state.update(status="REFUSED_LIVE_WORKLOAD", blockers=blockers)
        persist()
        raise SystemExit("live workload found; preserved refusal, no child launched")
    env = os.environ.copy()
    env["A144_CLEARED_SOURCE_ID"] = source_id
    started = time.monotonic()
    try:
        with (
            (output / "stdout.jsonl").open("w") as stdout,
            (output / "stderr.log").open("w") as stderr,
        ):
            child = subprocess.Popen(
                [str(binary), "--" + args.arm], stdout=stdout, stderr=stderr, env=env
            )
            state.update(status="RUNNING", child_pid=child.pid)
            persist()
            try:
                code = child.wait(timeout=args.timeout_seconds)
            except BaseException:
                # Only the child created above is owned here. Existing controllers are untouched.
                child.kill()
                child.wait()
                raise
        state["exit_code"] = code
        assert code == 0, "child failed"
        assert check_static.digest(binary) == args.expected_binary_sha256, (
            "binary changed during run"
        )
        assert check_static.source_id() == source_id, "source changed during run"
        rows = [
            json.loads(line)
            for line in (output / "stdout.jsonl").read_text().splitlines()
        ]
        state["status"] = validate(rows, args.arm, source_id)
    except BaseException as error:
        state.update(status="FAILED_OR_INTERRUPTED", error=repr(error))
        raise
    finally:
        state["elapsed_seconds_diagnostic_only"] = time.monotonic() - started
        persist()
    print(state_path)


if __name__ == "__main__":
    main()
