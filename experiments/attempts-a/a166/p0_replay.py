"""Replay A166 actual P0 records with frozen A158 arithmetic; no secret attestation."""

import argparse
from datetime import datetime, timedelta
import json
from pathlib import Path
import re

from audit import HERE, a158, sha, verify_source


def verify_records(record, before, key_binding, prepared, started, completed):
    assert record["kind"] == "client_observed"
    expected = dict(key_binding)
    for key in ("run_id", "source_sha256", "binary_sha256"):
        assert expected[key] == prepared[key] == started[key]
    assert started["schema"] == "a166.prefix.started.v1"
    assert type(started["pid"]) is int and started["pid"] > 0
    assert started["timed_benchmark"] is False
    assert started["secret_material_persisted"] is False
    assert before["bindings"] == expected
    assert before["ks_calls_so_far"] == 0 and type(before["ks_calls_so_far"]) is int
    assert before["post_ks_exists"] is False
    for name in ("score_low", "ks_input"):
        assert before[name] == record["ciphertexts"][name]
    # These public producer snapshots bind the client-local chain; their relationship
    # is independently checked below from the actual negacyclic polynomial and extraction.
    packed = a158.words(before["packed_query"], 4096)
    product = a158.words(before["product"], 4096)
    template = a158.fixture()["template"]
    taps = [(511 - i, -2 * t) for i, t in enumerate(template) if t]
    for block in range(2):
        inp = packed[block * 2048 : (block + 1) * 2048]
        want = [0] * 2048
        for j, a in enumerate(inp):
            for offset, coefficient in taps:
                position = j + offset
                sign = -1 if position >= 2048 else 1
                want[position % 2048] = (
                    want[position % 2048] + sign * coefficient * a
                ) % a158.Q
        assert product[block * 2048 : (block + 1) * 2048] == want, (
            "actual public score product"
        )
    mask = product[:2048]
    degree = 1535
    expected_mask = [
        mask[degree - i] if i <= degree else -mask[2048 + degree - i] % a158.Q
        for i in range(2048)
    ]
    low = a158.words(before["score_low"], 2049)
    assert low[:-1] == expected_mask
    assert low[-1] == (product[2048 + degree] + 1037 * (1 << 60)) % a158.Q
    assert before["initial_noise_terms_client"] == record["initial_noise_terms_client"]
    assert (
        before["input_noise_lift"]
        == record["client"]["input_probe_weighted_noise_shifted_lift"]
    )
    assert before["large_remainder_lift"] == record["client"]["large_remainder_lift"]
    assert (
        before["row_noise_signed_sum_direct_lift"]
        == record["client"]["row_noise_signed_sum_direct_lift"]
    )
    assert before["subgroup_g"] == record["subgroup_g"]
    kin = a158.words(before["ks_input"], 2049)
    used = [
        (i, 5 - j, d)
        for i, a in enumerate(kin[:-1])
        for j, d in enumerate(a158.a156.decompose(a, a158.Q, 3, 5)[0])
        if d
    ]
    rows = before["used_rows"]
    assert len(rows) == len(used)
    total = 0
    for row, (i, level, digit) in zip(rows, used):
        assert (row["input_index"], row["level"], row["digit"]) == (i, level, digit)
        assert row["storage_index"] == 5 - level
        for key in (
            "input_index",
            "level",
            "digit",
            "storage_index",
            "eta_centered_lift",
            "contribution_lift",
        ):
            assert type(row[key]) is int
        eta = row["eta_centered_lift"]
        assert -a158.Q // 2 <= eta < a158.Q // 2
        assert re.fullmatch("[0-9a-f]{64}", row["row_words_sha256"])
        assert row["contribution_lift"] == -digit * eta
        total += row["contribution_lift"]
    assert total == before["row_noise_signed_sum_direct_lift"]
    result = a158.verify(record, expected)
    assert completed == dict(
        status="P0_NATIVE_AND_CONDITIONAL_ADDRESS_PASS",
        ordinary_ks=1,
        configured_ms=1,
        blind_rotations=0,
        actual_sampler_p_fail=None,
        independent_replay_pending=True,
    )
    assert all(
        type(completed[key]) is int
        for key in ("ordinary_ks", "configured_ms", "blind_rotations")
    )
    assert result["selected_prefix_gate_pass"]
    result.update(
        actual_public_product_and_sample_pass=True,
        used_row_contribution_replay_pass=True,
        independently_attested_row_decryption=False,
        source_order_does_not_attest_runtime_chronology=True,
        producer_full_n4_scope=False,
    )
    return result


def verify_envelope(run, expected_binary, source, records):
    assert re.fullmatch("[0-9a-f]{64}", expected_binary)
    assert run.is_absolute() and run.parent == HERE / "runs"
    assert re.fullmatch("[A-Za-z0-9][A-Za-z0-9_-]{0,79}", run.name)
    prepared, exit_record, child = (
        records[name] for name in ("prepared.json", "exit.json", "child.json")
    )
    assert prepared["source_sha256"] == source
    assert prepared["binary_sha256"] == expected_binary
    assert prepared["run_id"] == run.name
    assert prepared["status"] == "PREPARED"
    assert prepared["timed_benchmark"] is False
    assert prepared["no_automatic_retries"] is True
    assert prepared["workload_check_is_external_root_obligation"] is True
    binary = HERE / "candidate/target-a166-only/release/a166_first_ks_prefix"
    assert prepared["command"] == [str(binary), "--run-authorized", str(run), run.name]
    for envelope in (child, exit_record):
        for key in ("source_sha256", "binary_sha256", "run_id"):
            assert envelope[key] == prepared[key]
    assert type(exit_record["exit_code"]) is int and exit_record["exit_code"] == 0
    assert exit_record["status"] == "EXITED"
    assert exit_record["binary_unchanged"] is True
    assert exit_record["source_unchanged"] is True
    assert (
        child["child_pid"] == records["started.json"]["pid"] == exit_record["child_pid"]
    )
    assert type(child["child_pid"]) is int and child["child_pid"] > 0
    times = [
        datetime.fromisoformat(value)
        for value in (
            prepared["prepared_at_utc"],
            child["started_at_utc"],
            exit_record["exited_at_utc"],
        )
    ]
    assert all(value.utcoffset() == timedelta(0) for value in times)
    assert times == sorted(times)


def private(path, directory=False):
    assert not path.is_symlink()
    assert path.is_dir() if directory else path.is_file()
    assert path.stat().st_mode & 0o777 == (0o700 if directory else 0o600)


def replay(run, expected_binary):
    source = verify_source()
    names = [
        "trace.json",
        "before-ks.json",
        "key-binding.json",
        "prepared.json",
        "started.json",
        "completed.json",
        "exit.json",
        "child.json",
    ]
    private(run.parent, directory=True)
    private(run, directory=True)
    for name in names + ["stdout.log", "stderr.log"]:
        private(run / name)
    records = {name: json.loads((run / name).read_text()) for name in names}
    verify_envelope(run, expected_binary, source, records)
    exit_record = records["exit.json"]
    assert exit_record["stderr_sha256"] == sha(run / "stderr.log")
    assert exit_record["stdout_sha256"] == sha(run / "stdout.log")
    result = verify_records(*(records[name] for name in names[:6]))
    result["runtime_files_sha256"] = {name: sha(run / name) for name in names}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    from run_gate import write_new

    write_new(args.output, replay(args.run, args.binary_sha256))


if __name__ == "__main__":
    main()
