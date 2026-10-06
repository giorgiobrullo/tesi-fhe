"""Fresh frozen replay plus independent finite coverage/counts on the same stream."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
BASE = HERE.parents[1]
sys.path.insert(0, str(BASE))
import audit as a  # noqa: E402
import replay  # noqa: E402
import run_gate as driver  # noqa: E402

SOURCE = "3104f9d691a4d5fb31695c8c07beb5b0fb9de8b6da7747bab60035b6802f32fa"
MANIFEST = "e49b68da0e25ed540144eca1c355e2aa931acc5e0db3d6dc85404ddafed54fde"
BINARY = "8bc24eccba0375f015b94a8d3ef4cbe0723025df3e8b09bedba650d009a77cba"
RAW = "406b30c55a6b1a382f8c7eedb07e20e9d7f8293a98024749b43f0db5bf954152"


def save(name, value):
    path = HERE / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


class IndependentCounts:
    def __init__(self):
        self.types = Counter()
        self.coverage = set()
        self.rounds = set()
        self.key_begins = []
        self.cm = Counter()
        self.anchor_cm = Counter()
        self.positive_counts = Counter()
        self.centers = 0
        self.ordinary_centers = 0
        self.positive_phase_rows = 0
        self.pair_results = 0
        self.negative_controls = []
        self.anchor_results = []

    def inspect(self, source):
        for row in source:
            kind = row["type"]
            self.types[kind] += 1
            case = row.get("case", "")
            positive = re.fullmatch(r"k([123])/p([0-9]+)/(plain|shared_zero)", case)
            if kind == "a176_key_begin":
                self.key_begins.append(row["key_index"])
            elif kind == "a176_pair_begin":
                key, index, bit = row["key_index"], row["pair_index"], row["bit"]
                names = ["asymmetric_zero_first", "all_dead_tail", "all_one_keep_tail", "only_zero_3", "only_zero_4", "only_zero_62", "only_zero_124", "only_zero_126", "tie_across_groups_and_lanes"]
                fixture = row["fixture"]
                fi=names.index(fixture)
                assert 0 <= bit < 8 and index == 8 * fi + (7 - bit)
                assert row["n"] == 127 and row["fixture_preparation_pbs"] == 254
                active = [0 if fi == 1 else 1] * 127
                zeros = {0} if fi == 0 else set(range(127)) if fi == 1 else set() if fi == 2 else {int(fixture.rsplit("_",1)[1])} if 3 <= fi <= 7 else {0,4,126}
                bits = [int(i not in zeros) for i in range(127)]
                assert row["public_active"] == active and row["public_bits"] == bits
                point = (key, fi, bit)
                assert point not in self.coverage
                self.coverage.add(point)
            elif kind == "a176_pair_result":
                assert row["plain_pass"] and row["shared_zero_pass"] and row["both_completed"] and row["passed"]
                self.pair_results += 1
            elif kind == "phase" and positive:
                self.positive_phase_rows += 1
            elif kind == "cm_zero_pool_event":
                target = self.cm if positive else self.anchor_cm
                target["events"] += 1
                target["chooser_invocations"] += row["chooser_invocations"]
                target["zero_additions"] += row["zero_additions"]
                target["refusals"] += not row["allowed"]
                target["unmet_bounds"] += row["estimator_satisfied"] is False
                target["pbs_executed"] += row["pbs_executed"]
                target["shared_policy_events"] += row["policy"] == "SharedZerosStockAssumption"
                if positive:
                    assert row["allowed"] and row["pbs_executed"]
                    self.centers += sum(not lane["corrected_inside_center_box"] for lane in row["lanes"])
            elif kind == "case_summary" and positive:
                assert case not in self.rounds
                self.rounds.add(case)
                assert row["passed"] and row["completed"] and row["ledger_ok"]
                assert row["stage_mismatches"] == row["output_mismatches"] == 0
                self.ordinary_centers += row["outside_center_boxes"]
                assert row["actual_cm_br_outside_center_boxes"] == 0
                self.positive_counts.update(row["counts"])
            elif kind == "graph_negative":
                # Complete source replay verifies actual mutation/expected detector semantics.
                self.negative_controls.append({k: v for k, v in row.items() if k in ("mutation", "detected", "fixture", "bit", "case")})
            elif kind == "a176_anchor_result":
                self.anchor_results.append(row)
            yield row


def main():
    assert __debug__, "review requires assertions"
    assert a.freeze_check() == {"source_sha256": SOURCE, "manifest_sha256": MANIFEST}
    for stage in ("n4-smoke", "n4-exhaustive", "n127"):
        run = BASE / "runs" / stage
        driver.private(run, True)
        assert run.stat().st_uid == os.getuid()
        for name in ("prepared.json","child.json","wait-complete.json","exit.json","clearance.json","stdout.jsonl","stderr.log"):
            path=run/name;driver.private(path)
            assert path.stat().st_uid==os.getuid() and path.stat().st_nlink==1
    counters = IndependentCounts()
    original = replay.inspect

    def inspected(source, stage, source_id, binary, pid):
        stream = counters.inspect(source) if stage == "n127" else source
        return original(stream, stage, source_id, binary, pid)

    replay.inspect = inspected
    try:
        fresh = driver.verify("n127")
    finally:
        replay.inspect = original
    assert fresh["gate_pass"]
    assert fresh["records"] == 777890 and fresh["pairs"] == 216
    assert fresh["source_sha256"] == SOURCE and fresh["binary_sha256"] == BINARY
    assert fresh["binding"]["stdout_sha256"] == RAW
    assert fresh["binding"]["child_pid"] == 40248 and fresh["binding"]["exit_code"] == 0
    assert fresh["binding"]["started_at_utc"] == "2026-09-05T09:25:15.842207+00:00"
    assert fresh["binding"]["exited_at_utc"] == "2026-09-05T10:00:38.877975+00:00"
    save("FRESH_REPLAY.json", fresh)
    expected_coverage = {(key, w, bit) for key in range(1, 4) for w in range(9) for bit in range(8)}
    assert counters.coverage == expected_coverage
    assert counters.key_begins == [1, 2, 3]
    assert len(counters.rounds) == 432 and counters.pair_results == 216
    assert sum(counters.types.values()) == 777890
    assert counters.positive_phase_rows == 432 * 1682
    assert counters.cm["events"] == counters.cm["pbs_executed"] == 432 * 113
    assert counters.cm["chooser_invocations"] == counters.cm["shared_policy_events"] == 216 * 113
    assert counters.cm["refusals"] == counters.cm["unmet_bounds"] == counters.centers == counters.ordinary_centers == 0
    per_round = dict(packing=65, cm_ks=81, cm_pbs=113, ordinary_ks=132, ordinary_pbs=130, extraction=131)
    assert dict(counters.positive_counts) == {k: 432 * v for k, v in per_round.items()}
    anchor = dict(packing=15, cm_ks=11, cm_pbs=17, ordinary_ks=45, ordinary_pbs=59, extraction=40)
    total = {k: counters.positive_counts[k] + 3 * anchor[k] for k in per_round}
    total["ordinary_pbs"] += 216 * 254
    assert total == fresh["reported_algorithm_counts"]
    root_report = BASE / "artifacts/n127-validation.json"
    if not root_report.exists():
        save("AWAITING_ROOT_REPORT.json", dict(status="FRESH_REPLAY_COMPLETE_ROOT_REPORT_NOT_YET_AVAILABLE"))
        print("FRESH_REPLAY_COMPLETE_ROOT_REPORT_NOT_YET_AVAILABLE", flush=True)
        return
    driver.private(root_report)
    root_bytes = root_report.read_bytes()
    a.same(a.parse(root_bytes), fresh, "independent frozen replay equals exact saved root report")
    raw = BASE / "runs/n127/stdout.jsonl"
    result = dict(
        status="INDEPENDENT_BOUND_N127_PASS",
        source_sha256=SOURCE, manifest_sha256=MANIFEST, binary_sha256=BINARY,
        validation_sha256=hashlib.sha256(root_bytes).hexdigest(), raw_sha256=RAW, raw_bytes=raw.stat().st_size,
        records=777890, record_types=dict(counters.types), child_pid=40248, exit_code=0,
        fresh_replay_equals_saved=True, private_source_binary_pid_utc_and_exact_bytes_bound=True,
        keys=3, fixtures_per_key=9, layouts_per_fixture=8, positive_pairs=216, positive_rounds=432,
        complete_registered_n127_fixture_coverage=True, positive_cm=dict(counters.cm), anchor_cm=dict(counters.anchor_cm),
        positive_cm_outside_center_boxes=counters.centers, positive_ordinary_outside_center_boxes=counters.ordinary_centers,
        reported_algorithm_counts=total, stock_output_extractions_outside_counts=24,
        anchor_diagnostics=fresh["anchor_diagnostics"],
        physical_counts_exclude_diagnostic_trace_extractions=True, margin_body_additions=48,
        old_A150_failure_unchanged=True, control_failures_not_used_for_key_selection=True,
        full_eight_round_composition=False, n127_executed=True, input_variance_proven=False,
        independent_lane_trials_or_key_membership_attested=False, noise_failure_probability=None, timing_claim=False,
        next_gate="Separate source-only A190 persistent eight-round composition; no automatic launch or inherited runtime result.",
    )
    save("RESULT.json", result)
    print(json.dumps({k: result[k] for k in ("status", "records", "positive_pairs", "positive_rounds", "positive_cm", "anchor_cm", "validation_sha256")}), flush=True)


if __name__ == "__main__":
    main()
