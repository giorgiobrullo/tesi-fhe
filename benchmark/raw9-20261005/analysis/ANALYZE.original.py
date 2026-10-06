"""Validate the new public run log and summarize its paired timings only."""
from pathlib import Path
import collections
import hashlib
import json
import statistics

phase = Path(__file__).resolve().parents[1]
root = phase / "root"
capture = json.loads((root / "NATIVE_CAPTURE.json").read_text())
assert capture["status"] == "terminal" and capture["exit_code"] == 0
assert (root / "NATIVE.stderr.log").stat().st_size == 0
rows = [json.loads(line) for line in (root / "NATIVE.stdout.log").read_text().splitlines()]
assert all(row["probe"] == "raw-threshold-fullquery.20261005.v1" for row in rows)
stages = collections.Counter(row["stage"] for row in rows)
assert stages == {"public_plan": 2, "fresh_key_generation": 1, "correctness": 6,
                  "correctness_complete": 1, "paired_cost": 18, "complete": 1}, stages
assert all(row["pass"] is True for row in rows if "pass" in row)
plans = [row for row in rows if row["stage"] == "public_plan"]
assert [row["gallery_index"] for row in plans] == [0, 1]
assert all((row["execution_lower"], row["execution_upper"], row["sentinel"]) ==
           (-987, 2318, 1261) for row in plans)
keys = next(row for row in rows if row["stage"] == "fresh_key_generation")
assert keys["key_families"] == 1 and keys["unique_queries"] == 5 and keys["rayon_threads"] == 16
expected_ids = {"einstein": 1, "curie": 2, "turing": 3, "right83": 83,
                "zero-reject": 0, "crossroot-tie": 1}
whole_counts = [dict(br=1111, ks=1080, pfks=509, marginals=1709, initial_samples=120),
                dict(br=1113, ks=1083, pfks=507, marginals=1710, initial_samples=120)]
field_names = ["br", "ks", "pfks", "marginals", "gadget_levels",
               "pfks_monomial_rotations", "polynomial_permutations", "glwe_additions",
               "lwe_subtractions", "lwe_addbacks", "public_centering_calls",
               "public_centering_mask_terms", "public_centering_body_additions",
               "initial_score_samples", "prototype_full51_to_full52_scales"]
terminal_work = [dict(zip(field_names, values)) for values in
                 [(11, 10, 7, 15, 11, 7, 14, 4, 7, 7, 4, 3436, 4, 0, 0),
                  (13, 13, 5, 16, 13, 5, 10, 3, 5, 5, 4, 3436, 4, 0, 0)]]
routes = [dict(batch3_merges=0, comparator_callbacks=callbacks, group_br_tasks=groups,
               parallel3_merges=parallel, pfks_tasks=pfks, selectors=2,
               selectors_by_ready_1_to_4=[2, 0, 0, 0])
          for callbacks, groups, parallel, pfks in [(6, 3, 2, 7), (9, 2, 3, 5)]]
gates = [row for row in rows if row["stage"] == "correctness"]
assert len({row["case"] for row in gates}) == 6
for row in gates:
    assert [arm["arm"] for arm in row["arms"]] == ["baseline", "raw_parallel9"]
    for index, arm in enumerate(row["arms"]):
        assert arm["id"] == expected_ids[row["case"]]
        assert arm["counts"] == whole_counts[index]
        assert arm["terminal"]["work"] == terminal_work[index]
        assert arm["terminal"]["scheduling"] == routes[index]
        assert arm["terminal"]["duration_ns"] > 0
assert next(row for row in rows if row["stage"] == "correctness_complete")["decoded_id_outputs"] == 12
complete = rows[-1]
assert complete["stage"] == "complete"
assert [complete[name] for name in ("correctness_id_outputs", "warmup_id_outputs",
                                  "timed_id_outputs", "decoded_id_outputs")] == [12, 6, 36, 54]
pairs = [row for row in rows if row["stage"] == "paired_cost"]
cases = {}
for case in ("einstein", "curie", "turing"):
    scene = [row for row in pairs if row["case"] == case]
    assert len(scene) == 6
    assert {(row["repeat"], row["order_index"]) for row in scene} == {
        (repeat, order) for repeat in range(3) for order in range(2)}
    assert [row["arm_order"] for row in scene] == [[0, 1], [1, 0]] * 3
    for row in scene:
        assert row["final_ids"] == [expected_ids[case]] * 2
        assert len(row["arm_reports"]) == 2
        for index, report in enumerate(row["arm_reports"]):
            assert report["counts"] == whole_counts[index]
            assert report["terminal_work"] == terminal_work[index]
            assert report["terminal_scheduling"] == routes[index]
        for boundary in ("whole_duration_ns", "terminal_duration_ns"):
            assert len(row[boundary]) == 2 and all(value > 0 for value in row[boundary])
        assert all(t < w for t, w in zip(row["terminal_duration_ns"], row["whole_duration_ns"]))
    case_result = {}
    for name, field in (("whole", "whole_duration_ns"), ("terminal", "terminal_duration_ns")):
        deltas = [100 * (row[field][1] / row[field][0] - 1) for row in scene]
        case_result[name] = {
            "baseline_median_ms": statistics.median(row[field][0] for row in scene) / 1e6,
            "raw9_median_ms": statistics.median(row[field][1] for row in scene) / 1e6,
            "median_paired_change_percent": statistics.median(deltas),
            "paired_change_range_percent": [min(deltas), max(deltas)],
            "raw9_faster_pairs": sum(delta < 0 for delta in deltas), "pairs": 6,
        }
    cases[case] = case_result
summary = {
    "native_exit_code": 0, "log_rows": len(rows), "stage_rows": dict(stages),
    "correctness_cases": expected_ids, "declared_validated_id_outputs": 54,
    "individually_logged_gate_and_timed_ids": 48,
    "warmup_ids": "6 checked inside source driver; not individually logged",
    "paired_orders_balanced": True, "all_public_counts_and_routes_verified": True,
    "whole_counts_by_arm": whole_counts, "terminal_work_by_arm": terminal_work,
    "terminal_routes_by_arm": routes, "cases": cases,
    "scope": complete["scope"], "timing_boundary": complete["timing_boundary"],
    "no_e2e_projection_or_baseline_adoption": True,
    "stdout_sha256": hashlib.sha256((root / "NATIVE.stdout.log").read_bytes()).hexdigest(),
}
with (root / "RESULT_SUMMARY.json").open("x") as output:
    json.dump(summary, output, indent=2)
    output.write("\n")
print(json.dumps({"rows": len(rows), "cases": cases, "declared_correct_ids": 54}))
