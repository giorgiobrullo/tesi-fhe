#!/usr/bin/env python3
"""Post-replay private observation summary; does not change frozen acceptance rules."""
from pathlib import Path
from collections import Counter
import hashlib
import json
import os

HERE = Path(__file__).resolve().parent
BASE = HERE.parents[2]
RUN = BASE / "runs/smoke-key1"
VALIDATION = HERE.parent / "smoke-key1-validation.json"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

rows = [json.loads(line) for line in (RUN / "stdout.jsonl").read_text().splitlines()]
validation = json.loads(VALIDATION.read_text())
assert validation["status"] == "PASS_RECORD_CONSISTENCY"
assert len(rows) == 16104
arms = list(dict.fromkeys(r["arm"] for r in rows if r.get("record") == "case"))
assert len(arms) == 6
arm_results = []
for arm in arms:
    cases = [r for r in rows if r.get("record") == "case" and r["arm"] == arm]
    consumers = [r for r in rows if r.get("record") == "consumer_scalar_phase" and r["arm"] == arm]
    margins = [r for r in rows if r.get("record") == "weighted_p16_margin" and r["arm"] == arm]
    outside = [r for r in margins if not r["inside_open_half_slot"]]
    assert len(cases) == 28 and len(consumers) == 784 and len(margins) == 224
    arm_results.append(dict(arm=arm, cases=len(cases),
        native_failed_cases=sum(not r["native_decode_pass"] for r in cases),
        scalar_consumer_failed_cases=sum(not r["consumer_scalar_phase_pass"] for r in cases),
        scalar_consumer_failed_rows=sum(not r["pass"] for r in consumers),
        case_failures=sum(not r["pass"] for r in cases),
        conservative_margin_outside_rows=len(outside),
        conservative_margin_outside_bit_counts=dict(Counter(r["bit"] for r in outside))))
assert [a["conservative_margin_outside_rows"] for a in arm_results] == validation["outside_open_half_slot_in_six_arm_order"]
new_arm = "single_full_direct_b0_b1"
private_excursions = []
for m in rows:
    if m.get("record") != "weighted_p16_margin" or m["arm"] != new_arm or m["inside_open_half_slot"]:
        continue
    matching = lambda r: (r["keyset"], r["scene"], r["x"], r["bit"]) == (m["keyset"], m["scene"], m["x"], m["bit"])
    cons = [r for r in rows if r.get("record") == "consumer_scalar_phase" and r["arm"] == new_arm and matching(r)]
    assert [(r["level"], r["candidate"]) for r in cons] == [(5, -1), (5, 0), (5, 1)]
    assert all(r["pass"] for r in cons)
    prior = [r for r in rows if r.get("record") == "weighted_p16_margin" and r["arm"] in arms[2:4] and matching(r)]
    assert len(prior) == 2
    assert all(all(r[k] == m[k] for k in ("actual_p16", "expected_p16", "signed_error", "inside_open_half_slot")) for r in prior)
    private_excursions.append(dict(margin_record=m, scalar_consumer_records=cons,
        unchanged_bit_margin_matches_prior_two_candidates=True))
assert len(private_excursions) == 2
assert all(e["margin_record"]["bit"] == 2 for e in private_excursions)
prior_fail = BASE.parent / "a165-low-correction-b1-repair/runtime-validation/artifacts/smoke-key1-validation.json"
assert sha(prior_fail) == "315102a7f1dc717b891f0000692e137abdb17524e70a5173c679fa2ac8722a2c"
result = dict(
    schema="a169-post-replay-private-observation-review-v1",
    status="PASS_FROZEN_REPLAY_WITH_CONSERVATIVE_MARGIN_OBSERVATIONS",
    acceptance_rules_changed=False,
    actual_run_retried=False,
    validation_sha256=sha(VALIDATION), stdout_sha256=sha(RUN / "stdout.jsonl"),
    source_sha256=validation["launch_binding"]["source_sha256"],
    binary_sha256=validation["launch_binding"]["binary_sha256"],
    frozen_checker_manifest_sha256=validation["validator_freeze"]["manifest_sha256"],
    records=len(rows), arms=arm_results,
    b1_pair_rows=validation["records"]["repair_pair"],
    b0_pair_rows=validation["records"]["repair_pair_b0"],
    b1_pair_failures=validation["summary"]["repair_pair_failures"],
    b0_pair_failures=validation["summary"]["repair_b0_pair_failures"],
    original_b1_gate_pass=validation["summary"]["repair_gate_pass"],
    new_b0_b1_gate_pass=validation["summary"]["repair_b0_b1_gate_pass"],
    negative_detections=validation["summary"]["negative_detections_drop_rescale"],
    private_new_repair_margin_excursions=private_excursions,
    prior_a165_failure_preserved_sha256=sha(prior_fail),
    margin_interpretation="Conservative open-half-slot excursions are observational. The frozen gate uses actual scalar-LUT predicates, which pass in all five positive arms. No independent coefficientwise KS/MS or composed noise bound follows.",
    scope="One declared fresh keyset, fixed 28-score smoke. Actual producer FHE and scalar ideal-candidate/KS zero-MS consumer checks only; no actual composed consumer PBS, full ID, latency, formal p_fail or independent key-membership attestation.",
    next_changed_premise="For consumer correctness, source-gate actual composed consumers with their real candidate/KS/coefficientwise MS noise. If investigating conservative bit-2 support, a separately derived direct-scale b2 intervention would increase the candidate from 10 to 11 PBS with 8 KS, removing its one-PBS extractor saving versus the 11-PBS split baseline; no such successor is implemented or authorized here.")
out = HERE / "RESULT.json"
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as handle:
    json.dump(result, handle, indent=2)
    handle.write("\n")
print(json.dumps(dict(status=result["status"], records=len(rows), new_gate=result["new_b0_b1_gate_pass"], margin_excursions=len(private_excursions), result_sha256=sha(out))))
