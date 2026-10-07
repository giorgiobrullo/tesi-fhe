"""Private additive A171 first-process review; no gate/acceptance-rule changes."""
from pathlib import Path
from collections import Counter
import hashlib
import json
import os

HERE = Path(__file__).resolve().parent
BASE = HERE.parents[2]
RUN = BASE / "runs/offset0-key1"
VALIDATION = HERE.parent / "offset0-key1-validation.json"
Q = 1 << 64

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def signed(value):
    return (value + Q // 2) % Q - Q // 2

def ms(word):
    return ((word + (1 << 51)) >> 52) % 4096

rows = [json.loads(line) for line in (RUN / "stdout.jsonl").read_text().splitlines()]
validated = json.loads(VALIDATION.read_text())
assert validated["status"] == "PASS_BOUND_A171_RECORDS"
assert len(rows) == 322
specs = json.loads((BASE.parent / "a137-pfks-runtime-error-observer/PREREGISTRATION.json").read_text())["fixture_specs"]
specs = {s["name"]: s for s in specs}
cases = [r for r in rows if r["record"] == "case"]
lanes = [r for r in rows if r["record"] == "lane"]
differences = [r for r in rows if r["record"] == "d1_difference_pfks"]
accumulators = [r for r in rows if r["record"] == "d1_accumulator"]
assert (len(cases), len(lanes), len(differences), len(accumulators)) == (8,32,32,8)
outputs = {}
for arm in ("direct", "scalar", "convolution", "direct_d1"):
    outputs[arm] = dict(lanes=len(lanes),
        native_pass=sum(r[arm]["decode_pass"] for r in lanes),
        strict_margin_pass=sum(r[arm]["half_slot_pass"] for r in lanes),
        nontrivial_pass=sum(r[arm]["nontrivial"] for r in lanes))
    assert outputs[arm] == dict(lanes=32,native_pass=32,strict_margin_pass=32,nontrivial_pass=32)
original_inputs = 0
for row in differences:
    delta = 1 << (56 if row["term"] == 3 else 59)
    for arm in ("left","right"):
        inp = row[arm]
        assert abs(signed(inp["phase"] - inp["message_phase"])) < delta // 2
        assert ((inp["phase"] + delta // 2) % Q) // delta == inp["message_phase"] // delta
        original_inputs += 1
    assert row["difference"]["words"] == [(r-l)%Q for r,l in zip(row["right"]["words"],row["left"]["words"])]
    assert row["difference_native_pass_is_prerequisite"] is False
    assert row["independent_noise_assumed"] is False
ms_words = 0
input_controls = 0
for acc in accumulators:
    spec=specs[acc["fixture"]]
    assert abs(signed(acc["input_control_phase"] - spec["control"]*(1<<59))) < (1<<58)
    input_controls += 1
    words=acc["control_words"]
    assert len(words)==860
    assert acc["modulus_switched_masks"] == [ms(w) for w in words[:-1]]
    assert acc["modulus_switched_body"] == ms(words[-1])
    ms_words+=len(words)
    effective=(ms(words[-1])-acc["secret_weighted_modulus_switched_mask_sum"])%4096
    assert effective==acc["actual_effective_rotation_degree"]
    error=(effective-spec["control"]*128)%4096
    if error>2048:error-=4096
    assert error==acc["actual_effective_rotation_error"] and abs(error)<=63
    assert acc["client_aggregate_key_membership_attested"] is False
for case in cases:
    assert all(case[k] for k in ("ingress_ok","prerequisites_ok","support_ok","post_ks_controls_bitwise_equal","d1_control_bitwise_equal","scalar_ok","direct_counters_pass","scalar_counters_pass","convolution_counters_pass","d1_observer_pass","observer_identity_pass"))
    assert all(case[k]=="pass" for k in ("d1_class","direct_class","convolution_class"))
d1_totals={k:sum(c["d1_counters"][k] for c in cases) for k in cases[0]["d1_counters"] if k!="pass"}
assert d1_totals==dict(pfks=32,ks=8,br=8,samples=32,rotations=32,polynomial_permutations=64,glwe_additions=24,lwe_subtractions=32,lwe_addbacks=32)
d2_fields=dict(pfks="direct_pfks",ks="direct_control_ks",br="direct_blind_rotations",samples="direct_extractions")
d2_totals={k:sum(c[field] for c in cases) for k,field in d2_fields.items()}
assert d2_totals==dict(pfks=64,ks=8,br=8,samples=32)
summary=rows[321]
total={k:v*8 for k,v in summary["primitives_per_fixture"].items()}
assert total==dict(pfks=224,ks=56,br=56,samples=128)
report=dict(schema="a171-private-offset0-post-replay-review-v1",
    status="PASS_FIRST_OFFSET0_COMPONENT_ONLY", gate_rules_changed=False, retry=False,
    validation_sha256=sha(VALIDATION), raw_sha256=sha(RUN/"stdout.jsonl"),
    envelope_manifest_sha256=sha(BASE/"execution-readiness/MANIFEST.json"),
    candidate_manifest_sha256=sha(BASE/"ARTIFACT_MANIFEST.json"),
    record_counts=dict(Counter(r["record"] for r in rows)),
    outputs_by_arm=outputs, original_payload_native_and_strict_inputs=original_inputs,
    original_control_strict_inputs=input_controls, original_ingress_total=original_inputs+input_controls,
    post_ks_control_native_strict_cases=sum(c["control_phase_audit"]["decode_pass"] and c["control_phase_audit"]["half_slot_pass"] for c in cases),
    coefficientwise_ms_words_checked=ms_words, effective_support_pass_cases=8,
    phase_only_support_disagreements=summary["phase_only_support_disagreements"],
    full_modular_subtraction_word_equalities=32*2049,
    d1_reported_counter_totals=d1_totals,d2_reported_counter_totals=d2_totals,
    full_four_arm_source_matched_counter_totals=total,
    old_control_projection_counts_scope="192PFKS/48KS/48BR/96samples covers only the three original arms, not the actual four-arm run.",
    difference_native_diagnostic_failures=sum(not r["difference_native_decode_diagnostic"] for r in differences),
    difference_half_slot_diagnostic_failures=sum(not r["difference_native_half_slot_diagnostic"] for r in differences),
    difference_native_is_not_prerequisite=True,
    difference_rows_with_nonlinear_public_digit_coefficients=sum(r["nonlinear_digit_count"]>0 for r in differences),
    observer_failures=summary["observer_failures"],
    declared_fresh_keysets=1, current_key_all_four_arm_cases=8,
    three_process_preregistration_complete=False, later_offsets_authorized_by_this_result=False,
    no_formal_tail_or_timing_or_full_id_claim=True,
    next_gate="Only a separate root decision and fresh workload clearance may authorize reviewed one-shot offset1 and offset2 successors; preserve offset0 launcher and output. After each process terminal, independently replay identities/outcomes. A 24-case aggregate must verify all24 four-arm permutations and six distinct functional-key hashes; hash distinctness does not attest independent sampling or key membership.")
fd=os.open(HERE/"RESULT.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"w") as out:json.dump(report,out,indent=2);out.write("\n")
print(json.dumps({k:report[k] for k in ("status","original_ingress_total","coefficientwise_ms_words_checked","difference_native_diagnostic_failures","difference_half_slot_diagnostic_failures","difference_rows_with_nonlinear_public_digit_coefficients")}))
