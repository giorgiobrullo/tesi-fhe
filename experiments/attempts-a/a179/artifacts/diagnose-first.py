"""Private exact-affine diagnosis of the already terminal first A149 negative."""

import hashlib
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = BASE.parents[1]
SOURCE = ROOT / "tmp/a149-padding-coefficient-gate"
sys.dont_write_bytecode = True
sys.path.insert(0, str(SOURCE))
from graph import Graph  # noqa: E402
from contract import ARMS, FIXTURES  # noqa: E402
import regions  # noqa: E402


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


raw_path = BASE / "runs/first-padding-coefficients/stdout.jsonl"
validation_path = HERE / "first-validation.json"
assert sha(validation_path) == "2909be7579a391ba9053e567f20a392c63e1f1724b12e44265c813aef046fb62"
validation = json.loads(validation_path.read_text())
assert sha(raw_path) == validation["input_sha256"]["stdout.jsonl"]
raw = [json.loads(line) for line in raw_path.read_bytes().splitlines()]
reports = []
for index, arm in enumerate(ARMS[:4]):
    events = [row for row in raw if row["record"] == "event" and row["arm"] == index]
    case = next(row for row in raw if row["record"] == "case" and row["arm"] == index)
    graph = Graph(events=events, padding=arm["padding"], wrong_final=arm["wrong_final"])
    result, outputs = graph.evaluate(FIXTURES[2], list(map(int, case["input_full_errors"])), list(map(int, case["input_packed_low_errors"])), arm["independent"], arm["wrong_scale"])
    native_failures = []
    for field, scale in (("low51", 51), ("middle51", 51), ("top60", 60)):
        for lane, value in enumerate(outputs[field]):
            error = regions.signed(graph.error(value))
            if not regions.native_safe(error, scale):
                terms = [dict(symbol=symbol, multiplier=factor, signed_symbol_error=regions.signed(graph.symbols[symbol]), signed_contribution=regions.signed(factor * graph.symbols[symbol])) for symbol, factor in value.terms.items()]
                assert regions.signed(sum(term["signed_contribution"] for term in terms)) == error
                native_failures.append(dict(field=field, lane=lane, log_scale=scale, signed_error=error, affine_terms=terms))
    region_failures = [row for row in graph.reports if not row["conditional_region_pass"]]
    assert all(row["expected_lut_word"] != row["observed_lut_word"] for row in region_failures)
    first = region_failures[0]
    terms = [dict(symbol=symbol, multiplier=factor, signed_symbol_error=regions.signed(graph.symbols[symbol]), signed_contribution=regions.signed(factor * graph.symbols[symbol])) for symbol, factor in first["input_affine_error_terms"].items()]
    assert regions.signed(sum(term["signed_contribution"] for term in terms)) == int(first["input_affine_error"])
    terms.sort(key=lambda term: abs(term["signed_contribution"]), reverse=True)
    reports.append(dict(arm=arm["name"], native_decode_pass=result["native_decode_pass"], final_flags_pass=result["composed_a34_a135_pass"], flags=result["flags"], expected_flags=result["expected_flags"], native_failure_count=len(native_failures), native_failures=native_failures, wrong_lut_value_count=len(region_failures), first_wrong_lut_stage=first["stage"], first_wrong_lut_report=first, first_input_affine_terms_by_absolute_contribution=terms, native_msb_outputs_pass=result["native_msb_outputs_pass"]))
result = dict(status="FIRST_A149_NEGATIVE_AFFINE_DIAGNOSIS", actual_fhe_rerun=False, counterfactual_runtime=False, records=355, coefficient_events=346, coefficient_closure_failures=0, reports=reports, input_sha256={str(raw_path):sha(raw_path),str(validation_path):sha(validation_path),str(SOURCE/'graph.py'):sha(SOURCE/'graph.py'),str(Path(__file__)):sha(Path(__file__))}, inference_scope="Exact decomposition under frozen observed graph/client aggregates; no independent key membership, causal noise law, replacement implementation or failure bound", full_exact_id=False, sampled_noise_improvement=False, next_test="Change the low/middle digit ingress or consumer precision premise before a new frozen first-key gate; retain both shared-512 and separate-scale failures")
os.umask(0o077)
with (HERE / "first-affine-diagnosis.json").open("x") as handle:
    json.dump(result, handle, indent=2)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
for report in reports:
    print(json.dumps({key:report[key] for key in ("arm", "native_failure_count", "wrong_lut_value_count", "first_wrong_lut_stage", "final_flags_pass", "native_msb_outputs_pass")}))
