"""Read-only checks of frozen first-negative affine identities; private additive output only."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import model as m

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pins():
    values = json.loads((HERE / "PINNED_INPUTS.json").read_text())["files"]
    for path, expected in values.items():
        if sha(Path(path)) != expected:
            raise ValueError("changed pinned input: " + path)
    return len(values)


def inspect():
    count = pins()
    base = ROOT / "tmp/a179-a149-first-runtime-launcher"
    diagnosis = json.loads(
        (base / "artifacts/first-affine-diagnosis.json").read_bytes()
    )
    validation = json.loads((base / "artifacts/first-validation.json").read_bytes())
    raw = (base / "runs/first-padding-coefficients/stdout.jsonl").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == validation["input_sha256"]["stdout.jsonl"]
    rows = [json.loads(x) for x in raw.splitlines()]
    assert len(rows) == 355 and validation["result"]["coefficient_failures"] == 0
    results = []
    for arm, report in enumerate(diagnosis["reports"]):
        case = next(x for x in rows if x["record"] == "case" and x["arm"] == arm)
        events = {
            x["stage"]: x for x in rows if x["record"] == "event" and x["arm"] == arm
        }
        for failure in report["native_failures"]:
            assert (
                m.signed(sum(t["signed_contribution"] for t in failure["affine_terms"]))
                == failure["signed_error"]
            )
            for term in failure["affine_terms"]:
                assert (
                    m.signed(term["multiplier"] * term["signed_symbol_error"])
                    == term["signed_contribution"]
                )
        first = report["first_wrong_lut_report"]
        terms = report["first_input_affine_terms_by_absolute_contribution"]
        assert m.signed(sum(t["signed_contribution"] for t in terms)) == int(
            first["input_affine_error"]
        )
        assert first["expected_lut_word"] != first["observed_lut_word"]
        raw_first = events[report["first_wrong_lut_stage"]]
        assert int(raw_first["big_phase_word"]) == m.word(
            int(first["input_nominal_word"]) + int(first["input_affine_error"])
        )
        public_upscale_identical = None
        if report["first_wrong_lut_stage"] == "middle_round.mask/2":
            d = m.word(
                ((case["scores"][2] >> 4) & 15) * (1 << 51)
                + int(case["middle51_errors"][2])
            )
            flag = int(events["a34.candidate/2"]["output_phase_word"])
            flag_factor = 1 if arm == 3 else 16
            original = m.word(256 * d + flag_factor * flag)
            scaled = m.word(32 * m.word(8 * d) + flag_factor * flag)
            assert original == scaled == int(raw_first["big_phase_word"])
            public_upscale_identical = True
        results.append(
            dict(
                arm=report["arm"],
                original_gate_pass=False,
                native_failure_count=report["native_failure_count"],
                native_failure_fields=[
                    (x["field"], x["lane"]) for x in report["native_failures"]
                ],
                first_wrong_lut_stage=report["first_wrong_lut_stage"],
                first_input_affine_coefficients=[
                    dict(symbol=t["symbol"], multiplier=t["multiplier"]) for t in terms
                ],
                first_input_affine_identity_checked=True,
                native_failure_affine_identities_checked=True,
                exact_public_upscale_same_consumed_input=public_upscale_identical,
                all_native_msb_outputs_pass=report["native_msb_outputs_pass"],
                final_flags_pass=report["final_flags_pass"],
            )
        )
    assert [r["native_failure_count"] for r in results] == [4, 2, 4, 2]
    assert all(r["all_native_msb_outputs_pass"] for r in results)
    return dict(
        status="PRESERVED_FIRST_NEGATIVE_AFFINE_IDENTITIES_CHECKED",
        pins=count,
        records=355,
        coefficient_events=346,
        coefficient_closure_failures=0,
        arms=results,
        old_result_reinterpreted=False,
        new_error_law_inferred=False,
        new_runtime_counterfactual=False,
        secret_membership_independently_attested=False,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--write", action="store_true")
    args = p.parse_args()
    if not args.write:
        print(
            json.dumps(
                dict(
                    status="PLAN_ONLY",
                    new_experiment=False,
                    clear_test="python3 -m unittest -q test_model.py",
                )
            )
        )
        return
    result = inspect()
    path = HERE / "OBSERVED_AFFINE_AUDIT.json"
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
    ) as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(
        json.dumps(
            dict(
                status=result["status"],
                records=355,
                native_failures=[4, 2, 4, 2],
                output_sha256=sha(path),
            )
        )
    )


if __name__ == "__main__":
    main()
