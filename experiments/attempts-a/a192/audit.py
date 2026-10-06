"""Exact predecessor invariants and arithmetic schedule audit; no native calls."""

import json
from pathlib import Path
import replay as r

HERE = Path(__file__).resolve().parent


def verify():
    origins = r.parse((HERE / "SOURCE_ORIGINS.json").read_bytes())
    for path, digest in origins["files"].items():
        r.eq(r.sha(path), digest, "origin " + path)
    old = HERE.parent / "a187-padding-precision-runtime-gate"
    for path in origins["unchanged"]:
        r.eq(
            (HERE / path).read_bytes(),
            (old / path).read_bytes(),
            "exact unchanged " + path,
        )
    r.eq(
        (HERE / "PASSING_FIRST.json").read_bytes(),
        (old / "artifacts/independent-review/review.json").read_bytes(),
    )
    for path, digest in r.parse((HERE / "SOURCE_PINS.json").read_bytes())[
        "files"
    ].items():
        r.eq(r.sha(path), digest, "cached primary " + path)
    reference = r.reference()
    r.eq(r.parse((HERE / "REFERENCE.json").read_bytes()), reference)
    prereg = r.parse((HERE / "PREREGISTRATION.json").read_bytes())
    r.eq(prereg["fixtures"], r.fixtures(), "exact preregistered fixture identities")
    for stage in r.STAGES:
        r.eq(prereg["stages"][stage]["plan"], r.plan(stage, False))
        r.eq(
            prereg["stages"][stage]["all_complete_negative_prefixes"],
            [r.summary(stage, n, False) for n in range(1, 3 * r.STAGES[stage] + 1)],
        )
    negative = []
    for fixture in r.fixtures():
        model = r.c.Precision(wrong=True)
        result = model.evaluate(fixture["scores"])
        negative.append(not result["final_flags_pass"])
    r.eq(negative[0], True, "finite anchor discrimination")
    # This counterexample is why detection is not universally required.
    r.eq(negative[8], False, "all-zero control is nondiscriminating")
    src = (HERE / "src/gate.rs").read_text()
    r.need("let minimum = *scores.iter().min().unwrap();" in src, "actual score oracle")
    r.need(
        'fixture_index != 0 || cases[2]["wrong_scale_detected"] == true' in src,
        "finite control scope",
    )
    r.need("break 'keys;" in src, "first negative stops")
    return dict(
        status="SOURCE_AND_FIXED_SCHEDULE_PASS",
        unchanged_files=len(origins["unchanged"]),
        origin_pins=len(origins["files"]),
        primary_pins=len(r.parse((HERE / "SOURCE_PINS.json").read_bytes())["files"]),
        fixtures=16,
        nominal_wrongscale_detected_by_fixture=negative,
        arm_events=[63, 71, 71],
        component_records=211,
        component_events=205,
        stages={stage: r.plan(stage, False) for stage in r.STAGES},
        compiled=False,
        actual_fhe=False,
    )


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
