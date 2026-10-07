"""Run only light static checks and save explicitly synthetic examples."""

import json
from pathlib import Path
import unittest

from checker import analyze_case, analyze_records, pinned_inputs
from synthetic import FAKE_BINARY_HASH, complete_safe_log, make_case

HERE = Path(__file__).resolve().parent


def write_json(path, result):
    path.write_text(json.dumps(result, indent=2) + "\n")


def main():
    pinned_inputs()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.discover(str(HERE), "test_checker.py")
    )
    if not result.wasSuccessful():
        raise SystemExit(1)
    examples = HERE / "examples"
    examples.mkdir(exist_ok=True)
    records = complete_safe_log()
    (examples / "safe_complete_synthetic.jsonl").write_text(
        "".join(json.dumps(x) + "\n" for x in records)
    )
    safe = analyze_records(records, FAKE_BINARY_HASH)
    safe_summary = {k: v for k, v in safe.items() if k != "reports"}
    write_json(examples / "safe_complete_summary.json", safe_summary)
    plans = [
        (
            "shared_joint_error",
            [1, 0, 255, 1024],
            0,
            [0, -(1 << 58), 0, 0],
            {"ingress/1/low.msb54": dict(error=3 << 48)},
        ),
        (
            "separate_joint_error_control",
            [1, 0, 255, 1024],
            1,
            [0, -(1 << 58), 0, 0],
            {"ingress/1/low.msb54": dict(error=3 << 48)},
        ),
        (
            "active_native_pass_consumer_fail",
            [1, 0, 2, 3],
            0,
            [0] * 4,
            {"a34.candidate/1": dict(error=1 << 56)},
        ),
        (
            "zero_alias_wrong_fold",
            [1, 0, 2, 3],
            1,
            [0] * 4,
            {"ingress/1/low.msb63_independent_scale": dict(error=1 << 63)},
        ),
        (
            "zero_phase_ms_displacement",
            [1, 0, 2, 3],
            0,
            [0] * 4,
            {"middle_round.mask/1": dict(ms=64)},
        ),
    ]
    summaries = []
    for name, scores, arm, low_errors, perturbations in plans:
        case, events, _ = make_case(
            scores, arm, low_errors=low_errors, perturbations=perturbations
        )
        replay = analyze_case(case, events)
        write_json(
            examples / (name + ".json"),
            dict(
                synthetic=True,
                case_fragment_only=True,
                case=case,
                events=events,
                replay=replay,
            ),
        )
        summaries.append(
            dict(
                name=name,
                native_decode_pass=replay["native_decode_pass"],
                native_msb_outputs_pass=replay["native_msb_outputs_pass"],
                composed_a34_a135_pass=replay["composed_a34_a135_pass"],
                conditional_joint_safe_region_pass=replay[
                    "conditional_joint_safe_region_pass"
                ],
                flags=replay["flags"],
                expected_flags=replay["expected_flags"],
                region_failures=replay["region_failures"],
            )
        )
    report = dict(
        status="STATIC_SYNTHETIC_REPLAY_ONLY",
        tests=result.testsRun,
        source_pin_count=7,
        safe_complete_synthetic=safe_summary,
        examples=summaries,
        loop_scope="No exhaustive FHE/noise enumeration; exact interval endpoints, thirteen tests, one eight-fixture/three-arm synthetic A138 stream.",
        mutation_scope="Nine single-event field corruptions, a missing event, missing summary, wrong binary hash and forged native-only completion.",
        ms_scope="Uses recorded actual MS address; no ciphertext coefficients or secret key available for independent recomputation.",
        no_noise_probability_reachability_or_independence_claim=True,
    )
    write_json(HERE / "STATIC_RESULT.json", report)
    print(json.dumps({k: report[k] for k in ("status", "tests", "source_pin_count")}))


if __name__ == "__main__":
    main()
