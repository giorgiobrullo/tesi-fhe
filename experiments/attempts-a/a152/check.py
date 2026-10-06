"""Reproducible static checks and fresh-mask examples. No FHE or process calls."""

from collections import Counter
from fractions import Fraction as F
import hashlib
import io
import json
from pathlib import Path
import unittest

from gate import encode, evaluate, write_json
from law import exact_escape, exact_joint_law, fresh_bound, native_witness
from sources import verify_sources

HERE = Path(__file__).resolve().parent


def main():
    assert not (HERE / "artifacts").exists(), (
        "Preserve prior evidence; run test_law.py to recheck"
    )
    pins = verify_sources()
    log = io.StringIO()
    tests = unittest.TextTestRunner(stream=log, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromName("test_law")
    )
    if not tests.wasSuccessful():
        print(log.getvalue())
        raise SystemExit(1)
    artifacts = HERE / "artifacts"
    artifacts.mkdir(mode=0o700)
    u = 1 << 52
    numeric = {
        "fixed_h859_phase0": evaluate(),
        "weight_at_most859_phase0": evaluate(weight_mode="at_most"),
        "fixed_h859_half_degree_phase0": evaluate(theta=u // 2),
        "fixed_h859_phase_bound4U_delta2m80": evaluate(
            phase_interval=(-4 * u, 4 * u), phase_failure=F(1, 1 << 80)
        ),
        "weight_at_most859_phase_bound4U_delta2m80": evaluate(
            weight_mode="at_most",
            phase_interval=(-4 * u, 4 * u),
            phase_failure=F(1, 1 << 80),
        ),
    }
    write_json(artifacts / "conditional-native-bounds.json", numeric)
    tiny = exact_joint_law(4, 4, degrees=4)
    correlated = Counter()
    for a in range(16):
        observation = native_witness([a] * 4, [1] * 4, 0, 0, 0, 16, 4)
        correlated[observation["lifted_displacement"]] += 1
    comparison = dict(
        same_uniform_native_coordinate_marginals=True,
        fixed_secret=[1, 1, 1, 1],
        phase_error=0,
        q=16,
        U=4,
        iid_law=tiny,
        iid_failure=exact_escape(tiny, (-1, 1), 4),
        iid_bound=fresh_bound(4, 4, (-1, 1)),
        perfectly_shared_native_mask_lift_counts=dict(correlated),
        perfectly_shared_mask_failure=F(1, 4),
        exact_scope="constructed finite distributions; not observed A44 post-KS randomness",
    )
    write_json(
        artifacts / "uniform-marginals-correlation-counterexample.json", comparison
    )
    write_json(
        artifacts / "body-dependence-and-bias.json",
        {
            "h1_e0": exact_joint_law(4, 1),
            "h4_e0": tiny,
            "half_degree_h0": exact_joint_law(4, 0, theta=2),
            "whole_period_noise_h0": exact_joint_law(
                4, 0, noise_law=((F(1), 16),), degrees=4
            ),
            "same_phase_marginal_failure_if_equal_to_residue": F(1, 2),
            "same_phase_marginal_failure_if_complement": F(0),
            "same_phase_marginal_failure_if_independent": F(1, 4),
        },
    )
    result = dict(
        status="STATIC_FRESH_MASK_LAW_AND_RIGOROUS_CONDITIONAL_BOUND_PASS",
        tests_run=tests.testsRun,
        test_output=log.getvalue(),
        source_pins=len(pins),
        full_native_mask_observations=12288,
        exact_tiny_law_bound_comparisons=126,
        numeric_conditional_upper_bounds={
            name: report["conditional_failure_upper"]
            for name, report in numeric.items()
        },
        ideal_randomness_model=True,
        actual_post_ks_freshness_proved=False,
        phase_noise_budget_for_actual_a44_proved=False,
        actual_a44_p_fail=None,
        rust_build_or_fhe=False,
        process_inspection_or_signals=False,
        network=False,
        staging_note="Initial Ruff check found ambiguous one-letter names and one unused import; corrected before any math test failure.",
        artifact_sha256={
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(artifacts.iterdir())
        },
    )
    write_json(HERE / "STATIC_RESULT.json", result)
    print(
        json.dumps(
            encode({k: v for k, v in result.items() if k != "test_output"}), indent=2
        )
    )


if __name__ == "__main__":
    main()
