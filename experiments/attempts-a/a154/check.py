"""Generate bounded exact certificates and finite counterexamples, preserving outputs."""

from fractions import Fraction as F
import hashlib
import io
import json
from pathlib import Path
import unittest

from gate import encode, write_json
from model import endpoint, integrate, tiny_exact_mixture, verify_sources

HERE = Path(__file__).resolve().parent


def main():
    artifacts = HERE / "artifacts"
    assert not artifacts.exists(), "Preserve evidence; rerun test_model.py for a check"
    verify_sources()
    log = io.StringIO()
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromName("test_model")
    )
    if not result.wasSuccessful():
        print(log.getvalue())
        raise SystemExit(1)
    artifacts.mkdir(mode=0o700)
    u = 1 << 52
    zero = integrate()
    bounded = integrate(phase_interval=(-4 * u, 4 * u), phase_failure=F(1, 1 << 80))
    robust = integrate(
        phase_interval=(-4 * u, 4 * u),
        phase_failure=F(1, 1 << 80),
        phase_independent_of_secret_and_masks=False,
    )
    assert zero["conditional_failure_upper"] < F(1, 1 << 64)
    # This compares the stated conditional bounds, not actual A44 probabilities.
    for name, report in [
        ("zero-phase-binomial-bound.json", zero),
        ("bounded-independent-phase.json", bounded),
        ("bounded-dependent-phase-union.json", robust),
    ]:
        write_json(artifacts / name, report)
    tiny = tiny_exact_mixture(2, 4)
    counterexamples = dict(
        exact_tiny_independent_model=tiny,
        n_over_2_fixed_weight_exact_failure=F(0),
        incorrectly_dropped_H2_mass=F(1, 4),
        correlated_fair_secret_bits_failure=F(1, 8),
        phase_selection=dict(
            n=2,
            quantum=4,
            law="e=4 for H<=1; e=0 for H=2; phase is independent of masks conditional on the secret, but dependent on weight",
            marginal_bad_phase_probability=F(3, 4),
            base_mask_failure=F(1, 16),
            true_joint_failure=F(13, 16),
            invalid_factored_result=F(49, 64),
            generic_union=F(13, 16),
        ),
        all_examples_are_ideal_finite_models=True,
    )
    write_json(
        artifacts / "mean-weight-heavy-tail-phase-counterexamples.json", counterexamples
    )
    final = dict(
        status="STATIC_CERTIFIED_BINOMIAL_MIXTURE_PASS",
        source_pins=6,
        tests_run=result.testsRun,
        test_output=log.getvalue(),
        native_zero_phase_strata=len(zero["bins"]),
        all_weights_included=True,
        binomial_total_probability=F(1),
        zero_phase_upper=zero["conditional_failure_upper"],
        worst_fixed_h859_upper=zero["worst_fixed_weight_mask_upper"],
        fixed_h430_reference_upper=endpoint(u, 430, (-63, 63), 0, (0, 0))[
            "conditional_failure_upper"
        ],
        heavy_bin_probability=zero["bins"][-1]["binomial_probability"],
        heavy_bin_upper_contribution=zero["bins"][-1]["weighted_upper_contribution"],
        phase_bound4U_delta2m80_independent_upper=bounded["conditional_failure_upper"],
        phase_bound4U_delta2m80_generic_union=robust["conditional_failure_upper"],
        actual_a44_p_fail=None,
        reused_key_uniform_conditional_bound=False,
        runtime_or_fhe_or_process_or_network_execution=False,
        artifacts_sha256={
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(artifacts.iterdir())
        },
    )
    write_json(HERE / "STATIC_RESULT.json", final)
    print(
        json.dumps(
            encode(
                {key: value for key, value in final.items() if key != "test_output"}
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
