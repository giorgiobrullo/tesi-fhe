"""Static proof checks and exact synthetic-law artifacts; no Rust or cryptography."""

from fractions import Fraction as F
import hashlib
import io
import json
from pathlib import Path
import unittest

from examples import EXPRESSION, a126_result, correlation_result, wrapping_result
from gate import encode, evaluate_spec, private_json
from model import moments, conditional_bound, rounding_support
from sources import Q, U, DEGREES, a126_safe_residues, intervals, verify_sources

HERE = Path(__file__).resolve().parent


def main():
    assert not (HERE / "artifacts").exists(), (
        "preserve evidence; rerun test_model.py instead"
    )
    pins = verify_sources()
    output = io.StringIO()
    tests = unittest.TextTestRunner(stream=output, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromName("test_model")
    )
    if not tests.wasSuccessful():
        print(output.getvalue())
        raise SystemExit(1)
    artifacts = HERE / "artifacts"
    artifacts.mkdir(mode=0o700)
    results = {
        "same-marginals-coupled-laws.json": [
            correlation_result(p) for p in (F(0), F(1, 4), F(1))
        ],
        "a126-sharp-conditional-bound.json": a126_result(),
        "lift-wrap-counterexample.json": wrapping_result(),
    }
    for name, value in results.items():
        private_json(artifacts / name, value)
    spec = dict(
        scope="conditional abstract model",
        atom_lift_scope="unwrapped lifts under the same conditioning event",
        integer_lattice_premise="Specified L is integer almost surely; caller must establish this for its actual MS identity",
        quantum=1,
        degrees=DEGREES,
        expression={"terms": [["L", 1]], "offset": 0},
        means={"L": "0"},
        covariance=[["L", "L", "16"]],
        condition="an explicitly hypothetical joint law with mean(L)=0 and Var(L)=16",
        justification="Abstract numerical premise only; not a sampled estimate or an actual A44 law",
        safe_residue_intervals=intervals(a126_safe_residues()),
    )
    private_json(artifacts / "hypothetical-premises.json", spec)
    cli_result = evaluate_spec(spec)
    assert cli_result["failure_bound"] == F(1, 256)
    private_json(artifacts / "hypothetical-bound.json", cli_result)
    open_moments = moments(
        EXPRESSION,
        U,
        {},
        {},
        "actual A44 after actual preceding-success history",
        "No justified conditional distribution/moments have been supplied",
    )
    actual = conditional_bound(open_moments, DEGREES, a126_safe_residues())
    result = dict(
        status="STATIC_CONDITIONAL_THEOREM_AND_FINITE_LAWS_PASS",
        tests_run=tests.testsRun,
        test_output=output.getvalue(),
        source_pins=len(pins),
        exact_small_coefficient_checks=1280,
        exact_three_point_laws_checked=45,
        source_safe_residue_intervals=intervals(a126_safe_residues()),
        a126_nearest_bad_distance=64,
        hypothetical_lifted_variance=16,
        hypothetical_sharp_failure_bound="1/256",
        same_coordinate_marginal_failure_probabilities=["0", "1/4", "1"],
        zero_phase_rounding_support_envelope=rounding_support(U, 859, (0, 0)),
        canonical_phase_rounding_support_envelope=rounding_support(
            U, 859, (-Q // 2, Q // 2 - 1)
        ),
        actual_a44=actual,
        actual_a44_p_fail=None,
        rust_or_fhe_execution=False,
        statistical_independence_assumed=False,
        runtime_observation_claimed=False,
        noise_tail_premises_supplied_for_actual_a44=False,
        artifacts_sha256={
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(artifacts.iterdir())
        },
    )
    private_json(HERE / "STATIC_RESULT.json", result)
    print(
        json.dumps(
            encode({k: v for k, v in result.items() if k != "test_output"}), indent=2
        )
    )


if __name__ == "__main__":
    main()
