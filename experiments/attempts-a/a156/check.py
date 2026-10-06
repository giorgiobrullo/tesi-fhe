"""Preserve source-pinned synthetic certificates and counterexamples; never FHE."""

from fractions import Fraction as F
import hashlib
import io
import json
from pathlib import Path
import unittest

from gate import encode, write_new
from model import Q, bound, native_context, synthetic_native_record, verify_sources
from test_model import tiny_native_law

HERE = Path(__file__).resolve().parent


def main():
    artifacts = HERE / "artifacts"
    assert not artifacts.exists(), (
        "Preserve evidence; rerun test_model.py for verification"
    )
    pins = verify_sources()
    log = io.StringIO()
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromName("test_model")
    )
    if not result.wasSuccessful():
        print(log.getvalue())
        raise SystemExit(1)
    artifacts.mkdir(mode=0o700)
    scenarios = []
    for name, g, negative in [
        ("g1", 1, False),
        ("g2", 2, False),
        ("g4", 4, False),
        ("zero_digits", Q, False),
        ("g1_negative_remainder", 1, True),
    ]:
        record = synthetic_native_record(g, negative)
        context = native_context(record)
        report = bound(context)
        write_new(artifacts / f"{name}.input.json", record)
        write_new(artifacts / f"{name}.bound.json", report)
        scenarios.append(
            dict(
                name=name,
                g=g,
                input_kind="synthetic",
                conditional_failure_upper=report["conditional_failure_upper"],
                power2_upper_exponent=report["combined_power2_upper_exponent"],
                joint_mean_words=context.remainder_mean + context.residue_mean,
                actual_a44_p_fail=None,
            )
        )
    exact = []
    for word in (5, 9, 17, 1):
        context, law, addresses = tiny_native_law(word)
        exact.append(
            dict(
                word=word,
                context=context.summary(),
                observations=8192,
                exact_y_law=law,
                exact_modular_failure=1 - F(addresses[0], 8192),
            )
        )
    residues = list(range(-4, 4))
    coupled = sum(F(2) ** ((1 + s) * r) for r in residues for s in (0, 1)) / 16
    independent = (
        sum(F(2) ** (r + s * t) for r in residues for t in residues for s in (0, 1))
        / 128
    )
    write_new(
        artifacts / "tiny-joint-laws-and-counterexamples.json",
        dict(
            native_tiny_laws=exact,
            row_error_coupling=dict(
                model="E_KS=T with T uniform[-4,3], small secret independent Bernoulli(1/2)",
                exact_mgf_base2_coupled=coupled,
                unsupported_independent_product=independent,
                demonstrates_missing_joint_premise=True,
            ),
            zero_digits_counterexample=dict(
                q=64,
                quantum=4,
                input_word=5,
                remainder=5,
                digits=[0],
                small_dimension=2,
                residue_mean=0,
                exact_failure=F(1, 2),
            ),
            development_correction="One initial test expected negative remainder mean -16U; corrected to -64U=1024*(-2^48). Model arithmetic was unchanged.",
            encrypted_observations=False,
        ),
    )
    final = dict(
        status="STATIC_CONDITIONAL_JOINT_MGF_GATE_PASS",
        source_pins=pins,
        tests_run=result.testsRun,
        test_output=log.getvalue(),
        finite_native_joint_observations=32768,
        native_synthetic_scenarios=scenarios,
        first_correction_safe_lifts=[-1024, 1023],
        public_offset_words=1 << 62,
        reference_degrees=[1024, 3072],
        no_actual_input_data=True,
        actual_a44_p_fail=None,
        actual_sampler_or_pipeline_or_reused_key_validated=False,
        cargo_build_fhe_process_inspection_network=False,
        artifacts_sha256={
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(artifacts.iterdir())
        },
    )
    write_new(HERE / "STATIC_RESULT.json", final)
    print(
        json.dumps(
            encode(
                {
                    k: v
                    for k, v in final.items()
                    if k not in ("test_output", "artifacts_sha256")
                }
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
