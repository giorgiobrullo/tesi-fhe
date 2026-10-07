"""Freeze A186 source/clear evidence and known actual prerequisite, no FHE."""

import hashlib
import json
from pathlib import Path
import re
import model as m

HERE = m.HERE
ROOT = HERE.parents[1]
TFHE = Path(
    "/opt/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-0.11.3/src"
)


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def write(name, value):
    (HERE / name).write_text(json.dumps(value, indent=2) + "\n")


def main():
    assert not (HERE / "MANIFEST.json").exists(), "already frozen"
    a171 = HERE.parent / "a171-pfks-d1-runtime-gate"
    a174 = HERE.parent / "a174-a171-three-process-readiness"
    source = (a171 / "candidate/src/main.rs").read_text()
    pattern = (
        r'Fixture\s*\{\s*name: "([^"]+)".*?left: \[([^\]]+)\],\s*right: \[([^\]]+)\],'
    )
    actual = []
    for name, left, right in re.findall(pattern, source, re.S):
        actual.append(
            (name, tuple(map(int, left.split(","))), tuple(map(int, right.split(","))))
        )
    assert tuple(actual) == m.FIXTURES, "exact original eight fixture tuples/order"
    aggregate = a174 / "artifacts/three-process-validation.json"
    assert (
        sha(aggregate)
        == "736b43188a111b846385b72e34952d4f248334f0ea5e22e9e5b9261ca65033e9"
    )
    prior = json.loads(aggregate.read_text())
    assert prior["component_gate_pass"] and prior["records"] == 966
    inputs = [
        aggregate,
        a174 / "MANIFEST.json",
        a174 / "verify.py",
        a171 / "ARTIFACT_MANIFEST.json",
        a171 / "SOURCE_SHA256SUMS",
        a171 / "PREREGISTRATION.json",
        a171 / "candidate/src/main.rs",
        a171 / "candidate/src/d1.rs",
        a171 / "candidate/src/observer.rs",
        a171 / "replay.py",
        a171 / "COUNTEREXAMPLES.json",
        a171 / "candidate/Cargo.lock",
        HERE.parent / "a121-direct-window-pfks/model.py",
        HERE.parent / "a121-direct-window-pfks/SOURCE_PINS.json",
        HERE.parent / "a122-direct-window-pfks-d1/model.py",
        HERE.parent / "a122-direct-window-pfks-d1/SOURCE_PINS.json",
        HERE.parent / "a108-packed-pfks-d2-k4/static_audit.py",
        HERE.parent / "a134-pfks-error-provenance/README.md",
    ]
    inputs += [
        TFHE / p
        for p in (
            "core_crypto/algorithms/lwe_keyswitch.rs",
            "core_crypto/algorithms/lwe_programmable_bootstrapping/fft64.rs",
            "core_crypto/algorithms/glwe_sample_extraction.rs",
            "core_crypto/fft_impl/fft64/crypto/bootstrap.rs",
            "core_crypto/fft_impl/common.rs",
            "core_crypto/algorithms/lwe_private_functional_packing_keyswitch.rs",
        )
    ]
    write(
        "SOURCE_PINS.json",
        dict(
            schema="a186-source-pins-v1",
            files={str(p): sha(p) for p in sorted(inputs)},
            prior_actual_aggregate_read_only=True,
            private_raw_logs_read=False,
        ),
    )
    witness = {}
    for name, phase, kind, wanted in [
        ("ternary_tie", 0, "ternary", 0),
        ("final_tie", -m.DELTA // 2, "control", -4),
        ("selector_right", 12 * m.DELTA, None, None),
    ]:
        row = m.ms_counterexample(phase)
        if kind:
            row.update(
                wanted_lut_coefficient=wanted,
                actual_lut_coefficient=m.raw_coefficient(kind, row["actual_degree"]),
            )
        witness[name] = row
    witness["sentinel_wrong_order"] = dict(
        left=m.bridge_design(1024, 127),
        right=[4, 0, 0, 0],
        actual=m.compare(m.bridge_design(1024, 127), (4, 0, 0, 0)),
        expected_service_id=0,
        actual_service_id=127,
    )
    write(
        "COUNTEREXAMPLES.json",
        dict(
            schema="a186-exact-synthetic-witnesses-v1",
            witnesses=witness,
            actual_crypto_reachability=False,
            actual_p_fail=None,
        ),
    )
    write(
        "REGIONS.json",
        dict(
            schema="a186-exact-lut-regions-v1",
            U=m.U,
            Q=m.Q,
            M=m.M,
            regions={
                kind: {
                    str(c): dict(
                        degree_islands=m.degree_islands(kind, c),
                        inclusive_native_phase_islands=m.phase_islands(kind, c),
                    )
                    for c in values
                }
                for kind, values in [("ternary", (-1, 0, 1)), ("control", (-4, 4))]
            },
            condition="actual coefficientwise used address, not phase-only address",
            actual_probability=None,
        ),
    )
    first = m.FIXTURES[7]
    write(
        "NEXT_GATE.json",
        dict(
            schema="a186-next-comparator-boundary-design-v1",
            status="CLEAR_AND_SOURCE_DESIGN_ONLY",
            actual_executable_materialized=False,
            first_fixture_index=7,
            first_fixture_name=first[0],
            left=first[1],
            right=first[2],
            clear=m.compare(first[1], first[2]),
            first_process_keys=1,
            first_process_cases=1,
            arms=["direct_window", "scalar_d2", "direct_d1"],
            shared_comparator_stages=[
                "ternary/top",
                "ternary/middle",
                "ternary/low",
                "final/control",
            ],
            first_ledger=m.ledger(),
            all_original_four_alternative=m.ledger("all_original_four"),
            supplied_control_extra_alternative=m.ledger(
                "minimal_three_plus_supplied_control"
            ),
            raw_schema_and_cardinality_not_yet_materialized=True,
            clear_negative_controls=[
                "wrong_limb_priority",
                "omitted_half_delta_tie_offset",
                "phase_only_MS_substitution",
                "sentinel_wrong_side",
            ],
            extra_actual_negative_arm_implemented=False,
            private_source_envelope_required=True,
            next_full8_requires_separate_bound_first_pass=True,
            full8_order=list(range(8)),
            full8_ledger={k: v * 8 for k, v in m.ledger()["total"].items()},
            first_fixture_proves_tie_or_threshold=False,
            full8_clear_fixtures_include_tie_threshold=True,
            actual_upstream_limb_bridge=False,
            automatic_retry=False,
            automatic_expansion=False,
            actual_p_fail=None,
            timing_claim=False,
        ),
    )
    write(
        "RESULT.json",
        dict(
            status="PASS_BOUNDED_CLEAR_COMPARATOR_D1_DESIGN",
            tests=9,
            elapsed_seconds=0.141,
            reachable_difference_combinations=8649,
            ternary_patterns=27,
            integer_lattice_preimage_endpoint_checks=40960,
            original_fixtures=8,
            conditional_selector_degrees_per_fixture=127,
            matched_d1_d2_tuple_lanes_checked=8 * 127 * 4 * 2,
            source_fixture_binding=True,
            actual_prior_supplied_selector=prior["status"],
            new_comparator_executed=False,
            actual_upstream_score_bridge=False,
            full_exact_id=False,
            actual_p_fail=None,
        ),
    )
    names = [
        "model.py",
        "test_model.py",
        "freeze.py",
        "README.md",
        "INTERFACE.md",
        "NOISE_IDENTITY.md",
        "SOURCE_PINS.json",
        "REGIONS.json",
        "COUNTEREXAMPLES.json",
        "NEXT_GATE.json",
        "RESULT.json",
        "STATIC_TESTS.log",
        "LINT.log",
        "PEER_REVIEW.json",
    ]
    write(
        "MANIFEST.json",
        dict(
            schema="a186-source-clear-freeze-v1",
            files={n: sha(HERE / n) for n in names},
            excluded=["MANIFEST.json", "__pycache__/", ".ruff_cache/"],
            actual_fhe=False,
        ),
    )
    print(
        json.dumps(
            dict(
                manifest_sha256=sha(HERE / "MANIFEST.json"),
                leaves=len(names),
                pins=len(inputs),
                model_sha256=sha(HERE / "model.py"),
                actual_fhe=False,
            )
        )
    )


if __name__ == "__main__":
    main()
