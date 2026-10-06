"""Source/artifact freeze only; execute after reviews/tests, never launch a native gate."""

from pathlib import Path
import hashlib
import json

import audit
import replay
import synthetic

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OLD = audit.OLD
TFHE = Path(
    "/opt/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-0.11.3/src"
)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(name, value):
    (HERE / name).write_text(json.dumps(value, indent=2) + "\n")


def main():
    audit.need(
        not (HERE / "ARTIFACT_MANIFEST.json").exists(),
        "A175 is already frozen; use a separate successor",
    )
    proof = audit.verify_source()
    inputs = [
        OLD / "SOURCE_MANIFEST.json",
        OLD / "ARTIFACT_MANIFEST.json",
        OLD / "runtime-validation/MANIFEST.json",
    ]
    for base, manifest in [
        (OLD, "ARTIFACT_MANIFEST.json"),
        (OLD / "runtime-validation", "MANIFEST.json"),
    ]:
        for name, expected in json.loads((base / manifest).read_text())[
            "files"
        ].items():
            audit.need(sha(base / name) == expected, "frozen source mismatch " + name)
            inputs.append(base / name)
    for name in (
        "derive.py",
        "README.md",
        "RESULT.json",
        "SOURCE_PINS.json",
        "MANIFEST.json",
    ):
        inputs.append(HERE.parent / "a173-bit2-consumer-region-audit" / name)
    inputs += [
        ROOT / "docs/research-state/2026-09-05/a130-smoke-root-review.json",
        ROOT / "docs/research-state/2026-09-05/a169-smoke-key1-review.json",
    ]
    history = json.loads((OLD / "ORIGIN.json").read_text())
    for name, expected in history["preserved_evidence_sha256"].items():
        path = Path(history["parent"]) / name
        audit.need(sha(path) == expected, "preserved A165 negative " + name)
        inputs.append(path)
    for name in [
        "core_crypto/algorithms/lwe_programmable_bootstrapping/fft64.rs",
        "core_crypto/fft_impl/fft64/crypto/bootstrap.rs",
        "core_crypto/fft_impl/fft64/crypto/ggsw.rs",
        "core_crypto/fft_impl/fft64/math/fft/mod.rs",
        "core_crypto/fft_impl/common.rs",
        "core_crypto/algorithms/lwe_keyswitch.rs",
        "core_crypto/algorithms/lwe_encryption.rs",
        "core_crypto/algorithms/glwe_encryption.rs",
        "core_crypto/algorithms/polynomial_algorithms.rs",
        "core_crypto/commons/math/decomposition/decomposer.rs",
        "core_crypto/entities/lwe_keyswitch_key.rs",
        "core_crypto/entities/lwe_secret_key.rs",
        "shortint/parameters/classic/gaussian/p_fail_2_minus_64/ks_pbs.rs",
    ]:
        inputs.append(TFHE / name)
    write(
        "SOURCE_PINS.json",
        dict(
            schema="a175-frozen-input-pins-v1",
            files={str(p): sha(p) for p in sorted(set(inputs))},
            actual_old_logs_hashed_only=True,
            new_runtime_evidence_inspected=False,
        ),
    )
    write("SOURCE_PRESERVATION.json", proof)
    plan = replay.plan_record()
    write(
        "PREREGISTRATION.json",
        dict(
            schema="a175-preregistration-v1",
            raw_plan=plan,
            fixture_order=dict(
                scenes=list(replay.m.SCENES),
                scores=list(replay.m.SCORES),
                bits=list(range(8)),
                candidates_by_bit=[list(replay.m.candidates(b)) for b in range(8)],
                paired_arms=list(replay.m.ARMS),
            ),
            sample_ledger=dict(
                producer_arm_pbs_samples=[15, 15, 12, 13, 14, 12],
                frozen_split_control_pbs_samples=[10, 10],
                score_extraction_samples=2,
                new_samples_per_consumer=2,
                total_samples_per_score=215,
            ),
            first_key_outcomes_all_retained=True,
            no_retry_or_automatic_expansion=True,
            candidate_is_previous_selector_output=False,
            launch_envelope_required_before_run=True,
            actual_p_fail=None,
            performance_claim=False,
        ),
    )
    args = synthetic.make(ms_boundary=True)
    row, identity, producer, big, small = args
    write(
        "COUNTEREXAMPLE.json",
        dict(
            schema="a175-phase-only-counterexample-v1",
            status="DETERMINISTIC_SYNTHETIC_NOT_RUNTIME",
            row=row,
            identity=identity,
            producer=list(producer),
            big_dimension=big,
            small_dimension=small,
            computed_gates=synthetic.check(args),
            phase_only_address=128,
            actual_address=192,
            actual_ks_reachability_demonstrated=False,
            tail_probability_claim=False,
            explanation="128 active masks U/2-1 preserve the chosen native phase but move the consumed target-one address from128 to192.",
        ),
    )
    target = (
        HERE
        / "candidate/target-a175-actual-consumer-only/release/a125_low_extraction_gate"
    )
    write(
        "EXECUTION_PLAN.json",
        dict(
            schema="a175-source-execution-plan-v1",
            cwd=str(HERE / "candidate"),
            check_argv=[
                "cargo",
                "check",
                "--locked",
                "--offline",
                "--bin",
                "a125_low_extraction_gate",
            ],
            build_argv=[
                "cargo",
                "build",
                "--release",
                "--locked",
                "--offline",
                "--bin",
                "a125_low_extraction_gate",
            ],
            binary=str(target),
            actual_argv=[
                str(target),
                "--run",
                "--stage=smoke",
                "--keysets=1",
                "--expected-binary-sha256=<independently measured>",
            ],
            required_environment=dict(
                RAYON_NUM_THREADS="1",
                A175_RUN_ACK="A175_ACTUAL_CONSUMER_AUTHORIZED",
                A175_SOURCE_SHA256="<SHA256 of SOURCE_MANIFEST.json>",
            ),
            child_exit_pass=0,
            child_exit_completed_negative=1,
            raw_records_on_both_complete_outcomes=17703,
            private_directory_mode="0700",
            private_file_mode="0600",
            actual_execution_performed=False,
            source_parser_only=True,
            root_scheduling_and_private_launch_envelope_required=True,
            raw_validator_argv=[
                "python3",
                str(HERE / "replay.py"),
                "--raw",
                "<private stdout.jsonl>",
                "--raw-sha256",
                "<envelope log hash>",
                "--binary-sha256",
                "<actual binary hash>",
                "--child-pid",
                "<actual PID>",
                "--exit-code",
                "<actual completed exit>",
                "--output",
                "<new private report>",
            ],
            raw_validator_does_not_attest_envelope=True,
        ),
    )
    names = [
        "README.md",
        "materialize.py",
        "freeze.py",
        "audit.py",
        "model.py",
        "replay.py",
        "synthetic.py",
        "test_gate.py",
        "test_structure.py",
        "DIAGNOSTIC.patch",
        "PREREGISTRATION.json",
        "SOURCE_PINS.json",
        "SOURCE_PRESERVATION.json",
        "COUNTEREXAMPLE.json",
        "EXECUTION_PLAN.json",
        "PEER_REVIEW.json",
        "CHECK_HISTORY.md",
        "candidate/Cargo.toml",
        "candidate/Cargo.lock",
        "candidate/.cargo/config.toml",
        "candidate/LICENSE.tfhe-rs-BSD-3-Clause-Clear",
        "candidate/src/main.rs",
        "candidate/src/diagnostic.rs",
        "candidate/src/frozen_extract.rs",
        "candidate/src/actual_consumer.rs",
        "candidate/src/retained_br.rs",
    ]
    write(
        "SOURCE_MANIFEST.json",
        dict(
            schema="a175-source-freeze-v1",
            files={n: sha(HERE / n) for n in sorted(names)},
            preserved_A169_source_id="35ea371d06d7616f079b72190115daa449ba5a50e4a0761c0930bfbe70f40c60",
            candidate_provenance_from_prior_round=False,
            excluded=[
                "candidate/SOURCE_DIGEST.txt",
                "__pycache__/",
                "candidate/target-a175-actual-consumer-only/",
                "runs/",
                "execution-readiness/",
                "build-artifacts/",
                "artifacts/",
                "ARTIFACT_MANIFEST.json",
                "STATIC_RESULT.json",
                "STATIC_TESTS.log",
                "LINT.log",
            ],
        ),
    )
    source = sha(HERE / "SOURCE_MANIFEST.json")
    (HERE / "candidate/SOURCE_DIGEST.txt").write_text(source + "\n")
    all_names = names + [
        "SOURCE_MANIFEST.json",
        "candidate/SOURCE_DIGEST.txt",
        "STATIC_RESULT.json",
        "STATIC_TESTS.log",
        "LINT.log",
    ]
    write(
        "ARTIFACT_MANIFEST.json",
        dict(
            schema="a175-source-static-artifacts-v1",
            source_id=source,
            files={n: sha(HERE / n) for n in sorted(all_names)},
        ),
    )
    print(
        json.dumps(
            dict(
                source_id=source,
                artifact_manifest_sha256=sha(HERE / "ARTIFACT_MANIFEST.json"),
                source_leaves=len(names),
                artifact_leaves=len(all_names),
                input_pins=len(set(inputs)),
                actual_runtime=False,
            )
        )
    )


if __name__ == "__main__":
    main()
