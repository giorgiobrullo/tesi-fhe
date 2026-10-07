"""Static checks and fresh synthetic evidence; no Rust execution or cryptography."""

import hashlib
import io
import json
import os
from pathlib import Path
import unittest

from coefficients import realize_synthetic_event, verify_event
from replay import a142, analyze_records, write_private_json
from synthetic_cases import FAKE_BINARY_HASH, a142_synthetic, stream
from test_a143 import membership_counterexample, standalone_event

HERE = Path(__file__).resolve().parent


def main():
    target = HERE / "synthetic-evidence"
    if target.exists() or (HERE / "STATIC_RESULT.json").exists():
        raise SystemExit(
            "Preserve existing evidence; run test_a143.py for a read-only check"
        )
    output = io.StringIO()
    result = unittest.TextTestRunner(stream=output, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromName("test_a143")
    )
    if not result.wasSuccessful():
        print(output.getvalue())
        raise SystemExit(1)
    target.mkdir(mode=0o700)
    records = stream()
    with os.fdopen(
        os.open(target / "smoke.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
        "w",
    ) as file:
        for record in records:
            file.write(json.dumps(record, separators=(",", ":")) + "\n")
    report = analyze_records(records, FAKE_BINARY_HASH)
    write_private_json(target / "smoke-replay.json", report)
    ms = standalone_event()
    write_private_json(
        target / "zero-phase-ms64.json", dict(event=ms, replay=verify_event(ms))
    )
    membership = membership_counterexample()
    write_private_json(
        target / "coherent-impossible-binary-aggregate.json",
        dict(
            event=membership,
            replay=verify_event(membership),
            possible_binary_mask_aggregate_words=[
                "0000000000000000",
                "0010000000000002",
            ],
            claimed_mask_aggregate_word="0000000000000001",
            note="Arithmetic closure does not attest binary-key membership or runtime execution.",
        ),
    )
    case, events, _ = a142_synthetic.make_case(
        [1, 0, 2, 3], perturbations={"middle_round.mask/1": dict(ms=64)}
    )
    events = [realize_synthetic_event(event) for event in events]
    consumer = a142.analyze_case(case, events)
    write_private_json(
        target / "consumer-ms64.json",
        dict(
            case=case,
            events=events,
            coefficient_checks=[verify_event(event) for event in events],
            replay=consumer,
            synthetic=True,
        ),
    )
    files = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(target.iterdir())
    }
    summary = dict(
        status="STATIC_AND_SYNTHETIC_CHECKS_PASS",
        tests_run=result.testsRun,
        test_output=output.getvalue(),
        smoke_source_fixture_indices=[2, 4],
        smoke_coefficient_events=report["coefficient_events"],
        synthetic_joint_witness_pass=report["joint_witness_pass"],
        full_schedule_executed=False,
        full_schedule_complete=report["full_schedule_complete"],
        original_first_two_fixture_indices_rejected_as_negative_insensitive=True,
        ms64_consumer_region_pass=consumer["conditional_joint_safe_region_pass"],
        ms64_final_flags_pass=consumer["composed_a34_a135_pass"],
        coherent_impossible_binary_aggregate_passes_conditional_arithmetic=True,
        synthetic_ciphertexts_encrypted=False,
        rust_typecheck_or_execution=False,
        fhe_execution=False,
        extra_crypto_calls=False,
        formal_failure_bound=False,
        service_validation=False,
        synthetic_evidence_sha256=files,
    )
    write_private_json(HERE / "STATIC_RESULT.json", summary)
    print(
        json.dumps({k: v for k, v in summary.items() if k != "test_output"}, indent=2)
    )


if __name__ == "__main__":
    main()
