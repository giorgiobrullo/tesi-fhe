"""Read-only A155 record replay; no candidate imports, subprocesses or crypto."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

from common import (
    Q,
    A44_DELTA,
    CM_DELTA,
    HERE,
    A155,
    Invalid,
    need,
    same,
    integer,
    word,
    signed,
    decode,
    fields,
    digest,
    sha,
    read_json,
    parse,
    write_private,
)
from legacy import check_legacy

OFFSETS = (-(1 << 59), 1 << 59)
PROBE_COUNTS = dict(body_additions=1, ordinary_pbs=1, ordinary_ks=0)
ALL_COUNTS = dict(body_additions=16, ordinary_pbs=16, ordinary_ks=0)
BINARY_REL = "target-a155-only/release/a155-common-mask-egress-margin-control"
COVERAGE = "at least one of eight fixed wrong-lane probes crosses an exact LUT value and decrypts that value; all baseline probes pass and all16 outputs match their consumed LUT values"


def identity_lut(degree):
    """Independently construct cached four-box, half-negated, rotated raw body."""
    coeff = [i // 512 for i in range(2048)]
    coeff[:256] = [-value for value in coeff[:256]]
    coeff = coeff[256:] + coeff[:256]
    degree %= 4096
    raw = coeff[degree] if degree < 2048 else -coeff[degree - 2048]
    return raw % 32


def check_margin(rows, egress):
    probes = [r for r in rows if r.get("type") == "egress_margin_probe"]
    summaries = [r for r in rows if r.get("type") == "egress_margin_summary"]
    need(
        len(probes) == 16 and len(summaries) == 1,
        "all sixteen margin probes and one summary required",
    )
    same(
        rows[-18:-1],
        probes + summaries,
        "margin schedule must follow original pair and precede final summary",
    )
    baseline_output = baseline_support = binding = all_lut = True
    mismatches, discriminators, crossings = [0, 0], [0, 0], [0, 0]
    schedule = [
        (arm, offset, i)
        for arm in ("baseline", "wrong_lane")
        for offset in OFFSETS
        for i in range(4)
    ]
    for row, (arm, offset, index) in zip(probes, schedule):
        case = "n4_plain" if arm == "baseline" else "n4_negative_WrongLaneKsk"
        original = egress[case, index]
        expected = int(index == 0)
        phase = word(row.get("original_phase_u64"))
        shifted_phase = word(row.get("shifted_phase_u64"))
        output_phase = word(row.get("output_phase_u64"))
        original_degree = integer(
            row.get("original_coefficientwise_degree"), 0, 4095, "original degree"
        )
        shifted_degree = integer(
            row.get("shifted_coefficientwise_degree"), 0, 4095, "shifted degree"
        )
        degree_offset = -128 if offset < 0 else 128
        fields(
            row,
            dict(
                arm=arm,
                offset_i64=str(offset),
                index=index,
                source_case=case,
                source_stage=f"egress_small/{index}",
                expected=expected,
                input_delta_u64=str(CM_DELTA),
                output_delta_u64=str(A44_DELTA),
                original_phase_u64=original["phase_u64"],
                original_coefficientwise_degree=original["br_geometry"][
                    "coefficientwise_degree"
                ],
                degree_offset=degree_offset,
                counts=PROBE_COUNTS,
                client_local_key_sensitive=True,
                clear_address_prediction_is_fhe_result=False,
            ),
            "margin probe binding",
        )
        phase_closure = shifted_phase == (phase + offset) % Q
        address_closure = shifted_degree == (original_degree + degree_offset) % 4096
        fields(
            row,
            dict(
                phase_closure=phase_closure,
                address_closure=address_closure,
                mask_unchanged=True,
            ),
            "margin closures",
        )
        binding &= phase_closure and address_closure
        lut = identity_lut(shifted_degree)
        output = decode(output_phase, A44_DELTA)
        error = signed(output_phase - expected * A44_DELTA)
        matches = output == expected and abs(error) < A44_DELTA // 2
        lut_matches = (
            output == lut
            and abs(signed(output_phase - lut * A44_DELTA)) < A44_DELTA // 2
        )
        input_matches = lut == expected
        fields(
            row,
            dict(
                output_signed_error_i64=str(error),
                output_decoded=output,
                input_lut_value=lut,
                input_expected_cell=input_matches,
                output_matches_expected=matches,
                output_matches_lut=lut_matches,
            ),
            "margin LUT/output arithmetic",
        )
        all_lut &= lut_matches
        if arm == "baseline":
            baseline_output &= matches
            baseline_support &= input_matches
        else:
            slot = int(offset > 0)
            mismatches[slot] += int(not matches)
            crossings[slot] += int(not input_matches)
            discriminators[slot] += int(
                not input_matches and not matches and lut_matches
            )
    coverage = sum(discriminators) > 0
    passed = baseline_output and baseline_support and binding and all_lut and coverage
    fields(
        summaries[0],
        dict(
            probe_count=16,
            baseline_probe_count=8,
            wrong_lane_probe_count=8,
            offsets_i64=[str(x) for x in OFFSETS],
            baseline_outputs_pass=baseline_output,
            baseline_support_pass=baseline_support,
            binding_pass=binding,
            counts=ALL_COUNTS,
            count_pass=True,
            wrong_output_mismatches_by_offset=mismatches,
            wrong_discriminators_by_offset=discriminators,
            all_outputs_match_lut=all_lut,
            finite_wrong_output_coverage=coverage,
            coverage_rule=COVERAGE,
            passed=passed,
            original_a150_control_reinterpreted=False,
            no_retry_until_pass=True,
            scope="one deterministic N4 bit7 witness, one fresh key; no universal detection or probability claim",
        ),
        "margin summary",
    )
    return dict(
        passed=passed,
        probe_count=16,
        wrong_output_mismatches_by_offset=mismatches,
        wrong_lut_crossings_by_offset=crossings,
        wrong_discriminators_by_offset=discriminators,
    )


def inspect(rows, metadata, *, suite, key_id, source_sha, manifest_sha, binary_sha):
    need(suite in ("stock", "witness"), "requested suite")
    need(type(key_id) is str and bool(key_id), "key label required")
    for value in (source_sha, manifest_sha, binary_sha):
        digest(value)
    need(
        type(rows) is list and all(type(row) is dict for row in rows),
        "record objects required",
    )
    need(bool(rows), "empty runtime log")
    prepared, started, exited = (
        metadata[name] for name in ("prepared", "started", "exit")
    )
    command = [
        str(A155 / BINARY_REL),
        "--run-authorized",
        "--suite",
        suite,
        "--key-id",
        key_id,
    ]
    fields(
        prepared,
        dict(
            status="PREPARED",
            command=command,
            suite=suite,
            key_id=key_id,
            source_sha256=source_sha,
            binary_sha256=binary_sha,
            manifest_sha256=manifest_sha,
            workload_reservation=False,
            root_clearance_required=True,
            client_local_key_sensitive=True,
        ),
        "prepared envelope",
    )
    pid = integer(started.get("child_pid"), 1, 2**31 - 1, "child PID")
    fields(started, dict(status="STARTED", child_pid=pid), "started envelope")
    fields(
        exited,
        dict(status="EXITED", child_pid=pid, correctness_independently_validated=False),
        "exit envelope",
    )
    times = [datetime.fromisoformat(row["utc"]) for row in (prepared, started, exited)]
    need(
        all(t.utcoffset() is not None for t in times) and times == sorted(times),
        "timestamp order",
    )
    fields(
        rows[0],
        dict(
            type="meta",
            experiment="A155",
            suite=suite,
            key_id=key_id,
            pid=pid,
            source_sha256=source_sha,
            runner_verified_binary_sha256=binary_sha,
            tfhe="1.7.0",
            fresh_keys=1,
            independent_lane_secrets=True,
            lanes=4,
            ordinary_profile="V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
            cm_profile="CM_PARAM_4_2_MINUS_64",
            timing_claim=False,
            catalog_certification=False,
            client_local_key_sensitive=True,
        ),
        "meta binding",
    )
    legacy = check_legacy(rows, suite)
    same(rows[1].get("key_id"), key_id, "key-ready label")
    if suite == "witness":
        margin = check_margin(rows, legacy["egress"])
        non_wrong = all(legacy["original_detections"][:2])
        new_gate = legacy["positive_pair"] and non_wrong and margin["passed"]
    else:
        need(
            not any(r.get("type", "").startswith("egress_margin_") for r in rows),
            "stock must not claim margin probes",
        )
        margin, non_wrong, new_gate = None, None, None
    fields(
        legacy["final"],
        dict(
            bounded_diagnostic_gate_scope="original A150 criterion retained without reinterpretation",
            original_a150_bounded_diagnostic_gate_pass=legacy["original_pass"],
            original_a150_graph_negatives_pass=all(legacy["original_detections"])
            if suite == "witness"
            else None,
            original_non_wrong_graph_negatives_pass=non_wrong,
            egress_margin_controls_pass=margin["passed"] if margin else None,
            a155_margin_control_gate_pass=new_gate,
            exit_status_criterion="A155 finite margin gate for witness; original stock gate for stock-only",
            historical_a150_witness_key2_gate="FAILED and frozen; no retrospective change",
        ),
        "separate final gate",
    )
    active_gate = legacy["original_pass"] if suite == "stock" else new_gate
    same(
        exited.get("returncode"),
        0 if active_gate else 2,
        "exit must match selected gate",
    )
    return dict(
        status="PASS_RECORD_CONSISTENCY",
        suite=suite,
        key_id=key_id,
        records=len(rows),
        cm_events=legacy["cm_events"],
        margin=margin,
        a155_margin_control_gate_pass=new_gate,
        original_a150_criterion_on_this_new_run=legacy["original_pass"],
        original_wrong_lane_detected=legacy["original_detections"][-1]
        if suite == "witness"
        else None,
        historical_a150_witness_key2_gate="FAILED and frozen",
        selected_runtime_gate_pass=active_gate,
        original_returncode=exited["returncode"],
        source_sha256=source_sha,
        binary_sha256=binary_sha,
        execution_attestation=False,
        secret_membership_attestation=False,
        raw_ciphertext_mask_or_phase_attestation=False,
        formal_failure_bound=False,
        no_probability_from_dependent_lanes=True,
    )


def verify_frozen():
    pins = read_json(HERE / "PINS.json")
    same(
        sha(A155 / "SOURCE_MANIFEST.json"),
        pins["source_sha256"],
        "source manifest changed",
    )
    same(
        sha(A155 / "MANIFEST.json"),
        pins["manifest_sha256"],
        "artifact manifest changed",
    )
    same(
        (A155 / "SOURCE_DIGEST.txt").read_text().strip(),
        pins["source_sha256"],
        "source marker changed",
    )
    for name in ("SOURCE_MANIFEST.json", "MANIFEST.json"):
        for relative, expected in read_json(A155 / name)["files"].items():
            path = A155 / relative
            need(
                path.resolve().is_relative_to(A155) and not path.is_symlink(),
                "unsafe frozen path",
            )
            same(sha(path), digest(expected), "frozen input changed")
    return pins


def validate_run(run, *, suite, key_id, binary_sha):
    pins = verify_frozen()
    binary = A155 / BINARY_REL
    same(sha(binary), digest(binary_sha), "actual binary differs from supplied digest")
    need(run.is_dir() and not run.is_symlink(), "run directory required")
    run = run.resolve()
    need(run.parent == A155 / "runs", "only this frozen A155 candidate accepted")
    need(not (run / "interrupted.json").exists(), "interrupted run unresolved")
    paths = {name: run / (name + ".json") for name in ("prepared", "started", "exit")}
    paths.update(stdout=run / "stdout.jsonl", stderr=run / "stderr.log")
    for path in paths.values():
        need(path.is_file() and not path.is_symlink(), "regular run evidence required")
        need(path.stat().st_size <= 32 * 1024 * 1024, "bounded run file size")
    initial = {name: sha(path) for name, path in paths.items()}
    content = paths["stdout"].read_bytes()
    need(bool(content) and content.endswith(b"\n"), "complete JSONL newline required")
    metadata = {
        name: read_json(paths[name]) for name in ("prepared", "started", "exit")
    }
    result = inspect(
        [parse(line) for line in content.decode().splitlines()],
        metadata,
        suite=suite,
        key_id=key_id,
        source_sha=pins["source_sha256"],
        manifest_sha=pins["manifest_sha256"],
        binary_sha=binary_sha,
    )
    same(
        initial,
        {name: sha(path) for name, path in paths.items()},
        "records changed during replay",
    )
    same(initial["stdout"], hashlib.sha256(content).hexdigest(), "stdout read hash")
    same(sha(binary), binary_sha, "binary changed during replay")
    same(verify_frozen(), pins, "frozen inputs changed during replay")
    result.update(run_directory=str(run), input_sha256=initial)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--suite", choices=("stock", "witness"), required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = validate_run(
            args.run_dir,
            suite=args.suite,
            key_id=args.key_id,
            binary_sha=args.binary_sha256,
        )
        code = 0 if result["selected_runtime_gate_pass"] else 2
    except (Invalid, KeyError, TypeError, ValueError, OSError) as error:
        result = dict(
            status="REJECTED_RECORDS",
            reason=str(error) if isinstance(error, Invalid) else type(error).__name__,
            execution_attestation=False,
            formal_failure_bound=False,
        )
        code = 2
    result["validated_at_utc"] = datetime.now(timezone.utc).isoformat()
    result["validator_sha256"] = sha(Path(__file__))
    write_private(args.output, result)
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    "status",
                    "reason",
                    "suite",
                    "records",
                    "a155_margin_control_gate_pass",
                    "original_a150_criterion_on_this_new_run",
                )
                if key in result
            }
        )
    )
    return code


if __name__ == "__main__":
    sys.exit(main())
