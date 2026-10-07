"""Independent A165 five-arm replay. No executable/process/cryptographic calls."""

import argparse
import ast
import hashlib
import json
from pathlib import Path

import arithmetic as a
import model as m

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent
SOURCE_ID = "4c513c136a831aeebcd8f3b2e7e2aa96d072322064876e6d3fd5e80e25beaf68"


def verify_sources():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())["files"]
    for path, expected in pins.items():
        a.equal(a.sha(path), expected, "frozen source pin " + path)
    artifact = json.loads((PARENT / "ARTIFACT_MANIFEST.json").read_text())
    for name, expected in artifact["files"].items():
        a.equal(a.sha(PARENT / name), expected, "frozen A165 artifact " + name)
    a.equal(
        a.sha(PARENT / "SOURCE_MANIFEST.json"), SOURCE_ID, "actual A165 source identity"
    )
    a.equal(
        (PARENT / "candidate/SOURCE_DIGEST.txt").read_text().strip(),
        SOURCE_ID,
        "embedded source ID file",
    )
    manifest = json.loads((PARENT / "SOURCE_MANIFEST.json").read_text())
    for name, expected in manifest["files"].items():
        a.equal(a.sha(PARENT / name), expected, "A165 source leaf " + name)
    return manifest["files"]


def verify_arithmetic_reuse():
    record = json.loads((HERE / "ARITHMETIC_REUSE.json").read_text())
    old = Path(record["original_source"]).read_text()
    new = (HERE / "arithmetic.py").read_text()

    def get(source):
        return {
            node.name: ast.get_source_segment(source, node)
            for node in ast.parse(source).body
            if isinstance(node, (ast.FunctionDef, ast.ClassDef))
        }

    before, after = get(old), get(new)
    for name, pin in record["functions"].items():
        a.equal(
            hashlib.sha256(before[name].encode()).hexdigest(),
            pin["original_sha256"],
            "old arithmetic block " + name,
        )
        a.equal(
            hashlib.sha256(after[name].encode()).hexdigest(),
            pin["copied_sha256"],
            "reused arithmetic block " + name,
        )
    return len(record["functions"])


def verify_pair(pair, original, repair):
    a.equal(pair["original_arm"], m.ARMS[2], "original aggressive arm identity")
    a.equal(pair["repair_arm"], m.REPAIR, "repair arm identity")
    old_events = m.events(m.ARMS[2])
    identical = all(
        original["hashes"][event.stage] == repair["hashes"][event.stage]
        and original["phases"][event.stage] == repair["phases"][event.stage]
        for event in old_events
    )
    a.equal(
        pair["old_trace_byte_identical"],
        identical,
        "48 old trace phase/hash identities",
    )
    other_identical = all(
        original["hashes"][m.weighted_stage(m.ARMS[2], bit)]
        == repair["hashes"][m.weighted_stage(m.REPAIR, bit)]
        and original["phases"][m.weighted_stage(m.ARMS[2], bit)]
        == repair["phases"][m.weighted_stage(m.REPAIR, bit)]
        for bit in range(8)
        if bit != 1
    )
    a.equal(
        pair["other_weighted_byte_identical"],
        other_identical,
        "other seven consumed ciphertext identities",
    )
    a.equal(
        pair["retained_small_input_sha256"],
        repair["hashes"]["full.ks_b1"],
        "actual retained small input hash",
    )
    a.equal(
        pair["original_x256_b1_sha256"],
        original["hashes"]["full.correction_x256_b1"],
        "original x256 b1 retained",
    )
    direct_hash = a.hash_value(
        pair["direct_weighted_b1_sha256"], "direct weighted output hash"
    )
    consumed = direct_hash == repair["hashes"]["repair_b1.pbs_correction_b1"]
    a.equal(
        pair["direct_output_consumed"], consumed, "actual direct output hash binding"
    )
    # Weighted phase records are independently decoded from that specific direct
    # phase; a false consumption flag is not evidence for a successful repair.
    a.need(
        consumed, "repaired weighted records cannot bind a different direct ciphertext"
    )
    top = pair["top_byte_identical"]
    a.need(type(top) is bool, "top byte comparison must be Boolean")
    if top:
        old_top = (
            original["phases"]["full.residual_before_b7"]
            - original["phases"]["full.pbs_correction_b7"]
        ) % m.Q
        new_top = (
            repair["phases"]["full.residual_before_b7"]
            - repair["phases"]["full.pbs_correction_b7"]
        ) % m.Q
        a.equal(
            old_top,
            new_top,
            "claimed unchanged top must have equal independently reconstructed phase",
        )
    # A165 emits no top ciphertext hash/words. Its byte comparison is a pinned
    # source assertion; phase equality alone does not prove ciphertext equality.
    a.equal(pair["additional_pbs"], 1, "exact extra PBS")
    a.equal(pair["additional_ks"], 0, "no new KS")
    a.equal(
        pair["full_residual_correction_retained"],
        True,
        "full residual correction retained",
    )
    a.equal(
        (repair["phases"]["repair_b1.pbs_raw_b1"] + (1 << 60)) % m.Q,
        repair["phases"]["repair_b1.pbs_correction_b1"],
        "direct b1 public alpha closure",
    )
    passed = identical and top and other_identical and consumed
    a.equal(pair["pass"], passed, "repair pair conjunction")
    return passed


def replay(rows, expected_binary, source_files):
    for index, row in enumerate(rows):
        a.equal(row.get("schema"), m.SCHEMA, f"A165 explicit schema row{index + 1}")
    reader = a.Reader(rows)
    plan = reader.take("plan")
    fields = dict(
        stage="smoke",
        keysets=1,
        scores_per_scene=14,
        scenes=2,
        arms=list(m.A165_ARMS),
        pbs_per_score=[11, 11, 8, 9, 8],
        ks_per_score=[8] * 5,
        frozen_control_extra_pbs_per_split=7,
        frozen_control_extra_ks_per_split=8,
        diagnostic_only=True,
        latency_claim_allowed=False,
        p_fail_certified=False,
        whole_exact_id_validated=False,
    )
    for key, value in fields.items():
        a.equal(plan.get(key), value, "fixed plan " + key)
    provenance = reader.take("provenance")
    a.equal(provenance["binary_sha256"], expected_binary, "actual compiled binary")
    a.equal(
        provenance["source_manifest_sha256"], SOURCE_ID, "full embedded source binding"
    )
    for field, name in [
        ("source_sha256", "candidate/src/diagnostic.rs"),
        ("frozen_helpers_sha256", "candidate/src/frozen_extract.rs"),
        ("lock_sha256", "candidate/Cargo.lock"),
    ]:
        a.equal(provenance[field], source_files[name], "embedded source field " + field)
    a.equal(
        provenance["parameter_fingerprint"], m.PARAMETER, "unchanged A44 fingerprint"
    )
    key = reader.take("keyset", dict(keyset=0))
    a.equal(
        key["params"],
        "V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
        "parameter name",
    )
    a.equal(key["key_material_persisted"], False, "no persisted key claim")
    a.equal(key["fresh_keyset"], True, "fresh keyset declaration")
    failures, natives, consumers, negatives = [0] * 4, [0] * 4, [0] * 4, [0] * 2
    outside = [0] * 5
    pair_failures = 0
    failed = []
    ciphertext_phases = {}
    for scene in m.SCENES:
        for x in m.targets("smoke"):
            identity = dict(keyset=0, scene=scene, x=x)
            pair = reader.take("repair_pair", identity)
            arms = [
                a.inspect_arm(reader, dict(identity, arm=arm)) for arm in m.A165_ARMS
            ]
            full_hash = arms[0]["hashes"]["score.full"]
            low_hash = arms[0]["hashes"]["score.low"]
            a.need(full_hash != low_hash, "distinct original full and low ciphertexts")
            for index, arm in enumerate(arms):
                a.equal(
                    arm["hashes"]["score.full"], full_hash, "all five share full input"
                )
                a.equal(
                    arm["phases"]["score.full"],
                    arms[0]["phases"]["score.full"],
                    "all five share full phase",
                )
                a.equal(arm["source_low"], low_hash, "original packed-low provenance")
                for event in m.events(m.A165_ARMS[index]):
                    identifier = (event.small, arm["hashes"][event.stage])
                    phase = arm["phases"][event.stage]
                    if identifier in ciphertext_phases:
                        a.equal(
                            ciphertext_phases[identifier],
                            phase,
                            "same hash/key domain must report same phase",
                        )
                    else:
                        ciphertext_phases[identifier] = phase
                outside[index] += arm["outside_half_slot"]
                if index < 4:
                    failures[index] += not arm["passed"]
                    natives[index] += not arm["native"]
                    consumers[index] += not arm["consumer"]
                    if not arm["passed"]:
                        failed.append(
                            dict(
                                identity,
                                arm=m.A165_ARMS[index],
                                native_pass=arm["native"],
                                consumer_scalar_pass=arm["consumer"],
                            )
                        )
                else:
                    negatives[0] += not arm["passed"]
            a.equal(
                arms[1]["phases"]["score.low"],
                arms[0]["phases"]["score.full"] * 256 % m.Q,
                "initial shift phase",
            )
            pair_failures += not verify_pair(pair, arms[2], arms[3])
            row = reader.take("negative_missing_rescale", identity)
            detected = m.decode(arms[2]["phases"]["full.pbs_correction_b0"], 60) != (
                x & 1
            )
            a.equal(row["detected"], detected, "original missing-rescale negative")
            negatives[1] += detected
    summary = reader.take("summary")
    a.need(reader.index == len(rows), "unexpected trailing records")
    ledger = m.a165_ledger()
    a.equal(len(rows), ledger["total_rows"], "fixed 13360-row completion")
    controls = failures[0] == 0 and all(count > 0 for count in negatives)
    repair_gate = controls and pair_failures == 0 and failures[3] == 0
    fields = dict(
        status="A165_DIAGNOSTIC_COMPLETE" if controls else "INVALID_CONTROLS",
        cases=28,
        positive_arm_order=list(m.A165_ARMS[:4]),
        failures_baseline_shift_single_repair=failures,
        native_decode_failures_baseline_shift_single_repair=natives,
        consumer_scalar_phase_failures_baseline_shift_single_repair=consumers,
        both_original_candidates_native_decode_pass=not any(natives[1:3]),
        both_original_candidates_consumer_scalar_phase_pass=not any(consumers[1:3]),
        both_original_candidates_all_checks_pass=not any(failures[1:3]),
        repair_native_decode_pass=natives[3] == 0,
        repair_consumer_scalar_phase_pass=consumers[3] == 0,
        repair_all_checks_pass=failures[3] == 0,
        repair_pair_failures=pair_failures,
        repair_gate_pass=repair_gate,
        negative_detections_drop_rescale=negatives,
        controls_valid=controls,
        p_fail_certified=False,
        whole_exact_id_validated=False,
        latency_claim_allowed=False,
    )
    for name, value in fields.items():
        a.equal(summary.get(name), value, "summary " + name)
    return dict(
        status="PASS_RECORD_CONSISTENCY",
        summary=fields,
        expected_exit_code=0 if repair_gate else 1,
        records=dict(reader.counts),
        ledger=ledger,
        candidate_failed_cases=failed,
        outside_open_half_slot_in_five_arm_order=outside,
        original_aggressive_failure_not_required_on_new_key=True,
        downstream_consumer_is_scalar_ideal_candidate_ks_zero_ms=True,
        actual_composed_consumer_pbs_validated=False,
        full_exact_id_validated=False,
        top_ciphertext_byte_identity_independently_attested=False,
        ciphertext_word_or_secret_membership_attested=False,
        key_freshness_independently_attested=False,
        coefficientwise_ms_or_ks_error_bound_established=False,
        benchmark_or_pfail_claim=False,
    )


def verify_validator_manifest():
    manifest_path = HERE / "MANIFEST.json"
    manifest = a.strict_json(manifest_path.read_text())
    a.equal(
        manifest["schema"],
        "a165-independent-validator-freeze-v1",
        "validator freeze schema",
    )
    for name, expected in manifest["files"].items():
        path = HERE / name
        a.need(
            path.parent == HERE and not path.is_symlink(),
            "validator frozen direct leaf",
        )
        a.equal(a.sha(path), expected, "frozen validator leaf " + name)
    return dict(
        manifest_sha256=a.sha(manifest_path),
        source_files=len(manifest["files"]),
        rules_frozen_before_actual_a165_log_inspection=True,
    )


def validate_complete(binding, rows, sources):
    result = replay(rows, binding["binary_sha256"], sources)
    a.equal(
        binding["exit_code"],
        result["expected_exit_code"],
        "repair gate determines executable exit",
    )
    result["launch_binding"] = binding
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    freeze = verify_validator_manifest()
    sources = verify_sources()
    verify_arithmetic_reuse()
    from envelope import verify_envelope

    binding = verify_envelope(args.run_dir)
    result = validate_complete(
        binding, a.load_rows(Path(binding["run_dir"]) / "stdout.jsonl"), sources
    )
    result["validator_freeze"] = freeze
    a.write_new(args.output, result)
    print(json.dumps({key: result[key] for key in ("status", "summary", "records")}))


if __name__ == "__main__":
    main()
