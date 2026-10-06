"""Synthetic record factory, not encryption or evidence of reachable noisy states."""

import hashlib
import model as m


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def phase_map(arm, x, injection=None, direct_error=0):
    phases = {"score.full": x * 2**52 % m.Q}

    def chain(prefix, first, stop, delta, correction_stop, initial):
        residual, small_bits = initial, []
        for bit in range(first, stop):
            phases[f"{prefix}.residual_before_b{bit}"] = residual
            shifted = residual * 2 ** (63 - delta - bit) % m.Q
            phases[f"{prefix}.shift_b{bit}"] = shifted
            phases[f"{prefix}.ks_b{bit}"] = shifted
            value = m.decode(shifted, 63)
            small_bits.append(value)
            if bit < correction_stop:
                log = delta + bit
                error = (
                    injection[1]
                    if injection and prefix == "full" and bit == injection[0]
                    else 0
                )
                correction = (value * 2**log + error) % m.Q
                phases[f"{prefix}.pbs_raw_b{bit}"] = (correction - 2 ** (log - 1)) % m.Q
                phases[f"{prefix}.pbs_correction_b{bit}"] = correction
                if 3 <= bit <= 6 and log < 60:
                    phases[f"{prefix}.fused_boolean_b{bit}"] = value * 2**59
                if not (arm == m.ARMS[3] and bit == 0):
                    residual = (residual - correction) % m.Q
        return residual, small_bits

    if arm in m.ARMS[:2]:
        phases["score.low"] = x * 2**60 % m.Q
        _, small = chain("low", 0, 4, 60, 3, phases["score.low"])
        high = phases["score.full"]
        for bit in range(4):
            correction = small[bit] * 2 ** (52 + bit)
            phases[f"low_to_full.pbs_correction_b{bit}"] = correction
            phases[f"low_to_full.pbs_raw_b{bit}"] = (correction - 2 ** (51 + bit)) % m.Q
            if bit == 3:
                phases["low_to_full.fused_boolean_b3"] = small[bit] * 2**59
            high = (high - correction) % m.Q
        top, _ = chain("high", 4, 8, 52, 8, high)
    else:
        top, _ = chain("full", 0, 8, 52, 8, phases["score.full"])
        for bit in range(3):
            phases[f"full.correction_x256_b{bit}"] = (
                phases[f"full.pbs_correction_b{bit}"] * 256 % m.Q
            )
    if arm == m.REPAIR:
        value = m.decode(phases["full.ks_b1"], 63)
        direct = (value * 2**61 + direct_error) % m.Q
        phases["repair_b1.pbs_raw_b1"] = (direct - 2**60) % m.Q
        phases["repair_b1.pbs_correction_b1"] = direct
    return phases, top


def arm_records(keyset, scene, x, arm, injection=None, direct_error=0):
    identity = dict(keyset=keyset, scene=scene, x=x, arm=arm)
    phases, top = phase_map(arm, x, injection, direct_error)
    hash_arm = m.ARMS[2] if arm == m.REPAIR else arm
    hashes = {
        name: digest(f"{keyset}/{scene}/{x}/{hash_arm}/{name}/{value}")
        for name, value in phases.items()
    }
    hashes["score.full"] = digest(f"{keyset}/{scene}/{x}/shared-full")
    original_low = digest(f"{keyset}/{scene}/{x}/packed-low")
    if arm in m.ARMS[:2]:
        hashes["score.low"] = (
            original_low
            if arm == m.ARMS[0]
            else digest(f"{keyset}/{scene}/{x}/scaled-full")
        )
        hashes["low.residual_before_b0"] = hashes["score.low"]
    else:
        hashes["full.residual_before_b0"] = hashes["score.full"]
    rows = []
    for event in m.events(arm):
        phase, expected = phases[event.stage], event.expected(x)
        error = m.signed(phase - expected)
        rows.append(
            dict(
                record="phase",
                **identity,
                stage=event.stage,
                small_key=event.small,
                expected_torus=str(expected),
                phase=str(phase),
                signed_error=str(error),
                error_in_delta=error / 2**event.log,
                ciphertext_sha256=hashes[event.stage],
            )
        )
    bit_mismatches = consumer_mismatches = 0
    for bit in range(8):
        phase = phases[m.weighted_stage(arm, bit)]
        expected, log = (x >> bit) & 1, 60 + bit if bit < 3 else 59
        for candidate in m.candidates(bit):
            inp = m.consumer_input(phase, bit, candidate)
            actual, wanted = m.target_one(inp), int(candidate == 1 and expected == 0)
            consumer_mismatches += actual != wanted
            rows.append(
                dict(
                    record="consumer_scalar_phase",
                    **identity,
                    bit=bit,
                    level=7 - bit,
                    candidate=candidate,
                    actual=actual,
                    expected=wanted,
                    **{"pass": actual == wanted},
                    input_torus=str(inp),
                    ideal_candidate_and_keyswitch=True,
                    coefficientwise_modulus_switch_error_assumed_zero=True,
                    actual_pbs_executed=False,
                )
            )
        expected_p16 = expected * (2 ** (bit + 1) if bit < 3 else 1)
        error = m.signed(phase - expected_p16 * 2**59)
        rows.append(
            dict(
                record="weighted_p16_margin",
                **identity,
                bit=bit,
                expected_p16=expected_p16,
                actual_p16=m.decode(phase, 59),
                signed_error=str(error),
                error_in_delta59=error / 2**59,
                inside_open_half_slot=abs(error) < 2**58,
                composed_noise_margin_certified=False,
            )
        )
        actual = m.decode(phase, log)
        bit_mismatches += actual != expected
        rows.append(
            dict(
                record="weighted_bit",
                **identity,
                bit=bit,
                delta_log=log,
                expected=expected,
                actual=actual,
                **{"pass": actual == expected},
                signed_error=str(m.signed(phase - expected * 2**log)),
            )
        )
    native = bit_mismatches == 0 and m.decode(top, 60) == x >> 8
    consumer = consumer_mismatches == 0
    split = arm in m.ARMS[:2]
    rows.append(
        dict(
            record="case",
            **identity,
            **{"pass": native and consumer},
            native_decode_pass=native,
            consumer_scalar_phase_pass=consumer,
            consumer_scalar_phase_mismatches=consumer_mismatches,
            bit_mismatches=bit_mismatches,
            top_signed_error=str(m.signed(top - ((x >> 8) << 60))),
            top_actual=m.decode(top, 60),
            top_expected=x >> 8,
            pbs=11 if split else (9 if arm == m.REPAIR else 8),
            ks=8,
            frozen_control_byte_identical=True if split else None,
            input_full_sha256=hashes["score.full"],
            input_low_sha256=hashes.get("score.low"),
            source_packed_low_sha256=original_low,
            nontrivial_product=True,
            public_score_offset_diagnostic=True,
        )
    )
    return rows, phases


def make_records(
    source_files, binary_hash, injection=None, direct_error=0, pair_failure=False
):
    """Fixed fake records. Error injections are algebra tests, not noisy laws.

    Injection is (full-PBS bit, signed raw output error). Both aggressive and
    repair retain that identical prefix. Only repair b1 uses direct_error.
    """
    from validate import SOURCE_ID

    rows = [
        dict(
            record="plan",
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
        ),
        dict(
            record="provenance",
            binary_sha256=binary_hash,
            source_manifest_sha256=SOURCE_ID,
            source_sha256=source_files["candidate/src/diagnostic.rs"],
            frozen_helpers_sha256=source_files["candidate/src/frozen_extract.rs"],
            lock_sha256=source_files["candidate/Cargo.lock"],
            parameter_fingerprint=m.PARAMETER,
        ),
        dict(
            record="keyset",
            keyset=0,
            params="V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
            key_material_persisted=False,
            fresh_keyset=True,
        ),
    ]
    failures, natives, consumers, negatives = [0] * 4, [0] * 4, [0] * 4, [0] * 2
    pair_failures = 0
    for scene in m.SCENES:
        for x in m.targets("smoke"):
            identity = dict(keyset=0, scene=scene, x=x)
            arms = []
            for arm in m.A165_ARMS:
                arm_rows, phases = arm_records(
                    0,
                    scene,
                    x,
                    arm,
                    injection if arm in (m.ARMS[2], m.REPAIR) else None,
                    direct_error if arm == m.REPAIR else 0,
                )
                arms.append((arm_rows, phases))
            old = {row["stage"]: row for row in arms[2][0] if row["record"] == "phase"}
            repair = {
                row["stage"]: row for row in arms[3][0] if row["record"] == "phase"
            }
            pair_pass = not pair_failure
            pair_failures += not pair_pass
            rows.append(
                dict(
                    record="repair_pair",
                    **identity,
                    original_arm=m.ARMS[2],
                    repair_arm=m.REPAIR,
                    old_trace_byte_identical=True,
                    top_byte_identical=pair_pass,
                    other_weighted_byte_identical=True,
                    direct_output_consumed=True,
                    **{"pass": pair_pass},
                    retained_small_input_sha256=repair["full.ks_b1"][
                        "ciphertext_sha256"
                    ],
                    direct_weighted_b1_sha256=repair["repair_b1.pbs_correction_b1"][
                        "ciphertext_sha256"
                    ],
                    original_x256_b1_sha256=old["full.correction_x256_b1"][
                        "ciphertext_sha256"
                    ],
                    additional_pbs=1,
                    additional_ks=0,
                    full_residual_correction_retained=True,
                )
            )
            for index, (arm_rows, phases) in enumerate(arms):
                rows.extend(arm_rows)
                case = arm_rows[-1]
                if index < 4:
                    failures[index] += not case["pass"]
                    natives[index] += not case["native_decode_pass"]
                    consumers[index] += not case["consumer_scalar_phase_pass"]
                else:
                    negatives[0] += not case["pass"]
            detected = m.decode(arms[2][1]["full.pbs_correction_b0"], 60) != (x & 1)
            negatives[1] += detected
            rows.append(
                dict(record="negative_missing_rescale", **identity, detected=detected)
            )
    controls = failures[0] == 0 and all(negatives)
    repair_gate = controls and pair_failures == 0 and failures[3] == 0
    rows.append(
        dict(
            record="summary",
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
    )
    for row in rows:
        row["schema"] = m.SCHEMA
    return rows
