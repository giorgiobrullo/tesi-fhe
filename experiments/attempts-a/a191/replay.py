"""Strict fixed48-record A191 arithmetic; an external saved launch envelope is required."""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import model as m

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OLD = ROOT / "tmp/a171-pfks-d1-runtime-gate"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


old = load("a191_frozen_d1", OLD / "replay.py")
oracle = load("a191_frozen_component_helpers", OLD / "control_oracle.py")
sys.path.insert(0, str(ROOT / "tmp/a137-pfks-runtime-error-observer"))
try:
    arithmetic = load("a191_frozen_direct_noise", OLD / "control_arithmetic.py")
finally:
    sys.path.pop(0)


def parse(data):
    def pairs(items):
        out = {}
        for k, v in items:
            m.need(k not in out, "duplicate JSON key")
            out[k] = v
        return out

    def reject(_):
        raise ValueError("noninteger/nonfinite JSON number")

    return json.loads(
        data, object_pairs_hook=pairs, parse_float=reject, parse_constant=reject
    )


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_check():
    source = parse((HERE / "SOURCE_MANIFEST.json").read_bytes())
    for name, expected in source["files"].items():
        m.eq(sha(HERE / name), expected, "source " + name)
    identity = sha(HERE / "SOURCE_MANIFEST.json")
    m.eq((HERE / "SOURCE_DIGEST.txt").read_text().strip(), identity, "embedded source")
    artifact = parse((HERE / "MANIFEST.json").read_bytes())
    m.eq(artifact["source_id"], identity)
    for name, expected in artifact["files"].items():
        m.eq(sha(HERE / name), expected, "artifact " + name)
    for filename in ("ORIGINS.json", "SOURCE_PINS.json"):
        for name, expected in parse((HERE / filename).read_bytes())["files"].items():
            m.eq(sha(ROOT / name), expected, "frozen dependency " + name)
    return identity


def plan(execute=True):
    return dict(
        record="plan",
        schema=m.SCHEMA,
        execution_requested=execute,
        fixture_index=7,
        fixture="right_low_nibble_boundary",
        left=m.LEFT,
        right=m.RIGHT,
        comparator_stages=m.STAGES,
        selector_order=["direct_window", "scalar_d2", "direct_d1"],
        keys=1,
        cases=1,
        records=48,
        pfks=20,
        ks=10,
        br=10,
        samples=16,
        input_lwe_encryptions=8,
        supplied_control_encryptions=0,
        functional_keys=2,
        diagnostic_extra_crypto=0,
        score_to_limb_bridge=False,
        tournament=False,
        tie_or_threshold_runtime_gate=False,
        timing_allowed=False,
        automatic_expansion=False,
    )


def audit(a, node, expected, delta):
    words, phase, closure = m.node(node, 2048)
    m.eq(a["phase"], phase)
    m.eq(a["sha256"], node["sha256"])
    m.eq(a["nontrivial"], any(words[:-1]), "actual public nontrivial mask")
    return oracle.audit_phase(a, expected, delta) and closure


def direct_block(pfks, acc, noise, d1_rows, payloads, switch, output_rows):
    fixture = "right_low_nibble_boundary"
    control = switch["small"]
    address = switch["actual_address"]
    support = abs(oracle.centered_degree(address - 1536)) <= 63
    inputs = [r["left"] for r in d1_rows[:4]] + [r["right"] for r in d1_rows[:4]]
    for j, (p, supplied) in enumerate(zip(pfks, inputs)):
        for k, v in dict(
            record="pfks_witness",
            fixture=fixture,
            arm="direct_window",
            term=j,
            producer=f"{fixture}/direct_window/pfks/{j}",
            key_family="window",
            function_sha256=oracle.function_hash(True),
            actual_level_order=[1],
            primitive_row_errors_independently_measured=False,
        ).items():
            m.eq(p[k], v, k)
        for key in (
            "input_sha256",
            "pfks_output_sha256",
            "phase_polynomial_sha256",
            "aggregate_key_error_polynomial_sha256",
            "public_digit_words_sha256",
        ):
            m.digest(p[key])
        m.eq(
            supplied["words"], payloads[j]["lwe"]["words"], "same original input words"
        )
        m.eq(
            supplied["phase"], payloads[j]["lwe"]["phase"], "same original input phase"
        )
        m.eq(p["actual_body_row_digits"], supplied["body_digits"])
        m.integer(p["aggregate_key_error_max_abs_centered"], 0, 1 << 63)
        m.eq(
            p["key_error_definition"],
            "phase(PFKS) - (phase(input)+rho)*F = -sum(digit*eta)",
        )
    for k, v in dict(
        record="accumulator_witness",
        fixture=fixture,
        arm="direct_window",
        post_ks_control_sha256=control["sha256"],
        input_control_sha256=switch["input"]["sha256"],
        input_control_phase=switch["input"]["phase"],
        post_ks_control_phase=control["phase"],
        actual_ks_aggregate_error=switch["ks_increment"],
        modulus_switched_body=switch["body_degree"],
        secret_weighted_modulus_switched_mask_sum=int(
            switch["client_weighted_degrees_decimal"]
        )
        % 4096,
        actual_effective_rotation_degree=address,
        actual_effective_rotation_error=oracle.centered_degree(address - 1536),
        rounded_phase_degree_diagnostic=switch["phase_only_address"],
        support_ok=support,
        direct_all_ciphertext_words_equal=True,
        diagnostics_after_all_arm_timers=True,
        contains_secret_derived_observations=True,
        not_independent_execution_attestation=True,
    ).items():
        m.eq(acc[k], v, "direct accumulator " + k)
    m.digest(acc["pre_br_ciphertext_sha256"])
    m.digest(acc["pre_br_phase_polynomial_sha256"])
    digits = [x["digits"] for x in inputs]
    gram = [[sum(a * b for a, b in zip(x, y)) for y in digits] for x in digits]
    l1 = sum(abs(d) for row in digits for d in row)
    l2 = sum(gram[j][j] for j in range(8))
    output_gram = [
        [
            str(
                sum(
                    gram[b + j][b + j + abs(a - c)]
                    for b in (0, 4)
                    for j in range(4 - abs(a - c))
                )
            )
            for c in range(4)
        ]
        for a in range(4)
    ]
    m.eq(
        acc["public_key_error_statistics"],
        dict(
            row_order="all mask rows then body; identical across eight ciphertexts",
            actual_level_order=[1],
            rows_per_input=2049,
            body_row_retained=True,
            digit_gram_decimal=[[str(v) for v in row] for row in gram],
            factorized_supported_domain=support,
            per_output_key_error_l1_decimal=str(l1) if support else None,
            per_output_key_error_squared_l2_decimal=str(l2) if support else None,
            four_output_key_error_gram_decimal=output_gram if support else None,
            interpretation="public coefficients of aggregate primitive-key errors; not observed covariance",
            primitive_row_errors_independently_measured=False,
            independence_or_tail_certified=False,
        ),
        "actual public coefficient statistics",
    )
    for j, row in enumerate(noise):
        for k, v in dict(
            record="noise_lane",
            fixture=fixture,
            arm="direct_window",
            lane=j,
            actual_pre_br_virtual_degree=address + 128 * j,
            expected_phase=m.RIGHT[j] * (1 << (56 if j == 3 else 59)),
            support_ok=support,
            closure_modulus_bits=64,
            output_sha256=output_rows[j]["direct"]["sha256"],
            actual_output_phase=output_rows[j]["direct"]["phase"],
        ).items():
            m.eq(row[k], v, "D2 lane binding " + k)
        for k in (
            "expected_phase",
            "ideal_body_at_actual_degree",
            "exact_pre_br_phase_reconstructed",
            "actual_pre_br_phase",
            "actual_output_phase",
        ):
            m.integer(row[k], 0, m.Q - 1)
        for k in (
            "support_message_residual",
            "transmitted_input_error",
            "transmitted_rounding_rho",
            "aggregate_pfks_key_error",
            "aggregate_fft_phase_residual",
            "br_and_numeric_residual",
            "semantic_error",
        ):
            m.integer(row[k], -m.Q // 2, m.Q // 2 - 1)
        contributions = row["term_contributions"]
        m.eq(len(contributions), 8)
        weights = [oracle.weight(address + 128 * j, t) for t in range(8)]
        for t, value in enumerate(contributions):
            m.eq(value["term"], t)
            m.eq(value["message_window_weight"], weights[t])
            m.integer(
                value["aggregate_key_error_contribution"], -m.Q // 2, m.Q // 2 - 1
            )
            m.integer(value["exact_pfks_phase_contribution"], 0, m.Q - 1)
        m.eq(
            row["transmitted_input_error"],
            m.signed(sum(weights[t] * pfks[t]["input_error"] for t in range(8))),
        )
        m.eq(
            row["transmitted_rounding_rho"],
            m.signed(
                sum(weights[t] * int(pfks[t]["rounding_rho_decimal"]) for t in range(8))
            ),
        )
        m.eq(
            row["ideal_body_at_actual_degree"],
            sum(weights[t] * pfks[t]["input_message_phase"] for t in range(8)) % m.Q,
        )
        arithmetic.validate_noise_lane(row)
    return True


def replay(rows, binary_sha, pid, exit_code, verify_source=True):
    source = source_check() if verify_source else "SYNTHETIC_SOURCE"
    m.integer(pid, 1, 1 << 31)
    m.integer(exit_code, 0, 1)
    m.eq(len(rows), 48, "exact first composition cardinality")
    m.eq(rows[0], plan())
    meta = rows[1]
    for k, v in dict(
        record="meta",
        schema=m.SCHEMA,
        keyset=0,
        process_id=pid,
        source_id=source,
        binary_sha256=binary_sha,
        params_fingerprint="b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1",
        tfhe="0.11.3",
        big_dimension=2048,
        small_dimension=859,
        glwe_size=2,
        polynomial_size=2048,
        pfks_base_log=24,
        pfks_levels=1,
        ks_base_log=3,
        ks_levels=5,
        all_server_arms_complete_before_observations=True,
        raw_secret_bits_serialized=False,
        timing_allowed=False,
    ).items():
        m.eq(meta[k], v, "actual metadata " + k)
    for key, filename in dict(
        main_sha256="main.rs",
        comparator_sha256="comparator.rs",
        driver_sha256="a191.rs",
        d1_sha256="d1.rs",
        observer_sha256="observer.rs",
        lock_sha256="../Cargo.lock",
    ).items():
        m.eq(
            meta[key],
            sha(HERE / "candidate/src" / filename) if verify_source else "0" * 64,
            "actual source file",
        )
    families = meta["key_family_ids"]
    m.eq(set(families), {"constant", "window", "big", "small", "ordinary_ksk"})
    m.need(
        len({m.digest(v) for v in families.values()}) == 5,
        "distinct bound key-family hashes",
    )
    payloads = rows[2:10]
    ingress = True
    for t, row in enumerate(payloads):
        j, values = t % 4, m.LEFT if t < 4 else m.RIGHT
        log = 56 if j == 3 else 59
        for k, v in dict(
            record="payload",
            schema=m.SCHEMA,
            keyset=0,
            side="left" if t < 4 else "right",
            lane=j,
            value=values[j],
            delta_log=log,
        ).items():
            m.eq(row[k], v, "payload " + k)
        valid = audit(row["audit"], row["lwe"], values[j], 1 << log)
        m.eq(row["native_pass"], valid)
        ingress &= valid
    stages = rows[10:14]
    outputs = []
    output_phases = []
    comparator = True
    for i, row in enumerate(stages):
        if i < 3:
            iw = [
                (a - b) % m.Q
                for a, b in zip(
                    payloads[i]["lwe"]["words"], payloads[i + 4]["lwe"]["words"]
                )
            ]
        else:
            iw = [(4 * a + 2 * b + c) % m.Q for a, b, c in zip(*outputs)]
            iw[-1] = (iw[-1] - m.D // 2) % m.Q
        expected_input_phase = (
            payloads[i]["lwe"]["phase"] - payloads[i + 4]["lwe"]["phase"]
            if i < 3
            else 4 * output_phases[0]
            + 2 * output_phases[1]
            + output_phases[2]
            - m.D // 2
        ) % m.Q
        m.eq(
            row["ks_observation"]["input"]["phase"],
            expected_input_phase,
            "same-key comparator affine phase",
        )
        ow, op, valid = m.stage(row, i, iw)
        outputs.append(ow)
        output_phases.append(op)
        comparator &= valid
    control_node = stages[3]["output"]
    controls = rows[14:20]
    observers, control_native, support = True, True, True
    first = None
    for row, arm in zip(controls, m.CONTROL_ORDER):
        for k, v in dict(
            record="selector_control",
            schema=m.SCHEMA,
            keyset=0,
            arm=arm,
            expected_control=12,
            expected_center=1536,
            support_radius=63,
            same_actual_comparator=True,
            control_sha256=control_node["sha256"],
            ordinary_ks_calls=1,
        ).items():
            m.eq(row[k], v, k)
        obs = m.switch(row["ks_observation"])
        m.eq(
            row["ks_observation"]["input"],
            control_node,
            "same actual comparator output",
        )
        if first is None:
            first = row["ks_observation"]
        m.eq(row["ks_observation"], first, "all six deterministic KS/observer objects")
        error = oracle.centered_degree(obs["actual_address"] - 1536)
        good = abs(error) <= 63
        native = m.native(obs["small_phase"], 12 * m.D, m.D)
        for k, v in dict(
            effective_error=error,
            support_pass=good,
            native_pass=native,
            observer_pass=obs["observer"],
        ).items():
            m.eq(row[k], v, k)
        observers &= obs["observer"]
        control_native &= native
        support &= good
    lanes = rows[20:24]
    native_outputs = {k: True for k in ("direct", "scalar", "direct_d1")}
    for j, row in enumerate(lanes):
        for k, v in dict(
            record="selector_lane",
            schema=m.SCHEMA,
            keyset=0,
            lane=j,
            expected=m.RIGHT[j],
            delta_log=56 if j == 3 else 59,
        ).items():
            m.eq(row[k], v, k)
        for arm, key in (
            ("direct", "direct_lwe"),
            ("scalar", "scalar_lwe"),
            ("direct_d1", "d1_lwe"),
        ):
            native_outputs[arm] &= audit(
                row[arm], row[key], m.RIGHT[j], 1 << (56 if j == 3 else 59)
            )
            if arm != "scalar":
                native_outputs[arm] &= row[arm]["decoded"] == row["scalar"]["decoded"]
    pfks, acc, noise, d1_rows = rows[24:32], rows[32], rows[33:37], rows[37:46]
    spec = dict(
        name="right_low_nibble_boundary", left=m.LEFT, right=m.RIGHT, control=12
    )
    control_audit = dict(sha256=first["small"]["sha256"], phase=first["small"]["phase"])
    d1_valid = old.check_block(
        d1_rows, spec, control_audit, [x["direct_d1"] for x in lanes], pfks, acc
    )
    direct_valid = direct_block(pfks, acc, noise, d1_rows, payloads, first, lanes)
    case = rows[46]
    expected_counts = dict(
        comparator_ks=4,
        comparator_br=4,
        comparator_samples=4,
        direct_pfks=8,
        direct_ks=1,
        direct_br=1,
        direct_samples=4,
        scalar_pfks=8,
        scalar_ks=4,
        scalar_br=4,
        scalar_samples=4,
    )
    m.eq(case["actual_counts"], expected_counts)
    m.eq(case["d1_counters"], old.COUNTS)
    prereq = (
        ingress
        and comparator
        and control_native
        and observers
        and native_outputs["scalar"]
    )
    dc = oracle.classification(
        support, prereq and direct_valid, native_outputs["direct"]
    )
    oc = oracle.classification(
        support, prereq and dc == "pass" and d1_valid, native_outputs["direct_d1"]
    )
    passed = dc == "pass" and oc == "pass"
    m.eq(
        case,
        dict(
            record="case",
            schema=m.SCHEMA,
            keyset=0,
            fixture_index=7,
            ingress_pass=ingress,
            comparator_pass=comparator,
            all_six_control_bytes_equal=True,
            controls_native_pass=control_native,
            control_observers_pass=observers,
            actual_support_pass=support,
            scalar_pass=native_outputs["scalar"],
            direct_pass=native_outputs["direct"],
            d1_pass=native_outputs["direct_d1"],
            prerequisites_pass=prereq,
            direct_observer_pass=direct_valid,
            d1_observer_pass=d1_valid,
            direct_class=dc,
            d1_class=oc,
            direct_counters_pass=True,
            scalar_counters_pass=True,
            d1_counters=old.COUNTS,
            actual_counts=expected_counts,
            **{"pass": passed},
        ),
    )
    m.eq(
        rows[47],
        dict(
            record="summary",
            schema=m.SCHEMA,
            process_id=pid,
            keysets=1,
            cases=1,
            records=48,
            gate_pass=passed,
            status="A191_FIRST_COMPOSITION_PASS"
            if passed
            else "A191_COMPLETE_NEGATIVE",
            pfks=20,
            ks=10,
            br=10,
            samples=16,
            actual_comparator=True,
            supplied_selector=False,
            full_id=False,
            score_bridge=False,
            tie_threshold_exercised=False,
            actual_p_fail=None,
            timing_allowed=False,
            automatic_expansion=False,
        ),
    )
    m.eq(exit_code, 0 if passed else 1, "complete conjunction/actual exit")
    return dict(
        status="VALID_A191_FIRST_PASS" if passed else "VALID_A191_COMPLETE_NEGATIVE",
        gate_pass=passed,
        records=48,
        keysets=1,
        fixture_index=7,
        comparator_pass=comparator,
        actual_support_pass=support,
        direct_class=dc,
        d1_class=oc,
        scalar_pass=native_outputs["scalar"],
        comparator_preimages=[r["preimage_pass"] for r in stages],
        comparator_native=[r["native_output_pass"] for r in stages],
        comparator_addresses=[r["ks_observation"]["actual_address"] for r in stages],
        selector_address=first["actual_address"],
        selector_phase_only_address=first["phase_only_address"],
        all_six_control_bytes_equal=True,
        source_id=source,
        binary_sha256=binary_sha,
        child_pid=pid,
        ledger=dict(PFKS=20, KS=10, BR=10, samples=16, input_encryptions=8),
        actual_internal_br_receipts=False,
        independent_key_membership_attestation=False,
        whole_tournament_or_exact_id=False,
        score_to_limb_bridge=False,
        actual_p_fail=None,
        timing_claim=False,
        launch_envelope_verified=False,
        automatic_retry_or_expansion=False,
    )
