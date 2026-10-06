"""Algebraic 48-record fixture using frozen D1/D2 test factories; no ciphertext sampling."""

import copy
import sys
import hashlib
import replay as r
import model as m


def frozen_factory():
    saved = {k: sys.modules.get(k) for k in ("replay", "verify")}
    try:
        sys.modules["replay"] = r.old
        sys.modules["verify"] = r.load(
            "a191_frozen_test_verifier",
            r.ROOT / "tmp/a167-a137-execution-readiness/runtime-validation/verify.py",
        )
        return r.load("a191_frozen_test_factory", r.OLD / "test_gate.py")
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


def node(words):
    return dict(
        words=words,
        sha256=m.hash_words(words),
        phase=words[-1],
        client_mask_dot=0,
        direct_phase_matches=True,
    )


def stage(i, iw, displacement=0):
    sw = [1] + [0] * 858 + [(iw[-1] + displacement) % m.Q]
    obs = m.synthetic_switch(sw, [0] * 859, iw, [0] * 2048)
    kind = "control" if i == 3 else "ternary"
    value = m.raw(kind, obs["actual_address"])
    raw = node([1] + [0] * 2047 + [(value * m.D) % m.Q])
    output = node(
        raw["words"][:-1] + [(raw["words"][-1] + (8 * m.D if i == 3 else 0)) % m.Q]
    )
    expected = [0, 1, -1, 4][i]
    expected_phase = ([0, m.D, -m.D, 12 * m.D][i]) % m.Q
    preimage = value == expected
    native = m.native(output["phase"], expected_phase, m.D)
    return dict(
        record="comparator_stage",
        schema=m.SCHEMA,
        keyset=0,
        stage=m.STAGES[i],
        kind=kind,
        ks_observation=obs,
        raw=raw,
        output=output,
        expected_raw=expected,
        expected_output_phase=expected_phase,
        body_sha256=m.hash_words(m.body(kind)),
        actual_lut=value,
        output_error_at_actual_address=0,
        preimage_pass=preimage,
        output_at_address_pass=True,
        native_output_pass=native,
        observer_pass=True,
        ks=1,
        br=1,
        samples=1,
        **{"pass": preimage and native},
    )


def make():
    factory = frozen_factory()
    base = factory.synthetic()
    block = copy.deepcopy(base[1 + 40 * 7 : 1 + 40 * 8])
    d1 = block[30:39]
    pfks = block[4:12]
    acc = block[12]
    noise = block[13:17]
    payloads = []
    inputs = [x["left"] for x in d1[:4]] + [x["right"] for x in d1[:4]]
    for t, inp in enumerate(inputs):
        j = t % 4
        values = m.LEFT if t < 4 else m.RIGHT
        delta = 1 << (56 if j == 3 else 59)
        payloads.append(
            dict(
                record="payload",
                schema=m.SCHEMA,
                keyset=0,
                side="left" if t < 4 else "right",
                lane=j,
                value=values[j],
                delta_log=56 if j == 3 else 59,
                lwe=node(inp["words"]),
                audit=factory.audit(inp["words"], inp["phase"], values[j], delta),
                native_pass=True,
            )
        )
    stages = []
    for i in range(4):
        if i < 3:
            iw = [
                (a - b) % m.Q
                for a, b in zip(inputs[i]["words"], inputs[i + 4]["words"])
            ]
        else:
            iw = [
                (4 * a + 2 * b + c) % m.Q
                for a, b, c in zip(*(s["output"]["words"] for s in stages))
            ]
            iw[-1] = (iw[-1] - m.D // 2) % m.Q
        stages.append(stage(i, iw))
    control = stages[3]["output"]
    sw = [1] + [0] * 858 + [12 * m.D]
    obs = m.synthetic_switch(sw, [0] * 859, control["words"], [0] * 2048)
    controls = [
        dict(
            record="selector_control",
            schema=m.SCHEMA,
            keyset=0,
            arm=arm,
            ks_observation=copy.deepcopy(obs),
            expected_control=12,
            expected_center=1536,
            support_radius=63,
            effective_error=0,
            support_pass=True,
            native_pass=True,
            observer_pass=True,
            same_actual_comparator=True,
            control_sha256=control["sha256"],
            ordinary_ks_calls=1,
        )
        for arm in m.CONTROL_ORDER
    ]
    lanes = []
    for j, lane in enumerate(block[:4]):
        delta = 1 << (56 if j == 3 else 59)
        direct = node([1] + [0] * 2047 + [lane["direct"]["phase"]])
        scalar = node([1] + [0] * 2047 + [lane["scalar"]["phase"]])
        out = node(d1[5 + j]["output_words"])
        lanes.append(
            dict(
                record="selector_lane",
                schema=m.SCHEMA,
                keyset=0,
                lane=j,
                expected=m.RIGHT[j],
                delta_log=56 if j == 3 else 59,
                direct=factory.audit(
                    direct["words"], direct["phase"], m.RIGHT[j], delta
                ),
                scalar=factory.audit(
                    scalar["words"], scalar["phase"], m.RIGHT[j], delta
                ),
                direct_d1=factory.audit(out["words"], out["phase"], m.RIGHT[j], delta),
                direct_lwe=direct,
                scalar_lwe=scalar,
                d1_lwe=out,
            )
        )
    for a in (acc, d1[4]):
        a.update(
            input_control_sha256=control["sha256"],
            input_control_phase=12 * m.D,
            post_ks_control_phase=12 * m.D,
            actual_ks_aggregate_error=0,
            modulus_switched_body=1536,
            secret_weighted_modulus_switched_mask_sum=0,
            actual_effective_rotation_degree=1536,
            actual_effective_rotation_error=0,
            rounded_phase_degree_diagnostic=1536,
            support_ok=True,
        )
    acc.update(
        contains_secret_derived_observations=True,
        not_independent_execution_attestation=True,
    )
    acc["post_ks_control_sha256"] = obs["small"]["sha256"]
    for p in pfks:
        p.update(
            aggregate_key_error_max_abs_centered=3,
            key_error_definition="phase(PFKS) - (phase(input)+rho)*F = -sum(digit*eta)",
        )
    digits = [x["digits"] for x in inputs]
    gram = [[sum(a * b for a, b in zip(x, y)) for y in digits] for x in digits]
    acc["public_key_error_statistics"] = dict(
        row_order="all mask rows then body; identical across eight ciphertexts",
        actual_level_order=[1],
        rows_per_input=2049,
        body_row_retained=True,
        digit_gram_decimal=[[str(v) for v in row] for row in gram],
        factorized_supported_domain=True,
        per_output_key_error_l1_decimal=str(sum(abs(d) for row in digits for d in row)),
        per_output_key_error_squared_l2_decimal=str(sum(gram[i][i] for i in range(8))),
        four_output_key_error_gram_decimal=[
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
        ],
        interpretation="public coefficients of aggregate primitive-key errors; not observed covariance",
        primitive_row_errors_independently_measured=False,
        independence_or_tail_certified=False,
    )
    meta = dict(
        record="meta",
        schema=m.SCHEMA,
        keyset=0,
        process_id=123,
        source_id="SYNTHETIC_SOURCE",
        binary_sha256="a" * 64,
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
        key_family_ids={
            k: hashlib.sha256(k.encode()).hexdigest()
            for k in ("constant", "window", "big", "small", "ordinary_ksk")
        },
        all_server_arms_complete_before_observations=True,
        raw_secret_bits_serialized=False,
        timing_allowed=False,
    )
    meta.update(
        {
            k: "0" * 64
            for k in (
                "main_sha256",
                "comparator_sha256",
                "driver_sha256",
                "d1_sha256",
                "observer_sha256",
                "lock_sha256",
            )
        }
    )
    counts = dict(
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
    case = dict(
        record="case",
        schema=m.SCHEMA,
        keyset=0,
        fixture_index=7,
        ingress_pass=True,
        comparator_pass=True,
        all_six_control_bytes_equal=True,
        controls_native_pass=True,
        control_observers_pass=True,
        actual_support_pass=True,
        scalar_pass=True,
        direct_pass=True,
        d1_pass=True,
        prerequisites_pass=True,
        direct_observer_pass=True,
        d1_observer_pass=True,
        direct_class="pass",
        d1_class="pass",
        direct_counters_pass=True,
        scalar_counters_pass=True,
        d1_counters=copy.deepcopy(r.old.COUNTS),
        actual_counts=counts,
        **{"pass": True},
    )
    summary = dict(
        record="summary",
        schema=m.SCHEMA,
        process_id=123,
        keysets=1,
        cases=1,
        records=48,
        gate_pass=True,
        status="A191_FIRST_COMPOSITION_PASS",
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
    )
    return (
        [r.plan(), meta]
        + payloads
        + stages
        + controls
        + lanes
        + pfks
        + [acc]
        + noise
        + d1
        + [case, summary]
    )
