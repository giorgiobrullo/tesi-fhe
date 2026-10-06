"""Clear synthetic ciphertext words and witnesses; no TFHE or key sampling."""

import hashlib

from schema import FINGERPRINT, Q, U, ct_record, degree, fixture, signed


def make_record(error=0, displacement64=False, impossible_small_aggregate=False):
    fixed = fixture()
    bindings = dict(
        run_id="synthetic-first-ks",
        tfhe_version="1.7.0",
        configuration="Standard",
        parameter_fingerprint=FINGERPRINT,
        source_sha256=hashlib.sha256(b"synthetic future candidate source").hexdigest(),
        binary_sha256=hashlib.sha256(
            b"synthetic binary placeholder; no executable"
        ).hexdigest(),
        ksk_words_sha256=hashlib.sha256(
            b"synthetic KSK binding; no KSK generated"
        ).hexdigest(),
    )
    bindings["keyset_id"] = hashlib.sha256(
        b"A158-KEYSET-V1\0"
        + bytes.fromhex(FINGERPRINT)
        + bytes.fromhex(bindings["ksk_words_sha256"])
        + bindings["run_id"].encode()
    ).hexdigest()
    assert error % 16 == 0
    # One active large-secret coefficient, with zero decomposition remainder.
    low_mask = [1 << 46] + [0] * 2047
    low_phase = (fixed["translated_score"] * (1 << 60) + error // 8) % Q
    low = low_mask + [(low_phase + low_mask[0]) % Q]
    kin = [8 * x % Q for x in low]
    post_phase = ((1 << 63) + error) % Q
    if impossible_small_aggregate:
        mask = [U + 2] + [0] * 858
        A, D, Z = (
            1,
            0,
            1,
        )  # No binary key realizes this tuple; closure alone cannot prove it.
    else:
        mask = [0] * 859
        if displacement64:
            mask[:128] = [U // 2 - 1] * 128
        mask[-1] = 3 * U
        A = sum(mask) % Q
        D = sum(degree(x) for x in mask)
        Z = sum(signed(x - degree(x) * U) for x in mask)
    post = mask + [(post_phase + A) % Q]
    centered = mask + [(post[-1] + (1 << 62)) % Q]
    address = (degree(centered[-1]) - D) % 4096
    lift = (error + Z + U // 2) // U
    record = dict(
        schema="a158.first_low_ks_trace.v1",
        kind="synthetic",
        bindings=bindings,
        fixture=fixed,
        counts=dict(ordinary_ks=1, configured_ms=1, blind_rotations=0),
        full_n4_evaluation=False,
        blind_rotation_consumed=False,
        key_sensitive_client_local_only=True,
        client_key_membership_attested=False,
        ciphertexts=dict(
            score_low=ct_record(low),
            ks_input=ct_record(kin),
            post_ks=ct_record(post),
            centered_input=ct_record(centered),
            returned_lazy_base=ct_record(centered),
        ),
        returned_body_correction_words=0,
        returned_log_modulus=12,
        actual_mask_degrees=[degree(x) for x in mask],
        actual_body_degree=degree(centered[-1]),
        subgroup_g=1,
        initial_noise_terms_client=[
            dict(coefficient_index=1024 + i, epsilon_lift=-error // 16 if i == 0 else 0)
            for i, t in enumerate(fixed["template"])
            if t
        ],
        client=dict(
            low_phase_words=low_phase,
            large_input_mask_dot_words=1 << 49,
            input_phase_words=((1 << 63) + error) % Q,
            input_probe_weighted_noise_low_lift=error // 8,
            input_probe_weighted_noise_shifted_lift=error,
            large_remainder_lift=0,
            row_noise_signed_sum_direct_lift=0,
            row_noise_signed_sum_inferred_words=0,
            small_mask_dot_words=A,
            post_phase_words=post_phase,
            small_weighted_ms_degrees=D,
            small_weighted_ms_residues_lift=Z,
            centered_phase_words=(post_phase + (1 << 62)) % Q,
            direct_address=address,
            displacement_lift=lift,
        ),
        native_first_bit_decode_pass=(((post_phase + (1 << 62)) % Q) >> 63) == 1,
        conditional_lut_address_pass=address >= 2048,
    )
    return record, bindings
