"""Frozen A164 synthetic_chain helper, task labels normalized; no actual keys."""
import hashlib
from audit import a158

def synthetic_chain(error=0, displacement64=False):
    """Clear arithmetic fixture with all-zero large key, all-one small key, eta=0.

    It has actual native shapes but no sampled keys or encryption. The result is
    tagged client_observed solely to exercise the future schema; not runtime evidence.
    """
    from synthetic import make_record

    record, binding = make_record()
    record["kind"] = "client_observed"
    q, u = a158.Q, a158.U
    assert error % 16 == 0
    plaintext = [0] * 2048
    for i, v in [(0, 1), (1, -2), (255, 2), (511, -1)]:
        plaintext[i] = v * (1 << 52) % q
        plaintext[1024 + i] = v * (1 << 60) % q
    plaintext[1024] = (plaintext[1024] - error // 16) % q
    # Public mask with sparse but nonzero coefficients; body is exact plaintext
    # under the synthetic all-zero large key. No iid or sampler premise.
    packed = [(19 * i * (1 << 40) + 7) % q for i in range(2048)] + plaintext
    product = [0] * 4096
    template = a158.fixture()["template"]
    for block in range(2):
        for i, word in enumerate(packed[block * 2048 : (block + 1) * 2048]):
            for coordinate, t in enumerate(template):
                if t:
                    degree = i + 511 - coordinate
                    product[block * 2048 + degree % 2048] = (
                        product[block * 2048 + degree % 2048]
                        + (-1 if degree >= 2048 else 1) * word * (-2 * t)
                    ) % q
    low = [
        product[1535 - i] if i <= 1535 else -product[2048 + 1535 - i] % q
        for i in range(2048)
    ]
    low += [(product[2048 + 1535] + 1037 * (1 << 60)) % q]
    kin = [8 * x % q for x in low]
    assert low[-1] == (1029 * (1 << 60) + error // 8) % q
    assert kin[-1] == ((1 << 63) + error) % q
    mask = (
        [u // 2 - 1] * 128 + [0] * 730 + [3 * u]
        if displacement64
        else [0] * 858 + [3 * u]
    )
    A = sum(mask) % q
    D = sum(a158.degree(x) for x in mask)
    Z = sum(a158.signed(x - a158.degree(x) * u) for x in mask)
    post = mask + [(kin[-1] + A) % q]
    centered = mask + [(post[-1] + (1 << 62)) % q]
    record["ciphertexts"] = {
        k: a158.ct_record(v)
        for k, v in dict(
            score_low=low,
            ks_input=kin,
            post_ks=post,
            centered_input=centered,
            returned_lazy_base=centered,
        ).items()
    }
    record["actual_mask_degrees"] = [a158.degree(x) for x in mask]
    record["actual_body_degree"] = a158.degree(centered[-1])
    rows = []
    g = q
    for i, a in enumerate(kin[:-1]):
        for j, d in enumerate(a158.a156.decompose(a, q, 3, 5)[0]):
            if d:
                g = min(g, abs(d) & -abs(d))
                rows.append(
                    dict(
                        input_index=i,
                        level=5 - j,
                        storage_index=j,
                        digit=d,
                        row_words_sha256=hashlib.sha256(
                            f"synthetic row {i} {j}".encode()
                        ).hexdigest(),
                        eta_centered_lift=0,
                        contribution_lift=0,
                    )
                )
    record["subgroup_g"] = g
    record["initial_noise_terms_client"] = [
        dict(coefficient_index=1024 + i, epsilon_lift=-error // 16 if i == 0 else 0)
        for i, t in enumerate(template)
        if t
    ]
    address = (a158.degree(centered[-1]) - D) % 4096
    lift = (error + Z + u // 2) // u
    record["client"] = dict(
        low_phase_words=low[-1],
        large_input_mask_dot_words=0,
        input_phase_words=kin[-1],
        input_probe_weighted_noise_low_lift=error // 8,
        input_probe_weighted_noise_shifted_lift=error,
        large_remainder_lift=0,
        row_noise_signed_sum_direct_lift=0,
        row_noise_signed_sum_inferred_words=0,
        small_mask_dot_words=A,
        post_phase_words=kin[-1],
        small_weighted_ms_degrees=D,
        small_weighted_ms_residues_lift=Z,
        centered_phase_words=(kin[-1] + (1 << 62)) % q,
        direct_address=address,
        displacement_lift=lift,
    )
    record["native_first_bit_decode_pass"] = ((kin[-1] + (1 << 62)) % q) >> 63 == 1
    record["conditional_lut_address_pass"] = address >= 2048
    before = dict(
        bindings=binding,
        packed_query=a158.ct_record(packed),
        product=a158.ct_record(product),
        score_low=record["ciphertexts"]["score_low"],
        ks_input=record["ciphertexts"]["ks_input"],
        initial_noise_terms_client=record["initial_noise_terms_client"],
        input_noise_lift=error,
        large_remainder_lift=0,
        row_noise_signed_sum_direct_lift=0,
        subgroup_g=g,
        used_rows=rows,
        ks_calls_so_far=0,
        post_ks_exists=False,
    )
    prepared = {
        key: binding[key] for key in ("run_id", "source_sha256", "binary_sha256")
    }
    started = dict(
        prepared,
        schema="a166.prefix.started.v1",
        pid=123,
        timed_benchmark=False,
        secret_material_persisted=False,
    )
    completed = dict(
        status="P0_NATIVE_AND_CONDITIONAL_ADDRESS_PASS",
        ordinary_ks=1,
        configured_ms=1,
        blind_rotations=0,
        actual_sampler_p_fail=None,
        independent_replay_pending=True,
    )
    return record, before, binding, prepared, started, completed

