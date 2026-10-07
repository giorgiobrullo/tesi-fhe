"""Small deterministic algebra records. No claim these inputs arise from actual KS/BR."""

import hashlib
import struct
import model as m


def node(mask, secret, phase):
    dot = sum(w * s for w, s in zip(mask, secret)) % m.Q
    words = [*mask, (phase + dot) % m.Q]
    raw = b"".join(struct.pack("<Q", w) for w in words)
    return dict(
        words_le_hex=raw.hex(),
        sha256=hashlib.sha256(raw).hexdigest(),
        word_count=len(words),
        phase=str(phase % m.Q),
        client_mask_dot=str(dot),
        direct_phase_matches_tfhe=True,
    )


def make(
    bit=2,
    candidate=1,
    x=0,
    arm=m.ARMS[0],
    candidate_error=0,
    producer_error=0,
    ks_error=0,
    br_error=0,
    ms_boundary=False,
):
    big = [1, 0]
    small = [1] * 128 if ms_boundary else [1, 0, 1]
    multiplier = 1 if bit == 2 else -1
    weight = 1 << (bit + 1) if bit < 3 else 1
    expected_bit = (x >> bit) & 1
    cp = (candidate * m.DELTA + candidate_error) % m.Q
    wp = (expected_bit * weight * m.DELTA + producer_error) % m.Q
    ip = (cp + multiplier * wp) % m.Q
    kp = (ip + ks_error) % m.Q
    cand = node([7, 11], big, cp)
    weighted = node([13, 17], big, wp)
    encoded_mask = [(a + multiplier * b) % m.Q for a, b in zip([7, 11], [13, 17])]
    encoded = node(encoded_mask, big, ip)
    small_mask = [m.U // 2 - 1] * 128 if ms_boundary else [m.U // 4, 123, m.U // 4]
    switched = node(small_mask, small, kp)
    words = [
        w[0] for w in struct.iter_unpack("<Q", bytes.fromhex(switched["words_le_hex"]))
    ]
    body = m.rounded(words[-1])
    degrees = list(map(m.rounded, small_mask))
    wd = sum(d * s for d, s in zip(degrees, small))
    wr = sum(m.signed(w - d * m.U) * s for w, d, s in zip(small_mask, degrees, small))
    body_residue = m.signed(words[-1] - body * m.U)
    address = (body - wd) % m.M
    lut = m.target(address)
    op = (lut * m.DELTA + br_error) % m.Q
    output = node([19, 23], big, op)
    grid = 1 << 49
    remainders = [
        m.signed(w - ((w + grid // 2) % m.Q // grid) * grid) for w in encoded_mask
    ]
    remainder = sum(v * s for v, s in zip(remainders, big))
    actual = m.decode(op)
    if actual >= 16:
        actual -= 32
    wanted = int(candidate == 1 and expected_bit == 0)
    gates = [
        m.decode(cp) == candidate % 32,
        lut == wanted,
        actual == lut,
        actual == wanted,
        True,
        True,
    ]
    row = dict(
        schema=m.SCHEMA,
        record="actual_consumer",
        keyset=0,
        scene=m.SCENES[0],
        x=x,
        arm=arm,
        bit=bit,
        level=7 - bit,
        candidate=candidate,
        source_multiplier=multiplier,
        expected_bit=expected_bit,
        weight_delta59=weight,
        expected_output=wanted,
        candidate_lwe=cand,
        weighted_lwe=weighted,
        encoded_lwe=encoded,
        post_ks_lwe=switched,
        output_lwe=output,
        candidate_error=str(m.signed(candidate_error)),
        producer_error=str(m.signed(producer_error)),
        encoded_error=str(
            m.signed(ip - (candidate + multiplier * expected_bit * weight) * m.DELTA)
        ),
        ks_increment=str(m.signed(ks_error)),
        ks_remainder_sum=str(remainder),
        inferred_signed_ks_row_term=str(m.signed(m.signed(ks_error) - remainder)),
        ks_row_term_independently_measured=False,
        ks_base_log=3,
        ks_level_count=5,
        receipt_body=body,
        receipt_masks=degrees,
        receipt_raw_mask_nonzero=[w != 0 for w in small_mask],
        client_weighted_degrees=str(wd),
        client_weighted_residues=str(wr),
        body_residue=str(body_residue),
        actual_address=address,
        phase_only_address=m.rounded(kp),
        actual_lut_value=lut,
        output_actual=actual,
        output_error_at_actual_address=str(m.signed(br_error)),
        traced_glwe_sha256="a" * 64,
        stock_glwe_sha256="a" * 64,
        stock_output_sha256=output["sha256"],
        stock_glwe_byte_identical=True,
        stock_output_byte_identical=True,
        ks_calls=1,
        traced_br_calls=1,
        stock_br_calls=1,
        sample_calls=2,
        traced_ms_body_calls=1,
        traced_ms_mask_calls=sum(w != 0 for w in small_mask),
        **dict(zip(m.GATE_FIELDS, gates)),
        **{"pass": all(gates)},
        candidate_is_previous_selector_output=False,
        client_aggregates_independently_attested=False,
        secret_key_bits_serialized=False,
        p_fail_certified=False,
        latency_claim_allowed=False,
    )
    identity = {k: row[k] for k in ("keyset", "scene", "x", "arm", "bit", "candidate")}
    return row, identity, (weighted["sha256"], wp), len(big), len(small)


def check(args):
    row, identity, producer, big, small = args
    return m.check_consumer(row, identity, producer, big, small)
