"""Public-word recomputation and conditional closure of client aggregates."""

import hashlib
import re

Q = 1 << 64
U = 1 << 52
DIMENSION = 859
DEGREES = 4096


def word(x):
    return x % Q


def signed(x):
    return (x + Q // 2) % Q - Q // 2


def round_degree(x):
    # Deliberately use quotient/remainder rather than the Rust add-and-shift expression.
    quotient, remainder = divmod(x, U)
    return (quotient + (remainder >= U // 2)) % DEGREES


def hex_word(text):
    assert isinstance(text, str) and re.fullmatch("[0-9a-f]{16}", text), (
        "canonical u64 hex"
    )
    return int(text, 16)


def decimal(text):
    assert isinstance(text, str)
    value = int(text)
    assert str(value) == text, "canonical signed decimal"
    return value


def digest_words(words):
    return hashlib.sha256(b"".join(x.to_bytes(8, "little") for x in words)).hexdigest()


def verify_event(event):
    observation = event["coefficient_observer"]
    assert observation["schema"] == "A143_POST_KS_V1"
    assert (
        type(observation["keyset"]) is int and observation["keyset"] == event["keyset"]
    )
    assert observation["lwe_dimension"] == DIMENSION
    assert observation["torus_bits"] == 64 and observation["log_degree_modulus"] == 12
    words = [hex_word(x) for x in observation["post_ks_words_hex"]]
    assert len(words) == DIMENSION + 1
    assert digest_words(words) == event["small_sha256"], "post-KS words/hash mismatch"
    mask, body = words[:-1], words[-1]
    mask_degrees = [round_degree(x) for x in mask]
    body_degree = round_degree(body)
    assert observation["public_mask_degrees"] == mask_degrees, "public mask rounding"
    assert all(type(x) is int for x in observation["public_mask_degrees"])
    assert (
        type(observation["public_body_degree"]) is int
        and observation["public_body_degree"] == body_degree
    )
    residues = [signed(x - d * U) for x, d in zip(mask, mask_degrees)]
    body_residue = signed(body - body_degree * U)
    assert all(-U // 2 <= x < U // 2 for x in residues + [body_residue])
    assert decimal(observation["public_body_residue_decimal"]) == body_residue
    weighted_words = hex_word(observation["client_weighted_mask_words_hex"])
    weighted_degrees = observation["client_weighted_mask_degrees"]
    weighted_residues = decimal(observation["client_weighted_mask_residues_decimal"])
    assert type(weighted_degrees) is int and 0 <= weighted_degrees <= sum(mask_degrees)
    assert (
        sum(min(x, 0) for x in residues)
        <= weighted_residues
        <= sum(max(x, 0) for x in residues)
    )
    phase = word(body - weighted_words)
    address = (body_degree - weighted_degrees) % DEGREES
    assert hex_word(observation["direct_phase_word_hex"]) == phase
    assert (
        type(observation["direct_address"]) is int
        and observation["direct_address"] == address
    )
    checks = dict(
        phase_matches_tfhe_decrypt=phase == int(event["small_phase_word"]),
        address_matches_existing_observer=address == event["actual_ms_address"],
        mask_decomposition_identity=weighted_words
        == word(U * weighted_degrees + weighted_residues),
        phase_ms_identity=phase == word(U * address + body_residue - weighted_residues),
    )
    for field, value in checks.items():
        assert type(observation[field]) is bool and observation[field] == value, field
    passed = all(checks.values())
    assert (
        type(observation["closure_pass"]) is bool
        and observation["closure_pass"] == passed
    )
    assert observation["secret_key_bits_serialized"] is False
    assert observation["key_sensitive_client_local_only"] is True
    assert observation["client_aggregates_independently_attested"] is False
    return dict(
        public_word_hash_and_rounding_pass=True,
        coefficient_closure_pass=passed,
        phase_from_body_and_client_aggregate=str(phase),
        address_from_public_rounding_and_client_aggregate=address,
        public_body_degree=body_degree,
        client_weighted_mask_degree_sum=weighted_degrees,
        client_weighted_mask_residue_sum=str(weighted_residues),
        observed_ms_displacement=(address - round_degree(phase) + 2048) % DEGREES
        - 2048,
        private_aggregate_key_membership_attested=False,
        actual_secret_key_or_execution_attested=False,
    )


def synthetic_witness(words, secret, phase, address, keyset=0):
    """Test-only clear arithmetic on synthetic words/key. Never called by runtime replay."""
    assert len(words) == DIMENSION + 1 and len(secret) == DIMENSION
    assert all(x in (0, 1) for x in secret)
    mask, body = words[:-1], words[-1]
    degrees = [round_degree(x) for x in mask]
    bd = round_degree(body)
    residues = [signed(x - d * U) for x, d in zip(mask, degrees)]
    total = word(sum(x * s for x, s in zip(mask, secret)))
    degree_sum = sum(x * s for x, s in zip(degrees, secret))
    residue_sum = sum(x * s for x, s in zip(residues, secret))
    direct_phase = word(body - total)
    direct_address = (bd - degree_sum) % DEGREES
    values = dict(
        schema="A143_POST_KS_V1",
        keyset=keyset,
        lwe_dimension=DIMENSION,
        torus_bits=64,
        log_degree_modulus=12,
        post_ks_words_hex=[f"{x:016x}" for x in words],
        public_mask_degrees=degrees,
        public_body_degree=bd,
        public_body_residue_decimal=str(signed(body - bd * U)),
        client_weighted_mask_words_hex=f"{total:016x}",
        client_weighted_mask_degrees=degree_sum,
        client_weighted_mask_residues_decimal=str(residue_sum),
        direct_phase_word_hex=f"{direct_phase:016x}",
        direct_address=direct_address,
        phase_matches_tfhe_decrypt=direct_phase == phase,
        address_matches_existing_observer=direct_address == address,
        mask_decomposition_identity=total == word(U * degree_sum + residue_sum),
        phase_ms_identity=direct_phase
        == word(U * direct_address + signed(body - bd * U) - residue_sum),
        secret_key_bits_serialized=False,
        key_sensitive_client_local_only=True,
        client_aggregates_independently_attested=False,
    )
    values["closure_pass"] = all(
        values[k]
        for k in (
            "phase_matches_tfhe_decrypt",
            "address_matches_existing_observer",
            "mask_decomposition_identity",
            "phase_ms_identity",
        )
    )
    return values


def realize_synthetic_event(event):
    """Realize the small +/-1 and64 MS witnesses with one fixed all-one synthetic key."""
    phase, address = int(event["small_phase_word"]), event["actual_ms_address"]
    displacement = (address - round_degree(phase) + 2048) % DEGREES - 2048
    assert 2 * abs(displacement) <= DIMENSION
    mask = [0] * DIMENSION
    if displacement:
        coefficient = U // 2 - 1 if displacement > 0 else Q - U // 2
        mask[: 2 * abs(displacement)] = [coefficient] * (2 * abs(displacement))
    mask[-1] = (
        3 * U
    )  # A nonzero public rounded mask coefficient; exact integer shift cancels.
    words = mask + [word(phase + sum(mask))]
    observation = synthetic_witness(
        words, [1] * DIMENSION, phase, address, event["keyset"]
    )
    assert observation["closure_pass"], (
        "synthetic construction did not realize requested displacement"
    )
    return dict(
        event,
        small_sha256=digest_words(words),
        coefficient_observer=observation,
        synthetic=True,
    )
