"""Synthetic-tested first-KS record checker. Client aggregates are not attested."""

import hashlib
import json
from pathlib import Path
import re
import sys

if not __debug__:
    raise RuntimeError("Source/domain/arithmetic checks require assertions")

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def verify_sources():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())["sources"]
    for name, digest in pins.items():
        assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest, name
    return len(pins)


verify_sources()
sys.path.insert(0, str(ROOT / "tmp/a156-initial-ks-joint-mgf"))
import model as a156  # noqa: E402

a156.verify_sources()
Q, U, M = 1 << 64, 1 << 52, 4096
FINGERPRINT = "ff8b62d46dee3427a6f048490a171f5eb74158ffe9dad1b32c8bd8990dc2ac61"


def signed(x):
    return (x + Q // 2) % Q - Q // 2


def degree(x):
    quotient, remainder = divmod(x, U)
    return (quotient + int(remainder >= U // 2)) % M


def digest_words(words):
    return hashlib.sha256(b"".join(x.to_bytes(8, "little") for x in words)).hexdigest()


def ct_record(words):
    return dict(words_hex=[f"{x:016x}" for x in words], sha256=digest_words(words))


def words(record, count):
    assert len(record["words_hex"]) == count
    assert all(
        isinstance(x, str) and re.fullmatch("[0-9a-f]{16}", x)
        for x in record["words_hex"]
    )
    result = [int(x, 16) for x in record["words_hex"]]
    assert digest_words(result) == record["sha256"]
    return result


def fixture():
    path = ROOT / "tmp/u9-corrected-cmnr-standard-gates/standard/fixtures.tsv"
    line = next(
        x for x in path.read_text().splitlines() if x.startswith("n4_boundary_accept|")
    )
    fields = line.split("|")

    def vector(text):
        result = [0] * 512
        for pair in text.split(","):
            i, value = map(int, pair.split(":"))
            result[i] = value
        return result

    probe, template = vector(fields[3]), vector(fields[4].split(";")[0])
    threshold = int(fields[5].split(",")[0])
    lower = threshold - 1023
    raw = sum(x * x for x in template) - 2 * sum(x * y for x, y in zip(probe, template))
    assert (raw, lower, raw - lower) == (-4, -1033, 1029)
    return dict(
        name=fields[0],
        gallery_index=0,
        translated_score=raw - lower,
        domain_lower=lower,
        template=template,
        fixtures_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
    )


def verify(record, expected_bindings):
    assert record["schema"] == "a158.first_low_ks_trace.v1"
    assert record["bindings"] == expected_bindings, "independent run/key/source binding"
    bindings = record["bindings"]
    assert (
        bindings["tfhe_version"] == "1.7.0" and bindings["configuration"] == "Standard"
    )
    assert bindings["parameter_fingerprint"] == FINGERPRINT
    for key in ("source_sha256", "binary_sha256", "ksk_words_sha256", "keyset_id"):
        assert re.fullmatch("[0-9a-f]{64}", bindings[key])
    keyset = hashlib.sha256(
        b"A158-KEYSET-V1\0"
        + bytes.fromhex(FINGERPRINT)
        + bytes.fromhex(bindings["ksk_words_sha256"])
        + bindings["run_id"].encode()
    ).hexdigest()
    assert bindings["keyset_id"] == keyset
    fixed = fixture()
    assert record["fixture"] == fixed
    assert record["counts"] == dict(ordinary_ks=1, configured_ms=1, blind_rotations=0)
    assert all(type(x) is int for x in record["counts"].values())
    assert (
        record["full_n4_evaluation"] is False
        and record["blind_rotation_consumed"] is False
    )
    assert record["key_sensitive_client_local_only"] is True
    assert record["client_key_membership_attested"] is False
    assert record["kind"] in ("synthetic", "client_observed")
    cts = record["ciphertexts"]
    low = words(cts["score_low"], 2049)
    kin = words(cts["ks_input"], 2049)
    post = words(cts["post_ks"], 860)
    centered = words(cts["centered_input"], 860)
    lazy = words(cts["returned_lazy_base"], 860)
    assert kin == [8 * x % Q for x in low], (
        "actual first shift is8 on every coefficient"
    )
    assert centered[:-1] == post[:-1] and centered[-1] == (post[-1] + (1 << 62)) % Q
    assert lazy == centered and record["returned_body_correction_words"] == 0
    assert type(record["returned_body_correction_words"]) is int
    assert record["returned_log_modulus"] == 12
    md = [degree(x) for x in lazy[:-1]]
    bd = degree(lazy[-1])
    assert record["actual_mask_degrees"] == md
    assert all(type(x) is int for x in record["actual_mask_degrees"])
    assert record["actual_body_degree"] == bd
    assert type(record["actual_body_degree"]) is int
    residues = [signed(x - d * U) for x, d in zip(lazy[:-1], md)]
    rb = signed(lazy[-1] - bd * U)
    decomposed = [a156.decompose(x, Q, 3, 5) for x in kin[:-1]]
    r = [x[1] for x in decomposed]
    export = dict(
        schema="a156.initial-low-ks.public.v1",
        tfhe_version="1.7.0",
        input_kind="synthetic"
        if record["kind"] == "synthetic"
        else "client_observed_public_input",
        public_offset_words=1 << 62,
        first_low_bit=1,
        reference_degree=3072,
        safe_lifts=[-1024, 1023],
        input_mask_words=kin[:-1],
        digits_descending=[list(x[0]) for x in decomposed],
        remainder_words=r,
        subgroup_g=record["subgroup_g"],
        template=fixed["template"],
    )
    assert type(record["subgroup_g"]) is int
    a156.native_context(export)
    client = record["client"]
    for key, value in client.items():
        assert type(value) is int, key
        if key.endswith("_words"):
            assert 0 <= value < Q, key
    low_phase = client["low_phase_words"]
    input_phase = (kin[-1] - client["large_input_mask_dot_words"]) % Q
    post_phase = (post[-1] - client["small_mask_dot_words"]) % Q
    assert input_phase == client["input_phase_words"] == 8 * low_phase % Q
    assert post_phase == client["post_phase_words"]
    e_low = client["input_probe_weighted_noise_low_lift"]
    e_input = client["input_probe_weighted_noise_shifted_lift"]
    terms = record["initial_noise_terms_client"]
    coordinates = [i for i, t in enumerate(fixed["template"]) if t]
    assert [term["coefficient_index"] for term in terms] == [
        1024 + i for i in coordinates
    ]
    assert all(
        type(term["epsilon_lift"]) is int and -Q // 2 <= term["epsilon_lift"] < Q // 2
        for term in terms
    )
    assert e_low == -2 * sum(
        fixed["template"][i] * term["epsilon_lift"]
        for i, term in zip(coordinates, terms)
    )
    assert e_input == 8 * e_low
    assert low_phase == (fixed["translated_score"] * (1 << 60) + e_low) % Q
    assert input_phase == ((1 << 63) + e_input) % Q
    remainder_sum = client["large_remainder_lift"]
    assert sum(min(x, 0) for x in r) <= remainder_sum <= sum(max(x, 0) for x in r)
    row_direct = client["row_noise_signed_sum_direct_lift"]
    row_inferred = (post_phase - input_phase - remainder_sum) % Q
    assert (
        row_direct % Q == client["row_noise_signed_sum_inferred_words"] == row_inferred
    )
    phase_error_lift = e_input + remainder_sum + row_direct
    assert post_phase == ((1 << 63) + phase_error_lift) % Q
    assert client["centered_phase_words"] == (post_phase + (1 << 62)) % Q
    A, D, Z = (
        client["small_mask_dot_words"],
        client["small_weighted_ms_degrees"],
        client["small_weighted_ms_residues_lift"],
    )
    assert 0 <= A < Q and 0 <= D <= sum(md)
    assert sum(min(x, 0) for x in residues) <= Z <= sum(max(x, 0) for x in residues)
    assert A == (U * D + Z) % Q
    address = (bd - D) % M
    assert client["direct_address"] == address
    assert client["centered_phase_words"] == (U * address + rb - Z) % Q
    lift = (phase_error_lift + Z + U // 2) // U
    assert client["displacement_lift"] == lift
    assert address == (3072 + lift) % M
    native_ok = ((post_phase + (1 << 62)) % Q) >> 63 == 1
    lut_ok = address >= 2048
    assert record["native_first_bit_decode_pass"] == native_ok
    assert record["conditional_lut_address_pass"] == lut_ok
    return dict(
        status="CONDITIONAL_CLIENT_ARITHMETIC_CLOSURE",
        public_coefficients_and_domains_pass=True,
        phase_component_modular_closure_pass=True,
        native_first_bit_decode_pass=native_ok,
        conditional_lut_address_pass=lut_ok,
        selected_prefix_gate_pass=native_ok and lut_ok,
        direct_address=address,
        displacement_lift=lift,
        a156_public_input=export,
        independently_attested_client_aggregates=False,
        actual_secret_key_membership_attested=False,
        full_n4_evaluation=False,
        blind_rotation_consumed=False,
        actual_sampler_p_fail=None,
        ideal_gaussian_integer_lifts_attested=False,
    )
