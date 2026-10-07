"""Independent P1 record arithmetic, with separately preserved frozen P0 replay."""

import argparse
import hashlib
import json
from pathlib import Path
import re

from audit import HERE, a158, sha, verify_source
from p0_replay import private, verify_envelope, verify_records as verify_p0_records

Q, N, ALPHA, DELTA = 1 << 64, 2048, 1 << 59, 1 << 60


def same(got, expected, label):
    assert type(got) is type(expected), label + " type"
    if type(expected) is dict:
        assert got.keys() == expected.keys(), label + " keys"
        for key in expected:
            same(got[key], expected[key], label + "." + key)
    elif type(expected) is list:
        assert len(got) == len(expected), label + " length"
        for i, item in enumerate(expected):
            same(got[i], item, f"{label}[{i}]")
    else:
        assert got == expected, label


def pairs(items):
    result = {}
    for key, value in items:
        assert key not in result, "duplicate JSON key"
        result[key] = value
    return result


def no_float(_):
    raise AssertionError("float or nonfinite JSON value")


def read(path):
    private(path)
    return json.loads(
        path.read_text(),
        object_pairs_hook=pairs,
        parse_float=no_float,
        parse_constant=no_float,
    )


def native(record, count):
    assert type(record) is dict and record.keys() == {"words_hex", "sha256"}
    assert type(record["words_hex"]) is list and len(record["words_hex"]) == count
    assert all(
        type(x) is str and re.fullmatch("[0-9a-f]{16}", x) for x in record["words_hex"]
    )
    words = [int(x, 16) for x in record["words_hex"]]
    same(record["sha256"], a158.digest_words(words), "ciphertext digest")
    return words


def signed(x):
    return (x + Q // 2) % Q - Q // 2


def raw_lut_value(address):
    assert type(address) is int and 0 <= address < 2 * N
    # Cached fft64 BR computes X^(-b+sum a_i*s_i). At degree0 the input
    # coefficient is +address; every N-degree wrap flips the constant body's sign.
    return (-ALPHA if address < N else ALPHA) % Q


def degree_zero_sample(rotated):
    assert len(rotated) == 2 * N
    return [rotated[0]] + [(-rotated[N - i]) % Q for i in range(1, N)] + [rotated[N]]


def check_key_binding(binding, p0_binding):
    same(binding["schema"], "a166.p1-key-binding.v1", "P1 key schema")
    same(binding["p0_bindings"], p0_binding, "P1 binds existing P0 keyset")
    bsk_hash = binding["fourier_bsk_re_im_f64le_sha256"]
    assert type(bsk_hash) is str and re.fullmatch("[0-9a-f]{64}", bsk_hash)
    keyset = hashlib.sha256(
        b"A166-KEYSET-V1\0"
        + bytes.fromhex(p0_binding["keyset_id"])
        + bytes.fromhex(bsk_hash)
    ).hexdigest()
    same(
        binding,
        dict(
            schema="a166.p1-key-binding.v1",
            p0_bindings=p0_binding,
            fourier_bsk_re_im_f64le_sha256=bsk_hash,
            p1_keyset_id=keyset,
            secret_key_membership_attested=False,
        ),
        "P1 full key binding",
    )


def verify_p1(record, p0, p0_completed, binding):
    check_key_binding(binding, p0["bindings"])
    same(record["bindings"], binding, "P1 key identity")
    same(
        record["p0_snapshot"],
        dict(schema="a166.frozen-p0-snapshot.v1", trace=p0, completed=p0_completed),
        "unmodified P0 snapshot",
    )
    constants = dict(
        schema="a166.first_low_p1_trace.v1",
        kind="client_observed",
        counts=dict(ordinary_ks=1, configured_ms=1, blind_rotations=1),
        counter_scope="producer post-call increments; not library-internal instrumentation",
        consumed_input_origin="same retained Standard lazy-MS object; no second KS/MS",
        extraction_degree=0,
        public_output_add_words=ALPHA,
        expected_fixture_bit=1,
        output_delta_words=DELTA,
        client_key_membership_attested=False,
        full_n4_evaluation=False,
        actual_sampler_p_fail=None,
        fixed_key_p_fail=None,
        pipeline_p_fail=None,
    )
    for key, value in constants.items():
        same(record[key], value, key)
    switched = dict(
        log_modulus=12,
        body_degree=p0["actual_body_degree"],
        mask_degrees=p0["actual_mask_degrees"],
    )
    same(record["switched_before"], switched, "retained switched input before")
    same(record["switched_after"], switched, "retained switched input after")
    initial = native(record["input_accumulator"], 2 * N)
    same(
        initial,
        [0] * N + [Q - ALPHA] * N,
        "exact negative constant trivial accumulator",
    )
    same(
        record["accumulator_body_u64le_sha256"],
        a158.digest_words(initial[N:]),
        "actual LUT bytes",
    )
    rotated = native(record["rotated_accumulator"], 2 * N)
    raw = native(record["raw_sample"], N + 1)
    output = native(record["output"], N + 1)
    client = record["client"]
    phase_fields = (
        "raw_mask_dot_words",
        "output_mask_dot_words",
        "raw_phase_words",
        "output_phase_words",
    )
    for key in phase_fields:
        assert type(client[key]) is int and 0 <= client[key] < Q, key
    for key in (
        "raw_error_centered_lift",
        "output_error_vs_fixture_centered_lift",
        "decoded_delta60",
    ):
        assert type(client[key]) is int, key
    assert client.keys() == set(phase_fields) | {
        "raw_error_centered_lift",
        "output_error_vs_fixture_centered_lift",
        "decoded_delta60",
    }
    raw_phase = (raw[-1] - client["raw_mask_dot_words"]) % Q
    output_phase = (output[-1] - client["output_mask_dot_words"]) % Q
    same(client["raw_phase_words"], raw_phase, "raw phase arithmetic")
    same(client["output_phase_words"], output_phase, "output phase arithmetic")
    # Same recorded mask under the same claimed large key has the same mask dot.
    if raw[:-1] == output[:-1]:
        same(
            client["output_mask_dot_words"],
            client["raw_mask_dot_words"],
            "same mask provenance",
        )
    address = p0["client"]["direct_address"]
    same(record["actual_address"], address, "actual P0 address")
    ideal_raw = raw_lut_value(address)
    same(
        record["ideal_raw_at_actual_address_words"],
        ideal_raw,
        "negacyclic actual-address LUT",
    )
    same(
        record["ideal_output_at_actual_address_words"],
        (ideal_raw + ALPHA) % Q,
        "post-add ideal",
    )
    raw_error = signed(raw_phase - ideal_raw)
    output_error = signed(output_phase - DELTA)
    decoded = ((output_phase + ALPHA) % Q) >> 60
    same(client["raw_error_centered_lift"], raw_error, "raw modular error")
    same(
        client["output_error_vs_fixture_centered_lift"],
        output_error,
        "semantic modular error",
    )
    same(client["decoded_delta60"], decoded, "nearest delta60 decode")
    expected_output = raw[:-1] + [(raw[-1] + ALPHA) % Q]
    predicates = dict(
        p0_prefix_pass=address >= N,
        retained_ms_input_unchanged=record["switched_before"]
        == record["switched_after"],
        degree0_extraction_matches_rotated=raw == degree_zero_sample(rotated),
        output_only_public_add=output == expected_output,
        raw_error_inside_actual_lut_decode_cell=-ALPHA <= raw_error < ALPHA,
        raw_to_output_phase_addition=output_phase == (raw_phase + ALPHA) % Q,
        output_decodes_fixture_bit=decoded == 1,
    )
    same(record["predicates"], predicates, "independently recomputed predicates")
    same(
        record["p1_selected_consumer_gate_pass"],
        all(predicates.values()),
        "P1 observed outcome",
    )
    expected_keys = set(constants) | {
        "bindings",
        "p0_snapshot",
        "switched_before",
        "switched_after",
        "accumulator_body_u64le_sha256",
        "input_accumulator",
        "rotated_accumulator",
        "raw_sample",
        "output",
        "actual_address",
        "ideal_raw_at_actual_address_words",
        "ideal_output_at_actual_address_words",
        "client",
        "predicates",
        "p1_selected_consumer_gate_pass",
    }
    assert record.keys() == expected_keys, "P1 exact schema"
    return dict(
        status="P1_RECORD_ARITHMETIC_CONSISTENT",
        predicates=predicates,
        p1_selected_consumer_gate_pass=all(predicates.values()),
        counts=constants["counts"],
        raw_cell_observation_not_tail_bound=True,
        same_object_source_binding_not_runtime_identity_attestation=True,
        independently_attested_client_mask_dots=False,
        independently_attested_bootstrap_key_membership=False,
        actual_sampler_p_fail=None,
        fixed_key_p_fail=None,
        pipeline_p_fail=None,
        full_n4_evaluation=False,
    )


def verify_completion(record):
    same(
        record,
        dict(
            status="P1_SINGLE_RETAINED_MS_CONSUMER_PASS",
            ordinary_ks=1,
            configured_ms=1,
            blind_rotations=1,
            p0_prefix_pass=True,
            p1_selected_consumer_gate_pass=True,
            actual_sampler_p_fail=None,
            fixed_key_p_fail=None,
            pipeline_p_fail=None,
            independent_replay_pending=True,
        ),
        "terminal P1 completion",
    )


def replay(run, expected_binary):
    source = verify_source()
    private(run.parent, directory=True)
    private(run, directory=True)
    assert run == run.resolve(), "canonical producer run"
    names = [
        "trace.json",
        "before-ks.json",
        "key-binding.json",
        "prepared.json",
        "started.json",
        "p0-completed.json",
        "p1-key-binding.json",
        "p1-trace.json",
        "completed.json",
        "exit.json",
        "child.json",
    ]
    records = {name: read(run / name) for name in names}
    verify_envelope(run, expected_binary, source, records)
    binary = HERE / "candidate/target-a166-only/release/a166_first_ks_prefix"
    assert not binary.is_symlink() and sha(binary) == expected_binary
    for name in ("stdout.log", "stderr.log"):
        private(run / name)
        same(
            records["exit.json"][name.replace(".log", "_sha256")],
            sha(run / name),
            "terminal log digest",
        )
    same(records["trace.json"]["fixture"], a158.fixture(), "strict fixed P0 fixture")
    p0 = verify_p0_records(*(records[name] for name in names[:6]))
    p1 = verify_p1(
        records["p1-trace.json"],
        records["trace.json"],
        records["p0-completed.json"],
        records["p1-key-binding.json"],
    )
    assert p1["p1_selected_consumer_gate_pass"], "P1 failed; no promotion"
    verify_completion(records["completed.json"])
    return dict(
        schema="a166.p1-validation.v1",
        status="PASS_P0_AND_P1_RECORD_CONSISTENCY",
        p0=p0,
        p1=p1,
        a156_public_input=p0["a156_public_input"],
        runtime_files_sha256={name: sha(run / name) for name in names},
        source_sha256=source,
        binary_sha256=expected_binary,
        actual_sampler_p_fail=None,
        fixed_key_p_fail=None,
        pipeline_p_fail=None,
        actual_os_execution_attested=False,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    from run_gate import write_new

    write_new(args.output, replay(args.run, args.binary_sha256))


if __name__ == "__main__":
    main()
