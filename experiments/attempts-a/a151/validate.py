"""Private local record validation, not remote attestation or recovery of unavailable row phases."""

import re

Q = 1 << 64
ORDER = [
    "meta",
    "key_bound",
    "rows_measured",
    "prediction_before_pfks",
    "comparison",
    "summary",
]


def digest(value):
    assert isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value), (
        "invalid digest"
    )
    return value


def prediction(value):
    assert set(value) == {
        "modular",
        "centered",
        "lifted",
        "wrap_quotient",
        "distinct_nonzero_row_functionals",
    }
    fields = {}
    for field in ["modular", "centered", "lifted", "wrap_quotient"]:
        assert isinstance(value[field], str) and str(int(value[field])) == value[field]
        fields[field] = int(value[field])
    assert 0 <= fields["modular"] < Q
    assert -Q // 2 <= fields["centered"] < Q // 2
    assert fields["centered"] == (fields["modular"] + Q // 2) % Q - Q // 2
    assert fields["lifted"] == fields["centered"] + fields["wrap_quotient"] * Q
    assert type(value["distinct_nonzero_row_functionals"]) is int
    assert 0 <= value["distinct_nonzero_row_functionals"] <= 2049
    return fields


def validate_records(records, expected, synthetic=False):
    assert [r.get("record") for r in records] == ORDER, (
        "incomplete/duplicate/out-of-order records"
    )
    meta, key, rows, before, comparison, summary = records
    assert meta["artifact"] == "A151" and meta["tfhe"] == "0.11.3"
    assert meta["evidence_kind"] == (
        "SYNTHETIC_REPLAY" if synthetic else "RUNTIME_PRIVATE"
    )
    for field in ["source_id", "binary_sha256", "params_sha256", "observer_sha256"]:
        assert digest(meta[field]) == expected[field], field
    assert (
        type(meta["process_id"]) is int
        and meta["process_id"] == expected["process_id"] > 0
    )
    key_id = digest(key["key_sha256"])
    assert digest(key["function_sha256"]) == expected["function_sha256"]
    assert (
        key["scalar_function"] == "identity"
        and key["effective_function"] == "W0_radius63"
    )
    assert (
        key["row_levels"],
        key["pfks_base_log"],
        key["pfks_levels"],
        key["key_words"],
    ) == (2049, 24, 1, 2049 * 4096)
    assert key["base_parameters_equal"] is True
    assert (
        rows["key_sha256"] == before["key_sha256"] == comparison["key_sha256"] == key_id
    )
    assert digest(rows["kernel_sha256"]) == expected["kernel_sha256"]
    assert rows["row_levels"] == 2049 and rows["targets"] == [0]
    assert rows["payload_exists"] is False and rows["pfks_output_exists"] is False
    assert (
        rows["raw_row_data_persisted"] is False
        and rows["samples_client_memory_only"] is True
    )
    assert (
        before["fixture"],
        before["fixture_index"],
        before["payload_side"],
        before["payload_lane"],
    ) == ("accept_threshold_left", 2, "left", 0)
    assert (before["message"], before["delta_log"], before["target"]) == (3, 59, 0)
    assert before["nontrivial_payload"] is True and before["pfks_calls_so_far"] == 0
    payload_id = digest(before["payload_sha256"])
    assert comparison["payload_sha256"] == payload_id
    pred = prediction(before["prediction"])
    assert comparison["prediction_after"] == before["prediction"]
    assert digest(comparison["output_sha256"]) != digest(
        comparison["changed_output_sha256"]
    )
    observed = int(comparison["observed_aggregate"])
    changed = int(comparison["changed_observed_aggregate"])
    assert 0 <= observed < Q and 0 <= changed < Q
    assert observed == pred["modular"] and changed == (observed + 1) % Q
    assert (
        comparison["positive_equal"] is True
        and comparison["changed_output_equal"] is False
    )
    for field in [
        "prediction_fixed",
        "observed_changes_by_one",
        "key_unchanged",
        "payload_unchanged",
    ]:
        assert comparison[field] is True, field
    assert (comparison["pfks_calls"], comparison["other_server_crypto_calls"]) == (1, 0)
    assert summary["status"] == "PASS_ONE_PAYLOAD_ROW_IDENTITY"
    assert (
        summary["row_levels"],
        summary["targets"],
        summary["payloads"],
        summary["pfks_calls"],
    ) == (2049, 1, 1, 1)
    assert summary["changed_output_control_pass"] is True
    assert summary["tails"] == summary["covariance"] == "OPEN"
    assert (
        summary["support_and_final_correctness"] == "NOT_TESTED_no_BR_selector_or_scan"
    )
    return {
        "status": "SYNTHETIC_REPLAY_PASS"
        if synthetic
        else "ONE_PAYLOAD_ROW_IDENTITY_RECORD_PASS",
        "records": 6,
        "row_levels": 2049,
        "targets": 1,
        "pfks_calls": 1,
        "actual_crypto_proved_by_parser": False,
        "tails": "OPEN",
    }
