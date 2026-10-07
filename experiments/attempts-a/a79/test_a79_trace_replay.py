#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import a79_trace_replay as replay  # noqa: E402


FP = replay.A44_PARAMETER_FINGERPRINT_SHA256
ENC = {
    "label": "p16",
    "delta_log": 59,
    "torus_period": 32,
    "logical_modulus": 16,
    "negacyclic_signed": False,
}
DOMAIN = {
    "parameter_fingerprint": FP,
    "keyset_id": "a79-test-keyset",
    "lwe_role": replay.LweRole.BIG.value,
    "lwe_dimension": replay.A44_BIG_LWE_DIMENSION,
    "ciphertext_modulus": replay.A44_CIPHERTEXT_MODULUS,
}
BINARY_BYTES = b"a79 independently bound instrumented binary fixture\n"
SOURCE_BYTES = b"a79 independently reviewed instrumented source fixture\n"
PARAMETER_BYTES = (
    b"tfhe-rs=0.11.3;symbol=V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;"
    b"bootstrap=classic_ks_pbs;lwe_dimension=859;glwe_dimension=1;"
    b"polynomial_size=2048;lwe_noise=gaussian_stddev_2.3088161607134664e-6;"
    b"glwe_noise=gaussian_stddev_2.845267479601915e-15;pbs_base_log=23;pbs_level=1;"
    b"ks_base_log=3;ks_level=5;message_modulus=2;carry_modulus=8;max_noise_level=15;"
    b"log2_p_fail=-64.088;ciphertext_modulus=native;encryption_key_choice=Big"
)


def valid_trace() -> list[dict[str, object]]:
    return [
        {
            "seq": 0,
            "op": "meta",
            "schema": replay.SCHEMA,
            "graph_id": "fixture",
            "parameter_fingerprint": FP,
            "expected_ledger": {
                "scan": {"blind_rotations": 1, "key_switches": 1, "marginals": 2},
                "total": {"blind_rotations": 1, "key_switches": 1, "marginals": 2},
            },
        },
        {
            "seq": 1,
            "op": "input",
            "output": "x",
            "encoding": dict(ENC),
            "crypto_domain": dict(DOMAIN),
            "wire_kind": replay.WireKind.A44_SHORTINT.value,
            "shortint_degree": 1,
            "reachable_overapprox": [0, 1],
            "source_contract": "fresh_encryption",
            "official_noise_level": 1,
        },
        {
            "seq": 2,
            "op": "linear",
            "output": "phase",
            "terms": [{"value": "x", "coefficient": 1}],
            "public_offset": 2,
            "reachable_overapprox": [2, 3],
        },
        {
            "seq": 3,
            "op": "keyswitch",
            "stage": "scan",
            "input": "phase",
            "output": "small",
            "key_switch_id": "ks:0",
        },
        {
            "seq": 4,
            "op": "pbs",
            "stage": "scan",
            "input": "small",
            "blind_rotation_id": "br:0",
            "accumulator_id": "acc:0",
            "pbs_mode": replay.PbsMode.RAW_BR_SMALL_INPUT.value,
            "strict_margin_radius": 63,
            "strict_margin_unit": replay.MarginUnit.ACCUMULATOR_ROTATION_INDEX.value,
            "input_max_degree": None,
            "outputs": [
                {
                    "id": "low",
                    "encoding": dict(ENC),
                    "reachable_overapprox": [0, 1],
                    "sample_degree": 0,
                    "shortint_degree": None,
                },
                {
                    "id": "high",
                    "encoding": dict(ENC),
                    "reachable_overapprox": [0, 1],
                    "sample_degree": 1024,
                    "shortint_degree": None,
                },
            ],
        },
        {
            "seq": 5,
            "op": "terminal",
            "outputs": ["low", "high"],
            "claim_model_obligations_closed": False,
        },
    ]


def direct_terminal_trace(
    *,
    source_contract: str,
    reachable: list[int],
    official_noise_level: int | None,
    claim_model_obligations_closed: bool,
) -> list[dict[str, object]]:
    shortint_degree = max(reachable) if reachable else 0
    return [
        {
            "seq": 0,
            "op": "meta",
            "schema": replay.SCHEMA,
            "graph_id": "direct-terminal-fixture",
            "parameter_fingerprint": FP,
            "expected_ledger": {
                "total": {
                    "blind_rotations": 0,
                    "key_switches": 0,
                    "marginals": 0,
                }
            },
        },
        {
            "seq": 1,
            "op": "input",
            "output": "x",
            "encoding": dict(ENC),
            "crypto_domain": dict(DOMAIN),
            "wire_kind": replay.WireKind.A44_SHORTINT.value,
            "shortint_degree": shortint_degree,
            "reachable_overapprox": reachable,
            "source_contract": source_contract,
            "official_noise_level": official_noise_level,
        },
        {
            "seq": 2,
            "op": "terminal",
            "outputs": ["x"],
            "claim_model_obligations_closed": claim_model_obligations_closed,
        },
    ]


def trusted_manifest(trace: list[dict[str, object]]) -> dict[str, object]:
    accumulators: dict[str, object] = {}
    for event in trace:
        if event["op"] != "pbs":
            continue
        accumulator_id = event["accumulator_id"]
        assert isinstance(accumulator_id, str)
        outputs = event["outputs"]
        assert isinstance(outputs, list)
        pbs_mode = event["pbs_mode"]
        if pbs_mode == replay.PbsMode.RAW_BR_SMALL_INPUT.value:
            input_domain = {
                **DOMAIN,
                "lwe_role": replay.LweRole.SMALL.value,
                "lwe_dimension": replay.A44_SMALL_LWE_DIMENSION,
            }
            input_wire_kind = replay.WireKind.RAW_CORE_LWE.value
            input_shortint_degree = None
            input_reachable = [2, 3]
            sample_extraction_stride = None
        else:
            input_domain = dict(DOMAIN)
            input_wire_kind = replay.WireKind.A44_SHORTINT.value
            input_shortint_degree = 1
            input_reachable = [0, 1]
            input_max_degree = event["input_max_degree"]
            assert isinstance(input_max_degree, int)
            sample_extraction_stride = (input_max_degree + 1) * (2048 // 16)
        accumulators[accumulator_id] = {
            "pbs_mode": pbs_mode,
            "input_encoding": dict(ENC),
            "input_crypto_domain": input_domain,
            "input_wire_kind": input_wire_kind,
            "input_shortint_degree": input_shortint_degree,
            "input_reachable_overapprox": input_reachable,
            "input_max_degree": event["input_max_degree"],
            "strict_margin_radius": event["strict_margin_radius"],
            "strict_margin_unit": event["strict_margin_unit"],
            "sample_extraction_stride": sample_extraction_stride,
            "samples": [
                {
                    "sample_degree": output["sample_degree"],
                    "encoding": output["encoding"],
                    "reachable_overapprox": output["reachable_overapprox"],
                    "shortint_degree": output["shortint_degree"],
                }
                for output in outputs
            ],
        }
    meta = trace[0]
    accumulator_bytes = json.dumps(
        accumulators,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    assert hashlib.sha256(PARAMETER_BYTES).hexdigest() == FP
    return {
        "schema": replay.MANIFEST_SCHEMA,
        "trace_schema": replay.SCHEMA,
        "graph_id": meta["graph_id"],
        "parameter_fingerprint": meta["parameter_fingerprint"],
        "expected_ledger": copy.deepcopy(meta["expected_ledger"]),
        "trace_sha256": replay.canonical_trace_sha256(trace),
        "polynomial_size": 2048,
        "max_noise_level": 15,
        "accumulators": accumulators,
        "artifacts": [
            {
                "id": "binary",
                "role": "instrumented_binary",
                "sha256": hashlib.sha256(BINARY_BYTES).hexdigest(),
            },
            {
                "id": "source",
                "role": "instrumented_source",
                "sha256": hashlib.sha256(SOURCE_BYTES).hexdigest(),
            },
            {
                "id": "parameter",
                "role": "parameter_spec",
                "sha256": hashlib.sha256(PARAMETER_BYTES).hexdigest(),
            },
            {
                "id": "accumulators",
                "role": "accumulator_spec",
                "sha256": hashlib.sha256(accumulator_bytes).hexdigest(),
            },
        ],
    }


def write_bound_artifacts(
    directory: Path,
    manifest: dict[str, object],
) -> dict[str, Path]:
    accumulator_bytes = json.dumps(
        manifest["accumulators"],
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    payloads = {
        "binary": BINARY_BYTES,
        "source": SOURCE_BYTES,
        "parameter": PARAMETER_BYTES,
        "accumulators": accumulator_bytes,
    }
    result: dict[str, Path] = {}
    for artifact_id, payload in payloads.items():
        path = directory / artifact_id
        path.write_bytes(payload)
        result[artifact_id] = path
    return result


class A79TraceReplayTests(unittest.TestCase):
    def assert_rejected(self, trace: list[dict[str, object]], pattern: str) -> None:
        with self.assertRaisesRegex(replay.TraceReplayError, pattern):
            replay.replay_events(trace)

    def test_valid_raw_trace_preserves_correlation_and_open_obligations(self) -> None:
        result = replay.replay_events(valid_trace())
        self.assertEqual(
            result["status"], "PASS_DECLARATIVE_TRACE_REPLAY_OPEN_TRUST_BINDING"
        )
        self.assertEqual(result["trust_binding"]["status"], "OPEN_NO_EXTERNAL_MANIFEST")
        self.assertEqual(
            result["ledger"]["total"],
            {
                "blind_rotations": 1,
                "key_switches": 1,
                "marginals": 2,
            },
        )
        self.assertEqual(result["terminal_model_obligations_closed"], [False, False])
        self.assertEqual(result["terminal_correlation_groups"][0], ["br:0"])
        self.assertEqual(result["terminal_correlation_groups"][1], ["br:0"])
        self.assertIn(
            "br:0:accumulator:acc:0:sample:0", result["terminal_open_obligations"][0]
        )
        self.assertIn(
            "br:0:accumulator:acc:0:sample:1024", result["terminal_open_obligations"][1]
        )

    def test_missing_producer_is_rejected(self) -> None:
        trace = valid_trace()
        trace[2]["terms"] = [{"value": "missing", "coefficient": 1}]
        self.assert_rejected(trace, "missing producer")

    def test_duplicate_producer_is_rejected(self) -> None:
        trace = valid_trace()
        trace[2]["output"] = "x"
        self.assert_rejected(trace, "duplicate producer")

    def test_encoding_mismatch_is_rejected(self) -> None:
        trace = valid_trace()
        trace.insert(
            2,
            {
                "seq": 2,
                "op": "input",
                "output": "other",
                "encoding": {
                    "label": "other",
                    "delta_log": 58,
                    "torus_period": 64,
                    "logical_modulus": 32,
                    "negacyclic_signed": False,
                },
                "crypto_domain": dict(DOMAIN),
                "wire_kind": replay.WireKind.A44_SHORTINT.value,
                "shortint_degree": 1,
                "reachable_overapprox": [0, 1],
                "source_contract": "fresh_encryption",
                "official_noise_level": 1,
            },
        )
        for index, event in enumerate(trace):
            event["seq"] = index
        trace[3]["terms"] = [
            {"value": "x", "coefficient": 1},
            {"value": "other", "coefficient": 1},
        ]
        self.assert_rejected(trace, "noncanonical encoding")

    def test_declared_reachable_drift_is_rejected(self) -> None:
        trace = valid_trace()
        trace[2]["reachable_overapprox"] = [2, 4]
        self.assert_rejected(trace, "does not replay")

    def test_duplicate_sample_degree_is_rejected(self) -> None:
        trace = valid_trace()
        outputs = trace[4]["outputs"]
        assert isinstance(outputs, list)
        outputs[1]["sample_degree"] = 0
        with self.assertRaisesRegex(ValueError, "sample degrees must be distinct"):
            replay.replay_events(trace)

    def test_reused_blind_rotation_id_is_rejected(self) -> None:
        trace = valid_trace()
        duplicate = copy.deepcopy(trace[4])
        duplicate["seq"] = 5
        duplicate["outputs"][0]["id"] = "again-low"
        duplicate["outputs"][1]["id"] = "again-high"
        trace.insert(5, duplicate)
        trace[6]["seq"] = 6
        self.assert_rejected(trace, "reused blind_rotation_id")

    def test_conditional_output_cannot_be_claimed_closed(self) -> None:
        trace = valid_trace()
        trace[-1]["claim_model_obligations_closed"] = True
        self.assert_rejected(trace, "conditional output")

    def test_direct_conditional_input_cannot_self_certify_as_closed(self) -> None:
        trace = direct_terminal_trace(
            source_contract="conditional_external",
            reachable=[0, 1],
            official_noise_level=None,
            claim_model_obligations_closed=True,
        )
        self.assert_rejected(trace, "conditional output")

    def test_direct_conditional_input_is_reported_open(self) -> None:
        trace = direct_terminal_trace(
            source_contract="conditional_external",
            reachable=[0, 1],
            official_noise_level=None,
            claim_model_obligations_closed=False,
        )
        result = replay.replay_events(trace)
        self.assertEqual(
            result["status"], "PASS_DECLARATIVE_TRACE_REPLAY_OPEN_TRUST_BINDING"
        )
        self.assertEqual(
            result["terminal_open_contracts"],
            [[replay.Contract.CONDITIONAL.value]],
        )

    def test_official_pbs_declaration_does_not_discharge_accumulator_mapping(
        self,
    ) -> None:
        trace = valid_trace()
        # The checked high-level API consumes a shortint big-LWE ciphertext and
        # accounts for its internal KS itself, so remove the raw phase and KS.
        trace.pop(2)
        trace.pop(2)
        trace[2]["seq"] = 2
        trace[2]["input"] = "x"
        trace[2]["pbs_mode"] = replay.PbsMode.CHECKED_CLASSIC_KS_PBS.value
        trace[2]["input_max_degree"] = 7
        for output in trace[2]["outputs"]:
            output["shortint_degree"] = 1
        trace[3]["seq"] = 3
        trace[-1]["claim_model_obligations_closed"] = True
        self.assert_rejected(trace, "conditional output")

    def test_public_trivial_must_be_one_known_plaintext(self) -> None:
        trace = direct_terminal_trace(
            source_contract="public_trivial",
            reachable=[0, 1],
            official_noise_level=0,
            claim_model_obligations_closed=True,
        )
        self.assert_rejected(trace, "one known plaintext")

    def test_singleton_public_trivial_can_be_closed(self) -> None:
        trace = direct_terminal_trace(
            source_contract="public_trivial",
            reachable=[1],
            official_noise_level=0,
            claim_model_obligations_closed=True,
        )
        result = replay.replay_events(trace)
        self.assertEqual(
            result["status"], "PASS_DECLARATIVE_TRACE_REPLAY_OPEN_TRUST_BINDING"
        )
        self.assertEqual(result["terminal_model_obligations_closed"], [True])

    def test_manifest_binds_trace_accumulator_and_external_artifact(self) -> None:
        trace = valid_trace()
        manifest = trusted_manifest(trace)
        with tempfile.TemporaryDirectory() as directory:
            artifacts = write_bound_artifacts(Path(directory), manifest)
            result = replay.replay_events(
                trace,
                trusted_manifest=manifest,
                expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
                artifact_bindings=artifacts,
            )
        self.assertEqual(
            result["status"], "PASS_DECLARATIVE_MANIFEST_DIGEST_BOUND_OPEN_OBLIGATIONS"
        )
        self.assertEqual(
            result["trust_binding"]["status"],
            "PASS_DIGEST_MATCH_ONLY_NOT_EXECUTION_ATTESTATION",
        )
        self.assertEqual(
            result["trust_binding"]["trace_sha256"],
            replay.canonical_trace_sha256(trace),
        )
        self.assertEqual(
            result["trust_binding"]["manifest_sha256"],
            replay.canonical_manifest_sha256(manifest),
        )

    def test_manifest_bound_closed_trace_is_reported_separately(self) -> None:
        trace = direct_terminal_trace(
            source_contract="public_trivial",
            reachable=[1],
            official_noise_level=0,
            claim_model_obligations_closed=True,
        )
        manifest = trusted_manifest(trace)
        with tempfile.TemporaryDirectory() as directory:
            artifacts = write_bound_artifacts(Path(directory), manifest)
            result = replay.replay_events(
                trace,
                trusted_manifest=manifest,
                expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
                artifact_bindings=artifacts,
            )
        self.assertEqual(
            result["status"], "PASS_DECLARATIVE_MANIFEST_DIGEST_BOUND_MODEL_CLOSED"
        )

    def test_manifest_cannot_promote_standalone_keyswitch_to_closed(self) -> None:
        trace = direct_terminal_trace(
            source_contract="fresh_encryption",
            reachable=[0, 1],
            official_noise_level=1,
            claim_model_obligations_closed=False,
        )
        trace.insert(
            2,
            {
                "seq": 2,
                "op": "keyswitch",
                "stage": "only_ks",
                "input": "x",
                "output": "after_ks",
                "key_switch_id": "ks:only",
            },
        )
        trace[0]["expected_ledger"] = {
            "only_ks": {
                "blind_rotations": 0,
                "key_switches": 1,
                "marginals": 0,
            },
            "total": {
                "blind_rotations": 0,
                "key_switches": 1,
                "marginals": 0,
            },
        }
        trace[-1]["seq"] = 3
        trace[-1]["outputs"] = ["after_ks"]
        trace[-1]["claim_model_obligations_closed"] = True
        manifest = trusted_manifest(trace)
        with tempfile.TemporaryDirectory() as directory:
            artifacts = write_bound_artifacts(Path(directory), manifest)
            with self.assertRaisesRegex(replay.TraceReplayError, "formally closed"):
                replay.replay_events(
                    trace,
                    trusted_manifest=manifest,
                    expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
                    artifact_bindings=artifacts,
                )

    def test_manifest_rejects_terminal_level_above_trusted_budget(self) -> None:
        trace = [
            {
                "seq": 0,
                "op": "meta",
                "schema": replay.SCHEMA,
                "graph_id": "over-budget-fixture",
                "parameter_fingerprint": FP,
                "expected_ledger": {
                    "total": {
                        "blind_rotations": 0,
                        "key_switches": 0,
                        "marginals": 0,
                    }
                },
            },
            {
                "seq": 1,
                "op": "input",
                "output": "x",
                "encoding": dict(ENC),
                "crypto_domain": dict(DOMAIN),
                "wire_kind": replay.WireKind.A44_SHORTINT.value,
                "shortint_degree": 1,
                "reachable_overapprox": [0, 1],
                "source_contract": "fresh_encryption",
                "official_noise_level": 1,
            },
            {
                "seq": 2,
                "op": "linear",
                "output": "over-budget",
                "terms": [{"value": "x", "coefficient": 16}],
                "reachable_overapprox": [0, 16],
            },
            {
                "seq": 3,
                "op": "terminal",
                "outputs": ["over-budget"],
                "claim_model_obligations_closed": True,
            },
        ]
        manifest = trusted_manifest(trace)
        with tempfile.TemporaryDirectory() as directory:
            artifacts = write_bound_artifacts(Path(directory), manifest)
            with self.assertRaisesRegex(replay.TraceReplayError, "formally closed"):
                replay.replay_events(
                    trace,
                    trusted_manifest=manifest,
                    expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
                    artifact_bindings=artifacts,
                )

    def test_manifest_cannot_raise_source_pinned_noise_budget(self) -> None:
        trace = direct_terminal_trace(
            source_contract="fresh_encryption",
            reachable=[0, 1],
            official_noise_level=1,
            claim_model_obligations_closed=False,
        )
        trace.insert(
            2,
            {
                "seq": 2,
                "op": "linear",
                "output": "over-budget",
                "terms": [{"value": "x", "coefficient": 16}],
                "reachable_overapprox": [0],
            },
        )
        trace[-1]["seq"] = 3
        trace[-1]["outputs"] = ["over-budget"]
        trace[-1]["claim_model_obligations_closed"] = True
        manifest = trusted_manifest(trace)
        manifest["max_noise_level"] = 16
        with tempfile.TemporaryDirectory() as directory:
            artifacts = write_bound_artifacts(Path(directory), manifest)
            with self.assertRaisesRegex(replay.TraceReplayError, "source-pinned A44"):
                replay.replay_events(
                    trace,
                    trusted_manifest=manifest,
                    expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
                    artifact_bindings=artifacts,
                )

    def test_manifest_cannot_raise_source_pinned_polynomial_size(self) -> None:
        trace = valid_trace()
        outputs = trace[4]["outputs"]
        assert isinstance(outputs, list)
        outputs[1]["sample_degree"] = 3000
        manifest = trusted_manifest(trace)
        manifest["polynomial_size"] = 4096
        with tempfile.TemporaryDirectory() as directory:
            artifacts = write_bound_artifacts(Path(directory), manifest)
            with self.assertRaisesRegex(replay.TraceReplayError, "source-pinned A44"):
                replay.replay_events(
                    trace,
                    trusted_manifest=manifest,
                    expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
                    artifact_bindings=artifacts,
                )

    def test_non_ascii_sha256_digits_are_rejected(self) -> None:
        trace = direct_terminal_trace(
            source_contract="public_trivial",
            reachable=[1],
            official_noise_level=0,
            claim_model_obligations_closed=True,
        )
        trace[0]["parameter_fingerprint"] = "٠" * 64
        self.assert_rejected(trace, "SHA-256 hex string")

    def test_ascii_but_wrong_a44_fingerprint_is_rejected_without_manifest(self) -> None:
        trace = direct_terminal_trace(
            source_contract="public_trivial",
            reachable=[1],
            official_noise_level=0,
            claim_model_obligations_closed=True,
        )
        trace[0]["parameter_fingerprint"] = "0" * 64
        self.assert_rejected(trace, "source-pinned A44")

    def test_schema_only_sample_degree_is_bounded_by_a44_polynomial(self) -> None:
        trace = valid_trace()
        trace[4]["outputs"][1]["sample_degree"] = replay.A44_POLYNOMIAL_SIZE
        self.assert_rejected(trace, "inside the A44 polynomial")

    def test_fresh_shortint_cannot_use_small_lwe_domain(self) -> None:
        trace = direct_terminal_trace(
            source_contract="fresh_encryption",
            reachable=[0, 1],
            official_noise_level=1,
            claim_model_obligations_closed=False,
        )
        trace[1]["crypto_domain"] = {
            **DOMAIN,
            "lwe_role": replay.LweRole.SMALL.value,
            "lwe_dimension": replay.A44_SMALL_LWE_DIMENSION,
        }
        self.assert_rejected(trace, "must use the big-LWE role")

    def test_repeated_parent_plaintext_relation_is_not_cartesianized(self) -> None:
        trace = direct_terminal_trace(
            source_contract="fresh_encryption",
            reachable=[0, 1],
            official_noise_level=1,
            claim_model_obligations_closed=False,
        )
        trace.insert(
            2,
            {
                "seq": 2,
                "op": "linear",
                "output": "zero",
                "terms": [
                    {"value": "x", "coefficient": 1},
                    {"value": "x", "coefficient": -1},
                ],
                "reachable_overapprox": [0],
            },
        )
        trace[-1]["seq"] = 3
        trace[-1]["outputs"] = ["zero"]
        trace[-1]["claim_model_obligations_closed"] = True
        result = replay.replay_events(trace)
        self.assertEqual(result["terminal_model_obligations_closed"], [True])
        self.assertEqual(result["terminal_official_noise_levels"], [0])

    def test_manifest_binds_accumulator_to_runtime_input_contract(self) -> None:
        trace = valid_trace()
        manifest = trusted_manifest(trace)
        manifest["accumulators"]["acc:0"]["input_reachable_overapprox"] = [1, 2]
        accumulator_bytes = json.dumps(
            manifest["accumulators"],
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        manifest["artifacts"][3]["sha256"] = hashlib.sha256(
            accumulator_bytes
        ).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            artifacts = write_bound_artifacts(Path(directory), manifest)
            with self.assertRaisesRegex(
                replay.TraceReplayError, "runtime input contract"
            ):
                replay.replay_events(
                    trace,
                    trusted_manifest=manifest,
                    expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
                    artifact_bindings=artifacts,
                )

    def test_manifest_artifact_roles_cannot_alias_or_be_nonstrings(self) -> None:
        trace = valid_trace()
        manifest = trusted_manifest(trace)
        manifest["artifacts"][0]["role"] = []
        with tempfile.TemporaryDirectory() as directory:
            artifacts = write_bound_artifacts(Path(directory), manifest)
            with self.assertRaisesRegex(
                replay.TraceReplayError, "unsupported manifest artifact role"
            ):
                replay.replay_events(
                    trace,
                    trusted_manifest=manifest,
                    expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
                    artifact_bindings=artifacts,
                )

        manifest = trusted_manifest(trace)
        with tempfile.TemporaryDirectory() as directory:
            artifacts = write_bound_artifacts(Path(directory), manifest)
            artifacts["binary"] = []
            with self.assertRaisesRegex(replay.TraceReplayError, "path-like"):
                replay.replay_events(
                    trace,
                    trusted_manifest=manifest,
                    expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
                    artifact_bindings=artifacts,
                )

        manifest = trusted_manifest(trace)
        with tempfile.TemporaryDirectory() as directory:
            artifacts = write_bound_artifacts(Path(directory), manifest)
            artifacts["binary"] = Path("x" * 5000)
            with self.assertRaisesRegex(replay.TraceReplayError, "cannot be inspected"):
                replay.replay_events(
                    trace,
                    trusted_manifest=manifest,
                    expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
                    artifact_bindings=artifacts,
                )

    def test_reused_accumulator_rejects_incompatible_runtime_input(self) -> None:
        trace = valid_trace()
        terminal = trace.pop()
        second_input = copy.deepcopy(trace[1])
        second_input.update(seq=5, output="y")
        second_linear = copy.deepcopy(trace[2])
        second_linear.update(
            seq=6,
            output="phase-second",
            terms=[{"value": "y", "coefficient": 1}],
            public_offset=3,
            reachable_overapprox=[3, 4],
        )
        second_keyswitch = copy.deepcopy(trace[3])
        second_keyswitch.update(
            seq=7,
            input="phase-second",
            output="small-second",
            key_switch_id="ks:second",
        )
        second_pbs = copy.deepcopy(trace[4])
        second_pbs.update(
            seq=8,
            input="small-second",
            blind_rotation_id="br:second",
        )
        second_pbs["outputs"][0]["id"] = "low-second"
        second_pbs["outputs"][1]["id"] = "high-second"
        terminal.update(
            seq=9,
            outputs=["low", "high", "low-second", "high-second"],
        )
        trace.extend(
            [second_input, second_linear, second_keyswitch, second_pbs, terminal]
        )
        trace[0]["expected_ledger"] = {
            "scan": {"blind_rotations": 2, "key_switches": 2, "marginals": 4},
            "total": {"blind_rotations": 2, "key_switches": 2, "marginals": 4},
        }

        manifest = trusted_manifest(valid_trace())
        manifest["expected_ledger"] = copy.deepcopy(trace[0]["expected_ledger"])
        manifest["trace_sha256"] = replay.canonical_trace_sha256(trace)
        with tempfile.TemporaryDirectory() as directory:
            artifacts = write_bound_artifacts(Path(directory), manifest)
            with self.assertRaisesRegex(
                replay.TraceReplayError, "runtime input contract"
            ):
                replay.replay_events(
                    trace,
                    trusted_manifest=manifest,
                    expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
                    artifact_bindings=artifacts,
                )

        manifest = trusted_manifest(trace)
        with tempfile.TemporaryDirectory() as directory:
            artifacts = write_bound_artifacts(Path(directory), manifest)
            artifacts["source"] = artifacts["binary"]
            manifest["artifacts"][1]["sha256"] = manifest["artifacts"][0]["sha256"]
            with self.assertRaisesRegex(replay.TraceReplayError, "alias the same file"):
                replay.replay_events(
                    trace,
                    trusted_manifest=manifest,
                    expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
                    artifact_bindings=artifacts,
                )

    def test_manifest_status_says_declarative_and_not_attested(self) -> None:
        trace = valid_trace()
        manifest = trusted_manifest(trace)
        with tempfile.TemporaryDirectory() as directory:
            artifacts = write_bound_artifacts(Path(directory), manifest)
            result = replay.replay_events(
                trace,
                trusted_manifest=manifest,
                expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
                artifact_bindings=artifacts,
            )
        self.assertTrue(result["status"].startswith("PASS_DECLARATIVE_"))
        self.assertFalse(result["execution_attested"])
        self.assertEqual(
            result["trust_binding"]["status"],
            "PASS_DIGEST_MATCH_ONLY_NOT_EXECUTION_ATTESTATION",
        )
        self.assertTrue(result["trust_binding"]["artifact_roles_self_declared"])

    def test_unknown_event_and_nested_fields_are_rejected(self) -> None:
        for event_index, field, value in (
            (0, "unknown_meta", True),
            (1, "source_contract_verified", False),
            (2, "unknown_linear", True),
            (3, "unknown_keyswitch", True),
            (4, "unknown_pbs", True),
            (5, "unrecognized_terminal_assertion", "NOT_CLOSED"),
        ):
            with self.subTest(event_index=event_index, field=field):
                trace = valid_trace()
                trace[event_index][field] = value
                self.assert_rejected(trace, "schema mismatch")

        trace = valid_trace()
        trace[1]["encoding"]["semantic_label"] = "unvalidated"
        self.assert_rejected(trace, "encoding must contain exactly")

        trace = valid_trace()
        trace[2]["terms"][0]["unvalidated"] = True
        self.assert_rejected(trace, "linear term must contain exactly")

        trace = valid_trace()
        trace[4]["outputs"][0]["unvalidated"] = True
        self.assert_rejected(trace, "PBS output must contain exactly")

        for malformed_operation in ([], {}):
            with self.subTest(malformed_operation=malformed_operation):
                trace = valid_trace()
                trace[2]["op"] = malformed_operation
                self.assert_rejected(trace, "unsupported operation")

    def test_manifest_trace_digest_rejects_any_event_drift(self) -> None:
        trace = valid_trace()
        manifest = trusted_manifest(trace)
        trace[3]["key_switch_id"] = "ks:drift"
        with tempfile.TemporaryDirectory() as directory:
            artifacts = write_bound_artifacts(Path(directory), manifest)
            with self.assertRaisesRegex(
                replay.TraceReplayError, "canonical trace hash"
            ):
                replay.replay_events(
                    trace,
                    trusted_manifest=manifest,
                    expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
                    artifact_bindings=artifacts,
                )

    def test_manifest_accumulator_map_must_match_trace(self) -> None:
        trace = valid_trace()
        manifest = trusted_manifest(trace)
        manifest["accumulators"]["acc:0"]["samples"][0]["reachable_overapprox"] = [1]
        with tempfile.TemporaryDirectory() as directory:
            artifacts = write_bound_artifacts(Path(directory), manifest)
            with self.assertRaisesRegex(replay.TraceReplayError, "output map"):
                replay.replay_events(
                    trace,
                    trusted_manifest=manifest,
                    expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
                    artifact_bindings=artifacts,
                )

    def test_manifest_bounds_sample_degree_by_polynomial_size(self) -> None:
        trace = valid_trace()
        manifest = trusted_manifest(trace)
        manifest["polynomial_size"] = 1024
        with tempfile.TemporaryDirectory() as directory:
            artifacts = write_bound_artifacts(Path(directory), manifest)
            with self.assertRaisesRegex(replay.TraceReplayError, "polynomial size"):
                replay.replay_events(
                    trace,
                    trusted_manifest=manifest,
                    expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
                    artifact_bindings=artifacts,
                )

    def test_manifest_requires_exact_external_artifact_bindings(self) -> None:
        trace = valid_trace()
        manifest = trusted_manifest(trace)
        with self.assertRaisesRegex(replay.TraceReplayError, "artifact bindings"):
            replay.replay_events(
                trace,
                trusted_manifest=manifest,
                expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
            )

    def test_manifest_rejects_external_artifact_hash_drift(self) -> None:
        trace = valid_trace()
        manifest = trusted_manifest(trace)
        with tempfile.TemporaryDirectory() as directory:
            artifacts = write_bound_artifacts(Path(directory), manifest)
            artifacts["binary"].write_bytes(b"different binary")
            with self.assertRaisesRegex(replay.TraceReplayError, "artifact hash drift"):
                replay.replay_events(
                    trace,
                    trusted_manifest=manifest,
                    expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
                    artifact_bindings=artifacts,
                )

    def test_manifest_must_pin_exactly_one_instrumented_binary(self) -> None:
        trace = valid_trace()
        manifest = trusted_manifest(trace)
        manifest["artifacts"][0]["role"] = "instrumented_source"
        with tempfile.TemporaryDirectory() as directory:
            artifacts = write_bound_artifacts(Path(directory), manifest)
            with self.assertRaisesRegex(replay.TraceReplayError, "exactly one"):
                replay.replay_events(
                    trace,
                    trusted_manifest=manifest,
                    expected_manifest_sha256=replay.canonical_manifest_sha256(manifest),
                    artifact_bindings=artifacts,
                )

    def test_duplicate_manifest_json_keys_are_rejected(self) -> None:
        payload = '{"schema":"a79.manifest.v3","schema":"fake"}\n'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(payload)
            with self.assertRaisesRegex(replay.TraceReplayError, "duplicate JSON key"):
                replay.load_json_object(path)

    def test_ledger_drift_is_rejected(self) -> None:
        trace = valid_trace()
        trace[0]["expected_ledger"]["scan"]["marginals"] = 1
        self.assert_rejected(trace, "ledger drift")

    def test_reserved_total_stage_cannot_mask_stage_breakdown(self) -> None:
        trace = valid_trace()
        trace[3]["stage"] = "total"
        self.assert_rejected(trace, "reserved")

    def test_expected_ledger_rejects_unknown_count_fields(self) -> None:
        trace = valid_trace()
        trace[0]["expected_ledger"]["scan"]["pbs"] = 1
        self.assert_rejected(trace, "must contain exactly")

    def test_noncontiguous_sequence_is_rejected(self) -> None:
        trace = valid_trace()
        trace[3]["seq"] = 99
        self.assert_rejected(trace, "not contiguous")

    def test_conditional_external_cannot_assert_official_level(self) -> None:
        trace = valid_trace()
        trace[1]["source_contract"] = "conditional_external"
        self.assert_rejected(trace, "cannot assert")

    def test_event_after_terminal_is_rejected(self) -> None:
        trace = valid_trace()
        trace.append(
            {
                "seq": len(trace),
                "op": "input",
                "output": "after-terminal",
                "encoding": dict(ENC),
                "crypto_domain": dict(DOMAIN),
                "wire_kind": replay.WireKind.A44_SHORTINT.value,
                "shortint_degree": 0,
                "reachable_overapprox": [0],
                "source_contract": "public_trivial",
                "official_noise_level": 0,
            }
        )
        self.assert_rejected(trace, "after its terminal")

    def test_dangling_producer_cannot_pad_a_trace(self) -> None:
        trace = valid_trace()
        trace.insert(
            -1,
            {
                "seq": 5,
                "op": "input",
                "output": "decoy",
                "encoding": dict(ENC),
                "crypto_domain": dict(DOMAIN),
                "wire_kind": replay.WireKind.A44_SHORTINT.value,
                "shortint_degree": 0,
                "reachable_overapprox": [0],
                "source_contract": "public_trivial",
                "official_noise_level": 0,
            },
        )
        trace[-1]["seq"] = 6
        self.assert_rejected(trace, "not ancestors of a terminal")

    def test_duplicate_terminal_output_is_rejected(self) -> None:
        trace = valid_trace()
        trace[-1]["outputs"] = ["low", "low"]
        self.assert_rejected(trace, "must be distinct")

    def test_missing_accumulator_id_is_rejected(self) -> None:
        trace = valid_trace()
        trace[4].pop("accumulator_id")
        self.assert_rejected(trace, "accumulator_id")

    def test_encoding_label_must_not_be_coerced(self) -> None:
        trace = valid_trace()
        trace[1]["encoding"] = {
            "label": None,
            "delta_log": 59,
            "torus_period": 32,
            "logical_modulus": 16,
            "negacyclic_signed": False,
        }
        self.assert_rejected(trace, "encoding.label")

    def test_duplicate_json_keys_are_rejected(self) -> None:
        payload = '{"seq":0,"seq":1,"op":"meta","schema":"a79.trace.v3"}\n'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.jsonl"
            path.write_text(payload)
            with self.assertRaisesRegex(replay.TraceReplayError, "duplicate JSON key"):
                replay.load_jsonl(path)


if __name__ == "__main__":
    unittest.main()
