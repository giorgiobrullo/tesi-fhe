#!/usr/bin/env python3
"""Correct A84's post-offset selector samples into an A79-v3 raw projection.

This is a deterministic static/declarative artifact builder and verifier.  It
does not compile Rust, execute TFHE/FHE, generate keys, or attest a runtime.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
DEFAULT_ARTIFACT_DIR = HERE / "artifacts"

PROJECTION_SCHEMA = "a93.a84-to-a79-raw-projection.v1"
STATUS = "PASS_CORRECTED_RAW_PROJECTION_DECLARATIVE_A79_V3_OPEN_RUNTIME"
A84_SCHEMA = "a84.accumulator-body-bindings.v1"
A79_TRACE_SCHEMA = "a79.trace.v3"
A79_MANIFEST_SCHEMA = "a79.manifest.v3"

A44_PARAMETER_FINGERPRINT = (
    "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1"
)
A44_PARAMETER_CANONICAL = (
    "tfhe-rs=0.11.3;"
    "symbol=V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;"
    "bootstrap=classic_ks_pbs;lwe_dimension=859;glwe_dimension=1;"
    "polynomial_size=2048;"
    "lwe_noise=gaussian_stddev_2.3088161607134664e-6;"
    "glwe_noise=gaussian_stddev_2.845267479601915e-15;"
    "pbs_base_log=23;pbs_level=1;ks_base_log=3;ks_level=5;"
    "message_modulus=2;carry_modulus=8;max_noise_level=15;"
    "log2_p_fail=-64.088;ciphertext_modulus=native;"
    "encryption_key_choice=Big"
)

A84_CANONICAL_MANIFEST_SHA256 = (
    "4b9eca2418fa17c4aed1009cf6ea8c5d8777d082f8eb280bc33177967fdbb12b"
)
A84_MANIFEST_FILE_SHA256 = (
    "a11bed233e1fe9afe113b93386aaebb5c4e2d9512903a0ac0245f5414ec4fb22"
)
A84_BUNDLE_SHA256 = (
    "836f783ea806758bc0a4cb553e1870f58934260ec3ddfb5b1acbcb119305730e"
)
A84_BUILDER_SHA256 = (
    "52f204ad57211faae9c9f66081787ea6c0537853e26a319d8321dd9f3a7f70f3"
)
A79_REPLAY_SHA256 = (
    "83943208ef64d5b1ada0f9124017f0d7e99bbdc3e777c238fc9c946c314bb47a"
)
A79_MODEL_SHA256 = (
    "f4f2ca99acf91959d1257d8f187235b395cc15379b95c28ced4228e3ab08a734"
)
EXPECTED_MISMATCH_SHA256 = (
    "7cb31250a4d4dcfaf5372182795b57cbd4118768e5cb296509f0b248614da875"
)
EXPECTED_PROJECTION_MANIFEST_SHA256 = (
    "5f4f10e8d728af2650df1b82ff8be0dd0c7b65ae5e37725c0aba89a246abef6a"
)

A84_BUILDER_PATH = (
    REPO_ROOT / "tmp/a84-accumulator-body-binding/a84_accumulator_binding.py"
)
A84_MANIFEST_PATH = (
    REPO_ROOT
    / "tmp/a84-accumulator-body-binding/artifacts/a84_a53_n127_manifest.json"
)
A84_BUNDLE_PATH = (
    REPO_ROOT
    / "tmp/a84-accumulator-body-binding/artifacts/"
    "a84_a53_n127_accumulator_bodies.bin"
)
A79_REPLAY_PATH = REPO_ROOT / "tmp/a79-a62-audited-lwe-model/a79_trace_replay.py"
A79_MODEL_PATH = REPO_ROOT / "tmp/a79-a62-audited-lwe-model/a79_audited_lwe.py"

FROZEN_INPUTS = {
    "tmp/a84-accumulator-body-binding/a84_accumulator_binding.py": (
        A84_BUILDER_SHA256
    ),
    "tmp/a84-accumulator-body-binding/artifacts/"
    "a84_a53_n127_manifest.json": A84_MANIFEST_FILE_SHA256,
    "tmp/a84-accumulator-body-binding/artifacts/"
    "a84_a53_n127_accumulator_bodies.bin": A84_BUNDLE_SHA256,
    "tmp/a79-a62-audited-lwe-model/a79_trace_replay.py": A79_REPLAY_SHA256,
    "tmp/a79-a62-audited-lwe-model/a79_audited_lwe.py": A79_MODEL_SHA256,
}

PARAMETER_SPEC_FILE = "a44_parameter_spec.txt"
SOURCE_FIXTURE_FILE = "a93_declarative_source_fixture.txt"
BINARY_FIXTURE_FILE = "a93_declarative_binary_fixture.bin"
ACCUMULATOR_FILE = "a93_corrected_a79_accumulators.json"
TRACE_FILE = "a93_a79_projection_trace.jsonl"
A79_MANIFEST_FILE = "a93_a79_projection_trusted_manifest.json"
PROJECTION_FILE = "a93_projection_manifest.json"

SOURCE_FIXTURE_BYTES = (
    b"A93 declarative A79-v3 projection source fixture; no compiled runtime.\n"
)
BINARY_FIXTURE_BYTES = (
    b"A93 declarative binary-role fixture; this is not an executable.\n"
)


class ProjectionError(ValueError):
    """The frozen input or corrected projection is invalid."""


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(payload: Any) -> bytes:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ProjectionError(f"payload is not canonical JSON: {error}") from error


def canonical_json_sha256(payload: Any) -> str:
    return sha256_bytes(canonical_json_bytes(payload))


def _load_json_object(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ProjectionError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProjectionError(f"cannot read JSON object {path}: {error}") from error
    if not isinstance(payload, dict):
        raise ProjectionError(f"JSON root is not an object: {path}")
    return payload


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ProjectionError(f"{label} must be an integer >= {minimum}")
    return value


def _sha256_hex(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ProjectionError(f"{label} must be lower-case SHA-256 hex")
    return value


def _reject_symlink_components(path: Path, anchor: Path, label: str) -> None:
    try:
        relative = path.relative_to(anchor)
    except ValueError as error:
        raise ProjectionError(f"{label} escapes its required root") from error
    cursor = anchor
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ProjectionError(f"{label} contains a symlink component: {cursor}")


def verify_frozen_inputs() -> dict[str, str]:
    manifest_path = HERE / "FROZEN_INPUTS.sha256"
    observed_manifest: dict[str, str] = {}
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00]+)", line)
        if match is None:
            raise ProjectionError(f"malformed frozen-input line: {line!r}")
        digest, relative = match.groups()
        if relative in observed_manifest:
            raise ProjectionError(f"duplicate frozen-input path: {relative}")
        observed_manifest[relative] = digest
    if observed_manifest != FROZEN_INPUTS:
        raise ProjectionError("frozen-input manifest differs from the code-pinned closure")
    for relative, expected in FROZEN_INPUTS.items():
        path = REPO_ROOT / relative
        _reject_symlink_components(path, REPO_ROOT, "frozen input")
        if path.is_symlink() or not path.is_file():
            raise ProjectionError(f"frozen input is not a regular file: {relative}")
        if file_sha256(path) != expected:
            raise ProjectionError(f"frozen input hash drift: {relative}")
    return dict(observed_manifest)


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ProjectionError(f"cannot construct import spec for {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except (ImportError, OSError, TypeError, ValueError) as error:
        raise ProjectionError(f"cannot import pinned module {path}: {error}") from error
    return module


def load_and_verify_a84() -> tuple[dict[str, Any], dict[str, Any]]:
    verify_frozen_inputs()
    manifest = _load_json_object(A84_MANIFEST_PATH)
    if canonical_json_sha256(manifest) != A84_CANONICAL_MANIFEST_SHA256:
        raise ProjectionError("A84 canonical manifest digest mismatch")
    if manifest.get("schema") != A84_SCHEMA:
        raise ProjectionError("unsupported A84 schema")
    module_name = "_a93_frozen_a84_binding"
    previous = sys.modules.pop(module_name, None)
    try:
        module = _load_module(module_name, A84_BUILDER_PATH)
        result = module.verify_manifest_and_bundle(
            manifest,
            A84_BUNDLE_PATH.read_bytes(),
            expected_manifest_sha256=A84_CANONICAL_MANIFEST_SHA256,
        )
    except Exception as error:
        if error.__class__.__name__ == "BindingError":
            raise ProjectionError(f"frozen A84 verifier rejected input: {error}") from error
        raise
    finally:
        sys.modules.pop(module_name, None)
        if previous is not None:
            sys.modules[module_name] = previous
    if result.get("status") != "PASS_SOURCE_BOUND_BODIES_AND_DECLARED_TRUTH_TABLES":
        raise ProjectionError("frozen A84 returned an unexpected status")
    return manifest, result


def load_a79_modules():
    if file_sha256(A79_MODEL_PATH) != A79_MODEL_SHA256:
        raise ProjectionError("A79 model source pin drift")
    if file_sha256(A79_REPLAY_PATH) != A79_REPLAY_SHA256:
        raise ProjectionError("A79 replay source pin drift")
    model_name = "a79_audited_lwe"
    replay_name = "_a93_pinned_a79_trace_replay"
    previous_model = sys.modules.pop(model_name, None)
    previous_replay = sys.modules.pop(replay_name, None)
    try:
        model = _load_module(model_name, A79_MODEL_PATH)
        replay = _load_module(replay_name, A79_REPLAY_PATH)
    finally:
        sys.modules.pop(replay_name, None)
        sys.modules.pop(model_name, None)
        if previous_model is not None:
            sys.modules[model_name] = previous_model
        if previous_replay is not None:
            sys.modules[replay_name] = previous_replay
    return model, replay


def derive_corrected_projection(
    a84_manifest: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    if canonical_json_sha256(a84_manifest) != A84_CANONICAL_MANIFEST_SHA256:
        raise ProjectionError("projection input is not the frozen A84 manifest")
    records = a84_manifest.get("accumulators")
    if not isinstance(records, Mapping):
        raise ProjectionError("A84 manifest has no accumulator map")
    corrected: dict[str, Any] = {}
    projection_records: dict[str, Any] = {}
    mismatches: list[dict[str, Any]] = []
    for accumulator_id in sorted(records):
        record = records[accumulator_id]
        if not isinstance(record, Mapping):
            raise ProjectionError("A84 accumulator record is not an object")
        contract = copy.deepcopy(record.get("a79_contract"))
        if not isinstance(contract, dict):
            raise ProjectionError("A84 accumulator has no A79 contract")
        raw_samples = contract.get("samples")
        truth_table = record.get("truth_table")
        if not isinstance(raw_samples, list) or not isinstance(truth_table, list):
            raise ProjectionError("A84 sample or truth-table payload is malformed")
        sample_views: list[dict[str, Any]] = []
        for sample in raw_samples:
            if not isinstance(sample, dict):
                raise ProjectionError("A84 A79 sample is not an object")
            degree = _integer(sample.get("sample_degree"), "sample degree")
            outputs = [
                output
                for row in truth_table
                for output in row["outputs"]
                if output["sample_degree"] == degree
            ]
            if not outputs:
                raise ProjectionError("sample degree has no A84 truth-table outputs")
            offsets = {
                _integer(output["public_offset"], "public offset")
                for output in outputs
            }
            if len(offsets) != 1:
                raise ProjectionError("public offset changes across truth-table rows")
            public_offset = next(iter(offsets))
            encoding = sample.get("encoding")
            if not isinstance(encoding, Mapping):
                raise ProjectionError("sample encoding is not an object")
            period = _integer(
                encoding.get("torus_period"), "output torus period", minimum=1
            )
            embedded_post = sample.get("reachable_overapprox")
            if (
                not isinstance(embedded_post, list)
                or embedded_post != sorted(set(embedded_post))
                or any(
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or not 0 <= value < period
                    for value in embedded_post
                )
            ):
                raise ProjectionError("embedded post-offset set is malformed")
            truth_post = {
                _integer(output["expected_residue"], "expected residue")
                for output in outputs
            }
            if not truth_post.issubset(embedded_post):
                raise ProjectionError("embedded set omits an A84 truth-table output")
            derived_raw = sorted(
                {(value - public_offset) % period for value in embedded_post}
            )
            if sorted({(value + public_offset) % period for value in derived_raw}) != embedded_post:
                raise ProjectionError("raw-to-post offset map is not reversible")
            if derived_raw != embedded_post:
                mismatches.append(
                    {
                        "accumulator_id": accumulator_id,
                        "sample_degree": degree,
                        "public_offset": public_offset,
                        "embedded_post_offset_reachable_overapprox": embedded_post,
                        "derived_raw_reachable_overapprox": derived_raw,
                    }
                )
            sample["reachable_overapprox"] = derived_raw
            sample_views.append(
                {
                    "sample_degree": degree,
                    "public_offset": public_offset,
                    "raw_reachable_overapprox": derived_raw,
                    "post_offset_reachable_overapprox": embedded_post,
                    "linear_event_required": record.get("kind")
                    == "selector_dual_sample",
                }
            )
        corrected[accumulator_id] = contract
        projection_records[accumulator_id] = {
            "a84_contract_id": record.get("contract_id"),
            "a84_body_id": record.get("body_id"),
            "kind": record.get("kind"),
            "sample_views": sample_views,
        }
    if len(corrected) != 35 or sum(len(item["samples"]) for item in corrected.values()) != 67:
        raise ProjectionError("corrected projection is not the frozen 35/67 scope")
    mismatch_digest = canonical_json_sha256(mismatches)
    if (
        len({entry["accumulator_id"] for entry in mismatches}) != 31
        or len(mismatches) != 55
        or mismatch_digest != EXPECTED_MISMATCH_SHA256
    ):
        raise ProjectionError("A84 raw/post-offset mismatch set drifted")
    return corrected, projection_records, mismatches


def build_trace(
    corrected: Mapping[str, Any], projection_records: Mapping[str, Any]
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []

    def append(event: dict[str, Any]) -> None:
        event["seq"] = len(events)
        events.append(event)

    ledger = {
        "projection_check": {
            "blind_rotations": 35,
            "key_switches": 0,
            "marginals": 67,
        },
        "total": {"blind_rotations": 35, "key_switches": 0, "marginals": 67},
    }
    append(
        {
            "op": "meta",
            "schema": A79_TRACE_SCHEMA,
            "graph_id": "a93-a84-a79-raw-projection-static-fixture",
            "parameter_fingerprint": A44_PARAMETER_FINGERPRINT,
            "expected_ledger": ledger,
        }
    )
    terminals: list[str] = []
    for accumulator_id in sorted(corrected):
        contract = corrected[accumulator_id]
        projection = projection_records[accumulator_id]
        input_id = f"input:{accumulator_id}"
        append(
            {
                "op": "input",
                "output": input_id,
                "encoding": contract["input_encoding"],
                "crypto_domain": contract["input_crypto_domain"],
                "wire_kind": contract["input_wire_kind"],
                "shortint_degree": contract["input_shortint_degree"],
                "reachable_overapprox": contract["input_reachable_overapprox"],
                "source_contract": "conditional_external",
                "official_noise_level": None,
            }
        )
        raw_output_ids = [
            f"raw:{accumulator_id}:degree:{sample['sample_degree']}"
            for sample in contract["samples"]
        ]
        append(
            {
                "op": "pbs",
                "stage": "projection_check",
                "input": input_id,
                "blind_rotation_id": f"br:{accumulator_id}",
                "accumulator_id": accumulator_id,
                "pbs_mode": contract["pbs_mode"],
                "strict_margin_radius": contract["strict_margin_radius"],
                "strict_margin_unit": contract["strict_margin_unit"],
                "input_max_degree": contract["input_max_degree"],
                "outputs": [
                    {"id": output_id, **sample}
                    for output_id, sample in zip(
                        raw_output_ids, contract["samples"], strict=True
                    )
                ],
            }
        )
        for raw_output_id, view in zip(
            raw_output_ids, projection["sample_views"], strict=True
        ):
            if not view["linear_event_required"]:
                terminals.append(raw_output_id)
                continue
            final_id = (
                f"post-offset:{accumulator_id}:degree:{view['sample_degree']}"
            )
            append(
                {
                    "op": "linear",
                    "output": final_id,
                    "terms": [{"value": raw_output_id, "coefficient": 1}],
                    "public_offset": view["public_offset"],
                    "reachable_overapprox": view[
                        "post_offset_reachable_overapprox"
                    ],
                }
            )
            terminals.append(final_id)
    append(
        {
            "op": "terminal",
            "outputs": terminals,
            "claim_model_obligations_closed": False,
        }
    )
    if len(events) != 136 or len(terminals) != 67:
        raise ProjectionError("declarative projection trace count drift")
    return events


def trace_jsonl_bytes(events: Sequence[Mapping[str, Any]]) -> bytes:
    return b"".join(canonical_json_bytes(event) + b"\n" for event in events)


def build_a79_manifest(
    events: Sequence[Mapping[str, Any]], corrected: Mapping[str, Any]
) -> dict[str, Any]:
    artifacts = [
        {
            "id": "a93-declarative-binary-fixture",
            "role": "instrumented_binary",
            "sha256": sha256_bytes(BINARY_FIXTURE_BYTES),
        },
        {
            "id": "a93-declarative-source-fixture",
            "role": "instrumented_source",
            "sha256": sha256_bytes(SOURCE_FIXTURE_BYTES),
        },
        {
            "id": "a44-parameter-spec",
            "role": "parameter_spec",
            "sha256": sha256_bytes(A44_PARAMETER_CANONICAL.encode("utf-8")),
        },
        {
            "id": "a93-corrected-accumulator-spec",
            "role": "accumulator_spec",
            "sha256": canonical_json_sha256(corrected),
        },
    ]
    if artifacts[2]["sha256"] != A44_PARAMETER_FINGERPRINT:
        raise ProjectionError("canonical A44 parameter bytes have the wrong digest")
    return {
        "schema": A79_MANIFEST_SCHEMA,
        "trace_schema": A79_TRACE_SCHEMA,
        "graph_id": events[0]["graph_id"],
        "parameter_fingerprint": A44_PARAMETER_FINGERPRINT,
        "expected_ledger": events[0]["expected_ledger"],
        "trace_sha256": canonical_json_sha256(events),
        "polynomial_size": 2048,
        "max_noise_level": 15,
        "accumulators": corrected,
        "artifacts": artifacts,
    }


def artifact_payloads(
    corrected: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    trusted_manifest: Mapping[str, Any],
) -> dict[str, bytes]:
    return {
        PARAMETER_SPEC_FILE: A44_PARAMETER_CANONICAL.encode("utf-8"),
        SOURCE_FIXTURE_FILE: SOURCE_FIXTURE_BYTES,
        BINARY_FIXTURE_FILE: BINARY_FIXTURE_BYTES,
        ACCUMULATOR_FILE: canonical_json_bytes(corrected),
        TRACE_FILE: trace_jsonl_bytes(events),
        A79_MANIFEST_FILE: canonical_json_bytes(trusted_manifest),
    }


def artifact_bindings(artifact_dir: Path) -> dict[str, Path]:
    return {
        "a93-declarative-binary-fixture": artifact_dir / BINARY_FIXTURE_FILE,
        "a93-declarative-source-fixture": artifact_dir / SOURCE_FIXTURE_FILE,
        "a44-parameter-spec": artifact_dir / PARAMETER_SPEC_FILE,
        "a93-corrected-accumulator-spec": artifact_dir / ACCUMULATOR_FILE,
    }


def run_actual_a79_replay(
    events: Sequence[Mapping[str, Any]],
    trusted_manifest: Mapping[str, Any],
    artifact_dir: Path,
) -> dict[str, Any]:
    _, replay = load_a79_modules()
    try:
        result = replay.replay_events(
            events,
            trusted_manifest=trusted_manifest,
            artifact_bindings=artifact_bindings(artifact_dir),
            expected_manifest_sha256=canonical_json_sha256(trusted_manifest),
        )
    except replay.TraceReplayError as error:
        raise ProjectionError(f"actual A79-v3 replay rejected projection: {error}") from error
    expected_status = "PASS_DECLARATIVE_MANIFEST_DIGEST_BOUND_OPEN_OBLIGATIONS"
    if result.get("status") != expected_status or result.get("execution_attested") is not False:
        raise ProjectionError("actual A79-v3 replay returned an unexpected status")
    return result


def build_projection_manifest(
    projection_records: Mapping[str, Any],
    mismatches: Sequence[Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    trusted_manifest: Mapping[str, Any],
    payloads: Mapping[str, bytes],
    replay_result: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema": PROJECTION_SCHEMA,
        "status": STATUS,
        "date": "2026-09-03",
        "scope": "A53 N=127 distinct accumulator contracts; not runtime invocation counts",
        "source_a84": {
            "schema": A84_SCHEMA,
            "canonical_manifest_sha256": A84_CANONICAL_MANIFEST_SHA256,
            "manifest_file_sha256": A84_MANIFEST_FILE_SHA256,
            "body_bundle_sha256": A84_BUNDLE_SHA256,
            "builder_verifier_sha256": A84_BUILDER_SHA256,
            "body_and_joint_truth_unchanged": True,
        },
        "source_a79": {
            "trace_schema": A79_TRACE_SCHEMA,
            "manifest_schema": A79_MANIFEST_SCHEMA,
            "replay_sha256": A79_REPLAY_SHA256,
            "model_sha256": A79_MODEL_SHA256,
        },
        "counts": {
            "distinct_accumulator_contracts": 35,
            "raw_pbs_samples": 67,
            "representative_raw_pbs_events": 35,
            "selector_linear_offset_events": 64,
            "declarative_trace_events": 136,
            "embedded_mismatched_records": 31,
            "embedded_mismatched_samples": 55,
        },
        "embedded_defect": {
            "description": "A84 selector samples are post-offset, not raw PBS sets",
            "mismatch_sha256": canonical_json_sha256(mismatches),
            "original_projection_raw_compatible": False,
        },
        "corrected_projection": {
            "rule": "raw=(post-public_offset) mod output_torus_period",
            "postprocess": "one A79 linear coefficient-1 event per selector sample",
            "records_sha256": canonical_json_sha256(projection_records),
            "records": projection_records,
        },
        "a79_fixture": {
            "trace_canonical_sha256": canonical_json_sha256(events),
            "trusted_manifest_canonical_sha256": canonical_json_sha256(
                trusted_manifest
            ),
            "replay_status": replay_result["status"],
            "execution_attested": replay_result["execution_attested"],
            "ledger": replay_result["ledger"],
            "terminal_model_obligations_closed": all(
                replay_result["terminal_model_obligations_closed"]
            ),
            "artifact_roles_self_declared": replay_result["trust_binding"][
                "artifact_roles_self_declared"
            ],
        },
        "artifact_files": {
            name: {"sha256": sha256_bytes(payload), "length_bytes": len(payload)}
            for name, payload in sorted(payloads.items())
        },
        "claim_boundary": {
            "corrected_projection_structurally_verified": True,
            "actual_a79_v3_declarative_replay_passed": True,
            "a84_body_or_joint_truth_changed": False,
            "production_trace": False,
            "runtime_execution_attested": False,
            "runtime_public_offset_execution_attested": False,
            "runtime_gate_ready": False,
            "end_to_end_nontrivial_p_fail_proved": False,
        },
    }


def expected_objects() -> tuple[
    dict[str, Any],
    dict[str, Any],
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any],
]:
    a84_manifest, _ = load_and_verify_a84()
    corrected, projection_records, mismatches = derive_corrected_projection(
        a84_manifest
    )
    events = build_trace(corrected, projection_records)
    trusted_manifest = build_a79_manifest(events, corrected)
    return corrected, projection_records, mismatches, events, trusted_manifest


def build(artifact_dir: Path = DEFAULT_ARTIFACT_DIR) -> dict[str, Any]:
    corrected, projection_records, mismatches, events, trusted_manifest = (
        expected_objects()
    )
    payloads = artifact_payloads(corrected, events, trusted_manifest)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    for name, payload in payloads.items():
        (artifact_dir / name).write_bytes(payload)
    replay_result = run_actual_a79_replay(events, trusted_manifest, artifact_dir)
    projection_manifest = build_projection_manifest(
        projection_records,
        mismatches,
        events,
        trusted_manifest,
        payloads,
        replay_result,
    )
    (artifact_dir / PROJECTION_FILE).write_bytes(
        canonical_json_bytes(projection_manifest)
    )
    return {
        "status": STATUS,
        "projection_manifest_sha256": canonical_json_sha256(projection_manifest),
        "a79_manifest_sha256": canonical_json_sha256(trusted_manifest),
        "a79_trace_sha256": canonical_json_sha256(events),
        "artifacts": len(payloads) + 1,
        "runtime_execution_attested": False,
        "runtime_gate_ready": False,
    }


def verify(
    artifact_dir: Path = DEFAULT_ARTIFACT_DIR,
    *,
    expected_projection_sha256: str = EXPECTED_PROJECTION_MANIFEST_SHA256,
) -> dict[str, Any]:
    expected_digest = _sha256_hex(
        expected_projection_sha256, "expected projection manifest sha256"
    )
    corrected, projection_records, mismatches, events, trusted_manifest = (
        expected_objects()
    )
    if artifact_dir.is_symlink():
        raise ProjectionError("artifact directory must not be a symlink")
    payloads = artifact_payloads(corrected, events, trusted_manifest)
    for name, expected in payloads.items():
        path = artifact_dir / name
        if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
            raise ProjectionError(f"generated artifact differs from reconstruction: {name}")
    replay_result = run_actual_a79_replay(events, trusted_manifest, artifact_dir)
    expected_projection = build_projection_manifest(
        projection_records,
        mismatches,
        events,
        trusted_manifest,
        payloads,
        replay_result,
    )
    projection_path = artifact_dir / PROJECTION_FILE
    if projection_path.is_symlink() or not projection_path.is_file():
        raise ProjectionError("projection manifest is missing or symlinked")
    observed_projection = _load_json_object(projection_path)
    if observed_projection != expected_projection:
        raise ProjectionError("projection manifest differs from reconstruction")
    actual_digest = canonical_json_sha256(observed_projection)
    if actual_digest != expected_digest:
        raise ProjectionError("projection manifest differs from independent digest")
    return {
        "status": STATUS,
        "projection_manifest_sha256": actual_digest,
        "a79_manifest_sha256": canonical_json_sha256(trusted_manifest),
        "a79_trace_sha256": canonical_json_sha256(events),
        "a79_replay_status": replay_result["status"],
        "distinct_accumulator_contracts": 35,
        "raw_pbs_samples": 67,
        "selector_linear_offset_events": 64,
        "embedded_mismatched_samples": 55,
        "runtime_execution_attested": False,
        "runtime_public_offset_execution_attested": False,
        "runtime_gate_ready": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR)
    verify_parser.add_argument(
        "--expected-projection-sha256",
        default=EXPECTED_PROJECTION_MANIFEST_SHA256,
    )
    args = parser.parse_args()
    result = (
        build(args.artifact_dir)
        if args.command == "build"
        else verify(
            args.artifact_dir,
            expected_projection_sha256=args.expected_projection_sha256,
        )
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
