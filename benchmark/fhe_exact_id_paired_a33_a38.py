"""Paired A33-vs-A38 latency benchmark for the exact open-set DigiFace scene.

The benchmark compares the two frozen ``varco_demo`` executables with a paired design.  Each
pair sends the *same ciphertext bytes* to both servers, which have received the same fresh
evaluation key and the same ordered clear gallery.  The primary timing is the server's
``X-Tempo-Ms`` header; HTTP wall time is retained as a secondary diagnostic.

The default invocation is a non-mutating dry validation of inputs and the complete schedule.
Pass ``--run`` for the preregistered experiment: three independent key blocks, four excluded
warm-up pairs per block, and four fresh ciphertexts for each of five frontier probes (60 measured
pairs).  A balanced, deterministically shuffled AB/BA order controls local drift.  If the initial
hierarchical-bootstrap 95% interval is wider than two percentage points, or the AB/BA reduction
differs by more than two points, one additional three-block/60-pair stage is run automatically.

Within each key block, key generation and all encryptions finish before either server is launched
or timed; the excluded warm-up pairs follow that preparation.  Blocks are prepared and executed
sequentially, and a triggered extension is prepared only after its preregistered decision.  No
result is decrypted until every timed pair, including a possible extension, has completed. Client
and secret-key material live only inside one temporary directory and are removed before results
are finalized.

For a shorter end-to-end plumbing check, use ``--smoke --run``.  Smoke results receive a distinct
timestamped stem and can never overwrite the canonical full-run artifacts.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import math
import os
import pathlib
import platform
import random
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # Supports both ``python benchmark/file.py`` and ``python -m benchmark.file``.
    from benchmark import fhe_digiface_validation as validation
except ImportError:  # pragma: no cover - direct-script import path
    import fhe_digiface_validation as validation


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_A33_BINARY = ROOT / "tmp" / "a33-aligned-sparse-2026-09-02" / "varco_demo"
DEFAULT_A38_BINARY = ROOT / "tmp" / "a38-combined-prototype" / "varco_demo"
DEFAULT_OUTPUT_DIR = ROOT / "benchmark" / "results"
DEFAULT_OUTPUT_STEM = "fhe_digiface_exact_paired_a33_a38_2026-09-02"

EXPECTED_A33_BINARY_SHA256 = (
    "13a1593be85d8e585bdf48d7d4e8a09a57a82902f6e8da7299a5b02415a3ea59"
)
EXPECTED_A38_BINARY_SHA256 = (
    "f4cdc28f92ffae8d34c207a06896299015aca2673fce14a959cc3bea34dc1e02"
)
EXPECTED_A33_PBS = 4273
EXPECTED_A38_PBS = 3655
EXPECTED_REDUCTION_PBS = EXPECTED_A33_PBS - EXPECTED_A38_PBS
EXPECTED_REDUCTION_PBS_FRACTION = EXPECTED_REDUCTION_PBS / EXPECTED_A33_PBS
EXPECTED_TIGHT_DOMAIN = {"l": -987, "u": 2329, "larghezza": 3317}
EXPECTED_A33_EXECUTION_DOMAIN = {"l": -1019, "u": 2329, "larghezza": 3349}
EXPECTED_A38_EXECUTION_DOMAIN = {"l": -1019, "u": 2329, "larghezza": 3349}
EXPECTED_A33_PATH = "a33_aligned_sparse"
EXPECTED_A38_PATH = "a38_combined"
FRONTIER: Tuple[Tuple[int, int], ...] = (
    (265, 2),
    (758, 3),
    (211, 4),
    (1943, 5),
    (407, 7),
)
SERVER_LABELS = ("a33", "a38")
PAIR_ORDERS = ("A33_A38", "A38_A33")

PROVENANCE_PATHS: Mapping[str, pathlib.Path] = {
    "paired_harness": pathlib.Path(__file__),
    "validation_dependency": ROOT / "benchmark" / "fhe_digiface_validation.py",
    "config": validation.CONFIG_PATH,
    "cache": validation.CACHE_PATH,
    "a33_source_patch": ROOT
    / "benchmark"
    / "patches"
    / "a33_aligned_sparse_source_2026-09-02.patch",
    "a33_snapshot_readme": ROOT
    / "tmp"
    / "a33-aligned-sparse-2026-09-02"
    / "README.md",
    "a33_snapshot_input_manifest": ROOT
    / "tmp"
    / "a33-aligned-sparse-2026-09-02"
    / "inputs-before.sha256",
    "a33_snapshot_binary_manifest": ROOT
    / "tmp"
    / "a33-aligned-sparse-2026-09-02"
    / "binaries.sha256",
    "a38_snapshot_readme": ROOT / "tmp" / "a38-combined-prototype" / "README.md",
    "a38_source_snapshot": ROOT
    / "tmp"
    / "a38-combined-prototype"
    / "source"
    / "experiments"
    / "14_pipeline_tfhe_rs"
    / "src"
    / "private_argmin.rs",
    "a38_service_source_snapshot": ROOT
    / "tmp"
    / "a38-combined-prototype"
    / "source"
    / "experiments"
    / "14_pipeline_tfhe_rs"
    / "src"
    / "bin"
    / "varco_demo.rs",
    "a38_component_report": ROOT
    / "experiments"
    / "14_pipeline_tfhe_rs"
    / "results"
    / "exact_id_a38_combined_component_fhe_2026-09-02.md",
}

CSV_FIELDS = [
    "pair_sequence",
    "stage",
    "block",
    "block_seed",
    "phase",
    "included_in_analysis",
    "phase_position",
    "probe_index",
    "probe_name",
    "cohort",
    "repetition",
    "pair_order",
    "clear_min_score",
    "clear_argmin_index",
    "clear_argmin_name",
    "clear_match_count",
    "expected_authorized",
    "expected_index",
    "expected_code",
    "probe_plaintext_sha256",
    "probe_ciphertext_bytes",
    "probe_ciphertext_sha256",
    "encrypt_wall_ms",
    "encrypt_reported_ms",
    "a33_input_ciphertext_sha256",
    "a33_http_wall_ms",
    "a33_server_ms",
    "a33_pbs",
    "a33_contract",
    "a33_output_epoch",
    "a33_output_revision",
    "a33_output_gallery_size",
    "a33_output_lwe_size",
    "a33_result_bytes",
    "a33_result_sha256",
    "a33_decrypt_wall_ms",
    "a33_decrypt_reported_ms",
    "a33_authorized",
    "a33_index",
    "a33_code",
    "a33_name",
    "a38_input_ciphertext_sha256",
    "a38_http_wall_ms",
    "a38_server_ms",
    "a38_pbs",
    "a38_contract",
    "a38_output_epoch",
    "a38_output_revision",
    "a38_output_gallery_size",
    "a38_output_lwe_size",
    "a38_result_bytes",
    "a38_result_sha256",
    "a38_decrypt_wall_ms",
    "a38_decrypt_reported_ms",
    "a38_authorized",
    "a38_index",
    "a38_code",
    "a38_name",
    "byte_identical_input_ciphertext",
    "same_exact_result",
    "both_match_clear_oracle",
    "semantic_discrepancy",
    "server_delta_ms_a38_minus_a33",
    "server_ratio_a38_over_a33",
    "server_reduction_fraction",
    "http_delta_ms_a38_minus_a33",
    "http_ratio_a38_over_a33",
]


class PairedBenchmarkError(RuntimeError):
    """Raised when a paired-design or protocol invariant fails."""


@dataclass
class ServerRuntime:
    label: str
    binary: pathlib.Path
    port: int
    process: subprocess.Popen
    stdout_path: pathlib.Path
    stderr_path: pathlib.Path
    stdout_handle: Any
    stderr_handle: Any
    process_record: Dict[str, Any]
    initial_state: Optional[Dict[str, Any]] = None
    enrolled_state: Optional[Dict[str, Any]] = None
    final_state: Optional[Dict[str, Any]] = None


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def json_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return sha256_bytes(payload)


def checked_file_record(path: pathlib.Path) -> Dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(path)
    return validation.file_record(path)


def collect_provenance(
    a33_binary: pathlib.Path, a38_binary: pathlib.Path
) -> Dict[str, Dict[str, Any]]:
    records = {
        label: checked_file_record(path) for label, path in PROVENANCE_PATHS.items()
    }
    records["a33_binary"] = checked_file_record(a33_binary)
    records["a38_binary"] = checked_file_record(a38_binary)
    return records


def validate_frozen_binaries(records: Mapping[str, Mapping[str, Any]]) -> None:
    observed = {
        "a33": records["a33_binary"]["sha256"],
        "a38": records["a38_binary"]["sha256"],
    }
    expected = {
        "a33": EXPECTED_A33_BINARY_SHA256,
        "a38": EXPECTED_A38_BINARY_SHA256,
    }
    for label in SERVER_LABELS:
        if observed[label] != expected[label]:
            raise PairedBenchmarkError(
                "{} binary hash is {}, expected frozen {}".format(
                    label.upper(), observed[label], expected[label]
                )
            )


def validate_args(args: argparse.Namespace) -> None:
    if args.blocks < 1:
        raise PairedBenchmarkError("--blocks must be positive")
    if args.warmup_pairs < 0:
        raise PairedBenchmarkError("--warmup-pairs cannot be negative")
    if args.repetitions_per_probe < 2 or args.repetitions_per_probe % 2:
        raise PairedBenchmarkError(
            "--repetitions-per-probe must be a positive even value of at least two"
        )
    if args.timeout < 1:
        raise PairedBenchmarkError("--timeout must be positive")
    if args.bootstrap_replicates < 100:
        raise PairedBenchmarkError("--bootstrap-replicates must be at least 100")
    if args.extension_interval_width_pp <= 0:
        raise PairedBenchmarkError("extension interval width must be positive")
    if args.extension_order_difference_pp <= 0:
        raise PairedBenchmarkError("extension order difference must be positive")
    if pathlib.Path(args.output_stem).name != args.output_stem:
        raise PairedBenchmarkError("--output-stem must be a filename stem")


def normalized_enrolled_state(state: Mapping[str, Any]) -> Dict[str, Any]:
    """Return state fields that must be identical despite process-specific epochs."""

    return {
        key: state.get(key)
        for key in (
            "iscritti",
            "nomi",
            "soglie",
            "chiave",
            "chiave_sha256",
            "dim",
            "soglia_default",
            "revision",
            "dominio",
            "contratto_esatto",
        )
    }


def normalized_live_domain(value: Any, context: str) -> Dict[str, int]:
    """Normalize live Rust domain metadata without relying on validator dispatch policy."""

    if not isinstance(value, Mapping):
        raise PairedBenchmarkError("{} is not an object".format(context))
    lower = value.get("l")
    upper = value.get("u")
    width = value.get("larghezza")
    if not all(type(item) is int for item in (lower, upper, width)):
        raise PairedBenchmarkError("{} lacks canonical integer fields".format(context))
    if lower > upper or width != upper - lower + 1:
        raise PairedBenchmarkError(
            "{} is not a canonical inclusive domain".format(context)
        )
    return {"l": lower, "u": upper, "larghezza": width}


def validate_variant_enrolled_state(
    label: str, state: Mapping[str, Any], expected_tight_domain: Mapping[str, int]
) -> Dict[str, Any]:
    """Enforce each frozen aligned-path execution contract independently."""

    expected_tight = dict(expected_tight_domain)
    tight = normalized_live_domain(
        state.get("dominio"), "{} tight domain".format(label)
    )
    if tight != expected_tight or tight != EXPECTED_TIGHT_DOMAIN:
        raise PairedBenchmarkError(
            "{} tight domain is {}, expected frozen {}".format(
                label.upper(), tight, EXPECTED_TIGHT_DOMAIN
            )
        )

    if label not in SERVER_LABELS:
        raise PairedBenchmarkError("unknown server label {}".format(label))
    if "dominio_esecuzione" not in state or "percorso_argmin" not in state:
        raise PairedBenchmarkError(
            "{} lacks mandatory execution metadata".format(label.upper())
        )

    expected_execution = (
        EXPECTED_A33_EXECUTION_DOMAIN
        if label == "a33"
        else EXPECTED_A38_EXECUTION_DOMAIN
    )
    expected_path = EXPECTED_A33_PATH if label == "a33" else EXPECTED_A38_PATH
    execution = normalized_live_domain(
        state.get("dominio_esecuzione"), "{} execution domain".format(label.upper())
    )
    if execution != expected_execution:
        raise PairedBenchmarkError(
            "{} execution domain is {}, expected {}".format(
                label.upper(), execution, expected_execution
            )
        )
    if state.get("percorso_argmin") != expected_path:
        raise PairedBenchmarkError(
            "{} argmin path is {!r}, expected {!r}".format(
                label.upper(), state.get("percorso_argmin"), expected_path
            )
        )
    return {
        "tight_domain": tight,
        "execution_domain": execution,
        "argmin_path": expected_path,
        "execution_metadata_mode": "required_{}".format(expected_path),
    }


def validate_common_server_state(
    state: Mapping[str, Any],
    *,
    gallery_size: int,
    key_present: bool,
    expected_key_sha256: Optional[str] = None,
) -> None:
    """Validate shared state without applying the dependency's current dispatch policy."""

    shared_state = dict(state)
    shared_state.pop("dominio_esecuzione", None)
    shared_state.pop("percorso_argmin", None)
    validation.validate_server_state(
        shared_state,
        gallery_size=gallery_size,
        key_present=key_present,
        expected_key_sha256=expected_key_sha256,
    )


def make_enrollment_bodies(gallery: Any, names: Any) -> List[bytes]:
    bodies: List[bytes] = []
    for index, template in enumerate(gallery):
        name = "digiface-{}-{}".format(index, names[index])
        bodies.append(
            (
                "{}\t{}\n{}\n".format(
                    name,
                    validation.EXPECTED_THRESHOLD,
                    " ".join(str(int(value)) for value in template),
                )
            ).encode()
        )
    return bodies


def enrollment_payload_sha256(bodies: Sequence[bytes]) -> str:
    digest = hashlib.sha256()
    for body in bodies:
        digest.update(len(body).to_bytes(8, "little"))
        digest.update(body)
    return digest.hexdigest()


def schedule_for_block(
    *,
    block: int,
    stage: str,
    seed: int,
    repetitions_per_probe: int,
    warmup_pairs: int,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    block_seed = seed + block * 1_000_003
    rng = random.Random(block_seed)
    measured: List[Dict[str, Any]] = []
    direction_count = repetitions_per_probe // 2
    for probe_index, expected_score in FRONTIER:
        directions = ["A33_A38"] * direction_count + ["A38_A33"] * direction_count
        rng.shuffle(directions)
        for repetition, pair_order in enumerate(directions):
            measured.append(
                {
                    "stage": stage,
                    "block": block,
                    "block_seed": block_seed,
                    "phase": "measured",
                    "included_in_analysis": True,
                    "probe_index": probe_index,
                    "frontier_expected_score": expected_score,
                    "repetition": repetition,
                    "pair_order": pair_order,
                }
            )
    rng.shuffle(measured)
    for position, item in enumerate(measured):
        item["phase_position"] = position

    warmups: List[Dict[str, Any]] = []
    warmup_frontier = list(FRONTIER)
    for position in range(warmup_pairs):
        probe_index, expected_score = warmup_frontier[position % len(warmup_frontier)]
        warmups.append(
            {
                "stage": stage,
                "block": block,
                "block_seed": block_seed,
                "phase": "warmup",
                "included_in_analysis": False,
                "phase_position": position,
                "probe_index": probe_index,
                "frontier_expected_score": expected_score,
                "repetition": position // len(warmup_frontier),
                "pair_order": PAIR_ORDERS[(block + position) % 2],
            }
        )

    schedule = warmups + measured
    measured_balance: Dict[str, Dict[str, int]] = {}
    for probe_index, _ in FRONTIER:
        matching = [row for row in measured if row["probe_index"] == probe_index]
        measured_balance[str(probe_index)] = {
            order: sum(row["pair_order"] == order for row in matching)
            for order in PAIR_ORDERS
        }
        expected_per_order = repetitions_per_probe // 2
        if set(measured_balance[str(probe_index)].values()) != {expected_per_order}:
            raise PairedBenchmarkError("block schedule is not balanced by probe")

    public_schedule = [
        {key: value for key, value in row.items() if key != "frontier_expected_score"}
        for row in schedule
    ]
    record = {
        "block": block,
        "stage": stage,
        "seed": block_seed,
        "startup_order": list(
            SERVER_LABELS if block % 2 == 0 else reversed(SERVER_LABELS)
        ),
        "warmup_pairs": len(warmups),
        "measured_pairs": len(measured),
        "measured_balance_by_probe": measured_balance,
        "schedule_sha256": json_sha256(public_schedule),
    }
    return schedule, record


def build_schedule_preview(
    args: argparse.Namespace, block_count: int
) -> List[Dict[str, Any]]:
    records = []
    for block in range(block_count):
        _, record = schedule_for_block(
            block=block,
            stage="initial",
            seed=args.seed,
            repetitions_per_probe=args.repetitions_per_probe,
            warmup_pairs=args.warmup_pairs,
        )
        records.append(record)
    return records


def launch_server(
    label: str,
    binary: pathlib.Path,
    port: int,
    work: pathlib.Path,
    binary_sha256: str,
) -> ServerRuntime:
    stdout_path = work / "{}.stdout.log".format(label)
    stderr_path = work / "{}.stderr.log".format(label)
    stdout_handle = stdout_path.open("w")
    stderr_handle = stderr_path.open("w")
    argv = [
        str(binary),
        "serve",
        str(port),
        str(validation.EXPECTED_DIMENSION),
        str(validation.EXPECTED_THRESHOLD),
    ]
    process = subprocess.Popen(
        argv,
        stdout=stdout_handle,
        stderr=stderr_handle,
        text=True,
    )
    try:
        state = validation.wait_for_server(process, port)
        validation.validate_server_state(state, gallery_size=0, key_present=False)
        process_record = validation.process_binding(process, binary)
    except BaseException:
        validation.stop_server(process)
        stdout_handle.close()
        stderr_handle.close()
        raise
    process_record.update(
        {
            "label": label,
            "bind_address": "127.0.0.1:{}".format(port),
            "argv": argv,
            "binary_sha256_at_launch": binary_sha256,
        }
    )
    return ServerRuntime(
        label=label,
        binary=binary,
        port=port,
        process=process,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        stdout_handle=stdout_handle,
        stderr_handle=stderr_handle,
        process_record=process_record,
        initial_state=state,
    )


def port_is_closed(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.2)
        return probe.connect_ex(("127.0.0.1", port)) != 0


def stop_runtime(server: ServerRuntime) -> Dict[str, Any]:
    errors = []
    try:
        validation.stop_server(server.process)
    except Exception as error:  # Keep tearing down the other owned server.
        errors.append("stop_server: {}: {}".format(type(error).__name__, error))
        if server.process.poll() is None:
            try:
                server.process.kill()
                server.process.wait(timeout=10)
            except Exception as fallback_error:
                errors.append(
                    "fallback_kill: {}: {}".format(
                        type(fallback_error).__name__, fallback_error
                    )
                )
    for label, handle in (
        ("stdout", server.stdout_handle),
        ("stderr", server.stderr_handle),
    ):
        try:
            handle.close()
        except Exception as error:
            errors.append("close_{}: {}: {}".format(label, type(error).__name__, error))
    return {
        "pid": server.process.pid,
        "exit_code": server.process.returncode,
        "process_terminated": server.process.poll() is not None,
        "port": server.port,
        "port_closed": port_is_closed(server.port),
        "stdout_sha256": validation.sha256_file(server.stdout_path),
        "stderr_sha256": validation.sha256_file(server.stderr_path),
        "stdout_tail": server.stdout_path.read_text(errors="replace")[-2000:],
        "stderr_tail": server.stderr_path.read_text(errors="replace")[-4000:],
        "teardown_errors": errors,
    }


def install_key_and_gallery(
    server: ServerRuntime,
    *,
    server_key: pathlib.Path,
    server_key_sha256: str,
    enrollment_bodies: Sequence[bytes],
    expected_names: Sequence[str],
    expected_domain: Mapping[str, Any],
    timeout: int,
) -> Dict[str, Any]:
    status, body, _ = validation.http_upload_file(
        server.port, "/chiave", server_key, timeout=timeout
    )
    upload = validation.require_http_ok(
        status, body, "{} key upload".format(server.label)
    )
    if upload.get("chiave_sha256") != server_key_sha256:
        raise PairedBenchmarkError(
            "{} returned the wrong key hash".format(server.label)
        )

    started = time.perf_counter()
    if server.initial_state is None:
        raise PairedBenchmarkError("server has no initial state")
    for index, enrollment_body in enumerate(enrollment_bodies):
        status, body, _ = validation.http_request(
            server.port,
            "POST",
            "/iscrivi",
            enrollment_body,
            "text/plain",
            timeout=timeout,
        )
        response = validation.require_http_ok(
            status, body, "{} enrollment {}".format(server.label, index)
        )
        if response.get("indice") != index or response.get("iscritti") != index + 1:
            raise PairedBenchmarkError(
                "{} enrollment order diverged at {}".format(server.label, index)
            )
        if response.get("galleria_epoch") != server.initial_state["epoch"]:
            raise PairedBenchmarkError(
                "{} enrollment changed epoch".format(server.label)
            )
        if (
            response.get("galleria_revision")
            != server.initial_state["revision"] + index + 1
        ):
            raise PairedBenchmarkError(
                "{} enrollment revision diverged at {}".format(server.label, index)
            )

    status, body, _ = validation.http_request(
        server.port, "GET", "/stato", timeout=timeout
    )
    state = validation.require_http_ok(
        status, body, "{} enrolled state".format(server.label)
    )
    validate_common_server_state(
        state,
        gallery_size=validation.EXPECTED_GALLERY_SIZE,
        key_present=True,
        expected_key_sha256=server_key_sha256,
    )
    if state["nomi"] != list(expected_names):
        raise PairedBenchmarkError(
            "{} gallery names/order diverged".format(server.label)
        )
    if state["revision"] != server.initial_state["revision"] + len(enrollment_bodies):
        raise PairedBenchmarkError("{} final revision is wrong".format(server.label))
    if state["dominio"] != dict(expected_domain):
        raise PairedBenchmarkError("{} score domain is wrong".format(server.label))
    variant_execution = validate_variant_enrolled_state(
        server.label, state, expected_domain
    )
    server.enrolled_state = state
    return {
        "key_upload_response": upload,
        "enrollment_wall_ms": round((time.perf_counter() - started) * 1000.0, 3),
        "enrolled_state_sha256": json_sha256(state),
        "normalized_state_sha256": json_sha256(normalized_enrolled_state(state)),
        "variant_execution_contract": variant_execution,
    }


def prepare_ciphertexts(
    *,
    schedule: Sequence[Mapping[str, Any]],
    first_sequence: int,
    binary: pathlib.Path,
    keys: pathlib.Path,
    work: pathlib.Path,
    probes: Any,
    names: Any,
    all_scores: Any,
    timeout: int,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    observed_hashes = set()
    for offset, item in enumerate(schedule):
        sequence = first_sequence + offset
        row = validation.clear_case(
            "paired_frontier_{}".format(item["phase"]),
            sequence,
            int(item["probe_index"]),
            int(item["repetition"]),
            names,
            all_scores,
        )
        if row["clear_min_score"] != item["frontier_expected_score"]:
            raise PairedBenchmarkError(
                "probe {} score changed from {} to {}".format(
                    item["probe_index"],
                    item["frontier_expected_score"],
                    row["clear_min_score"],
                )
            )
        row.update(
            {
                "pair_sequence": sequence,
                "stage": item["stage"],
                "block": item["block"],
                "block_seed": item["block_seed"],
                "phase": item["phase"],
                "included_in_analysis": item["included_in_analysis"],
                "phase_position": item["phase_position"],
                "pair_order": item["pair_order"],
            }
        )
        row.pop("sequence", None)
        row.pop("suite", None)

        probe_text = (
            " ".join(str(int(value)) for value in probes[int(item["probe_index"])])
            + "\n"
        ).encode()
        plain_path = work / "probe-{:04d}.txt".format(sequence)
        cipher_path = work / "probe-{:04d}.ct".format(sequence)
        plain_path.write_bytes(probe_text)
        encrypted, encrypt_wall_s = validation.run_command(
            [str(binary), "encrypt", str(keys), str(plain_path), str(cipher_path)],
            timeout=timeout,
        )
        encrypt_report = validation.last_json_line(
            encrypted.stdout, "A38 client encrypt"
        )
        ciphertext = cipher_path.read_bytes()
        validation.validate_probe_ciphertext(ciphertext)
        ciphertext_hash = sha256_bytes(ciphertext)
        if ciphertext_hash in observed_hashes:
            raise PairedBenchmarkError(
                "fresh block encryptions produced a duplicate ciphertext"
            )
        observed_hashes.add(ciphertext_hash)
        row.update(
            {
                "probe_plaintext_sha256": sha256_bytes(probe_text),
                "probe_ciphertext_bytes": len(ciphertext),
                "probe_ciphertext_sha256": ciphertext_hash,
                "encrypt_wall_ms": round(encrypt_wall_s * 1000.0, 3),
                "encrypt_reported_ms": encrypt_report.get("encrypt_ms"),
                "_probe_ciphertext": ciphertext,
                "_keys": keys,
            }
        )
        rows.append(row)
    return rows


def evaluate_server(row: Dict[str, Any], server: ServerRuntime, timeout: int) -> None:
    if server.enrolled_state is None:
        raise PairedBenchmarkError("{} lacks enrolled state".format(server.label))
    ciphertext = row["_probe_ciphertext"]
    input_sha256 = sha256_bytes(ciphertext)
    if input_sha256 != row["probe_ciphertext_sha256"]:
        raise PairedBenchmarkError(
            "{} input ciphertext changed after preparation".format(server.label)
        )
    started = time.perf_counter()
    status, result, headers = validation.http_request(
        server.port, "POST", "/varco", ciphertext, timeout=timeout
    )
    wall_ms = (time.perf_counter() - started) * 1000.0
    if status != 200:
        raise PairedBenchmarkError(
            "{} /varco returned HTTP {}: {}".format(
                server.label, status, result.decode(errors="replace")
            )
        )
    if headers.get("content-type") != "application/octet-stream":
        raise PairedBenchmarkError("{} returned non-binary output".format(server.label))
    if headers.get("x-varco-contract") != validation.EXPECTED_VARCO_HEADER:
        raise PairedBenchmarkError(
            "{} returned the wrong contract".format(server.label)
        )
    if validation.parse_int(headers, "content-length") != len(result):
        raise PairedBenchmarkError(
            "{} returned the wrong Content-Length".format(server.label)
        )
    expected_pbs = EXPECTED_A33_PBS if server.label == "a33" else EXPECTED_A38_PBS
    observed_pbs = validation.parse_int(headers, "x-pbs")
    if observed_pbs != expected_pbs:
        raise PairedBenchmarkError(
            "{} reported {} PBS, expected {}".format(
                server.label, observed_pbs, expected_pbs
            )
        )
    server_ms = validation.parse_float(headers, "x-tempo-ms")
    if server_ms is None or not math.isfinite(server_ms) or server_ms <= 0:
        raise PairedBenchmarkError(
            "{} returned invalid X-Tempo-Ms".format(server.label)
        )
    output = validation.validate_output_ciphertext(result, server.enrolled_state)
    prefix = server.label
    row.update(
        {
            "{}_input_ciphertext_sha256".format(prefix): input_sha256,
            "{}_http_wall_ms".format(prefix): round(wall_ms, 3),
            "{}_server_ms".format(prefix): server_ms,
            "{}_pbs".format(prefix): observed_pbs,
            "{}_contract".format(prefix): headers["x-varco-contract"],
            "{}_output_epoch".format(prefix): output["epoch"],
            "{}_output_revision".format(prefix): output["revision"],
            "{}_output_gallery_size".format(prefix): output["gallery_size"],
            "{}_output_lwe_size".format(prefix): output["lwe_size"],
            "{}_result_bytes".format(prefix): len(result),
            "{}_result_sha256".format(prefix): sha256_bytes(result),
            "_{}_result".format(prefix): result,
        }
    )


def add_paired_timing_fields(row: Dict[str, Any]) -> None:
    a33 = float(row["a33_server_ms"])
    a38 = float(row["a38_server_ms"])
    a33_http = float(row["a33_http_wall_ms"])
    a38_http = float(row["a38_http_wall_ms"])
    row.update(
        {
            "server_delta_ms_a38_minus_a33": round(a38 - a33, 6),
            "server_ratio_a38_over_a33": a38 / a33,
            "server_reduction_fraction": 1.0 - a38 / a33,
            "http_delta_ms_a38_minus_a33": round(a38_http - a33_http, 6),
            "http_ratio_a38_over_a33": a38_http / a33_http,
        }
    )


def check_final_state(server: ServerRuntime, timeout: int) -> None:
    if server.enrolled_state is None:
        raise PairedBenchmarkError("server was not enrolled")
    status, body, _ = validation.http_request(
        server.port, "GET", "/stato", timeout=timeout
    )
    final_state = validation.require_http_ok(
        status, body, "{} final state".format(server.label)
    )
    validate_common_server_state(
        final_state,
        gallery_size=validation.EXPECTED_GALLERY_SIZE,
        key_present=True,
        expected_key_sha256=server.enrolled_state["chiave_sha256"],
    )
    if final_state != server.enrolled_state:
        raise PairedBenchmarkError(
            "{} state changed during queries".format(server.label)
        )
    server.final_state = final_state


def execute_timed_block(
    *,
    block: int,
    stage: str,
    first_sequence: int,
    args: argparse.Namespace,
    temporary_root: pathlib.Path,
    gallery: Any,
    probes: Any,
    names: Any,
    config: Mapping[str, Any],
    scene: Mapping[str, Any],
    binaries: Mapping[str, pathlib.Path],
    binary_records: Mapping[str, Mapping[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    block_started = time.perf_counter()
    block_work = temporary_root / "block-{:02d}".format(block)
    block_work.mkdir()
    keys = block_work / "keys"
    keygen, keygen_s = validation.run_command(
        [str(binaries["a38"]), "keygen", str(keys)], timeout=args.timeout
    )
    keygen_report = validation.last_json_line(keygen.stdout, "A38 client keygen")
    server_key = keys / "server.key"
    client_key = keys / "client.key"
    if not server_key.is_file() or not client_key.is_file():
        raise PairedBenchmarkError("keygen did not create both key files")
    server_key_sha256 = validation.sha256_file(server_key)

    schedule, schedule_record = schedule_for_block(
        block=block,
        stage=stage,
        seed=args.seed,
        repetitions_per_probe=args.repetitions_per_probe,
        warmup_pairs=args.warmup_pairs,
    )
    pair_work = block_work / "pairs"
    pair_work.mkdir()
    rows = prepare_ciphertexts(
        schedule=schedule,
        first_sequence=first_sequence,
        binary=binaries["a38"],
        keys=keys,
        work=pair_work,
        probes=probes,
        names=names,
        all_scores=scene["all_scores"],
        timeout=args.timeout,
    )

    enrollment_bodies = make_enrollment_bodies(gallery, names)
    gallery_payload_hash = enrollment_payload_sha256(enrollment_bodies)
    expected_names = [
        "digiface-{}-{}".format(index, names[index])
        for index in range(validation.EXPECTED_GALLERY_SIZE)
    ]
    configured_domain = config.get("dominio_score_cauchy", {}).get(
        "galleria_sintetica_base"
    )
    if not isinstance(configured_domain, dict):
        raise PairedBenchmarkError("configuration lacks the calibrated score domain")
    expected_domain = {
        "l": configured_domain.get("lower"),
        "u": configured_domain.get("upper"),
        "larghezza": configured_domain.get("width"),
    }
    if expected_domain != EXPECTED_TIGHT_DOMAIN:
        raise PairedBenchmarkError(
            "configured tight domain is {}, expected frozen {}".format(
                expected_domain, EXPECTED_TIGHT_DOMAIN
            )
        )

    startup_order = list(SERVER_LABELS if block % 2 == 0 else reversed(SERVER_LABELS))
    ports = {label: validation.free_port() for label in SERVER_LABELS}
    while ports["a33"] == ports["a38"]:
        ports["a38"] = validation.free_port()
    servers: Dict[str, ServerRuntime] = {}
    setup_records: Dict[str, Any] = {}
    teardown_records: Dict[str, Any] = {}
    teardown_exceptions: Dict[str, str] = {}
    try:
        for label in startup_order:
            server_work = block_work / label
            server_work.mkdir()
            servers[label] = launch_server(
                label,
                binaries[label],
                ports[label],
                server_work,
                str(binary_records["{}_binary".format(label)]["sha256"]),
            )
        for label in startup_order:
            setup_records[label] = install_key_and_gallery(
                servers[label],
                server_key=server_key,
                server_key_sha256=server_key_sha256,
                enrollment_bodies=enrollment_bodies,
                expected_names=expected_names,
                expected_domain=expected_domain,
                timeout=args.timeout,
            )
        a33_state = servers["a33"].enrolled_state
        a38_state = servers["a38"].enrolled_state
        if a33_state is None or a38_state is None:
            raise PairedBenchmarkError("both servers must be enrolled")
        if normalized_enrolled_state(a33_state) != normalized_enrolled_state(a38_state):
            raise PairedBenchmarkError(
                "A33 and A38 did not receive identical key/gallery/domain state"
            )

        for row in rows:
            order = ("a33", "a38") if row["pair_order"] == "A33_A38" else ("a38", "a33")
            # The same immutable bytes object is passed to both HTTP requests in this pair.
            for label in order:
                evaluate_server(row, servers[label], args.timeout)
            row["byte_identical_input_ciphertext"] = bool(
                row["a33_input_ciphertext_sha256"]
                == row["a38_input_ciphertext_sha256"]
                == row["probe_ciphertext_sha256"]
            )
            if not row["byte_identical_input_ciphertext"]:
                raise PairedBenchmarkError("paired input ciphertext hashes differ")
            add_paired_timing_fields(row)

        for label in SERVER_LABELS:
            check_final_state(servers[label], args.timeout)
    finally:
        for label in reversed(startup_order):
            if label in servers:
                try:
                    teardown_records[label] = stop_runtime(servers[label])
                except Exception as error:
                    teardown_exceptions[label] = "{}: {}".format(
                        type(error).__name__, error
                    )

    if teardown_exceptions:
        raise PairedBenchmarkError(
            "server teardown raised after attempting every runtime: {}".format(
                teardown_exceptions
            )
        )

    if set(teardown_records) != set(SERVER_LABELS):
        raise PairedBenchmarkError("not every server produced a teardown record")
    if not all(
        record["process_terminated"]
        and record["port_closed"]
        and not record["teardown_errors"]
        for record in teardown_records.values()
    ):
        raise PairedBenchmarkError(
            "server teardown did not close every process and port"
        )

    record = {
        **schedule_record,
        "key": {
            "fresh_keypair_for_block": True,
            "generated_by": "a38 frozen client binary",
            "keygen_wall_s": round(keygen_s, 3),
            "keygen_report": keygen_report,
            "client_key_bytes": client_key.stat().st_size,
            "server_key_bytes": server_key.stat().st_size,
            "server_key_sha256": server_key_sha256,
            "secret_key_material_recorded": False,
        },
        "shared_inputs": {
            "same_server_key_uploaded_to_both": True,
            "same_ordered_gallery_bytes_sent_to_both": True,
            "gallery_enrollment_payload_sha256": gallery_payload_hash,
            "same_uniform_threshold": validation.EXPECTED_THRESHOLD,
            "same_tight_score_domain": expected_domain,
            "variant_execution_contracts_checked_independently": True,
            "a33_execution_domain": EXPECTED_A33_EXECUTION_DOMAIN,
            "a33_argmin_path": EXPECTED_A33_PATH,
            "a38_execution_domain": EXPECTED_A38_EXECUTION_DOMAIN,
            "a38_argmin_path": EXPECTED_A38_PATH,
            "normalized_server_states_equal": True,
            "normalized_server_state_sha256": setup_records["a33"][
                "normalized_state_sha256"
            ],
            "same_ciphertext_bytes_per_pair": True,
            "ciphertexts_prepared_before_server_launch_and_timing": True,
        },
        "server_setup": setup_records,
        "server_processes": {
            label: servers[label].process_record for label in SERVER_LABELS
        },
        "server_state": {
            label: {
                "initial": servers[label].initial_state,
                "after_enrollment": servers[label].enrolled_state,
                "final": servers[label].final_state,
            }
            for label in SERVER_LABELS
        },
        "teardown": teardown_records,
        "block_wall_s_before_decryption": round(time.perf_counter() - block_started, 3),
        "_keys": keys,
    }
    return rows, record


def validate_decrypt_report(
    report: Mapping[str, Any], state: Mapping[str, Any], context: str
) -> Tuple[bool, Optional[int], int, Optional[str]]:
    required = {
        "autorizzato",
        "indice",
        "codice",
        "iscritti",
        "galleria_epoch",
        "galleria_revision",
    }
    missing = sorted(required.difference(report))
    if missing:
        raise PairedBenchmarkError("{} lacks fields {}".format(context, missing))
    authorized = report["autorizzato"]
    index = report["indice"]
    code = report["codice"]
    if not isinstance(authorized, bool):
        raise PairedBenchmarkError("{} authorization is not boolean".format(context))
    if not isinstance(code, int) or isinstance(code, bool):
        raise PairedBenchmarkError("{} code is not an integer".format(context))
    if authorized:
        if not isinstance(index, int) or isinstance(index, bool):
            raise PairedBenchmarkError("{} accepted without integer ID".format(context))
        if not 0 <= index < int(state["iscritti"]) or code != index + 1:
            raise PairedBenchmarkError(
                "{} returned an invalid exact ID".format(context)
            )
        name: Optional[str] = str(state["nomi"][index])
    else:
        if index is not None or code != 0:
            raise PairedBenchmarkError(
                "{} rejection is not code 0/null".format(context)
            )
        name = None
    for forbidden in ("score", "distanza", "conteggio"):
        if forbidden in report:
            raise PairedBenchmarkError("{} leaks {}".format(context, forbidden))
    expected_metadata = {
        "iscritti": state["iscritti"],
        "galleria_epoch": state["epoch"],
        "galleria_revision": state["revision"],
    }
    for field, expected in expected_metadata.items():
        if report[field] != expected:
            raise PairedBenchmarkError("{} has stale {}".format(context, field))
    return authorized, index, code, name


def decrypt_all_rows(
    *,
    rows: Sequence[Dict[str, Any]],
    block_records: Mapping[int, Mapping[str, Any]],
    binary: pathlib.Path,
    decrypt_work: pathlib.Path,
    timeout: int,
) -> None:
    decrypt_work.mkdir()
    for row in rows:
        block = int(row["block"])
        keys = block_records[block]["_keys"]
        for label in SERVER_LABELS:
            result = row["_{}_result".format(label)]
            result_path = decrypt_work / "pair-{:04d}-{}.ct".format(
                row["pair_sequence"], label
            )
            result_path.write_bytes(result)
            decrypted, wall_s = validation.run_command(
                [str(binary), "decrypt", str(keys), str(result_path)], timeout=timeout
            )
            report = validation.last_json_line(
                decrypted.stdout, "A38 client decrypt {}".format(label)
            )
            state = block_records[block]["server_state"][label]["after_enrollment"]
            authorized, index, code, name = validate_decrypt_report(
                report,
                state,
                "pair {} {}".format(row["pair_sequence"], label),
            )
            row.update(
                {
                    "{}_decrypt_wall_ms".format(label): round(wall_s * 1000.0, 3),
                    "{}_decrypt_reported_ms".format(label): report.get("decrypt_ms"),
                    "{}_authorized".format(label): authorized,
                    "{}_index".format(label): index,
                    "{}_code".format(label): code,
                    "{}_name".format(label): name,
                }
            )

        exact_a33 = (
            row["a33_authorized"],
            row["a33_index"],
            row["a33_code"],
        )
        exact_a38 = (
            row["a38_authorized"],
            row["a38_index"],
            row["a38_code"],
        )
        expected = (
            bool(row["expected_authorized"]),
            row["expected_index"],
            int(row["expected_code"]),
        )
        row["same_exact_result"] = exact_a33 == exact_a38
        row["both_match_clear_oracle"] = exact_a33 == expected and exact_a38 == expected
        row["semantic_discrepancy"] = not (
            row["same_exact_result"] and row["both_match_clear_oracle"]
        )


def public_row(row: Mapping[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in row.items() if not key.startswith("_")}


def public_block(record: Mapping[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in record.items() if not key.startswith("_")}


def geometric_mean(values: Sequence[float]) -> float:
    if not values or any(value <= 0 for value in values):
        raise PairedBenchmarkError("geometric mean requires positive values")
    return math.exp(statistics.fmean(math.log(value) for value in values))


def linear_quantile(values: Sequence[float], probability: float) -> float:
    if not values:
        raise PairedBenchmarkError("quantile requires observations")
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def regression_slope(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    center_x = (len(values) - 1) / 2.0
    center_y = statistics.fmean(values)
    numerator = sum(
        (index - center_x) * (value - center_y) for index, value in enumerate(values)
    )
    denominator = sum((index - center_x) ** 2 for index in range(len(values)))
    return numerator / denominator if denominator else 0.0


def core_group_summary(rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    if not rows:
        return {"pairs": 0}
    a33 = [float(row["a33_server_ms"]) for row in rows]
    a38 = [float(row["a38_server_ms"]) for row in rows]
    deltas = [float(row["server_delta_ms_a38_minus_a33"]) for row in rows]
    ratios = [float(row["server_ratio_a38_over_a33"]) for row in rows]
    reductions_pct = [100.0 * float(row["server_reduction_fraction"]) for row in rows]
    geometric_ratio = geometric_mean(ratios)
    return {
        "pairs": len(rows),
        "a33_server_ms": validation.distribution(a33),
        "a38_server_ms": validation.distribution(a38),
        "paired_delta_ms_a38_minus_a33": validation.distribution(deltas),
        "paired_ratio_a38_over_a33": validation.distribution(ratios),
        "paired_reduction_pct": validation.distribution(reductions_pct),
        "geometric_mean_ratio_a38_over_a33": geometric_ratio,
        "geometric_mean_reduction_pct": 100.0 * (1.0 - geometric_ratio),
        "median_paired_reduction_pct": statistics.median(reductions_pct),
        "reduction_from_separate_medians_pct": 100.0
        * (1.0 - statistics.median(a38) / statistics.median(a33)),
        "wins": {
            "a38_faster": sum(value < 0 for value in deltas),
            "a33_faster": sum(value > 0 for value in deltas),
            "ties": sum(value == 0 for value in deltas),
        },
    }


def grouped_summaries(
    rows: Sequence[Mapping[str, Any]], field: str
) -> Dict[str, Dict[str, Any]]:
    groups: Dict[str, List[Mapping[str, Any]]] = {}
    for row in rows:
        groups.setdefault(str(row[field]), []).append(row)
    return {
        key: core_group_summary(sorted(value, key=lambda row: row["pair_sequence"]))
        for key, value in sorted(groups.items())
    }


def hierarchical_bootstrap(
    rows: Sequence[Mapping[str, Any]], *, seed: int, replicates: int
) -> Dict[str, Any]:
    by_block: Dict[int, List[Mapping[str, Any]]] = {}
    for row in rows:
        by_block.setdefault(int(row["block"]), []).append(row)
    block_ids = sorted(by_block)
    if not block_ids:
        raise PairedBenchmarkError("bootstrap requires measured rows")
    rng = random.Random(seed)
    estimates: List[float] = []
    for _ in range(replicates):
        sampled_ratios: List[float] = []
        for _ in block_ids:
            selected_block = rng.choice(block_ids)
            block_rows = by_block[selected_block]
            strata: Dict[Tuple[int, str], List[Mapping[str, Any]]] = {}
            for row in block_rows:
                stratum = (int(row["probe_index"]), str(row["pair_order"]))
                strata.setdefault(stratum, []).append(row)
            expected_strata = {
                (probe_index, pair_order)
                for probe_index, _ in FRONTIER
                for pair_order in PAIR_ORDERS
            }
            if set(strata) != expected_strata:
                raise PairedBenchmarkError(
                    "bootstrap block lacks a complete probe-by-order design"
                )
            for stratum in sorted(strata):
                stratum_rows = strata[stratum]
                sampled_ratios.extend(
                    float(rng.choice(stratum_rows)["server_ratio_a38_over_a33"])
                    for _ in stratum_rows
                )
        estimates.append(100.0 * (1.0 - geometric_mean(sampled_ratios)))
    lower = linear_quantile(estimates, 0.025)
    upper = linear_quantile(estimates, 0.975)
    return {
        "method": (
            "paired stratified hierarchical nonparametric bootstrap: resample key blocks, "
            "then resample pairs within each probe-by-order stratum while preserving its fixed "
            "size; estimand is 100*(1-geometric mean A38/A33)"
        ),
        "seed": seed,
        "replicates": replicates,
        "blocks": len(block_ids),
        "ci_level": 0.95,
        "geometric_mean_reduction_pct_ci95": [lower, upper],
        "ci95_width_percentage_points": upper - lower,
        "bootstrap_median_reduction_pct": statistics.median(estimates),
    }


def analyze_timings(
    rows: Sequence[Mapping[str, Any]], *, bootstrap_seed: int, bootstrap_replicates: int
) -> Dict[str, Any]:
    measured = sorted(
        (row for row in rows if bool(row["included_in_analysis"])),
        key=lambda row: row["pair_sequence"],
    )
    if not measured:
        raise PairedBenchmarkError("no measured pairs")
    overall = core_group_summary(measured)
    by_order = grouped_summaries(measured, "pair_order")
    order_values = {
        order: by_order[order]["geometric_mean_reduction_pct"]
        for order in PAIR_ORDERS
        if order in by_order
    }
    if len(order_values) != 2:
        raise PairedBenchmarkError("both pair orders must appear in the measured set")
    order_difference = abs(order_values["A33_A38"] - order_values["A38_A33"])
    midpoint = len(measured) // 2
    first_half = measured[:midpoint]
    second_half = measured[midpoint:]
    first_summary = core_group_summary(first_half)
    second_summary = core_group_summary(second_half)
    drift_difference = abs(
        first_summary["geometric_mean_reduction_pct"]
        - second_summary["geometric_mean_reduction_pct"]
    )
    reductions = [100.0 * float(row["server_reduction_fraction"]) for row in measured]
    a33_values = [float(row["a33_server_ms"]) for row in measured]
    a38_values = [float(row["a38_server_ms"]) for row in measured]
    bootstrap = hierarchical_bootstrap(
        measured, seed=bootstrap_seed, replicates=bootstrap_replicates
    )
    return {
        "primary_timing": "server X-Tempo-Ms",
        "overall": overall,
        "by_block": grouped_summaries(measured, "block"),
        "by_stage": grouped_summaries(measured, "stage"),
        "by_probe": grouped_summaries(measured, "probe_index"),
        "by_pair_order": by_order,
        "pair_order_geometric_reduction_difference_pp": order_difference,
        "hierarchical_bootstrap": bootstrap,
        "drift_diagnostics": {
            "chronological_first_half": first_summary,
            "chronological_second_half": second_summary,
            "first_vs_second_half_geometric_reduction_difference_pp": drift_difference,
            "ordinary_least_squares_slope_ms_per_pair": {
                "a33": regression_slope(a33_values),
                "a38": regression_slope(a38_values),
            },
            "ordinary_least_squares_reduction_slope_pp_per_pair": regression_slope(
                reductions
            ),
        },
    }


def timing_fingerprint(rows: Sequence[Mapping[str, Any]]) -> str:
    fixed_fields = (
        "pair_sequence",
        "stage",
        "block",
        "phase",
        "probe_index",
        "repetition",
        "pair_order",
        "probe_ciphertext_sha256",
        "a33_server_ms",
        "a38_server_ms",
        "a33_result_sha256",
        "a38_result_sha256",
    )
    payload = [
        {field: row.get(field) for field in fixed_fields}
        for row in sorted(rows, key=lambda value: value["pair_sequence"])
    ]
    return json_sha256(payload)


def validate_complete_results(
    rows: Sequence[Mapping[str, Any]], expected_blocks: int, args: argparse.Namespace
) -> Dict[str, Any]:
    measured = [row for row in rows if row["included_in_analysis"]]
    warmups = [row for row in rows if not row["included_in_analysis"]]
    discrepancies = [row for row in rows if row.get("semantic_discrepancy")]
    ciphertext_hashes = [str(row["probe_ciphertext_sha256"]) for row in rows]
    expected_measured = expected_blocks * len(FRONTIER) * args.repetitions_per_probe
    expected_warmups = expected_blocks * args.warmup_pairs
    pbs_pairs = sorted({(row["a33_pbs"], row["a38_pbs"]) for row in rows})
    contracts = sorted({(row["a33_contract"], row["a38_contract"]) for row in rows})
    success = bool(
        len(measured) == expected_measured
        and len(warmups) == expected_warmups
        and not discrepancies
        and all(row["byte_identical_input_ciphertext"] for row in rows)
        and len(set(ciphertext_hashes)) == len(ciphertext_hashes)
        and pbs_pairs == [(EXPECTED_A33_PBS, EXPECTED_A38_PBS)]
        and contracts
        == [(validation.EXPECTED_VARCO_HEADER, validation.EXPECTED_VARCO_HEADER)]
    )
    return {
        "success": success,
        "pairs_total": len(rows),
        "measured_pairs": len(measured),
        "expected_measured_pairs": expected_measured,
        "warmup_pairs_excluded": len(warmups),
        "expected_warmup_pairs": expected_warmups,
        "semantic_discrepancies": len(discrepancies),
        "semantic_discrepancy_pair_sequences": [
            row["pair_sequence"] for row in discrepancies
        ],
        "fresh_ciphertexts_total": len(ciphertext_hashes),
        "fresh_ciphertexts_unique": len(set(ciphertext_hashes)),
        "all_ciphertexts_unique": len(set(ciphertext_hashes)) == len(ciphertext_hashes),
        "same_ciphertext_bytes_sent_to_a33_and_a38_per_pair": True,
        "pbs_pairs": [list(pair) for pair in pbs_pairs],
        "contract_pairs": [list(pair) for pair in contracts],
        "expected_pbs_reduction": EXPECTED_REDUCTION_PBS,
        "expected_pbs_reduction_fraction": EXPECTED_REDUCTION_PBS_FRACTION,
    }


def atomic_create(path: pathlib.Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".{}.".format(path.name), suffix=".tmp", dir=str(path.parent)
    )
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(
            temporary, path
        )  # Atomic no-overwrite publication on the same filesystem.
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def write_results(
    rows: Sequence[Mapping[str, Any]],
    summary: Dict[str, Any],
    output_dir: pathlib.Path,
    output_stem: str,
) -> Tuple[pathlib.Path, pathlib.Path]:
    output_dir = output_dir.resolve()
    csv_path = output_dir / "{}.csv".format(output_stem)
    json_path = output_dir / "{}.json".format(output_stem)
    if csv_path.exists() or json_path.exists():
        raise FileExistsError(
            "refusing to overwrite {} or {}".format(csv_path, json_path)
        )

    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS)
    writer.writeheader()
    for row in rows:
        writer.writerow({field: row.get(field, "") for field in CSV_FIELDS})
    csv_payload = buffer.getvalue().encode()
    summary["artifacts"] = {
        "csv": str(csv_path),
        "csv_sha256": sha256_bytes(csv_payload),
        "json": str(json_path),
        "publication": "atomic same-filesystem hard-link; existing files are never replaced",
    }
    json_payload = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode()
    atomic_create(csv_path, csv_payload)
    try:
        atomic_create(json_path, json_payload)
    except BaseException:
        # This CSV was created by this call and JSON publication failed; avoid a partial pair.
        csv_path.unlink()
        raise
    return csv_path, json_path


def git_provenance() -> Dict[str, Any]:
    # The executable and source snapshots are the authority for this frozen comparison. Avoid
    # consulting or recording mutable workspace Git state during a benchmark run.
    return {
        "queried": False,
        "reason": "frozen binary hashes, source patches, and snapshot manifests are authoritative",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="generate ephemeral keys and execute the paired FHE benchmark",
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help=(
            "short run: one block, one warm-up, two repetitions/probe, no extension; "
            "uses a non-canonical timestamped output stem"
        ),
    )
    parser.add_argument("--blocks", type=int, default=3)
    parser.add_argument("--warmup-pairs", type=int, default=4)
    parser.add_argument("--repetitions-per-probe", type=int, default=4)
    parser.add_argument("--seed", type=int, default=29_092_026)
    parser.add_argument("--bootstrap-seed", type=int, default=20_260_902)
    parser.add_argument("--bootstrap-replicates", type=int, default=20_000)
    parser.add_argument(
        "--no-auto-extend",
        action="store_true",
        help="disable the one-stage precision/order-balance extension",
    )
    parser.add_argument(
        "--extension-interval-width-pp",
        type=float,
        default=2.0,
        help="extend when the initial bootstrap CI is wider than this many percentage points",
    )
    parser.add_argument(
        "--extension-order-difference-pp",
        type=float,
        default=2.0,
        help="extend when AB and BA reductions differ by more than this many percentage points",
    )
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--a33-binary", type=pathlib.Path, default=DEFAULT_A33_BINARY)
    parser.add_argument("--a38-binary", type=pathlib.Path, default=DEFAULT_A38_BINARY)
    parser.add_argument("--output-dir", type=pathlib.Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--output-stem", default=DEFAULT_OUTPUT_STEM)
    args = parser.parse_args()
    if args.smoke:
        args.blocks = 1
        args.warmup_pairs = 1
        args.repetitions_per_probe = 2
        args.no_auto_extend = True
        args.bootstrap_replicates = min(args.bootstrap_replicates, 2_000)
        if args.output_stem == DEFAULT_OUTPUT_STEM:
            timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H%M%S.%fZ")
            args.output_stem = "fhe_digiface_exact_paired_a33_a38_smoke_{}".format(
                timestamp
            )
    return args


def main() -> int:
    args = parse_args()
    validate_args(args)
    if tuple(validation.HISTORICAL_FRONTIER) != FRONTIER:
        raise PairedBenchmarkError(
            "validation dependency frontier no longer matches the freeze"
        )
    binaries = {
        "a33": args.a33_binary.resolve(),
        "a38": args.a38_binary.resolve(),
    }
    inputs_before = collect_provenance(binaries["a33"], binaries["a38"])
    validate_frozen_binaries(inputs_before)
    gallery, probes, names, config, scene = validation.load_scene()
    for probe_index, expected_score in FRONTIER:
        observed = int(scene["all_scores"][probe_index].min())
        if observed != expected_score:
            raise PairedBenchmarkError(
                "frontier probe {} score is {}, expected {}".format(
                    probe_index, observed, expected_score
                )
            )

    measured_per_block = len(FRONTIER) * args.repetitions_per_probe
    dry_plan = {
        "mode": "run" if args.run else "dry_validation_only",
        "smoke": args.smoke,
        "exact_id_requirement": (
            "one encrypted scalar: 0=reject; i+1=accepted exact nearest gallery identity"
        ),
        "protocol": validation.EXPECTED_VARCO_HEADER,
        "primary_timing": "server X-Tempo-Ms",
        "secondary_timing": "client-observed HTTP wall milliseconds",
        "frontier_probe_indices_and_min_scores": [list(value) for value in FRONTIER],
        "initial_blocks": args.blocks,
        "fresh_keypair_per_block": True,
        "warmup_pairs_per_block_excluded": args.warmup_pairs,
        "fresh_ciphertexts_per_probe_per_block": args.repetitions_per_probe,
        "measured_pairs_per_block": measured_per_block,
        "initial_measured_pairs": args.blocks * measured_per_block,
        "initial_warmup_pairs": args.blocks * args.warmup_pairs,
        "same_ciphertext_bytes_within_each_a33_a38_pair": True,
        "balanced_order_per_probe_per_block": {
            "A33_A38": args.repetitions_per_probe // 2,
            "A38_A33": args.repetitions_per_probe // 2,
        },
        "startup_order_alternates_by_block": True,
        "block_preparation_policy": (
            "blocks execute sequentially; within each block keygen and every encryption finish "
            "before either server launch, then excluded warmups precede measured pairs"
        ),
        "schedule_preview": build_schedule_preview(args, args.blocks),
        "automatic_extension": {
            "enabled": not args.no_auto_extend,
            "at_most_one_additional_stage": True,
            "additional_blocks": args.blocks,
            "additional_measured_pairs": args.blocks * measured_per_block,
            "preserves_initial_rows": True,
            "trigger_ci95_width_gt_pp": args.extension_interval_width_pp,
            "trigger_ab_ba_difference_gt_pp": args.extension_order_difference_pp,
        },
        "decryption_deferred_until_all_timed_pairs_complete": True,
        "bootstrap_design": (
            "resample key blocks, then rows within fixed probe-by-order strata while preserving "
            "each stratum size"
        ),
        "expected_pbs": {
            "a33": EXPECTED_A33_PBS,
            "a38": EXPECTED_A38_PBS,
            "reduction": EXPECTED_REDUCTION_PBS,
            "reduction_fraction": EXPECTED_REDUCTION_PBS_FRACTION,
        },
        "independent_server_state_contract": {
            "a33": {
                "tight_domain": EXPECTED_TIGHT_DOMAIN,
                "required_path": EXPECTED_A33_PATH,
                "required_execution_domain": EXPECTED_A33_EXECUTION_DOMAIN,
            },
            "a38": {
                "tight_domain": EXPECTED_TIGHT_DOMAIN,
                "required_path": EXPECTED_A38_PATH,
                "required_execution_domain": EXPECTED_A38_EXECUTION_DOMAIN,
            },
        },
        "clear_scene": scene["clear_summary"],
        "frozen_binaries": {
            label: inputs_before["{}_binary".format(label)] for label in SERVER_LABELS
        },
    }
    if not args.run:
        print(json.dumps(dry_plan, indent=2, sort_keys=True))
        print(
            "No key generation, server launch, FHE query, or result write was performed."
        )
        return 0

    canonical_parameters = {
        "blocks": 3,
        "warmup_pairs": 4,
        "repetitions_per_probe": 4,
        "seed": 29_092_026,
        "bootstrap_seed": 20_260_902,
        "bootstrap_replicates": 20_000,
        "auto_extend": True,
        "extension_interval_width_pp": 2.0,
        "extension_order_difference_pp": 2.0,
    }
    observed_parameters = {
        "blocks": args.blocks,
        "warmup_pairs": args.warmup_pairs,
        "repetitions_per_probe": args.repetitions_per_probe,
        "seed": args.seed,
        "bootstrap_seed": args.bootstrap_seed,
        "bootstrap_replicates": args.bootstrap_replicates,
        "auto_extend": not args.no_auto_extend,
        "extension_interval_width_pp": args.extension_interval_width_pp,
        "extension_order_difference_pp": args.extension_order_difference_pp,
    }
    if (
        args.output_stem == DEFAULT_OUTPUT_STEM
        and observed_parameters != canonical_parameters
    ):
        raise PairedBenchmarkError(
            "the canonical output stem requires the preregistered full-run parameters; "
            "use a distinct --output-stem for a custom or reduced run"
        )

    output_dir = args.output_dir.resolve()
    csv_path = output_dir / "{}.csv".format(args.output_stem)
    json_path = output_dir / "{}.json".format(args.output_stem)
    if csv_path.exists() or json_path.exists():
        raise FileExistsError(
            "refusing to overwrite {} or {}".format(csv_path, json_path)
        )

    run_started_utc = dt.datetime.now(dt.timezone.utc).isoformat()
    run_started = time.perf_counter()
    host_before = validation.host_runtime_snapshot()
    rows: List[Dict[str, Any]] = []
    block_records: Dict[int, Dict[str, Any]] = {}
    initial_analysis: Optional[Dict[str, Any]] = None
    extension_record: Dict[str, Any] = {}
    temporary_path: Optional[pathlib.Path] = None
    key_paths: List[pathlib.Path] = []

    with tempfile.TemporaryDirectory(prefix="fhe-exact-id-paired-") as temporary:
        temporary_path = pathlib.Path(temporary)
        for block in range(args.blocks):
            new_rows, block_record = execute_timed_block(
                block=block,
                stage="initial",
                first_sequence=len(rows),
                args=args,
                temporary_root=temporary_path,
                gallery=gallery,
                probes=probes,
                names=names,
                config=config,
                scene=scene,
                binaries=binaries,
                binary_records=inputs_before,
            )
            rows.extend(new_rows)
            block_records[block] = block_record
            key_paths.append(block_record["_keys"])
            print(
                "timed initial block {}/{} ({} measured pairs total)".format(
                    block + 1,
                    args.blocks,
                    sum(bool(row["included_in_analysis"]) for row in rows),
                ),
                file=sys.stderr,
                flush=True,
            )

        initial_rows = list(rows)
        initial_fingerprint = timing_fingerprint(initial_rows)
        initial_analysis = analyze_timings(
            initial_rows,
            bootstrap_seed=args.bootstrap_seed,
            bootstrap_replicates=args.bootstrap_replicates,
        )
        ci_width = initial_analysis["hierarchical_bootstrap"][
            "ci95_width_percentage_points"
        ]
        order_difference = initial_analysis[
            "pair_order_geometric_reduction_difference_pp"
        ]
        reasons = []
        if ci_width > args.extension_interval_width_pp:
            reasons.append("bootstrap_ci95_width")
        if order_difference > args.extension_order_difference_pp:
            reasons.append("ab_ba_order_difference")
        extension_triggered = bool(reasons) and not args.no_auto_extend
        extension_record = {
            "enabled": not args.no_auto_extend,
            "triggered": extension_triggered,
            "trigger_reasons": reasons,
            "initial_ci95_width_pp": ci_width,
            "initial_ab_ba_difference_pp": order_difference,
            "thresholds_pp": {
                "ci95_width": args.extension_interval_width_pp,
                "ab_ba_difference": args.extension_order_difference_pp,
            },
            "initial_pairs_timing_sha256_before_extension": initial_fingerprint,
            "initial_rows_preserved": True,
        }
        if extension_triggered:
            for offset in range(args.blocks):
                block = args.blocks + offset
                new_rows, block_record = execute_timed_block(
                    block=block,
                    stage="extension",
                    first_sequence=len(rows),
                    args=args,
                    temporary_root=temporary_path,
                    gallery=gallery,
                    probes=probes,
                    names=names,
                    config=config,
                    scene=scene,
                    binaries=binaries,
                    binary_records=inputs_before,
                )
                rows.extend(new_rows)
                block_records[block] = block_record
                key_paths.append(block_record["_keys"])
                print(
                    "timed extension block {}/{} ({} measured pairs total)".format(
                        offset + 1,
                        args.blocks,
                        sum(bool(row["included_in_analysis"]) for row in rows),
                    ),
                    file=sys.stderr,
                    flush=True,
                )
            preserved = timing_fingerprint(rows[: len(initial_rows)])
            if preserved != initial_fingerprint:
                raise PairedBenchmarkError(
                    "extension mutated the initial paired timings"
                )
            extension_record["initial_pairs_timing_sha256_after_extension"] = preserved
            extension_record["initial_rows_preserved"] = True

        # This is deliberately after the complete initial+optional-extension timed phase.
        decrypt_all_rows(
            rows=rows,
            block_records=block_records,
            binary=binaries["a38"],
            decrypt_work=temporary_path / "decrypted-results",
            timeout=args.timeout,
        )

    if temporary_path is None or temporary_path.exists():
        raise PairedBenchmarkError("temporary key directory was not removed")
    if any(path.exists() for path in key_paths):
        raise PairedBenchmarkError("at least one ephemeral key directory remains")

    inputs_after = collect_provenance(binaries["a33"], binaries["a38"])
    unchanged = {
        key: inputs_before[key]["sha256"] == inputs_after[key]["sha256"]
        for key in inputs_before
    }
    final_analysis = analyze_timings(
        rows,
        bootstrap_seed=args.bootstrap_seed,
        bootstrap_replicates=args.bootstrap_replicates,
    )
    total_blocks = len(block_records)
    validation_summary = validate_complete_results(rows, total_blocks, args)
    server_key_hashes = [
        block_records[index]["key"]["server_key_sha256"]
        for index in sorted(block_records)
    ]
    validation_summary["fresh_server_keys_per_block"] = (
        len(set(server_key_hashes)) == len(server_key_hashes) == total_blocks
    )
    validation_summary["server_key_hashes_unique"] = len(set(server_key_hashes))
    teardown_success = all(
        block["teardown"][label]["process_terminated"]
        and block["teardown"][label]["port_closed"]
        and not block["teardown"][label]["teardown_errors"]
        for block in block_records.values()
        for label in SERVER_LABELS
    )
    success = bool(
        validation_summary["success"]
        and validation_summary["fresh_server_keys_per_block"]
        and teardown_success
        and all(unchanged.values())
    )

    public_rows = [public_row(row) for row in rows]
    summary = {
        "schema_version": 1,
        "run_started_utc": run_started_utc,
        "run_finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "run_wall_s": round(time.perf_counter() - run_started, 3),
        "argv": sys.argv,
        "success": success,
        "scope": (
            "paired implementation latency and exact clear-oracle agreement on five fixed "
            "DigiFace frontier probes; not a population accuracy estimate or p-fail proof"
        ),
        "plan": dry_plan,
        "scene": {
            "cache_metadata": scene["cache_metadata"],
            "clear_summary": scene["clear_summary"],
        },
        "extension_decision": extension_record,
        "initial_timing_analysis": initial_analysis,
        "final_timing_analysis": final_analysis,
        "result_validation": validation_summary,
        "pairs": public_rows,
        "blocks": [
            public_block(block_records[index]) for index in sorted(block_records)
        ],
        "lifecycle": {
            "all_ciphertexts_prepared_before_corresponding_timing_block": True,
            "blocks_prepared_and_executed_sequentially": True,
            "excluded_warmups_follow_each_block_preparation": True,
            "extension_preparation_policy": "only_after_preregistered_trigger",
            "extension_blocks_prepared": extension_record["triggered"],
            "all_decryption_deferred_until_every_timed_pair_completed": True,
            "decryption_client": "frozen A38 varco_demo (wire-compatible for both outputs)",
            "temporary_directory_removed": True,
            "all_ephemeral_key_directories_removed": True,
            "client_secret_or_client_key_hash_recorded": False,
            "all_server_processes_terminated_and_ports_closed": teardown_success,
        },
        "provenance": {
            "inputs_before": inputs_before,
            "inputs_after": inputs_after,
            "inputs_unchanged_during_run": unchanged,
            "git": git_provenance(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "numpy": __import__("numpy").__version__,
            "host_runtime_before": host_before,
            "host_runtime_after": validation.host_runtime_snapshot(),
        },
    }
    csv_path, json_path = write_results(
        public_rows, summary, args.output_dir, args.output_stem
    )
    print(
        json.dumps(
            {
                "success": success,
                "measured_pairs": validation_summary["measured_pairs"],
                "warmup_pairs_excluded": validation_summary["warmup_pairs_excluded"],
                "extension_triggered": extension_record["triggered"],
                "geometric_mean_reduction_pct": final_analysis["overall"][
                    "geometric_mean_reduction_pct"
                ],
                "semantic_discrepancies": validation_summary["semantic_discrepancies"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    print("wrote {}".format(csv_path))
    print("wrote {}".format(json_path))
    return 0 if success else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        FileNotFoundError,
        FileExistsError,
        PairedBenchmarkError,
        validation.ValidationError,
    ) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        raise SystemExit(2)
