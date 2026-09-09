"""Standalone clear-vs-FHE validation of the exact-ID DigiFace demo scene.

The default invocation is intentionally cheap: it validates the cache, configuration, cohort
boundaries, and historical clear-score fixtures, then prints the run plan.  Pass ``--run`` to
build and bind the current ``varco_demo`` binary, generate fresh temporary keys, enroll all 127
cached templates at T=4, and execute 16 fresh encryptions for each historical frontier probe.
``--primary-suite`` additionally evaluates every genuine probe and the 500 non-tuning primary
test impostors once each.

Every measured query follows the real protocol boundary:

    plaintext vector -> dual-layout GLWE -> exact argmin + winner threshold -> one coded LWE

For every query the clear oracle and FHE result must agree on the complete open-set result:
``0``/``null`` for rejection, otherwise ``argmin + 1`` and the exact nearest gallery index.

Results are written to new timestamped CSV/JSON files.  Existing artifacts are never replaced.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import http.client
import json
import math
import os
import pathlib
import platform
import shlex
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


ROOT = pathlib.Path(__file__).resolve().parents[1]
CRATE = ROOT / "experiments" / "14_pipeline_tfhe_rs"
RUST_SOURCE = CRATE / "src" / "bin" / "varco_demo.rs"
CORE_SOURCE = CRATE / "src" / "private_argmin.rs"
LIB_SOURCE = CRATE / "src" / "lib.rs"
DEFAULT_BINARY = CRATE / "target" / "release" / "varco_demo"
CONFIG_PATH = ROOT / "demo" / "config.json"
CACHE_PATH = ROOT / "datasets" / "digiface" / "_q_demo_calibrazione_resnet100.npz"
RESULTS_DIR = ROOT / "benchmark" / "results"

HISTORICAL_FRONTIER: Tuple[Tuple[int, int], ...] = (
    (265, 2),
    (758, 3),
    (211, 4),
    (1943, 5),
    (407, 7),
)
EXPECTED_GALLERY_SIZE = 127
EXPECTED_THRESHOLD = 4
EXPECTED_DIMENSION = 512
EXPECTED_Q_MAX = 3
EXPECTED_TUNING_IMPOSTORS = 500
EXPECTED_PRIMARY_IMPOSTORS = 500
EXPECTED_VARCO_HEADER = "exact-open-set-id-v2"
EXPECTED_COMPARATOR = "argmin_esatto_bucket_bits_dual_glwe"
ALIGNED_UNIFORM_THRESHOLD = 1023
A29_GENERAL_PATH = "a29_general"
A38_ALIGNED_PATH = "a38_combined"
SCORE_DOMAIN_WIDTH_MAX = 4096
I64_MIN = -(1 << 63)
I64_MAX = (1 << 63) - 1
EXPECTED_CONTRACT = {
    "wire_version": 2,
    "probe_magic": int.from_bytes(b"VRCOPRB2", "little"),
    "probe_layout": 1,
    "score_delta_log": 52,
    "low_mod16_offset": 1024,
    "low_mod16_delta_log": 60,
    "output_magic": int.from_bytes(b"VRCOUTP2", "little"),
    "output_mode": 2,
    "code_delta_log": 56,
    "codice": "0=rifiuto; i+1=identita_accettata",
    "un_solo_lwe": True,
}
EXPECTED_CONFIG_CONTRACT = {
    key: value
    for key, value in EXPECTED_CONTRACT.items()
    if key not in {"probe_magic", "output_magic"}
}
EXPECTED_CONFIG_CONTRACT.update(
    {
        "score_bits": 12,
        "probe_norm2_max": 1024,
        "score_domain_width_max": 4096,
        "tie_break": "primo_indice_galleria",
        "selezione_soglia": "solo_del_vincitore_argmin",
    }
)

CSV_FIELDS = [
    "sequence",
    "suite",
    "probe_index",
    "probe_name",
    "cohort",
    "repetition",
    "clear_min_score",
    "clear_argmin_index",
    "clear_argmin_name",
    "clear_match_count",
    "expected_authorized",
    "expected_index",
    "expected_code",
    "actual_authorized",
    "actual_index",
    "actual_code",
    "actual_name",
    "discrepancy",
    "error",
    "encrypt_wall_ms",
    "encrypt_reported_ms",
    "probe_ciphertext_bytes",
    "probe_ciphertext_sha256",
    "http_wall_ms",
    "server_reported_ms",
    "pbs",
    "varco_contract",
    "output_epoch",
    "output_revision",
    "output_gallery_size",
    "output_lwe_size",
    "result_ciphertext_bytes",
    "result_ciphertext_sha256",
    "decrypt_wall_ms",
    "decrypt_reported_ms",
]


class ValidationError(RuntimeError):
    """Raised when an input or protocol invariant is not satisfied."""


def host_runtime_snapshot() -> Dict[str, Any]:
    """Capture only non-secret scheduling context needed to interpret timings."""

    try:
        load_average = [round(value, 3) for value in os.getloadavg()]
    except OSError:
        load_average = []
    return {
        "load_average_1m_5m_15m": load_average,
        "logical_cpu_count": os.cpu_count(),
        "rayon_num_threads": os.environ.get("RAYON_NUM_THREADS"),
    }


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_arrays(*arrays: Any) -> str:
    import numpy as np

    digest = hashlib.sha256()
    for array in arrays:
        digest.update(np.ascontiguousarray(array).tobytes())
    return digest.hexdigest()


def scalar(value: Any) -> Any:
    item = value.item()
    return item.item() if hasattr(item, "item") else item


def last_json_line(stdout: str, label: str) -> Dict[str, Any]:
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise ValidationError(
        "{} did not emit a JSON object: {!r}".format(label, stdout[-1000:])
    )


def run_command(
    argv: Sequence[str],
    *,
    cwd: Optional[pathlib.Path] = None,
    timeout: int = 900,
) -> Tuple[subprocess.CompletedProcess, float]:
    started = time.perf_counter()
    result = subprocess.run(
        list(argv),
        cwd=str(cwd) if cwd is not None else None,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result, time.perf_counter() - started


def command_text(argv: Sequence[str], cwd: Optional[pathlib.Path] = None) -> str:
    result, _ = run_command(argv, cwd=cwd, timeout=60)
    return result.stdout.strip() or result.stderr.strip()


def file_record(path: pathlib.Path) -> Dict[str, Any]:
    resolved = path.resolve()
    return {
        "path": str(resolved),
        "bytes": resolved.stat().st_size,
        "sha256": sha256_file(resolved),
    }


def source_records(binary: Optional[pathlib.Path] = None) -> Dict[str, Dict[str, Any]]:
    records = {
        "harness": file_record(pathlib.Path(__file__)),
        "config": file_record(CONFIG_PATH),
        "cache": file_record(CACHE_PATH),
        "rust_source": file_record(RUST_SOURCE),
        "exact_argmin_core": file_record(CORE_SOURCE),
        "rust_library": file_record(LIB_SOURCE),
        "cargo_toml": file_record(CRATE / "Cargo.toml"),
        "cargo_lock": file_record(CRATE / "Cargo.lock"),
    }
    if binary is not None:
        records["rust_binary"] = file_record(binary)
    return records


def require_exact_subset(
    actual: Mapping[str, Any], expected: Mapping[str, Any], context: str
) -> None:
    for key, expected_value in expected.items():
        actual_value = actual.get(key)
        if actual_value != expected_value:
            raise ValidationError(
                "{} {!r} is {!r}, expected {!r}".format(
                    context, key, actual_value, expected_value
                )
            )


def load_scene() -> Tuple[Any, Any, Any, Dict[str, Any], Dict[str, Any]]:
    import numpy as np

    if not CONFIG_PATH.is_file():
        raise FileNotFoundError(CONFIG_PATH)
    if not CACHE_PATH.is_file():
        raise FileNotFoundError(CACHE_PATH)

    config = json.loads(CONFIG_PATH.read_text())
    with np.load(CACHE_PATH, allow_pickle=False) as cached:
        required = {
            "G",
            "P",
            "names",
            "scala",
            "q_max",
            "k_galleria",
            "k_probe",
            "n_galleria",
            "modello",
            "manifest_sha256",
            "manifest_entries",
            "manifest_format",
        }
        missing = sorted(required.difference(cached.files))
        if missing:
            raise ValidationError("cache fields missing: {}".format(missing))
        gallery = np.asarray(cached["G"], dtype=np.int64)
        probes = np.asarray(cached["P"], dtype=np.int64)
        names = np.asarray(cached["names"])
        cache_metadata = {
            key: scalar(cached[key])
            for key in (
                "scala",
                "q_max",
                "k_galleria",
                "k_probe",
                "n_galleria",
                "modello",
                "manifest_sha256",
                "manifest_entries",
                "manifest_format",
            )
        }

    calibration = config.get("calibrazione_sintetica", {})
    expected_config = {
        "dim": EXPECTED_DIMENSION,
        "T": EXPECTED_THRESHOLD,
        "n_galleria_demo": EXPECTED_GALLERY_SIZE,
        "decisione": "exact_argmin_then_selected_threshold",
    }
    for key, expected in expected_config.items():
        if config.get(key) != expected:
            raise ValidationError(
                "config {!r} is {!r}, expected {!r}".format(
                    key, config.get(key), expected
                )
            )
    configured_contract = config.get("contratto_esatto")
    if not isinstance(configured_contract, dict):
        raise ValidationError("config 'contratto_esatto' is missing or not an object")
    require_exact_subset(
        configured_contract, EXPECTED_CONFIG_CONTRACT, "config contratto_esatto"
    )
    comparator = config.get("comparatore_fhe")
    if not isinstance(comparator, dict):
        raise ValidationError("config 'comparatore_fhe' is missing or not an object")
    if comparator.get("stato") != EXPECTED_COMPARATOR:
        raise ValidationError("config does not select the current exact-ID comparator")
    if int(calibration.get("impostori_tuning", -1)) != EXPECTED_TUNING_IMPOSTORS:
        raise ValidationError("unexpected DigiFace tuning cohort size")
    if int(calibration.get("impostori_test", -1)) != EXPECTED_PRIMARY_IMPOSTORS:
        raise ValidationError("unexpected DigiFace primary-test cohort size")
    if gallery.shape != (EXPECTED_GALLERY_SIZE, EXPECTED_DIMENSION):
        raise ValidationError("unexpected gallery shape: {}".format(gallery.shape))
    if probes.shape != (2000, EXPECTED_DIMENSION):
        raise ValidationError("unexpected probe shape: {}".format(probes.shape))
    if names.shape != (len(probes),):
        raise ValidationError("unexpected names shape: {}".format(names.shape))
    if int(cache_metadata["n_galleria"]) != EXPECTED_GALLERY_SIZE:
        raise ValidationError("cache n_galleria does not match the configured scene")
    if int(cache_metadata["k_galleria"]) != int(config["k_galleria"]):
        raise ValidationError("cache k_galleria does not match the configuration")
    if int(cache_metadata["k_probe"]) != int(config["k_probe"]):
        raise ValidationError("cache k_probe does not match the configuration")
    if not math.isclose(
        float(cache_metadata["scala"]),
        float(config["scala"]),
        rel_tol=0.0,
        abs_tol=5e-9,
    ):
        raise ValidationError("cache scale does not match the configuration")
    if str(cache_metadata["manifest_sha256"]) != calibration.get(
        "file_metadata_manifest_sha256"
    ):
        raise ValidationError("cache file manifest does not match the configuration")
    configured_q_max = 2 ** (int(config["bit"]) - 1) - 1
    if configured_q_max != EXPECTED_Q_MAX:
        raise ValidationError("unexpected quantization domain in the configuration")
    if int(cache_metadata["q_max"]) != configured_q_max:
        raise ValidationError("cache q_max does not match the configured bit width")
    if str(cache_metadata["modello"]) != str(config["modello"]):
        raise ValidationError("cache model does not match the configuration")
    if int(np.abs(gallery).max()) > configured_q_max:
        raise ValidationError("gallery exceeds the configured quantization domain")
    if int(np.abs(probes).max()) > configured_q_max:
        raise ValidationError("probes exceed the configured quantization domain")

    tuning_start = EXPECTED_GALLERY_SIZE
    primary_start = tuning_start + EXPECTED_TUNING_IMPOSTORS
    primary_end = primary_start + EXPECTED_PRIMARY_IMPOSTORS
    scene_sha256 = sha256_arrays(
        gallery,
        probes[:EXPECTED_GALLERY_SIZE],
        probes[tuning_start:primary_start],
        probes[primary_start:primary_end],
    )
    # The 500-case primary test is the leading, nested subset of the full non-tuning holdout.
    holdout_sha256 = sha256_arrays(probes[primary_start:])
    if scene_sha256 != calibration.get("scene_sha256"):
        raise ValidationError("cache scene hash does not match demo/config.json")
    if holdout_sha256 != calibration.get("holdout_sha256"):
        raise ValidationError("cache holdout hash does not match demo/config.json")

    gallery_norms = np.sum(gallery * gallery, axis=1, dtype=np.int64)
    all_scores = gallery_norms[None, :] - 2 * (probes @ gallery.T)
    for probe_index, expected_score in HISTORICAL_FRONTIER:
        actual_score = int(all_scores[probe_index].min())
        if actual_score != expected_score:
            raise ValidationError(
                "historical probe {} has minimum {}, expected {}".format(
                    probe_index, actual_score, expected_score
                )
            )

    clear_argmins = np.argmin(all_scores, axis=1)
    clear_minima = all_scores[np.arange(len(probes)), clear_argmins]
    primary_minima = clear_minima[primary_start:primary_end]
    genuine_argmins = clear_argmins[:EXPECTED_GALLERY_SIZE]
    genuine_minima = clear_minima[:EXPECTED_GALLERY_SIZE]
    genuine_clear_accepts = int(np.count_nonzero(genuine_minima <= EXPECTED_THRESHOLD))
    genuine_exact_identifications = int(
        np.count_nonzero(
            (genuine_minima <= EXPECTED_THRESHOLD)
            & (genuine_argmins == np.arange(EXPECTED_GALLERY_SIZE))
        )
    )
    primary_impostor_clear_accepts = int(
        np.count_nonzero(primary_minima <= EXPECTED_THRESHOLD)
    )
    if genuine_clear_accepts != EXPECTED_GALLERY_SIZE:
        raise ValidationError(
            "the cached genuine suite no longer has 127 clear accepts"
        )
    if genuine_exact_identifications != EXPECTED_GALLERY_SIZE:
        raise ValidationError(
            "the cached genuine suite no longer has 127 exact rank-1 identifications"
        )
    if primary_impostor_clear_accepts != int(calibration.get("accettati_test", -1)):
        raise ValidationError(
            "primary-test clear accepts do not match the configuration"
        )
    clear_summary = {
        "gallery_shape": list(gallery.shape),
        "probe_shape": list(probes.shape),
        "scene_sha256": scene_sha256,
        "scene_sha256_verified_against_config": True,
        "holdout_sha256": holdout_sha256,
        "holdout_sha256_verified_against_config": True,
        "gallery_l1_max": int(np.abs(gallery).sum(axis=1).max()),
        "gallery_squared_norm_max": int(gallery_norms.max()),
        "historical_min_scores": {
            str(index): int(all_scores[index].min()) for index, _ in HISTORICAL_FRONTIER
        },
        "genuine_clear_accepts": genuine_clear_accepts,
        "genuine_exact_identifications": genuine_exact_identifications,
        "genuine_dir": genuine_exact_identifications / EXPECTED_GALLERY_SIZE,
        "genuine_total": EXPECTED_GALLERY_SIZE,
        "primary_impostor_clear_accepts": primary_impostor_clear_accepts,
        "primary_impostor_total": EXPECTED_PRIMARY_IMPOSTORS,
        "primary_test_indices": [primary_start, primary_end - 1],
    }
    return (
        gallery,
        probes,
        names,
        config,
        {
            "cache_metadata": cache_metadata,
            "clear_summary": clear_summary,
            "gallery_norms": gallery_norms,
            "all_scores": all_scores,
        },
    )


def cohort_for_index(index: int) -> str:
    primary_start = EXPECTED_GALLERY_SIZE + EXPECTED_TUNING_IMPOSTORS
    primary_end = primary_start + EXPECTED_PRIMARY_IMPOSTORS
    if index < EXPECTED_GALLERY_SIZE:
        return "genuine"
    if index < primary_start:
        return "tuning_impostor"
    if index < primary_end:
        return "primary_test_impostor"
    return "extended_holdout_non_tuning_impostor"


def build_cases(
    include_primary: bool, repetitions: int, only_probes: Sequence[int] = ()
) -> List[Tuple[str, int, int]]:
    if repetitions < 1:
        raise ValidationError("--regression-repetitions must be at least one")
    if only_probes:
        if include_primary:
            raise ValidationError(
                "--only-probe cannot be combined with --primary-suite"
            )
        if len(set(only_probes)) != len(only_probes):
            raise ValidationError("--only-probe values must be unique")
        return [
            ("targeted_regression", probe_index, repetition)
            for probe_index in only_probes
            for repetition in range(repetitions)
        ]
    cases = [
        ("historical_frontier", probe_index, repetition)
        for probe_index, _ in HISTORICAL_FRONTIER
        for repetition in range(repetitions)
    ]
    if include_primary:
        primary_start = EXPECTED_GALLERY_SIZE + EXPECTED_TUNING_IMPOSTORS
        cases.extend(
            ("primary_genuine", index, 0) for index in range(EXPECTED_GALLERY_SIZE)
        )
        cases.extend(
            ("primary_test_impostor", index, 0)
            for index in range(
                primary_start, primary_start + EXPECTED_PRIMARY_IMPOSTORS
            )
        )
    return cases


def http_request(
    port: int,
    method: str,
    path: str,
    body: bytes = b"",
    content_type: str = "application/octet-stream",
    timeout: int = 900,
) -> Tuple[int, bytes, Dict[str, str]]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        headers = {"Content-Type": content_type} if body else {}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        return response.status, data, response_headers
    finally:
        connection.close()


def http_upload_file(
    port: int,
    path: str,
    source: pathlib.Path,
    timeout: int = 900,
) -> Tuple[int, bytes, Dict[str, str]]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        with source.open("rb") as handle:
            connection.request(
                "POST",
                path,
                body=handle,
                headers={
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(source.stat().st_size),
                },
            )
            response = connection.getresponse()
            data = response.read()
            response_headers = {
                key.lower(): value for key, value in response.getheaders()
            }
            return response.status, data, response_headers
    finally:
        connection.close()


def require_http_ok(status: int, body: bytes, context: str) -> Dict[str, Any]:
    if status != 200:
        raise ValidationError(
            "{} failed with HTTP {}: {}".format(
                context, status, body.decode(errors="replace")
            )
        )
    if not body:
        return {}
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("{} returned invalid JSON".format(context)) from exc
    if not isinstance(value, dict):
        raise ValidationError("{} returned a non-object JSON value".format(context))
    return value


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_for_server(
    server: subprocess.Popen, port: int, timeout_s: float = 15.0
) -> Dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        if server.poll() is not None:
            raise ValidationError(
                "varco_demo exited during startup with code {}".format(
                    server.returncode
                )
            )
        try:
            status, body, _ = http_request(port, "GET", "/stato", timeout=2)
            if status == 200:
                return require_http_ok(status, body, "initial /stato")
        except (OSError, http.client.HTTPException) as exc:
            last_error = exc
        time.sleep(0.05)
    raise ValidationError("varco_demo did not start: {!r}".format(last_error))


def process_binding(server: subprocess.Popen, binary: pathlib.Path) -> Dict[str, Any]:
    command = command_text(["ps", "-p", str(server.pid), "-o", "command="])
    started = command_text(["ps", "-p", str(server.pid), "-o", "lstart="])
    tokens = shlex.split(command)
    observed_executable = pathlib.Path(tokens[0]).resolve() if tokens else None
    expected_executable = binary.resolve()
    exact = observed_executable == expected_executable
    if not exact:
        raise ValidationError(
            "PID {} is not bound to {}: {}".format(
                server.pid, expected_executable, command
            )
        )
    return {
        "pid": server.pid,
        "expected_binary_path": str(expected_executable),
        "observed_executable_path": str(observed_executable),
        "ps_command": command,
        "ps_started": started,
        "exact_path_verified": True,
    }


def percentile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def distribution(values: Iterable[Optional[float]]) -> Optional[Dict[str, float]]:
    present = [float(value) for value in values if value is not None]
    if not present:
        return None
    return {
        "count": len(present),
        "min": round(min(present), 3),
        "median": round(float(statistics.median(present)), 3),
        "mean": round(float(statistics.mean(present)), 3),
        "p95": round(percentile(present, 0.95), 3),
        "max": round(max(present), 3),
    }


def parse_float(headers: Mapping[str, str], key: str) -> Optional[float]:
    value = headers.get(key)
    return None if value is None else float(value)


def parse_int(headers: Mapping[str, str], key: str) -> Optional[int]:
    value = headers.get(key)
    return None if value is None else int(value)


def _or_reduction_pbs(items: int) -> int:
    count = 0
    while items > 1:
        items = (items + 3) // 4
        count += items
    return count


def _reduction_pbs_with_radix(items: int, radix: int) -> int:
    if radix < 2:
        raise ValidationError("reduction radix must be at least two")
    count = 0
    while items > 1:
        items = (items + radix - 1) // radix
        count += items
    return count


def _exclusive_prefix_pbs_with_radix(items: int, radix: int) -> int:
    if items <= 0 or radix < 2:
        raise ValidationError("exclusive-prefix dimensions are invalid")
    if items <= 2:
        return 0
    if items <= radix:
        return items - 2
    totals = 0
    expansion = 0
    groups = 0
    for start in range(0, items, radix):
        length = min(radix, items - start)
        groups += 1
        totals += int(length > 1)
        expansion += max(0, length - 2) if start == 0 else length - 1
    return totals + expansion + _exclusive_prefix_pbs_with_radix(groups, radix)


def _radix4_exclusive_prefix_pbs(items: int) -> int:
    if items <= 2:
        return 0
    if items <= 4:
        return items - 2
    totals = 0
    expansion = 0
    groups = 0
    for start in range(0, items, 4):
        length = min(4, items - start)
        groups += 1
        totals += int(length > 1)
        expansion += max(0, length - 2) if start == 0 else length - 1
    return totals + expansion + _radix4_exclusive_prefix_pbs(groups)


def _first_one_scan_pbs(items: int) -> int:
    groups = (items + 2) // 3
    group_totals = sum(min(3, items - start) > 1 for start in range(0, items, 3))
    return group_totals + _radix4_exclusive_prefix_pbs(groups) + items


def _a38_scan_output_pbs(items: int) -> int:
    groups = (items + 2) // 3
    group_nodes = sum(min(3, items - start) > 1 for start in range(0, items, 3))
    prefix_nodes = _exclusive_prefix_pbs_with_radix(groups, 5)
    digit_nodes = 2 * _reduction_pbs_with_radix(groups, 5)
    return 2 * group_nodes + prefix_nodes + groups + digit_nodes


def _a38_aligned_pbs(items: int, legacy_output_pbs: int) -> int:
    a34_top = (
        27 * items
        + 8 * _or_reduction_pbs(items)
        + _first_one_scan_pbs(items)
        + legacy_output_pbs
        - 1
    )
    old_low = 12 * items + 8 * _or_reduction_pbs(items)
    old_scan_output = _first_one_scan_pbs(items) + legacy_output_pbs
    new_low = 10 * items + 8 * _reduction_pbs_with_radix(items, 5)
    return a34_top - old_low - old_scan_output + new_low + _a38_scan_output_pbs(items)


def normalized_score_domain(
    domain: Mapping[str, int], context: str = "score domain"
) -> Dict[str, int]:
    """Validate either the Rust short keys or the report long keys."""

    if not isinstance(domain, Mapping):
        raise ValidationError("{} is not an object".format(context))
    try:
        lower = int(domain["lower"] if "lower" in domain else domain["l"])
        upper = int(domain["upper"] if "upper" in domain else domain["u"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValidationError("{} lacks integer bounds".format(context)) from error
    if not I64_MIN <= lower <= I64_MAX or not I64_MIN <= upper <= I64_MAX:
        raise ValidationError("{} is outside the signed 64-bit range".format(context))
    width = upper - lower + 1
    if lower > upper or not 1 <= width <= SCORE_DOMAIN_WIDTH_MAX:
        raise ValidationError("{} is invalid for the exact core".format(context))
    reported_width = domain.get("width", domain.get("larghezza"))
    if reported_width is not None and int(reported_width) != width:
        raise ValidationError("{} reports an inconsistent width".format(context))
    return {"l": lower, "u": upper, "larghezza": width}


def expected_execution_plan(
    thresholds: Sequence[int], cauchy_domain: Mapping[str, int]
) -> Dict[str, Any]:
    """Mirror the fail-closed public-domain planner used by ``varco_demo``."""

    tight = normalized_score_domain(cauchy_domain, "tight Cauchy score domain")
    execution = dict(tight)
    path = A29_GENERAL_PATH
    normalized_thresholds = [int(threshold) for threshold in thresholds]
    if normalized_thresholds and len(set(normalized_thresholds)) == 1:
        threshold = normalized_thresholds[0]
        candidate_lower = threshold - ALIGNED_UNIFORM_THRESHOLD
        if I64_MIN <= candidate_lower <= I64_MAX and candidate_lower <= tight["l"]:
            candidate_width = tight["u"] - candidate_lower + 1
            if 1 <= candidate_width <= SCORE_DOMAIN_WIDTH_MAX:
                execution = {
                    "l": candidate_lower,
                    "u": tight["u"],
                    "larghezza": candidate_width,
                }
                path = A38_ALIGNED_PATH
    return {
        "dominio": tight,
        "dominio_esecuzione": execution,
        "percorso_argmin": path,
    }


def expected_pbs_count(
    gallery_size: int,
    thresholds: Optional[Sequence[int]] = None,
    domain: Optional[Mapping[str, int]] = None,
) -> int:
    """Mirror A38 dispatch and the A29 public-threshold mask sparsity."""

    if not 1 <= gallery_size <= 128:
        raise ValidationError("gallery size outside the exact core capacity")
    output_bit_count = gallery_size.bit_length()
    output = (
        sum(
            max(
                1,
                _or_reduction_pbs(
                    sum(1 for code in range(1, gallery_size + 1) if code & (1 << bit))
                ),
            )
            for bit in range(output_bit_count)
        )
        + (output_bit_count + 2) // 3
    )
    maximum = (
        32 * gallery_size
        + 25 * _or_reduction_pbs(gallery_size)
        + _first_one_scan_pbs(gallery_size)
        + output
        + 13
    )
    if thresholds is None and domain is None:
        count = maximum
    else:
        if thresholds is None or domain is None or len(thresholds) != gallery_size:
            raise ValidationError("threshold metadata does not match the gallery")
        normalized = normalized_score_domain(domain)
        lower = normalized["l"]
        upper = normalized["u"]
        normalized_thresholds = [int(threshold) for threshold in thresholds]
        aligned = (
            len(set(normalized_thresholds)) == 1
            and normalized_thresholds[0] - lower == ALIGNED_UNIFORM_THRESHOLD
        )
        if aligned:
            count = _a38_aligned_pbs(gallery_size, output)
        else:
            metadata = [
                (
                    min(max(threshold, lower), upper) - lower,
                    threshold < lower,
                )
                for threshold in normalized_thresholds
            ]
            masks = [
                [bool((threshold >> bit) & 1) for threshold, _ in metadata]
                for bit in reversed(range(12))
            ]
            masks.append([below for _, below in metadata])

            def mask_pbs(mask: Sequence[bool]) -> int:
                enabled = sum(mask)
                if enabled in (0, gallery_size):
                    return 0
                return _or_reduction_pbs(enabled)

            count = (
                maximum
                - 13 * _or_reduction_pbs(gallery_size)
                + sum(mask_pbs(mask) for mask in masks)
            )
    if gallery_size == EXPECTED_GALLERY_SIZE and thresholds is None and count != 5524:
        raise ValidationError(
            "the exact-core PBS formula no longer gives 5524 at N=127"
        )
    if (
        gallery_size == EXPECTED_GALLERY_SIZE
        and thresholds is not None
        and len(set(int(threshold) for threshold in thresholds)) == 1
    ):
        threshold = int(thresholds[0])
        lower = normalized_score_domain(domain)["l"]
        expected_uniform = (
            3655 if threshold - lower == ALIGNED_UNIFORM_THRESHOLD else 4965
        )
        if count != expected_uniform:
            raise ValidationError(
                "the exact-core PBS formula no longer gives {} for this uniform-threshold N=127 gallery".format(
                    expected_uniform
                )
            )
    return count


def validate_execution_metadata(
    payload: Mapping[str, Any],
    *,
    thresholds: Sequence[int],
    cauchy_domain: Optional[Mapping[str, int]],
    context: str,
    required: bool,
) -> None:
    """Validate A38/A29 path metadata without breaking frozen legacy binaries."""

    fields_present = "dominio_esecuzione" in payload or "percorso_argmin" in payload
    if not required and not fields_present:
        return
    if "dominio_esecuzione" not in payload or "percorso_argmin" not in payload:
        raise ValidationError("{} lacks complete execution metadata".format(context))
    execution_domain = payload.get("dominio_esecuzione")
    path = payload.get("percorso_argmin")
    if not thresholds:
        if (
            cauchy_domain is not None
            or execution_domain is not None
            or path is not None
        ):
            raise ValidationError(
                "{} reports an execution plan for an empty gallery".format(context)
            )
        return
    if cauchy_domain is None:
        raise ValidationError("{} lacks its tight Cauchy domain".format(context))
    if not isinstance(execution_domain, Mapping):
        raise ValidationError("{} lacks its execution domain".format(context))
    expected = expected_execution_plan(thresholds, cauchy_domain)
    actual_execution = normalized_score_domain(
        execution_domain, "{} execution domain".format(context)
    )
    if actual_execution != expected["dominio_esecuzione"]:
        raise ValidationError(
            "{} execution domain does not match the fail-closed planner".format(context)
        )
    if path != expected["percorso_argmin"]:
        raise ValidationError(
            "{} argmin path does not match its public metadata".format(context)
        )


def split_ciphertext(payload: bytes, context: str) -> Tuple[List[int], int]:
    if len(payload) < 8 or len(payload) % 8:
        raise ValidationError("{} is not an aligned ciphertext".format(context))
    words = struct.unpack("<{}Q".format(len(payload) // 8), payload)
    header_words = int(words[0])
    if header_words > len(words) - 1:
        raise ValidationError("{} has a truncated header".format(context))
    return list(words[1 : 1 + header_words]), len(words) - 1 - header_words


def validate_probe_ciphertext(payload: bytes) -> Dict[str, int]:
    header, body_words = split_ciphertext(payload, "encrypted probe")
    if len(header) != 8:
        raise ValidationError("probe header is not the current eight-word format")
    expected = (
        EXPECTED_CONTRACT["probe_magic"],
        EXPECTED_CONTRACT["wire_version"],
        EXPECTED_CONTRACT["probe_layout"],
    )
    if tuple(header[:3]) != expected:
        raise ValidationError("probe header is not the exact-ID v2 dual layout")
    if header[5] != EXPECTED_DIMENSION:
        raise ValidationError("probe header has the wrong embedding dimension")
    if header[6] != EXPECTED_CONTRACT["score_delta_log"]:
        raise ValidationError("probe header has the wrong full-score scale")
    if header[7] != EXPECTED_CONTRACT["low_mod16_delta_log"]:
        raise ValidationError("probe header has the wrong modulo-16 scale")
    expected_body_words = (header[4] + 1) * header[3]
    if body_words != expected_body_words:
        raise ValidationError("probe body does not match its GLWE geometry")
    return {
        "polynomial_size": int(header[3]),
        "glwe_dimension": int(header[4]),
        "body_words": body_words,
    }


def validate_output_ciphertext(
    payload: bytes, server_state: Mapping[str, Any]
) -> Dict[str, int]:
    header, body_words = split_ciphertext(payload, "encrypted result")
    if len(header) != 8:
        raise ValidationError("result header is not the current eight-word format")
    if tuple(header[:3]) != (
        EXPECTED_CONTRACT["output_magic"],
        EXPECTED_CONTRACT["wire_version"],
        EXPECTED_CONTRACT["output_mode"],
    ):
        raise ValidationError("result header is not exact open-set ID v2")
    if header[7] != EXPECTED_CONTRACT["code_delta_log"]:
        raise ValidationError("result header has the wrong code scale")
    expected_metadata = (
        int(server_state["epoch"]),
        int(server_state["revision"]),
        int(server_state["iscritti"]),
    )
    if tuple(header[3:6]) != expected_metadata:
        raise ValidationError(
            "result header does not bind the queried gallery snapshot"
        )
    if header[6] == 0 or body_words != header[6]:
        raise ValidationError("result is not exactly one complete LWE")
    return {
        "epoch": int(header[3]),
        "revision": int(header[4]),
        "gallery_size": int(header[5]),
        "lwe_size": int(header[6]),
        "body_words": body_words,
    }


def validate_server_state(
    state: Mapping[str, Any],
    *,
    gallery_size: int,
    key_present: bool,
    expected_key_sha256: Optional[str] = None,
    require_execution_metadata: bool = False,
) -> None:
    if state.get("iscritti") != gallery_size:
        raise ValidationError("/stato reports the wrong gallery size")
    if state.get("chiave") is not key_present:
        raise ValidationError("/stato reports the wrong evaluation-key state")
    key_sha256 = state.get("chiave_sha256")
    if key_present:
        if (
            not isinstance(key_sha256, str)
            or len(key_sha256) != 64
            or any(character not in "0123456789abcdef" for character in key_sha256)
        ):
            raise ValidationError("/stato lacks a valid evaluation-key SHA-256")
        if expected_key_sha256 is not None and key_sha256 != expected_key_sha256:
            raise ValidationError(
                "/stato evaluation-key SHA-256 does not match the run key"
            )
    elif key_sha256 is not None:
        raise ValidationError(
            "/stato fingerprints an evaluation key that is not installed"
        )
    if state.get("dim") != EXPECTED_DIMENSION:
        raise ValidationError("/stato reports the wrong embedding dimension")
    if state.get("soglia_default") != EXPECTED_THRESHOLD:
        raise ValidationError("/stato reports the wrong default threshold")
    if not isinstance(state.get("epoch"), int) or not isinstance(
        state.get("revision"), int
    ):
        raise ValidationError("/stato lacks integer gallery version metadata")
    names = state.get("nomi")
    thresholds = state.get("soglie")
    if not isinstance(names, list) or len(names) != gallery_size:
        raise ValidationError("/stato reports an invalid gallery-name vector")
    if thresholds != [EXPECTED_THRESHOLD] * gallery_size:
        raise ValidationError("/stato reports unexpected per-identity thresholds")
    domain = state.get("dominio")
    if gallery_size == 0 and domain is not None:
        raise ValidationError("/stato reports a score domain for an empty gallery")
    if gallery_size and not isinstance(domain, dict):
        raise ValidationError("/stato lacks the enrolled Cauchy score domain")
    validate_execution_metadata(
        state,
        thresholds=thresholds,
        cauchy_domain=domain,
        context="/stato",
        required=require_execution_metadata,
    )
    contract = state.get("contratto_esatto")
    if not isinstance(contract, dict):
        raise ValidationError("/stato lacks contratto_esatto")
    require_exact_subset(contract, EXPECTED_CONTRACT, "/stato contratto_esatto")


def clear_case(
    suite: str,
    sequence: int,
    probe_index: int,
    repetition: int,
    names: Any,
    scores: Any,
) -> Dict[str, Any]:
    import numpy as np

    probe_scores = scores[probe_index]
    argmin = int(np.argmin(probe_scores))
    minimum = int(probe_scores[argmin])
    match_count = int(np.count_nonzero(probe_scores <= EXPECTED_THRESHOLD))
    authorized = minimum <= EXPECTED_THRESHOLD
    return {
        "sequence": sequence,
        "suite": suite,
        "probe_index": probe_index,
        "probe_name": str(names[probe_index]),
        "cohort": cohort_for_index(probe_index),
        "repetition": repetition,
        "clear_min_score": minimum,
        "clear_argmin_index": argmin,
        "clear_argmin_name": str(names[argmin]),
        "clear_match_count": match_count,
        "expected_authorized": authorized,
        "expected_index": argmin if authorized else None,
        "expected_code": argmin + 1 if authorized else 0,
    }


def measure_query(
    *,
    binary: pathlib.Path,
    keys: pathlib.Path,
    work: pathlib.Path,
    port: int,
    probe: Any,
    row: Dict[str, Any],
    server_state: Mapping[str, Any],
    timeout: int,
) -> Dict[str, Any]:
    sequence = int(row["sequence"])
    probe_path = work / "probe-{:04d}.txt".format(sequence)
    probe_ciphertext_path = work / "probe-{:04d}.ct".format(sequence)
    result_ciphertext_path = work / "result-{:04d}.ct".format(sequence)
    probe_path.write_text(" ".join(str(int(value)) for value in probe) + "\n")

    encrypted, encrypt_wall_s = run_command(
        [
            str(binary),
            "encrypt",
            str(keys),
            str(probe_path),
            str(probe_ciphertext_path),
        ],
        timeout=timeout,
    )
    encrypt_report = last_json_line(encrypted.stdout, "varco_demo encrypt")
    probe_ciphertext = probe_ciphertext_path.read_bytes()
    validate_probe_ciphertext(probe_ciphertext)

    http_started = time.perf_counter()
    status, encrypted_result, headers = http_request(
        port,
        "POST",
        "/varco",
        probe_ciphertext,
        timeout=timeout,
    )
    http_wall_ms = (time.perf_counter() - http_started) * 1000.0
    if status != 200:
        raise ValidationError(
            "/varco failed with HTTP {}: {}".format(
                status, encrypted_result.decode(errors="replace")
            )
        )
    if headers.get("content-type") != "application/octet-stream":
        raise ValidationError("/varco did not return an encrypted binary result")
    if headers.get("x-varco-contract") != EXPECTED_VARCO_HEADER:
        raise ValidationError("/varco did not advertise exact-open-set-id-v2")
    if parse_int(headers, "content-length") != len(encrypted_result):
        raise ValidationError("/varco Content-Length does not match the result")
    reported_pbs = parse_int(headers, "x-pbs")
    expected_pbs = expected_pbs_count(
        int(server_state["iscritti"]),
        server_state["soglie"],
        server_state.get("dominio_esecuzione", server_state["dominio"]),
    )
    if reported_pbs != expected_pbs:
        raise ValidationError(
            "/varco reports {} PBS, expected {} for N={}".format(
                reported_pbs, expected_pbs, server_state["iscritti"]
            )
        )
    server_ms = parse_float(headers, "x-tempo-ms")
    if server_ms is None or not math.isfinite(server_ms) or server_ms < 0:
        raise ValidationError("/varco lacks a valid X-Tempo-Ms measurement")
    output_header = validate_output_ciphertext(encrypted_result, server_state)
    result_ciphertext_path.write_bytes(encrypted_result)

    decrypted, decrypt_wall_s = run_command(
        [str(binary), "decrypt", str(keys), str(result_ciphertext_path)],
        timeout=timeout,
    )
    decrypt_report = last_json_line(decrypted.stdout, "varco_demo decrypt")
    required_decrypt_fields = {
        "autorizzato",
        "indice",
        "codice",
        "iscritti",
        "galleria_epoch",
        "galleria_revision",
    }
    missing_decrypt_fields = sorted(required_decrypt_fields.difference(decrypt_report))
    if missing_decrypt_fields:
        raise ValidationError(
            "decrypt output lacks fields: {}".format(missing_decrypt_fields)
        )
    if not isinstance(decrypt_report["autorizzato"], bool):
        raise ValidationError("decrypt output 'autorizzato' is not a JSON boolean")
    actual_authorized = decrypt_report["autorizzato"]
    actual_index = decrypt_report.get("indice")
    actual_code = decrypt_report.get("codice")
    if not isinstance(actual_code, int) or isinstance(actual_code, bool):
        raise ValidationError("decrypt output 'codice' is not an integer")
    if actual_authorized:
        if not isinstance(actual_index, int) or isinstance(actual_index, bool):
            raise ValidationError("accepted exact-ID output lacks an integer index")
        if not 0 <= actual_index < int(server_state["iscritti"]):
            raise ValidationError("accepted exact-ID index is outside the gallery")
        if actual_code != actual_index + 1:
            raise ValidationError("accepted output does not encode index + 1")
    elif actual_index is not None or actual_code != 0:
        raise ValidationError("rejected output must be code 0 with a null index")
    for field in ("score", "distanza", "conteggio"):
        if field in decrypt_report:
            raise ValidationError(
                "decrypt output leaks forbidden field {!r}".format(field)
            )
    for field, expected in (
        ("iscritti", server_state["iscritti"]),
        ("galleria_epoch", server_state["epoch"]),
        ("galleria_revision", server_state["revision"]),
    ):
        if decrypt_report.get(field) != expected:
            raise ValidationError(
                "decrypt output has stale {!r} metadata".format(field)
            )

    expected_authorized = bool(row["expected_authorized"])
    expected_index = row["expected_index"]
    expected_code = int(row["expected_code"])
    discrepancy = (
        actual_authorized != expected_authorized
        or actual_index != expected_index
        or actual_code != expected_code
    )
    actual_name = (
        str(server_state["nomi"][actual_index]) if actual_index is not None else None
    )

    row.update(
        {
            "actual_authorized": actual_authorized,
            "actual_index": actual_index,
            "actual_code": actual_code,
            "actual_name": actual_name,
            "discrepancy": discrepancy,
            "error": "",
            "encrypt_wall_ms": round(encrypt_wall_s * 1000.0, 3),
            "encrypt_reported_ms": encrypt_report.get("encrypt_ms"),
            "probe_ciphertext_bytes": len(probe_ciphertext),
            "probe_ciphertext_sha256": hashlib.sha256(probe_ciphertext).hexdigest(),
            "http_wall_ms": round(http_wall_ms, 3),
            "server_reported_ms": server_ms,
            "pbs": reported_pbs,
            "varco_contract": headers["x-varco-contract"],
            "output_epoch": output_header["epoch"],
            "output_revision": output_header["revision"],
            "output_gallery_size": output_header["gallery_size"],
            "output_lwe_size": output_header["lwe_size"],
            "result_ciphertext_bytes": len(encrypted_result),
            "result_ciphertext_sha256": hashlib.sha256(encrypted_result).hexdigest(),
            "decrypt_wall_ms": round(decrypt_wall_s * 1000.0, 3),
            "decrypt_reported_ms": decrypt_report.get("decrypt_ms"),
        }
    )
    return row


def stop_server(server: subprocess.Popen) -> None:
    if server.poll() is None:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)


def write_results(
    rows: List[Dict[str, Any]],
    summary: Dict[str, Any],
    output_dir: pathlib.Path,
    output_stem: Optional[str],
) -> Tuple[pathlib.Path, pathlib.Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    if output_stem is None:
        timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H%M%S.%fZ")
        output_stem = "fhe_digiface_validation_{}".format(timestamp)
    if pathlib.Path(output_stem).name != output_stem:
        raise ValidationError("--output-stem must be a filename stem, not a path")
    csv_path = output_dir / "{}.csv".format(output_stem)
    json_path = output_dir / "{}.json".format(output_stem)
    if csv_path.exists() or json_path.exists():
        raise FileExistsError(
            "refusing to overwrite {} or {}".format(csv_path, json_path)
        )

    with csv_path.open("x", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows({key: row.get(key, "") for key in CSV_FIELDS} for row in rows)

    summary["artifacts"] = {
        "csv": str(csv_path.resolve()),
        "csv_sha256": sha256_file(csv_path),
        "json": str(json_path.resolve()),
    }
    with json_path.open("x") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return csv_path, json_path


def summarize_rows(rows: List[Dict[str, Any]], planned: int) -> Dict[str, Any]:
    measured = [row for row in rows if not row.get("error")]
    discrepancies = [row for row in measured if row.get("discrepancy")]
    errors = [row for row in rows if row.get("error")]
    hashes = [str(row["probe_ciphertext_sha256"]) for row in measured]
    suites: Dict[str, Dict[str, int]] = {}
    for row in rows:
        suite = str(row["suite"])
        counts = suites.setdefault(
            suite,
            {
                "rows": 0,
                "measured": 0,
                "errors": 0,
                "expected_authorized": 0,
                "actual_authorized": 0,
                "discrepancies": 0,
            },
        )
        counts["rows"] += 1
        counts["expected_authorized"] += int(bool(row["expected_authorized"]))
        if row.get("error"):
            counts["errors"] += 1
        else:
            counts["measured"] += 1
            counts["actual_authorized"] += int(bool(row["actual_authorized"]))
            counts["discrepancies"] += int(bool(row["discrepancy"]))

    return {
        "planned_queries": planned,
        "rows_recorded": len(rows),
        "measured_queries": len(measured),
        "operational_errors": len(errors),
        "clear_vs_fhe_exact_result_discrepancies": len(discrepancies),
        "expected_authorized": sum(bool(row["expected_authorized"]) for row in rows),
        "actual_authorized": sum(bool(row["actual_authorized"]) for row in measured),
        "probe_ciphertexts_unique": len(set(hashes)),
        "probe_ciphertexts_measured": len(hashes),
        "all_probe_ciphertexts_unique": len(set(hashes)) == len(hashes),
        "pbs_values": sorted(
            {int(row["pbs"]) for row in measured if row.get("pbs") is not None}
        ),
        "varco_contract_values": sorted(
            {
                str(row["varco_contract"])
                for row in measured
                if row.get("varco_contract")
            }
        ),
        "probe_ciphertext_byte_sizes": sorted(
            {int(row["probe_ciphertext_bytes"]) for row in measured}
        ),
        "result_ciphertext_byte_sizes": sorted(
            {int(row["result_ciphertext_bytes"]) for row in measured}
        ),
        "timings_ms": {
            "encrypt_wall": distribution(
                row.get("encrypt_wall_ms") for row in measured
            ),
            "encrypt_reported": distribution(
                row.get("encrypt_reported_ms") for row in measured
            ),
            "http_wall": distribution(row.get("http_wall_ms") for row in measured),
            "server_reported": distribution(
                row.get("server_reported_ms") for row in measured
            ),
            "decrypt_wall": distribution(
                row.get("decrypt_wall_ms") for row in measured
            ),
            "decrypt_reported": distribution(
                row.get("decrypt_reported_ms") for row in measured
            ),
        },
        "per_suite": suites,
        "discrepancy_rows": [int(row["sequence"]) for row in discrepancies],
        "error_rows": [
            {"sequence": int(row["sequence"]), "error": str(row["error"])}
            for row in errors
        ],
    }


def git_provenance() -> Dict[str, Any]:
    return {
        "head": command_text(["git", "rev-parse", "HEAD"], cwd=ROOT),
        "branch": command_text(["git", "branch", "--show-current"], cwd=ROOT),
        "status_short": command_text(
            ["git", "status", "--short"], cwd=ROOT
        ).splitlines(),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run",
        action="store_true",
        help="perform key generation and real FHE queries; without this flag only clear checks run",
    )
    parser.add_argument(
        "--primary-suite",
        action="store_true",
        help="also run all 127 genuine and 500 non-tuning primary-test impostor probes once",
    )
    parser.add_argument(
        "--regression-repetitions",
        type=int,
        default=16,
        help="fresh encryptions per historical probe (default: 16)",
    )
    parser.add_argument(
        "--only-probe",
        type=int,
        action="append",
        default=[],
        help=(
            "run only this cached probe index, repeatable; each index uses "
            "--regression-repetitions fresh ciphertexts"
        ),
    )
    parser.add_argument(
        "--binary",
        type=pathlib.Path,
        default=DEFAULT_BINARY,
        help="varco_demo binary path; the default is rebuilt from the current Rust source",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="use the declared binary as-is; its path and hash are still bound to the server PID",
    )
    parser.add_argument(
        "--timeout", type=int, default=900, help="per-command/HTTP timeout seconds"
    )
    parser.add_argument("--output-dir", type=pathlib.Path, default=RESULTS_DIR)
    parser.add_argument(
        "--output-stem",
        help="optional artifact stem; fails if either corresponding CSV/JSON already exists",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    gallery, probes, names, config, scene = load_scene()
    invalid_only_probes = [
        index for index in args.only_probe if not 0 <= index < len(probes)
    ]
    if invalid_only_probes:
        raise ValidationError(
            "--only-probe indices outside the cached probe range: {}".format(
                invalid_only_probes
            )
        )
    cases = build_cases(
        args.primary_suite, args.regression_repetitions, args.only_probe
    )
    dry_plan = {
        "mode": "run" if args.run else "clear_validation_only",
        "protocol": EXPECTED_VARCO_HEADER,
        "output": "one encrypted scalar: 0=reject, i+1=accepted nearest identity",
        "expected_pbs_n127_a29_upper_bound": expected_pbs_count(EXPECTED_GALLERY_SIZE),
        "expected_pbs_n127_a29_uniform_non_aligned": expected_pbs_count(
            EXPECTED_GALLERY_SIZE,
            [EXPECTED_THRESHOLD] * EXPECTED_GALLERY_SIZE,
            {"lower": 0, "upper": EXPECTED_THRESHOLD + 1},
        ),
        "expected_pbs_n127_a38_aligned_uniform": expected_pbs_count(
            EXPECTED_GALLERY_SIZE,
            [EXPECTED_THRESHOLD] * EXPECTED_GALLERY_SIZE,
            {"lower": -1019, "upper": 2329},
        ),
        "historical_probe_indices": [index for index, _ in HISTORICAL_FRONTIER],
        "regression_repetitions": args.regression_repetitions,
        "primary_suite": args.primary_suite,
        "only_probes": args.only_probe,
        "planned_queries": len(cases),
        "clear_scene": scene["clear_summary"],
    }
    if not args.run:
        print(json.dumps(dry_plan, indent=2, sort_keys=True))
        print(
            "No key generation or FHE query was run; pass --run to execute the validation."
        )
        return 0

    if args.timeout < 1:
        raise ValidationError("--timeout must be positive")
    binary = args.binary.resolve()
    if not args.skip_build and binary != DEFAULT_BINARY.resolve():
        raise ValidationError("a custom --binary requires --skip-build")
    build_record: Dict[str, Any]
    if args.skip_build:
        build_record = {"performed": False, "reason": "--skip-build"}
    else:
        build_result, build_s = run_command(
            ["cargo", "build", "--release", "--bin", "varco_demo"],
            cwd=CRATE,
            timeout=args.timeout,
        )
        build_record = {
            "performed": True,
            "command": ["cargo", "build", "--release", "--bin", "varco_demo"],
            "wall_s": round(build_s, 3),
            "stdout_tail": build_result.stdout[-2000:],
            "stderr_tail": build_result.stderr[-2000:],
        }
    if not binary.is_file():
        raise FileNotFoundError(binary)

    inputs_before = source_records(binary)
    rows: List[Dict[str, Any]] = []
    server: Optional[subprocess.Popen] = None
    server_stdout_path: Optional[pathlib.Path] = None
    server_stderr_path: Optional[pathlib.Path] = None
    server_stdout_handle = None
    server_stderr_handle = None
    process_record: Optional[Dict[str, Any]] = None
    initial_state: Optional[Dict[str, Any]] = None
    enrolled_state: Optional[Dict[str, Any]] = None
    final_state: Optional[Dict[str, Any]] = None
    key_record: Dict[str, Any] = {}
    enrollment_record: Dict[str, Any] = {}
    host_runtime_before = host_runtime_snapshot()
    run_started_utc = dt.datetime.now(dt.timezone.utc).isoformat()
    run_started = time.perf_counter()

    with tempfile.TemporaryDirectory(prefix="fhe-digiface-validation-") as temporary:
        work = pathlib.Path(temporary)
        keys = work / "keys"
        keygen, keygen_s = run_command(
            [str(binary), "keygen", str(keys)],
            timeout=args.timeout,
        )
        keygen_report = last_json_line(keygen.stdout, "varco_demo keygen")
        key_record = {
            "fresh_temporary_keys": True,
            "temporary_directory_removed_after_run": True,
            "keygen_wall_s": round(keygen_s, 3),
            "keygen_report": keygen_report,
            "client_key_bytes": (keys / "client.key").stat().st_size,
            "server_key_bytes": (keys / "server.key").stat().st_size,
            "server_key_sha256": sha256_file(keys / "server.key"),
        }

        port = free_port()
        server_stdout_path = work / "server.stdout.log"
        server_stderr_path = work / "server.stderr.log"
        server_stdout_handle = server_stdout_path.open("w")
        server_stderr_handle = server_stderr_path.open("w")
        server = subprocess.Popen(
            [
                str(binary),
                "serve",
                str(port),
                str(EXPECTED_DIMENSION),
                str(EXPECTED_THRESHOLD),
            ],
            stdout=server_stdout_handle,
            stderr=server_stderr_handle,
            text=True,
        )

        try:
            initial_state = wait_for_server(server, port)
            validate_server_state(
                initial_state,
                gallery_size=0,
                key_present=False,
                require_execution_metadata=True,
            )
            process_record = process_binding(server, binary)
            process_record["bind_address"] = "127.0.0.1:{}".format(port)
            process_record["argv"] = [
                str(binary),
                "serve",
                str(port),
                str(EXPECTED_DIMENSION),
                str(EXPECTED_THRESHOLD),
            ]
            process_record["binary_sha256_at_launch"] = inputs_before["rust_binary"][
                "sha256"
            ]

            status, body, _ = http_upload_file(
                port, "/chiave", keys / "server.key", timeout=args.timeout
            )
            upload_response = require_http_ok(status, body, "evaluation-key upload")
            if upload_response.get("chiave_sha256") != key_record["server_key_sha256"]:
                raise ValidationError(
                    "evaluation-key upload returned the wrong SHA-256"
                )

            enrollment_started = time.perf_counter()
            for index, template in enumerate(gallery):
                name = "digiface-{}-{}".format(index, names[index])
                enrollment_body = (
                    "{}\t{}\n{}\n".format(
                        name,
                        EXPECTED_THRESHOLD,
                        " ".join(str(int(value)) for value in template),
                    )
                ).encode()
                status, body, _ = http_request(
                    port,
                    "POST",
                    "/iscrivi",
                    enrollment_body,
                    "text/plain",
                    timeout=args.timeout,
                )
                response = require_http_ok(status, body, "enrollment {}".format(index))
                if int(response.get("indice", -1)) != index:
                    raise ValidationError(
                        "enrollment index mismatch at {}".format(index)
                    )
                if response.get("iscritti") != index + 1:
                    raise ValidationError(
                        "enrollment gallery-size mismatch at {}".format(index)
                    )
                if response.get("galleria_epoch") != initial_state["epoch"]:
                    raise ValidationError("enrollment changed the process epoch")
                if (
                    response.get("galleria_revision")
                    != initial_state["revision"] + index + 1
                ):
                    raise ValidationError(
                        "enrollment revision mismatch at {}".format(index)
                    )
                if not isinstance(response.get("dominio"), dict):
                    raise ValidationError(
                        "enrollment lacks its validated Cauchy domain at {}".format(
                            index
                        )
                    )
                validate_execution_metadata(
                    response,
                    thresholds=[EXPECTED_THRESHOLD] * (index + 1),
                    cauchy_domain=response["dominio"],
                    context="enrollment {}".format(index),
                    required=True,
                )
            enrollment_record = {
                "templates": len(gallery),
                "threshold": EXPECTED_THRESHOLD,
                "wall_ms": round(
                    (time.perf_counter() - enrollment_started) * 1000.0, 3
                ),
            }

            status, body, _ = http_request(port, "GET", "/stato", timeout=args.timeout)
            enrolled_state = require_http_ok(status, body, "enrolled /stato")
            validate_server_state(
                enrolled_state,
                gallery_size=EXPECTED_GALLERY_SIZE,
                key_present=True,
                expected_key_sha256=str(key_record["server_key_sha256"]),
                require_execution_metadata=True,
            )
            expected_names = [
                "digiface-{}-{}".format(index, names[index])
                for index in range(EXPECTED_GALLERY_SIZE)
            ]
            if enrolled_state["nomi"] != expected_names:
                raise ValidationError(
                    "/stato does not preserve enrollment order and names"
                )
            if enrolled_state["epoch"] != initial_state["epoch"]:
                raise ValidationError("gallery epoch changed during enrollment")
            if enrolled_state["revision"] != initial_state["revision"] + len(gallery):
                raise ValidationError(
                    "gallery revision does not cover every enrollment"
                )
            expected_domain = config.get("dominio_score_cauchy", {}).get(
                "galleria_sintetica_base"
            )
            if enrolled_state["dominio"] != {
                "l": expected_domain.get("lower")
                if isinstance(expected_domain, dict)
                else None,
                "u": expected_domain.get("upper")
                if isinstance(expected_domain, dict)
                else None,
                "larghezza": expected_domain.get("width")
                if isinstance(expected_domain, dict)
                else None,
            }:
                raise ValidationError(
                    "/stato Cauchy domain does not match the calibrated DigiFace gallery"
                )
            scene_execution_plan = expected_execution_plan(
                enrolled_state["soglie"], enrolled_state["dominio"]
            )
            if scene_execution_plan["percorso_argmin"] != A38_ALIGNED_PATH:
                raise ValidationError(
                    "the calibrated uniform-threshold DigiFace scene does not activate A38"
                )
            if (
                normalized_score_domain(enrolled_state["dominio_esecuzione"])
                != scene_execution_plan["dominio_esecuzione"]
            ):
                raise ValidationError(
                    "/stato does not expose the expected A38 execution domain"
                )

            for sequence, (suite, probe_index, repetition) in enumerate(cases):
                row = clear_case(
                    suite,
                    sequence,
                    probe_index,
                    repetition,
                    names,
                    scene["all_scores"],
                )
                try:
                    measure_query(
                        binary=binary,
                        keys=keys,
                        work=work,
                        port=port,
                        probe=probes[probe_index],
                        row=row,
                        server_state=enrolled_state,
                        timeout=args.timeout,
                    )
                except (
                    OSError,
                    subprocess.SubprocessError,
                    http.client.HTTPException,
                    ValidationError,
                    ValueError,
                ) as exc:
                    row.update(
                        {
                            "actual_authorized": "",
                            "actual_index": "",
                            "actual_code": "",
                            "actual_name": "",
                            "discrepancy": "",
                            "error": "{}: {}".format(type(exc).__name__, exc),
                        }
                    )
                    rows.append(row)
                    if server.poll() is not None:
                        break
                else:
                    rows.append(row)
                completed = sequence + 1
                if completed == 1 or completed % 10 == 0 or completed == len(cases):
                    discrepancies = sum(
                        bool(measured.get("discrepancy"))
                        for measured in rows
                        if not measured.get("error")
                    )
                    errors = sum(bool(measured.get("error")) for measured in rows)
                    print(
                        "progress {}/{} queries, discrepancies={}, errors={}".format(
                            completed, len(cases), discrepancies, errors
                        ),
                        file=sys.stderr,
                        flush=True,
                    )

            status, body, _ = http_request(port, "GET", "/stato", timeout=args.timeout)
            final_state = require_http_ok(status, body, "final /stato")
            validate_server_state(
                final_state,
                gallery_size=EXPECTED_GALLERY_SIZE,
                key_present=True,
                expected_key_sha256=str(key_record["server_key_sha256"]),
                require_execution_metadata=True,
            )
            if final_state != enrolled_state:
                raise ValidationError(
                    "gallery state changed while queries were evaluated"
                )
        finally:
            stop_server(server)
            server_stdout_handle.close()
            server_stderr_handle.close()

        server_stdout = server_stdout_path.read_text(errors="replace")
        server_stderr = server_stderr_path.read_text(errors="replace")

    inputs_after = source_records(binary)
    host_runtime_after = host_runtime_snapshot()
    unchanged = {
        key: inputs_before[key]["sha256"] == inputs_after[key]["sha256"]
        for key in inputs_before
    }
    row_summary = summarize_rows(rows, len(cases))
    query_contract_verified = (
        enrolled_state is not None
        and enrolled_state.get("percorso_argmin") == A38_ALIGNED_PATH
        and row_summary["varco_contract_values"] == [EXPECTED_VARCO_HEADER]
        and row_summary["pbs_values"]
        == [
            expected_pbs_count(
                int(enrolled_state["iscritti"]),
                enrolled_state["soglie"],
                enrolled_state["dominio_esecuzione"],
            )
        ]
    )
    success = bool(
        len(rows) == len(cases)
        and row_summary["operational_errors"] == 0
        and row_summary["clear_vs_fhe_exact_result_discrepancies"] == 0
        and row_summary["all_probe_ciphertexts_unique"]
        and query_contract_verified
        and all(unchanged.values())
    )

    summary = {
        "schema_version": 2,
        "run_started_utc": run_started_utc,
        "run_finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "run_wall_s": round(time.perf_counter() - run_started, 3),
        "argv": sys.argv,
        "success": success,
        "warning": (
            "Functional empirical validation only: this does not derive a composed p-fail "
            "bound for the exact TFHE argmin pipeline."
        ),
        "plan": dry_plan,
        "scene": {
            "config_snapshot": config,
            "cache_metadata": scene["cache_metadata"],
            "clear_summary": scene["clear_summary"],
        },
        "provenance": {
            "inputs_before": inputs_before,
            "inputs_after": inputs_after,
            "inputs_unchanged_during_run": unchanged,
            "git": git_provenance(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "numpy": __import__("numpy").__version__,
            "rustc": command_text(["rustc", "--version", "--verbose"]),
            "cargo": command_text(["cargo", "--version"]),
            "build": build_record,
            "server_process": process_record,
            "host_runtime_before": host_runtime_before,
            "host_runtime_after": host_runtime_after,
        },
        "keys": key_record,
        "enrollment": enrollment_record,
        "server_state": {
            "initial": initial_state,
            "after_enrollment": enrolled_state,
            "final": final_state,
            "exact_contract_and_query_headers_verified": query_contract_verified,
            "stdout_sha256": hashlib.sha256(server_stdout.encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(server_stderr.encode()).hexdigest(),
            "stdout_tail": server_stdout[-2000:],
            "stderr_tail": server_stderr[-4000:],
            "exit_code": server.returncode if server is not None else None,
        },
        "results": row_summary,
    }
    csv_path, json_path = write_results(
        rows, summary, args.output_dir, args.output_stem
    )
    print(
        json.dumps(
            {"success": success, "results": row_summary}, indent=2, sort_keys=True
        )
    )
    print("wrote {}".format(csv_path))
    print("wrote {}".format(json_path))
    return 0 if success else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, ValidationError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        raise SystemExit(2)
