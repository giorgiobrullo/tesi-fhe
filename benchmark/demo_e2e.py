"""Evidence-grade synthetic-query benchmark of the running exact-ID demo.

The measured request is the same /api/verifica request used by the browser. The outer wall clock
includes image loading, ResNet100, fusion, quantization, encryption, client/server HTTP, server
FHE, decryption and serialization. Camera acquisition, browser rendering and setup checks are not
part of the measured interval.

Semantic identification errors are written to CSV and JSON and make the process exit with status
1. Structural evidence failures (wrong protocol, N, PBS count, state, source or container) abort
immediately because the resulting timing would not describe the requested experiment.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import importlib.metadata
import json
import math
import os
import pathlib
import platform
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[1]
RUST_ROOT = ROOT / "experiments" / "14_pipeline_tfhe_rs"
EXACT_SERVER_CONTRACT = "exact-open-set-id-v2"
EXACT_DECISION = "exact_argmin_then_selected_threshold"
EXACT_COMPARATOR = "argmin_esatto_bucket_bits_dual_glwe"
DOCKER_BINARY = "/usr/local/bin/varco_demo"
DOCKER_MANIFEST = "/usr/local/share/tesi-fhe/build-provenance.sha256"
DOCKER_DATASET_ROOT = "/app/datasets/digiface/estratto"
DOCKER_CLIENT_PYTHON = "/usr/local/bin/python"
EXPECTED_CONTAINER_COMMAND = {
    "server": {
        "path": "/bin/sh",
        "args": [
            "-c",
            "exec /usr/local/bin/varco_demo serve $PORTA $DIM $SOGLIA",
        ],
    },
    "client": {
        "path": "/usr/local/bin/uvicorn",
        "args": [
            "demo.client.app:app",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
        ],
    },
}
EXPECTED_CLIENT_ENVIRONMENT = {
    "VARCO_SERVER": "http://server:9000",
    "VARCO_BIN": "/usr/local/bin/varco_demo",
    "VARCO_CHIAVI": "/app/chiavi",
    "PYTHONPATH": "/app",
    "INSIGHTFACE_HOME": "/root/.insightface",
}

EXACT_WIRE_CONTRACT: dict[str, object] = {
    "wire_version": 2,
    "probe_layout": 1,
    "score_delta_log": 52,
    "low_mod16_offset": 1024,
    "low_mod16_delta_log": 60,
    "output_mode": 2,
    "code_delta_log": 56,
    "codice": "0=rifiuto; i+1=identita_accettata",
    "un_solo_lwe": True,
}
EXACT_SERVER_WIRE_CONTRACT: dict[str, object] = {
    **EXACT_WIRE_CONTRACT,
    "probe_magic": 3621547555239973462,
    "output_magic": 3625490425412014678,
}
SCORE_DOMAIN_WIDTH_MAX = 4096
EXACT_CONFIG_CONTRACT: dict[str, object] = {
    **EXACT_WIRE_CONTRACT,
    "score_bits": 12,
    "probe_norm2_max": 1024,
    "score_domain_width_max": SCORE_DOMAIN_WIDTH_MAX,
    "tie_break": "primo_indice_galleria",
    "selezione_soglia": "solo_del_vincitore_argmin",
}
EXPECTED_SYNTHETIC_CAUCHY_DOMAIN = {"l": -987, "u": 2329, "larghezza": 3317}
ALIGNED_UNIFORM_THRESHOLD = 1023
A38_ALIGNED_PATH = "a38_combined"
A29_GENERAL_PATH = "a29_general"
I64_MIN = -(1 << 63)
I64_MAX = (1 << 63) - 1
MODEL_LAYOUT = {
    "mobilefacenet": ("buffalo_s", "w600k_mbf.onnx"),
    "resnet50": ("buffalo_l", "w600k_r50.onnx"),
    "resnet100": ("antelopev2", "glintr100.onnx"),
}
COMMON_BUILD_INPUTS = {
    "Cargo.toml": RUST_ROOT / "Cargo.toml",
    "Cargo.lock": RUST_ROOT / "Cargo.lock",
    "src/bin/varco_demo.rs": RUST_ROOT / "src" / "bin" / "varco_demo.rs",
    "src/lib.rs": RUST_ROOT / "src" / "lib.rs",
    "src/private_argmin.rs": RUST_ROOT / "src" / "private_argmin.rs",
}
SERVICE_BUILD_INPUTS = {
    "server": {
        **COMMON_BUILD_INPUTS,
        "demo/server/Dockerfile": ROOT / "demo" / "server" / "Dockerfile",
    },
    "client": {
        **COMMON_BUILD_INPUTS,
        "demo/client/Dockerfile": ROOT / "demo" / "client" / "Dockerfile",
        "demo/client/app.py": ROOT / "demo" / "client" / "app.py",
        "demo/config.json": ROOT / "demo" / "config.json",
        "experiments/08_cnn/embedding.py": (
            ROOT / "experiments" / "08_cnn" / "embedding.py"
        ),
    },
}
CLIENT_RUNTIME_FILES = {
    "/app/demo/client/app.py": "demo/client/app.py",
    "/app/demo/config.json": "demo/config.json",
    "/app/experiments/08_cnn/embedding.py": "experiments/08_cnn/embedding.py",
}


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def sha256_arrays(*arrays: object) -> str:
    import numpy as np

    digest = hashlib.sha256()
    for array in arrays:
        digest.update(np.ascontiguousarray(array).tobytes())
    return digest.hexdigest()


def _same_value(actual: object, expected: object) -> bool:
    """Do not let bool/int equivalence weaken a serialized protocol assertion."""

    return type(actual) is type(expected) and actual == expected


def _contract_mismatches(
    actual: dict[str, object], expected: dict[str, object]
) -> dict[str, dict[str, object]]:
    return {
        field: {"expected": value, "observed": actual.get(field)}
        for field, value in expected.items()
        if not _same_value(actual.get(field), value)
    }


def normalized_score_domain(
    domain: object,
    context: str,
    *,
    config_keys: bool = False,
) -> dict[str, int]:
    """Validate a complete signed-64-bit score domain without coercing JSON types."""

    if not isinstance(domain, dict):
        raise RuntimeError(f"{context} non e' un oggetto")
    lower_key, upper_key, width_key = (
        ("lower", "upper", "width")
        if config_keys
        else ("l", "u", "larghezza")
    )
    required = (lower_key, upper_key, width_key)
    missing = [field for field in required if field not in domain]
    if missing:
        raise RuntimeError(f"{context} incompleto: " + ", ".join(missing))
    lower = domain[lower_key]
    upper = domain[upper_key]
    reported_width = domain[width_key]
    if any(type(value) is not int for value in (lower, upper, reported_width)):
        raise RuntimeError(f"{context} deve contenere soltanto interi")
    if not I64_MIN <= lower <= I64_MAX or not I64_MIN <= upper <= I64_MAX:
        raise RuntimeError(f"{context} eccede il dominio signed 64-bit")
    width = upper - lower + 1
    if lower > upper or not 1 <= width <= SCORE_DOMAIN_WIDTH_MAX:
        raise RuntimeError(f"{context} non e' valido per il core exact-ID")
    if reported_width != width:
        raise RuntimeError(f"{context} dichiara una larghezza incoerente")
    return {"l": lower, "u": upper, "larghezza": width}


def expected_execution_plan(
    thresholds: object, tight_domain: dict[str, int]
) -> tuple[dict[str, int], str]:
    """Derive the same fail-closed public-domain decision independently of the server."""

    if (
        not isinstance(thresholds, list)
        or not thresholds
        or any(type(threshold) is not int for threshold in thresholds)
        or any(not I64_MIN <= threshold <= I64_MAX for threshold in thresholds)
    ):
        raise RuntimeError("soglie non valide per il piano di esecuzione")
    execution_domain = dict(tight_domain)
    path = A29_GENERAL_PATH
    if len(set(thresholds)) == 1:
        candidate_lower = thresholds[0] - ALIGNED_UNIFORM_THRESHOLD
        candidate_width = tight_domain["u"] - candidate_lower + 1
        if (
            I64_MIN <= candidate_lower <= I64_MAX
            and candidate_lower <= tight_domain["l"]
            and 1 <= candidate_width <= SCORE_DOMAIN_WIDTH_MAX
        ):
            execution_domain = {
                "l": candidate_lower,
                "u": tight_domain["u"],
                "larghezza": candidate_width,
            }
            path = A38_ALIGNED_PATH
    return execution_domain, path


def validate_exact_contract(state: dict[str, object]) -> dict[str, object]:
    """Fail closed unless config and live server independently match the canonical wire."""

    client = state.get("client")
    server = state.get("server")
    if not isinstance(client, dict) or not isinstance(server, dict):
        raise RuntimeError("/api/stato non contiene client e server")
    config = client.get("config")
    if not isinstance(config, dict):
        raise RuntimeError("/api/stato non contiene la configurazione client")
    client_contract = config.get("contratto_esatto")
    server_contract = server.get("contratto_esatto")
    if not isinstance(client_contract, dict) or not isinstance(server_contract, dict):
        raise RuntimeError("contratto exact-ID assente da client o server")

    client_mismatches = _contract_mismatches(client_contract, EXACT_CONFIG_CONTRACT)
    server_mismatches = _contract_mismatches(
        server_contract, EXACT_SERVER_WIRE_CONTRACT
    )
    if client_mismatches or server_mismatches:
        raise RuntimeError(
            "contratto exact-ID non canonico: "
            f"client={client_mismatches}, server={server_mismatches}"
        )
    if config.get("decisione") != EXACT_DECISION:
        raise RuntimeError("la configurazione non seleziona l'argmin esatto finale")
    comparator = config.get("comparatore_fhe")
    if not isinstance(comparator, dict) or comparator.get("stato") != EXACT_COMPARATOR:
        raise RuntimeError("la configurazione non dichiara il comparatore exact-ID canonico")

    key_sha256 = server.get("chiave_sha256")
    if (
        server.get("chiave") is not True
        or not isinstance(key_sha256, str)
        or len(key_sha256) != 64
        or any(character not in "0123456789abcdef" for character in key_sha256)
    ):
        raise RuntimeError("il server non dichiara una evaluation key fingerprintata")
    return {
        "expected_http_contract": EXACT_SERVER_CONTRACT,
        "decisione": EXACT_DECISION,
        "comparatore": EXACT_COMPARATOR,
        "evaluation_key_sha256": key_sha256,
        "client": client_contract,
        "server": server_contract,
    }


def stable_state_snapshot(
    state: dict[str, object], expected_n: int
) -> dict[str, object]:
    """Validate and retain only state that must remain identical across all queries."""

    contract = validate_exact_contract(state)
    client = state["client"]
    server = state["server"]
    if not isinstance(client, dict) or not isinstance(server, dict):
        raise RuntimeError("stato client/server non valido")
    config = client.get("config")
    if not isinstance(config, dict):
        raise RuntimeError("configurazione client non valida")
    if client.get("modello_caricato") is not True:
        raise RuntimeError("il client non dichiara il modello caricato dopo il preload")

    required = (
        "iscritti",
        "nomi",
        "soglie",
        "chiave",
        "chiave_sha256",
        "dim",
        "soglia_default",
        "epoch",
        "revision",
        "dominio",
        "dominio_esecuzione",
        "percorso_argmin",
        "contratto_esatto",
    )
    missing = [field for field in required if field not in server]
    if missing:
        raise RuntimeError("stato server incompleto: " + ", ".join(missing))
    if type(server["iscritti"]) is not int or server["iscritti"] != expected_n:
        raise RuntimeError(
            f"galleria live inattesa: {server['iscritti']!r}, atteso N={expected_n}"
        )
    names = server["nomi"]
    if (
        not isinstance(names, list)
        or len(names) != expected_n
        or not all(isinstance(name, str) for name in names)
        or len(set(names)) != expected_n
    ):
        raise RuntimeError("mappa posizionale dei nomi non valida o non univoca")

    threshold = config.get("T_sintetico_digiface")
    thresholds = server["soglie"]
    if type(threshold) is not int:
        raise RuntimeError("soglia sintetica client non intera")
    if (
        not isinstance(thresholds, list)
        or len(thresholds) != expected_n
        or any(type(value) is not int or value != threshold for value in thresholds)
    ):
        raise RuntimeError(
            f"soglie live non canoniche per la galleria sintetica: atteso T={threshold}"
        )

    configured_domains = config.get("dominio_score_cauchy")
    if not isinstance(configured_domains, dict):
        raise RuntimeError("dominio Cauchy assente dalla configurazione client")
    configured_tight = normalized_score_domain(
        configured_domains.get("galleria_sintetica_base"),
        "dominio Cauchy sintetico configurato",
        config_keys=True,
    )
    if configured_tight != EXPECTED_SYNTHETIC_CAUCHY_DOMAIN:
        raise RuntimeError(
            "dominio Cauchy sintetico configurato non canonico: "
            f"{configured_tight!r}"
        )
    observed_tight = normalized_score_domain(
        server["dominio"], "dominio Cauchy live"
    )
    if observed_tight != configured_tight:
        raise RuntimeError(
            "dominio Cauchy live diverso dalla galleria sintetica configurata: "
            f"{observed_tight!r} != {configured_tight!r}"
        )
    expected_execution, expected_path = expected_execution_plan(
        thresholds, observed_tight
    )
    observed_execution = normalized_score_domain(
        server["dominio_esecuzione"], "dominio di esecuzione live"
    )
    if observed_execution != expected_execution:
        raise RuntimeError(
            "dominio di esecuzione live diverso dal piano derivato indipendentemente: "
            f"{observed_execution!r} != {expected_execution!r}"
        )
    if not _same_value(server["percorso_argmin"], expected_path):
        raise RuntimeError(
            "percorso argmin live diverso dal piano derivato indipendentemente: "
            f"{server['percorso_argmin']!r} != {expected_path!r}"
        )
    expected_dim = config.get("dim")
    if type(expected_dim) is not int or not _same_value(server["dim"], expected_dim):
        raise RuntimeError(
            f"dimensione server/client incoerente: {server['dim']!r} != {expected_dim!r}"
        )
    default_threshold = config.get("T")
    if type(default_threshold) is not int or not _same_value(
        server["soglia_default"], default_threshold
    ):
        raise RuntimeError("soglia di default server/client incoerente")
    for field in ("epoch", "revision"):
        if type(server[field]) is not int or server[field] < 0:
            raise RuntimeError(f"{field} server non valido")

    config_json = json.dumps(config, sort_keys=True, separators=(",", ":"))
    return {
        "client_config_sha256": sha256_text(config_json),
        "contract": contract,
        "server": {field: server[field] for field in required},
    }


def runtime_model_file(model: str, override: pathlib.Path | None) -> pathlib.Path:
    if override is not None:
        candidates = [override]
    else:
        try:
            pack, filename = MODEL_LAYOUT[model]
        except KeyError as exc:
            raise ValueError(f"modello senza layout di provenance: {model}") from exc
        base = pathlib.Path.home() / ".insightface" / "models" / pack
        candidates = sorted(base.rglob(filename)) if base.is_dir() else []
    files = [path.resolve() for path in candidates if path.is_file()]
    if len(files) != 1:
        raise RuntimeError(f"atteso un solo file ONNX per {model}, trovati: {files}")
    return files[0]


def host_runtime_packages() -> dict[str, str]:
    return {
        package: importlib.metadata.version(package)
        for package in ("insightface", "numpy", "onnxruntime", "uvicorn")
    }


def server_process(
    pid: int | None, binary: pathlib.Path | None
) -> dict[str, object] | None:
    if pid is None:
        return None
    if binary is None:
        raise ValueError("--server-pid richiede --server-binary")
    resolved = binary.resolve()
    result = subprocess.run(
        ["ps", "-p", str(pid), "-o", "lstart=", "-o", "command="],
        check=True,
        capture_output=True,
        text=True,
    )
    process_line = result.stdout.strip()
    if str(resolved) not in process_line:
        raise RuntimeError(
            f"il PID {pid} non risulta avviato dal binario dichiarato {resolved}: "
            f"{process_line}"
        )
    return {
        "pid": pid,
        "ps_lstart_command": process_line,
        "binding": "exact_path_in_ps_command",
    }


def selected_dataset_files(
    config: dict[str, object],
    cases: list[tuple[int, str]],
) -> list[tuple[str, int, pathlib.Path]]:
    dataset = ROOT / "datasets" / "digiface" / "estratto"
    folders = sorted(path for path in dataset.iterdir() if path.is_dir())
    gallery_size = int(config["n_galleria_demo"])
    k_gallery = int(config["k_galleria"])
    k_probe = int(config["k_probe"])
    if len(folders) <= max(index for index, _ in cases):
        raise RuntimeError(
            "DigiFace non contiene tutti gli indici richiesti dal benchmark"
        )

    selected: list[tuple[str, int, pathlib.Path]] = []
    for index, folder in enumerate(folders[:gallery_size]):
        images = sorted(folder.glob("*.png"))[:k_gallery]
        if len(images) != k_gallery:
            raise RuntimeError(f"{folder}: immagini enrollment incomplete")
        selected.extend(("gallery", index, image) for image in images)
    for index, _ in cases:
        images = sorted(folders[index].glob("*.png"))[
            k_gallery : k_gallery + k_probe
        ]
        if len(images) != k_probe:
            raise RuntimeError(f"{folders[index]}: immagini query incomplete")
        selected.extend(("query", index, image) for image in images)
    return selected


def docker_dataset_expected_files(
    config: dict[str, object], cases: list[tuple[int, str]]
) -> dict[str, str]:
    """Map the exact host-selected DigiFace content to the paths read in the client."""

    dataset = ROOT / "datasets" / "digiface" / "estratto"
    expected: dict[str, str] = {}
    for _role, _index, image in selected_dataset_files(config, cases):
        relative = image.relative_to(dataset).as_posix()
        container_path = f"{DOCKER_DATASET_ROOT}/{relative}"
        if container_path in expected:
            raise RuntimeError(f"file DigiFace selezionato due volte: {container_path}")
        expected[container_path] = sha256_file(image)
    return expected


def dataset_provenance(
    config: dict[str, object],
    cases: list[tuple[int, str]],
    require_calibration_cache: bool,
) -> dict[str, object]:
    import numpy as np

    dataset = ROOT / "datasets" / "digiface" / "estratto"
    selected = selected_dataset_files(config, cases)
    gallery_size = int(config["n_galleria_demo"])

    manifest = hashlib.sha256()
    total_bytes = 0
    for role, index, image in selected:
        payload = image.read_bytes()
        total_bytes += len(payload)
        relative = image.relative_to(ROOT)
        manifest.update(
            f"{role}\t{index}\t{relative}\t{hashlib.sha256(payload).hexdigest()}\n".encode()
        )

    cache_path = ROOT / "datasets" / "digiface" / "_q_demo_calibrazione_resnet100.npz"
    if not cache_path.is_file():
        if require_calibration_cache:
            raise FileNotFoundError(
                f"cache di calibrazione DigiFace non trovata: {cache_path}"
            )
        return {
            "dataset_root": str(dataset.resolve()),
            "selected_image_count": len(selected),
            "selected_image_bytes": total_bytes,
            "selected_content_manifest_sha256": manifest.hexdigest(),
            "calibration_cache": None,
            "calibration_cache_sha256": None,
            "scene_sha256_verified": None,
            "holdout_sha256_verified": None,
        }
    with np.load(cache_path, allow_pickle=False) as cache:
        gallery = cache["G"].astype(np.int64)
        probes = cache["P"].astype(np.int64)
    calibration = config["calibrazione_sintetica"]
    dev_size = int(calibration["impostori_tuning"])
    test_size = int(calibration["impostori_test"])
    scene_hash = sha256_arrays(
        gallery,
        probes[:gallery_size],
        probes[gallery_size : gallery_size + dev_size],
        probes[gallery_size + dev_size : gallery_size + dev_size + test_size],
    )
    holdout_hash = sha256_arrays(probes[gallery_size + dev_size :])
    if (
        scene_hash != calibration["scene_sha256"]
        or holdout_hash != calibration["holdout_sha256"]
    ):
        raise RuntimeError("cache DigiFace e hash della configurazione non coincidono")
    return {
        "dataset_root": str(dataset.resolve()),
        "selected_image_count": len(selected),
        "selected_image_bytes": total_bytes,
        "selected_content_manifest_sha256": manifest.hexdigest(),
        "calibration_cache": str(cache_path.resolve()),
        "calibration_cache_sha256": sha256_file(cache_path),
        "scene_sha256_verified": scene_hash,
        "holdout_sha256_verified": holdout_hash,
    }


def _strict_sha256(value: str, label: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(c not in "0123456789abcdef" for c in normalized):
        raise RuntimeError(f"SHA-256 non valido per {label}: {value!r}")
    return normalized


def parse_build_manifest(text: str) -> dict[str, str]:
    """Parse the sha256sum manifest embedded by each Docker image."""

    entries: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        if not raw_line.strip():
            continue
        parts = raw_line.split(maxsplit=1)
        if len(parts) != 2:
            raise RuntimeError(f"manifest Docker malformato alla riga {line_number}")
        digest = _strict_sha256(parts[0], f"manifest riga {line_number}")
        path = parts[1].removeprefix("*")
        pure = pathlib.PurePosixPath(path)
        if not path or pure.is_absolute() or ".." in pure.parts or path in entries:
            raise RuntimeError(f"path non valido o duplicato nel manifest: {path!r}")
        entries[path] = digest
    if not entries:
        raise RuntimeError("manifest Docker vuoto")
    return entries


def _run_command(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"eseguibile non trovato: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        raise RuntimeError(
            f"comando {command[0]!r} fallito con exit {exc.returncode}: {stderr}"
        ) from exc
    return result.stdout


def docker_exec_text(container_id: str, *command: str) -> str:
    return _run_command(["docker", "exec", container_id, *command])


def docker_sha256(container_id: str, path: str) -> str:
    output = docker_exec_text(container_id, "sha256sum", "--", path).strip()
    parts = output.split(maxsplit=1)
    if len(parts) != 2 or parts[1].removeprefix("*") != path:
        raise RuntimeError(f"output sha256sum inatteso per {path}: {output!r}")
    return _strict_sha256(parts[0], path)


def docker_sha256_files(container_id: str, paths: list[str]) -> dict[str, str]:
    """Hash exact container paths in bounded batches and reject ambiguous filenames."""

    if len(set(paths)) != len(paths):
        raise RuntimeError("lista di file container duplicata")
    observed: dict[str, str] = {}
    for offset in range(0, len(paths), 100):
        batch = paths[offset : offset + 100]
        output = docker_exec_text(container_id, "sha256sum", "--", *batch)
        for line in output.splitlines():
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                raise RuntimeError(f"output sha256sum multiplo malformato: {line!r}")
            path = parts[1].removeprefix("*")
            if path not in batch or path in observed:
                raise RuntimeError(f"path inatteso o duplicato da sha256sum: {path!r}")
            observed[path] = _strict_sha256(parts[0], path)
    if set(observed) != set(paths):
        missing = sorted(set(paths) - set(observed))
        raise RuntimeError(f"sha256sum container incompleto, mancano: {missing}")
    return observed


def docker_service_container(
    compose_file: pathlib.Path, project: str, service: str
) -> str:
    output = _run_command(
        [
            "docker",
            "compose",
            "-p",
            project,
            "-f",
            str(compose_file),
            "ps",
            "--status",
            "running",
            "-q",
            service,
        ]
    )
    containers = [line.strip() for line in output.splitlines() if line.strip()]
    if len(containers) != 1:
        raise RuntimeError(
            f"atteso un solo container {service!r} in esecuzione, trovati {containers}"
        )
    return containers[0]


def _json_singleton(output: str, label: str) -> dict[str, object]:
    try:
        decoded = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label}: JSON non valido") from exc
    if (
        not isinstance(decoded, list)
        or len(decoded) != 1
        or not isinstance(decoded[0], dict)
    ):
        raise RuntimeError(f"{label}: atteso un singolo oggetto")
    return decoded[0]


def _path_is_mounted(path: str, mounts: list[object]) -> bool:
    pure_path = pathlib.PurePosixPath(path)
    for raw_mount in mounts:
        if not isinstance(raw_mount, dict):
            continue
        destination = raw_mount.get("Destination")
        if not isinstance(destination, str):
            continue
        mount_path = pathlib.PurePosixPath(destination)
        if pure_path == mount_path or mount_path in pure_path.parents:
            return True
    return False


def docker_service_snapshot(
    compose_file: pathlib.Path,
    project: str,
    service: str,
    model: str | None = None,
    dataset_expected: dict[str, str] | None = None,
) -> dict[str, object]:
    """Bind a running service to its image, embedded sources and live executable."""

    container_id = docker_service_container(compose_file, project, service)
    container = _json_singleton(
        _run_command(["docker", "container", "inspect", container_id]),
        f"inspect container {service}",
    )
    state = container.get("State")
    config = container.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if (
        not isinstance(state, dict)
        or state.get("Running") is not True
        or not isinstance(labels, dict)
        or labels.get("com.docker.compose.project") != project
        or labels.get("com.docker.compose.service") != service
    ):
        raise RuntimeError(f"container {service} non appartiene al servizio atteso")
    expected_command = EXPECTED_CONTAINER_COMMAND[service]
    if (
        container.get("Path") != expected_command["path"]
        or container.get("Args") != expected_command["args"]
    ):
        raise RuntimeError(
            f"comando live del container {service} non canonico: "
            f"Path={container.get('Path')!r}, Args={container.get('Args')!r}"
        )
    if service == "client" and config.get("WorkingDir") != "/app":
        raise RuntimeError(
            f"working directory live del client non canonica: "
            f"{config.get('WorkingDir')!r}"
        )

    image_id = container.get("Image")
    if not isinstance(image_id, str):
        raise RuntimeError(f"image ID mancante per {service}")
    image = _json_singleton(
        _run_command(["docker", "image", "inspect", image_id]),
        f"inspect image {service}",
    )
    if image.get("Id") != image_id:
        raise RuntimeError(f"image ID incoerente per {service}")

    manifest_text = docker_exec_text(container_id, "cat", "--", DOCKER_MANIFEST)
    manifest = parse_build_manifest(manifest_text)
    expected_inputs = SERVICE_BUILD_INPUTS[service]
    expected_manifest_paths = set(expected_inputs) | {"target/release/varco_demo"}
    if set(manifest) != expected_manifest_paths:
        raise RuntimeError(
            f"manifest {service} incompleto o inatteso: "
            f"expected={sorted(expected_manifest_paths)}, observed={sorted(manifest)}"
        )
    host_source_hashes = {
        path: sha256_file(host_path) for path, host_path in expected_inputs.items()
    }
    source_mismatches = {
        path: {"host": digest, "image_manifest": manifest.get(path)}
        for path, digest in host_source_hashes.items()
        if manifest.get(path) != digest
    }
    if source_mismatches:
        raise RuntimeError(
            f"sorgenti host e manifest immagine {service} non coincidono: "
            f"{source_mismatches}"
        )

    mounts = container.get("Mounts")
    if not isinstance(mounts, list):
        raise RuntimeError(f"mount metadata non valido per {service}")
    protected_paths = [DOCKER_BINARY, DOCKER_MANIFEST]
    runtime_files: dict[str, dict[str, object]] = {}
    launcher_hash = None
    runtime_dataset = None
    if service == "client":
        for container_path, manifest_path in CLIENT_RUNTIME_FILES.items():
            live_hash = docker_sha256(container_id, container_path)
            if live_hash != manifest[manifest_path]:
                raise RuntimeError(
                    f"runtime client {container_path} non coincide col manifest immagine"
                )
            protected_paths.append(container_path)
            runtime_files[container_path] = {
                "sha256": live_hash,
                "manifest_path": manifest_path,
            }
        launcher_path = str(EXPECTED_CONTAINER_COMMAND["client"]["path"])
        launcher_hash = docker_sha256(container_id, launcher_path)
        protected_paths.append(launcher_path)
        if dataset_expected is None:
            raise RuntimeError(
                "manifest DigiFace richiesto per la provenance del client Docker"
            )
        observed_dataset = docker_sha256_files(
            container_id, sorted(dataset_expected)
        )
        dataset_mismatches = {
            path: {"host": digest, "client_container": observed_dataset.get(path)}
            for path, digest in dataset_expected.items()
            if observed_dataset.get(path) != digest
        }
        if dataset_mismatches:
            raise RuntimeError(
                "i file DigiFace letti dal client Docker non coincidono con "
                f"il manifest host: {dataset_mismatches}"
            )
        runtime_dataset = {
            "root": DOCKER_DATASET_ROOT,
            "selected_file_count": len(observed_dataset),
            "path_content_manifest_sha256": sha256_text(
                "".join(
                    f"{path}\t{observed_dataset[path]}\n"
                    for path in sorted(observed_dataset)
                )
            ),
        }
    mounted_protected = [
        path for path in protected_paths if _path_is_mounted(path, mounts)
    ]
    if mounted_protected:
        raise RuntimeError(
            f"file probatori nascosti da mount nel container {service}: "
            f"{mounted_protected}"
        )

    live_binary_hash = docker_sha256(container_id, DOCKER_BINARY)
    if live_binary_hash != manifest["target/release/varco_demo"]:
        raise RuntimeError(f"binario live {service} non coincide col manifest immagine")
    manifest_hash = sha256_text(manifest_text)

    network_settings = container.get("NetworkSettings")
    raw_networks = (
        network_settings.get("Networks")
        if isinstance(network_settings, dict)
        else None
    )
    if not isinstance(raw_networks, dict) or not raw_networks:
        raise RuntimeError(f"reti container mancanti per {service}")
    networks = {}
    for name, raw_network in raw_networks.items():
        if not isinstance(raw_network, dict):
            raise RuntimeError(f"rete {name} non valida per {service}")
        aliases = raw_network.get("Aliases")
        networks[name] = {
            "network_id": raw_network.get("NetworkID"),
            "aliases": sorted(aliases) if isinstance(aliases, list) else [],
            "ip_address": raw_network.get("IPAddress"),
        }

    ports = network_settings.get("Ports") if isinstance(network_settings, dict) else {}
    if not isinstance(ports, dict):
        raise RuntimeError(f"port binding non valido per {service}")
    port_bindings = {
        port: sorted(
            [
                {
                    "host_ip": binding.get("HostIp"),
                    "host_port": binding.get("HostPort"),
                }
                for binding in bindings
                if isinstance(binding, dict)
            ],
            key=lambda binding: (
                str(binding["host_ip"]),
                str(binding["host_port"]),
            ),
        )
        for port, bindings in ports.items()
        if isinstance(bindings, list)
    }

    environment: dict[str, str] = {}
    selected_environment_names = (
        set(EXPECTED_CLIENT_ENVIRONMENT)
        if service == "client"
        else {"DIM", "SOGLIA", "PORTA"}
    )
    raw_environment = config.get("Env") if isinstance(config, dict) else None
    if isinstance(raw_environment, list):
        for entry in raw_environment:
            if isinstance(entry, str) and "=" in entry:
                name, value = entry.split("=", 1)
                if name in selected_environment_names:
                    environment[name] = value
    if service == "client" and environment != EXPECTED_CLIENT_ENVIRONMENT:
        raise RuntimeError(
            f"ambiente runtime del client Docker non canonico: {environment}"
        )
    if service == "server" and environment != {
        "DIM": "512",
        "SOGLIA": "4",
        "PORTA": "9000",
    }:
        raise RuntimeError(
            f"parametri runtime del server Docker non canonici: {environment}"
        )

    raw_pid1_cmdline = docker_exec_text(
        container_id, "cat", "--", "/proc/1/cmdline"
    )
    pid1_cmdline = [
        argument for argument in raw_pid1_cmdline.rstrip("\0").split("\0") if argument
    ]
    pid1_executable = docker_exec_text(
        container_id, "readlink", "-f", "--", "/proc/1/exe"
    ).strip()
    pid1_executable_sha256 = docker_sha256(container_id, "/proc/1/exe")
    pid1_working_directory = docker_exec_text(
        container_id, "readlink", "-f", "--", "/proc/1/cwd"
    ).strip()
    raw_pid1_environment = docker_exec_text(
        container_id, "cat", "--", "/proc/1/environ"
    )
    pid1_environment: dict[str, str] = {}
    process_environment_names = set(selected_environment_names) | {"HOME"}
    for entry in raw_pid1_environment.rstrip("\0").split("\0"):
        if "=" in entry:
            name, value = entry.split("=", 1)
            if name in process_environment_names:
                pid1_environment[name] = value
    if service == "server":
        expected_pid1 = [
            DOCKER_BINARY,
            "serve",
            environment["PORTA"],
            environment["DIM"],
            environment["SOGLIA"],
        ]
        if pid1_cmdline != expected_pid1 or pid1_executable != DOCKER_BINARY:
            raise RuntimeError(
                "il PID 1 del server non e' il varco_demo canonico: "
                f"exe={pid1_executable!r}, argv={pid1_cmdline!r}"
            )
        if pid1_executable_sha256 != live_binary_hash:
            raise RuntimeError("il PID 1 server non coincide col binario live hashato")
    else:
        expected_tail = [
            str(EXPECTED_CONTAINER_COMMAND["client"]["path"]),
            *EXPECTED_CONTAINER_COMMAND["client"]["args"],
        ]
        if pid1_cmdline[-len(expected_tail) :] != expected_tail:
            raise RuntimeError(
                f"il PID 1 del client non esegue uvicorn canonico: {pid1_cmdline!r}"
            )
        if not pid1_executable.startswith("/usr/local/bin/python"):
            raise RuntimeError(
                f"interprete PID 1 client inatteso: {pid1_executable!r}"
            )
        expected_pid1_environment = {
            **EXPECTED_CLIENT_ENVIRONMENT,
            "HOME": "/root",
        }
        if pid1_environment != expected_pid1_environment:
            raise RuntimeError(
                f"ambiente effettivo PID 1 client non canonico: {pid1_environment}"
            )
        if pid1_working_directory != "/app":
            raise RuntimeError(
                f"cwd effettiva PID 1 client non canonica: {pid1_working_directory!r}"
            )
        effective_home = docker_exec_text(
            container_id,
            DOCKER_CLIENT_PYTHON,
            "-c",
            "import os; print(os.path.expanduser('~'))",
        ).strip()
        if effective_home != "/root":
            raise RuntimeError(
                f"home effettiva del client non canonica: {effective_home!r}"
            )
        import_origin = docker_exec_text(
            container_id,
            DOCKER_CLIENT_PYTHON,
            "-c",
            "import importlib.util; print(importlib.util.find_spec("
            "'demo.client.app').origin)",
        ).strip()
        if import_origin != "/app/demo/client/app.py":
            raise RuntimeError(
                f"demo.client.app risolve a un sorgente inatteso: {import_origin!r}"
            )

    runtime_model = None
    runtime_packages = None
    if service == "client" and model is not None:
        try:
            model_pack, model_filename = MODEL_LAYOUT[model]
        except KeyError as exc:
            raise ValueError(f"modello senza layout di provenance: {model}") from exc
        model_root = f"/root/.insightface/models/{model_pack}"
        discovery_script = (
            "import json,os,sys;"
            "root,name=sys.argv[1:];"
            "print(json.dumps(sorted(os.path.join(directory,filename) "
            "for directory,_,files in os.walk(root) for filename in files "
            "if filename==name)))"
        )
        try:
            model_candidates = json.loads(
                docker_exec_text(
                    container_id,
                    DOCKER_CLIENT_PYTHON,
                    "-c",
                    discovery_script,
                    model_root,
                    model_filename,
                )
            )
        except json.JSONDecodeError as exc:
            raise RuntimeError("discovery del modello client Docker non valida") from exc
        if (
            not isinstance(model_candidates, list)
            or len(model_candidates) != 1
            or not isinstance(model_candidates[0], str)
        ):
            raise RuntimeError(
                f"atteso un solo modello {model_filename} nel client, "
                f"trovati {model_candidates!r}"
            )
        model_path = model_candidates[0]
        docker_exec_text(container_id, "test", "-f", model_path)
        resolved_model_path = docker_exec_text(
            container_id, "readlink", "-f", "--", model_path
        ).strip()
        expected_prefix = "/root/.insightface/models/"
        if not resolved_model_path.startswith(expected_prefix):
            raise RuntimeError(
                f"modello client risolto fuori dalla directory attesa: {resolved_model_path}"
            )
        model_size = docker_exec_text(
            container_id, "stat", "-c", "%s", "--", model_path
        ).strip()
        if not model_size.isdigit() or int(model_size) <= 0:
            raise RuntimeError("dimensione del modello ONNX nel client non valida")
        runtime_model = {
            "search_root": model_root,
            "filename": model_filename,
            "resolved_path": resolved_model_path,
            "sha256": docker_sha256(container_id, model_path),
            "bytes": int(model_size),
        }
        package_script = (
            "import importlib.metadata as m,json;"
            "print(json.dumps({p:m.version(p) for p in "
            "('insightface','numpy','onnxruntime','uvicorn')},sort_keys=True))"
        )
        try:
            runtime_packages = json.loads(
                docker_exec_text(
                    container_id, DOCKER_CLIENT_PYTHON, "-c", package_script
                )
            )
        except json.JSONDecodeError as exc:
            raise RuntimeError("versioni pacchetti client Docker non valide") from exc
        expected_packages = {"insightface", "numpy", "onnxruntime", "uvicorn"}
        if (
            not isinstance(runtime_packages, dict)
            or set(runtime_packages) != expected_packages
            or not all(
                isinstance(version, str) and version
                for version in runtime_packages.values()
            )
        ):
            raise RuntimeError(
                f"versioni pacchetti client Docker incomplete: {runtime_packages!r}"
            )

    # Run this after all diagnostic commands: first-run Python bytecode created by those commands
    # is then already part of both the before and after snapshots.
    diff_lines = sorted(
        line.strip()
        for line in _run_command(["docker", "diff", container_id]).splitlines()
        if line.strip()
    )
    changed_protected: list[str] = []
    for line in diff_lines:
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            raise RuntimeError(f"docker diff malformato per {service}: {line!r}")
        changed_path = parts[1]
        if any(
            changed_path == protected
            or changed_path.startswith(protected.rstrip("/") + "/")
            for protected in protected_paths
        ):
            changed_protected.append(line)
    if changed_protected:
        raise RuntimeError(
            f"file probatori modificati nel container {service}: {changed_protected}"
        )

    image_config = image.get("Config")
    image_reference = config.get("Image") if isinstance(config, dict) else None
    return {
        "service": service,
        "container_id": container_id,
        "container_name": container.get("Name"),
        "container_created": container.get("Created"),
        "container_started_at": state.get("StartedAt"),
        "container_status": state.get("Status"),
        "restart_count": container.get("RestartCount"),
        "image_id": image_id,
        "image_reference": image_reference,
        "image_created": image.get("Created"),
        "image_os": image.get("Os"),
        "image_architecture": image.get("Architecture"),
        "image_repo_digests": sorted(image.get("RepoDigests") or []),
        "image_working_dir": (
            image_config.get("WorkingDir") if isinstance(image_config, dict) else None
        ),
        "build_manifest_path": DOCKER_MANIFEST,
        "build_manifest_sha256": manifest_hash,
        "build_manifest": manifest,
        "host_source_hashes": host_source_hashes,
        "live_binary_path": DOCKER_BINARY,
        "live_binary_sha256": live_binary_hash,
        "container_config_path": container.get("Path"),
        "container_config_args": container.get("Args"),
        "pid1_executable": pid1_executable,
        "pid1_executable_sha256": pid1_executable_sha256,
        "pid1_cmdline": pid1_cmdline,
        "pid1_working_directory": pid1_working_directory,
        "selected_pid1_environment": pid1_environment,
        "launcher_sha256": launcher_hash,
        "runtime_files": runtime_files,
        "runtime_dataset": runtime_dataset,
        "runtime_model": runtime_model,
        "runtime_packages": runtime_packages,
        "selected_environment": environment,
        "networks": networks,
        "port_bindings": port_bindings,
        "mounts": sorted(
            [
                {
                    "type": mount.get("Type"),
                    "destination": mount.get("Destination"),
                    "rw": mount.get("RW"),
                }
                for mount in mounts
                if isinstance(mount, dict)
            ],
            key=lambda mount: str(mount["destination"]),
        ),
        "docker_diff_sha256": sha256_text("\n".join(diff_lines)),
    }


def docker_provenance(
    compose_file: pathlib.Path,
    project: str,
    base_url: str,
    model: str | None,
    dataset_expected: dict[str, str],
) -> dict[str, object]:
    compose_file = compose_file.resolve()
    compose_config = _run_command(
        [
            "docker",
            "compose",
            "-p",
            project,
            "-f",
            str(compose_file),
            "config",
        ]
    )
    services = {
        "server": docker_service_snapshot(compose_file, project, "server"),
        "client": docker_service_snapshot(
            compose_file,
            project,
            "client",
            model=model,
            dataset_expected=dataset_expected,
        ),
    }
    common_networks = sorted(
        set(services["server"]["networks"]) & set(services["client"]["networks"])
    )
    usable_networks = [
        network
        for network in common_networks
        if "server" in services["server"]["networks"][network]["aliases"]
    ]
    if not usable_networks:
        raise RuntimeError(
            "client e server Docker non condividono una rete con alias server"
        )

    parsed_url = urllib.parse.urlsplit(base_url)
    if parsed_url.scheme != "http" or parsed_url.hostname not in {
        "127.0.0.1",
        "localhost",
        "::1",
    }:
        raise RuntimeError(
            "--base-url deve essere HTTP loopback per vincolarlo al client Docker"
        )
    measured_port = parsed_url.port or 80
    client_bindings = services["client"]["port_bindings"].get("8000/tcp", [])
    if not any(
        binding.get("host_port") == str(measured_port)
        and binding.get("host_ip") in {"127.0.0.1", "::1"}
        for binding in client_bindings
    ):
        raise RuntimeError(
            f"--base-url non coincide col port binding del client Docker: {client_bindings}"
        )

    context_files = {
        "compose": compose_file,
        "server_dockerfile": ROOT / "demo" / "server" / "Dockerfile",
        "client_dockerfile": ROOT / "demo" / "client" / "Dockerfile",
    }
    dockerignore = ROOT / ".dockerignore"
    if dockerignore.is_file():
        context_files["dockerignore"] = dockerignore
    return {
        "project": project,
        "compose_file": str(compose_file),
        "compose_config_sha256": sha256_text(compose_config),
        "context_file_sha256": {
            name: sha256_file(path) for name, path in context_files.items()
        },
        "verified_common_networks": usable_networks,
        "measured_client_port": measured_port,
        "services": services,
    }


def docker_static_binding(provenance: dict[str, object]) -> dict[str, object]:
    """Projection that must not change while preload creates the in-memory gallery."""

    projected = json.loads(json.dumps(provenance))
    for service in ("server", "client"):
        snapshot = projected["services"][service]
        snapshot.pop("runtime_model", None)
        snapshot.pop("runtime_packages", None)
        snapshot.pop("docker_diff_sha256", None)
    return projected


def host_input_hashes() -> dict[str, str]:
    inputs = {
        "benchmark/demo_e2e.py": pathlib.Path(__file__),
        "demo/client/app.py": ROOT / "demo" / "client" / "app.py",
        "demo/client/Dockerfile": ROOT / "demo" / "client" / "Dockerfile",
        "demo/server/Dockerfile": ROOT / "demo" / "server" / "Dockerfile",
        "demo/docker-compose.yml": ROOT / "demo" / "docker-compose.yml",
        "demo/config.json": ROOT / "demo" / "config.json",
        "experiments/08_cnn/embedding.py": (
            ROOT / "experiments" / "08_cnn" / "embedding.py"
        ),
        **{
            f"experiments/14_pipeline_tfhe_rs/{path}": host_path
            for path, host_path in COMMON_BUILD_INPUTS.items()
        },
    }
    return {name: sha256_file(path) for name, path in inputs.items()}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--positivi", type=int, default=20)
    parser.add_argument("--negativi", type=int, default=20)
    parser.add_argument(
        "--preload",
        action="store_true",
        required=True,
        help="required: rebuild the gallery from the bound model and DigiFace inputs",
    )
    parser.add_argument(
        "--expect-n",
        type=int,
        required=True,
        help="cardinalita' canonica attesa della galleria live",
    )
    parser.add_argument(
        "--expect-pbs",
        type=int,
        required=True,
        help="conteggio PBS canonico atteso in ogni singola query",
    )
    parser.add_argument(
        "--server-binary",
        type=pathlib.Path,
        help="optional local Rust binary whose SHA-256 should be recorded",
    )
    parser.add_argument(
        "--server-pid",
        type=int,
        help="optional PID used to bind the declared local binary to the measured server process",
    )
    parser.add_argument(
        "--model-file",
        type=pathlib.Path,
        help="runtime ONNX file; auto-discovered for a non-Docker run",
    )
    parser.add_argument(
        "--docker-project",
        help="Compose project whose live client/server should be bound to the evidence",
    )
    parser.add_argument(
        "--docker-compose-file",
        type=pathlib.Path,
        default=ROOT / "demo" / "docker-compose.yml",
    )
    parser.add_argument(
        "--require-docker-provenance",
        action="store_true",
        help="fail closed unless --docker-project enables full live-container provenance",
    )
    parser.add_argument(
        "--require-calibration-cache",
        action="store_true",
        help="fail unless the ignored DigiFace cache matches the config scene hashes",
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=ROOT / "benchmark" / "results" / "demo_e2e.csv",
    )
    args = parser.parse_args(argv)
    if args.expect_n <= 0:
        parser.error("--expect-n deve essere positivo")
    if args.expect_pbs <= 0:
        parser.error("--expect-pbs deve essere positivo")
    if args.docker_project is not None and not args.docker_project.strip():
        parser.error("--docker-project non puo' essere vuoto")
    if args.require_docker_provenance and not args.docker_project:
        parser.error(
            "--require-docker-provenance richiede --docker-project (fail closed)"
        )
    return args


def richiesta(base_url: str, path: str, body: dict | None = None) -> dict:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        base_url + path,
        data=data,
        method="GET" if body is None else "POST",
        headers={"Content-Type": "application/json"} if body is not None else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=600) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"{path}: HTTP {exc.code}: {exc.read().decode(errors='replace')}"
        ) from exc
    if not isinstance(result, dict):
        raise RuntimeError(f"{path}: risposta JSON non oggetto")
    return result


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def distribuzione(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    middle = len(ordered) // 2
    median = (
        ordered[middle]
        if len(ordered) % 2
        else (ordered[middle - 1] + ordered[middle]) / 2
    )
    return {
        "min": round(ordered[0], 3),
        "median": round(median, 3),
        "p95": round(percentile(ordered, 0.95), 3),
        "max": round(ordered[-1], 3),
    }


def write_results(
    output: pathlib.Path,
    rows: list[dict[str, object]],
    summary: dict[str, object],
) -> int:
    """Persist diagnostics first, then return a semantic success/failure exit status."""

    if not rows:
        raise ValueError("nessuna query da scrivere")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    failures = [
        {
            "trial": row["trial"],
            "indice_sintetico": row["indice_sintetico"],
            "atteso": row["atteso"],
            "esito": row["esito"],
            "identita_attesa": row["identita_attesa"],
            "identita_restituita": row["identita_restituita"],
            "esito_corretto": row["esito_corretto"],
            "identita_corretta": row["identita_corretta"],
        }
        for row in rows
        if row["corretto"] is not True
    ]
    summary["success"] = not failures
    summary["semantic_failure_count"] = len(failures)
    summary["semantic_failures"] = failures
    summary["csv_sha256"] = sha256_file(output)
    summary_path = output.with_suffix(".json")
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    print(f"scritto {output}")
    print(f"scritto {summary_path}")
    if failures:
        print(
            f"fallimento semantico: {len(failures)} query errate; artefatti preservati",
            file=sys.stderr,
        )
        return 1
    return 0


def main() -> int:
    args = parse_args()
    if args.require_docker_provenance and not args.docker_project:
        raise ValueError(
            "--require-docker-provenance richiede --docker-project (fail closed)"
        )
    docker_mode = args.docker_project is not None
    if docker_mode and any(
        value is not None
        for value in (args.server_binary, args.server_pid, args.model_file)
    ):
        raise ValueError(
            "in modalita' Docker non usare --server-binary, --server-pid o --model-file"
        )
    if docker_mode and not args.docker_compose_file.is_file():
        raise FileNotFoundError(
            f"Compose file non trovato: {args.docker_compose_file}"
        )
    if args.server_binary is not None and not args.server_binary.is_file():
        raise FileNotFoundError(f"server binary non trovato: {args.server_binary}")

    load_prima = list(os.getloadavg())
    host_hashes_before = host_input_hashes()
    stato_iniziale = richiesta(args.base_url, "/api/stato")
    initial_contract = validate_exact_contract(stato_iniziale)
    client = stato_iniziale.get("client")
    if not isinstance(client, dict) or not isinstance(client.get("config"), dict):
        raise RuntimeError("configurazione client mancante")
    if client.get("modello_caricato") is not False:
        raise RuntimeError(
            "run probatorio richiede un client fresco col modello non ancora caricato"
        )
    config = client["config"]
    configured_n = config.get("n_galleria_demo")
    if type(configured_n) is not int or configured_n != args.expect_n:
        raise RuntimeError(
            f"N configurato {configured_n!r}, ma --expect-n={args.expect_n}"
        )
    calibration = config.get("calibrazione_sintetica")
    if (
        not isinstance(calibration, dict)
        or not _same_value(calibration.get("iscritti"), args.expect_n)
    ):
        raise RuntimeError("la calibrazione sintetica non e' vincolata a --expect-n")
    n_galleria = args.expect_n
    impostori_tuning = int(calibration["impostori_tuning"])
    impostori_test = int(calibration["impostori_test"])
    primo_impostore_test = n_galleria + impostori_tuning
    if not 1 <= args.positivi <= n_galleria:
        raise ValueError(f"--positivi deve essere fra 1 e {n_galleria}")
    if not 1 <= args.negativi <= impostori_test:
        raise ValueError(f"--negativi deve essere fra 1 e {impostori_test}")

    cases = [(index, "aperto") for index in range(args.positivi)]
    cases += [
        (primo_impostore_test + index, "negato")
        for index in range(args.negativi)
    ]
    process_before = server_process(args.server_pid, args.server_binary)
    server_binary_hash_before = (
        sha256_file(args.server_binary) if args.server_binary else None
    )
    input_provenance = dataset_provenance(
        config, cases, args.require_calibration_cache
    )
    digiface_folders = sorted(
        path
        for path in (ROOT / "datasets" / "digiface" / "estratto").iterdir()
        if path.is_dir()
    )

    docker_preload = None
    docker_dataset_expected = None
    if docker_mode:
        docker_dataset_expected = docker_dataset_expected_files(config, cases)
        docker_preload = docker_provenance(
            args.docker_compose_file,
            args.docker_project,
            args.base_url,
            None,
            docker_dataset_expected,
        )

    stato_preload = richiesta(args.base_url, "/api/stato")
    preload_contract = validate_exact_contract(stato_preload)
    preload_client = stato_preload.get("client")
    if (
        preload_contract != initial_contract
        or not isinstance(preload_client, dict)
        or preload_client.get("config") != config
        or preload_client.get("modello_caricato") is not False
    ):
        raise RuntimeError(
            "client, config, contratto o cache modello sono cambiati prima del preload"
        )

    preload = richiesta(args.base_url, "/api/precarica", {})
    if not _same_value(preload.get("iscritti"), args.expect_n):
        raise RuntimeError(
            f"preload incompleto: {preload.get('iscritti')!r} iscritti, "
            f"attesi {args.expect_n}"
        )

    stato_prima = richiesta(args.base_url, "/api/stato")
    state_before = stable_state_snapshot(stato_prima, args.expect_n)
    post_preload_client = stato_prima.get("client")
    if (
        not isinstance(post_preload_client, dict)
        or post_preload_client.get("config") != config
    ):
        raise RuntimeError("la configurazione client e' cambiata durante il preload")
    if state_before["contract"] != initial_contract:
        raise RuntimeError("il contratto exact-ID e' cambiato durante il setup")

    docker_before = None
    model_file = None
    model_hash_before = None
    if docker_mode:
        if docker_dataset_expected is None or docker_preload is None:
            raise RuntimeError("snapshot Docker pre-preload mancante")
        docker_before = docker_provenance(
            args.docker_compose_file,
            args.docker_project,
            args.base_url,
            str(config["modello"]),
            docker_dataset_expected,
        )
        if docker_static_binding(docker_before) != docker_static_binding(
            docker_preload
        ):
            raise RuntimeError(
                "container, processi, sorgenti o dataset sono cambiati durante il preload"
            )
        runtime_model = docker_before["services"]["client"]["runtime_model"]
        runtime_packages = docker_before["services"]["client"]["runtime_packages"]
    else:
        model_file = runtime_model_file(str(config["modello"]), args.model_file)
        model_hash_before = sha256_file(model_file)
        runtime_model = {
            "requested_path": str(model_file),
            "resolved_path": str(model_file),
            "sha256": model_hash_before,
            "bytes": model_file.stat().st_size,
        }
        runtime_packages = host_runtime_packages()

    rows: list[dict[str, object]] = []
    for trial, (index, expected_result) in enumerate(cases):
        t0 = time.perf_counter()
        response = richiesta(
            args.base_url, "/api/verifica", {"sintetico": index}
        )
        endpoint_http_ms = (time.perf_counter() - t0) * 1000
        observed_protocol = response.get("protocollo_http")
        if observed_protocol != EXACT_SERVER_CONTRACT:
            raise RuntimeError(
                "la query non prova di avere osservato l'header HTTP canonico: "
                f"{observed_protocol!r}"
            )
        observed_pbs = response.get("pbs")
        if type(observed_pbs) is not int or observed_pbs != args.expect_pbs:
            raise RuntimeError(
                f"query {trial}: PBS={observed_pbs!r}, atteso {args.expect_pbs}"
            )
        timings = response.get("tempi_ms")
        byte_counts = response.get("byte")
        if not isinstance(timings, dict) or not isinstance(byte_counts, dict):
            raise RuntimeError(f"query {trial}: telemetria strutturale incompleta")
        timing_fields = (
            "embedding",
            "cifratura",
            "server",
            "rete_e_server",
            "decifratura",
            "endpoint",
        )
        invalid_timings = {
            field: timings.get(field)
            for field in timing_fields
            if (
                type(timings.get(field)) not in (int, float)
                or not math.isfinite(float(timings[field]))
                or float(timings[field]) < 0
            )
        }
        if invalid_timings:
            raise RuntimeError(
                f"query {trial}: tempi mancanti o non validi: {invalid_timings}"
            )
        byte_fields = ("probe_cifrato", "esito_cifrato")
        invalid_bytes = {
            field: byte_counts.get(field)
            for field in byte_fields
            if type(byte_counts.get(field)) is not int or byte_counts[field] <= 0
        }
        if invalid_bytes:
            raise RuntimeError(
                f"query {trial}: dimensioni cifrati non valide: {invalid_bytes}"
            )
        instrumented_sum = (
            timings["embedding"]
            + timings["cifratura"]
            + timings["rete_e_server"]
            + timings["decifratura"]
        )
        probe_identity = f"sintetico_{digiface_folders[index].name}"
        if response.get("atteso") != probe_identity:
            raise RuntimeError(
                "il client ha caricato un'identita' diversa dal caso richiesto: "
                f"{response.get('atteso')!r} != {probe_identity!r}"
            )
        result_correct = response.get("esito") == expected_result
        identity_correct = (
            response.get("identita") == probe_identity
            if expected_result == "aperto"
            else response.get("identita") is None
        )
        rows.append(
            {
                "trial": trial,
                "indice_sintetico": index,
                "atteso": expected_result,
                "esito": response.get("esito"),
                "identita_attesa": (
                    probe_identity if expected_result == "aperto" else None
                ),
                "identita_restituita": response.get("identita"),
                "esito_corretto": result_correct,
                "identita_corretta": identity_correct,
                "corretto": result_correct and identity_correct,
                "protocollo_http_osservato": observed_protocol,
                "embedding_ms": timings["embedding"],
                "cifratura_ms": timings["cifratura"],
                "server_ms": timings["server"],
                "rete_e_server_ms": timings["rete_e_server"],
                "decifratura_ms": timings["decifratura"],
                "somma_tappe_strumentate_ms": round(instrumented_sum, 3),
                "endpoint_interno_ms": timings["endpoint"],
                "endpoint_http_ms": round(endpoint_http_ms, 3),
                "probe_cifrato_b": byte_counts["probe_cifrato"],
                "esito_cifrato_b": byte_counts["esito_cifrato"],
                "pbs": observed_pbs,
            }
        )

    stato_dopo = richiesta(args.base_url, "/api/stato")
    state_after = stable_state_snapshot(stato_dopo, args.expect_n)
    if state_after != state_before:
        raise RuntimeError("lo stato canonico client/server e' cambiato durante le query")

    docker_after = None
    if docker_mode:
        if docker_dataset_expected is None:
            raise RuntimeError("manifest DigiFace Docker perso durante il benchmark")
        docker_after = docker_provenance(
            args.docker_compose_file,
            args.docker_project,
            args.base_url,
            str(config["modello"]),
            docker_dataset_expected,
        )
        if docker_after != docker_before:
            raise RuntimeError("container, immagini o runtime sono cambiati durante le query")
    else:
        if model_file is not None and sha256_file(model_file) != model_hash_before:
            raise RuntimeError("il modello ONNX host e' cambiato durante le query")
        if host_runtime_packages() != runtime_packages:
            raise RuntimeError("i pacchetti runtime host sono cambiati durante le query")

    host_hashes_after = host_input_hashes()
    if host_hashes_after != host_hashes_before:
        raise RuntimeError("uno o piu' input sorgente sono cambiati durante le query")
    input_provenance_after = dataset_provenance(
        config, cases, args.require_calibration_cache
    )
    if input_provenance_after != input_provenance:
        raise RuntimeError("gli input DigiFace sono cambiati durante le query")
    process_after = server_process(args.server_pid, args.server_binary)
    if process_after != process_before:
        raise RuntimeError("il processo server host e' cambiato durante le query")
    if args.server_binary and sha256_file(args.server_binary) != server_binary_hash_before:
        raise RuntimeError("il binario server host e' cambiato durante le query")

    server_times = [float(row["server_ms"]) for row in rows]
    instrumented_times = [
        float(row["somma_tappe_strumentate_ms"]) for row in rows
    ]
    endpoint_times = [float(row["endpoint_http_ms"]) for row in rows]
    summary: dict[str, object] = {
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "argv": sys.argv,
        "base_url": args.base_url,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "load_average_prima": load_prima,
        "load_average_dopo": list(os.getloadavg()),
        "expected": {
            "n": args.expect_n,
            "pbs_per_query": args.expect_pbs,
            "http_contract": EXACT_SERVER_CONTRACT,
            "decisione": EXACT_DECISION,
            "comparatore": EXACT_COMPARATOR,
        },
        "preload": preload,
        "n_galleria": n_galleria,
        "iscritti_effettivi": state_after["server"]["iscritti"],
        "primo_impostore_test": primo_impostore_test,
        "stato_stabile_durante_query": True,
        "stato_prima_e_dopo": state_before,
        "provenienza": {
            "host_input_sha256": host_hashes_before,
            "host_inputs_stable_during_run": True,
            "config_snapshot": config,
            "contratto_esatto": state_after["contract"],
            "server_binary": (
                str(args.server_binary.resolve()) if args.server_binary else None
            ),
            "server_binary_sha256": server_binary_hash_before,
            "server_process": process_before,
            "runtime_model": runtime_model,
            "runtime_packages": runtime_packages,
            "dataset": input_provenance,
            "dataset_stable_during_run": True,
            "docker_required": args.require_docker_provenance,
            "docker_preload": docker_preload,
            "docker": docker_before,
            "docker_static_binding_stable_during_preload": (
                True if docker_mode else None
            ),
            "docker_stable_during_run": True if docker_mode else None,
        },
        "positivi_corretti": sum(
            row["corretto"] is True for row in rows[: args.positivi]
        ),
        "positivi_totali": args.positivi,
        "negativi_corretti": sum(
            row["corretto"] is True for row in rows[args.positivi :]
        ),
        "negativi_totali": args.negativi,
        "server_ms": distribuzione(server_times),
        "somma_tappe_strumentate_ms": distribuzione(instrumented_times),
        "endpoint_http_ms": distribuzione(endpoint_times),
        "probe_cifrato_b": sorted({row["probe_cifrato_b"] for row in rows}),
        "esito_cifrato_b": sorted({row["esito_cifrato_b"] for row in rows}),
        "pbs": sorted({row["pbs"] for row in rows}),
        "protocolli_http_osservati": sorted(
            {str(row["protocollo_http_osservato"]) for row in rows}
        ),
        "identita_restituite": sorted(
            {
                str(row["identita_restituita"])
                for row in rows
                if row["identita_restituita"] is not None
            }
        ),
    }
    return write_results(args.output, rows, summary)


if __name__ == "__main__":
    raise SystemExit(main())
