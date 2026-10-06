"""Fail-closed driver for the frozen A33 Docker end-to-end gate.

This wrapper loads the benchmark copy stored in the A33 snapshot, redirects every Rust build
input to that snapshot, and extends its Docker provenance checks to this dedicated context.
`--verify-only` performs no Docker, key-generation, or FHE work.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import re
import sys
from types import ModuleType


ROOT = pathlib.Path(__file__).resolve().parents[2]
GATE_ROOT = ROOT / "tmp" / "a33-docker-gate-2026-09-02"
SNAPSHOT_ROOT = ROOT / "tmp" / "a33-aligned-sparse-2026-09-02"
FROZEN_RUST_ROOT = SNAPSHOT_ROOT / "source" / "experiments" / "14_pipeline_tfhe_rs"
FROZEN_DRIVER = SNAPSHOT_ROOT / "source" / "benchmark" / "demo_e2e.py"
PIN_MANIFEST = GATE_ROOT / "frozen-inputs.sha256"
COMPOSE_FILE = GATE_ROOT / "docker-compose.e2e.yml"
SERVER_DOCKERFILE = GATE_ROOT / "Dockerfile.server"
CLIENT_DOCKERFILE = GATE_ROOT / "Dockerfile.client"
PROJECT = "thesis-a33-frozen"
BASE_URL = "http://127.0.0.1:18080"
EXPECTED_N = "127"
EXPECTED_PBS = "4273"
CORE_FILES = (
    "__init__.py",
    "client.py",
    "dataset.py",
    "matching.py",
    "metriche.py",
    "quantize.py",
    "server.py",
)

COMMON_BUILD_INPUTS = {
    "Cargo.toml": FROZEN_RUST_ROOT / "Cargo.toml",
    "Cargo.lock": FROZEN_RUST_ROOT / "Cargo.lock",
    "src/bin/varco_demo.rs": FROZEN_RUST_ROOT / "src" / "bin" / "varco_demo.rs",
    "src/bin/a33_full_validation.rs": (
        FROZEN_RUST_ROOT / "src" / "bin" / "a33_full_validation.rs"
    ),
    "src/bin/a33_sparse_residual_trace.rs": (
        FROZEN_RUST_ROOT / "src" / "bin" / "a33_sparse_residual_trace.rs"
    ),
    "src/lib.rs": FROZEN_RUST_ROOT / "src" / "lib.rs",
    "src/private_argmin.rs": FROZEN_RUST_ROOT / "src" / "private_argmin.rs",
    "gate/docker-compose.e2e.yml": COMPOSE_FILE,
    "gate/run_gate.py": pathlib.Path(__file__).resolve(),
    "gate/frozen-inputs.sha256": PIN_MANIFEST,
    "gate/frozen_demo_e2e.py": FROZEN_DRIVER,
    "snapshot/README.md": SNAPSHOT_ROOT / "README.md",
    "snapshot/inputs-before.sha256": SNAPSHOT_ROOT / "inputs-before.sha256",
    "snapshot/binaries.sha256": SNAPSHOT_ROOT / "binaries.sha256",
}

CLIENT_RUNTIME_INPUTS = {
    "demo/client/app.py": ROOT / "demo" / "client" / "app.py",
    "demo/config.json": SNAPSHOT_ROOT / "source" / "demo" / "config.json",
    "experiments/08_cnn/embedding.py": (
        ROOT / "experiments" / "08_cnn" / "embedding.py"
    ),
    "demo/client/static/index.html": ROOT / "demo" / "client" / "static" / "index.html",
    **{f"core/{name}": ROOT / "core" / name for name in CORE_FILES},
}

SERVICE_BUILD_INPUTS = {
    "server": {
        **COMMON_BUILD_INPUTS,
        "gate/Dockerfile.server": SERVER_DOCKERFILE,
    },
    "client": {
        **COMMON_BUILD_INPUTS,
        "gate/Dockerfile.client": CLIENT_DOCKERFILE,
        **CLIENT_RUNTIME_INPUTS,
    },
}

CLIENT_RUNTIME_FILES = {
    "/app/demo/client/app.py": "demo/client/app.py",
    "/app/demo/config.json": "demo/config.json",
    "/app/experiments/08_cnn/embedding.py": "experiments/08_cnn/embedding.py",
    "/app/demo/client/static/index.html": "demo/client/static/index.html",
    **{f"/app/core/{name}": f"core/{name}" for name in CORE_FILES},
}


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def pinned_input_hashes() -> dict[str, str]:
    if not PIN_MANIFEST.is_file():
        raise FileNotFoundError(f"manifest frozen mancante: {PIN_MANIFEST}")
    records: dict[str, str] = {}
    for number, line in enumerate(PIN_MANIFEST.read_text().splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\0]+)", line)
        if match is None:
            raise RuntimeError(f"riga manifest {number} non valida")
        expected, relative = match.groups()
        candidate = pathlib.PurePosixPath(relative)
        if candidate.is_absolute() or ".." in candidate.parts or relative in records:
            raise RuntimeError(f"path manifest non sicuro o duplicato: {relative!r}")
        path = ROOT.joinpath(*candidate.parts).resolve()
        try:
            path.relative_to(ROOT)
        except ValueError as exc:
            raise RuntimeError(f"path manifest fuori repository: {relative!r}") from exc
        if not path.is_file():
            raise FileNotFoundError(f"input frozen mancante: {relative}")
        actual = sha256_file(path)
        if actual != expected:
            raise RuntimeError(
                f"input frozen mutato: {relative}: expected={expected}, actual={actual}"
            )
        records[relative] = actual
    if not records:
        raise RuntimeError("manifest frozen vuoto")
    return records


def repository_relative(path: pathlib.Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def dockerfile_manifest_paths(path: pathlib.Path) -> set[str]:
    lines = path.read_text().splitlines()
    try:
        start = next(
            index for index, line in enumerate(lines) if line == "RUN sha256sum \\"
        )
        end = next(
            index
            for index in range(start + 1, len(lines))
            if lines[index].strip() == "> /src/build-provenance.sha256"
        )
    except StopIteration as exc:
        raise RuntimeError(f"blocco sha256sum mancante in {path}") from exc
    result = {
        line.strip().removesuffix(" \\")
        for line in lines[start + 1 : end]
        if line.strip()
    }
    if not result or any(" " in item for item in result):
        raise RuntimeError(f"blocco sha256sum ambiguo in {path}")
    return result


def validate_static_layout(pinned: dict[str, str]) -> None:
    for service, dockerfile in (
        ("server", SERVER_DOCKERFILE),
        ("client", CLIENT_DOCKERFILE),
    ):
        expected = set(SERVICE_BUILD_INPUTS[service]) | {"target/release/varco_demo"}
        observed = dockerfile_manifest_paths(dockerfile)
        if observed != expected:
            raise RuntimeError(
                f"manifest immagine {service} non coincide con la mappa probatoria: "
                f"missing={sorted(expected - observed)}, extra={sorted(observed - expected)}"
            )
        dockerfile_text = dockerfile.read_text()
        if "COPY experiments/14_pipeline_tfhe_rs" in dockerfile_text:
            raise RuntimeError(f"{service} tenta di compilare il crate live")
        if (
            "COPY tmp/a33-aligned-sparse-2026-09-02/source/experiments"
            not in dockerfile_text
        ):
            raise RuntimeError(f"{service} non copia il crate A33 frozen")
        for forbidden in (
            "COPY demo/chiavi",
            "COPY datasets",
            "COPY .insightface",
            "/src ./src",
            "COPY core ./core",
            "COPY core /app/core",
        ):
            if forbidden in dockerfile_text:
                raise RuntimeError(f"COPY vietato in {service}: {forbidden}")

    if not set(CLIENT_RUNTIME_FILES.values()).issubset(SERVICE_BUILD_INPUTS["client"]):
        raise RuntimeError(
            "un file runtime client non e' incluso nel manifest immagine"
        )
    pinned_required = {
        repository_relative(path)
        for inputs in SERVICE_BUILD_INPUTS.values()
        for path in inputs.values()
        if path.resolve() != PIN_MANIFEST.resolve()
    }
    pinned_required.update(
        {
            ".dockerignore",
            "demo/config.env",
            "benchmark/patches/a33_aligned_sparse_source_2026-09-02.patch",
        }
    )
    missing_pins = pinned_required - set(pinned)
    if missing_pins:
        raise RuntimeError(
            f"input del gate non fissati nel manifest: {sorted(missing_pins)}"
        )


def load_frozen_driver() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_a33_frozen_demo_e2e", FROZEN_DRIVER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"impossibile caricare il driver frozen: {FROZEN_DRIVER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def option_value(arguments: list[str], name: str) -> str | None:
    prefix = name + "="
    inline = [
        argument[len(prefix) :] for argument in arguments if argument.startswith(prefix)
    ]
    split = [
        arguments[index + 1]
        for index, argument in enumerate(arguments[:-1])
        if argument == name
    ]
    values = inline + split
    if len(values) != 1:
        return None
    return values[0]


def validate_gate_arguments(arguments: list[str]) -> None:
    model_cache = os.environ.get("A33_MODEL_CACHE")
    if not model_cache or not pathlib.Path(model_cache).expanduser().is_dir():
        raise RuntimeError(
            "A33_MODEL_CACHE deve indicare una directory modello esistente"
        )
    required_flags = {
        "--preload",
        "--require-docker-provenance",
        "--require-calibration-cache",
    }
    missing = sorted(flag for flag in required_flags if flag not in arguments)
    if missing:
        raise RuntimeError(f"flag probatorie mancanti: {missing}")
    expected_values = {
        "--base-url": BASE_URL,
        "--docker-project": PROJECT,
        "--expect-n": EXPECTED_N,
        "--expect-pbs": EXPECTED_PBS,
        "--positivi": "3",
        "--negativi": "3",
    }
    for option, expected in expected_values.items():
        observed = option_value(arguments, option)
        if observed != expected:
            raise RuntimeError(
                f"{option} deve valere {expected!r}, ricevuto {observed!r}"
            )
    compose = option_value(arguments, "--docker-compose-file")
    if compose is None or pathlib.Path(compose).resolve() != COMPOSE_FILE:
        raise RuntimeError(f"--docker-compose-file deve risolvere a {COMPOSE_FILE}")


def configure_driver(module: ModuleType) -> None:
    module.ROOT = ROOT
    module.RUST_ROOT = FROZEN_RUST_ROOT
    module.COMMON_BUILD_INPUTS = dict(COMMON_BUILD_INPUTS)
    module.SERVICE_BUILD_INPUTS = {
        service: dict(paths) for service, paths in SERVICE_BUILD_INPUTS.items()
    }
    module.CLIENT_RUNTIME_FILES = dict(CLIENT_RUNTIME_FILES)

    original_docker_provenance = module.docker_provenance

    def frozen_host_input_hashes() -> dict[str, str]:
        records = pinned_input_hashes()
        records["tmp/a33-docker-gate-2026-09-02/frozen-inputs.sha256"] = sha256_file(
            PIN_MANIFEST
        )
        return records

    def frozen_docker_provenance(*args: object, **kwargs: object) -> dict[str, object]:
        result = original_docker_provenance(*args, **kwargs)
        result["context_file_sha256"] = {
            "compose": sha256_file(COMPOSE_FILE),
            "server_dockerfile": sha256_file(SERVER_DOCKERFILE),
            "client_dockerfile": sha256_file(CLIENT_DOCKERFILE),
            "dockerignore": sha256_file(ROOT / ".dockerignore"),
            "frozen_input_manifest": sha256_file(PIN_MANIFEST),
            "frozen_benchmark_driver": sha256_file(FROZEN_DRIVER),
        }
        result["frozen_snapshot"] = {
            "path": str(SNAPSHOT_ROOT),
            "input_manifest_sha256": sha256_file(
                SNAPSHOT_ROOT / "inputs-before.sha256"
            ),
            "binary_manifest_sha256": sha256_file(SNAPSHOT_ROOT / "binaries.sha256"),
            "pin_manifest_sha256": sha256_file(PIN_MANIFEST),
        }
        return result

    module.host_input_hashes = frozen_host_input_hashes
    module.docker_provenance = frozen_docker_provenance


def verify_only() -> int:
    records = pinned_input_hashes()
    validate_static_layout(records)
    payload = {
        "status": "ok",
        "mode": "static_only",
        "snapshot": str(SNAPSHOT_ROOT.relative_to(ROOT)),
        "pinned_files": len(records),
        "pin_manifest_sha256": sha256_file(PIN_MANIFEST),
        "docker_or_fhe_started": False,
    }
    print(json.dumps(payload, sort_keys=True))
    return 0


def main() -> int:
    if sys.argv[1:] == ["--verify-only"]:
        return verify_only()
    pinned = pinned_input_hashes()
    validate_static_layout(pinned)
    validate_gate_arguments(sys.argv[1:])
    driver = load_frozen_driver()
    configure_driver(driver)
    return int(driver.main())


if __name__ == "__main__":
    raise SystemExit(main())
