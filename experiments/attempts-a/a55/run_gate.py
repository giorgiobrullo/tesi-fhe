"""Fail-closed driver for the frozen A38 Docker end-to-end gate.

This wrapper loads the benchmark copy stored in the A38 snapshot, redirects every Rust build
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
GATE_ROOT = ROOT / "tmp" / "a55-a38-docker-gate-design"
SNAPSHOT_ROOT = ROOT / "tmp" / "a38-combined-prototype"
FROZEN_RUST_ROOT = SNAPSHOT_ROOT / "source" / "experiments" / "14_pipeline_tfhe_rs"
FROZEN_DRIVER = SNAPSHOT_ROOT / "source" / "benchmark" / "demo_e2e.py"
PIN_MANIFEST = GATE_ROOT / "frozen-inputs.sha256"
IDENTITY_MANIFEST = GATE_ROOT / "a38-identity.json"
COMPOSE_FILE = GATE_ROOT / "docker-compose.e2e.yml"
SERVER_DOCKERFILE = GATE_ROOT / "Dockerfile.server"
CLIENT_DOCKERFILE = GATE_ROOT / "Dockerfile.client"
PROJECT = "thesis-a38-frozen-a55"
BASE_URL = "http://127.0.0.1:18038"
EXPECTED_N = "127"
EXPECTED_PBS = "3655"
EXPECTED_PATH = "a38_combined"
EXPECTED_MODEL = {
    "filename": "glintr100.onnx",
    "bytes": 260665334,
    "sha256": "4ab1d6435d639628a6f3e5008dd4f929edf4c4124b1a7169e1048f9fef534cdf",
}
OUTPUT_ROOT = ROOT / "benchmark" / "results"
OUTPUT_NAME_RE = re.compile(
    r"demo_e2e_exact_id_a38_frozen_2026-09-02(?:T[0-9]{6}Z|_gate[0-9]{2})[.]csv"
)
EXPECTED_CRITICAL_HASHES = {
    "tmp/a38-combined-prototype/source/experiments/14_pipeline_tfhe_rs/Cargo.toml": (
        "290b97cfd9af85685db419b5782d0e9ab073179b6ffe2c97ef9c8a33c4fddfb6"
    ),
    "tmp/a38-combined-prototype/source/experiments/14_pipeline_tfhe_rs/Cargo.lock": (
        "1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a"
    ),
    "tmp/a38-combined-prototype/source/experiments/14_pipeline_tfhe_rs/src/bin/varco_demo.rs": (
        "89eb3df057fd69e2ed3c96df94be9fdbd9e998eafe4401554da93ee168404f44"
    ),
    "tmp/a38-combined-prototype/source/experiments/14_pipeline_tfhe_rs/src/lib.rs": (
        "855288001429bf9148412d984b26acc4df9179b0bfc79f91469a1eb274807532"
    ),
    "tmp/a38-combined-prototype/source/experiments/14_pipeline_tfhe_rs/src/private_argmin.rs": (
        "5230f3863a5cad726aefe51a3c6a786899e4f1cdd47aeb0ff8f7141fcc3917ae"
    ),
    "tmp/a38-combined-prototype/varco_demo": (
        "f4cdc28f92ffae8d34c207a06896299015aca2673fce14a959cc3bea34dc1e02"
    ),
    "tmp/a38-combined-prototype/source/benchmark/demo_e2e.py": (
        "bb687d632e6b5c260b2423edd4bf06823a027ffc55597929a5c1d660d633438c"
    ),
    "tmp/a38-combined-prototype/source/demo/config.json": (
        "eef0f46e153a6c3f23e8fb258a34db663376a391578aff03a79046e4691318dc"
    ),
}
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
    "src/lib.rs": FROZEN_RUST_ROOT / "src" / "lib.rs",
    "src/private_argmin.rs": FROZEN_RUST_ROOT / "src" / "private_argmin.rs",
    "gate/docker-compose.e2e.yml": COMPOSE_FILE,
    "gate/run_gate.py": pathlib.Path(__file__).resolve(),
    "gate/frozen-inputs.sha256": PIN_MANIFEST,
    "gate/a38-identity.json": IDENTITY_MANIFEST,
    "gate/frozen_demo_e2e.py": FROZEN_DRIVER,
    "snapshot/README.md": SNAPSHOT_ROOT / "README.md",
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


def safe_repository_file(relative: str) -> pathlib.Path:
    candidate = pathlib.PurePosixPath(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise RuntimeError(f"path identity non sicuro: {relative!r}")
    path = ROOT.joinpath(*candidate.parts).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise RuntimeError(f"path identity fuori repository: {relative!r}") from exc
    if not path.is_file():
        raise FileNotFoundError(f"input identity mancante: {relative}")
    return path


def load_identity_manifest() -> tuple[dict[str, object], dict[str, str]]:
    if not IDENTITY_MANIFEST.is_file():
        raise FileNotFoundError(f"manifest identita' A38 mancante: {IDENTITY_MANIFEST}")
    try:
        payload = json.loads(IDENTITY_MANIFEST.read_text())
    except json.JSONDecodeError as exc:
        raise RuntimeError("manifest identita' A38 non e' JSON valido") from exc
    expected_contract = {
        "n": 127,
        "pbs_per_query": 3655,
        "path": EXPECTED_PATH,
        "wire": "exact-open-set-id-v2",
        "result": "one LWE: 0=reject; i+1=accepted first exact nearest identity",
    }
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != 1
        or payload.get("candidate") != "A38"
        or payload.get("contract") != expected_contract
        or payload.get("runtime_model") != {"name": "resnet100", **EXPECTED_MODEL}
    ):
        raise RuntimeError("manifest identita' A38 non canonico")

    records: dict[str, str] = {}

    def add_record(relative: object, record: object, label: str) -> None:
        if not isinstance(relative, str) or not isinstance(record, dict):
            raise RuntimeError(f"record identity non valido: {label}")
        expected_hash = record.get("sha256")
        if (
            not isinstance(expected_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None
            or relative in records
        ):
            raise RuntimeError(f"hash identity non valido o duplicato: {label}")
        path = safe_repository_file(relative)
        expected_bytes = record.get("bytes")
        if expected_bytes is not None and (
            type(expected_bytes) is not int
            or expected_bytes <= 0
            or path.stat().st_size != expected_bytes
        ):
            raise RuntimeError(f"dimensione identity incoerente: {label}")
        actual_hash = sha256_file(path)
        if actual_hash != expected_hash:
            raise RuntimeError(
                f"input identity mutato: {relative}: "
                f"expected={expected_hash}, actual={actual_hash}"
            )
        records[relative] = actual_hash

    service_inputs = payload.get("service_build_inputs")
    if not isinstance(service_inputs, dict):
        raise RuntimeError("service_build_inputs assente dal manifest identity")
    for relative, record in service_inputs.items():
        add_record(relative, record, f"service_build_inputs.{relative}")

    frozen_binary = payload.get("frozen_service_binary")
    if not isinstance(frozen_binary, dict):
        raise RuntimeError("frozen_service_binary assente dal manifest identity")
    add_record(
        frozen_binary.get("path"), frozen_binary, "frozen_service_binary"
    )

    for section_name in (
        "component_reference",
        "frozen_gate_inputs",
        "prior_validation_evidence",
    ):
        section = payload.get(section_name)
        if not isinstance(section, dict) or not section:
            raise RuntimeError(f"sezione identity assente o vuota: {section_name}")
        for name, record in section.items():
            if not isinstance(record, dict):
                raise RuntimeError(f"record identity non valido: {section_name}.{name}")
            add_record(record.get("path"), record, f"{section_name}.{name}")

    expected_service_paths = {
        repository_relative(path)
        for name, path in COMMON_BUILD_INPUTS.items()
        if name
        in {
            "Cargo.toml",
            "Cargo.lock",
            "src/bin/varco_demo.rs",
            "src/lib.rs",
            "src/private_argmin.rs",
        }
    }
    if set(service_inputs) != expected_service_paths:
        raise RuntimeError(
            "sorgenti service identity incompleti o inattesi: "
            f"expected={sorted(expected_service_paths)}, "
            f"observed={sorted(service_inputs)}"
        )
    critical_mismatches = {
        relative: {"expected": expected, "observed": records.get(relative)}
        for relative, expected in EXPECTED_CRITICAL_HASHES.items()
        if records.get(relative) != expected
    }
    if critical_mismatches:
        raise RuntimeError(f"identita' A38 critica non coincide: {critical_mismatches}")
    return payload, records


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
    _, identity_records = load_identity_manifest()
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
            "COPY tmp/a38-combined-prototype/source/experiments"
            not in dockerfile_text
        ):
            raise RuntimeError(f"{service} non copia il crate A38 frozen")
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
            repository_relative(IDENTITY_MANIFEST),
            *identity_records,
        }
    )
    missing_pins = pinned_required - set(pinned)
    if missing_pins:
        raise RuntimeError(
            f"input del gate non fissati nel manifest: {sorted(missing_pins)}"
        )
    compose_text = COMPOSE_FILE.read_text()
    for required in (
        "127.0.0.1:18038:8000",
        "${A38_MODEL_CACHE:?A38_MODEL_CACHE required}",
        "../../datasets/digiface/estratto:/app/datasets/digiface/estratto:ro",
        "- chiavi:/app/chiavi",
    ):
        if required not in compose_text:
            raise RuntimeError(f"vincolo Compose A38 mancante: {required}")
    if "ports:" in compose_text.split("client:", 1)[0]:
        raise RuntimeError("il server A38 non deve esporre porte host")


def load_frozen_driver() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_a38_frozen_demo_e2e", FROZEN_DRIVER)
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
    model_cache = os.environ.get("A38_MODEL_CACHE")
    if not model_cache or not pathlib.Path(model_cache).expanduser().is_dir():
        raise RuntimeError(
            "A38_MODEL_CACHE deve indicare una directory modello esistente"
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
    output_value = option_value(arguments, "--output")
    if output_value is None:
        raise RuntimeError("--output deve essere specificato una sola volta")
    output = pathlib.Path(output_value).resolve()
    if output.parent != OUTPUT_ROOT or OUTPUT_NAME_RE.fullmatch(output.name) is None:
        raise RuntimeError(
            "--output deve usare uno stem A38 frozen collision-safe sotto "
            f"{OUTPUT_ROOT}"
        )
    collisions = [path for path in (output, output.with_suffix(".json")) if path.exists()]
    if collisions:
        raise FileExistsError(
            "artifact A38 gia' esistente; usare il successivo suffisso _gateNN: "
            + ", ".join(str(path) for path in collisions)
        )


def configure_driver(module: ModuleType) -> None:
    identity, identity_records = load_identity_manifest()
    if (
        getattr(module, "A38_ALIGNED_PATH", None) != EXPECTED_PATH
        or getattr(module, "EXACT_SERVER_CONTRACT", None) != "exact-open-set-id-v2"
    ):
        raise RuntimeError("il driver frozen non dichiara il contratto/path A38 atteso")
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
        records["tmp/a55-a38-docker-gate-design/frozen-inputs.sha256"] = sha256_file(
            PIN_MANIFEST
        )
        return records

    def frozen_docker_provenance(*args: object, **kwargs: object) -> dict[str, object]:
        result = original_docker_provenance(*args, **kwargs)
        services = result.get("services")
        if not isinstance(services, dict):
            raise RuntimeError("provenance Docker non contiene i due servizi")
        server = services.get("server")
        client = services.get("client")
        if not isinstance(server, dict) or not isinstance(client, dict):
            raise RuntimeError("snapshot Docker server/client incompleto")
        if server.get("live_binary_sha256") != client.get("live_binary_sha256"):
            raise RuntimeError("i binari Linux live di server e client non coincidono")
        if server.get("port_bindings"):
            raise RuntimeError("il server A38 espone inaspettatamente una porta host")
        if server.get("mounts"):
            raise RuntimeError("il server A38 possiede mount inattesi")
        client_mounts = client.get("mounts")
        if not isinstance(client_mounts, list):
            raise RuntimeError("mount client A38 mancanti")
        observed_mounts = {
            mount.get("destination"): mount.get("rw")
            for mount in client_mounts
            if isinstance(mount, dict)
        }
        expected_mounts = {
            "/app/datasets/digiface/estratto": False,
            "/root/.insightface": False,
            "/app/chiavi": True,
        }
        if observed_mounts != expected_mounts:
            raise RuntimeError(
                f"mount client A38 non canonici: {observed_mounts!r}"
            )
        runtime_model = client.get("runtime_model")
        if runtime_model is not None:
            if not isinstance(runtime_model, dict) or any(
                runtime_model.get(field) != expected
                for field, expected in EXPECTED_MODEL.items()
            ):
                raise RuntimeError(
                    f"modello ResNet100 A38 non canonico: {runtime_model!r}"
                )
        result["context_file_sha256"] = {
            "compose": sha256_file(COMPOSE_FILE),
            "server_dockerfile": sha256_file(SERVER_DOCKERFILE),
            "client_dockerfile": sha256_file(CLIENT_DOCKERFILE),
            "dockerignore": sha256_file(ROOT / ".dockerignore"),
            "frozen_input_manifest": sha256_file(PIN_MANIFEST),
            "a38_identity_manifest": sha256_file(IDENTITY_MANIFEST),
            "frozen_benchmark_driver": sha256_file(FROZEN_DRIVER),
        }
        result["frozen_snapshot"] = {
            "candidate": "A38",
            "path": str(SNAPSHOT_ROOT),
            "contract": identity["contract"],
            "identity_manifest_sha256": sha256_file(IDENTITY_MANIFEST),
            "pin_manifest_sha256": sha256_file(PIN_MANIFEST),
            "frozen_service_binary": identity["frozen_service_binary"],
            "identity_file_sha256": identity_records,
        }
        return result

    module.host_input_hashes = frozen_host_input_hashes
    module.docker_provenance = frozen_docker_provenance


def verify_only() -> int:
    records = pinned_input_hashes()
    validate_static_layout(records)
    identity, identity_records = load_identity_manifest()
    payload = {
        "status": "ok",
        "mode": "static_only",
        "snapshot": str(SNAPSHOT_ROOT.relative_to(ROOT)),
        "pinned_files": len(records),
        "pin_manifest_sha256": sha256_file(PIN_MANIFEST),
        "identity_manifest_sha256": sha256_file(IDENTITY_MANIFEST),
        "identity_files": len(identity_records),
        "contract": identity["contract"],
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
