"""Check or refresh source bindings, or copy a new local runtime variant."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
MODES = ("public_parallel",)
GENERATED = {
    "config.json", "CIRCUIT_CONTRACT.json", "circuit.sha256", "service-source.sha256",
    "core-source.sha256", "SOURCE_DIGEST.txt", "CORE_ORIGINS.json", "runtime-mode.txt",
    "variant-id.txt", "SOURCE_PINS.json", "BUILD_SELECTION.json",
}
NON_SOURCE = {"__pycache__", ".local", "target", "target-service", "keys", "runs", "actions"}


def encoded(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_leaves(leaves: dict[str, str]) -> str:
    return sha(json.dumps(leaves, sort_keys=True, separators=(",", ":")).encode())


def read_sources(root: Path) -> dict[str, bytes]:
    sources = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if path.is_symlink():
            raise ValueError(f"source symlink is not supported: {relative}")
        if not path.is_file():
            continue
        if any(part in NON_SOURCE or part.startswith("target-") for part in relative.parts):
            raise ValueError(f"keep generated artifacts outside runtime/: {relative}")
        if path.suffix in {".key", ".pyc", ".bin"} or path.stat().st_size > 1_000_000:
            raise ValueError(f"unexpected non-source input: {relative}")
        if relative.as_posix() not in GENERATED:
            sources[relative.as_posix()] = path.read_bytes()
    return sources


def build_files(mode: str, root: Path = ROOT) -> dict[str, bytes]:
    """Compute bindings from current leaves, without writing or compiling."""
    if mode not in MODES:
        raise ValueError(f"unsupported runtime mode: {mode}")
    sources = read_sources(root)
    baseline = json.loads(sources["BASELINE_ORIGINS.json"])
    core_leaves = {name: sha(data) for name, data in sources.items() if name.startswith("core/")}
    core_digest = digest_leaves(core_leaves)
    sources["BUILD_SELECTION.json"] = encoded({
        "mode": mode, "wire_version": 9, "fixed_threads": 16,
        "core_source_sha256": core_digest,
    })
    source_leaves = {name: sha(data) for name, data in sources.items()}
    source_digest = digest_leaves(source_leaves)
    variant = f"head-selector-refresh4-12-w127-pack4-b22-mean2-tfhe17-base15-p16-{mode}-v9"
    circuit = json.loads(sources["circuit.template.json"])
    circuit.update(
        schema="maintained-composite-service-circuit.v1",
        http_contract="exact-open-set-id-v9-composite-tfhe17-base15-three-lwe",
        variant_id=variant, wire_version=9, core_source_sha256=core_digest,
        service_source_sha256=source_digest, runtime_mode=mode,
        g4_required=mode == "public_parallel_g4",
        g4_key_binding="v9 sidecar bound to base server envelope SHA256",
        source_digest_scope="non-generated source leaves and BUILD_SELECTION.json; generated bindings closed by SOURCE_PINS.json",
    )
    circuit["magics"]["g4_key"] = "VRCG4V9!"
    circuit["g4_sidecar"] = {
        "catalog": "V1_7_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128",
        "small_lwe_dimension": 904, "glwe_dimension": 1, "polynomial_size": 2048,
        "grouping_factor": 4, "ksk_container_bytes": 59310080,
        "fourier_container_bytes": 236978176,
    }
    circuit["http_limits_bytes"]["g4_key"] = 288 * 1024 * 1024
    circuit_bytes = encoded(circuit)
    circuit_digest = sha(circuit_bytes)
    config = json.loads(sources["config.template.json"])
    config["contratto_esatto"].update(
        http_contract=circuit["http_contract"], variant_id=variant, wire_version=9,
        circuit_sha256=circuit_digest, runtime_mode=mode,
        g4_required=circuit["g4_required"], g4_key_body_limit_bytes=288 * 1024 * 1024,
        service_source_sha256=source_digest, core_source_sha256=core_digest,
    )
    generated = {
        "runtime-mode.txt": mode.encode(), "variant-id.txt": variant.encode(),
        "service-source.sha256": source_digest.encode(),
        "core-source.sha256": core_digest.encode(), "SOURCE_DIGEST.txt": core_digest.encode(),
        "CIRCUIT_CONTRACT.json": circuit_bytes, "circuit.sha256": circuit_digest.encode(),
        "config.json": encoded(config),
        "CORE_ORIGINS.json": encoded({
            "schema": "maintained-core-origins.v1",
            "baseline_core_source_sha256": baseline["runtime_source_sha256"],
            "runtime_source_sha256": core_digest, "current_core_leaves": core_leaves,
        }),
    }
    files = {**sources, **generated}
    files["SOURCE_PINS.json"] = encoded({
        "schema": "maintained-service-source.v1", "service_source_sha256": source_digest,
        "mode": mode, "core_source_sha256": core_digest, "circuit_sha256": circuit_digest,
        "source_leaves": source_leaves,
        "all_leaves": {name: sha(data) for name, data in files.items()},
        "compiled": False, "executed": False,
    })
    return files


def create(mode: str, destination: Path) -> dict[str, str]:
    destination = destination.resolve()
    if (destination.exists() or destination.is_relative_to(ROOT)
            or not destination.is_relative_to(ROOT.parent)):
        raise ValueError("use a new directory inside the repository, outside runtime/")
    files = build_files(mode, ROOT)
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return {
        "destination": str(destination), "mode": mode,
        "source_sha256": files["service-source.sha256"].decode(),
        "circuit_sha256": files["circuit.sha256"].decode(),
        "manifest_sha256": sha(files["SOURCE_PINS.json"]),
    }


def refresh(mode: str, root: Path = ROOT) -> None:
    files = build_files(mode, root)
    for name in sorted(GENERATED - {"SOURCE_PINS.json"}):
        (root / name).write_bytes(files[name])
    (root / "SOURCE_PINS.json").write_bytes(files["SOURCE_PINS.json"])


def check(mode: str, root: Path = ROOT) -> None:
    files = build_files(mode, root)
    stale = [name for name in sorted(GENERATED)
             if not (root / name).is_file() or (root / name).read_bytes() != files[name]]
    if stale:
        raise ValueError("stale source bindings; run --refresh: " + ", ".join(stale))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", default="public_parallel", choices=MODES)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--destination", type=Path)
    action.add_argument("--refresh", action="store_true")
    action.add_argument("--check", action="store_true")
    options = parser.parse_args()
    try:
        if options.refresh:
            refresh(options.mode)
            print("Source bindings refreshed; older service envelopes have different circuit identities.")
        elif options.check:
            check(options.mode)
            print("Source, circuit and client bindings match.")
        else:
            print(json.dumps(create(options.mode, options.destination), indent=2))
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
