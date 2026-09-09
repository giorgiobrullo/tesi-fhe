"""Create a new immutable source variant; no compiler, models, keys or service calls."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
GENERATED = {"config.json", "CIRCUIT_CONTRACT.json", "circuit.sha256", "service-source.sha256",
             "runtime-mode.txt", "variant-id.txt", "SOURCE_PINS.json", "BUILD_SELECTION.json"}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def create(mode: str, destination: Path):
    destination = destination.resolve()
    if destination.exists() or not destination.is_relative_to(ROOT.parent):
        raise RuntimeError("create a new variant directory beneath this service-audit directory")
    origins = json.loads((ROOT / "CORE_ORIGINS.json").read_text())
    for name, expected in origins["copied_core_leaves"].items():
        if sha((ROOT / name).read_bytes()) != expected:
            raise RuntimeError("frozen core copy changed: " + name)
    sources = {}
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if path.is_symlink() or any(part in {"__pycache__", "target", "target-service", "keys", "runs", "actions"} for part in relative.parts):
            raise RuntimeError("unexpected non-source artifact: " + str(relative))
        if str(relative) in GENERATED:
            continue
        if path.stat().st_size > 1_000_000:
            raise RuntimeError("unexpected large source input: " + str(relative))
        sources[str(relative)] = path.read_bytes()
    selection = {"mode": mode, "wire_version": 9, "fixed_threads": 16,
                 "core_source_sha256": origins["runtime_source_sha256"]}
    sources["BUILD_SELECTION.json"] = encoded(selection)
    source_leaves = {name: sha(data) for name, data in sources.items()}
    source_digest = sha(json.dumps(source_leaves, sort_keys=True, separators=(",", ":")).encode())
    variant = f"head-composite-b22-tfhe17-base15-p16-{mode}-v9"
    circuit = json.loads(sources["circuit.template.json"])
    circuit.update(http_contract="exact-open-set-id-v9-composite-tfhe17-base15-three-lwe",
                   variant_id=variant, wire_version=9, core_source_sha256=selection["core_source_sha256"],
                   service_source_sha256=source_digest, runtime_mode=mode,
                   g4_required=mode == "public_parallel_g4",
                   g4_key_binding="v9 sidecar bound to base server envelope SHA256",
                   source_digest_scope="all non-generated source leaves and BUILD_SELECTION.json; generated contract/config/binding files closed separately")
    circuit["schema"] = "composite-service-circuit.v1"
    circuit["magics"]["g4_key"] = "VRCG4V9!"
    circuit["g4_sidecar"] = {"catalog":"V1_7_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128",
                             "small_lwe_dimension":904,"glwe_dimension":1,"polynomial_size":2048,
                             "grouping_factor":4,"ksk_container_bytes":59310080,"fourier_container_bytes":236978176}
    circuit["http_limits_bytes"]["g4_key"] = 288 * 1024 * 1024
    circuit_bytes = encoded(circuit)
    circuit_digest = sha(circuit_bytes)
    config = json.loads(sources["config.template.json"])
    contract = config["contratto_esatto"]
    contract.update(http_contract=circuit["http_contract"], variant_id=variant, wire_version=9,
                    circuit_sha256=circuit_digest, runtime_mode=mode,
                    g4_required=circuit["g4_required"], g4_key_body_limit_bytes=288 * 1024 * 1024,
                    service_source_sha256=source_digest, core_source_sha256=selection["core_source_sha256"])
    generated = {"runtime-mode.txt": mode.encode(), "variant-id.txt": variant.encode(),
                 "service-source.sha256": source_digest.encode(), "CIRCUIT_CONTRACT.json": circuit_bytes,
                 "circuit.sha256": circuit_digest.encode(), "config.json": encoded(config)}
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in {**sources, **generated}.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    all_leaves = {name: sha(data) for name, data in {**sources, **generated}.items()}
    manifest = {"schema": "composite-service-source.v1", "service_source_sha256": source_digest,
                "mode": mode, "core_source_sha256": selection["core_source_sha256"],
                "circuit_sha256": circuit_digest, "source_leaves": source_leaves,
                "all_leaves": all_leaves, "compiled": False, "executed": False}
    (destination / "SOURCE_PINS.json").write_bytes(encoded(manifest))
    return {"destination": str(destination), "mode": mode, "source_sha256": source_digest,
            "circuit_sha256": circuit_digest, "manifest_sha256": sha(encoded(manifest))}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=("public_parallel", "public_parallel_g4"))
    parser.add_argument("--destination", required=True, type=Path)
    options = parser.parse_args()
    print(json.dumps(create(options.mode, options.destination), indent=2))
