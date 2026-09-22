# /// script
# requires-python = ">=3.12"
# dependencies = ["matplotlib==3.10.9"]
# ///
"""Rigenera entrambe le figure del 20 settembre dai dati pubblici, senza FHE."""

import argparse
import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path

if __package__:
    from . import figure_current_ckks as ckks
    from . import figure_current_progression as progression
else:
    import figure_current_ckks as ckks
    import figure_current_progression as progression

ROOT = Path(__file__).resolve().parents[1]
INPUT_SHA256 = {
    "output/figures/progressione-fhe/selettori-corretti-20260920/misure.csv": "562e95792bf33438eba1a3985f830b4239edea1ce39bc6825654c7a60ba31227",
    "output/figures/progressione-fhe/selettori-corretti-20260920/punti.csv": "5d2d2fc3000b74f8b25d0e4db2c43d087fa9ff2f4627e592a3937d0be64355ff",
    "output/figures/progressione-fhe/selettori-corretti-20260920/dati.json": "6382dcadf0f984f9bb3c15930b377e069965815896bd46a9b380e0dc8f09d2ef",
    "output/figures/progressione-fhe/benchmark-comune-20260909/osservazioni-prototipi.csv": "e2060aae5b043b08b95dff9ab3d95f087f6d116dba250505502fd139f4ebe4df",
    "output/figures/ckks-tfhe/selettore-corretto-20260920/samples.csv": "ac110c9ea969f1f16c47ae705865878e598ab08e90abc1118202de419b9013f9",
    "output/figures/ckks-tfhe/selettore-corretto-20260920/blocks.csv": "c0b44f2c2c764e562c2859938578a309e36cfd653da4aff173d8a021f2f4ef9d",
    "output/figures/ckks-tfhe/selettore-corretto-20260920/SOURCE_PINS.json": "e2e3e6e0578d2093498657a017c9bc2d57e3af5de48cf65daeab8376d78e9f54",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_sources(root: Path) -> None:
    for name, expected in INPUT_SHA256.items():
        if digest(root / name) != expected:
            raise ValueError(f"Impronta dei dati non corrispondente: {name}")


def generate(root: Path, output: Path) -> dict:
    root, output = root.resolve(), output.resolve()
    if output.exists():
        raise ValueError(f"La cartella esiste già; scegliere una destinazione nuova: {output}")
    if output.is_relative_to(root / "output/figures"):
        raise ValueError("Usare una destinazione esterna a output/figures, che contiene le figure originali")
    verify_sources(root)
    data = {"progressione": progression.prepare_data(root), "ckks_tfhe": ckks.prepare_data(root)}
    used_sources = set(data["progressione"]["source_files"]) | set(data["ckks_tfhe"]["source_files"])
    if used_sources != set(INPUT_SHA256):
        raise ValueError("Elenco delle fonti diverso dalle impronte verificate")

    import matplotlib
    if matplotlib.__version__ != "3.10.9":
        raise ValueError("Usare matplotlib 3.10.9 oppure il comando uv run --script documentato")
    output.mkdir(parents=True, exist_ok=False)
    paths = progression.render(data["progressione"], output) + ckks.render(data["ckks_tfhe"], output)
    statistics = output / "statistiche.json"
    statistics.write_text(json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    paths.append(statistics)
    verify_sources(root)
    receipt = {
        "schema": "public-current-figures-render.v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "new_benchmark": False,
        "cryptographic_revalidation": False,
        "scope": "Rigenerazione dai dati pubblici. Gli hash degli audit privati sono riferimenti storici, non dipendenze lette o audit rieseguiti.",
        "environment": {"python": platform.python_version(), "matplotlib": matplotlib.__version__},
        "inputs": INPUT_SHA256,
        "generators": {name: digest(Path(__file__).with_name(name))
                       for name in ("figure_current.py", "figure_current_progression.py", "figure_current_ckks.py")},
        "outputs": {path.name: digest(path) for path in sorted(paths)},
    }
    (output / "RENDER.json").write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return {"output": str(output), "figures": 2, "new_benchmark": False,
            "statistics": str(statistics), "receipt": str(output / "RENDER.json")}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / ".local/grafici-20260920",
                        help="Cartella nuova per PNG, SVG, PDF, statistiche e ricevuta")
    options = parser.parse_args()
    try:
        result = generate(ROOT, options.output)
    except (OSError, ValueError, KeyError) as error:
        parser.error(str(error))
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
