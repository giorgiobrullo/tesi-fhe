"""Initialize a new local gallery from the qualified public synthetic fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import uuid

from .gallery import GalleryStore, validate_entries


FIXTURE_SHA256 = "fd4d90eff7612c0b04a1c6fd77c46830f1fb1adef7ede1dae091987749dc10d6"
HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[1]


def prepare(fixtures: Path, photos: Path) -> tuple[list[dict], list[Path], dict]:
    raw = fixtures.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != FIXTURE_SHA256:
        raise ValueError("Le fixture non corrispondono ai template sintetici qualificati.")
    source = json.loads(raw)
    # Only these public fields are imported. Other fields in the source are not used.
    names = source["synthetic_names"]
    templates = source["synthetic_templates"]
    if len(names) != 127 or len(templates) != 127 or len(set(names)) != 127:
        raise ValueError("Le fixture devono contenere i 127 soggetti sintetici previsti.")
    entries = []
    photo_paths = []
    photo_pins = {}
    for name, vector in zip(names, templates, strict=True):
        folder = name.removeprefix("sintetico_")
        if not name.startswith("sintetico_") or not folder.isdecimal():
            raise ValueError("Nome del soggetto sintetico non valido.")
        choices = sorted((photos / folder).glob("*.png"))
        if not choices:
            raise ValueError(f"Manca la foto del soggetto sintetico {folder}.")
        photo = choices[0]
        if not 0 < photo.stat().st_size <= 4 * 1024 * 1024:
            raise ValueError("La foto sintetica supera il limite previsto.")
        identifier = str(uuid.uuid5(uuid.NAMESPACE_URL, "varco-dual-view/" + name))
        entries.append({
            "id": identifier, "nome": "Sintetico " + folder, "soglia": 4,
            "vettore": vector, "foto_file": identifier + ".png", "origine": "sintetico",
        })
        photo_paths.append(photo)
        photo_pins[str(photo.resolve())] = hashlib.sha256(photo.read_bytes()).hexdigest()
    return validate_entries(entries), photo_paths, {
        "fixture_sha256": digest, "imported_fields": ["synthetic_names", "synthetic_templates"],
        "count": 127, "photos": photo_pins,
    }


def seed(state_dir: Path, fixtures: Path, photos: Path) -> dict:
    if state_dir.exists():
        raise ValueError("La cartella di stato esiste già; la galleria non è stata modificata.")
    entries, photo_paths, receipt = prepare(fixtures, photos)
    state_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    store = GalleryStore(state_dir)
    store.photos.mkdir(mode=0o700)
    for entry, photo in zip(entries, photo_paths, strict=True):
        destination = store.photos / entry["foto_file"]
        with destination.open("xb") as stream, photo.open("rb") as source:
            os.chmod(destination, 0o600)
            shutil.copyfileobj(source, stream)
    store.replace(entries)
    receipt["gallery_sha256"] = hashlib.sha256(store.gallery_path.read_bytes()).hexdigest()
    with (state_dir / "seed-receipt.json").open("x") as stream:
        os.chmod(stream.name, 0o600)
        json.dump(receipt, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return {"iscritti": len(entries), "gallery_sha256": receipt["gallery_sha256"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=HERE / ".local/server")
    parser.add_argument("--fixtures", type=Path, default=REPOSITORY /
                        "tmp/e2e-camera-fast-mixed-20260906/runs/camera-first/clear-model-vectors.json")
    parser.add_argument("--photos", type=Path, default=REPOSITORY / "datasets/digiface/estratto")
    options = parser.parse_args()
    print(json.dumps(seed(options.state_dir.resolve(), options.fixtures.resolve(), options.photos.resolve())))


if __name__ == "__main__":
    main()
