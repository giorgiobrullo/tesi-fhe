"""Public example portraits, prepared once and copied into each visitor's session."""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from demo.dual_view.enrollment import image_from_bytes
from demo.dual_view.gallery import validate_entries

GALLERY = Path(__file__).resolve().parent / "gallery"


@dataclass
class DefaultGallery:
    entries: list[dict] = field(default_factory=list)
    photos: dict[str, bytes] = field(default_factory=dict)
    metadata: dict[str, dict] = field(default_factory=dict)


def prepare_gallery(enroller, directory: Path = GALLERY) -> DefaultGallery:
    """Use the same enrollment pipeline as uploads; never persist model vectors."""
    result = DefaultGallery()
    vectors = set()
    catalogue = json.loads((directory / "catalogue.json").read_text())
    if not isinstance(catalogue, list) or not 1 <= len(catalogue) <= 128:
        raise ValueError("La galleria iniziale deve contenere da 1 a 128 persone.")
    for person in catalogue:
        photo_path = (directory / person["foto"]).resolve()
        if not photo_path.is_relative_to(directory.resolve()):
            raise ValueError("Foto della galleria fuori dalla directory prevista.")
        photo = photo_path.read_bytes()
        if hashlib.sha256(photo).hexdigest() != person["sha256"]:
            raise ValueError(f"Foto della galleria modificata: {person['nome']}.")
        try:
            vector, _ = enroller([np.asarray(image_from_bytes(photo, "JPEG"))])
        except ValueError as exc:
            raise ValueError(f"Foto di {person['nome']}: {exc}") from exc
        # Each example is also offered as a probe, whose norm has a tighter bound.
        if sum(value * value for value in vector) > 1024:
            raise ValueError(f"Il volto di {person['nome']} supera il dominio della verifica.")
        if tuple(vector) in vectors:
            raise ValueError("Due esempi della galleria hanno lo stesso template.")
        vectors.add(tuple(vector))
        identifier = str(uuid.uuid5(uuid.NAMESPACE_URL, "varco:gallery:" + person["slug"]))
        result.entries.append({"id": identifier, "nome": person["nome"],
                               "soglia": person["soglia"], "vettore": vector,
                               "foto_file": identifier + ".jpg", "origine": "registrato"})
        # Keep the source photo so 'use for a test' submits the enrollment image,
        # rather than detecting and aligning an already aligned face again.
        result.photos[identifier] = photo
        result.metadata[identifier] = {"esempio": True, "nota": person["nota"],
                                       "crediti": person["crediti"]}
    result.entries = validate_entries(result.entries)
    return result
