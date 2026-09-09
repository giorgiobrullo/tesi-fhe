"""Bounded enrollment images and the selected detector-only embedding algorithm.

This server-side module never imports the trusted client or accesses FHE keys.
Only enrollment photographs reach it; query photographs stay with the client.
"""

from __future__ import annotations

import base64
import binascii
import importlib.util
import io
import json
import pathlib
import threading
import warnings

import numpy as np
from PIL import Image, UnidentifiedImageError


ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "experiments/22_demo_composita/runtime/config.json"
MAX_IMAGE_BYTES = 4 * 1024 * 1024
MAX_PIXELS = 4_000_000
MAX_SIDE = 4096
MIME_FORMATS = {"image/jpeg": "JPEG", "image/png": "PNG", "image/webp": "WEBP"}


def image_from_bytes(raw: bytes, expected_format: str | None = None) -> Image.Image:
    if not 0 < len(raw) <= MAX_IMAGE_BYTES:
        raise ValueError("Ogni immagine deve occupare al massimo 4 MiB.")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(raw)) as image:
                if image.format not in MIME_FORMATS.values() or (expected_format and image.format != expected_format):
                    raise ValueError("Il formato dell'immagine non corrisponde al contenuto.")
                if getattr(image, "n_frames", 1) != 1:
                    raise ValueError("Scegli un'immagine statica.")
                width, height = image.size
                if width < 1 or height < 1 or max(width, height) > MAX_SIDE or width * height > MAX_PIXELS:
                    raise ValueError("L'immagine è troppo grande: massimo 4 milioni di pixel e lato 4096.")
                image.load()
                return image.convert("RGB")
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError,
            Image.DecompressionBombWarning) as exc:
        raise ValueError("L'immagine non può essere letta.") from exc


def decode_frames(data_urls: object) -> list[np.ndarray]:
    if not isinstance(data_urls, list) or not 1 <= len(data_urls) <= 3:
        raise ValueError("Invia da una a tre immagini.")
    frames = []
    for value in data_urls:
        if not isinstance(value, str) or len(value) > 4 * ((MAX_IMAGE_BYTES + 2) // 3) + 64:
            raise ValueError("Immagine mancante o troppo grande.")
        header, separator, encoded = value.partition(",")
        if not separator or not header.startswith("data:") or not header.endswith(";base64"):
            raise ValueError("Invia immagini JPEG, PNG o WebP.")
        mime = header[5:-7]
        if mime not in MIME_FORMATS:
            raise ValueError("Invia immagini JPEG, PNG o WebP.")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("La codifica dell'immagine non è valida.") from exc
        frames.append(np.asarray(image_from_bytes(raw, MIME_FORMATS[mime])))
    return frames


class EnrollmentProcessor:
    def __init__(self) -> None:
        self.config = json.loads(CONFIG_PATH.read_text())
        self._embedding = None
        self._lock = threading.Lock()

    def _model(self):
        if self._embedding is None:
            models = pathlib.Path.home() / ".insightface/models"
            recognition = list((models / "antelopev2").rglob("glintr100.onnx"))
            detector = models / "buffalo_s/det_500m.onnx"
            if not recognition or not detector.is_file():
                raise RuntimeError("I modelli locali per l'iscrizione non sono disponibili.")
            source = ROOT / "experiments/08_cnn/embedding.py"
            spec = importlib.util.spec_from_file_location("dual_view_enrollment_embedding", source)
            if spec is None or spec.loader is None:
                raise RuntimeError("Il modello locale non può essere caricato.")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.carica(self.config["modello"])
            self._embedding = module
        return self._embedding

    def __call__(self, frames_rgb: list[np.ndarray]) -> tuple[list[int], bytes]:
        """Match selected allinea/embedding_fuso, preserving detection and quantization."""
        with self._lock:
            from insightface.utils import face_align

            embedding = self._model()
            detector = embedding._app("mobilefacenet")
            crops = []
            for image in frames_rgb:
                bgr = image[..., ::-1]
                boxes, landmarks = detector.det_model.detect(bgr, max_num=0, metric="default")
                if len(boxes):
                    index = max(range(len(boxes)), key=lambda i:
                                (boxes[i, 2] - boxes[i, 0]) * (boxes[i, 3] - boxes[i, 1]))
                    crops.append(face_align.norm_crop(bgr, landmarks[index])[..., ::-1])
            if not crops:
                raise ValueError("Nessun volto rilevato: inquadra il viso e riprova.")
            vectors = embedding.embedding(np.array(crops), self.config["modello"])
            vector = vectors.mean(0)
            vector = vector / (np.linalg.norm(vector) + 1e-9)
            quantized = np.clip(np.round(vector / self.config["scala"]),
                                -self.config["q_max"], self.config["q_max"]).astype(int)
            photo = io.BytesIO()
            Image.fromarray(crops[0]).save(photo, format="JPEG", quality=90)
            return quantized.tolist(), photo.getvalue()
