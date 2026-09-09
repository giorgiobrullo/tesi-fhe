"""Persistent public gallery and ciphertext-only request metadata for the demo."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import pathlib
import tempfile
import threading
import uuid
from datetime import datetime, timezone


DIMENSION = 512
MAX_GALLERY = 3374
MAX_EVENTS = 250
MAX_PHOTO_BYTES = 4 * 1024 * 1024
ENTRY_FIELDS = {"id", "nome", "soglia", "vettore", "foto_file", "origine"}


def strict_json(raw: bytes | str) -> object:
    def object_pairs(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Campo JSON duplicato.")
            result[key] = value
        return result

    def invalid_constant(_value: str) -> None:
        raise ValueError("Valore JSON non valido.")

    try:
        return json.loads(raw, object_pairs_hook=object_pairs, parse_constant=invalid_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Il contenuto JSON non è valido.") from exc


def validate_name(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Inserisci un nome valido.")
    name = value.strip()
    if not 1 <= len(name) <= 80 or not all(char.isprintable() for char in name):
        raise ValueError("Il nome deve contenere da 1 a 80 caratteri, senza a capo.")
    return name


def validate_threshold(value: object) -> int:
    if type(value) is not int or not -(1 << 63) <= value < (1 << 63):
        raise ValueError("La soglia deve essere un intero valido.")
    return value


def validate_entries(entries: object) -> list[dict]:
    """Mirror the native enrollment domain before any backend reset is attempted."""
    if not isinstance(entries, list) or len(entries) > MAX_GALLERY:
        raise ValueError(f"La galleria può contenere al massimo {MAX_GALLERY} iscritti.")
    result = []
    seen = set()
    lower = upper = None
    for item in entries:
        if not isinstance(item, dict) or set(item) != ENTRY_FIELDS:
            raise ValueError("La scheda dell'iscritto non è valida.")
        identifier = item["id"]
        try:
            valid_id = str(uuid.UUID(identifier)) == identifier
        except (ValueError, TypeError, AttributeError):
            valid_id = False
        if not valid_id or identifier in seen:
            raise ValueError("Identificatore dell'iscritto non valido o duplicato.")
        seen.add(identifier)
        vector = item["vettore"]
        if not isinstance(vector, list) or len(vector) != DIMENSION:
            raise ValueError("Il template deve contenere 512 coordinate.")
        if any(type(value) is not int or not -3 <= value <= 3 for value in vector):
            raise ValueError("Il template contiene coordinate fuori dal dominio ammesso.")
        norm2 = sum(value * value for value in vector)
        squared_bound = norm2 * 1024
        dot_bound = math.isqrt(squared_bound)
        if dot_bound * dot_bound != squared_bound:
            dot_bound += 1
        entry_lower, entry_upper = norm2 - 2 * dot_bound, norm2 + 2 * dot_bound
        lower = entry_lower if lower is None else min(lower, entry_lower)
        upper = entry_upper if upper is None else max(upper, entry_upper)
        photo = item["foto_file"]
        if photo is not None and photo not in (identifier + ".jpg", identifier + ".png"):
            raise ValueError("Il riferimento alla foto non è valido.")
        if item["origine"] not in ("sintetico", "registrato"):
            raise ValueError("L'origine dell'iscritto non è valida.")
        result.append({
            "id": identifier,
            "nome": validate_name(item["nome"]),
            "soglia": validate_threshold(item["soglia"]),
            "vettore": list(vector),
            "foto_file": photo,
            "origine": item["origine"],
        })
    if result and upper - lower + 1 > 4096:
        raise ValueError("Questi template superano il dominio dei punteggi ammesso dalla demo.")
    return result


def _atomic_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".pending-", delete=False) as stream:
            temporary = pathlib.Path(stream.name)
            json.dump(value, stream, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class GalleryStore:
    """A single-process store. Backend transactions are serialized by the server."""

    def __init__(self, state_dir: str | pathlib.Path):
        self.directory = pathlib.Path(state_dir).resolve()
        self.photos = self.directory / "photos"
        self.gallery_path = self.directory / "gallery.json"
        self.events_path = self.directory / "events.json"
        self.lock = threading.RLock()
        self._entries = []
        self._revision = 0
        self._events = []
        self._total = 0
        if self.gallery_path.exists():
            if self.gallery_path.stat().st_size > 16 * 1024 * 1024:
                raise ValueError("Archivio della galleria troppo grande.")
            value = strict_json(self.gallery_path.read_bytes())
            if not isinstance(value, dict) or set(value) != {"schema", "revision", "iscritti"}:
                raise ValueError("Archivio della galleria non valido.")
            if value["schema"] != 1 or type(value["revision"]) is not int or value["revision"] < 0:
                raise ValueError("Versione dell'archivio non valida.")
            self._entries = validate_entries(value["iscritti"])
            self._revision = value["revision"]
        if self.events_path.exists():
            self._load_events()

    def entries(self) -> list[dict]:
        with self.lock:
            return copy.deepcopy(self._entries)

    def replace(self, entries: list[dict]) -> None:
        checked = validate_entries(entries)
        with self.lock:
            revision = self._revision + 1
            _atomic_json(self.gallery_path, {"schema": 1, "revision": revision, "iscritti": checked})
            self._entries = checked
            self._revision = revision

    def public_entry(self, entry: dict, index: int) -> dict:
        return {
            "id": entry["id"], "nome": entry["nome"], "soglia": entry["soglia"],
            "foto_url": f"/api/foto/{entry['id']}" if entry["foto_file"] else None,
            "origine": entry["origine"], "indice": index + 1,
        }

    def gallery(self) -> dict:
        with self.lock:
            return {"iscritti": [self.public_entry(entry, index)
                                 for index, entry in enumerate(self._entries)],
                    "totale": len(self._entries)}

    def photo_path(self, identifier: str) -> pathlib.Path | None:
        with self.lock:
            entry = next((entry for entry in self._entries if entry["id"] == identifier), None)
            if entry is None or entry["foto_file"] is None:
                return None
            path = self.photos / entry["foto_file"]
            if path.is_symlink() or not path.is_file() or path.parent.resolve() != self.photos.resolve():
                return None
            return path

    def write_photo(self, identifier: str, photo: bytes) -> str:
        if str(uuid.UUID(identifier)) != identifier or not 0 < len(photo) <= MAX_PHOTO_BYTES:
            raise ValueError("Foto non valida.")
        self.photos.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.photos / (identifier + ".jpg")
        with path.open("xb") as stream:
            os.chmod(path, 0o600)
            stream.write(photo)
            stream.flush()
            os.fsync(stream.fileno())
        return path.name

    def remove_photo(self, filename: str | None) -> None:
        if filename is None:
            return
        stem, extension = pathlib.Path(filename).stem, pathlib.Path(filename).suffix
        if filename == stem + extension and extension in (".png", ".jpg"):
            try:
                if str(uuid.UUID(stem)) == stem:
                    (self.photos / filename).unlink(missing_ok=True)
            except (ValueError, OSError):
                pass

    def _load_events(self) -> None:
        if self.events_path.stat().st_size > 1024 * 1024:
            raise ValueError("Archivio delle richieste troppo grande.")
        value = strict_json(self.events_path.read_bytes())
        if not isinstance(value, dict) or value.get("schema") != 1:
            raise ValueError("Archivio delle richieste non valido.")
        events = value.get("richieste")
        total = value.get("totale")
        if not isinstance(events, list) or len(events) > MAX_EVENTS or type(total) is not int:
            raise ValueError("Archivio delle richieste non valido.")
        allowed = {"id", "ora", "stato", "durata_ms", "byte_richiesta", "byte_risposta",
                   "impronta", "errore"}
        for event in events:
            if not isinstance(event, dict) or set(event) - allowed or not allowed - {"errore"} <= set(event):
                raise ValueError("Metadati delle richieste non validi.")
            if event["stato"] in ("ricevuta", "in_elaborazione"):
                event["stato"] = "errore"
                event["errore"] = "La richiesta è stata interrotta dal riavvio del servizio."
        self._events = events
        self._total = max(total, len(events))

    def _save_events(self) -> None:
        _atomic_json(self.events_path, {"schema": 1, "totale": self._total, "richieste": self._events})

    def begin_request(self, ciphertext: bytes) -> str:
        identifier = str(uuid.uuid4())
        event = {"id": identifier, "ora": datetime.now(timezone.utc).isoformat(),
                 "stato": "ricevuta", "durata_ms": None, "byte_richiesta": len(ciphertext),
                 "byte_risposta": None, "impronta": hashlib.sha256(ciphertext).hexdigest()}
        with self.lock:
            self._total += 1
            self._events.insert(0, event)
            self._events = self._events[:MAX_EVENTS]
            self._save_events()
        return identifier

    def update_request(self, identifier: str, *, stato: str, durata_ms: float | None = None,
                       byte_risposta: int | None = None, errore: str | None = None) -> None:
        with self.lock:
            event = next((item for item in self._events if item["id"] == identifier), None)
            if event is None:
                return
            event.update(stato=stato, durata_ms=durata_ms, byte_risposta=byte_risposta)
            if errore is not None:
                event["errore"] = errore
            self._save_events()

    def requests(self) -> dict:
        with self.lock:
            return {"richieste": copy.deepcopy(self._events), "totale": self._total}

    def request_summary(self) -> dict:
        with self.lock:
            pending = sum(event["stato"] in ("ricevuta", "in_elaborazione") for event in self._events)
            duration = next((event["durata_ms"] for event in self._events
                             if event["durata_ms"] is not None), None)
            return {"richieste": self._total, "in_corso": pending, "ultima_durata_ms": duration}
