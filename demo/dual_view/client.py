"""Access-only client around the unchanged, qualified exact-ID pipeline."""
from __future__ import annotations

import base64
import binascii
import importlib
import importlib.util
import io
import json
import math
import os
import re
import sys
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
import urllib.parse
import urllib.request

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from PIL import Image

HERE = Path(__file__).resolve().parent
QUALIFIED = HERE.parents[1] / "experiments/22_demo_composita/runtime"
MAX_FRAME_BYTES = 4 * 1024 * 1024
MAX_BODY_BYTES = 17 * 1024 * 1024
MAX_PIXELS = 4_000_000
MAX_SIDE = 4096
IMAGE_FORMATS = {"image/jpeg": "JPEG", "image/png": "PNG", "image/webp": "WEBP"}
UNAVAILABLE = "Servizio temporaneamente non disponibile. Riprova tra poco."


class AccessError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class ClientSettings:
    binary: Path
    keys: Path
    gateway: str = "http://127.0.0.1:8005/fhe"
    origin: str = "http://127.0.0.1:8006"

    @classmethod
    def from_environment(cls) -> "ClientSettings":
        return cls(Path(os.environ.get("VARCO_BIN", "")),
                   Path(os.environ.get("VARCO_CHIAVI", "")),
                   os.environ.get("VARCO_SERVER", "http://127.0.0.1:8005/fhe").rstrip("/"),
                   os.environ.get("VARCO_DUAL_CLIENT_ORIGIN", "http://127.0.0.1:8006").rstrip("/"))

    def validate(self) -> None:
        if not self.binary.is_absolute() or not self.binary.is_file() or not self.keys.is_absolute():
            raise AccessError(503, "Client non configurato per l'accesso.")
        for url, path in ((self.gateway, "/fhe"), (self.origin, "")):
            parsed = urllib.parse.urlsplit(url)
            if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
                    or parsed.path != path or parsed.query or parsed.fragment
                    or parsed.username is not None or parsed.password is not None
                    or parsed.port is None):
                raise AccessError(503, "Client non configurato per l'accesso.")
        self.check_keys()

    def check_keys(self) -> None:
        for name in ("client.key", "server.key"):
            path = self.keys / name
            if not path.is_file() or path.stat().st_size == 0:
                raise AccessError(503, "Chiavi del client non disponibili. Avvio interrotto.")
        if (self.keys / "g4.key").exists():
            raise AccessError(503, "Le chiavi non corrispondono al client configurato.")


class LocalGateway:
    """Keep the qualified transport interface, with no proxies or admin routes."""
    def __init__(self, url: str):
        self.url = url
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def __call__(self, path, data=None, ctype="application/octet-stream", timeout=120):
        limits = {"/chiave": 320 * 1024 * 1024, "/varco": 64 * 1024}
        if data is None:
            if path != "/stato":
                raise AccessError(503, UNAVAILABLE)
        elif path not in limits or not isinstance(data, bytes) or not 0 < len(data) <= limits[path]:
            raise AccessError(503, UNAVAILABLE)
        request = urllib.request.Request(self.url + path, data=data,
                                         method="POST" if data is not None else "GET",
                                         headers={"Content-Type": ctype} if data is not None else {})
        with self.opener.open(request, timeout=timeout) as response:
            body = response.read(4 * 1024 * 1024 + 1)
            if len(body) > 4 * 1024 * 1024:
                raise AccessError(503, UNAVAILABLE)
            return body, dict(response.headers)


def load_qualified_client(settings: ClientSettings):
    name = "_dual_view_access_qualified_client"
    package_path = QUALIFIED / "client"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            name, package_path / "__init__.py", submodule_search_locations=[str(package_path)])
        package = importlib.util.module_from_spec(spec)
        sys.modules[name] = package
        spec.loader.exec_module(package)
    module = importlib.import_module(name + ".app")
    if Path(module.__file__).resolve() != package_path / "app.py":
        raise AccessError(503, "Modulo del client non valido.")
    if module.CFG["contratto_esatto"]["g4_required"]:
        raise AccessError(503, "Configurazione del client non valida.")
    module.SERVER = settings.gateway
    module.BIN = str(settings.binary)
    module.CHIAVI = settings.keys
    module.srv = LocalGateway(settings.gateway)
    return module


def check_local_models() -> None:
    root = Path.home() / ".insightface/models"
    for pack, filename in (("antelopev2", "glintr100.onnx"),
                           ("buffalo_s", "det_500m.onnx"), ("buffalo_s", "w600k_mbf.onnx")):
        if not any(path.is_file() for path in (root / pack).rglob(filename)):
            raise AccessError(503, "Modelli locali non disponibili per la verifica.")


def validate_frame(value: str) -> None:
    if not isinstance(value, str) or len(value) > 4 * ((MAX_FRAME_BYTES + 2) // 3) + 64:
        raise AccessError(400, "Immagine assente o troppo grande.")
    header, separator, payload = value.partition(",")
    mime = header.removeprefix("data:").removesuffix(";base64")
    if separator != "," or header != f"data:{mime};base64" or mime not in IMAGE_FORMATS:
        raise AccessError(400, "Usa immagini JPEG, PNG o WebP.")
    try:
        raw = base64.b64decode(payload, validate=True)
        if not 0 < len(raw) <= MAX_FRAME_BYTES:
            raise ValueError("image size")
        with Image.open(io.BytesIO(raw)) as picture:
            width, height = picture.size
            if (picture.format != IMAGE_FORMATS[mime] or getattr(picture, "n_frames", 1) != 1
                    or width < 1 or height < 1 or max(width, height) > MAX_SIDE
                    or width * height > MAX_PIXELS):
                raise ValueError("image geometry or format")
            picture.verify()
    except (ValueError, OSError, SyntaxError, binascii.Error, Image.DecompressionBombError) as error:
        raise AccessError(400, "Immagine non valida, animata o troppo grande.") from error


def parse_payload(raw: bytes) -> list[str]:
    def fields(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("duplicate field")
            result[name] = value
        return result

    def invalid_constant(value):
        raise ValueError("nonfinite JSON")

    try:
        payload = json.loads(raw, object_pairs_hook=fields, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise AccessError(400, "Richiesta non valida.") from error
    if not isinstance(payload, dict) or set(payload) != {"frames"}:
        raise AccessError(400, "La richiesta deve contenere soltanto le immagini.")
    frames = payload["frames"]
    if not isinstance(frames, list) or not 1 <= len(frames) <= 3:
        raise AccessError(400, "Invia da una a tre immagini.")
    if any(not isinstance(frame, str) for frame in frames):
        raise AccessError(400, "Formato delle immagini non valido.")
    return frames


class AccessRuntime:
    def __init__(self, settings: ClientSettings | None = None,
                 loader: Callable = load_qualified_client,
                 model_check: Callable = check_local_models):
        self.settings = settings
        self.loader = loader
        self.model_check = model_check
        self.module = None
        self.lock = threading.Lock()
        self.cached_status = {"pronto": False, "iscritti": 0, "frame_richiesti": 3}

    def configured(self):
        if self.settings is None:
            self.settings = ClientSettings.from_environment()
        self.settings.validate()
        if self.module is None:
            self.module = self.loader(self.settings)
        return self.module

    def _status(self, module):
        raw, _ = module.srv("/stato")
        state = module.protocol.strict_json(raw)
        snapshot = module.protocol.validate_status(state, module.CFG["contratto_esatto"], allow_empty=True)
        if not state["chiave"]:
            module.assicura_chiave()
            raw, _ = module.srv("/stato")
            state = module.protocol.strict_json(raw)
            snapshot = module.protocol.validate_status(state, module.CFG["contratto_esatto"], allow_empty=True)
        module.valida_fingerprint_chiave(state)
        module.valida_fingerprint_g4(state)
        count = snapshot["iscritti"]
        self.cached_status = {"pronto": count > 0, "iscritti": count, "frame_richiesti": 3}
        if not count:
            self.cached_status["errore"] = "La galleria non contiene ancora iscritti."
        return dict(self.cached_status)

    def initialize(self) -> None:
        with self.lock:
            try:
                module = self.configured()
                module.assicura_chiave()
                self._status(module)
            except Exception as error:
                self._unavailable(error)

    def _unavailable(self, error):
        message = error.message if isinstance(error, AccessError) else UNAVAILABLE
        self.cached_status = {"pronto": False, "iscritti": 0, "frame_richiesti": 3, "errore": message}
        return dict(self.cached_status)

    def status(self):
        if not self.lock.acquire(blocking=False):
            return dict(self.cached_status)
        try:
            return self._status(self.configured())
        except Exception as error:
            return self._unavailable(error)
        finally:
            self.lock.release()

    def access(self, frames: list[str]):
        if not self.lock.acquire(blocking=False):
            raise AccessError(409, "Una verifica è già in corso. Attendi il risultato.")
        started = time.perf_counter()
        try:
            module = self.configured()
            for frame in frames:
                validate_frame(frame)
            try:
                images = [module.da_dataurl(frame) for frame in frames]
                if any(len(image.shape) != 3 or image.shape[2] != 3 for image in images):
                    raise ValueError("expected RGB images")
            except Exception as error:
                raise AccessError(400, "Le immagini non possono essere lette.") from error
            self.model_check()
            try:
                query, _ = module.embedding_fuso(images)
            except ValueError as error:
                if "nessun volto" in str(error).lower():
                    raise AccessError(422, "Nessun volto rilevato. Inquadra il viso e riprova.") from error
                raise AccessError(400, "Le immagini non possono essere usate per la verifica.") from error
            module.assicura_chiave()
            snapshot = module.snapshot_galleria()
            ciphertext, _ = module.cifra(query, snapshot["query_profile"])
            encrypted_result, headers = module.srv("/varco", ciphertext)
            headers = module.valida_header_varco(headers, snapshot)
            decoded = module.decifra(encrypted_result)
            module.identita_da_esito(decoded, snapshot)
            server_ms = float(headers["x-tempo-ms"])
            if type(decoded["autorizzato"]) is not bool or not math.isfinite(server_ms) or server_ms < 0:
                raise AccessError(503, UNAVAILABLE)
            result = {"esito": "aperto" if decoded["autorizzato"] else "negato",
                      "tempi_ms": {"endpoint": round((time.perf_counter() - started) * 1000, 1),
                                   "server": server_ms}}
            request_id = headers.get("x-request-id")
            if isinstance(request_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", request_id):
                result["richiesta_id"] = request_id
            self.cached_status = {"pronto": True, "iscritti": snapshot["iscritti"], "frame_richiesti": 3}
            return result
        except AccessError:
            raise
        except Exception as error:
            self._unavailable(error)
            raise AccessError(503, UNAVAILABLE) from error
        finally:
            self.lock.release()


async def read_access_body(request: Request) -> bytes:
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise AccessError(415, "Invia le immagini come richiesta JSON.")
    length = request.headers.get("content-length")
    if length is not None:
        try:
            size = int(length)
        except ValueError as error:
            raise AccessError(400, "Richiesta non valida.") from error
        if size < 0 or size > MAX_BODY_BYTES:
            raise AccessError(413, "Le immagini superano la dimensione massima.")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_BODY_BYTES:
            raise AccessError(413, "Le immagini superano la dimensione massima.")
        body.extend(chunk)
    return bytes(body)


def create_app(runtime: AccessRuntime | None = None) -> FastAPI:
    runtime = runtime or AccessRuntime()

    @asynccontextmanager
    async def lifespan(app):
        await run_in_threadpool(runtime.initialize)
        yield

    app = FastAPI(title="Accesso al varco", docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.state.runtime = runtime
    app.mount("/static", StaticFiles(directory=HERE / "static", check_dir=False), name="static")

    @app.exception_handler(AccessError)
    async def access_error(request, error):
        return JSONResponse({"errore": error.message}, status_code=error.status,
                            headers={"Cache-Control": "no-store"})

    @app.exception_handler(Exception)
    async def unavailable(request, error):
        return JSONResponse({"errore": UNAVAILABLE}, status_code=503,
                            headers={"Cache-Control": "no-store"})

    @app.get("/")
    async def page():
        return FileResponse(HERE / "static/client.html", headers={"Cache-Control": "no-store"})

    @app.get("/api/stato")
    async def status():
        value = await run_in_threadpool(runtime.status)
        return JSONResponse(value, headers={"Cache-Control": "no-store"})

    @app.post("/api/accesso")
    async def access(request: Request):
        origin = request.headers.get("origin")
        expected_origin = (runtime.settings.origin if runtime.settings is not None
                           else os.environ.get("VARCO_DUAL_CLIENT_ORIGIN", "http://127.0.0.1:8006").rstrip("/"))
        if origin is not None and origin != expected_origin:
            raise AccessError(403, "Origine della richiesta non consentita.")
        frames = parse_payload(await read_access_body(request))
        value = await run_in_threadpool(runtime.access, frames)
        return JSONResponse(value, headers={"Cache-Control": "no-store"})

    return app


app = create_app()
