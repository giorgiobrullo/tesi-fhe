"""Gallery administration and a raw-ciphertext gateway on the owned demo backend."""

from __future__ import annotations

import json
import os
import pathlib
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from .enrollment import CONFIG_PATH, EnrollmentProcessor, decode_frames, image_from_bytes
from .gallery import GalleryStore, MAX_PHOTO_BYTES, strict_json, validate_entries, validate_name, validate_threshold


ROOT = pathlib.Path(__file__).resolve().parents[2]
STATIC = pathlib.Path(__file__).resolve().parent / "static"
MAX_JSON_BODY = 18 * 1024 * 1024
MAX_PROBE_BODY = 64 * 1024
MAX_KEY_BODY = 320 * 1024 * 1024
MAX_BACKEND_RESPONSE = 2 * 1024 * 1024
PUBLIC_CONFIG = json.loads(CONFIG_PATH.read_text())
EXPECTED_CONTRACT = PUBLIC_CONFIG["contratto_esatto"]


class BackendUnavailable(RuntimeError):
    pass


class MissingEntry(ValueError):
    pass


@dataclass(frozen=True)
class BackendResponse:
    status: int
    body: bytes
    headers: dict[str, str]


class HTTPBackend:
    """This adapter deliberately cannot target either preserved backend."""

    def __init__(self, url: str | None = None, *, owned: bool | None = None):
        self.url = url or os.environ.get("VARCO_BACKEND_URL", "http://127.0.0.1:9005")
        parsed = urllib.parse.urlsplit(self.url)
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port != 9005
                or parsed.username or parsed.password or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment):
            raise ValueError("Il backend di questa demo deve essere quello locale dedicato sulla porta 9005.")
        self.url = self.url.rstrip("/")
        self.owned = os.environ.get("VARCO_DUAL_OWN_BACKEND") == "1" if owned is None else owned
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def request(self, method: str, path: str, data: bytes | None = None,
                content_type: str = "application/octet-stream") -> BackendResponse:
        allowed = {("GET", "/stato"), ("POST", "/reset"), ("POST", "/iscrivi"),
                   ("POST", "/varco"), ("POST", "/chiave")}
        if (method, path) not in allowed or (method == "POST" and not self.owned):
            raise BackendUnavailable("Il backend dedicato non è autorizzato per questa operazione.")
        request = urllib.request.Request(self.url + path, data=data, method=method,
                                         headers={"Content-Type": content_type} if data is not None else {})
        try:
            try:
                stream = self.opener.open(request, timeout=600 if path == "/chiave" else 120)
            except urllib.error.HTTPError as error:
                stream = error
            with stream:
                body = stream.read(MAX_BACKEND_RESPONSE + 1)
                if len(body) > MAX_BACKEND_RESPONSE:
                    raise BackendUnavailable("La risposta del servizio cifrato è troppo grande.")
                return BackendResponse(stream.code, body, dict(stream.headers))
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise BackendUnavailable("Il servizio cifrato non è raggiungibile.") from exc


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


class GalleryCoordinator:
    def __init__(self, store: GalleryStore, backend):
        self.store = store
        self.backend = backend
        self.lock = threading.RLock()
        self.synced = False
        self.error: str | None = "Preparazione del servizio in corso."
        self.last_status: dict = {}

    def _read_status(self, reply: BackendResponse) -> dict:
        if reply.status != 200:
            raise BackendUnavailable("Il servizio cifrato non è disponibile.")
        try:
            status = strict_json(reply.body)
            if not isinstance(status, dict) or status.get("dim") != 512:
                raise ValueError("stato")
            contract = status.get("contratto_esatto", {})
            for key in ("circuit_sha256", "variant_id", "service_source_sha256", "runtime_mode",
                        "g4_required", "max_gallery_size", "score_domain_max_width"):
                actual, expected = contract.get(key), EXPECTED_CONTRACT[key]
                if type(actual) is not type(expected) or actual != expected:
                    raise ValueError("contratto")
            if type(status.get("iscritti")) is not int or not isinstance(status.get("nomi"), list):
                raise ValueError("galleria")
        except (ValueError, TypeError, AttributeError) as exc:
            raise BackendUnavailable("Il servizio cifrato non corrisponde alla demo configurata.") from exc
        self.last_status = status
        return status

    def _status(self) -> dict:
        return self._read_status(self.backend.request("GET", "/stato"))

    def _check_current_gallery(self, status: dict) -> None:
        entries = self.store.entries()
        if (status["iscritti"] != len(entries)
                or status["nomi"] != [entry["id"] for entry in entries]
                or status.get("soglie") != [entry["soglia"] for entry in entries]):
            self.synced = False
            self.error = "La galleria non è sincronizzata. Riavvia la demo dedicata."
            raise BackendUnavailable(self.error)

    def _rebuild(self, entries: list[dict]) -> None:
        validate_entries(entries)
        self._status()  # Verify the actual circuit before touching the dedicated gallery.
        reply = self.backend.request("POST", "/reset", b"")
        if reply.status != 200:
            raise BackendUnavailable("La galleria cifrata non può essere aggiornata.")
        for entry in entries:
            # Native enrollment is an upsert by name. Stable UUIDs prevent accidental replacement.
            payload = f"{entry['id']}\t{entry['soglia']}\n" + " ".join(map(str, entry["vettore"]))
            reply = self.backend.request("POST", "/iscrivi", payload.encode(), "text/plain; charset=utf-8")
            if reply.status != 200:
                raise BackendUnavailable("Il servizio cifrato ha rifiutato l'aggiornamento della galleria.")
        status = self._status()
        if (status["iscritti"] != len(entries)
                or status["nomi"] != [entry["id"] for entry in entries]
                or status.get("soglie") != [entry["soglia"] for entry in entries]):
            raise BackendUnavailable("La verifica della galleria aggiornata non è riuscita.")

    def synchronize(self) -> None:
        with self.lock:
            try:
                self._rebuild(self.store.entries())
            except Exception:
                self.synced = False
                self.error = "La galleria non è sincronizzata. Riavvia la demo dedicata."
                raise BackendUnavailable(self.error) from None
            self.synced = True
            self.error = None

    def change(self, transform, *, new_photo: bytes | None = None) -> dict:
        with self.lock:
            old_entries = self.store.entries()
            proposed, changed_id, removed_photo = transform(old_entries)
            proposed = validate_entries(proposed)
            created_photo = None
            if new_photo is not None:
                image_from_bytes(new_photo, "JPEG")
                created_photo = self.store.write_photo(changed_id, new_photo)
            try:
                self._rebuild(proposed)
                self.store.replace(proposed)
            except Exception:
                try:
                    self._rebuild(self.store.entries())
                    self.synced = True
                    self.error = None
                    message = "Aggiornamento non riuscito. La galleria precedente è stata ripristinata."
                except Exception:
                    self.synced = False
                    self.error = "La galleria non è sincronizzata. Il servizio è temporaneamente indisponibile."
                    message = self.error
                if created_photo:
                    self.store.remove_photo(created_photo)
                raise BackendUnavailable(message) from None
            self.synced = True
            self.error = None
            if removed_photo:
                self.store.remove_photo(removed_photo)
            gallery = self.store.gallery()
            changed = next((entry for entry in gallery["iscritti"] if entry["id"] == changed_id), None)
            result = {"ok": True, "totale": gallery["totale"]}
            if changed is not None:
                result["iscritto"] = changed
            return result

    def public_status(self) -> dict:
        acquired = self.lock.acquire(blocking=False)
        connection_ok = bool(self.last_status)
        if acquired:
            try:
                current = self._status()
                if self.synced:
                    self._check_current_gallery(current)
                connection_ok = True
            except BackendUnavailable:
                connection_ok = False
            finally:
                self.lock.release()
        count = len(self.store.entries())
        ready = self.synced and connection_ok and count > 0 and self.last_status.get("chiave") is True
        result = {"pronto": ready, "iscritti": count, **self.store.request_summary()}
        if self.error:
            result["errore"] = self.error
        elif not connection_ok:
            result["errore"] = "Il servizio cifrato non è raggiungibile."
        return result

    def forward(self, path: str, body: bytes | None = None) -> BackendResponse:
        with self.lock:
            if not self.synced:
                raise BackendUnavailable(self.error or "La galleria non è sincronizzata.")
            if path != "/stato":
                self._check_current_gallery(self._status())
            reply = self.backend.request("GET" if body is None else "POST", path, body)
            if path == "/stato":
                self._check_current_gallery(self._read_status(reply))
            if path == "/chiave" and reply.status == 200:
                self._status()
            return reply

    def query(self, body: bytes) -> tuple[BackendResponse, str]:
        identifier = self.store.begin_request(body)
        started = time.perf_counter()
        try:
            with self.lock:
                self.store.update_request(identifier, stato="in_elaborazione")
                reply = self.forward("/varco", body)
            duration = round((time.perf_counter() - started) * 1000, 3)
            error = None if reply.status == 200 else "Il servizio cifrato ha rifiutato la richiesta."
            self.store.update_request(identifier, stato="completata" if error is None else "errore",
                                      durata_ms=duration, byte_risposta=len(reply.body), errore=error)
            return reply, identifier
        except Exception:
            self.store.update_request(identifier, stato="errore",
                                      durata_ms=round((time.perf_counter() - started) * 1000, 3),
                                      errore="La richiesta cifrata non è stata completata.")
            return BackendResponse(503, b'{"errore":"Servizio cifrato non disponibile."}',
                                   {"Content-Type": "application/json"}), identifier


async def _bounded_body(request: Request, maximum: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            length = int(declared)
        except ValueError as exc:
            raise ValueError("Lunghezza della richiesta non valida.") from exc
        if length < 0:
            raise ValueError("Lunghezza della richiesta non valida.")
        if length > maximum:
            raise OverflowError("La richiesta supera la dimensione consentita.")
    chunks = []
    length = 0
    async for chunk in request.stream():
        length += len(chunk)
        if length > maximum:
            raise OverflowError("La richiesta supera la dimensione consentita.")
        chunks.append(chunk)
    return b"".join(chunks)


async def _json_body(request: Request, required: set[str], optional: set[str]) -> dict:
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise ValueError("Invia una richiesta JSON.")
    value = strict_json(await _bounded_body(request, MAX_JSON_BODY))
    if not isinstance(value, dict) or not required <= set(value) or set(value) - required - optional:
        raise ValueError("I campi della richiesta non sono validi.")
    return value


def _proxy_response(reply: BackendResponse, identifier: str | None = None) -> Response:
    # Keep cryptographic contract headers, but do not inherit the Rust server's wildcard CORS.
    excluded = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                "te", "trailer", "transfer-encoding", "upgrade", "content-length"}
    headers = {key: value for key, value in reply.headers.items()
               if key.lower() not in excluded and not key.lower().startswith("access-control-")}
    headers["Cache-Control"] = "no-store"
    if identifier:
        headers["X-Request-Id"] = identifier
    return Response(reply.body, status_code=reply.status, headers=headers)


def create_app(store: GalleryStore | None = None, backend=None, enroller=None,
               server_origin: str | None = None) -> FastAPI:
    store = store if store is not None else GalleryStore(
        os.environ.get("VARCO_DUAL_STATE", str(pathlib.Path(__file__).resolve().parent / ".local/server")))
    backend = backend if backend is not None else HTTPBackend()
    enroller = enroller if enroller is not None else EnrollmentProcessor()
    coordinator = GalleryCoordinator(store, backend)
    origin = server_origin or os.environ.get("VARCO_DUAL_SERVER_ORIGIN", "http://127.0.0.1:8005")

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            await run_in_threadpool(coordinator.synchronize)
        except BackendUnavailable:
            pass  # The status endpoint remains available with a bounded error.
        yield

    app = FastAPI(title="Varco · Server", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store
    app.state.coordinator = coordinator
    app.mount("/static", StaticFiles(directory=STATIC, check_dir=False), name="static")

    @app.middleware("http")
    async def browser_boundary(request: Request, call_next):
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            request_origin = request.headers.get("origin")
            site = request.headers.get("sec-fetch-site")
            if ((request_origin is not None and request_origin != origin)
                    or site in ("cross-site", "same-site")):
                return JSONResponse({"errore": "Origine della richiesta non consentita."}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        if request.url.path.startswith("/api/") and not request.url.path.startswith("/api/foto/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(ValueError)
    async def invalid_input(_request: Request, error: ValueError):
        status = 404 if isinstance(error, MissingEntry) else 400
        return JSONResponse({"errore": str(error)}, status_code=status)

    @app.exception_handler(OverflowError)
    async def too_large(_request: Request, error: OverflowError):
        return JSONResponse({"errore": str(error)}, status_code=413)

    @app.exception_handler(BackendUnavailable)
    async def unavailable(_request: Request, error: BackendUnavailable):
        return JSONResponse({"errore": str(error)}, status_code=503)

    @app.exception_handler(Exception)
    async def unexpected(_request: Request, _error: Exception):
        return JSONResponse({"errore": "L'operazione non è disponibile. Riprova tra poco."}, status_code=503)

    @app.get("/")
    def page():
        if not (STATIC / "server.html").is_file():
            return JSONResponse({"errore": "La pagina è in preparazione."}, status_code=503)
        return FileResponse(STATIC / "server.html")

    @app.get("/api/stato")
    def status():
        return coordinator.public_status()

    @app.get("/api/galleria")
    def gallery():
        return store.gallery()

    @app.get("/api/richieste")
    def requests():
        return store.requests()

    @app.get("/api/foto/{identifier}")
    def photo(identifier: str):
        path = store.photo_path(identifier)
        if path is None:
            raise MissingEntry("Foto non trovata.")
        if path.stat().st_size > MAX_PHOTO_BYTES:
            raise ValueError("La foto non può essere visualizzata.")
        raw = path.read_bytes()
        image_from_bytes(raw, "PNG" if path.suffix == ".png" else "JPEG")
        return Response(raw, media_type="image/png" if path.suffix == ".png" else "image/jpeg",
                        headers={"Cache-Control": "private, max-age=300"})

    @app.post("/api/iscritti")
    async def enroll(request: Request):
        value = await _json_body(request, {"nome", "frames"}, {"soglia"})
        name = validate_name(value["nome"])
        threshold = validate_threshold(value.get("soglia", 273))
        frames = await run_in_threadpool(decode_frames, value["frames"])
        try:
            vector, image = await run_in_threadpool(enroller, frames)
        except RuntimeError:
            raise BackendUnavailable("Il modello locale per l'iscrizione non è disponibile.") from None
        identifier = str(uuid.uuid4())
        entry = {"id": identifier, "nome": name, "soglia": threshold, "vettore": vector,
                 "foto_file": identifier + ".jpg", "origine": "registrato"}

        def add(entries):
            return entries + [entry], identifier, None

        return await run_in_threadpool(coordinator.change, add, new_photo=image)

    @app.patch("/api/iscritti/{identifier}")
    async def edit(identifier: str, request: Request):
        value = await _json_body(request, set(), {"nome", "soglia"})
        if not value:
            raise ValueError("Indica almeno un campo da modificare.")
        if "nome" in value:
            value["nome"] = validate_name(value["nome"])
        if "soglia" in value:
            value["soglia"] = validate_threshold(value["soglia"])

        def update(entries):
            entry = next((entry for entry in entries if entry["id"] == identifier), None)
            if entry is None:
                raise MissingEntry("Iscritto non trovato.")
            entry.update(value)
            return entries, identifier, None

        return await run_in_threadpool(coordinator.change, update)

    @app.delete("/api/iscritti/{identifier}")
    async def delete(identifier: str, request: Request):
        if await _bounded_body(request, 0):
            raise ValueError("La richiesta di eliminazione non deve contenere dati.")

        def remove(entries):
            entry = next((entry for entry in entries if entry["id"] == identifier), None)
            if entry is None:
                raise MissingEntry("Iscritto non trovato.")
            return [entry for entry in entries if entry["id"] != identifier], identifier, entry["foto_file"]

        return await run_in_threadpool(coordinator.change, remove)

    @app.get("/fhe/stato")
    def backend_status():
        return _proxy_response(coordinator.forward("/stato"))

    @app.post("/fhe/chiave")
    async def evaluation_key(request: Request):
        body = await _bounded_body(request, MAX_KEY_BODY)
        reply = await run_in_threadpool(coordinator.forward, "/chiave", body)
        return _proxy_response(reply)

    @app.post("/fhe/varco")
    async def query(request: Request):
        body = await _bounded_body(request, MAX_PROBE_BODY)
        reply, identifier = await run_in_threadpool(coordinator.query, body)
        return _proxy_response(reply, identifier)

    return app


app = create_app()
