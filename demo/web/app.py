"""Session-isolated UI; one worker owns embedding and native verification."""
from __future__ import annotations

import asyncio
import copy
import ipaddress
import logging
import os
import re
import secrets
import threading
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from demo.dual_view.client import AccessError, check_local_models
from demo.dual_view.enrollment import EnrollmentProcessor, decode_frames
from demo.dual_view.gallery import strict_json, validate_entries, validate_name, validate_threshold
from .default_gallery import DefaultGallery, prepare_gallery
from .events import EventHub, EventResponse, HEARTBEAT_SECONDS, TIMELINE_SECONDS, SSEWriteTimeoutMiddleware, encode_event
from .timeline import Timeline, clock_ns

HERE = Path(__file__).resolve().parent
COOKIE = "varco_sessione"
MAX_BODY = 17 * 1024 * 1024
MAX_BODY_READERS = 8
BODY_READ_TIMEOUT_SECONDS = 60
MAX_ENTRIES = 128
MAX_REQUESTS = 128
DEFAULT_MAX_SESSIONS = 512
MAX_SESSION_LIMIT = 4096
READ_ONLY_IDLE_SECONDS = 300
STAGES = {"cifratura", "elaborazione", "decifratura"}
TERMINAL = {"completata", "errore"}


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        self.status, self.message = status, message


def session_limit(value: object) -> int:
    error = f"Il limite delle sessioni deve essere un intero tra 1 e {MAX_SESSION_LIMIT}."
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,4}", value):
        value = int(value)
    if type(value) is not int or not 1 <= value <= MAX_SESSION_LIMIT:
        raise ValueError(error)
    return value


def normalize_public_origin(value: str) -> str:
    """Validate one HTTPS origin, without trusting request or proxy headers."""
    error = "L'origine pubblica deve essere un URL HTTPS con solo host e porta opzionale."
    if (not isinstance(value, str) or not value or not value.isascii()
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
            or any(char in value for char in "?#\\%")):
        raise ValueError(error)
    try:
        parsed = urlsplit(value)
        host, port = parsed.hostname, parsed.port
        if (parsed.scheme != "https" or not host or parsed.username is not None
                or parsed.password is not None or parsed.path not in ("", "/")
                or parsed.netloc.endswith(":") or (port is not None and not 1 <= port <= 65535)):
            raise ValueError
        if ":" in host:
            if not re.fullmatch(r"\[[0-9a-fA-F:.]+\](?::[0-9]+)?", parsed.netloc):
                raise ValueError
            authority = f"[{ipaddress.IPv6Address(host).compressed}]"
        else:
            if len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                      for label in host.split(".")):
                raise ValueError
            authority = host
        if port is not None and port != 443:
            authority += f":{port}"
        return "https://" + authority
    except ValueError:
        raise ValueError(error) from None


def timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def public_entry(entry: dict, metadata: dict | None = None) -> dict:
    return {key: entry[key] for key in ("id", "nome", "soglia")} | {
        "foto_url": f"/api/foto/{entry['id']}"
    } | copy.deepcopy(metadata or {})


def validate_query(vector: object) -> list[int]:
    if (not isinstance(vector, list) or len(vector) != 512
            or any(type(v) is not int or not -3 <= v <= 3 for v in vector)
            or sum(v * v for v in vector) > 1024):
        raise ValueError("Il volto preparato supera il dominio ammesso dalla verifica.")
    return vector


def validate_frames_shape(frames: object) -> list[str]:
    # Full image validation is performed by decode_frames in the serial worker.
    if (not isinstance(frames, list) or not 1 <= len(frames) <= 3
            or any(not isinstance(frame, str) or not frame.startswith("data:image/")
                   or len(frame) > 4 * ((4 * 1024 * 1024 + 2) // 3) + 100
                   for frame in frames)):
        raise ValueError("Invia da una a tre immagini valide.")
    return frames


async def json_body(request: Request, fields: set[str]) -> dict:
    service = request.app.state.service
    service.begin_body_read()
    try:
        async with asyncio.timeout(BODY_READ_TIMEOUT_SECONDS):
            return await read_json_body(request, fields)
    except TimeoutError as exc:
        raise ApiError(408, "L'invio della richiesta ha superato il tempo disponibile. Riprova.") from exc
    finally:
        service.end_body_read()


async def read_json_body(request: Request, fields: set[str]) -> dict:
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise ApiError(415, "Invia il contenuto in formato JSON.")
    try:
        lengths = request.headers.getlist("content-length")
        if len(lengths) > 1:
            raise ValueError
        declared = int(lengths[0]) if lengths else 0
        if declared < 0:
            raise ValueError
    except ValueError as exc:
        raise ApiError(400, "Dimensione della richiesta non valida.") from exc
    if declared > MAX_BODY:
        raise ApiError(413, "Le immagini superano la dimensione massima.")
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > MAX_BODY:
            raise ApiError(413, "Le immagini superano la dimensione massima.")
        raw.extend(chunk)
    try:
        body = strict_json(bytes(raw))
    except (ValueError, RecursionError) as exc:
        raise ApiError(400, "Il contenuto JSON non è valido.") from exc
    if not isinstance(body, dict) or set(body) != fields:
        raise ApiError(400, "I campi della richiesta non sono validi.")
    return body


@dataclass
class Session:
    token: str
    expires: float
    last_seen: float
    entries: list[dict] = field(default_factory=list)
    photos: dict[str, bytes] = field(default_factory=dict)
    requests: list[dict] = field(default_factory=list)
    modified: bool = False
    pending_jobs: int = 0


@dataclass
class Job:
    token: str
    frames: list[str]
    submitted: float
    request_id: str | None = None
    entries: list[dict] = field(default_factory=list)
    engines: tuple[str, ...] = ()
    name: str = ""
    threshold: int = 0
    future: asyncio.Future | None = None
    timeline: Timeline | None = None


class Service:
    def __init__(self, engines, enroller, *, clock, session_ttl, max_sessions, queue_capacity,
                 default_gallery=None):
        self.engines, self.enroller = engines, enroller
        self.clock, self.session_ttl, self.max_sessions = clock, session_ttl, max_sessions
        self.sessions: dict[str, Session] = {}
        self.lock = threading.RLock()
        self.queue = asyncio.Queue(maxsize=queue_capacity)
        self.body_readers = 0
        self.engine_info = copy.deepcopy(engines.info())
        self.preparation_error = None
        self.closing = False
        self.default_gallery = default_gallery or DefaultGallery()
        self.events = EventHub()
        self.events_closed = False

    def begin_body_read(self):
        with self.lock:
            if self.body_readers >= MAX_BODY_READERS:
                raise ApiError(429, "Troppi invii contemporanei. Riprova tra poco.")
            self.body_readers += 1

    def end_body_read(self):
        with self.lock:
            self.body_readers -= 1

    def close_events(self):
        """Stop only event streams, including before the HTTP server drains connections."""
        with self.lock:
            self.events_closed = True
            self.events.close()

    def expire(self):
        with self.lock:
            for token in [t for t, s in self.sessions.items() if s.expires <= self.clock()]:
                self.remove_session(token)

    def remove_session(self, token: str):
        session = self.sessions.pop(token)
        # Pristine sessions share the default gallery; never mutate those objects.
        session.entries = []
        session.photos = {}
        session.requests.clear()
        self.events.notify(token)

    def reclaim_read_only_session(self, now: float):
        eligible = [session for session in self.sessions.values()
                    if not session.modified and not session.requests and not session.pending_jobs
                    and session.last_seen <= now - READ_ONLY_IDLE_SECONDS]
        if eligible:
            self.remove_session(min(eligible, key=lambda session: session.last_seen).token)

    def session(self, token: str | None, *, create=False, touch=False) -> tuple[Session, bool]:
        with self.lock:
            self.expire()
            now = self.clock()
            if token in self.sessions:
                session = self.sessions[token]
                if touch:
                    session.last_seen = now
                return session, False
            if not create:
                raise ApiError(401, "Sessione scaduta. Ricarica la pagina.")
            if len(self.sessions) >= self.max_sessions:
                self.reclaim_read_only_session(now)
            if len(self.sessions) >= self.max_sessions:
                raise ApiError(503, "Tutte le sessioni sono occupate. Riprova più tardi.")
            token = secrets.token_urlsafe(32)
            session = Session(token, now + self.session_ttl, now,
                              entries=self.default_gallery.entries,
                              photos=self.default_gallery.photos)
            self.sessions[token] = session
            return session, True

    def ready(self, engines: tuple[str, ...] = ()):
        if self.preparation_error:
            raise ApiError(503, self.preparation_error)
        self.engine_info = copy.deepcopy(self.engines.info())
        ready = {item["id"] for item in self.engine_info if item["pronto"]}
        if not set(engines) <= ready:
            raise ApiError(503, "Il motore richiesto non è disponibile.")

    def enqueue(self, job: Job):
        with self.lock:
            if self.closing:
                raise ApiError(503, "Il servizio si sta chiudendo.")
            session, _ = self.session(job.token)
            try:
                self.queue.put_nowait(job)
            except asyncio.QueueFull as exc:
                raise ApiError(429, "La coda è piena. Attendi il completamento di una richiesta.") from exc
            session.pending_jobs += 1

    def update(self, job: Job, **values):
        with self.lock:
            session, _ = self.session(job.token)
            row = next(row for row in session.requests if row["id"] == job.request_id)
            row.update(values)
            self.events.notify(job.token)

    def public_status(self, session):
        with self.lock:
            self.engine_info = copy.deepcopy(self.engines.info())
            result = {"sessione": {"scadenza": timestamp(session.expires)},
                      "motori": copy.deepcopy(self.engine_info), "iscritti": len(session.entries),
                      "pronto": not self.preparation_error and any(m["pronto"] for m in self.engine_info)}
            if self.preparation_error:
                result["errore"] = self.preparation_error
            return result

    def public_gallery(self, session):
        with self.lock:
            return {"iscritti": [public_entry(e, self.default_gallery.metadata.get(e["id"]))
                                 for e in session.entries], "totale": len(session.entries)}

    def public_requests(self, session):
        with self.lock:
            rows = []
            for row in reversed(session.requests):
                public = copy.deepcopy({key: value for key, value in row.items() if key != "_timeline"})
                public["timeline"] = row["_timeline"].snapshot()
                rows.append(public)
            return {"richieste": rows, "totale": len(rows)}

    async def stream_events(self, subscription):
        previous = {}
        last_sent = asyncio.get_running_loop().time()
        try:
            while not subscription.closed:
                subscription.consume()
                with self.lock:
                    if self.closing or self.events_closed:
                        return
                    try:
                        session, _ = self.session(subscription.token)
                    except ApiError:
                        session = None
                    if session is not None:
                        snapshots = {"stato": self.public_status(session),
                                     "galleria": self.public_gallery(session),
                                     "richieste": self.public_requests(session)}
                        active = any(row["stato"] not in TERMINAL for row in session.requests)
                        remaining = session.expires - self.clock()
                if session is None:
                    yield encode_event("scaduta", {"errore": "Sessione scaduta. Ricarica la pagina."})
                    return
                for name, body in snapshots.items():
                    encoded = encode_event(name, body)
                    if previous.get(name) != encoded:
                        previous[name] = encoded
                        yield encoded
                        last_sent = asyncio.get_running_loop().time()
                now = asyncio.get_running_loop().time()
                if now - last_sent >= HEARTBEAT_SECONDS:
                    yield ": keep-alive\n\n"
                    last_sent = asyncio.get_running_loop().time()
                timeout = min(remaining, TIMELINE_SECONDS if active else HEARTBEAT_SECONDS,
                              max(0, HEARTBEAT_SECONDS - (asyncio.get_running_loop().time() - last_sent)))
                await subscription.wait(max(0, timeout))
        finally:
            self.events.unsubscribe(subscription)

    def execute(self, job: Job):
        self.session(job.token)
        if job.future is not None and job.future.cancelled():
            return None
        started = time.perf_counter()
        if job.request_id:
            with self.lock:
                now = clock_ns()
                job.timeline.end("queue", now)
                job.timeline.begin("prepare", "prepare", "job", now)
                self.update(job, stato="preparazione", attesa_ms=(started - job.submitted) * 1000)
        try:
            frames = decode_frames(job.frames)
            vector, photo = self.enroller(frames)
        except AccessError as exc:
            raise ApiError(exc.status, exc.message) from exc
        except ValueError as exc:
            raise ApiError(400, str(exc)) from exc
        job.frames.clear()
        prepared = time.perf_counter()
        self.session(job.token)
        if not job.request_id:
            identifier = str(uuid.uuid4())
            entry = {"id": identifier, "nome": job.name, "soglia": job.threshold,
                     "vettore": vector, "foto_file": identifier + ".jpg", "origine": "registrato"}
            with self.lock:
                session, _ = self.session(job.token)
                if len(session.entries) >= MAX_ENTRIES:
                    raise ApiError(409, "La galleria contiene già 128 iscritti.")
                try:
                    session.entries = validate_entries(session.entries + [entry])
                except ValueError as exc:
                    raise ApiError(400, str(exc)) from exc
                session.photos = {**session.photos, identifier: bytes(photo)}
                session.modified = True
                self.events.notify(job.token)
                return {"iscritto": public_entry(entry), "totale": len(session.entries)}
        query = validate_query(vector)
        with self.lock:
            job.timeline.end("prepare")
            self.update(job, preparazione_ms=(prepared - started) * 1000)
        results = []

        def progress(stage):
            if stage not in STAGES:
                raise ValueError("Stato del motore non valido.")
            self.update(job, stato=stage)

        for engine in job.engines:
            self.session(job.token)
            with self.lock:
                job.timeline.begin(engine, "engine", "job", engine=engine)
            # Keep the submitted gallery independent of worker mutations.
            result = self.engines.verify(list(query), copy.deepcopy(job.entries), engine, progress)
            result = copy.deepcopy(result)
            index = result["selected_id"]
            if (result["motore"] != engine or type(index) is not int
                    or not 0 <= index <= len(job.entries)
                    or result["esito"] != ("aperto" if index else "negato")):
                raise RuntimeError("Risultato del motore non valido.")
            if index:
                result["selected_name"] = job.entries[index - 1]["nome"]
            with self.lock:
                job.timeline.end(engine)
                job.timeline.add_phases(engine, result.pop("spans_ns", []))
            results.append(result)
            self.update(job, risultati=copy.deepcopy(results))
        values = {"stato": "completata", "risultati": results,
                  "tempo_complessivo_ms": (time.perf_counter() - job.submitted) * 1000}
        if len({result["esito"] for result in results}) == 1:
            values["esito"] = results[0]["esito"]
        if len(results) == 1:
            values["tempi_ms"] = results[0]["tempi_ms"]
        with self.lock:
            job.timeline.finish()
            self.update(job, **values)

    async def work(self):
        while True:
            try:
                job = await asyncio.wait_for(self.queue.get(), timeout=min(60, self.session_ttl))
            except asyncio.TimeoutError:
                self.expire()
                continue
            if job is None:
                self.queue.task_done()
                return
            try:
                if self.closing:
                    raise ApiError(503, "Il servizio si sta chiudendo.")
                result = await run_in_threadpool(self.execute, job)
                if job.future is not None and not job.future.done():
                    job.future.set_result(result)
            except Exception as exc:
                message = exc.message if isinstance(exc, ApiError) else "La preparazione o la verifica non è riuscita. Riprova."
                if job.request_id:
                    try:
                        with self.lock:
                            job.timeline.finish(error=True)
                            self.update(job, stato="errore", errore=message,
                                        tempo_complessivo_ms=(time.perf_counter() - job.submitted) * 1000)
                    except ApiError:
                        pass  # Expired sessions must never be recreated by queued work.
                elif job.future is not None and not job.future.done():
                    job.future.set_exception(exc if isinstance(exc, ApiError) else ApiError(503, message))
            finally:
                job.frames.clear()
                job.entries.clear()
                with self.lock:
                    session = self.sessions.get(job.token)
                    if session is not None:
                        session.pending_jobs -= 1
                self.queue.task_done()


def create_app(*, engines=None, enroller=None, default_gallery=None, clock=time.time, session_ttl=3600,
               max_sessions=None, queue_capacity=8, public_origin=None, additional_origins=None) -> FastAPI:
    max_sessions = session_limit(os.environ.get("VARCO_WEB_MAX_SESSIONS", str(DEFAULT_MAX_SESSIONS))
                                 if max_sessions is None else max_sessions)
    configured_origin = public_origin if public_origin is not None else os.environ.get("VARCO_WEB_PUBLIC_ORIGIN")
    hosted_origin = normalize_public_origin(configured_origin) if configured_origin is not None else None
    if additional_origins is None:
        extra = os.environ.get("VARCO_WEB_ADDITIONAL_ORIGINS", "")
        additional_origins = [value.strip() for value in extra.split(",")] if extra else []
    additional_origins = [normalize_public_origin(value) for value in additional_origins]
    if additional_origins and hosted_origin is None:
        raise ValueError("Le origini aggiuntive richiedono un'origine pubblica principale.")
    hosted_origins = {urlsplit(value).netloc: value for value in [hosted_origin, *additional_origins] if value}

    @asynccontextmanager
    async def lifespan(app):
        actual_engines = engines
        if actual_engines is None:
            from .engines import EngineSet
            actual_engines = await run_in_threadpool(EngineSet)
        actual_enroller = enroller
        if actual_enroller is None:
            processor = EnrollmentProcessor()

            def actual_enroller(frames):
                check_local_models()
                return processor(frames)

        service = Service(actual_engines, actual_enroller, clock=clock,
                          session_ttl=session_ttl, max_sessions=max_sessions,
                          queue_capacity=queue_capacity, default_gallery=default_gallery)
        if enroller is None:
            try:
                await run_in_threadpool(check_local_models)
                if default_gallery is None:
                    service.default_gallery = await run_in_threadpool(prepare_gallery, actual_enroller)
            except AccessError:
                service.preparation_error = "I modelli locali del volto non sono disponibili."
            except Exception:
                logging.getLogger(__name__).exception("Preparazione della galleria iniziale non riuscita")
                service.preparation_error = "La galleria iniziale non è disponibile. Controlla l'avvio della demo."
        app.state.service = service
        worker = asyncio.create_task(service.work())
        try:
            yield
        finally:
            service.closing = True
            service.close_events()
            await service.queue.put(None)
            await worker
            with service.lock:
                service.sessions.clear()
            await run_in_threadpool(actual_engines.close)

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.public_origin = hosted_origin

    @app.exception_handler(ApiError)
    async def api_error(_request, exc):
        return JSONResponse({"errore": exc.message}, status_code=exc.status)

    @app.exception_handler(ValueError)
    async def invalid_value(_request, exc):
        return JSONResponse({"errore": str(exc)}, status_code=400)

    @app.middleware("http")
    async def origin_session(request, call_next):
        try:
            hosts = request.headers.getlist("host")
            host = hosts[0] if len(hosts) == 1 else ""
            if hosted_origin:
                origin = hosted_origins.get(host)
                if origin is None:
                    raise ApiError(403, "Host della richiesta non consentito.")
                # Match Origin to this Host, even when several hosts are allowed.
            else:
                parsed = urlsplit("//" + host)
                if (parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
                        or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment):
                    raise ApiError(403, "Questa pagina è disponibile soltanto in locale.")
                _ = parsed.port
                origin = f"{request.url.scheme}://{host}"
            supplied = request.headers.getlist("origin")
            landing = request.method in {"GET", "HEAD"} and request.url.path == "/"
            navigation = (landing and request.headers.get("sec-fetch-mode") == "navigate"
                          and request.headers.get("sec-fetch-dest") == "document")
            if (len(supplied) > 1 or (supplied and supplied[0] != origin)
                    or (request.headers.get("sec-fetch-site") in {"cross-site", "same-site"}
                        and not navigation)):
                raise ApiError(403, "Origine della richiesta non consentita.")
            if request.method not in {"GET", "HEAD", "OPTIONS"} and not supplied:
                raise ApiError(403, "Origine della richiesta mancante.")
            session = None
            fresh = False
            if request.url.path.startswith("/api/"):
                service = request.app.state.service
                session, fresh = service.session(
                    request.cookies.get(COOKIE), create=request.method == "GET"
                    and request.url.path == "/api/stato", touch=request.url.path != "/api/eventi")
                request.state.session = session
            response = await call_next(request)
            if fresh:
                response.set_cookie(COOKIE, session.token, max_age=int(service.session_ttl),
                                    httponly=True, secure=hosted_origin is not None, samesite="lax", path="/")
        except ApiError as exc:
            response = JSONResponse({"errore": exc.message}, status_code=exc.status)
        except ValueError:
            response = JSONResponse({"errore": "Richiesta non valida."}, status_code=400)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'"
        return response

    def current(request):
        service = request.app.state.service
        return service, service.session(request.state.session.token)[0]

    @app.api_route("/", methods=["GET", "HEAD"])
    async def index():
        return FileResponse(HERE / "static/index.html")

    @app.get("/api/stato")
    async def status(request: Request):
        service, session = current(request)
        return service.public_status(session)

    @app.get("/api/galleria")
    async def gallery(request: Request):
        service, session = current(request)
        return service.public_gallery(session)

    @app.post("/api/galleria", status_code=201)
    async def enroll(request: Request):
        body = await json_body(request, {"nome", "soglia", "frames"})
        name, threshold = validate_name(body["nome"]), validate_threshold(body["soglia"])
        frames = validate_frames_shape(body["frames"])
        service, session = current(request)
        service.ready()
        with service.lock:
            if len(session.entries) >= MAX_ENTRIES:
                raise ApiError(409, "La galleria contiene già 128 iscritti.")
        future = asyncio.get_running_loop().create_future()
        service.enqueue(Job(session.token, frames, time.perf_counter(), name=name,
                            threshold=threshold, future=future))
        return await future

    @app.patch("/api/galleria/{identifier}")
    async def edit(identifier: str, request: Request):
        body = await json_body(request, {"nome", "soglia"})
        name, threshold = validate_name(body["nome"]), validate_threshold(body["soglia"])
        service, session = current(request)
        with service.lock:
            entry = next((e for e in session.entries if e["id"] == identifier), None)
            if entry is None:
                raise ApiError(404, "Iscritto non trovato.")
            entry = dict(entry, nome=name, soglia=threshold)
            session.entries = [entry if e["id"] == identifier else e for e in session.entries]
            session.modified = True
            service.events.notify(session.token)
            return {"iscritto": public_entry(entry, service.default_gallery.metadata.get(identifier)),
                    "totale": len(session.entries)}

    @app.delete("/api/galleria/{identifier}")
    async def delete(identifier: str, request: Request):
        service, session = current(request)
        with service.lock:
            if not any(e["id"] == identifier for e in session.entries):
                raise ApiError(404, "Iscritto non trovato.")
            session.entries = [e for e in session.entries if e["id"] != identifier]
            session.photos = {key: photo for key, photo in session.photos.items() if key != identifier}
            session.modified = True
            service.events.notify(session.token)
            return {"totale": len(session.entries)}

    @app.get("/api/foto/{identifier}")
    async def photo(identifier: str, request: Request):
        service, session = current(request)
        with service.lock:
            content = session.photos.get(identifier)
            if content is None:
                raise ApiError(404, "Foto non trovata.")
            return Response(content, media_type="image/jpeg")

    @app.post("/api/accesso", status_code=202)
    async def access(request: Request):
        body = await json_body(request, {"frames", "motore"})
        frames = validate_frames_shape(body["frames"])
        engine = body["motore"]
        if engine != "attuale":
            raise ApiError(400, "La demo usa soltanto la versione attuale.")
        selected = ("attuale",)
        service, session = current(request)
        service.ready(selected)
        with service.lock:
            if not session.entries:
                raise ApiError(409, "Iscrivi almeno una persona prima della verifica.")
            identifier = str(uuid.uuid4())
            retained = list(session.requests)
            while len(retained) >= MAX_REQUESTS:
                oldest = next((r for r in retained if r["stato"] in TERMINAL), None)
                if oldest is None:
                    raise ApiError(429, "Attendi il completamento delle richieste in corso.")
                retained.remove(oldest)
            job = Job(session.token, frames, time.perf_counter(), request_id=identifier,
                      entries=copy.deepcopy(session.entries), engines=selected, timeline=Timeline())
            service.enqueue(job)
            session.requests = retained
            session.requests.append({"id": identifier, "ora": timestamp(service.clock()),
                                     "stato": "in_attesa", "motore": engine,
                                     "iscritti": len(job.entries), "_timeline": job.timeline})
            service.events.notify(session.token)
        return {"richiesta_id": identifier}

    @app.get("/api/richieste")
    async def requests(request: Request):
        service, session = current(request)
        return service.public_requests(session)

    @app.get("/api/eventi")
    async def events(request: Request):
        service, session = current(request)
        with service.lock:
            if service.closing or service.events_closed:
                raise ApiError(503, "Il servizio si sta chiudendo.")
            try:
                subscription = service.events.subscribe(session.token)
            except ValueError as exc:
                raise ApiError(429, str(exc)) from exc
        return EventResponse(service.stream_events(subscription), service.events, subscription)

    app.mount("/static", StaticFiles(directory=HERE / "static", check_dir=False), name="static")
    @app.get("/shared/shared.js")
    async def shared_script():
        return FileResponse(HERE.parent / "dual_view/static/shared.js", media_type="text/javascript")

    @app.get("/shared/shared.css")
    async def shared_style():
        return FileResponse(HERE.parent / "dual_view/static/shared.css", media_type="text/css")

    app.add_middleware(SSEWriteTimeoutMiddleware)
    return app
