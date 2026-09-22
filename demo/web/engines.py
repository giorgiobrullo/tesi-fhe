"""Owned native workers for the trusted web demo, with one query at a time."""

from __future__ import annotations

import json
import logging
import math
import os
from pathlib import Path
import select
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid

from runtime.client.configuration import ClientConfiguration
from runtime.client.pipeline import AccessPipeline

ROOT = Path(__file__).resolve().parents[2]
ENGINE_NAMES = {"attuale": "Attuale"}
A28_CORE_SHA256 = "7ad812724bf43742d9d03ec9db204e93d6a2c0db3e6ea9dbc650054633fa3596"
PHASE_KINDS = ("setup", "encryption", "fhe", "decryption")


def clock_ns() -> int:
    """Use the same OS clock as the native adapter, including on macOS."""
    try:
        value = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    except (AttributeError, OSError, OverflowError):
        raise RuntimeError("Orologio delle fasi non disponibile.") from None
    if type(value) is not int or value < 0:
        raise RuntimeError("Orologio delle fasi non valido.")
    return value


def validate_spans(spans, parent_start_ns: int, parent_end_ns: int) -> list[dict]:
    """Reject malformed or cross-clock spans instead of inventing offsets."""
    error = "Il motore ha restituito intervalli temporali non validi."
    if (type(parent_start_ns) is not int or type(parent_end_ns) is not int
            or not 0 <= parent_start_ns <= parent_end_ns
            or not isinstance(spans, list) or len(spans) > len(PHASE_KINDS)):
        raise RuntimeError(error)
    result = []
    previous_end, previous_kind = parent_start_ns, -1
    for span in spans:
        if not isinstance(span, dict) or set(span) != {"kind", "start_ns", "end_ns"}:
            raise RuntimeError(error)
        kind, start, end = span["kind"], span["start_ns"], span["end_ns"]
        if (kind not in PHASE_KINDS or type(start) is not int or type(end) is not int
                or not previous_end <= start <= end <= parent_end_ns):
            raise RuntimeError(error)
        position = PHASE_KINDS.index(kind)
        if position <= previous_kind:
            raise RuntimeError(error)
        result.append(dict(span))
        previous_end, previous_kind = end, position
    return result


def validate_input(query: list[int], entries: list[dict]) -> int:
    """The common domain and first-minimum rule of both native engines."""
    if not isinstance(entries, list) or not 1 <= len(entries) <= 128:
        raise ValueError("La galleria deve contenere da 1 a 128 persone.")
    vectors = [query, *(entry["vettore"] for entry in entries)]
    for vector in vectors:
        if (not isinstance(vector, list) or len(vector) != 512
                or any(type(value) is not int or not -3 <= value <= 3 for value in vector)):
            raise ValueError("Il volto non rientra nel dominio delle due versioni.")
    if sum(value * value for value in query) > 1024:
        raise ValueError("Il volto non rientra nel dominio delle due versioni.")
    bounds = []
    scores = []
    identifiers = set()
    for entry in entries:
        if (not isinstance(entry["id"], str) or len(entry["id"]) > 128
                or not entry["id"] or any(character.isspace() for character in entry["id"])
                or entry["id"] in identifiers):
            raise ValueError("Identificatore della galleria non valido.")
        identifiers.add(entry["id"])
        if type(entry["soglia"]) is not int or not -(1 << 63) <= entry["soglia"] < (1 << 63):
            raise ValueError("Soglia non valida.")
        vector = entry["vettore"]
        norm = sum(value * value for value in vector)
        radius = math.isqrt(norm * 1024)
        if radius * radius != norm * 1024:
            radius += 1
        bounds.append((norm - 2 * radius, norm + 2 * radius))
        scores.append(norm - 2 * sum(left * right for left, right in zip(query, vector)))
    if max(bound[1] for bound in bounds) - min(bound[0] for bound in bounds) + 1 > 4096:
        raise ValueError("Questa galleria supera il dominio delle due versioni.")
    winner = min(range(len(scores)), key=scores.__getitem__)
    return winner + 1 if scores[winner] <= entries[winner]["soglia"] else 0


def stop_owned(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


class LocalTransport:
    def __init__(self, port: int):
        self.base = f"http://127.0.0.1:{port}"
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def __call__(self, path, data=None, ctype="application/octet-stream", timeout=180):
        if path not in {"/stato", "/chiave", "/reset", "/iscrivi", "/varco"}:
            raise ValueError("Operazione del motore non disponibile.")
        request = urllib.request.Request(self.base + path, data=data,
                                         headers={"Content-Type": ctype} if data is not None else {})
        with self.opener.open(request, timeout=timeout) as response:
            body = response.read(4 * 1024 * 1024 + 1)
            if len(body) > 4 * 1024 * 1024:
                raise RuntimeError("Risposta del motore troppo grande.")
            return body, dict(response.headers)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class CurrentEngine:
    def __init__(self, binary: Path, keys: Path, directory: Path, port: int):
        self.process = None
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                raise RuntimeError("La porta del motore è già occupata; nessun servizio è stato sostituito.")
        environment = os.environ.copy()
        environment["RAYON_NUM_THREADS"] = "16"
        self.transport = LocalTransport(port)
        try:
            with (directory / "current.log").open("ab") as log:
                self.process = subprocess.Popen([str(binary), "serve", str(port), "512", "4"],
                                                stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                                env=environment)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError("Il motore attuale non è partito.")
                try:
                    self.transport("/stato", timeout=1)
                    break
                except (OSError, urllib.error.URLError):
                    time.sleep(.1)
            else:
                raise RuntimeError("Il motore attuale non risponde.")
            self.pipeline = AccessPipeline(ClientConfiguration(ROOT / "runtime", binary, keys), self.transport)
            self.pipeline.require_existing_keys()
            self.pipeline.assicura_chiave()
        except BaseException:
            self.close()
            raise

    def alive(self):
        return self.process is not None and self.process.poll() is None

    def set_gallery(self, entries):
        self.transport("/reset", b"")
        for entry in entries:
            body = f"{entry['id']}\t{entry['soglia']}\n" + " ".join(map(str, entry["vettore"]))
            self.transport("/iscrivi", body.encode(), "text/plain; charset=utf-8")
        state, snapshot = self.pipeline.server_status()
        if (snapshot["nomi"] != tuple(entry["id"] for entry in entries)
                or state["soglie"] != [entry["soglia"] for entry in entries]):
            raise RuntimeError("La galleria del motore non corrisponde alla richiesta.")

    def verify(self, query, entries, progress):
        try:
            return self._verify(query, entries, progress)
        finally:
            try:
                self.transport("/reset", b"")
            except Exception:
                self.close()
                raise RuntimeError("Il motore è stato chiuso per liberare la galleria temporanea.") from None

    def _verify(self, query, entries, progress):
        setup_start = clock_ns()
        self.set_gallery(entries)
        self.pipeline.assicura_chiave()
        snapshot = self.pipeline.snapshot_galleria()
        spans = [{"kind": "setup", "start_ns": setup_start, "end_ns": clock_ns()}]
        progress("cifratura")
        encryption_start = clock_ns()
        started = time.perf_counter()
        ciphertext, _ = self.pipeline.cifra(query, snapshot["query_profile"])
        encryption_ms = (time.perf_counter() - started) * 1000
        spans.append({"kind": "encryption", "start_ns": encryption_start, "end_ns": clock_ns()})
        progress("elaborazione")
        fhe_start = clock_ns()
        started = time.perf_counter()
        encrypted_result, headers = self.transport("/varco", ciphertext)
        network_ms = (time.perf_counter() - started) * 1000
        # This interval includes local transport. The native duration stays in tempi_ms.server.
        spans.append({"kind": "fhe", "start_ns": fhe_start, "end_ns": clock_ns()})
        headers = self.pipeline.valida_header_varco(headers, snapshot)
        progress("decifratura")
        decryption_start = clock_ns()
        started = time.perf_counter()
        decoded = self.pipeline.decifra(encrypted_result)
        self.pipeline.identita_da_esito(decoded, snapshot)
        decryption_ms = (time.perf_counter() - started) * 1000
        spans.append({"kind": "decryption", "start_ns": decryption_start, "end_ns": clock_ns()})
        return {
            "selected_id": decoded["codice"],
            "spans_ns": spans,
            "tempi_ms": {"cifratura": encryption_ms, "server": float(headers["x-tempo-ms"]),
                         "decifratura": decryption_ms, "rete_e_server": network_ms},
            "sizes": {"probe_cifrato": len(ciphertext), "esito_cifrato": len(encrypted_result)},
        }

    def close(self):
        stop_owned(self.process)


class A28Engine:
    def __init__(self, binary: Path, keys: Path, directory: Path):
        self.process = None
        try:
            with (directory / "a28.log").open("ab") as log:
                self.process = subprocess.Popen([str(binary), "--keys", str(keys), "--threads", "16"],
                                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                stderr=log, bufsize=0)
            os.set_blocking(self.process.stdin.fileno(), False)
            status = self.exchange({"command": "status"}, timeout=600)
            if (status.get("ready") is not True or status.get("core_sha256") != A28_CORE_SHA256
                    or status.get("threads") != 16):
                raise RuntimeError("A28 non è pronta.")
        except BaseException:
            self.close()
            raise

    def alive(self):
        return self.process is not None and self.process.poll() is None

    def exchange(self, payload, timeout=180):
        identifier = uuid.uuid4().hex
        data = json.dumps({**payload, "id": identifier}, separators=(",", ":")).encode() + b"\n"
        if not self.alive():
            raise RuntimeError("A28 non è disponibile.")
        try:
            deadline = time.monotonic() + timeout
            remaining_input = memoryview(data)
            while remaining_input:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([], [self.process.stdin], [], remaining)[1]:
                    raise TimeoutError("A28 non ha ricevuto la richiesta entro il tempo disponibile.")
                try:
                    written = os.write(self.process.stdin.fileno(), remaining_input)
                except BlockingIOError:
                    continue
                if not written:
                    raise RuntimeError("A28 non ha ricevuto la richiesta.")
                remaining_input = remaining_input[written:]
            output = bytearray()
            while b"\n" not in output:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                    raise TimeoutError("A28 non ha terminato entro il tempo disponibile.")
                block = os.read(self.process.stdout.fileno(), 4096)
                if not block or len(output) + len(block) > 65536:
                    raise RuntimeError("A28 ha restituito una risposta incompleta.")
                output.extend(block)
            response = json.loads(output)
            if not isinstance(response, dict) or response.get("id") != identifier:
                raise RuntimeError("La risposta A28 non corrisponde alla richiesta.")
        except BaseException:
            self.close()
            raise
        if "error" in response:
            raise ValueError(response["error"].get("message", "A28 non ha completato la verifica."))
        return response

    def verify(self, query, entries, progress):
        # The legacy adapter has one synchronous call; do not invent intermediate progress.
        progress("elaborazione")
        response = self.exchange({"query": query, "gallery": [entry["vettore"] for entry in entries],
                                  "thresholds": [entry["soglia"] for entry in entries]})
        times = response["timings_ms"]
        return {"selected_id": response["selected_id"],
                "tempi_ms": {"cifratura": times["encryption"], "server": times["server"],
                             "decifratura": times["decryption"]},
                "sizes": response["sizes"],
                "spans_ns": response.get("spans_ns", [])}

    def close(self):
        stop_owned(self.process)
        if self.process is not None:
            for stream in (self.process.stdin, self.process.stdout):
                if stream is not None:
                    stream.close()


class EngineSet:
    def __init__(self):
        self.lock = threading.Lock()
        self.workers = {}
        self.errors = {}
        directory = Path(os.environ.get("VARCO_WEB_STATE", ROOT / "demo/web/.local")).resolve()
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        binary_value = os.environ.get("VARCO_WEB_BINARY")
        keys_value = os.environ.get("VARCO_WEB_KEYS")
        if not binary_value or not keys_value:
            self.errors["attuale"] = "Motore non configurato."
            return
        binary, keys = Path(binary_value), Path(keys_value)
        if not binary.is_absolute() or not binary.is_file() or not keys.is_absolute():
            self.errors["attuale"] = "Percorsi del motore non validi."
            return
        try:
            port = int(os.environ.get("VARCO_WEB_NATIVE_PORT", "9010"))
            self.workers["attuale"] = CurrentEngine(binary, keys, directory, port)
        except Exception:
            logging.getLogger(__name__).exception("Avvio del motore attuale non riuscito")
            self.errors["attuale"] = "Avvio del motore non riuscito. Consulta il log locale."

    def info(self):
        rows = []
        for identifier, name in ENGINE_NAMES.items():
            ready = identifier in self.workers and self.workers[identifier].alive()
            row = {"id": identifier, "nome": name, "pronto": ready}
            if not ready:
                row["errore"] = self.errors.get(identifier, "Motore non disponibile. Riavvia la demo.")
            rows.append(row)
        return rows

    def verify(self, query, entries, engine, progress):
        if engine not in ENGINE_NAMES:
            raise RuntimeError("Il motore selezionato non è disponibile nella demo.")
        expected = validate_input(query, entries)
        with self.lock:
            if engine not in self.workers or not self.workers[engine].alive():
                raise RuntimeError("Il motore selezionato non è disponibile.")
            parent_start_ns = clock_ns()
            started = time.perf_counter()
            result = self.workers[engine].verify(query, entries, progress)
            parent_end_ns = clock_ns()
            code = result["selected_id"]
            if type(code) is not int or code != expected:
                raise RuntimeError("La verifica cifrata non coincide con il controllo di correttezza.")
            times = result["tempi_ms"]
            if any(type(value) not in (int, float) or not math.isfinite(value) or value < 0 for value in times.values()):
                raise RuntimeError("Il motore ha restituito tempi non validi.")
            times["totale"] = (time.perf_counter() - started) * 1000
            result["spans_ns"] = validate_spans(result.get("spans_ns", []), parent_start_ns, parent_end_ns)
            result.update(motore=engine, esito="aperto" if code else "negato")
            result["tempi_ms"] = {key: round(value, 3) for key, value in times.items()}
            return result

    def close(self):
        with self.lock:
            for worker in self.workers.values():
                worker.close()
