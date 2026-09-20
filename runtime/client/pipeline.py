"""Trusted access operations with per-client state and injected I/O."""
from dataclasses import dataclass
import hashlib
import pathlib
import tempfile
import time

from . import protocol
from .adapters import RustRunner
from .configuration import ClientConfiguration


@dataclass(frozen=True)
class Verification:
    decoded: dict
    identity: str | None
    snapshot: dict
    headers: dict
    timings_ms: dict
    sizes: dict


class AccessPipeline:
    def __init__(self, settings: ClientConfiguration, transport, runner=None, embedder=None):
        self.settings = settings
        self.config = settings.load()
        self.srv = transport
        self._run = runner if runner is not None else RustRunner(settings.binary)
        self._embedder = embedder
        self.messages = []
        self.ready = False
        self.gallery_snapshot = None
        self._key_hash_cache = None
        self._g4_hash_cache = None

    def log(self, message):
        print(message, flush=True)
        self.messages.append(message)

    @property
    def embedder(self):
        if self._embedder is None:
            from .embedding import FaceEmbedding
            self._embedder = FaceEmbedding(self.config, self.settings.assets, self.log)
        return self._embedder

    @property
    def model_loaded(self):
        return self._embedder is not None and self._embedder.loaded

    def da_dataurl(self, value):
        return self.embedder.da_dataurl(value)

    def embedding_fuso(self, frames_rgb, gia_allineati=False):
        return self.embedder.embedding_fuso(frames_rgb, gia_allineati=gia_allineati)

    def require_existing_keys(self):
        for name in ("client.key", "server.key"):
            path = self.settings.keys / name
            if not path.is_file() or path.stat().st_size == 0:
                raise RuntimeError("coppia di chiavi locale mancante o incompleta; avvio interrotto")
        if (self.settings.keys / "g4.key").exists() != self.config["contratto_esatto"]["g4_required"]:
            raise RuntimeError("file G4 locale incoerente con il circuito selezionato; non sostituire le chiavi")

    def server_status(self):
        raw, _ = self.srv("/stato")
        state = protocol.strict_json(raw)
        snapshot = protocol.validate_status(state, self.config["contratto_esatto"], allow_empty=True)
        return state, snapshot

    def verify_vector(self, query):
        self.assicura_chiave()
        started = time.perf_counter()
        snapshot = self.snapshot_galleria()
        ciphertext, _ = self.cifra(query, snapshot["query_profile"])
        encryption_ms = (time.perf_counter() - started) * 1000

        started = time.perf_counter()
        encrypted_result, headers = self.srv("/varco", ciphertext)
        network_ms = (time.perf_counter() - started) * 1000
        # Validate the gallery binding before decrypting or releasing an identity.
        headers = self.valida_header_varco(headers, snapshot)

        started = time.perf_counter()
        decoded = self.decifra(encrypted_result)
        decryption_ms = (time.perf_counter() - started) * 1000
        identity = self.identita_da_esito(decoded, snapshot)
        return Verification(
            decoded, identity, snapshot, headers,
            {"cifratura": round(encryption_ms, 1),
             "server": float(headers["x-tempo-ms"]),
             "rete_e_server": round(network_ms, 1),
             "decifratura": round(decryption_ms, 1)},
            {"probe_cifrato": len(ciphertext), "esito_cifrato": len(encrypted_result)},
        )

    def cifra(self, vettore, query_profile):
        with tempfile.TemporaryDirectory() as d:
            p, c = f"{d}/probe.txt", f"{d}/probe.ct"
            pathlib.Path(p).write_text(" ".join(map(str, vettore)))
            if query_profile != "head51":
                raise RuntimeError("profilo pubblico del probe mancante o errato")
            info = self._run("encrypt", self.settings.keys, p, c, query_profile)
            return pathlib.Path(c).read_bytes(), info

    def decifra(self, esito_bytes):
        with tempfile.TemporaryDirectory() as d:
            c = f"{d}/esito.ct"
            pathlib.Path(c).write_bytes(esito_bytes)
            return self._run("decrypt", self.settings.keys, c)

    def valida_header_varco(self, headers, snapshot):
        """Vincola contratto, profilo e contatori alla galleria letta prima di cifrare."""
        return protocol.validate_headers(headers, self.config["contratto_esatto"], snapshot)

    def fingerprint_chiave_locale(self):
        """SHA-256 della evaluation key locale, in cache finche' il file non cambia."""

        path = self.settings.keys / "server.key"
        stat = path.stat()
        firma_file = (
            str(path.resolve()),
            stat.st_dev,
            stat.st_ino,
            stat.st_size,
            stat.st_mtime_ns,
            stat.st_ctime_ns,
        )
        if self._key_hash_cache is not None and self._key_hash_cache[0] == firma_file:
            return self._key_hash_cache[1]

        digest = hashlib.sha256()
        with path.open("rb") as key_file:
            for chunk in iter(lambda: key_file.read(1024 * 1024), b""):
                digest.update(chunk)
        fingerprint = digest.hexdigest()
        self._key_hash_cache = (firma_file, fingerprint)
        return fingerprint

    def valida_fingerprint_chiave(self, stato_server, atteso=None):
        """Vincola lo stato remoto alla evaluation key posseduta da questo client."""

        if stato_server.get("chiave") is not True:
            raise RuntimeError(
                "il server non dichiara una chiave di valutazione installata"
            )
        fingerprint_server = stato_server.get("chiave_sha256")
        if (
            not isinstance(fingerprint_server, str)
            or len(fingerprint_server) != 64
            or any(c not in "0123456789abcdef" for c in fingerprint_server)
        ):
            raise RuntimeError(
                "fingerprint SHA-256 della chiave server mancante o non valido"
            )
        fingerprint_locale = self.fingerprint_chiave_locale() if atteso is None else atteso
        if fingerprint_server != fingerprint_locale:
            raise RuntimeError(
                "la chiave di valutazione del server non coincide con server.key del client"
            )
        return fingerprint_server

    def snapshot_galleria(self):
        """Conserva piano, nomi e versione della galleria prima della cifratura."""
        raw, _ = self.srv("/stato")
        stato_server = protocol.strict_json(raw)
        snapshot = protocol.validate_status(stato_server, self.config["contratto_esatto"])
        self.valida_fingerprint_chiave(stato_server)
        self.valida_fingerprint_g4(stato_server)
        self.gallery_snapshot = snapshot
        return snapshot

    def identita_da_esito(self, decifrato, snapshot):
        return protocol.decode_identity(decifrato, snapshot, self.config["contratto_esatto"])

    def fingerprint_g4_locale(self):
        path = self.settings.keys / "g4.key"
        stat = path.stat()
        signature = (str(path.resolve()), stat.st_dev, stat.st_ino, stat.st_size,
                     stat.st_mtime_ns, stat.st_ctime_ns)
        if self._g4_hash_cache is None or self._g4_hash_cache[0] != signature:
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            self._g4_hash_cache = signature, digest.hexdigest()
        return self._g4_hash_cache[1]

    def valida_fingerprint_g4(self, state):
        if self.config["contratto_esatto"]["g4_required"]:
            protocol.same(state.get("g4_sha256"), self.fingerprint_g4_locale(), "chiave G4 locale/server")
            protocol.same(state.get("g4_ready"), True, "prontezza G4")
        elif state.get("g4_sha256") is not None:
            raise RuntimeError("chiave G4 inattesa nel circuito senza G4")

    def assicura_g4(self, state):
        if not self.config["contratto_esatto"]["g4_required"]:
            self.valida_fingerprint_g4(state)
            return
        if state.get("g4_sha256") is None:
            path = self.settings.keys / "g4.key"
            if not 0 < path.stat().st_size <= self.config["contratto_esatto"]["g4_key_body_limit_bytes"]:
                raise RuntimeError("dimensione del sidecar G4 non valida")
            fingerprint = self.fingerprint_g4_locale()
            payload = path.read_bytes()
            protocol.same(hashlib.sha256(payload).hexdigest(), fingerprint, "sidecar G4 durante upload")
            raw, _ = self.srv("/g4-key", payload, timeout=600)
            result = protocol.strict_json(raw)
            protocol.same(result.get("ok"), True, "upload G4")
            protocol.same(result.get("g4_sha256"), fingerprint, "fingerprint G4 upload")
            protocol.same(result.get("base_sha256"), self.fingerprint_chiave_locale(), "famiglia base G4")
            raw, _ = self.srv("/stato")
            state = protocol.strict_json(raw)
            protocol.validate_status(state, self.config["contratto_esatto"], allow_empty=True)
            self.valida_fingerprint_chiave(state)
        self.valida_fingerprint_g4(state)

    def assicura_chiave(self):
        """Consegna la chiave di VALUTAZIONE se il server non ce l'ha (anche dopo un suo riavvio).
        La chiave segreta non lascia mai il client."""
        stato_raw, _ = self.srv("/stato")
        stato = protocol.strict_json(stato_raw)
        protocol.validate_status(stato, self.config["contratto_esatto"], allow_empty=True)
        if stato.get("chiave") is True:
            self.valida_fingerprint_chiave(stato)
            self.assicura_g4(stato)
            return False
        if stato.get("chiave") is not False or stato.get("chiave_sha256") is not None:
            raise RuntimeError("stato della chiave server incoerente")
        _mb = (
            pathlib.Path(self.settings.keys, "server.key").stat().st_size / 1e6
            if pathlib.Path(self.settings.keys, "server.key").exists()
            else None
        )
        self.log(
            "mando al server la chiave di VALUTAZIONE (non la segreta)"
            + (f", {_mb:.0f} MB..." if _mb else "...")
        )
        t0 = time.perf_counter()
        raw_key = (self.settings.keys / "server.key").read_bytes()
        fingerprint_locale = hashlib.sha256(raw_key).hexdigest()
        self.srv("/chiave", raw_key, timeout=600)
        stato_dopo_raw, _ = self.srv("/stato")
        stato_dopo = protocol.strict_json(stato_dopo_raw)
        protocol.validate_status(stato_dopo, self.config["contratto_esatto"], allow_empty=True)
        self.valida_fingerprint_chiave(stato_dopo, atteso=fingerprint_locale)
        self.assicura_g4(stato_dopo)
        self.log(f"chiave consegnata in {time.perf_counter() - t0:.1f}s")
        return True
