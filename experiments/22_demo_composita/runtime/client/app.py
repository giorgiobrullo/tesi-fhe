"""Il CLIENT del varco: il terminale fidato al cancello.

E' l'unico che possiede la chiave segreta. Fa tre cose e nient'altro:
  1. cattura i frame dalla telecamera (li riceve dalla pagina web che serve lui stesso),
  2. calcola l'embedding IN CHIARO (ResNet100), fonde i frame (F48), quantizza a 3 bit e CIFRA,
  3. per ogni verifica manda al server il probe cifrato, decifra `low`, `middle` e `high` e ricostruisce
     `code = low + 15*middle + 225*high` (0=rifiuto, i+1=identita' esatta).

Il server (processo separato, altro container) non vede mai il volto/probe, il suo embedding, i
punteggi o l'esito decifrato. Nel Mondo 1 vede però galleria e soglie in chiaro, oltre alla chiave
di valutazione e ai metadati di controllo. La pagina rende visibile questa separazione.

Avvio dalla nuova directory: uvicorn ui.camera_web:app --host 127.0.0.1 --port 8002
Config locale: config.json. Esecuzione e generazione chiavi sono riservate al gate root.
"""

import base64
import hashlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import numpy as np
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from . import protocol

ROOT = pathlib.Path(__file__).resolve().parents[1]
QUI = pathlib.Path(__file__).resolve().parent
ASSET_ROOT = next(parent for parent in ROOT.parents if (parent / "pyproject.toml").is_file()
                  and (parent / "experiments/08_cnn/embedding.py").is_file())
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ASSET_ROOT / "experiments" / "08_cnn"))

CFG = protocol.strict_json((ROOT / "config.json").read_bytes())
CIRCUIT = (ROOT / "CIRCUIT_CONTRACT.json").read_bytes()
if hashlib.sha256(CIRCUIT).hexdigest() != CFG["contratto_esatto"]["circuit_sha256"]:
    raise RuntimeError("configurazione non vincolata al circuito locale")
SERVER = os.environ.get("VARCO_SERVER", "http://127.0.0.1:9004")
BIN = os.environ.get(
    "VARCO_BIN", str(ROOT / "target-service/release/varco_demo_composite_v9")
)
CHIAVI = pathlib.Path(os.environ.get("VARCO_CHIAVI", str(ROOT / "keys")))
DIGIFACE = ASSET_ROOT / "datasets" / "digiface" / "estratto"

app = FastAPI(title="Varco cifrato")
STATO = {"pronto": False, "messaggi": []}
GALLERIA_SNAPSHOT = None
_CHIAVE_HASH_CACHE = None
_G4_HASH_CACHE = None


def log(m):
    print(m, flush=True)
    STATO["messaggi"].append(m)


# ---------------------------------------------------------------- crypto (binario Rust)
def _run(*args):
    r = subprocess.run([BIN, *map(str, args)], capture_output=True, text=True,
                       timeout=600 if args[0] == "keygen" else 120)
    if r.returncode != 0:
        raise RuntimeError(f"{args[0]}: {r.stderr[:400]}")
    return protocol.strict_json(r.stdout.strip().splitlines()[-1])


def cifra(vettore, query_profile):
    with tempfile.TemporaryDirectory() as d:
        p, c = f"{d}/probe.txt", f"{d}/probe.ct"
        pathlib.Path(p).write_text(" ".join(map(str, vettore)))
        if query_profile != "head51":
            raise RuntimeError("profilo pubblico del probe mancante o errato")
        info = _run("encrypt", CHIAVI, p, c, query_profile)
        return pathlib.Path(c).read_bytes(), info


def decifra(esito_bytes):
    with tempfile.TemporaryDirectory() as d:
        c = f"{d}/esito.ct"
        pathlib.Path(c).write_bytes(esito_bytes)
        return _run("decrypt", CHIAVI, c)


# ---------------------------------------------------------------- rete verso il server
def srv(path, data=None, ctype="application/octet-stream", timeout=120):
    req = urllib.request.Request(
        SERVER + path,
        data=data,
        method="POST" if data is not None else "GET",
        headers={"Content-Type": ctype} if data is not None else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as f:
            return f.read(), dict(f.headers)
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            detail = json.loads(body).get("errore", body.decode(errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            detail = body.decode(errors="replace")
        raise RuntimeError(f"server HTTP {e.code}: {detail}") from e


def valida_header_varco(headers, snapshot):
    """Vincola contratto, profilo e contatori alla galleria letta prima di cifrare."""
    return protocol.validate_headers(headers, CFG["contratto_esatto"], snapshot)


def fingerprint_chiave_locale():
    """SHA-256 della evaluation key locale, in cache finche' il file non cambia."""

    path = CHIAVI / "server.key"
    stat = path.stat()
    firma_file = (
        str(path.resolve()),
        stat.st_dev,
        stat.st_ino,
        stat.st_size,
        stat.st_mtime_ns,
        stat.st_ctime_ns,
    )
    global _CHIAVE_HASH_CACHE
    if _CHIAVE_HASH_CACHE is not None and _CHIAVE_HASH_CACHE[0] == firma_file:
        return _CHIAVE_HASH_CACHE[1]

    digest = hashlib.sha256()
    with path.open("rb") as key_file:
        for chunk in iter(lambda: key_file.read(1024 * 1024), b""):
            digest.update(chunk)
    fingerprint = digest.hexdigest()
    _CHIAVE_HASH_CACHE = (firma_file, fingerprint)
    return fingerprint


def valida_fingerprint_chiave(stato_server, atteso=None):
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
    fingerprint_locale = fingerprint_chiave_locale() if atteso is None else atteso
    if fingerprint_server != fingerprint_locale:
        raise RuntimeError(
            "la chiave di valutazione del server non coincide con server.key del client"
        )
    return fingerprint_server


def snapshot_galleria():
    """Conserva piano, nomi e versione della galleria prima della cifratura."""
    raw, _ = srv("/stato")
    stato_server = protocol.strict_json(raw)
    snapshot = protocol.validate_status(stato_server, CFG["contratto_esatto"])
    valida_fingerprint_chiave(stato_server)
    valida_fingerprint_g4(stato_server)
    global GALLERIA_SNAPSHOT
    GALLERIA_SNAPSHOT = snapshot
    return snapshot


def identita_da_esito(decifrato, snapshot):
    return protocol.decode_identity(decifrato, snapshot, CFG["contratto_esatto"])


# ---------------------------------------------------------------- volti -> embedding
_emb = {}


def modello():
    if "ec" not in _emb:
        import embedding as ec

        log("carico ResNet100 (in chiaro, sul client)...")
        ec.carica(CFG["modello"])
        _emb["ec"] = ec
    return _emb["ec"]


def da_dataurl(d):
    import imageio.v2 as imageio

    return imageio.imread(io.BytesIO(base64.b64decode(d.split(",", 1)[1])))[..., :3]


def allinea(frames_rgb):
    """Rileva e allinea sui 5 landmark, tenendo il volto piu' grande (chi e' davanti al varco).

    Il rilevatore e' quello di buffalo_s: l'allineamento e' lo stesso template canonico per tutti i
    modelli ArcFace, quindi si puo' usare un rilevatore leggero e poi l'embedding col modello scelto
    (e' esattamente quello che fa la pipeline dei benchmark, che allinea una volta e riusa i crop).
    Torna None se in nessun frame c'e' un volto."""
    from insightface.utils import face_align

    ec = modello()
    det = ec._app("mobilefacenet")
    out = []
    for im in frames_rgb:
        bgr = im[..., ::-1]
        boxes, landmarks = det.det_model.detect(bgr, max_num=0, metric="default")
        if len(boxes):
            index = max(range(len(boxes)), key=lambda i:
                        (boxes[i, 2] - boxes[i, 0]) * (boxes[i, 3] - boxes[i, 1]))
            out.append(face_align.norm_crop(bgr, landmarks[index])[..., ::-1])
    return np.array(out) if out else None


def embedding_fuso(frames_rgb, gia_allineati=False):
    """Multi-frame (F48): allinea, embedda, media, L2. Torna (vettore quantizzato, dettagli)."""
    ec = modello()
    t0 = time.perf_counter()
    X = np.array(frames_rgb) if gia_allineati else allinea(frames_rgb)
    if X is None:
        raise ValueError("nessun volto rilevato: inquadra il viso e riprova")
    E = ec.embedding(X, CFG["modello"])
    t_emb = (time.perf_counter() - t0) * 1000
    v = E.mean(0)
    v = v / (np.linalg.norm(v) + 1e-9)
    qm = CFG["q_max"]
    q = np.clip(np.round(v / CFG["scala"]), -qm, qm).astype(int)
    return q, {"frame": len(X), "embedding_ms": round(t_emb, 1)}


# ---------------------------------------------------------------- API
class Frames(BaseModel):
    frames: list[str] = []
    nome: str = ""
    sintetico: int | None = None


def fingerprint_g4_locale():
    path = CHIAVI / "g4.key"
    stat = path.stat()
    signature = (str(path.resolve()), stat.st_dev, stat.st_ino, stat.st_size,
                 stat.st_mtime_ns, stat.st_ctime_ns)
    global _G4_HASH_CACHE
    if _G4_HASH_CACHE is None or _G4_HASH_CACHE[0] != signature:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        _G4_HASH_CACHE = signature, digest.hexdigest()
    return _G4_HASH_CACHE[1]


def valida_fingerprint_g4(state):
    if CFG["contratto_esatto"]["g4_required"]:
        protocol.same(state.get("g4_sha256"), fingerprint_g4_locale(), "chiave G4 locale/server")
        protocol.same(state.get("g4_ready"), True, "prontezza G4")
    elif state.get("g4_sha256") is not None:
        raise RuntimeError("chiave G4 inattesa nel circuito senza G4")


def assicura_g4(state):
    if not CFG["contratto_esatto"]["g4_required"]:
        valida_fingerprint_g4(state)
        return
    if state.get("g4_sha256") is None:
        path = CHIAVI / "g4.key"
        if not 0 < path.stat().st_size <= CFG["contratto_esatto"]["g4_key_body_limit_bytes"]:
            raise RuntimeError("dimensione del sidecar G4 non valida")
        fingerprint = fingerprint_g4_locale()
        payload = path.read_bytes()
        protocol.same(hashlib.sha256(payload).hexdigest(), fingerprint, "sidecar G4 durante upload")
        raw, _ = srv("/g4-key", payload, timeout=600)
        result = protocol.strict_json(raw)
        protocol.same(result.get("ok"), True, "upload G4")
        protocol.same(result.get("g4_sha256"), fingerprint, "fingerprint G4 upload")
        protocol.same(result.get("base_sha256"), fingerprint_chiave_locale(), "famiglia base G4")
        raw, _ = srv("/stato")
        state = protocol.strict_json(raw)
        protocol.validate_status(state, CFG["contratto_esatto"], allow_empty=True)
        valida_fingerprint_chiave(state)
    valida_fingerprint_g4(state)


def assicura_chiave():
    """Consegna la chiave di VALUTAZIONE se il server non ce l'ha (anche dopo un suo riavvio).
    La chiave segreta non lascia mai il client."""
    stato_raw, _ = srv("/stato")
    stato = protocol.strict_json(stato_raw)
    protocol.validate_status(stato, CFG["contratto_esatto"], allow_empty=True)
    if stato.get("chiave") is True:
        valida_fingerprint_chiave(stato)
        assicura_g4(stato)
        return False
    if stato.get("chiave") is not False or stato.get("chiave_sha256") is not None:
        raise RuntimeError("stato della chiave server incoerente")
    _mb = (
        pathlib.Path(CHIAVI, "server.key").stat().st_size / 1e6
        if pathlib.Path(CHIAVI, "server.key").exists()
        else None
    )
    log(
        "mando al server la chiave di VALUTAZIONE (non la segreta)"
        + (f", {_mb:.0f} MB..." if _mb else "...")
    )
    t0 = time.perf_counter()
    raw_key = (CHIAVI / "server.key").read_bytes()
    fingerprint_locale = hashlib.sha256(raw_key).hexdigest()
    srv("/chiave", raw_key, timeout=600)
    stato_dopo_raw, _ = srv("/stato")
    stato_dopo = protocol.strict_json(stato_dopo_raw)
    protocol.validate_status(stato_dopo, CFG["contratto_esatto"], allow_empty=True)
    valida_fingerprint_chiave(stato_dopo, atteso=fingerprint_locale)
    assicura_g4(stato_dopo)
    log(f"chiave consegnata in {time.perf_counter() - t0:.1f}s")
    return True


@app.on_event("startup")
def avvio():
    CHIAVI.mkdir(parents=True, exist_ok=True, mode=0o700)
    CHIAVI.chmod(0o700)
    has_client = (CHIAVI / "client.key").exists()
    has_server = (CHIAVI / "server.key").exists()
    if has_client != has_server:
        raise RuntimeError("coppia di chiavi locale incompleta; avvio interrotto")
    if not has_client:
        log("genero le chiavi (la segreta resta qui, sul client)...")
        log(str(_run("keygen", CHIAVI)))
    required_g4 = CFG["contratto_esatto"]["g4_required"]
    if (CHIAVI / "g4.key").exists() != required_g4:
        raise RuntimeError("file G4 locale incoerente con il circuito selezionato; non sostituire le chiavi")
    for _ in range(30):
        try:
            srv("/stato")
            break
        except urllib.error.URLError:
            time.sleep(1)
    else:
        log(f"server non raggiungibile su {SERVER}")
        return
    assicura_chiave()
    STATO["pronto"] = True
    log("pronto.")


@app.exception_handler(Exception)
def errori(request, exc):
    """La pagina deve ricevere sempre JSON: un 500 HTML diventerebbe un errore di parsing."""
    return JSONResponse({"errore": str(exc) or exc.__class__.__name__}, status_code=500)


@app.get("/")
def pagina():
    return FileResponse(ROOT / "ui" / "index.html")


@app.get("/api/stato")
def stato():
    try:
        s, _ = srv("/stato")
        stato_server = protocol.strict_json(s)
        protocol.validate_status(stato_server, CFG["contratto_esatto"], allow_empty=True)
        if stato_server["chiave"]:
            valida_fingerprint_chiave(stato_server)
        return {
            "client": {
                "pronto": STATO["pronto"] and stato_server["chiave"],
                "log": STATO["messaggi"][-8:],
                "config": CFG,
                # Per un run probatorio il benchmark pretende False prima del preload e True
                # subito dopo: cosi' la galleria viene costruita da un modello caricato nello
                # stesso processo osservato, non da una cache preesistente non attestata.
                "modello_caricato": "ec" in _emb,
            },
            "server": stato_server,
        }
    except urllib.error.URLError as e:
        return JSONResponse(
            {"errore": f"server non raggiungibile: {e}"}, status_code=503
        )


@app.post("/api/precarica")
def precarica(n: int | None = None):
    """Iscrive n identita' SINTETICHE (DigiFace, gia' allineate): i 'colleghi' della galleria.
    Volti generati, non persone reali: la galleria della demo e' license-clean. Il reset rende
    l'operazione idempotente: due click non duplicano le identita'."""
    import imageio.v2 as imageio

    assicura_chiave()
    n = int(CFG.get("n_galleria_demo", 127)) if n is None else n
    if not 1 <= n <= int(CFG.get("capacita_galleria", 3374)):
        return JSONResponse(
            {"errore": f"numero iscritti non valido: {n}"}, status_code=400
        )
    cartelle = sorted([p for p in DIGIFACE.iterdir() if p.is_dir()])[:n]
    if len(cartelle) != n:
        return JSONResponse(
            {"errore": f"servono {n} identita' in {DIGIFACE}, trovate {len(cartelle)}"},
            status_code=400,
        )
    t0 = time.perf_counter()
    enrollment: list[bytes] = []
    for c in cartelle:
        foto = sorted(c.glob("*.png"))[: CFG["k_galleria"]]
        if len(foto) < CFG["k_galleria"]:
            return JSONResponse(
                {
                    "errore": f"{c}: servono {CFG['k_galleria']} immagini, trovate {len(foto)}"
                },
                status_code=400,
            )
        img = [imageio.imread(f)[..., :3] for f in foto]
        q, _ = embedding_fuso(img, gia_allineati=True)
        intestazione = f"sintetico_{c.name}\t{CFG['T_sintetico_digiface']}\n"
        enrollment.append(intestazione.encode() + " ".join(map(str, q)).encode())

    # Il modello ha preparato tutti i template; il server ammette ogni iscrizione separatamente.
    # Il reset e la sequenza di iscrizioni non costituiscono una transazione unica.
    global GALLERIA_SNAPSHOT
    srv("/reset", b"")
    GALLERIA_SNAPSHOT = None
    for corpo in enrollment:
        srv("/iscrivi", corpo, "text/plain")
    s, _ = srv("/stato")
    return {
        "iscritti": json.loads(s)["iscritti"],
        "secondi": round(time.perf_counter() - t0, 1),
    }


@app.post("/api/iscrivi")
def iscrivi(req: Frames):
    """Registrazione: k_galleria foto -> template. Va al server IN CHIARO: la galleria e' dati
    del server (Mondo 1). Solo il volto della QUERY viaggia cifrato."""
    if not req.frames:
        return JSONResponse({"errore": "nessun frame"}, status_code=400)
    assicura_chiave()
    q, det = embedding_fuso([da_dataurl(f) for f in req.frames])
    # Le soglie sintetica e reale sono due operating point diversi. Il server conserva la soglia
    # insieme al template: una registrazione webcam non viene quindi valutata con T_sintetico.
    intestazione = f"{req.nome or 'io'}\t{CFG['T_reale_vggface2']}\n"
    r, _ = srv(
        "/iscrivi", intestazione.encode() + " ".join(map(str, q)).encode(), "text/plain"
    )
    global GALLERIA_SNAPSHOT
    GALLERIA_SNAPSHOT = None
    return {"server": json.loads(r), **det}


@app.post("/api/verifica")
def verifica(req: Frames):
    """La query: frame -> embedding in chiaro -> fusione -> quantizzazione -> CIFRA -> server ->
    esito cifrato -> decifra. Sul percorso di verifica il server vede solo cifrati; setup,
    galleria e metadati di controllo restano in chiaro nel Mondo 1."""
    t_endpoint = time.perf_counter()
    if req.sintetico is not None:
        import imageio.v2 as imageio

        c = sorted([p for p in DIGIFACE.iterdir() if p.is_dir()])[req.sintetico]
        foto = sorted(c.glob("*.png"))[
            CFG["k_galleria"] : CFG["k_galleria"] + CFG["k_probe"]
        ]
        q, det = embedding_fuso(
            [imageio.imread(f)[..., :3] for f in foto], gia_allineati=True
        )
        atteso = f"sintetico_{c.name}"
    else:
        if not req.frames:
            return JSONResponse({"errore": "nessun frame"}, status_code=400)
        q, det = embedding_fuso([da_dataurl(f) for f in req.frames])
        atteso = None

    assicura_chiave()
    t0 = time.perf_counter()
    snapshot = snapshot_galleria()
    ct, _ = cifra(q, snapshot["query_profile"])
    t_cifra = (time.perf_counter() - t0) * 1000

    # Lo snapshot precede cifratura e /varco: l'esito cifrato porta la versione effettivamente usata
    # dal server e viene scartato se nel frattempo reset/enrollment hanno cambiato gli indici.
    t0 = time.perf_counter()
    esito, hdr = srv("/varco", ct)
    t_rete = (time.perf_counter() - t0) * 1000
    hdr = valida_header_varco(hdr, snapshot)
    protocollo_http = hdr["x-varco-contract"]

    t0 = time.perf_counter()
    dec = decifra(esito)
    t_dec = (time.perf_counter() - t0) * 1000
    identita = identita_da_esito(dec, snapshot)
    autorizzato = dec["autorizzato"]
    endpoint_ms = (time.perf_counter() - t_endpoint) * 1000
    return {
        "esito": "aperto" if autorizzato else "negato",
        "identita": identita,
        "atteso": atteso,
        "tempi_ms": {
            "embedding": det["embedding_ms"],
            "cifratura": round(t_cifra, 1),
            "server": float(hdr["x-tempo-ms"]),
            "rete_e_server": round(t_rete, 1),
            "decifratura": round(t_dec, 1),
            # Include lettura/decodifica, fusione, quantizzazione, lo snapshot `/stato` che
            # vincola gli indici e la serializzazione HTTP. Resta esclusa l'acquisizione dei
            # frame, precedente alla richiesta HTTP.
            "endpoint": round(endpoint_ms, 1),
        },
        "byte": {"probe_cifrato": len(ct), "esito_cifrato": len(esito)},
        "frame": det["frame"],
        "pbs": int(hdr["x-pbs"]),
        "protocollo_http": protocollo_http,
        "conteggi": snapshot["conteggi"],
        "execution_mode": snapshot["execution_mode"],
    }
