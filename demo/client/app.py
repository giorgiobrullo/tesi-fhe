"""Il CLIENT del varco: il terminale fidato al cancello.

E' l'unico che possiede la chiave segreta. Fa tre cose e nient'altro:
  1. cattura i frame dalla telecamera (li riceve dalla pagina web che serve lui stesso),
  2. calcola l'embedding IN CHIARO (ResNet100), fonde i frame (F48), quantizza a 3 bit e CIFRA,
  3. per ogni verifica manda al server il probe cifrato e decifra l'esito cifrato.

Il server (processo separato, altro container) non vede mai il volto/probe, il suo embedding, i
punteggi o l'esito decifrato. Nel Mondo 1 vede però galleria e soglie in chiaro, oltre alla chiave
di valutazione e ai metadati di controllo. La pagina rende visibile questa separazione.

Avvio:  uv run uvicorn demo.client.app:app --port 8000
Config: demo/config.json (scala, soglie e contratto cifrato), generato da demo/calibra.py.
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

ROOT = pathlib.Path(__file__).resolve().parents[2]
QUI = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments" / "08_cnn"))

CFG = json.loads((ROOT / "demo" / "config.json").read_text())
SERVER = os.environ.get("VARCO_SERVER", "http://127.0.0.1:9000")
BIN = os.environ.get(
    "VARCO_BIN", str(ROOT / "experiments/14_pipeline_tfhe_rs/target/release/varco_demo")
)
CHIAVI = pathlib.Path(os.environ.get("VARCO_CHIAVI", str(ROOT / "demo" / "chiavi")))
DIGIFACE = ROOT / "datasets" / "digiface" / "estratto"

app = FastAPI(title="Varco cifrato")
STATO = {"pronto": False, "messaggi": []}
GALLERIA_SNAPSHOT = None
_CHIAVE_HASH_CACHE = None


def log(m):
    print(m, flush=True)
    STATO["messaggi"].append(m)


# ---------------------------------------------------------------- crypto (binario Rust)
def _run(*args):
    r = subprocess.run([BIN, *map(str, args)], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{args[0]}: {r.stderr[:400]}")
    return json.loads(r.stdout.strip().splitlines()[-1])


def cifra(vettore):
    with tempfile.TemporaryDirectory() as d:
        p, c = f"{d}/probe.txt", f"{d}/probe.ct"
        pathlib.Path(p).write_text(" ".join(map(str, vettore)))
        # Le due scale (score 2^52 e residui mod16 2^60) sono parte del wire v2 e non
        # sono parametri negoziabili da riga di comando.
        info = _run("encrypt", CHIAVI, p, c)
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


def valida_header_varco(headers):
    """Rifiuta risposte HTTP che non dichiarano esplicitamente il wire exact-ID v2."""

    normalizzati = {str(k).lower(): str(v).strip() for k, v in headers.items()}
    contratto = normalizzati.get("x-varco-contract")
    if contratto != "exact-open-set-id-v2":
        raise RuntimeError(
            "il server non ha dichiarato il contratto HTTP exact-open-set-id-v2"
        )
    return contratto


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
    """Legge e valida la mappa posizionale usata per interpretare il prossimo esito.

    L'indice restituito dal cifrato ha senso soltanto rispetto alla stessa versione della
    galleria sulla quale il server ha calcolato l'argmin. Il chiamante conserva quindi questo
    snapshot locale e, dopo la decifratura, ne verifica epoch, revisione e cardinalita'.
    """

    raw, _ = srv("/stato")
    try:
        stato_server = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError("stato della galleria non valido") from exc

    richiesti = (
        "epoch",
        "revision",
        "nomi",
        "iscritti",
        "chiave",
        "chiave_sha256",
        "contratto_esatto",
    )
    mancanti = [campo for campo in richiesti if campo not in stato_server]
    if mancanti:
        raise RuntimeError(
            "stato della galleria incompleto: mancano " + ", ".join(mancanti)
        )

    epoch = stato_server["epoch"]
    revision = stato_server["revision"]
    iscritti = stato_server["iscritti"]
    nomi = stato_server["nomi"]
    if any(
        type(valore) is not int or valore < 0 for valore in (epoch, revision, iscritti)
    ):
        raise RuntimeError(
            "epoch, revisione e numero di iscritti devono essere interi non negativi"
        )
    if not isinstance(nomi, list) or len(nomi) != iscritti:
        raise RuntimeError(
            "mappa nomi della galleria incoerente con il numero di iscritti"
        )
    if not all(isinstance(nome, str) for nome in nomi):
        raise RuntimeError("mappa nomi della galleria non valida")
    chiave_sha256 = valida_fingerprint_chiave(stato_server)

    contratto = stato_server["contratto_esatto"]
    atteso = {
        chiave: CFG["contratto_esatto"][chiave]
        for chiave in (
            "wire_version",
            "probe_layout",
            "score_delta_log",
            "low_mod16_offset",
            "low_mod16_delta_log",
            "output_mode",
            "code_delta_log",
            "codice",
            "un_solo_lwe",
        )
    }
    if not isinstance(contratto, dict) or any(
        contratto.get(chiave) != valore for chiave, valore in atteso.items()
    ):
        raise RuntimeError(
            "il server non dichiara il contratto di identificazione esatta atteso"
        )

    snapshot = {
        "epoch": epoch,
        "revision": revision,
        "nomi": tuple(nomi),
        "iscritti": iscritti,
        "chiave_sha256": chiave_sha256,
    }
    global GALLERIA_SNAPSHOT
    GALLERIA_SNAPSHOT = snapshot
    return snapshot


def identita_da_esito(decifrato, snapshot):
    """Valida il contratto argmin e torna il nome soltanto per un match accettato."""

    richiesti = (
        "autorizzato",
        "indice",
        "iscritti",
        "galleria_epoch",
        "galleria_revision",
        "codice",
    )
    mancanti = [campo for campo in richiesti if campo not in decifrato]
    if mancanti:
        raise RuntimeError("esito cifrato incompleto: mancano " + ", ".join(mancanti))

    autorizzato = decifrato["autorizzato"]
    if type(autorizzato) is not bool:
        raise RuntimeError("campo autorizzato non booleano")
    for campo in ("iscritti", "galleria_epoch", "galleria_revision"):
        if type(decifrato[campo]) is not int or decifrato[campo] < 0:
            raise RuntimeError(f"campo {campo} non valido")

    versione_decifrata = (
        decifrato["galleria_epoch"],
        decifrato["galleria_revision"],
        decifrato["iscritti"],
    )
    versione_snapshot = (
        snapshot["epoch"],
        snapshot["revision"],
        snapshot["iscritti"],
    )
    if versione_decifrata != versione_snapshot:
        raise RuntimeError(
            "la galleria e' cambiata durante la verifica: esito scartato per sicurezza"
        )

    indice = decifrato["indice"]
    codice = decifrato["codice"]
    if type(codice) is not int:
        raise RuntimeError("codice dell'esito non intero")
    if autorizzato:
        if type(indice) is not int or not 0 <= indice < snapshot["iscritti"]:
            raise RuntimeError("indice dell'identita' accettata fuori dalla galleria")
        if codice != indice + 1:
            raise RuntimeError(
                "codice e indice dell'identita' accettata non coincidono"
            )
        return snapshot["nomi"][indice]

    if indice is not None:
        raise RuntimeError("un esito negato non deve contenere un indice")
    if codice != 0:
        raise RuntimeError("codice di rifiuto non valido")
    return None


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
        volti = det.get(bgr)
        if volti:
            v = max(
                volti, key=lambda f: (f.bbox[2] - f.bbox[0]) * (f.bbox[3] - f.bbox[1])
            )
            out.append(face_align.norm_crop(bgr, v.kps)[..., ::-1])
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


def assicura_chiave():
    """Consegna la chiave di VALUTAZIONE se il server non ce l'ha (anche dopo un suo riavvio).
    La chiave segreta non lascia mai il client."""
    stato_raw, _ = srv("/stato")
    try:
        stato = json.loads(stato_raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError("stato della chiave server non valido") from exc
    if stato.get("chiave") is True:
        valida_fingerprint_chiave(stato)
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
    try:
        stato_dopo = json.loads(stato_dopo_raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError(
            "stato della chiave server non valido dopo l'upload"
        ) from exc
    valida_fingerprint_chiave(stato_dopo, atteso=fingerprint_locale)
    log(f"chiave consegnata in {time.perf_counter() - t0:.1f}s")
    return True


@app.on_event("startup")
def avvio():
    CHIAVI.mkdir(parents=True, exist_ok=True)
    if not (CHIAVI / "client.key").exists():
        log("genero le chiavi (la segreta resta qui, sul client)...")
        log(str(_run("keygen", CHIAVI)))
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
    return FileResponse(QUI / "static" / "index.html")


@app.get("/api/stato")
def stato():
    try:
        s, _ = srv("/stato")
        return {
            "client": {
                "pronto": STATO["pronto"],
                "log": STATO["messaggi"][-8:],
                "config": CFG,
                # Per un run probatorio il benchmark pretende False prima del preload e True
                # subito dopo: cosi' la galleria viene costruita da un modello caricato nello
                # stesso processo osservato, non da una cache preesistente non attestata.
                "modello_caricato": "ec" in _emb,
            },
            "server": json.loads(s),
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
    if not 1 <= n <= int(CFG.get("capacita_galleria", 128)):
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

    # Preserve the existing gallery until every local template has been loaded and validated.
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
    ct, _ = cifra(q)
    t_cifra = (time.perf_counter() - t0) * 1000

    # Lo snapshot deve precedere /varco: l'esito cifrato porta la versione effettivamente usata
    # dal server e viene scartato se nel frattempo reset/enrollment hanno cambiato gli indici.
    snapshot = snapshot_galleria()

    t0 = time.perf_counter()
    esito, hdr = srv("/varco", ct)
    t_rete = (time.perf_counter() - t0) * 1000
    protocollo_http = valida_header_varco(hdr)

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
            "server": float(hdr.get("X-Tempo-Ms", 0)),
            "rete_e_server": round(t_rete, 1),
            "decifratura": round(t_dec, 1),
            # Include lettura/decodifica, fusione, quantizzazione, lo snapshot `/stato` che
            # vincola gli indici e la serializzazione HTTP. Resta esclusa l'acquisizione dei
            # frame, precedente alla richiesta HTTP.
            "endpoint": round(endpoint_ms, 1),
        },
        "byte": {"probe_cifrato": len(ct), "esito_cifrato": len(esito)},
        "frame": det["frame"],
        "pbs": int(hdr.get("X-Pbs", 0)),
        "protocollo_http": protocollo_http,
    }
