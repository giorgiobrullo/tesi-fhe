"""Il CLIENT del varco: il terminale fidato al cancello.

E' l'unico che possiede la chiave segreta. Fa tre cose e nient'altro:
  1. cattura i frame dalla telecamera (li riceve dalla pagina web che serve lui stesso),
  2. calcola l'embedding IN CHIARO (ResNet100), fonde i frame (F48), quantizza a 3 bit e CIFRA,
  3. manda al server solo byte cifrati, e decifra l'esito che torna.

Il server (processo separato, altro container) non vede mai il volto, l'embedding, i punteggi o
l'esito: vede solo byte. Questa demo rende visibile quella separazione — la pagina mostra, per
ogni query, cosa sta da una parte e cosa passa sul filo.

Avvio:  uv run uvicorn demo.client.app:app --port 8000
Config: demo/config.json (scala, soglia, Delta), generato da demo/calibra.py.
"""
import base64
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
BIN = os.environ.get("VARCO_BIN", str(ROOT / "experiments/14_pipeline_tfhe_rs/target/release/varco_demo"))
CHIAVI = pathlib.Path(os.environ.get("VARCO_CHIAVI", str(ROOT / "demo" / "chiavi")))
DIGIFACE = ROOT / "datasets" / "digiface" / "estratto"

app = FastAPI(title="Varco cifrato")
STATO = {"pronto": False, "messaggi": []}


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
        info = _run("encrypt", CHIAVI, p, c, CFG["log_delta"])
        return pathlib.Path(c).read_bytes(), info


def decifra(esito_bytes):
    with tempfile.TemporaryDirectory() as d:
        c = f"{d}/esito.ct"
        pathlib.Path(c).write_bytes(esito_bytes)
        return _run("decrypt", CHIAVI, c)


# ---------------------------------------------------------------- rete verso il server
def srv(path, data=None, ctype="application/octet-stream", timeout=120):
    req = urllib.request.Request(SERVER + path, data=data, method="POST" if data is not None else "GET",
                                 headers={"Content-Type": ctype} if data is not None else {})
    with urllib.request.urlopen(req, timeout=timeout) as f:
        return f.read(), dict(f.headers)


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
            v = max(volti, key=lambda f: (f.bbox[2] - f.bbox[0]) * (f.bbox[3] - f.bbox[1]))
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
    stato, _ = srv("/stato")
    if json.loads(stato)["chiave"]:
        return False
    _mb = pathlib.Path(CHIAVI, "server.key").stat().st_size / 1e6 if pathlib.Path(CHIAVI, "server.key").exists() else None
    log(f"mando al server la chiave di VALUTAZIONE (non la segreta)"
        + (f", {_mb:.0f} MB..." if _mb else "..."))
    t0 = time.perf_counter()
    srv("/chiave", (CHIAVI / "server.key").read_bytes(), timeout=600)
    log(f"chiave consegnata in {time.perf_counter()-t0:.1f}s")
    return True


@app.on_event("startup")
def avvio():
    CHIAVI.mkdir(parents=True, exist_ok=True)
    if not (CHIAVI / "client.key").exists():
        log("genero le chiavi (la segreta resta qui, sul client)...")
        log(str(_run("keygen", CHIAVI)))
    for _ in range(30):
        try:
            srv("/stato"); break
        except urllib.error.URLError:
            time.sleep(1)
    else:
        log(f"server non raggiungibile su {SERVER}"); return
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
        return {"client": {"pronto": STATO["pronto"], "log": STATO["messaggi"][-8:], "config": CFG},
                "server": json.loads(s)}
    except urllib.error.URLError as e:
        return JSONResponse({"errore": f"server non raggiungibile: {e}"}, status_code=503)


@app.post("/api/precarica")
def precarica(n: int = 127):
    """Iscrive n identita' SINTETICHE (DigiFace, gia' allineate): i 'colleghi' della galleria.
    Volti generati, non persone reali: la galleria della demo e' license-clean."""
    import imageio.v2 as imageio
    assicura_chiave()
    cartelle = sorted([p for p in DIGIFACE.iterdir() if p.is_dir()])[:n]
    if not cartelle:
        return JSONResponse({"errore": f"manca {DIGIFACE}"}, status_code=400)
    t0 = time.perf_counter()
    for c in cartelle:
        foto = sorted(c.glob("*.png"))[:CFG["k_galleria"]]
        if len(foto) < CFG["k_galleria"]:
            continue
        img = [imageio.imread(f)[..., :3] for f in foto]
        q, _ = embedding_fuso(img, gia_allineati=True)
        srv("/iscrivi", f"sintetico_{c.name}\n".encode() + " ".join(map(str, q)).encode(), "text/plain")
    s, _ = srv("/stato")
    return {"iscritti": json.loads(s)["iscritti"], "secondi": round(time.perf_counter() - t0, 1)}


@app.post("/api/iscrivi")
def iscrivi(req: Frames):
    """Registrazione: k_galleria foto -> template. Va al server IN CHIARO: la galleria e' dati
    del server (Mondo 1). Solo il volto della QUERY viaggia cifrato."""
    if not req.frames:
        return JSONResponse({"errore": "nessun frame"}, status_code=400)
    assicura_chiave()
    q, det = embedding_fuso([da_dataurl(f) for f in req.frames])
    r, _ = srv("/iscrivi", f"{req.nome or 'io'}\n".encode() + " ".join(map(str, q)).encode(), "text/plain")
    return {"server": json.loads(r), **det, "template_primi": q[:12].tolist()}


@app.post("/api/verifica")
def verifica(req: Frames):
    """La query: frame -> embedding in chiaro -> fusione -> quantizzazione -> CIFRA -> server ->
    esito cifrato -> decifra. Il server ha visto solo byte."""
    if req.sintetico is not None:
        import imageio.v2 as imageio
        c = sorted([p for p in DIGIFACE.iterdir() if p.is_dir()])[req.sintetico]
        foto = sorted(c.glob("*.png"))[CFG["k_galleria"]:CFG["k_galleria"] + CFG["k_probe"]]
        q, det = embedding_fuso([imageio.imread(f)[..., :3] for f in foto], gia_allineati=True)
        atteso = f"sintetico_{c.name}"
    else:
        if not req.frames:
            return JSONResponse({"errore": "nessun frame"}, status_code=400)
        q, det = embedding_fuso([da_dataurl(f) for f in req.frames])
        atteso = None

    assicura_chiave()
    t0 = time.perf_counter(); ct, info_c = cifra(q); t_cifra = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter(); esito, hdr = srv("/varco", ct); t_rete = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter(); dec = decifra(esito); t_dec = (time.perf_counter() - t0) * 1000
    s, _ = srv("/stato")
    nomi = json.loads(s)["nomi"]
    idx = dec["indice"]
    return {
        "esito": "aperto" if dec["conteggio"] == 1 else ("negato" if dec["conteggio"] == 0 else "ambiguo"),
        "identita": nomi[idx] if 0 <= idx < len(nomi) else None,
        "conteggio": dec["conteggio"], "atteso": atteso,
        "tempi_ms": {"embedding": det["embedding_ms"], "cifratura": round(t_cifra, 1),
                     "server": float(hdr.get("X-Tempo-Ms", 0)), "rete_e_server": round(t_rete, 1),
                     "decifratura": round(t_dec, 1)},
        "byte": {"probe_cifrato": len(ct), "esito_cifrato": len(esito)},
        "frame": det["frame"], "pbs": int(hdr.get("X-Pbs", 0)),
        "template_primi": q[:12].tolist(),
        "cifrato_primi": ct[16:40].hex(),
    }
