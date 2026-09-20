"""Legacy camera API around the explicit trusted-client pipeline.

Run from runtime with uvicorn ui.camera_web:app. The access-only demo imports
AccessPipeline directly and never imports or rewires this FastAPI application.
"""
import json
import os
from pathlib import Path
import time
import urllib.error

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from . import protocol
from .adapters import HttpTransport
from .configuration import ClientConfiguration
from .pipeline import AccessPipeline

ROOT = Path(__file__).resolve().parents[1]
SERVER = os.environ.get("VARCO_SERVER", "http://127.0.0.1:9004")
settings = ClientConfiguration(
    ROOT,
    Path(os.environ.get("VARCO_BIN", str(ROOT / "target-service/release/varco_demo_composite_v9"))),
    Path(os.environ.get("VARCO_CHIAVI", str(ROOT / "keys"))),
)
pipeline = AccessPipeline(settings, HttpTransport(SERVER))
DIGIFACE = settings.assets / "datasets/digiface/estratto"
app = FastAPI(title="Varco cifrato")


class Frames(BaseModel):
    frames: list[str] = []
    nome: str = ""
    sintetico: int | None = None



@app.on_event("startup")
def avvio():
    # Preserve the legacy camera startup. The access-only demo never uses it.
    keys = pipeline.settings.keys
    keys.mkdir(parents=True, exist_ok=True, mode=0o700)
    keys.chmod(0o700)
    has_client = (keys / "client.key").exists()
    has_server = (keys / "server.key").exists()
    if has_client != has_server:
        raise RuntimeError("coppia di chiavi locale incompleta; avvio interrotto")
    if not has_client:
        pipeline.log("genero le chiavi (la segreta resta qui, sul client)...")
        pipeline.log(str(pipeline._run("keygen", keys)))
    pipeline.require_existing_keys()
    for _ in range(30):
        try:
            pipeline.srv("/stato")
            break
        except urllib.error.URLError:
            time.sleep(1)
    else:
        pipeline.log(f"server non raggiungibile su {SERVER}")
        return
    pipeline.assicura_chiave()
    pipeline.ready = True
    pipeline.log("pronto.")


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
        s, _ = pipeline.srv("/stato")
        stato_server = protocol.strict_json(s)
        protocol.validate_status(stato_server, pipeline.config["contratto_esatto"], allow_empty=True)
        if stato_server["chiave"]:
            pipeline.valida_fingerprint_chiave(stato_server)
        return {
            "client": {
                "pronto": pipeline.ready and stato_server["chiave"],
                "log": pipeline.messages[-8:],
                "config": pipeline.config,
                # Per un run probatorio il benchmark pretende False prima del preload e True
                # subito dopo: cosi' la galleria viene costruita da un modello caricato nello
                # stesso processo osservato, non da una cache preesistente non attestata.
                "modello_caricato": pipeline.model_loaded,
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

    pipeline.assicura_chiave()
    n = int(pipeline.config.get("n_galleria_demo", 127)) if n is None else n
    if not 1 <= n <= int(pipeline.config.get("capacita_galleria", 3374)):
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
        foto = sorted(c.glob("*.png"))[: pipeline.config["k_galleria"]]
        if len(foto) < pipeline.config["k_galleria"]:
            return JSONResponse(
                {
                    "errore": f"{c}: servono {pipeline.config['k_galleria']} immagini, trovate {len(foto)}"
                },
                status_code=400,
            )
        img = [imageio.imread(f)[..., :3] for f in foto]
        q, _ = pipeline.embedding_fuso(img, gia_allineati=True)
        intestazione = f"sintetico_{c.name}\t{pipeline.config['T_sintetico_digiface']}\n"
        enrollment.append(intestazione.encode() + " ".join(map(str, q)).encode())

    # Il modello ha preparato tutti i template; il server ammette ogni iscrizione separatamente.
    # Il reset e la sequenza di iscrizioni non costituiscono una transazione unica.
    pipeline.srv("/reset", b"")
    pipeline.gallery_snapshot = None
    for corpo in enrollment:
        pipeline.srv("/iscrivi", corpo, "text/plain")
    s, _ = pipeline.srv("/stato")
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
    pipeline.assicura_chiave()
    q, det = pipeline.embedding_fuso([pipeline.da_dataurl(f) for f in req.frames])
    # Le soglie sintetica e reale sono due operating point diversi. Il server conserva la soglia
    # insieme al template: una registrazione webcam non viene quindi valutata con T_sintetico.
    intestazione = f"{req.nome or 'io'}\t{pipeline.config['T_reale_vggface2']}\n"
    r, _ = pipeline.srv(
        "/iscrivi", intestazione.encode() + " ".join(map(str, q)).encode(), "text/plain"
    )
    pipeline.gallery_snapshot = None
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
            pipeline.config["k_galleria"] : pipeline.config["k_galleria"] + pipeline.config["k_probe"]
        ]
        q, det = pipeline.embedding_fuso(
            [imageio.imread(f)[..., :3] for f in foto], gia_allineati=True
        )
        atteso = f"sintetico_{c.name}"
    else:
        if not req.frames:
            return JSONResponse({"errore": "nessun frame"}, status_code=400)
        q, det = pipeline.embedding_fuso([pipeline.da_dataurl(f) for f in req.frames])
        atteso = None

    result = pipeline.verify_vector(q)
    return {
        "esito": "aperto" if result.decoded["autorizzato"] else "negato",
        "identita": result.identity,
        "atteso": atteso,
        "tempi_ms": {
            "embedding": det["embedding_ms"],
            **result.timings_ms,
            "endpoint": round((time.perf_counter() - t_endpoint) * 1000, 1),
        },
        "byte": result.sizes,
        "frame": det["frame"],
        "pbs": int(result.headers["x-pbs"]),
        "protocollo_http": result.headers["x-varco-contract"],
        "conteggi": result.snapshot["conteggi"],
        "execution_mode": result.snapshot["execution_mode"],
    }
