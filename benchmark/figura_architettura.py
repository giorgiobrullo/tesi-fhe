"""Architettura exact-ID del prototipo e misure end-to-end preservate.

I numeri vengono letti dall'artefatto exact-ID Docker del 2026-09-02: sei query
sintetiche (tre genuine e tre impostori held-out), 127 iscritti e processi client/server
separati. Sono misure engineering, non una derivazione formale della probabilita'
d'errore composta.
"""

import csv
import json
import pathlib

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

DPI = 300
plt.rcParams["svg.hashsalt"] = "tesi-fhe-benchmark"
R = pathlib.Path(__file__).resolve().parent / "results"
CLIENT, SERVER, FILO, TENUE = "#2a9d8f", "#e9a000", "#6a4c93", "#7a8a94"
ARTEFATTO = R / "demo_e2e_exact_id_split4_2026-09-02.json"

with ARTEFATTO.open() as f:
    e2e = json.load(f)

config = e2e["provenienza"]["config_snapshot"]
contratto = config["contratto_esatto"]
comparatore = config["comparatore_fhe"]
if config["decisione"] != "exact_argmin_then_selected_threshold":
    raise ValueError("l'artefatto non usa la decisione exact-ID finale")
if comparatore["stato"] != "argmin_esatto_bucket_bits_dual_glwe":
    raise ValueError("l'artefatto non usa il comparatore exact-ID finale")
if contratto["codice"] != "0=rifiuto; i+1=identita_accettata":
    raise ValueError("contratto del codice exact-ID inatteso")
if not contratto["un_solo_lwe"]:
    raise ValueError("il contratto finale richiede un unico LWE")

n_galleria = e2e["n_galleria"]
n_query = e2e["positivi_totali"] + e2e["negativi_totali"]
n_corrette = e2e["positivi_corretti"] + e2e["negativi_corretti"]
preload_s = e2e["preload"]["secondi"]
pbs_totali = e2e["pbs"]
if len(pbs_totali) != 1:
    raise ValueError(f"conteggi PBS non omogenei nell'artefatto: {pbs_totali}")
pbs_totali = pbs_totali[0]
score_bits = contratto["score_bits"]

server_mediana = e2e["server_ms"]["median"]
server_p95 = e2e["server_ms"]["p95"]
endpoint_mediana = e2e["endpoint_http_ms"]["median"]
endpoint_p95 = e2e["endpoint_http_ms"]["p95"]

dimensione_probe = e2e["probe_cifrato_b"]
dimensione_esito = e2e["esito_cifrato_b"]
if len(dimensione_probe) != 1 or len(dimensione_esito) != 1:
    raise ValueError("dimensioni wire non omogenee nell'artefatto")
dimensione_probe = dimensione_probe[0]
dimensione_esito = dimensione_esito[0]

with (R / "demo_e2e_exact_id_split4_2026-09-02.csv").open() as f:
    righe = list(csv.DictReader(f))


def mediana(colonna):
    valori = sorted(float(riga[colonna]) for riga in righe)
    meta = len(valori) // 2
    return (valori[meta - 1] + valori[meta]) / 2


def intero_it(valore):
    return f"{valore:,}".replace(",", ".")


embedding_mediana = mediana("embedding_ms")
cifratura_mediana = mediana("cifratura_ms")
rete_server_mediana = mediana("rete_e_server_ms")
decifratura_mediana = mediana("decifratura_ms")

fig, ax = plt.subplots(figsize=(12.4, 5.8))
ax.set_xlim(0, 100)
ax.set_ylim(0, 55)
ax.axis("off")


def scatola(x, y, w, h, colore, titolo, righe, sottotitolo=""):
    ax.add_patch(
        FancyBboxPatch(
            (x, y),
            w,
            h,
            boxstyle="round,pad=0.6,rounding_size=1.2",
            facecolor="white",
            edgecolor=colore,
            linewidth=1.8,
        )
    )
    ax.text(
        x + 1.4, y + h - 3.2, titolo, fontsize=11.5, fontweight="bold", color=colore
    )
    if sottotitolo:
        ax.text(
            x + 1.4, y + h - 6.0, sottotitolo, fontsize=8.4, color=TENUE, style="italic"
        )
    for i, (t, c) in enumerate(righe):
        ax.text(x + 1.4, y + h - 9.6 - i * 3.5, t, fontsize=8.9, color=c)


# ── i tre ruoli
scatola(
    1,
    8,
    27,
    43,
    CLIENT,
    "Client — terminale al varco",
    [
        ("● chiave SEGRETA (23,6 KB)", "#111"),
        ("● telecamera: raffica di 3 frame", "#444"),
        (f"● ResNet100 in chiaro → med. {embedding_mediana:.0f} ms", "#444"),
        ("● fusione multi-frame (F48)", "#444"),
        ("● quantizzazione 3 bit e vincoli sul probe", "#444"),
        ("● doppio canale nello stesso GLWE", "#444"),
        (
            f"● cifra + decifra → med. {cifratura_mediana + decifratura_mediana:.0f} ms",
            "#444",
        ),
        ("● decifra 0 oppure i+1", "#444"),
        ("il volto e l'embedding in chiaro restano qui", CLIENT),
    ],
    "fidato: sta accanto alla persona",
)

scatola(
    72,
    8,
    27,
    43,
    SERVER,
    "Server — macchina remota",
    [
        ("● galleria IN CHIARO (Mondo 1)", "#111"),
        ("● chiave di VALUTAZIONE (129,7 MB)", "#444"),
        (f"● score interi esatti su {score_bits} bit", "#444"),
        ("● argmin MSB→LSB; pareggio al primo indice", "#444"),
        ("● seleziona la soglia del solo vincitore", "#444"),
        (f"● exact-ID: {intero_it(pbs_totali)} PBS per query", "#444"),
        (
            f"● server med. {intero_it(round(server_mediana))} ms; "
            f"p95 {intero_it(round(server_p95))} ms",
            "#444",
        ),
        ("non ha la chiave: calcola alla cieca", SERVER),
    ],
    "honest-but-curious sul probe",
)

# ── il filo
ax.text(
    50,
    49,
    "query online: probe ed esito cifrati",
    fontsize=10,
    color=FILO,
    ha="center",
    fontweight="bold",
)
for y, testo, dettaglio, verso in [
    (40, "probe cifrato", f"un GLWE — {intero_it(dimensione_probe)} byte", 1),
    (
        25,
        "codice exact-ID cifrato",
        f"pacchetto con un LWE — {intero_it(dimensione_esito)} byte · 0=rifiuto, i+1=identità",
        -1,
    ),
]:
    x0, x1 = (29.5, 70.5) if verso > 0 else (70.5, 29.5)
    ax.add_patch(
        FancyArrowPatch(
            (x0, y),
            (x1, y),
            arrowstyle="-|>",
            mutation_scale=17,
            linewidth=2.0,
            color=FILO,
        )
    )
    ax.text(
        50, y + 1.6, testo, fontsize=9.6, color=FILO, ha="center", fontweight="bold"
    )
    ax.text(50, y - 3.0, dettaglio, fontsize=8.4, color=TENUE, ha="center")

ax.text(
    50,
    17.0,
    "sul server: mai in chiaro probe, punteggi, distanza minima o identità rifiutata",
    fontsize=8.8,
    color="#c0392b",
    ha="center",
    style="italic",
)
ax.text(
    50,
    10.8,
    f"setup: chiave di valutazione (non segreta) · galleria in chiaro (Mondo 1)\n"
    f"preload di {n_galleria} template: {preload_s:.1f} s",
    fontsize=8.0,
    color=TENUE,
    ha="center",
)

# ── barra dei tempi
ax.text(
    50,
    4.6,
    f"endpoint HTTP exact-ID: mediana {intero_it(round(endpoint_mediana))} ms, "
    f"p95 {intero_it(round(endpoint_p95))} ms "
    f"({n_corrette}/{n_query}: 3 identità esatte + 3 rifiuti)",
    fontsize=10,
    ha="center",
    fontweight="bold",
    color="#222",
)
tempi = [
    ("embedding (client)", embedding_mediana, CLIENT),
    ("cifra", cifratura_mediana, "#3fb6a6"),
    ("rete + server", rete_server_mediana, SERVER),
    ("decifra", decifratura_mediana, FILO),
]
tot = sum(t[1] for t in tempi)
x = 12.0
for nome, ms, c in tempi:
    w = 76.0 * ms / tot
    ax.add_patch(
        FancyBboxPatch(
            (x, 0.9),
            w,
            2.2,
            boxstyle="square,pad=0",
            facecolor=c,
            edgecolor="white",
            linewidth=0.8,
        )
    )
    if w > 7:
        ax.text(
            x + w / 2,
            1.95,
            f"{ms:.0f} ms",
            fontsize=7.6,
            color="white",
            ha="center",
            va="center",
            fontweight="bold",
        )
    x += w

ax.text(
    12,
    -1.5,
    f"client: embedding {embedding_mediana:.0f} ms; cifra {cifratura_mediana:.0f} ms",
    fontsize=7.2,
    color=TENUE,
    ha="left",
)
ax.text(50, -1.5, "rete + server", fontsize=7.2, color=TENUE, ha="center")
ax.text(
    88,
    -1.5,
    f"decifra {decifratura_mediana:.0f} ms",
    fontsize=7.2,
    color=TENUE,
    ha="right",
)

ax.text(
    50,
    -3.0,
    "Smoke operativo exact-ID; non stima da solo il p-fail del circuito composto",
    fontsize=8.8,
    ha="center",
    fontweight="bold",
    color="#c0392b",
)
ax.set_ylim(-5.5, 55)
fig.suptitle(
    "Il varco exact-ID: chi sa cosa, e cosa attraversa il filo",
    fontsize=13.5,
    fontweight="bold",
    y=0.99,
)
fig.text(
    0.5,
    0.935,
    "argmin intero esatto + soglia del vincitore · N=127 · run Docker 2026-09-02 · 3 genuini + 3 impostori",
    fontsize=9,
    color=TENUE,
    ha="center",
)
fig.tight_layout(rect=[0, 0, 1, 0.925])
for ext in ("png", "svg"):
    metadata = {"Date": None} if ext == "svg" else None
    fig.savefig(
        R / f"architettura.{ext}", dpi=DPI, bbox_inches="tight", metadata=metadata
    )
# Matplotlib lascia spazi terminali nei path SVG: normalizzali per mantenere pulito `git diff --check`.
svg = R / "architettura.svg"
svg.write_text("\n".join(line.rstrip() for line in svg.read_text().splitlines()) + "\n")
print("scritto architettura.png/svg @", DPI, "dpi")
