"""Percorso storico della tesi e punto operativo exact-ID finale.

(a) ricostruisce i passi storici a N=8;
(b) conserva le curve storiche, ottenute con versioni e parametri diversi, e sovrappone
    il punto exact-ID a N=127 dal run end-to-end Docker del 2026-09-02.

Le curve non sono un benchmark omogeneo e quelle di soglia precedono il comparatore
finale. I percorsi any-match sono mantenuti soltanto come tappe storiche scartate:
non restituiscono l'identita' piu' vicina e quindi non soddisfano il requisito.

Legge i risultati reali: benchmark/results/costo_reale.csv (Concrete, F33),
experiments/14_pipeline_tfhe_rs/results/{selezione_16thread.txt, varco_leveled_{16,1}thread.txt} (F37/F38),
experiments/15_ckks_confronto/results/ckks_varco.csv (F39). I "perché" stanno nelle didascalie
dei findings, non nel grafico.
"""

import csv
import json
import pathlib
import re

import matplotlib.pyplot as plt
import numpy as np

DPI = 300
plt.rcParams["svg.hashsalt"] = "tesi-fhe-benchmark"
ROOT = pathlib.Path(__file__).resolve().parents[1]
R = ROOT / "benchmark" / "results"
E14 = ROOT / "experiments" / "14_pipeline_tfhe_rs" / "results"
E15 = ROOT / "experiments" / "15_ckks_confronto" / "results"
E2E = R / "demo_e2e_exact_id_split4_2026-09-02.json"


def leggi_tabella(nome, col):
    """legge una tabella 'N | c1 | c2 | ...' da un file di risultati di experiments/14."""
    out = {}
    f = E14 / nome
    if not f.exists():
        return out
    for line in open(f):
        parti = [x.strip() for x in line.split("|")]
        if len(parti) > col and parti[0].isdigit():
            try:
                out[int(parti[0])] = float(parti[col].replace("s", "").strip())
            except ValueError:
                pass
    return out


def concrete(tec):
    rows = csv.DictReader(open(R / "costo_reale.csv"))
    return {int(r["N"]): float(r["run_s"]) for r in rows if r["tecnica"] == tec}


def selezione(param, col):
    """col: 2 = seq-F32, 3 = seq, 4 = torneo (dal file testo del microbenchmark)."""
    out = {}
    for line in open(E14 / "selezione_16thread.txt"):
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 6 and parts[0] == param:
            out[int(parts[1])] = float(parts[col].rstrip("s"))
    return out


def varco(thread):
    """unisce il run sulla scena da 128 e, se c'e', quello sulla scena da 1024 (N = 256…1024)."""
    out = {}
    for nome in (
        f"varco_leveled_{thread}thread.txt",
        f"varco_leveled_{thread}thread_1024.txt",
    ):
        if not (E14 / nome).exists():
            continue
        for line in open(E14 / nome):
            m = re.match(r"\s*(\d+) \|\s*([\d.]+)s \|\s*([\d.]+)s \|\s*([\d.]+)s", line)
            if m:
                out.setdefault(int(m.group(1)), float(m.group(4)))
    return out


def argmin_delta():
    out = {}
    if (E14 / "argmin_delta_16thread.txt").exists():
        for line in open(E14 / "argmin_delta_16thread.txt"):
            m = re.match(
                r"\s*(\d+) \|\s*([\d.]+)s \|\s*([\d.]+)s \|\s*([\d.]+)s \|\s*([\d.]+)s \|\s*([\d.]+)s",
                line,
            )
            if m:
                out[int(m.group(1))] = float(m.group(6))
    return out


def ckks(poly, dg, df):
    rows = csv.DictReader(open(E15 / "ckks_varco.csv"))
    return {
        int(r["N"]): float(r["t_distanze"]) + float(r["t_soglia"])
        for r in rows
        if int(r["poly"]) == poly and int(r["dg"]) == dg and int(r["df"]) == df
    }


c_arg, c_sog = concrete("argmin"), concrete("soglia")
rad_seqF32, rad_seq, rad_tor = (
    selezione("def/u16", 2),
    selezione("def/u16", 3),
    selezione("def/u8", 4),
)
lev16 = varco(16)
ck = ckks(32768, 6, 2)

with E2E.open() as f:
    corrente = json.load(f)
config = corrente["provenienza"]["config_snapshot"]
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
n_corrente = corrente["n_galleria"]
server_min_corrente = corrente["server_ms"]["min"] / 1000
server_mediana_corrente = corrente["server_ms"]["median"] / 1000
server_p95_corrente = corrente["server_ms"]["p95"] / 1000
query_correnti = corrente["positivi_totali"] + corrente["negativi_totali"]
corrette_correnti = corrente["positivi_corretti"] + corrente["negativi_corretti"]
pbs_correnti = corrente["pbs"]
if len(pbs_correnti) != 1:
    raise ValueError(f"conteggi PBS non omogenei nell'artefatto: {pbs_correnti}")
pbs_correnti = pbs_correnti[0]
esiti_cifrati = corrente["esito_cifrato_b"]
if len(esiti_cifrati) != 1:
    raise ValueError(f"dimensioni dell'esito non omogenee: {esiti_cifrati}")
esito_cifrato_b = esiti_cifrati[0]


def intero_it(valore):
    return f"{valore:,}".replace(",", ".")


fig, (ax1, ax2) = plt.subplots(
    1, 2, figsize=(14, 5.4), gridspec_kw={"width_ratios": [1.1, 1]}
)

# ---------------- (a) il percorso a N=8: exact-ID e deviazioni scartate
passi = [
    ("EXACT-ID\nConcrete argmin\nsequenziale", c_arg[8], "#9aa3ad"),
    ("EXACT-ID\ntfhe-rs radix\ncatena (16 bit)", rad_seqF32[8], "#5b6b8c"),
    ("EXACT-ID\ntfhe-rs radix\ntorneo (8 bit)", rad_tor[8], "#6a4c93"),
    ("CONFRONTO\nCKKS packing\n+ segno", ck[8], "#e9a000"),
    (
        "SCARTATO\nsoglia diretta\nany-match",
        leggi_tabella("varco_1_0_sweep.txt", 3).get(8, lev16[8]),
        "#c0392b",
    ),
]
x = np.arange(len(passi))
ys = [p[1] for p in passi]
CONFRONTO = 3  # CKKS e' un confronto (F39), non un passo del percorso TFHE exact-ID
SCARTATO = 4
bars = ax1.bar(
    x, ys, color=[p[2] for p in passi], width=0.62, edgecolor="white", linewidth=0.8
)
bars[CONFRONTO].set_hatch("//")
bars[CONFRONTO].set_alpha(0.75)
bars[SCARTATO].set_hatch("xx")
bars[SCARTATO].set_alpha(0.72)
ax1.set_yscale("log")
ax1.set_ylim(0.005, 3000)
for i, (nome, y, c) in enumerate(passi):
    lab = (
        f"{y:.0f} s" if y >= 10 else (f"{y:.1f} s" if y >= 1 else f"{y * 1000:.0f} ms")
    )
    ax1.text(
        i,
        y * 1.35,
        lab,
        ha="center",
        fontsize=9.5,
        fontweight="bold",
        color=c if c != "#9aa3ad" else "#666",
    )
percorso = [0, 1, 2]
for a, b in zip(percorso, percorso[1:]):
    f = ys[a] / ys[b]
    xm = (a + b) / 2 if b - a == 1 else b - 0.5
    ax1.annotate(
        f"÷{f:.0f}" if f >= 3 else f"÷{f:.1f}",
        xy=(xm, np.sqrt(ys[a] * ys[b])),
        ha="center",
        va="center",
        fontsize=8.5,
        color="#c0392b",
        bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="none"),
    )
ax1.axhline(10, ls=(0, (4, 4)), lw=0.9, color="#bbb", zorder=0)
ax1.text(
    len(passi) - 0.45, 10, "10 s", fontsize=8, color="#999", va="center", ha="left"
)
ax1.set_xticks(x)
ax1.set_xticklabels([p[0] for p in passi], fontsize=8.6)
ax1.set_xlim(-0.6, len(passi) - 0.2)
ax1.set_ylabel("tempo per query sul server (s, scala log)")
ax1.set_title(
    "(a) Esplorazione storica a N = 8\nil gate veloce non soddisfa l'identificazione",
    fontsize=11,
)
ax1.annotate(
    "non restituisce l'ID\npiù vicino",
    xy=(SCARTATO, ys[SCARTATO]),
    xytext=(SCARTATO - 0.35, 0.055),
    textcoords="data",
    fontsize=8.4,
    color="#c0392b",
    fontweight="bold",
    ha="center",
    arrowprops=dict(arrowstyle="-|>", color="#c0392b", lw=1.0),
)
ax1.spines[["top", "right"]].set_visible(False)
ax1.tick_params(labelsize=9)

# ---------------- (b) i design finali al crescere di N
# Ogni serie e' storica: gli stili tratteggiati sono gate any-match scartati.
serie = [
    ("scartato: Concrete soglia (F28)", c_sog, "#aeb6bf", "s", 0, "--", 0.65),
    (
        "exact-ID storico: argmin matrice N² (F45)",
        argmin_delta(),
        "#e07a5f",
        "v",
        7,
        "-",
        0.9,
    ),
    (
        "exact-ID storico: radix torneo 8 bit (F38)",
        rad_tor,
        "#6a4c93",
        "D",
        -1,
        "-",
        0.9,
    ),
    ("confronto: CKKS packing + segno (F39)", ck, "#e9a000", "^", -9, ":", 0.8),
    ("scartato: soglia tfhe-rs (F37/F46)", lev16, "#9cc9c2", "o", 8, "--", 0.58),
    (
        "scartato: soglia set 1_0 (F55)",
        leggi_tabella("varco_1_0_sweep.txt", 3),
        "#1b6f65",
        "o",
        -9,
        "--",
        0.58,
    ),
    (
        "scartato: soglia con galleria cifrata (F51)",
        leggi_tabella("galleria_cifrata_1024.txt", 3),
        "#2a9d8f",
        "s",
        9,
        "--",
        0.58,
    ),
    (
        "exact-ID storico: argmin a torneo (F52)",
        leggi_tabella("argmin_torneo.txt", 3),
        "#c0392b",
        "^",
        -9,
        "-",
        0.9,
    ),
]
for nome, d, c, mk, dy, ls, alpha in serie:
    if not d:
        continue
    ns = sorted(d)
    vals = [d[n] for n in ns]
    ax2.plot(
        ns,
        vals,
        marker=mk,
        linestyle=ls,
        color=c,
        label=nome,
        lw=1.8,
        ms=6.2,
        alpha=alpha,
    )
    n_last, v_last = ns[-1], vals[-1]
    lab = (
        f"{v_last:.0f} s"
        if v_last >= 10
        else (f"{v_last:.1f} s" if v_last >= 1 else f"{v_last * 1000:.0f} ms")
    )
    ax2.annotate(
        lab,
        (n_last, v_last),
        xytext=(7, dy),
        textcoords="offset points",
        fontsize=8.5,
        color=c,
        fontweight="bold",
        va="center",
    )

# Il solo dato del percorso finale: non lo si unisce alle curve storiche per evitare di
# suggerire una continuita' sperimentale inesistente tra versioni, parametri e carichi diversi.
ax2.vlines(
    n_corrente,
    server_min_corrente,
    server_p95_corrente,
    color="#111111",
    linewidth=2.3,
    zorder=8,
)
ax2.scatter(
    [n_corrente],
    [server_mediana_corrente],
    marker="*",
    s=190,
    color="#111111",
    edgecolor="white",
    linewidth=0.8,
    zorder=9,
    label="finale: exact-ID + soglia del vincitore",
)
ax2.annotate(
    f"exact-ID N={n_corrente}\nmed. {server_mediana_corrente:.3f} s · p95 {server_p95_corrente:.3f} s\n"
    f"{intero_it(pbs_correnti)} PBS · {corrette_correnti}/{query_correnti} query",
    (n_corrente, server_mediana_corrente),
    xytext=(0.58, 0.73),
    textcoords="axes fraction",
    fontsize=8.5,
    color="#111111",
    fontweight="bold",
    ha="left",
    va="bottom",
    bbox=dict(boxstyle="round,pad=0.28", fc="white", ec="#111111", lw=0.8),
    arrowprops=dict(arrowstyle="-", color="#111111", lw=0.8),
)
ax2.set_xscale("log", base=2)
ax2.set_yscale("log")
ax2.set_xticks([8, 32, 128, 512, 2048])
ax2.set_xticklabels(["8", "32", "128", "512", "2048"])
ax2.set_ylim(0.004, 400)
ax2.set_xlim(7, 9000)
for y, t in ((10, "10 s"), (5, "5 s")):
    ax2.axhline(y, ls=(0, (4, 4)), lw=0.9, color="#bbb", zorder=0)
    ax2.text(5200, y, t, fontsize=8, color="#999", va="center", ha="left")
ax2.set_xlabel("iscritti in galleria N")
ax2.set_ylabel("tempo per query (s, scala log)")
ax2.set_title(
    "(b) Curve storiche + risultato exact-ID finale\nconfronto orientativo, non benchmark omogeneo",
    fontsize=11,
)
ax2.legend(fontsize=7.6, loc="lower right", frameon=False)
ax2.spines[["top", "right"]].set_visible(False)
ax2.tick_params(labelsize=9)

fig.text(
    0.5,
    0.012,
    f"Stella: pacchetto da {intero_it(esito_cifrato_b)} byte con un solo LWE; plaintext 0=rifiuto, "
    f"i+1=ID accettata; {intero_it(pbs_correnti)} PBS. I gate any-match tratteggiati sono scartati.",
    ha="center",
    fontsize=8.4,
    color="#666666",
)
fig.tight_layout(rect=[0, 0.055, 1, 1])
for ext in ("png", "svg"):
    metadata = {"Date": None} if ext == "svg" else None
    fig.savefig(R / f"percorso.{ext}", dpi=DPI, bbox_inches="tight", metadata=metadata)
svg = R / "percorso.svg"
svg.write_text("\n".join(line.rstrip() for line in svg.read_text().splitlines()) + "\n")
print("scritto percorso.png/svg @", DPI, "dpi")
