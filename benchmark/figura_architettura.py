"""Figura dell'architettura del varco (F49): i tre ruoli, cosa attraversa il filo, i tempi veri.

Non è uno schema di principio: i numeri sono quelli misurati dalla demo end-to-end (demo/,
127 iscritti, M4 Max, server in container). Il punto della figura è mostrare **dove sta cosa**:
la chiave segreta e il volto da una parte, la galleria dall'altra, e in mezzo solo byte cifrati.
"""
import pathlib

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

DPI = 300
R = pathlib.Path(__file__).resolve().parent / "results"
CLIENT, SERVER, FILO, TENUE = "#2a9d8f", "#e9a000", "#6a4c93", "#7a8a94"

fig, ax = plt.subplots(figsize=(12.4, 5.0))
ax.set_xlim(0, 100); ax.set_ylim(0, 55); ax.axis("off")


def scatola(x, y, w, h, colore, titolo, righe, sottotitolo=""):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.6,rounding_size=1.2",
                                facecolor="white", edgecolor=colore, linewidth=1.8))
    ax.text(x + 1.4, y + h - 3.2, titolo, fontsize=11.5, fontweight="bold", color=colore)
    if sottotitolo:
        ax.text(x + 1.4, y + h - 6.0, sottotitolo, fontsize=8.4, color=TENUE, style="italic")
    for i, (t, c) in enumerate(righe):
        ax.text(x + 1.4, y + h - 9.6 - i * 3.5, t, fontsize=8.9, color=c)


# ── i tre ruoli
scatola(1, 6, 27, 45, CLIENT, "Client — terminale al varco", [
    ("● chiave SEGRETA (23 KB)", "#111"),
    ("● telecamera: raffica di 3 frame", "#444"),
    ("● ResNet100 in chiaro → 170 ms", "#444"),
    ("● fusione multi-frame (F48)", "#444"),
    ("● quantizzazione 3 bit (F47)", "#444"),
    ("● cifra e decifra → 18 ms", "#444"),
    ("", "#444"),
    ("il volto non esce mai da qui", CLIENT),
], "fidato: sta accanto alla persona")

scatola(72, 6, 27, 45, SERVER, "Server — macchina remota", [
    ("● galleria IN CHIARO (Mondo 1)", "#111"),
    ("● chiave di VALUTAZIONE (119 MB)", "#444"),
    ("● prodotto scalare leveled: 0 PBS", "#444"),
    ("● 127 soglie cifrate in parallelo", "#444"),
    ("   1 bootstrap di segno ciascuna", "#444"),
    ("● 125 ms per query", "#444"),
    ("", "#444"),
    ("non ha la chiave: calcola alla cieca", SERVER),
], "honest-but-curious sul volto")

# ── il filo
ax.text(50, 49, "sul filo passa solo cifrato", fontsize=10, color=FILO, ha="center", fontweight="bold")
for y, testo, dettaglio, verso in [(40, "probe cifrato", "un GLWE — 20 KB", 1),
                                   (25, "esito cifrato", "conteggio + indice — 230 KB", -1)]:
    x0, x1 = (29.5, 70.5) if verso > 0 else (70.5, 29.5)
    ax.add_patch(FancyArrowPatch((x0, y), (x1, y), arrowstyle="-|>", mutation_scale=17,
                                 linewidth=2.0, color=FILO))
    ax.text(50, y + 1.6, testo, fontsize=9.6, color=FILO, ha="center", fontweight="bold")
    ax.text(50, y - 3.0, dettaglio, fontsize=8.4, color=TENUE, ha="center")

ax.text(50, 17.0, "mai: il volto, l'embedding, i punteggi, la distanza", fontsize=8.8,
        color="#c0392b", ha="center", style="italic")
ax.text(50, 10.8, "una volta sola, alla messa in servizio:\nchiave di valutazione, non la segreta",
        fontsize=8.0, color=TENUE, ha="center")

# ── barra dei tempi
ax.text(50, 4.6, "una query end-to-end: 288 ms", fontsize=10, ha="center", fontweight="bold", color="#222")
tempi = [("embedding (client)", 170, CLIENT), ("cifra", 10, "#3fb6a6"),
         ("varco cifrato (server)", 125, SERVER), ("decifra", 8, FILO)]
tot = sum(t[1] for t in tempi)
x = 12.0
for nome, ms, c in tempi:
    w = 76.0 * ms / tot
    ax.add_patch(FancyBboxPatch((x, 0.9), w, 2.2, boxstyle="square,pad=0", facecolor=c, edgecolor="white", linewidth=0.8))
    if w > 7:
        ax.text(x + w / 2, 1.95, f"{ms} ms", fontsize=7.6, color="white", ha="center", va="center", fontweight="bold")
    ax.text(x + w / 2, -1.5 if len(nome) < 16 else -1.5, nome, fontsize=7.2, color=TENUE, ha="center")
    x += w

ax.set_ylim(-3.5, 55)
fig.suptitle("Il varco cifrato: chi sa cosa, e cosa attraversa il filo", fontsize=13.5, fontweight="bold", y=0.99)
fig.text(0.5, 0.935, "misure della demo end-to-end (demo/), galleria di 127 iscritti, M4 Max, server in container",
         fontsize=9, color=TENUE, ha="center")
fig.tight_layout(rect=[0, 0, 1, 0.925])
for ext in ("png", "svg"):
    fig.savefig(R / f"architettura.{ext}", dpi=DPI, bbox_inches="tight")
print("scritto architettura.png/svg @", DPI, "dpi")
