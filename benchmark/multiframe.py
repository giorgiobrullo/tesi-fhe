"""Fusione multi-frame: quanto migliora il varco usando piu' foto (F48)?

Al cancello la telecamera da' una raffica di frame, e ogni iscritto puo' avere piu' foto di
registrazione. Aggregare (media degli embedding, poi L2-normalizzazione) e' standard in biometria
e — cosa che conta qui — e' GRATIS lato FHE: il client media i k_probe frame in UN embedding prima
di cifrare, il server calcola lo stesso identico varco; e il template della galleria (media di
k_gal foto) e' in chiaro sul server. Nessun costo cifrato in piu', potenziale guadagno di DIR.

Misura la DIR@FPIR=1% (protocollo 1:N open-set di F19, ResNet100 su VGGFace2 reale) al variare di
k_gal (foto per template) e k_probe (frame per query), tenendo le foto di galleria e di probe
DISGIUNTE (6 immagini per identita': niente foto condivisa, niente leakage). Baseline = (1,1).
"""
import csv
import itertools
import pathlib
import sys

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.metriche import dir_at_fpir   # noqa: E402

OUT = ROOT / "benchmark" / "results"
z = np.load(OUT / "_emb_reale_extra.npz")
E, y = z["rn100"].astype(np.float32), z["y"]
E = E / (np.linalg.norm(E, axis=1, keepdims=True) + 1e-9)

# per identita': lista degli indici delle sue 6 immagini
per_id = {}
for i, yy in enumerate(y):
    per_id.setdefault(int(yy), []).append(i)
ids = np.array(sorted(k for k, v in per_id.items() if len(v) >= 6))


def fondi(indici_lista):
    """media L2-normalizzata degli embedding (aggregazione multi-frame)."""
    v = E[indici_lista].mean(0)
    return v / (np.linalg.norm(v) + 1e-9)


def valuta(N, k_gal, k_probe, seed=0):
    rng = np.random.RandomState(seed)
    sel = ids.copy(); rng.shuffle(sel)
    iscritti, altri = sel[:N], sel[N:N * 2]           # meta' iscritti, meta' identita' ignote
    Eg, yg = [], []
    Epn, ypn = [], []
    for sid in iscritti:
        im = per_id[sid][:]; rng.shuffle(im)
        Eg.append(fondi(im[:k_gal])); yg.append(sid)   # template = k_gal foto
        resto = im[k_gal:]                              # le foto rimaste -> probe (disgiunte)
        for lotto in [resto[i:i + k_probe] for i in range(0, len(resto), k_probe)]:
            if len(lotto) == k_probe:
                Epn.append(fondi(lotto)); ypn.append(sid)
    Epi = []
    for sid in altri:
        im = per_id[sid][:]; rng.shuffle(im)
        for lotto in [im[i:i + k_probe] for i in range(0, len(im), k_probe)]:
            if len(lotto) == k_probe:
                Epi.append(fondi(lotto))
    Eg, yg = np.array(Eg), np.array(yg)
    Epn, ypn, Epi = np.array(Epn), np.array(ypn), np.array(Epi)
    return dir_at_fpir(Eg, yg, Epn, ypn, Epi), len(Epn), len(Epi)


if __name__ == "__main__":
    N = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    combos = [(kg, kp) for kg, kp in itertools.product([1, 2, 3], [1, 2, 3]) if kg + kp <= 6]
    print(f"N={N} iscritti, ResNet100, VGGFace2 reale, 5 seed. DIR@FPIR=1% per (k_gal, k_probe):\n")
    righe = []
    base = None
    for kg, kp in combos:
        ds = [valuta(N, kg, kp, s)[0] for s in range(5)]
        d = float(np.mean(ds)); sd = float(np.std(ds))
        if (kg, kp) == (1, 1):
            base = d
        delta = "" if base is None else f"  ({(d - base) * 100:+.1f})"
        print(f"  k_gal={kg}, k_probe={kp}: {d:.1%} ± {sd:.1%}{delta}")
        righe.append({"N": N, "k_gal": kg, "k_probe": kp, "dir": round(d, 4), "std": round(sd, 4)})
    with open(OUT / "multiframe.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)
    print(f"\nscritto {OUT / 'multiframe.csv'}")
