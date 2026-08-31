"""Limitare la norma L1 dei template: due bit di Delta in cambio di quanta accuratezza? (F68)

Il Delta difendibile e' 2^63 / (2q*max||g_i||_1 + max||g_i||^2 + |T|), quindi ||g||_1 e' la leva
che il server controlla all'iscrizione. Azzerando i coefficienti piu' piccoli finche' ||g||_1 <= cap
il bound crolla e Delta sale; con Delta piu' grande la banda di rumore in unita' di punteggio si
stringe, e i set di parametri piccoli (piu' veloci) tornano utilizzabili.

Qui misuro il prezzo: DIR@FPIR=1% al variare del cap, protocollo 1:N open-set completo su embedding
reali (ResNet100, VGGFace2), 10 semi, con la fusione multi-frame di F48.
"""
import csv
import pathlib

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "benchmark" / "results"
z = np.load(OUT / "_emb_reale_extra.npz")
E, y = z["rn100"].astype(np.float32), z["y"]
E = E / (np.linalg.norm(E, axis=1, keepdims=True) + 1e-9)
per_id = {}
for i, v in enumerate(y):
    per_id.setdefault(int(v), []).append(i)
QM, SEEDS, K_GAL, K_PROBE = 3, 10, 2, 3


def fondi(idx):
    v = E[idx].mean(0); return v / (np.linalg.norm(v) + 1e-9)


def scena(rng, N, ni=600):
    ids = np.array(sorted(k for k, v in per_id.items() if len(v) >= K_GAL + K_PROBE)); rng.shuffle(ids)
    G, gen = [], []
    for s in ids[:N]:
        im = per_id[s][:]; rng.shuffle(im)
        G.append(fondi(im[:K_GAL])); gen.append(fondi(im[K_GAL:K_GAL + K_PROBE]))
    imp = [fondi(per_id[s][:K_PROBE]) for s in ids[N:N + ni]]
    return np.array(G), np.array(gen), np.array(imp)


def limita(G, cap):
    """azzera i coefficienti piu' piccoli finche' ||g||_1 <= cap (in chiaro, all'iscrizione)"""
    if cap is None:
        return G
    H = G.copy()
    for i in range(len(H)):
        v = H[i]; ordine = np.argsort(np.abs(v)); k = 0
        while np.abs(v).sum() > cap and k < len(v):
            v[ordine[k]] = 0; k += 1
    return H


righe = []
print("DIR@FPIR=1% al variare del cap su ||g||_1 (ResNet100, VGGFace2, 3 bit, fusione 2+3, 10 semi)\n")
print(f"{'N':>5} | {'cap':>6} | {'nnz':>4} | {'bound':>6} | {'Delta':>6} | {'DIR':>13} | {'costo'}")
for N in (128, 1024):
    base = None
    for cap in (None, 200, 150, 110, 90):
        d, bo, nz = [], [], []
        for seed in range(SEEDS):
            rng = np.random.RandomState(seed)
            Gf, genf, impf = scena(rng, N)
            sc = float(np.percentile(np.abs(np.vstack([Gf, genf, impf])), 99.5) / QM)
            q = lambda x: np.clip(np.round(x / sc), -QM, QM).astype(np.int64)
            G, gen, imp = limita(q(Gf), cap), q(genf), q(impf)
            bsq = (G * G).sum(1)
            Sg, Si = bsq[None, :] - 2 * (gen @ G.T), bsq[None, :] - 2 * (imp @ G.T)
            T = np.quantile(Si.min(1), 0.01, method="lower")
            d.append(np.mean((Sg <= T).any(1) & (Sg.argmin(1) == np.arange(N))))
            bo.append(2 * QM * int(np.abs(G).sum(1).max()) + int(bsq.max()) + abs(int(T)))
            nz.append((G != 0).sum(1).mean())
        m, b = float(np.mean(d)), int(np.mean(bo))
        ld = 63 - int(np.ceil(np.log2(b + 1)))
        if base is None: base = m
        print(f"{N:>5} | {str(cap):>6} | {np.mean(nz):>4.0f} | {b:>6} | {'2^'+str(ld):>6} | "
              f"{m:>12.1%} | {m-base:+.1f} punti")
        righe.append({"N": N, "cap": cap or 0, "nnz": round(float(np.mean(nz)), 1), "bound": b,
                      "log_delta": ld, "dir": round(m, 4), "delta_dir": round(m - base, 4)})
with open(OUT / "norma_limitata.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)
print(f"\nscritto {OUT / 'norma_limitata.csv'}")
