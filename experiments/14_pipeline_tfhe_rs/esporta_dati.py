"""Esporta una scena REALE per i microbenchmark tfhe-rs (esperimento 14).

Galleria di N=128 iscritti (1 immagine ciascuno, ResNet100 su VGGFace2, quantizzata a 4 bit),
64 probe genuini + 64 impostori, e la soglia T tarata al quantile 1% dei minimi di 2000
impostori (come in precisione_punteggio.py). Tutto intero: i binari Rust ricalcolano i punteggi
in chiaro e verificano l'esito cifrato contro quello in chiaro.

Formato (results/scena_reale.txt), tutto su righe di interi separati da spazi:
  DIM N NPROBE T
  N righe: galleria (DIM interi)
  NPROBE righe: etichetta (indice in galleria, o -1 se impostore) + probe (DIM interi)
"""
import pathlib
import sys

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
OUT = pathlib.Path(__file__).resolve().parent / "results"
OUT.mkdir(exist_ok=True)

B = np.load(ROOT / "benchmark" / "results" / "_emb_reale_extra.npz")
E_full, y_full = B["rn100"].astype(np.float32), B["y"]
N = int(sys.argv[1]) if len(sys.argv) > 1 else 128      # es. 1024 per la scala
N_GEN, N_IMP, N_IMP_TARA, Q = 64, 64, 2000, 4


def quant_fit(pool, q=Q):
    qm = 2 ** (q - 1) - 1
    return np.percentile(np.abs(pool), 99.5) / qm, qm


def quant(E, sc, qm):
    return np.clip(np.round(E / sc), -qm, qm).astype(np.int64)


rng = np.random.RandomState(0)
ids = np.unique(y_full); rng.shuffle(ids)
iscritti, altri = ids[:N], ids[N:]
g_idx, gen_idx, gen_lab = [], [], []
for k, sid in enumerate(iscritti):
    idx = np.where(y_full == sid)[0]
    g_idx.append(idx[0]); gen_idx += list(idx[1:]); gen_lab += [k] * (len(idx) - 1)
imp_pool = np.where(np.isin(y_full, altri))[0]
imp_tara = rng.choice(imp_pool, N_IMP_TARA, replace=False)
gen_sel = rng.choice(len(gen_idx), N_GEN, replace=False)

Gf = E_full[g_idx]
sc, qm = quant_fit(np.vstack([Gf, E_full[gen_idx], E_full[imp_tara]]))
G = quant(Gf, sc, qm); bsq = np.sum(G * G, axis=1)
S_imp = bsq[None, :] - 2 * (quant(E_full[imp_tara], sc, qm) @ G.T)
T = int(np.quantile(S_imp.min(1), 0.01, method="lower"))

probes, labels = [], []
for j in gen_sel:
    probes.append(quant(E_full[gen_idx[j]], sc, qm)); labels.append(gen_lab[j])
for j in imp_tara[:N_IMP]:
    probes.append(quant(E_full[j], sc, qm)); labels.append(-1)
P = np.array(probes)
S = bsq[None, :] - 2 * (P @ G.T)
smin, smax = int(S.min()), int(S.max())

NOME = "scena_reale.txt" if N == 128 else f"scena_reale_{N}.txt"
with open(OUT / NOME, "w") as fp:
    fp.write(f"{G.shape[1]} {N} {len(P)} {T}\n")
    for g in G:
        fp.write(" ".join(map(str, g)) + "\n")
    for lab, p in zip(labels, P):
        fp.write(str(lab) + " " + " ".join(map(str, p)) + "\n")

jm = S.argmin(1); mn = S[np.arange(len(S)), jm]; lab = np.array(labels)
gen = lab >= 0
print(f"scritto {OUT / NOME}: DIM={G.shape[1]} N={N} probe={len(P)} T={T}")
print(f"punteggi in [{smin}, {smax}] -> {int(np.ceil(np.log2(max(abs(smin), abs(smax)) + 1))) + 1} bit signed")
print(f"in chiaro: genuini riconosciuti {np.mean((jm[gen] == lab[gen]) & (mn[gen] <= T)):.1%}, "
      f"impostori accettati {np.mean(mn[~gen] <= T):.1%}; "
      f"iscritti sotto soglia per probe: media {np.mean((S <= T).sum(1)):.2f}, max {(S <= T).sum(1).max()}")
