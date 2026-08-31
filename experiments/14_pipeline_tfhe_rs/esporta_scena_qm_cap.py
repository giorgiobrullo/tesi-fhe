"""Scena reale con quantizzatore a LIVELLI arbitrari (qm) e tetto sulla norma L1 della galleria.

Come esporta_dati.py, ma:
  - qm e' il numero di livelli per lato (valori in [-qm, qm]), NON 2^(q-1)-1: cosi' e' esprimibile
    anche qm=2 (5 livelli), che la griglia a potenze di due saltava;
  - --cap C azzera i coefficienti piu' piccoli di ogni template finche' ||g||_1 <= C (F58).

  python3 esporta_scena_qm_cap.py N QM CAP   ->  results/scena_reale_qm{QM}_cap{CAP}.txt
"""
import pathlib, sys
import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = pathlib.Path(__file__).resolve().parent / "results"; OUT.mkdir(exist_ok=True)
B = np.load(ROOT / "benchmark" / "results" / "_emb_reale_extra.npz")
E_full, y_full = B["rn100"].astype(np.float32), B["y"]
N = int(sys.argv[1]) if len(sys.argv) > 1 else 128
QM = int(sys.argv[2]) if len(sys.argv) > 2 else 2       # livelli per lato: 3 = punto attuale, 2 = candidato
CAP = int(sys.argv[3]) if len(sys.argv) > 3 else 170    # tetto su ||g||_1; 0 = nessuno
N_GEN, N_IMP, N_IMP_TARA = 64, 64, 2000

def limita(G, cap):
    if not cap: return G
    H = G.copy()
    for i in range(len(H)):
        v = H[i]; o = np.argsort(np.abs(v)); k = 0
        while np.abs(v).sum() > cap and k < len(v):
            v[o[k]] = 0; k += 1
    return H

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
sc = float(np.percentile(np.abs(np.vstack([Gf, E_full[gen_idx], E_full[imp_tara]])), 99.5) / QM)
q = lambda x: np.clip(np.round(x / sc), -QM, QM).astype(np.int64)
G = limita(q(Gf), CAP); bsq = np.sum(G * G, axis=1)
S_imp = bsq[None, :] - 2 * (q(E_full[imp_tara]) @ G.T)
T = int(np.quantile(S_imp.min(1), 0.01, method="lower"))

probes, labels = [], []
for j in gen_sel: probes.append(q(E_full[gen_idx[j]])); labels.append(gen_lab[j])
for j in imp_tara[:N_IMP]: probes.append(q(E_full[j])); labels.append(-1)
P = np.array(probes); S = bsq[None, :] - 2 * (P @ G.T)

NOME = f"scena_reale{'' if N == 128 else '_' + str(N)}_qm{QM}_cap{CAP}.txt"
with open(OUT / NOME, "w") as fp:
    fp.write(f"{G.shape[1]} {N} {len(P)} {T}\n")
    for g in G: fp.write(" ".join(map(str, g)) + "\n")
    for lab, p in zip(labels, P): fp.write(str(lab) + " " + " ".join(map(str, p)) + "\n")

l1 = np.abs(G).sum(1); qmax = max(int(np.abs(G).max()), int(np.abs(P).max()))
bound = 2 * qmax * int(l1.max()) + int(bsq.max()) + abs(T)
stretto = int((2 * qmax * l1 + np.abs(bsq - T)).max())
jm = S.argmin(1); mn = S[np.arange(len(S)), jm]; lab = np.array(labels); gen = lab >= 0
print(f"scritto {OUT / NOME}: DIM={G.shape[1]} N={N} qm={QM} cap={CAP} T={T}")
print(f"nnz medio {np.mean((G != 0).sum(1)):.1f} | ||g||_1 max {l1.max()} | ||g||^2 max {bsq.max()}")
print(f"bound (formula attuale) {bound} -> Delta = 2^{63 - int(np.ceil(np.log2(bound + 1)))}")
print(f"bound stretto max_i(2q||g_i||_1 + |bsq_i - T|) {stretto} -> Delta = 2^{63 - int(np.ceil(np.log2(stretto + 1)))}")
print(f"in chiaro: genuini riconosciuti {np.mean((jm[gen] == lab[gen]) & (mn[gen] <= T)):.1%}, "
      f"impostori accettati {np.mean(mn[~gen] <= T):.1%}")
