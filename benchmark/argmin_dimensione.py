"""L'argmin cifrato dipende dalla DIMENSIONE dell'embedding? (ricostruzione, F64)

`benchmark/results/compressione_tradeoff.csv` riporta 457 / 542 / 586 s a 512 / 128 / 64
dimensioni, citando tre script (`argmin_verifica.py`, `dim_sweep.py`, `argmin_dim.py`) che **non
esistono nel repo ne' nella storia git**: i numeri c'erano, il codice no. Questo script rifa la
misura da zero, cosi' la conclusione di F23/F31 ("comprimere non abbassa il costo dell'argmin,
la dimensione non e' una leva FHE") torna verificabile.

Stesso circuito di benchmark/breakdown_query.py: punteggio ||g||^2 - 2 g.a su galleria in chiaro
(0 PBS), poi argmin sequenziale con strategia CHUNKED. Embedding ResNet100 reali, 4 bit.
La dimensione si riduce con PCA, come in F31.

  PATH=$(pwd)/tools/ldfix:$PATH uv run python benchmark/argmin_dimensione.py     (vedi tools/README.md)
"""
import csv
import pathlib
import sys
import time

import numpy as np
from concrete import fhe

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "benchmark" / "results"
B = np.load(OUT / "_emb_reale_extra.npz")
E_full = B["rn100"].astype(np.float64)
y = B["y"]
rng = np.random.RandomState(0)
N = int(sys.argv[1]) if len(sys.argv) > 1 else 4
DIMS = [int(x) for x in sys.argv[2].split(",")] if len(sys.argv) > 2 else [512, 128, 64]


def proietta(dim):
    """PCA a `dim` componenti (identita' se dim = 512), stimata sull'intero insieme."""
    if dim >= E_full.shape[1]:
        return E_full
    X = E_full - E_full.mean(0)
    _, _, Vt = np.linalg.svd(X[:2000], full_matrices=False)
    return X @ Vt[:dim].T


def quant(E, q=4):
    qm = 2 ** (q - 1) - 1
    sc = np.percentile(np.abs(E), 99.5) / qm
    return np.clip(np.round(E / sc), -qm, qm).astype(np.int64)


righe = []
print(f"argmin cifrato (Concrete, CHUNKED, 4 bit, N={N}) al variare della dimensione\n")
print(f"{'dim':>5} | {'compila':>8} | {'argmin':>9} | {'PBS':>5} | {'bit punteggio':>13} | esito")
for dim in DIMS:
    Ep = quant(proietta(dim))
    ids = np.unique(y)[:N]
    G = Ep[np.array([np.where(y == s)[0][0] for s in ids])]
    bsq = np.sum(G * G, axis=1)

    def costruisci(G, bsq, N):
        # closure, non argomenti di default: Concrete ispeziona la firma e pretende
        # uno stato di cifratura per ogni parametro
        def fn(a):
            p = bsq - 2 * (G @ a)
            idx = fhe.zeros(()); val = p[0]
            for i in range(1, N):
                lt = (p[i] < val).astype(np.int64)
                idx = lt * i + (1 - lt) * idx
                val = np.minimum(val, p[i])
            return idx
        return fn
    fn = costruisci(G, bsq, N)

    iset = [Ep[k] for k in rng.choice(len(Ep), 100, replace=False)]
    cfg = fhe.Configuration(comparison_strategy_preference=[fhe.ComparisonStrategy.CHUNKED],
                            min_max_strategy_preference=[fhe.MinMaxStrategy.CHUNKED])
    t = time.time(); circ = fhe.Compiler(fn, {"a": "encrypted"}).compile(iset, cfg); tc = time.time() - t
    circ.keygen()
    a = Ep[123]
    atteso = int(np.argmin(bsq - 2 * (G @ a)))
    enc = circ.encrypt(a)
    t = time.time(); res = circ.run(enc); tr = time.time() - t
    ok = int(circ.decrypt(res)) == atteso
    pbs = circ.statistics["programmable_bootstrap_count"]
    rangep = int(np.abs(bsq[None, :] - 2 * (quant(proietta(dim))[:500] @ G.T)).max())
    bit = int(np.ceil(np.log2(rangep + 1))) + 1
    print(f"{dim:>5} | {tc:>7.1f}s | {tr:>8.1f}s | {pbs:>5} | {bit:>13} | {'OK' if ok else 'ERRATO'}")
    righe.append({"N": N, "dim": dim, "compila_s": round(tc, 1), "argmin_s": round(tr, 1),
                  "pbs": pbs, "bit_punteggio": bit, "corretto": int(ok)})
with open(OUT / "argmin_dimensione.csv", "w", newline="") as fp:
    w = csv.DictWriter(fp, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)
print(f"\nscritto {OUT / 'argmin_dimensione.csv'}")
