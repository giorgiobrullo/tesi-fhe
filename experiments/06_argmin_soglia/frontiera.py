"""Gradino 06, la frontiera dell'argmin cifrato: tempo vs dimensione (numeri VERI).

Su questa macchina il parallelismo dataflow non c'è (solo macOS) e la GPU nemmeno,
quindi l'unica leva per velocizzare l'argmin cifrato sul server è **comprimere l'embedding**
(meno dimensioni danno punteggi più stretti, quindi confronti più economici). Ma comprimere costa
accuratezza (F23). Qui misuriamo il tempo FHE dell'argmin al variare della dimensione,
con la larghezza-bit REALE dei punteggi, così la frontiera velocità↔accuratezza ha
numeri misurati, non stimati.

Esegui:  uv run python experiments/06_argmin_soglia/frontiera.py
         (dai dim piccoli ai grandi; i grandi sono lenti, interrompibile)
"""

import csv
import pathlib
import sys
import time

import numpy as np
from concrete import fhe
from sklearn.decomposition import PCA

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from core import quantize                             # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "results"
EMB = pathlib.Path(__file__).resolve().parents[2] / "benchmark" / "results" / "_emb_reale.npz"
N = 8                        # galleria piccola
QB = 4                       # bit di quantizzazione
Q = 2 ** (QB - 1) - 1
DIMS = [32, 64]              # i punti con accuratezza usabile (16 e 128 già noti/estrapolati)


def P(*a):
    print(*a, flush=True)


def main():
    OUT.mkdir(exist_ok=True)
    if not EMB.exists():
        P("manca la cache _emb_reale.npz (gira prima scaling_reale.py)"); return
    E = np.load(EMB)["rn"][:2000]                       # ResNet50, pool grande per la PCA
    P(f"argmin cifrato su galleria N={N}, quantizzazione {QB} bit\n")
    P(f"{'dim':>5} | {'punteggi':>8} | {'argmin FHE':>11} | corretto")
    P("-" * 44)
    righe = []
    for dim in DIMS:
        Ed = PCA(n_components=dim, random_state=0).fit_transform(E)
        sc = quantize.scala_quant(Ed, Q); Gq = quantize.quantizza(Ed[:N], sc, Q); probe = quantize.quantizza(Ed[N], sc, Q)
        b_sq = np.sum(Gq ** 2, axis=1)
        larg = int(np.ceil(np.log2(max(2, (b_sq - 2 * (Gq @ probe)).ptp()))))

        def argmin(a):
            p = b_sq - 2 * (Gq @ a)
            idx = fhe.zeros(()); val = p[0]
            for i in range(1, N):
                lt = (p[i] < val).astype(np.int64); idx = lt * i + (1 - lt) * idx; val = np.minimum(val, p[i])
            return idx
        try:
            circ = fhe.compiler({"a": "encrypted"})(argmin).compile([b for b in Gq]); circ.keygen()
            enc = circ.encrypt(probe)
            t = time.perf_counter(); got = int(circ.decrypt(circ.run(enc))); tr = time.perf_counter() - t
            ok = got == int(np.argmin(b_sq - 2 * (Gq @ probe)))
            run = f"{tr:.1f}s"
        except Exception:
            run = "MURO"; tr = np.nan; ok = None
        P(f"{dim:>5} | {larg:>6}bit | {run:>11} | {ok}")
        righe.append({"dim": dim, "bit": larg, "argmin_s": (round(tr, 1) if tr == tr else ""), "corretto": (int(ok) if ok is not None else "")})
        with open(OUT / "frontiera.csv", "w", newline="") as f:    # scrive a ogni riga
            w = csv.DictWriter(f, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)
    P(f"\nscritto {OUT/'frontiera.csv'}")
    P("(accuratezza per dimensione: benchmark/results/scaling_dimensione.csv)")


if __name__ == "__main__":
    t = time.perf_counter(); main(); P(f"({time.perf_counter()-t:.0f}s)")
