"""Varco a soglia cifrato end-to-end su embedding reali (VGGFace2, ResNet100). Vedi F33.
Unisce i 'due binari' privacy/accuratezza: il percorso privato (il server calcola le distanze
cifrate e ritorna 1 bit 'c'e' un iscritto sotto soglia?') deve (a) riprodurre esattamente la
decisione in chiaro quantizzata e (b) dare un'accuratezza vera sui volti reali.

Mondo 1: probe cifrata, galleria in chiaro (enc x plaintext, niente PBS sul prodotto scalare);
niente ||a||^2 (sarebbe enc x enc) perche' gli embedding sono L2-normalizzati e la soglia lo
assorbe. Nota: l'inputset di Concrete va preso dai probe veri; con vettori casuali sottostima
il range (i genuini danno distanze estreme) e il circuito tronca, dando esiti errati.

Richiede compilazione FHE; su macOS beta puo' servire un wrapper di ld (PATH=/tmp/ldfix:$PATH)."""
import csv
import pathlib
import sys
import time

import numpy as np
from sklearn.decomposition import PCA
from concrete import fhe

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

OUT = ROOT / "benchmark" / "results"
B = np.load(OUT / "_emb_reale_extra.npz")                 # rn100, ada, y
E_full, y_full = B["rn100"], B["y"]                       # ResNet100, modello di testa
rng = np.random.RandomState(0)
_fit = E_full[rng.choice(len(E_full), 20000, replace=False)]
_PCA = {d: PCA(n_components=d, random_state=0).fit(_fit) for d in (128, 64)}


def quant_fit(pool, q=4):
    qm = 2 ** (q - 1) - 1
    return np.percentile(np.abs(pool), 99.5) / qm, qm


def quant(E, sc, qm):
    return np.clip(np.round(E / sc), -qm, qm).astype(np.int64)


def scena(N, n_imp=400):
    ids = np.unique(y_full); rng.shuffle(ids)
    iscritti, altri = ids[:N], ids[N:]
    g_idx, gen_idx = [], []
    for sid in iscritti:
        idx = np.where(y_full == sid)[0]
        g_idx.append(idx[0]); gen_idx += list(idx[1:])
    imp_pool = np.where(np.isin(y_full, altri))[0]
    imp_idx = rng.choice(imp_pool, min(n_imp, len(imp_pool)), replace=False)
    return np.array(g_idx), np.array(gen_idx), np.array(imp_idx)


def red(X, dim):
    return X if dim == 512 else _PCA[dim].transform(X).astype(np.float32)


def min_score(G, b_sq, A):
    return (b_sq[None, :] - 2.0 * (A @ G.T)).min(axis=1)


def valuta(N, dim):
    gi, ji, ii = scena(N)
    Gf, Agf, Aif = red(E_full[gi], dim), red(E_full[ji], dim), red(E_full[ii], dim)
    sc, qm = quant_fit(np.vstack([Gf, Agf, Aif]))
    Gq, Ag, Ai = quant(Gf, sc, qm), quant(Agf, sc, qm), quant(Aif, sc, qm)
    bsq = np.sum(Gq * Gq, axis=1)

    sg, si = min_score(Gq, bsq, Ag), min_score(Gq, bsq, Ai)
    T = float(np.quantile(si, 0.01))
    tpir, fpir = float(np.mean(sg <= T)), float(np.mean(si <= T))
    bsq_f = np.sum(Gf * Gf, axis=1)
    sgf, sif = min_score(Gf, bsq_f, Agf), min_score(Gf, bsq_f, Aif)
    tpir_f = float(np.mean(sgf <= float(np.quantile(sif, 0.01))))

    Ti = int(round(T))
    def f(a):
        return np.sum(((bsq - 2 * (Gq @ a)) < Ti).astype(np.int64))
    probes = np.vstack([Ag, Ai])
    iset = [probes[k] for k in rng.choice(len(probes), min(150, len(probes)), replace=False)]
    cfg = fhe.Configuration(comparison_strategy_preference=[fhe.ComparisonStrategy.CHUNKED],
                            min_max_strategy_preference=[fhe.MinMaxStrategy.CHUNKED])
    t0 = time.time(); circ = fhe.Compiler(f, {"a": "encrypted"}).compile(iset, cfg); tc = time.time() - t0
    bw = circ.graph.maximum_integer_bit_width(); pbs = circ.statistics['programmable_bootstrap_count']
    circ.keygen()
    camp = np.vstack([Ag[:8], Ai[:8]]); ok, tt = 0, []
    for a in camp:
        atteso = int(np.sum((bsq - 2 * (Gq @ a)) < Ti))
        enc = circ.encrypt(a.astype(np.int64))
        t0 = time.time(); res = circ.run(enc); tt.append(time.time() - t0)
        ok += int(int(circ.decrypt(res)) == atteso)
    print(f"  N={N:>2} dim={dim:>3}: TPIR {tpir:.1%}/float {tpir_f:.1%} | {bw} bit, {pbs} PBS, "
          f"run {np.mean(tt):.1f}s | esatto {ok}/{len(camp)}", flush=True)
    return {"N": N, "dim": dim, "tpir_cifrato": round(tpir, 4), "tpir_float": round(tpir_f, 4),
            "fpir": round(fpir, 4), "bit": bw, "pbs": pbs, "run_s": round(float(np.mean(tt)), 1),
            "esatto": f"{ok}/{len(camp)}"}


if __name__ == "__main__":
    righe = [valuta(N, dim) for N in (8, 64) for dim in (512, 128, 64)]
    with open(OUT / "soglia_reale.csv", "w", newline="") as fp:
        w = csv.DictWriter(fp, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)
    print(f"scritto {OUT / 'soglia_reale.csv'}")
