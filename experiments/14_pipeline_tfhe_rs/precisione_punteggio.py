"""Quanti bit del punteggio servono davvero alla selezione? (validazione IN CHIARO, prima dell'FHE)

Il costo della selezione cifrata (argmin + soglia) dipende dalla larghezza del punteggio: in
tfhe-rs un confronto su FheUint8 (4 blocchi da 2 bit) costa meno di uno su FheUint16 (8
blocchi). Il punteggio reale a 512 dim / 4 bit occupa ~13-14 bit (F31), ma per DECIDERE
(chi e' il piu' vicino, e sta sotto soglia?) forse bastano i bit alti. Qui misuriamo, in chiaro,
la DIR@FPIR=1% quando il punteggio viene troncato ai suoi k bit piu' significativi
(s' = floor((s + C) / 2^t), con C offset che lo rende non-negativo), alla config reale:
embedding ResNet100 su VGGFace2 (volti reali), quantizzazione a 4 bit, galleria di N=64/128
(i target dell'incontro di luglio) e N=1000 come riferimento stabile.

Metodo dell'incontro: prima si valida l'accuratezza in chiaro, poi si misura il costo FHE solo
sulle configurazioni valide. Vedi findings F36.
"""
import csv
import pathlib
import sys

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
OUT = pathlib.Path(__file__).resolve().parent / "results"
OUT.mkdir(exist_ok=True)

B = np.load(ROOT / "benchmark" / "results" / "_emb_reale_extra.npz")   # rn100, ada, y
E_full, y_full = B["rn100"].astype(np.float32), B["y"]

Q_BIT = 4
N_IMP = 2000          # impostori per scena: al quantile 1% ne restano 20, non 4
SEEDS = 20
BIT_KEPT = [None, 12, 11, 10, 9, 8, 7, 6, 5, 4]   # None = punteggio intero (nessun troncamento)


def quant_fit(pool, q=Q_BIT):
    qm = 2 ** (q - 1) - 1
    return np.percentile(np.abs(pool), 99.5) / qm, qm


def quant(E, sc, qm):
    return np.clip(np.round(E / sc), -qm, qm).astype(np.int64)


def scena(rng, N, n_imp=N_IMP):
    """Galleria: 1 immagine per iscritto; genuini: le altre immagini degli iscritti;
    impostori: immagini di identita' NON iscritte. Come in benchmark/soglia_reale.py."""
    ids = np.unique(y_full); rng.shuffle(ids)
    iscritti, altri = ids[:N], ids[N:]
    g_idx, gen_idx = [], []
    for sid in iscritti:
        idx = np.where(y_full == sid)[0]
        g_idx.append(idx[0]); gen_idx += list(idx[1:])
    imp_pool = np.where(np.isin(y_full, altri))[0]
    imp_idx = rng.choice(imp_pool, min(n_imp, len(imp_pool)), replace=False)
    return np.array(g_idx), np.array(gen_idx), np.array(imp_idx)


def punteggi(G, bsq, A):
    """s_i = ||g_i||^2 - 2 g_i.a  (la formula espansa, senza ||a||^2: L2-normalizzati)."""
    return bsq[None, :] - 2 * (A @ G.T)


def decisione(Sg, yg, y_gen, Si, fpir=0.01):
    """Argmin (vince il primo minimo, come la catena cifrata) poi soglia sul minimo.
    Soglia = valore del quantile `fpir` dei minimi degli impostori (metodo 'lower': e' un
    valore realmente osservato, come farebbe il taratore). Ritorna DIR e FPIR effettivo."""
    jg = Sg.argmin(1); mg = Sg[np.arange(len(Sg)), jg]
    mi = Si.min(1)
    T = np.quantile(mi, fpir, method="lower")
    return float(np.mean((yg[jg] == y_gen) & (mg <= T))), float(np.mean(mi <= T))


def valuta(N):
    righe = []
    for seed in range(SEEDS):
        rng = np.random.RandomState(seed)
        gi, ji, ii = scena(rng, N)
        Gf, Agf, Aif = E_full[gi], E_full[ji], E_full[ii]
        yg, y_gen = y_full[gi], y_full[ji]

        # riferimento float (nessuna quantizzazione)
        bsq_f = np.einsum("ij,ij->i", Gf, Gf)
        dir_f, _ = decisione(punteggi(Gf, bsq_f, Agf), yg, y_gen, punteggi(Gf, bsq_f, Aif))

        # quantizzato a 4 bit: punteggi interi
        sc, qm = quant_fit(np.vstack([Gf, Agf, Aif]))
        G, Ag, Ai = quant(Gf, sc, qm), quant(Agf, sc, qm), quant(Aif, sc, qm)
        bsq = np.sum(G * G, axis=1)
        Sg, Si = punteggi(G, bsq, Ag), punteggi(G, bsq, Ai)
        smin, smax = int(min(Sg.min(), Si.min())), int(max(Sg.max(), Si.max()))
        bit_signed = int(np.ceil(np.log2(max(abs(smin), abs(smax)) + 1))) + 1
        # offset in chiaro (il server conosce il range): punteggio non-negativo
        C = -smin
        W = int(np.ceil(np.log2(smax - smin + 1)))            # bit del punteggio unsigned
        for k in BIT_KEPT:
            t = 0 if k is None else max(W - k, 0)
            d, f = decisione((Sg + C) >> t, yg, y_gen, (Si + C) >> t)
            righe.append({"N": N, "seed": seed, "bit_tenuti": W if k is None else min(k, W),
                          "bit_totali": W, "bit_signed": bit_signed, "shift": t,
                          "dir": d, "fpir_eff": f, "dir_float": dir_f})
    return righe


if __name__ == "__main__":
    tutte = []
    for N in (64, 128, 1000):
        r = valuta(N); tutte += r
        print(f"\nN={N}  (ResNet100, VGGFace2 reale, 4 bit, {SEEDS} scene, {N_IMP} impostori)")
        W = int(np.median([x["bit_totali"] for x in r])); bs = int(np.median([x["bit_signed"] for x in r]))
        print(f"  punteggio: ~{bs} bit signed, ~{W} bit unsigned con offset; float DIR = "
              f"{np.mean([x['dir_float'] for x in r]):.1%}")
        print(f"  {'bit tenuti':>10} | {'DIR@FPIR=1%':>12} | {'±':>5} | {'FPIR eff.':>9}")
        for k in BIT_KEPT:
            sel = [x for x in r if x["bit_tenuti"] == (x["bit_totali"] if k is None else min(k, x["bit_totali"]))
                   and (x["shift"] == 0) == (k is None)]
            if not sel:
                continue
            d = np.array([x["dir"] for x in sel]); f = np.array([x["fpir_eff"] for x in sel])
            print(f"  {('tutti (' + str(W) + ')') if k is None else k:>10} | {d.mean():>11.1%} | "
                  f"{d.std():>5.1%} | {f.mean():>9.2%}")
    with open(OUT / "precisione_punteggio.csv", "w", newline="") as fp:
        w = csv.DictWriter(fp, fieldnames=list(tutte[0].keys())); w.writeheader(); w.writerows(tutte)
    print(f"\nscritto {OUT / 'precisione_punteggio.csv'}")
