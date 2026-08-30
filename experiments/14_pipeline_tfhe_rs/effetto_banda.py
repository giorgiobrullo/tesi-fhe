"""Effetto della banda di sfocatura della soglia leveled su DIR e FPIR (simulazione in chiaro).

banda_soglia.rs misura che il PBS di segno decide "s <= T" con probabilita' che segue una
sigmoide intorno a T: P(match | d = s - T) ~ Phi((0.5 - d) / sigma), con sigma ~ 12 unita' di
punteggio a Delta_s = 2^51 (quella usata sulla scena reale), ~6.5 a 2^52, ~25 a 2^50. Sui dati
reali non e' mai scattata (F37) perche' nessuna coppia (probe, iscritto) cadeva nella banda. Qui
la applichiamo per simulazione alle stesse 20 scene di precisione_punteggio.py (ResNet100,
VGGFace2, 4 bit; N = 64, 128, 1000): ogni decisione per coppia e' un lancio con quella
probabilita', l'esito e' one-hot (accettato se esattamente un iscritto sotto soglia ed e' quello
giusto), e confrontiamo DIR e FPIR con la decisione esatta. Stima anche quante coppie cadono
davvero nella banda.
"""
import csv
import pathlib
import sys

import numpy as np
from scipy.stats import norm

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from precisione_punteggio import E_full, y_full, quant_fit, quant, scena, punteggi, SEEDS   # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "results"
SIGME = {"2^52": 6.5, "2^51": 12.0, "2^50": 25.0}
if len(sys.argv) > 1:      # es. "set 2_1:30 set 1_1:50" -> bande misurate di altri set di parametri (F46)
    SIGME = {a.split(":")[0]: float(a.split(":")[1]) for a in sys.argv[1:]}
RIP = 5   # ripetizioni del lancio per scena


def esatto(Sg, yg, y_gen, Si, T):
    acc_g = Sg <= T; acc_i = Si <= T
    uno_g = acc_g.sum(1) == 1
    giusto = np.array([acc_g[k, :].argmax() for k in range(len(Sg))])
    return float(np.mean(uno_g & (yg[giusto] == y_gen))), float(np.mean(acc_i.any(1)))


def sfocato(rng, Sg, yg, y_gen, Si, T, sigma):
    pg = norm.cdf((T + 0.5 - Sg) / sigma); pi = norm.cdf((T + 0.5 - Si) / sigma)
    acc_g = rng.random_sample(Sg.shape) < pg; acc_i = rng.random_sample(Si.shape) < pi
    uno_g = acc_g.sum(1) == 1
    giusto = np.array([acc_g[k, :].argmax() for k in range(len(Sg))])
    return float(np.mean(uno_g & (yg[giusto] == y_gen))), float(np.mean(acc_i.any(1)))


righe = []
for N in (64, 128, 1000):
    res = {k: [] for k in ["esatto"] + list(SIGME)}
    in_banda = []
    for seed in range(SEEDS):
        rng = np.random.RandomState(seed)
        gi, ji, ii = scena(rng, N)
        Gf, Agf, Aif = E_full[gi], E_full[ji], E_full[ii]
        yg, y_gen = y_full[gi], y_full[ji]
        sc, qm = quant_fit(np.vstack([Gf, Agf, Aif]))
        G, Ag, Ai = quant(Gf, sc, qm), quant(Agf, sc, qm), quant(Aif, sc, qm)
        bsq = np.sum(G * G, axis=1)
        Sg, Si = punteggi(G, bsq, Ag), punteggi(G, bsq, Ai)
        T = np.quantile(Si.min(1), 0.01, method="lower")
        res["esatto"].append(esatto(Sg, yg, y_gen, Si, T))
        in_banda.append(np.mean(np.abs(np.concatenate([Sg.ravel(), Si.ravel()]) - T) <= 24))
        for k, sg in SIGME.items():
            for _ in range(RIP):
                res[k].append(sfocato(rng, Sg, yg, y_gen, Si, T, sg))
    print(f"\nN={N}  ({SEEDS} scene x {RIP} lanci; coppie entro +-24 unita' da T: {np.mean(in_banda):.3%})")
    print(f"  {'decisione':>12} | {'DIR@FPIR=1%':>12} | {'FPIR eff.':>9}")
    for k, v in res.items():
        v = np.array(v)
        print(f"  {k:>12} | {v[:, 0].mean():>11.1%} | {v[:, 1].mean():>9.2%}")
        righe.append({"N": N, "decisione": k, "sigma": 0 if k == "esatto" else SIGME[k],
                      "dir": round(float(v[:, 0].mean()), 4), "fpir": round(float(v[:, 1].mean()), 4),
                      "coppie_in_banda": round(float(np.mean(in_banda)), 5)})
with open(OUT / "effetto_banda.csv", "w", newline="") as fp:
    w = csv.DictWriter(fp, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)
print(f"\nscritto {OUT / 'effetto_banda.csv'}")
