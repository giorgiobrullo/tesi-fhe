"""Cascata varco -> argmin: quanto costa davvero risolvere gli 'ambigui'? (F57)

Il varco risponde con (conteggio, indice). Tre casi:
  conteggio 0  -> nessuno sotto soglia: respinto
  conteggio 1  -> un solo iscritto sotto soglia: identificato, ed e' la risposta che vogliamo
  conteggio >1 -> AMBIGUO: piu' iscritti sotto soglia, il varco non sa scegliere

Finora l'ambiguo lo contavo come fallimento (e infatti la demo ne ha mostrato uno). Ma
l'ambiguita' e' esattamente cio' che l'argmin a torneo (F52) risolve. La domanda e' se convenga
pagarlo SEMPRE o solo QUANDO SERVE:

  A) argmin sempre           costo = argmin(N)                     ~1,3 s a N=128
  B) varco sempre            costo = varco(N)                      ~0,15 s, ma perde gli ambigui
  C) cascata: varco, e argmin solo se il conteggio e' >1
                             costo atteso = varco(N) + p_amb * argmin(N)

La cascata costa una perdita di riservatezza precisa e limitata: il server impara UN BIT per
query, "questo probe era ambiguo". Il probe resta cifrato, la risposta pure.

Misura p_amb e il guadagno di accuratezza, protocollo 1:N open-set di F19 (ResNet100, VGGFace2
reale, 3 bit, fusione 2+3 di F48).
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
QM, SEEDS = 3, 10
# varco: misurato (F56, set 2_2 con Delta onesto, stessa macchina) — 0,153 s a N=128, 1,258 s a N=1024
# argmin: misurato a N=128 (F52); a N=1024 estrapolato dalla retta 0,216 + 0,0086*N che interpola
# i cinque punti misurati (N=8..128), l'estrapolazione e' marcata come tale nel finding
T_VARCO = {128: 0.153, 1024: 1.258}
T_ARGMIN = {128: 1.316, 1024: 9.02}


def fondi(idx):
    v = E[idx].mean(0)
    return v / (np.linalg.norm(v) + 1e-9)


def scena(rng, N, k_gal=2, k_probe=3, n_imp=600):
    ids = np.array(sorted(k for k, v in per_id.items() if len(v) >= k_gal + k_probe))
    rng.shuffle(ids)
    G, gen = [], []
    for sid in ids[:N]:
        im = per_id[sid][:]; rng.shuffle(im)
        G.append(fondi(im[:k_gal])); gen.append(fondi(im[k_gal:k_gal + k_probe]))
    imp = [fondi(per_id[s][:k_probe]) for s in ids[N:N + n_imp]]
    return np.array(G), np.array(gen), np.array(imp)


def valuta(N, seed):
    rng = np.random.RandomState(seed)
    Gf, genf, impf = scena(rng, N)
    scala = float(np.percentile(np.abs(np.vstack([Gf, genf, impf])), 99.5) / QM)
    q = lambda x: np.clip(np.round(x / scala), -QM, QM).astype(np.int64)
    G, gen, imp = q(Gf), q(genf), q(impf)
    bsq = (G * G).sum(1)
    S_gen = bsq[None, :] - 2 * (gen @ G.T)
    S_imp = bsq[None, :] - 2 * (imp @ G.T)
    # soglia globale tarata a FPIR = 1% (un impostore su cento apre almeno un iscritto)
    T = np.quantile(S_imp.min(1), 0.01, method="lower")

    acc_g, acc_i = S_gen <= T, S_imp <= T
    cnt_g, cnt_i = acc_g.sum(1), acc_i.sum(1)
    giusto = np.arange(N)
    # B) varco solo: successo = esattamente uno sotto soglia ed e' il proprio
    dir_varco = float(np.mean((cnt_g == 1) & (acc_g.argmax(1) == giusto)))
    # C) cascata: se ambiguo, l'argmin sceglie il minimo TRA GLI ACCETTATI
    scelta = np.where(cnt_g >= 1, S_gen.argmin(1), -1)
    dir_casc = float(np.mean((cnt_g >= 1) & (scelta == giusto)))
    # A) argmin sempre: identifica il minimo, poi lo confronta con la soglia -> identico a C
    p_amb_gen = float(np.mean(cnt_g >= 2))
    p_amb_imp = float(np.mean(cnt_i >= 2))
    # frequenza di ambiguita' su un traffico misto: qui meta' genuini, meta' impostori
    p_amb = 0.5 * p_amb_gen + 0.5 * p_amb_imp
    fpir = float(np.mean(cnt_i >= 1))
    return dir_varco, dir_casc, p_amb_gen, p_amb_imp, p_amb, fpir


if __name__ == "__main__":
    righe = []
    print("Cascata varco -> argmin (ResNet100, VGGFace2 reale, 3 bit, fusione 2+3, FPIR=1%)\n")
    print(f"{'N':>5} | {'DIR varco':>9} | {'DIR cascata':>11} | {'ambigui gen':>11} | {'ambigui imp':>11} | "
          f"{'costo A sempre':>14} | {'costo C cascata':>15}")
    for N in (128, 1024):
        r = np.array([valuta(N, s) for s in range(SEEDS)])
        dv, dc, ag, ai, pa, fp = r.mean(0)
        ca = T_ARGMIN[N]
        cc = T_VARCO[N] + pa * T_ARGMIN[N]
        print(f"{N:>5} | {dv:>8.1%} | {dc:>10.1%} | {ag:>10.1%} | {ai:>10.1%} | "
              f"{ca:>13.2f}s | {cc:>14.2f}s")
        righe.append({"N": N, "dir_varco": round(dv, 4), "dir_cascata": round(dc, 4),
                      "p_ambiguo_genuini": round(ag, 4), "p_ambiguo_impostori": round(ai, 4),
                      "p_ambiguo_misto": round(pa, 4), "fpir": round(fp, 4),
                      "costo_argmin_sempre_s": ca, "costo_cascata_s": round(cc, 3),
                      "risparmio": round(ca / cc, 1)})
    with open(OUT / "cascata.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)
    print(f"\nscritto {OUT / 'cascata.csv'}")
