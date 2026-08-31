"""Soglia PER TEMPLATE (Z-norm) a costo FHE zero: guadagna accuratezza? (F54)

Il varco decide "s_i <= T" con una soglia unica. In biometria e' noto che i template non sono
equivalenti: alcuni sono "lupi" (attirano punteggi bassi da chiunque) e alzano i falsi positivi,
altri sono "agnelli". La normalizzazione per template (Z-norm) corregge questo:

    s'_i = (s_i - mu_i) / sigma_i <= T      <=>      s_i <= mu_i + sigma_i * T

dove mu_i e sigma_i sono media e deviazione dei punteggi che l'iscritto i ottiene contro una
COORTE di volti che non sono lui (dati disponibili all'iscrizione, in chiaro).

Il punto: nel nostro circuito la soglia entra come costante additiva per iscritto — la
combinazione (||g_i||^2 - T) e' gia' calcolata per ogni i. Sostituirla con (||g_i||^2 - mu_i -
sigma_i*T) non cambia NIENTE nel costo cifrato: stessa operazione, altro numero. Se guadagna
accuratezza, e' un guadagno gratuito.

Misura: DIR@FPIR=1% con soglia globale contro soglia per template, protocollo 1:N open-set di F19
(ResNet100, VGGFace2 reale), con e senza fusione multi-frame (F48).
"""
import csv
import pathlib
import sys

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "benchmark" / "results"
z = np.load(OUT / "_emb_reale_extra.npz")
E, y = z["rn100"].astype(np.float32), z["y"]
E = E / (np.linalg.norm(E, axis=1, keepdims=True) + 1e-9)
per_id = {}
for i, v in enumerate(y):
    per_id.setdefault(int(v), []).append(i)
BIT, QM = 3, 3
SEEDS = 10


def quant(v, scala):
    return np.clip(np.round(v / scala), -QM, QM).astype(np.int64)


def fondi(idx):
    v = E[idx].mean(0)
    return v / (np.linalg.norm(v) + 1e-9)


def scena(rng, N, k_gal, k_probe, n_coorte=300):
    """galleria, probe genuini, probe impostori e una COORTE separata per la calibrazione."""
    ids = np.array(sorted(k for k, v in per_id.items() if len(v) >= k_gal + k_probe))
    rng.shuffle(ids)
    iscritti = ids[:N]
    coorte_id = ids[N:N + n_coorte]                      # identita' per la taratura, disgiunte
    impostori_id = ids[N + n_coorte:N + n_coorte + 600]  # impostori del test, ancora disgiunte
    G, gen = [], []
    for sid in iscritti:
        im = per_id[sid][:]; rng.shuffle(im)
        G.append(fondi(im[:k_gal])); gen.append(fondi(im[k_gal:k_gal + k_probe]))
    coorte = [fondi(per_id[s][:k_probe]) for s in coorte_id]
    imp = [fondi(per_id[s][:k_probe]) for s in impostori_id]
    return np.array(G), np.array(gen), np.array(coorte), np.array(imp)


def punteggi(G, bsq, P):
    return bsq[None, :] - 2 * (P @ G.T)


def valuta(N, k_gal, k_probe, seed):
    rng = np.random.RandomState(seed)
    Gf, genf, coof, impf = scena(rng, N, k_gal, k_probe)
    scala = float(np.percentile(np.abs(np.vstack([Gf, genf, impf])), 99.5) / QM)
    G, gen, coo, imp = (quant(x, scala) for x in (Gf, genf, coof, impf))
    bsq = (G * G).sum(1)
    S_coo, S_gen, S_imp = punteggi(G, bsq, coo), punteggi(G, bsq, gen), punteggi(G, bsq, imp)

    def dir_fpir(offset):
        """offset[i] = soglia del template i, a meno della costante globale z (cercata per FPIR=1%)."""
        # z tale che l'1% degli impostori sia accettato da qualche template
        marg_imp = (S_imp - offset[None, :]).min(1)
        zq = np.quantile(marg_imp, 0.01, method="lower")
        acc_g = (S_gen - offset[None, :]) <= zq
        acc_i = (S_imp - offset[None, :]) <= zq
        uno = acc_g.sum(1) == 1
        giusto = acc_g.argmax(1) == np.arange(len(S_gen))
        return float(np.mean(uno & giusto)), float(np.mean(acc_i.any(1)))

    globale = dir_fpir(np.zeros(N))                       # soglia unica: offset nullo
    mu, sd = S_coo.mean(0), S_coo.std(0) + 1e-9
    znorm = dir_fpir(mu)                                  # solo media (T-norm): s_i - mu_i
    # Z-norm pieno: (s_i - mu_i)/sigma_i <= z  <=>  s_i <= mu_i + sigma_i*z; l'offset non basta,
    # serve la scala: si applica ai punteggi normalizzati
    def dir_fpir_scalato():
        Zg, Zi = (S_gen - mu) / sd, (S_imp - mu) / sd
        zq = np.quantile(Zi.min(1), 0.01, method="lower")
        acc_g, acc_i = Zg <= zq, Zi <= zq
        uno = acc_g.sum(1) == 1
        giusto = acc_g.argmax(1) == np.arange(len(Zg))
        return float(np.mean(uno & giusto)), float(np.mean(acc_i.any(1)))
    zfull = dir_fpir_scalato()
    return globale, znorm, zfull


if __name__ == "__main__":
    righe = []
    print("DIR@FPIR=1% — soglia globale vs per template (ResNet100, VGGFace2 reale, 3 bit)\n")
    print(f"{'N':>5} | {'fusione':>8} | {'soglia unica':>13} | {'-mu_i (T-norm)':>15} | {'(s-mu)/sd (Z-norm)':>19}")
    for N in (128, 1000):
        for (kg, kp) in ((1, 1), (2, 3)):
            r = np.array([valuta(N, kg, kp, s) for s in range(SEEDS)])  # (seed, metodo, [dir,fpir])
            g, t, zf = r[:, 0, 0].mean(), r[:, 1, 0].mean(), r[:, 2, 0].mean()
            print(f"{N:>5} | {kg}+{kp:<6} | {g:>12.1%} | {t:>14.1%} ({t-g:+.1%}) | {zf:>13.1%} ({zf-g:+.1%})")
            righe.append({"N": N, "k_gal": kg, "k_probe": kp, "dir_globale": round(g, 4),
                          "dir_tnorm": round(t, 4), "dir_znorm": round(zf, 4)})
    with open(OUT / "soglia_per_template.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)
    print(f"\nscritto {OUT / 'soglia_per_template.csv'}")
    print("Nota: la T-norm (solo -mu_i) e' GRATIS nel circuito: cambia solo la costante per iscritto.")
    print("La Z-norm piena richiede anche il fattore 1/sigma_i, che si puo' assorbire nel template")
    print("in chiaro (Mondo 1) ma cambierebbe la quantizzazione: va verificata a parte.")
