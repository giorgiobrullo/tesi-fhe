"""Cosa rivela il bit di esito? L'attacco con l'oracolo di appartenenza, misurato in chiaro (F40).

Il client malicious (F35) non manda un volto: manda vettori arbitrari e legge le risposte. Il prof
ha vietato di restituire la distanza (con la distanza si scende per gradiente fino all'embedding).
Ma anche il solo esito e' un oracolo: "il mio vettore v e' accettato per l'iscritto i?". Qui
misuriamo quante query servono per ricostruire l'embedding g_i dell'iscritto con ciascun tipo
di risposta, sulla scena reale (ResNet100, VGGFace2, 4 bit, 128 iscritti).

Osservazione che rende l'attacco lineare: il server calcola s_i(v) = ||g_i||^2 - 2 g_i.v (formula
espansa senza ||v||^2, perche' i probe onesti sono L2-normalizzati). Per un client malicious che
manda v qualunque, la regione di accettazione {v : s_i(v) <= T} e' un SEMISPAZIO g_i.v >= c_i, non
una palla. Con l'oracolo a 1 bit, partendo da un punto accettato, la frontiera del semispazio si
trova per bisezione coordinata per coordinata (~4 query per coordinata sui 15 valori a 4 bit), e
512 punti di frontiera danno g_i a meno di scala per minimi quadrati. Con la distanza in chiaro
bastano 2 query per coordinata e g_i esce esatto.

Tre esperimenti:
  A. attacco con il bit, partendo da un probe GENUINO dell'iscritto (l'attaccante ha una foto):
     query, coseno tra g stimato e g vero, e se il vettore ricostruito viene accettato;
  B. lo stesso con la distanza in chiaro (2 query per coordinata, esatto);
  C. partendo da un IMPOSTORE o da vettori casuali: quante query prima di una sola accettazione
     (senza un punto dentro il semispazio l'oracolo risponde sempre no).
"""
import pathlib
import sys

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
OUT = pathlib.Path(__file__).resolve().parent / "results"
SCENA = OUT / "scena_reale.txt"
Q = 7   # valori a 4 bit in [-7, 7]

righe = SCENA.read_text().splitlines()
dim, N, NP, T = map(int, righe[0].split())
G = np.array([list(map(int, r.split())) for r in righe[1:1 + N]])
PR = np.array([list(map(int, r.split())) for r in righe[1 + N:1 + N + NP]])
labels, P = PR[:, 0], PR[:, 1:]
bsq = (G * G).sum(1)


class Oracolo:
    """il server: risponde per ogni iscritto s_i(v) <= T (one-hot di F37); nel design del prof
    risponde solo per il piu' vicino, che per un v vicino a g_i e' i stesso: stesso bit."""
    def __init__(self):
        self.query = 0

    def bit(self, v, i):
        self.query += 1
        return bsq[i] - 2 * int(G[i] @ v) <= T

    def distanza(self, v, i):
        self.query += 1
        return bsq[i] - 2 * int(G[i] @ v)


def frontiera(o, i, v0):
    """dal probe accettato v0, bisezione sul raggio alpha*v0 fino all'ultimo alpha accettato:
    un punto a ridosso della frontiera del semispazio (margine < un passo del raggio)."""
    lo, hi = 1.0, 0.0                                  # alpha=1 accettato, alpha=0 (v=0) rifiutato
    assert o.bit(v0, i) and not o.bit(np.zeros(dim, dtype=int), i)
    while lo - hi > 1e-3:
        mid = (lo + hi) / 2
        if o.bit(np.round(mid * v0).astype(int), i):
            lo = mid
        else:
            hi = mid
    return np.round(lo * v0).astype(int)


def attacco_bit(i, v0, n_query=3000, rng=None):
    """apprendimento del semispazio da query di appartenenza attorno alla frontiera. Le
    perturbazioni sono sparse e l'attaccante ne adatta l'ampiezza per tenere l'oracolo al 50%
    (altrimenti le risposte non portano informazione); poi regressione logistica -> normale ~ g_i."""
    from sklearn.linear_model import LogisticRegression
    o = Oracolo(); vb = frontiera(o, i, v0)
    X, y, nz = [], [], 48
    while o.query < n_query:
        lotto_y = []
        for _ in range(100):
            d = np.zeros(dim, dtype=int); idx = rng.choice(dim, nz, replace=False)
            d[idx] = rng.choice([-2, -1, 1, 2], size=nz)
            w = np.clip(vb + d, -Q, Q)
            b = int(o.bit(w, i)); X.append(w - vb); y.append(b); lotto_y.append(b)
        tasso = np.mean(lotto_y)                     # adatta l'ampiezza verso il 50%
        if tasso > 0.6:
            nz = min(dim, int(nz * 1.5) + 1)
        elif tasso < 0.4:
            nz = max(4, int(nz / 1.5))
    X, y = np.array(X, dtype=float), np.array(y)
    if y.min() == y.max():
        return o.query, 0.0, False, float(y.mean())
    clf = LogisticRegression(C=10.0, max_iter=3000, fit_intercept=True).fit(X, y)
    g_hat = clf.coef_[0]
    cos = float(g_hat @ G[i] / (np.linalg.norm(g_hat) * np.linalg.norm(G[i])))
    v_att = np.clip(np.round(g_hat / np.abs(g_hat).max() * Q), -Q, Q).astype(int)
    acc = Oracolo().bit(v_att, i)
    return o.query, cos, acc, float(y.mean())


def attacco_distanza(i, v0):
    o = Oracolo(); s0 = o.distanza(v0, i); g = np.zeros(dim, dtype=int)
    for j in range(dim):
        w = v0.copy(); w[j] += 1 if v0[j] < Q else -1
        g[j] = (s0 - o.distanza(w, i)) // (2 * (w[j] - v0[j]))
    return o.query, float(np.array_equal(g, G[i]))


def da_fuori(i, v0, max_query=20000, rng=None):
    """perturbazioni casuali da un punto rifiutato: prima accettazione entro max_query?"""
    o = Oracolo(); v = v0.copy()
    for _ in range(max_query):
        w = np.clip(v + rng.randint(-2, 3, size=dim), -Q, Q)
        if o.bit(w, i):
            return o.query
    return None


if __name__ == "__main__":
    rng = np.random.RandomState(0)
    gen = np.where(labels >= 0)[0]; imp = np.where(labels < 0)[0]
    print(f"scena: N={N}, T={T}, {len(gen)} probe genuini, {len(imp)} impostori\n")

    print("A. oracolo a 1 BIT, partenza da un probe genuino (l'attaccante ha una foto dell'iscritto)")
    print(f"   {'query':>7} | {'coseno medio (min)':>20} | {'ricostruito accettato':>22} | oracolo al")
    for nq in (1000, 3000, 10000, 30000):
        ris = []
        for k in gen[:12]:
            i = labels[k]
            if bsq[i] - 2 * int(G[i] @ P[k]) > T:
                continue
            ris.append(attacco_bit(i, P[k], n_query=nq, rng=rng))
        ris = np.array(ris)
        print(f"   {nq:>7} | {ris[:, 1].mean():>13.3f} ({ris[:, 1].min():.3f}) | {int(ris[:, 2].sum()):>12}/{len(ris):<9} | {ris[:, 3].mean():.0%}")

    print("\nB. DISTANZA in chiaro, stessa partenza")
    ris = np.array([attacco_distanza(labels[k], P[k]) for k in gen[:20]])
    print(f"   query {ris[:, 0].mean():.0f}, embedding esatto {int(ris[:, 1].sum())}/{len(ris)}")

    print("\nC. oracolo a 1 BIT senza un punto dentro: da un impostore e da vettori casuali")
    hits = [da_fuori(rng.randint(N), P[k], rng=rng) for k in imp[:10]]
    print(f"   da 10 impostori, 20.000 perturbazioni casuali ciascuno: accettazioni {sum(h is not None for h in hits)}/10")
    hits = [da_fuori(rng.randint(N), rng.randint(-Q, Q + 1, size=dim), rng=rng) for _ in range(10)]
    print(f"   da 10 vettori casuali: accettazioni {sum(h is not None for h in hits)}/10")
    # quanto e' lontano un impostore dalla frontiera, in unita' di punteggio?
    smin_imp = np.array([(bsq - 2 * (G @ P[k])).min() for k in imp])
    print(f"   distanza minima degli impostori dalla soglia: mediana {np.median(smin_imp - T):.0f}, min {(smin_imp - T).min():.0f} unita' "
          f"(una coordinata spostata di 1 cambia il punteggio di al piu' 2*|g_j| <= {2 * np.abs(G).max()})")
