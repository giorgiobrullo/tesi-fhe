"""Gradino 06: il muro dell'argmin cifrato sugli embedding CNN (riproduce F21).

I punteggi degli embedding CNN (512-dim) sono ~18 bit; il confronto cifrato di Concrete
è limitato a ~16 bit. Qui riproduciamo il muro e i tentativi che NON bastano per
aggirarlo (il diario di F21). Le compilazioni falliscono in fretta, quindi script veloce.

Esegui:  uv run python experiments/06_argmin_soglia/ottimizza.py
"""

import pathlib
import sys

import numpy as np
from concrete import fhe

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "experiments" / "08_cnn"))
from core import dataset, quantize                    # noqa: E402
import embedding as ec                                 # noqa: E402

N = 8


def P(*a):
    print(*a, flush=True)


def prova(nome, costruisci, B):
    """Tenta di compilare un circuito argmin; riporta se ci riesce."""
    try:
        comp = fhe.compiler({"a": "encrypted"})(costruisci)
        comp.compile([b for b in B])
        P(f"  [OK]   {nome}: compila")
    except Exception as e:
        msg = str(e).splitlines()[0]
        for r in str(e).splitlines():
            if "is used as an operand to a comparison" in r:
                msg = "punteggio a 18 bit usato in un confronto (oltre il limite di Concrete)"; break
        P(f"  [MURO] {nome}: {msg[:90]}")


def main():
    X, y = dataset.carica_digiface(max_identita=N, max_per_identita=2, grigio=False)
    E = ec.embedding(X[:N], "mobilefacenet")
    sc = quantize.scala_quant(E, 31); B = quantize.quantizza(E, sc, 31)
    b_sq = np.sum(B ** 2, axis=1)
    scores = b_sq - 2 * (B @ B[0])
    larg = int(np.ceil(np.log2(scores.max() - scores.min())))
    P(f"punteggi CNN (512-dim, 6 bit): ~{larg} bit\n")

    def argmin_base(a):
        p = b_sq - 2 * (B @ a)
        idx = fhe.zeros(()); val = p[0]
        for i in range(1, N):
            lt = (p[i] < val).astype(np.int64); idx = lt * i + (1 - lt) * idx; val = np.minimum(val, p[i])
        return idx

    def argmin_round(a):
        p = fhe.round_bit_pattern(b_sq - 2 * (B @ a), lsbs_to_remove=6)
        idx = fhe.zeros(()); val = p[0]
        for i in range(1, N):
            lt = (p[i] < val).astype(np.int64); idx = lt * i + (1 - lt) * idx; val = np.minimum(val, p[i])
        return idx

    def argmin_div(a):
        p = (b_sq - 2 * (B @ a)) // 64
        idx = fhe.zeros(()); val = p[0]
        for i in range(1, N):
            lt = (p[i] < val).astype(np.int64); idx = lt * i + (1 - lt) * idx; val = np.minimum(val, p[i])
        return idx

    P("tentativi di argmin cifrato sul server:")
    prova("argmin ingenuo (piena larghezza)", argmin_base, B)
    prova("+ round_bit_pattern (arrotonda i bit bassi)", argmin_round, B)
    prova("+ divisione // 64 (taglia il range)", argmin_div, B)
    P("\nTutti contro il limite di bit-width del confronto: il punteggio largo non si")
    P("  tocca. L'unica leva è comprimere l'embedding a monte (PCA), ma è un trade-off")
    P("  accuratezza↔velocità, non un'ottimizzazione. Vedi findings.md F21.")


if __name__ == "__main__":
    main()
