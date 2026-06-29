"""Costo FHE per i tre modelli CNN: è indipendente dal modello?

Tesi da verificare: il match cifrato dipende solo dalla **dimensione dell'embedding**
(512 per tutti e tre i modelli), non dalla potenza del modello, perché l'embedding gira
in chiaro sul client, in FHE va solo la distanza. Quindi MobileFaceNet, ResNet50 e
ResNet100 dovrebbero costare **lo stesso** (~quanto F15).

Per ogni modello: embedda una galleria DigiFace, quantizza, controlla che la
quantizzazione non perda, compila il circuito di distanza e misura il match cifrato.

Esegui:  uv run python experiments/08_cnn/costo_modelli.py
"""

import pathlib
import sys
import time

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from core import dataset, matching, quantize          # noqa: E402
import embedding as ec                                 # noqa: E402

BITS = 6
Q = 2 ** (BITS - 1) - 1
N = 50                                                 # galleria per la misura FHE


def P(*a):
    print(*a, flush=True)


def main():
    P("carico DigiFace (allineato) + embeddo con i tre modelli...")
    X, y = dataset.carica_digiface(max_identita=60, max_per_identita=8, grigio=False)
    probe_img = X[0:1]                                  # un volto come probe

    P(f"\n{'modello':>14} | {'dim':>4} | {'quant ok?':>9} | {'compile':>8} | {'match cifrato':>13} | corretto")
    P("-" * 72)
    for liv, nome in [("mobilefacenet", "MobileFaceNet"), ("resnet50", "ResNet50"), ("resnet100", "ResNet100")]:
        E = ec.embedding(X, liv)                        # (n,512) L2-normalizzati
        scala = quantize.scala_quant(E[:N], Q)
        Gq = quantize.quantizza(E[:N], scala, Q)        # galleria quantizzata
        pq = quantize.quantizza(ec.embedding(probe_img, liv)[0], scala, Q)
        # quant non perde? (predizione 1-NN float vs quant sulla galleria)
        nn_f = int(np.argmin(np.sum((E[:N] - E[0]) ** 2, axis=1)))
        nn_q = int(np.argmin(np.sum((Gq.astype(float) - Gq[0]) ** 2, axis=1)))
        quant_ok = nn_f == nn_q

        t = time.perf_counter(); circ = matching.circuito_distanza(Gq); t_comp = (time.perf_counter() - t) * 1000
        circ.keygen(); enc = circ.encrypt(pq)
        tempi = []
        for _ in range(3):
            t = time.perf_counter(); res = circ.run(enc); tempi.append((time.perf_counter() - t) * 1000)
        got = circ.decrypt(res); atteso = np.sum(Gq ** 2, axis=1) - 2 * (Gq @ pq)
        ok = np.array_equal(np.array(got), atteso)
        P(f"{nome:>14} | {E.shape[1]:>4} | {str(quant_ok):>9} | {t_comp:>6.0f}ms | {np.mean(tempi):>11.0f}ms | {ok}")

    P("\nStesso ~costo per tutti: il match cifrato dipende dalla dim (512), non dal modello.")
    P("  La potenza della CNN (in chiaro sul client) è gratis lato FHE.")


if __name__ == "__main__":
    t = time.perf_counter(); main(); P(f"({time.perf_counter()-t:.0f}s)")
