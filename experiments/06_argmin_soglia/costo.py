"""Gradino 06 — costo dell'argmin cifrato sul server (evidenza di F6).

Per privacy l'argmin deve stare sul server, sotto FHE (vedi F6). Qui misuriamo quanto
costa: la riduzione cifrata in funzione della **larghezza in bit dei punteggi**. Il
costo raddoppia ~ad ogni bit → è la leva di progetto (tenere stretta la precisione).

Confronto: il gradino 05 (argmin sul client, in chiaro) costa ~31 ms/query; spostarlo
sul server lo fa passare da gratis a questo costo. NON facciamo uno sweep a tappeto su
PCA (violerebbe il metodo: prima i parametri validi in chiaro, poi il costo FHE solo
su quelli) — la caratterizzazione fine va sulla tecnica finale.

Esegui:  uv run python experiments/06_argmin_soglia/costo.py
         (default fino a 8 bit, ~1 min; oltre cresce ×2/bit e diventa lento)
"""

import csv
import pathlib
import time

import numpy as np
from concrete import fhe

N = 10                          # galleria piccola: isola il costo dell'argmin
BIT_MAX = 8                     # fino a quanti bit di larghezza misurare (8 ≈ 1 min)
OUT = pathlib.Path(__file__).resolve().parent / "results"


def circuito_argmin(n):
    """argmin a riduzione su n valori cifrati (np.argmin non è supportato)."""
    def f(x):
        idx, val = fhe.zeros(()), x[0]
        for i in range(1, n):
            lt = (x[i] < val).astype(np.int64)
            idx = lt * i + (1 - lt) * idx
            val = np.minimum(val, x[i])
        return idx
    return fhe.compiler({"x": "encrypted"})(f)


def main() -> None:
    OUT.mkdir(exist_ok=True)
    righe = []
    print(f"argmin cifrato a riduzione, N={N} — gradino 05 (client): ~31 ms/query\n")
    print(f"{'larghezza':>9} | {'compile':>9} | {'run argmin':>11} | corretto")
    print("-" * 48)
    for bits in range(4, BIT_MAX + 1):
        vmax = 2 ** (bits - 1)
        rng = np.random.RandomState(0)
        inputset = [rng.randint(-vmax, vmax, size=N) for _ in range(30)]
        t = time.perf_counter()
        circ = circuito_argmin(N).compile(inputset)
        t_comp = (time.perf_counter() - t) * 1000
        sample = rng.randint(-vmax, vmax, size=N)
        circ.keygen()
        enc = circ.encrypt(sample)
        t = time.perf_counter()
        got = circ.run(enc)
        t_run = (time.perf_counter() - t) * 1000
        ok = int(circ.decrypt(got)) == int(np.argmin(sample))
        print(f"{bits:>6} bit | {t_comp:>7.0f}ms | {t_run:>9.0f}ms | {ok}")
        righe.append({"N": N, "larghezza_bit": bits,
                      "compile_ms": round(t_comp, 1), "run_ms": round(t_run, 1),
                      "corretto": int(ok)})

    csv_path = OUT / "muro_argmin.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(righe[0].keys()))
        w.writeheader()
        w.writerows(righe)
    print(f"\nscritto {csv_path}")
    print("\nIl run raddoppia ~ad ogni bit. Punteggi PCA reali ≈ 14 bit → intrattabile (F6).")


if __name__ == "__main__":
    main()
