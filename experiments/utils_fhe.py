"""
Funzioni di utilità condivise dagli esperimenti FHE.
"""

import time
from typing import Callable, TypeVar

import numpy as np
from concrete import fhe

T = TypeVar("T")


def timed(funzione: Callable[[], T]) -> tuple[T, float]:
    """Esegue `funzione` e restituisce (risultato, tempo_in_millisecondi)."""
    inizio = time.perf_counter()
    risultato = funzione()
    ms = (time.perf_counter() - inizio) * 1000
    return risultato, ms


def square_distance_compiler():
    """L'operazione centrale della tesi: ||a - b||^2 su vettori interi, con
    entrambi gli operandi cifrati.

    Restituisce un "compiler" di Concrete (la funzione ancora da compilare in
    circuito)."""

    @fhe.compiler({"a": "encrypted", "b": "encrypted"})
    def sq_dist(a, b):
        d = a - b
        return np.sum(d * d)

    return sq_dist


def random_vectors(
    dim: int, value_max: int, rng: np.random.RandomState
) -> tuple[np.ndarray, np.ndarray]:
    """Una coppia di vettori interi casuali con valori in [0, value_max]."""
    return (
        rng.randint(0, value_max + 1, dim),
        rng.randint(0, value_max + 1, dim),
    )


def build_distance_circuit(
    dim: int,
    value_max: int,
    n_samples: int = 100,
    rng: np.random.RandomState | None = None,
) -> tuple[fhe.Circuit, float]:
    """Compila il circuito della distanza per una certa dimensione/intervallo.

    Restituisce (circuit, compile_ms). L'inputset serve a Concrete per capire
    l'intervallo dei valori e dimensionare di conseguenza il circuito intero.
    """
    rng = rng if rng is not None else np.random.RandomState(0)
    compiler = square_distance_compiler()
    inputset = [random_vectors(dim, value_max, rng) for _ in range(n_samples)]
    circuit, compile_ms = timed(lambda: compiler.compile(inputset))
    return circuit, compile_ms


def cronometra_circuito(
    circuit: fhe.Circuit, args: tuple, eval_reps: int = 5, warmup: int = 1
) -> dict:
    """Misura un circuito già compilato: keygen, encrypt, scarta `warmup`
    esecuzioni (riscaldamento JIT/cache), cronometra `eval_reps` esecuzioni,
    decifra. Restituisce un dict con i tempi (ms) e il risultato decifrato.

    `args` è la tupla di input runtime (es. (a, b) o (a, b, b_sq)).
    """
    _, keygen_ms = timed(circuit.keygen)
    enc, encrypt_ms = timed(lambda: circuit.encrypt(*args))

    for _ in range(warmup):
        circuit.run(enc)

    tempi: list[float] = []
    res = None
    for _ in range(eval_reps):
        res, ms = timed(lambda: circuit.run(enc))
        tempi.append(ms)

    assert res is not None  # il ciclo gira almeno una volta (eval_reps >= 1)
    dec, decrypt_ms = timed(lambda: circuit.decrypt(res))
    return {
        "keygen_ms": keygen_ms,
        "encrypt_ms": encrypt_ms,
        "eval_ms_mean": float(np.mean(tempi)),
        "eval_ms_std": float(np.std(tempi)),
        "decrypt_ms": decrypt_ms,
        "risultato": dec,
    }
