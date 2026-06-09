"""
Esperimento 03 -- tenere la galleria inchiaro

Nel sistema reale il probe è cifrato ma la galleria sta in chiaro sul server:
l'operazione diventa cifrato×chiaro invece di cifrato×cifrato. Ma "in chiaro" da
solo non basta, conta la *forma* della formula. Calcoliamo lo stesso punteggio di
distanza in tre modi e, come nell'Esp. 01, contiamo i PBS (l'operazione cara) e
cronometriamo la `run`:

  V1  ‖a−b‖²        cifrato×cifrato                  il caso peggiore (come l'Esp. 02)
  V2  ‖a−b‖²        galleria in chiaro, ingenuo      il quadrato (a−b)² resta cifrato×cifrato
  V3  ‖b‖²−2·a·b    forma espansa, galleria chiara   solo un prodotto scalare cifrato×chiaro

Risultato: V1 e V2 hanno PBS (cari, ~uguali), V3 ne ha 0 (economico). Il guadagno
viene dallo spostare il quadrato cifrato fuori dal ciclo sulla galleria, non solo dal tenere la galleria in chiaro.

Esegui con:  uv run python experiments/03_galleria_in_chiaro.py
"""

import numpy as np
from concrete import fhe

from utils_fhe import cronometra_circuito, random_vectors

DIM = 32
VALUE_MAX = 15                       # 4 bit per valore


def confronta(nome: str, compiler, inputset: list, args: tuple, atteso: int) -> None:
    """Compila una variante, conta i PBS, cronometra la run e verifica il risultato."""
    circuit = compiler.compile(inputset)
    t = cronometra_circuito(circuit, args)
    pbs = circuit.statistics["programmable_bootstrap_count"]
    ok = "OK" if t["risultato"] == atteso else "ERRORE"
    print(f"  {nome:<42} PBS={pbs:<3} eval={t['eval_ms_mean']:>7.1f} ms  {ok}")


def main() -> None:
    print(f"Galleria in chiaro: lo stesso punteggio in tre forme (dim={DIM}, 4 bit)\n")
    rng = np.random.RandomState(0)
    a, b = random_vectors(DIM, VALUE_MAX, rng)
    campioni = [random_vectors(DIM, VALUE_MAX, rng) for _ in range(50)]

    @fhe.compiler({"a": "encrypted", "b": "encrypted"})
    def v1(a, b):                                 # cifrato×cifrato
        d = a - b
        return np.sum(d * d)

    @fhe.compiler({"a": "encrypted", "b": "clear"})
    def v2(a, b):                                 # galleria in chiaro, ma il quadrato resta cifrato×cifrato
        d = a - b
        return np.sum(d * d)

    @fhe.compiler({"a": "encrypted", "b": "clear", "b_sq": "clear"})
    def v3(a, b, b_sq):                           # forma espansa: ‖b‖² precalcolato, resta a·b cifrato×chiaro
        return b_sq - 2 * np.sum(a * b)

    confronta("V1  cifrato×cifrato  ‖a−b‖²", v1,
              [(x, y) for x, y in campioni], (a, b),
              int(np.sum((a - b) ** 2)))
    confronta("V2  cifrato×chiaro   ‖a−b‖² (ingenuo)", v2,
              [(x, y) for x, y in campioni], (a, b),
              int(np.sum((a - b) ** 2)))
    confronta("V3  cifrato×chiaro   ‖b‖²−2·a·b (espansa)", v3,
              [(x, y, int(np.sum(y * y))) for x, y in campioni], (a, b, int(np.sum(b * b))),
              int(np.sum(b * b) - 2 * np.sum(a * b)))

    print("\n  -> V1 e V2 hanno PBS (cari); V3 ne ha 0 (economico).")


if __name__ == "__main__":
    main()
