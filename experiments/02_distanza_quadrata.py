"""
Esperimento 02: distanza euclidea al quadrato cifrata (l'operazione di matching).

Sale di un gradino rispetto a 00/01: invece di una singola operazione calcola
‖a − b‖² = Σ(aᵢ − bᵢ)² tra due *vettori* interi, con entrambi gli operandi cifrati.
È l'operazione che il server esegue per confrontare due embedding di volti. Qui la
verifichiamo per correttezza; il suo costo lo misuriamo in 03 e 04.

Nota: con entrambi i vettori cifrati la somma dei quadrati richiede moltiplicazioni
cifrato×cifrato (Esp. 01: operazione cara). Negli esperimenti successivi la galleria
passa in chiaro e la forma espansa elimina questo costo.

Esegui con:  uv run python experiments/02_distanza_quadrata.py
"""

import numpy as np

from utils_fhe import build_distance_circuit, random_vectors, timed


def main(dim: int = 8, value_max: int = 7) -> None:
    print(f"Distanza euclidea al quadrato cifrata (dim={dim}, valori 0..{value_max})\n")

    rng = np.random.RandomState(0)
    circuit, ms = build_distance_circuit(dim, value_max, rng=rng)
    print(f"  compile  {ms:8.2f} ms")
    _, ms = timed(circuit.keygen); print(f"  keygen   {ms:8.2f} ms")

    a, b = random_vectors(dim, value_max, rng)
    enc, ms = timed(lambda: circuit.encrypt(a, b)); print(f"  encrypt  {ms:8.2f} ms")
    res, ms = timed(lambda: circuit.run(enc));      print(f"  run      {ms:8.2f} ms")
    dec, ms = timed(lambda: circuit.decrypt(res));  print(f"  decrypt  {ms:8.2f} ms")

    atteso = int(np.sum((a - b) ** 2))
    print(f"\n  a = {a.tolist()}")
    print(f"  b = {b.tolist()}")
    print(f"  -> risultato FHE = {dec}  (atteso {atteso})  "
          f"{'OK' if dec == atteso else 'ERRORE'}")
    print(f"  bit massimi nel circuito: {circuit.graph.maximum_integer_bit_width()}")
    print(f"  PBS nel circuito: {circuit.statistics['programmable_bootstrap_count']} "
          f"(cifrato×cifrato: caro, l'Esp. 03 mostra come azzerarlo)")


if __name__ == "__main__":
    main()
