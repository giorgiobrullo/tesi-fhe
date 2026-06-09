"""Lato server del prototipo.

Il server tiene la galleria in chiaro (è un suo dato) e calcola i punteggi di
distanza direttamente sul probe cifrato del client. Non vede mai il volto né
l'esito: riceve solo byte (chiave di valutazione + probe cifrato) e restituisce
byte (punteggi cifrati), che solo il client può decifrare.

Siccome la galleria appartiene al server, la matrice degli embedding e i loro
quadrati sono costanti fisse dentro il circuito: l'unico ingresso cifrato è il
probe. Il punteggio per ogni faccia è ‖b‖² − 2·a·b, cioè la distanza al quadrato a
meno della costante ‖a‖² (uguale per tutte, non cambia quale sia la più vicina).
Sono tutte moltiplicazioni cifrato×chiaro, quindi nessun bootstrapping.
"""

import numpy as np
from concrete import fhe


class Server:
    def __init__(self, galleria_q: np.ndarray) -> None:
        B = galleria_q                              # (N, D) interi, in chiaro
        b_sq = np.sum(B ** 2, axis=1)               # (N,) ‖b‖² precalcolato, in chiaro

        @fhe.compiler({"a": "encrypted"})
        def match(a):
            return b_sq - 2 * (B @ a)               # i punteggi di tutte le facce in una volta

        # inputset: probe plausibili (la galleria stessa è un buon campione dell'intervallo)
        self._circuito = match.compile([b for b in B])

    def client_specs(self) -> bytes:
        """Parametri pubblici del circuito da spedire al client (nessun segreto):
        gli bastano per ricostruire il circuito, generare le chiavi e cifrare."""
        return self._circuito.server.client_specs.serialize()

    def match(self, probe_cifrato: bytes, eval_keys: bytes) -> bytes:
        """Riceve probe cifrato + chiave di valutazione (byte), calcola i punteggi
        sul cifrato e li restituisce cifrati (byte). Alla cieca: senza la chiave
        segreta il server non può decifrare né l'ingresso né l'uscita."""
        ek = fhe.EvaluationKeys.deserialize(eval_keys)
        probe = fhe.Value.deserialize(probe_cifrato)
        return self._circuito.server.run(probe, evaluation_keys=ek).serialize()
