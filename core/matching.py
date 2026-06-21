"""Circuiti FHE per il matching — la matematica cifrata, fonte unica.

Qui vive l'unica definizione dei circuiti: il `Server` e gli script di benchmark li
importano entrambi da qui, così prototipo e misura non possono divergere (è ciò che
chiude il rischio "ma il prototipo userà davvero la formula giusta?").

Gradino 05 — distanza euclidea al quadrato in forma espansa:

    punteggio_i = ‖b_i‖² − 2·a·b_i          (probe `a` cifrato, galleria `b` in chiaro)

cioè la distanza ‖a−b_i‖² a meno della costante ‖a‖² (uguale per tutte le facce →
non cambia quale sia la più vicina, quindi si butta). `b` e `‖b‖²` sono costanti in
chiaro dentro il circuito: sono tutte moltiplicazioni cifrato×chiaro → nessun
bootstrapping. L'argmin sui punteggi è ancora fuori dal circuito (lo fa il client).

Gradino 06 (in arrivo) — argmin + soglia *dentro* il circuito, sotto FHE: il server
riduce gli N punteggi al solo match e il client apprende l'esito, non le N distanze.
Reintroduce i confronti cifrati → PBS. Vivrà qui, accanto a `circuito_distanza`.
"""

import numpy as np
from concrete import fhe


def circuito_distanza(galleria_q: np.ndarray):
    """Compila il circuito dei punteggi di distanza per la galleria data.

    Ritorna un circuito che, dato il probe cifrato `a`, produce il vettore degli N
    punteggi `‖b_i‖² − 2·a·b_i` (uno per faccia iscritta), tutti cifrati.
    """
    B = galleria_q                              # (N, D) interi, in chiaro
    b_sq = np.sum(B ** 2, axis=1)               # (N,) ‖b‖² precalcolato, in chiaro

    @fhe.compiler({"a": "encrypted"})
    def match(a):
        return b_sq - 2 * (B @ a)               # i punteggi di tutte le facce in una volta

    # inputset: probe plausibili (la galleria stessa è un buon campione dell'intervallo)
    return match.compile([b for b in B])
