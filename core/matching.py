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


def _argmin_riduzione(punteggi, N):
    """argmin a riduzione su punteggi cifrati: porta avanti (indice, valore minimo).

    `np.argmin` non è supportato da Concrete. Ogni passo confronta il candidato col
    minimo corrente (confronto cifrato → PBS) e seleziona indice e valore. Ritorna
    (indice_min, valore_min), entrambi cifrati. È il centro di costo del gradino 06,
    dominato dalla larghezza in bit dei punteggi.
    """
    idx_min = fhe.zeros(())
    val_min = punteggi[0]
    for i in range(1, N):
        piu_piccolo = (punteggi[i] < val_min).astype(np.int64)   # confronto cifrato → PBS
        idx_min = piu_piccolo * i + (1 - piu_piccolo) * idx_min  # select indice (enc×enc)
        val_min = np.minimum(val_min, punteggi[i])               # → PBS
    return idx_min, val_min


def circuito_distanza_argmin(galleria_q: np.ndarray):
    """Gradino 06a: punteggi + argmin sotto FHE (senza soglia).

    Il server riduce gli N punteggi al solo indice del più vicino: il client riceve
    *chi* è il match, non le N distanze. È il confronto "pulito" prima/dopo rispetto
    al gradino 05 (lì l'argmin era sul client, in chiaro, senza PBS).

    ATTENZIONE (vedi findings.md F6): tracciabile solo a punteggi *stretti*. La
    riduzione è corretta su input piccoli, ma il costo raddoppia ~ad ogni bit di
    larghezza del punteggio, e sui punteggi PCA reali (~14 bit) la compilazione di
    Concrete 2.11 diventa intrattabile. Questa funzione resta come implementazione di
    riferimento della decisione (argmin cifrato), da rivalutare sulla tecnica vera.
    """
    B = galleria_q
    b_sq = np.sum(B ** 2, axis=1)
    N = len(B)

    @fhe.compiler({"a": "encrypted"})
    def match(a):
        punteggi = b_sq - 2 * (B @ a)
        idx_min, _ = _argmin_riduzione(punteggi, N)
        return idx_min

    return match.compile([b for b in B])


# Nota — soglia open-set (rifiuto impostori) sotto FHE: deve confrontare la distanza
# *vera* del match con una soglia, quindi rimettere ‖a‖² (scartato per il ranking) e
# fare un confronto cifrato in più. Un primo tentativo (`val_min + ‖a‖² < soglia`)
# inciampa in un limite interno di Concrete 2.11 (assert sul bit-width nel "trick" di
# np.minimum quando coesiste col termine ‖a‖²). È un costo marginale rispetto agli
# N−1 confronti dell'argmin e non cambia le conclusioni del gradino 06, quindi è
# rimandato alla tecnica vera (CNN) — vedi findings.md F6.
