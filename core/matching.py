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

    Nota (vedi findings.md F6): il costo raddoppia ~ad ogni bit di larghezza del
    punteggio, quindi a larghezze realistiche pesa (la leva è tenere stretti i bit dei
    punteggi). Versione "solo indice"; quella completa col rifiuto è
    `circuito_distanza_argmin_soglia`.
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


def circuito_distanza_argmin_soglia(galleria_q: np.ndarray, soglia_dist_sq: int, inputset):
    """Gradino 06 completo: argmin + soglia open-set sotto FHE → (indice, è_match).

    È l'operazione vera del varco. Restituisce la coppia cifrata:
      - `indice`  : argmin sui punteggi (chi è il più vicino in galleria);
      - `è_match` : 1 se la distanza² vera del match è < soglia, altrimenti **0 =
                    "nessun match"** (impostore/sconosciuto rifiutato).

    La distanza² vera è `val_min + ‖a‖²`: il termine `‖a‖²` scartato per il ranking va
    **rimesso** per confrontare con una soglia assoluta (`‖a‖²` è enc×enc → un PBS, una
    volta). Si usa il **select** per portare avanti `val_min` (non `np.minimum`, che col
    termine `+‖a‖²` inciampa in un assert interno di Concrete 2.11).

    IMPORTANTE — `inputset` deve essere un campione **rappresentativo dei probe reali**
    (non le sole righe della galleria): Concrete inferisce la larghezza in bit dei
    valori cifrati dall'inputset, e se è troppo stretto il confronto della soglia va in
    **overflow silenzioso** (il valore gira modulo) → il rifiuto non si attiva mai e
    tutto sembra "match". Con un inputset adeguato il ramo "nessun match" è corretto.
    """
    B = galleria_q
    b_sq = np.sum(B ** 2, axis=1)
    N = len(B)

    @fhe.compiler({"a": "encrypted"})
    def match(a):
        punteggi = b_sq - 2 * (B @ a)               # (N,) = dist² − ‖a‖²
        a_sq = np.sum(a * a)                         # ‖a‖² (enc×enc, una volta)
        idx_min = fhe.zeros(())
        val_min = punteggi[0]
        for i in range(1, N):
            lt = (punteggi[i] < val_min).astype(np.int64)
            idx_min = lt * i + (1 - lt) * idx_min        # select indice
            val_min = lt * punteggi[i] + (1 - lt) * val_min  # select valore (no np.minimum)
        dist_sq_min = val_min + a_sq                 # distanza² vera del match
        e_match = (dist_sq_min < soglia_dist_sq).astype(np.int64)   # 1=match, 0=nessun match
        return idx_min, e_match

    return match.compile(inputset)
