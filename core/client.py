"""Lato client: possiede la chiave segreta.

Calcola l'embedding del volto in chiaro tramite la funzione fornita dal gradino
(PCA, CNN, …), lo quantizza, lo cifra e manda al server solo byte (chiave di
valutazione + probe cifrato); riceve l'esito cifrato (byte) e lo decifra. Solo il
client, con la sua chiave segreta, può leggere qualcosa.

Generico rispetto all'embedding: riceve una `embedding_fn` (volto -> vettore float),
non un modello specifico — così PCA e CNN riusano lo stesso client.
"""

from typing import Callable

import numpy as np
from concrete import fhe

from core import quantize


class Client:
    def __init__(
        self,
        client_specs: bytes,
        embedding_fn: Callable[[np.ndarray], np.ndarray],
        scala: float,
        q_max: int,
        etichette_galleria: np.ndarray,
    ) -> None:
        # ricostruisce il circuito dalle sole specs pubbliche ricevute dal server
        self.fhe = fhe.Client(fhe.ClientSpecs.deserialize(client_specs))
        self.fhe.keys.generate()         # genera chiave segreta + di valutazione: restano qui
        self.embedding_fn = embedding_fn
        self.scala = scala
        self.q_max = q_max
        self.etichette = etichette_galleria

    def eval_keys(self) -> bytes:
        """Chiave di valutazione (serializzata) da mandare al server. NON la segreta."""
        return self.fhe.evaluation_keys.serialize()

    def cifra_volto(self, immagine: np.ndarray) -> bytes:
        """volto (in chiaro) -> embedding -> quantizzazione -> cifratura -> byte."""
        embedding = self.embedding_fn(immagine)          # volto -> embedding (in chiaro)
        # da float a interi piccoli con segno (la FHE lavora su interi, non su float)
        embedding_q = quantize.quantizza(embedding, self.scala, self.q_max)
        # cifra l'embedding quantizzato e serializzalo in byte da mandare al server
        return self.fhe.encrypt(embedding_q).serialize()

    def leggi_esito(self, punteggi_cifrati: bytes) -> int:
        """Decifra i punteggi (byte) e ritorna l'identità della faccia più vicina.

        NB: l'argmin è qui sul client (gradino 05). Il client decifra tutti gli N
        punteggi e prende il minimo — quindi vede le distanze con tutta la galleria.
        Il gradino 06 sposterà argmin+soglia dentro il circuito, così il client
        apprenderà solo l'esito.
        """
        punteggi = self.fhe.decrypt(fhe.Value.deserialize(punteggi_cifrati))
        piu_vicino = int(np.argmin(punteggi))        # indice della faccia col punteggio minimo
        return int(self.etichette[piu_vicino])       # a chi appartiene quel volto
