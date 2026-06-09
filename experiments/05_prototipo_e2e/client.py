"""Client.

Ha la chiave segreta FHE e la base PCA. Proietta e quantizza il volto in chiaro, lo
cifra e manda al server solo byte (chiave di valutazione + probe cifrato); riceve i
punteggi cifrati (byte), li decifra e trova il più vicino. Solo il client, con la
sua chiave segreta, può leggere qualcosa.
"""

import numpy as np
from concrete import fhe
from sklearn.decomposition import PCA

from pca import quantizza


class Client:
    def __init__(
        self,
        client_specs: bytes,
        modello_pca: PCA,
        scala: float,
        q_max: int,
        etichette_galleria: np.ndarray,
    ) -> None:
        # ricostruisce il circuito dalle sole specs pubbliche ricevute dal server
        self.fhe = fhe.Client(fhe.ClientSpecs.deserialize(client_specs))
        self.fhe.keys.generate()         # genera chiave segreta + di valutazione: restano qui
        self.pca = modello_pca
        self.scala = scala
        self.q_max = q_max
        self.etichette = etichette_galleria

    def eval_keys(self) -> bytes:
        """Chiave di valutazione (serializzata) da mandare al server. NON la segreta."""
        return self.fhe.evaluation_keys.serialize()

    def cifra_volto(self, immagine: np.ndarray) -> bytes:
        """volto (in chiaro) -> embedding PCA -> quantizzazione -> cifratura -> byte."""
        # La PCA di sklearn proietta un *batch* di immagini (matrice 2D), non una sola.
        # Quindi: (pixel,) -> batch da 1, (1, pixel) -> proietta -> prendi l'unica riga.
        embedding = self.pca.transform(immagine.reshape(1, -1))[0]
        # da float a interi piccoli con segno (la FHE lavora su interi, non su float)
        embedding_q = quantizza(embedding, self.scala, self.q_max)
        # cifra l'embedding quantizzato e serializzalo in byte da mandare al server
        return self.fhe.encrypt(embedding_q).serialize()

    def leggi_esito(self, punteggi_cifrati: bytes) -> int:
        """Decifra i punteggi (byte) e ritorna l'identità della faccia più vicina."""
        punteggi = self.fhe.decrypt(fhe.Value.deserialize(punteggi_cifrati))
        piu_vicino = int(np.argmin(punteggi))        # indice della faccia col punteggio minimo
        return int(self.etichette[piu_vicino])       # a chi appartiene quel volto
