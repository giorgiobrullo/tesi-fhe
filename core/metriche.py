"""Metriche di identificazione 1:N open-set: fonte unica.

`dir_at_fpir` era copiata (in varianti naive per-probe, a matrice piena e a blocchi
BLAS, tutte con la stessa matematica) in dieci script di benchmark: un rischio di
divergenza silenziosa sui numeri della tesi. Qui vive l'unica definizione, nella
versione a blocchi: identica al calcolo per-probe a meno del rumore float e decine di
volte più veloce sulle gallerie grandi (verificato in F29).
"""

import numpy as np


def dir_at_fpir(Eg, yg, Epn, ypn, Epi, fpir=0.01, blocco=1024):
    """DIR@FPIR: la metrica del varco open-set (vedi findings F10).

    Quota di probe noti identificati con l'identità giusta E sotto soglia, con la
    soglia tarata sul quantile `fpir` delle distanze minime dei probe impostori
    (es. fpir=0.01: solo l'1% degli impostori entra per errore).

    Distanza euclidea al quadrato al vicino più prossimo, via BLAS con la forma
    espansa ‖p‖² − 2·p·gᵀ + ‖g‖², a blocchi di `blocco` probe per non esplodere in
    memoria. `blocco` cambia solo tempi/memoria, non la matematica.

    Eg, yg: galleria e sue etichette; Epn, ypn: probe noti; Epi: probe impostori.
    """
    gnorm = np.einsum("ij,ij->i", Eg, Eg)

    def nn_dist(P):
        sn = np.empty(len(P)); idx = np.empty(len(P), dtype=int)
        for i in range(0, len(P), blocco):
            Pb = P[i:i + blocco]
            d = np.einsum("ij,ij->i", Pb, Pb)[:, None] - 2.0 * (Pb @ Eg.T) + gnorm[None, :]
            j = d.argmin(1)
            idx[i:i + len(Pb)] = j; sn[i:i + len(Pb)] = d[np.arange(len(Pb)), j]
        return sn, idx

    sn, nn = nn_dist(Epn)
    si, _ = nn_dist(Epi)
    return float(np.mean((yg[nn] == ypn) & (sn <= np.quantile(si, fpir))))
