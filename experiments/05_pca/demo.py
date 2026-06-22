"""Gradino 05 -- PCA: prototipo end-to-end del riconoscimento che preserva la privacy.

Mette insieme l'intera catena. Il client proietta il volto con la PCA in chiaro,
quantizza l'embedding, lo cifra e lo manda al server. Il server tiene la galleria in
chiaro e calcola i punteggi di distanza direttamente sul cifrato, senza mai vedere
il volto; restituisce i punteggi cifrati. Solo il client li decifra e trova la
faccia più vicina.

  client: volto -> PCA (in chiaro) -> quantizza -> cifra ----->  server
  server: punteggi cifrati  ‖b‖² - 2·a·b  (nessun bootstrapping) -->  client
  client: decifra -> più vicino -> identità

Per controllo confronta tre accuratezze sullo stesso insieme di test:
  - float in chiaro (1-NN euclidea)   il riferimento ideale
  - quantizzata in chiaro             l'effetto della quantizzazione
  - cifrata end-to-end                deve coincidere con la quantizzata

L'embedding (PCA) è locale a questo gradino; il resto (FHE, dataset, quantizzazione)
viene da `core/`.

Esegui:  uv run python experiments/05_pca/demo.py [olivetti|lfw]
         (default: olivetti; lfw è più grande e realistico, scarica ~200 MB)
"""

import pathlib
import sys
import time

import numpy as np

# repo root sul path, per importare il motore condiviso core/
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from core import dataset, quantize          # noqa: E402
from core.client import Client              # noqa: E402
from core.server import Server              # noqa: E402

import embedding                            # noqa: E402  (PCA, specifico di questo gradino)

DATASET = sys.argv[1] if len(sys.argv) > 1 else "olivetti"
N_COMPONENTI = 150 if DATASET == "lfw" else 50
BITS = 6
Q_MAX = 2 ** (BITS - 1) - 1          # 6 bit con segno -> intervallo [-31, 31]


def _ms(fn):
    """Esegue fn() e ritorna (risultato, tempo in ms)."""
    t = time.perf_counter()
    r = fn()
    return r, (time.perf_counter() - t) * 1000


def accuratezza(predette: list, vere: np.ndarray) -> float:
    """Frazione di predizioni che coincidono con l'identità vera."""
    return float(np.mean(np.array(predette) == np.array(vere)))


def nn_float(emb_galleria: np.ndarray, etichette_galleria: np.ndarray,
             emb_probe: np.ndarray) -> list:
    """Per ogni probe, l'identità della faccia di galleria più vicina (distanza
    euclidea, in chiaro). È la baseline ideale."""
    return [etichette_galleria[np.argmin(np.sum((emb_galleria - query) ** 2, axis=1))]
            for query in emb_probe]


def nn_quant_chiaro(galleria_q: np.ndarray, etichette_galleria: np.ndarray,
                    probe_q: np.ndarray) -> list:
    """Stesso punteggio del server (‖b‖² − 2·a·b) ma calcolato in chiaro, per
    verificare che la versione cifrata dia le identiche predizioni."""
    b_sq = np.sum(galleria_q ** 2, axis=1)          # ‖b‖² per ogni faccia (b = galleria)
    return [etichette_galleria[np.argmin(b_sq - 2 * (galleria_q @ query))]
            for query in probe_q]


def main() -> None:
    (volti_galleria, etichette_galleria), (volti_probe, etichette_probe) = dataset.carica(DATASET)
    print(f"Dataset {DATASET}: {len(etichette_galleria)} in galleria, "
          f"{len(etichette_probe)} probe, {len(set(etichette_galleria))} persone")

    # --- Iscrizione (in chiaro, una volta sola) ---
    # 1. stima la base PCA (eigenfaces) sulle foto della galleria
    modello = embedding.fit(volti_galleria, N_COMPONENTI)
    # 2. proietta galleria e probe nello spazio PCA: embedding corti, ancora float
    emb_galleria = modello.transform(volti_galleria)
    emb_probe = modello.transform(volti_probe)
    # 3. scala di quantizzazione, calcolata SOLO sulla galleria e riusata per i probe
    scala = quantize.scala_quant(emb_galleria, Q_MAX)
    # 4. quantizza entrambi: float -> interi con segno (la FHE lavora su interi)
    galleria_q = quantize.quantizza(emb_galleria, scala, Q_MAX)
    probe_q = quantize.quantizza(emb_probe, scala, Q_MAX)
    print(f"PCA: {N_COMPONENTI} componenti | quantizzazione: {BITS} bit "
          f"(q_max={Q_MAX})\n")

    # Riferimenti in chiaro (per confronto con la versione cifrata).
    acc_float = accuratezza(nn_float(emb_galleria, etichette_galleria, emb_probe), etichette_probe)
    acc_quant = accuratezza(nn_quant_chiaro(galleria_q, etichette_galleria, probe_q), etichette_probe)

    # Catena cifrata end-to-end. Server() compila il circuito, Client() genera le
    # chiavi: costi una tantum (all'iscrizione), non per ogni interrogazione.
    server, t_compile = _ms(lambda: Server(galleria_q))
    client, t_keygen = _ms(lambda: Client(
        server.client_specs(), embedding.embedding_fn(modello), scala, Q_MAX, etichette_galleria))
    eval_keys = client.eval_keys()

    pred_cifrata: list = []
    t_cifra = t_match = t_decifra = 0.0
    for volto in volti_probe:
        probe_cifrato, dt = _ms(lambda: client.cifra_volto(volto))
        t_cifra += dt
        punteggi, dt = _ms(lambda: server.match(probe_cifrato, eval_keys))
        t_match += dt
        identita, dt = _ms(lambda: client.leggi_esito(punteggi))
        t_decifra += dt
        pred_cifrata.append(identita)
    acc_cifrata = accuratezza(pred_cifrata, etichette_probe)

    n = len(etichette_probe)
    print("Accuratezza:")
    print(f"  float (1-NN euclidea, in chiaro) : {acc_float:6.1%}")
    print(f"  quantizzata (in chiaro)          : {acc_quant:6.1%}")
    print(f"  cifrata end-to-end               : {acc_cifrata:6.1%}")
    print(f"  (cifrata == quantizzata in chiaro: {pred_cifrata == nn_quant_chiaro(galleria_q, etichette_galleria, probe_q)})\n")
    print("Setup (una volta sola, all'iscrizione):")
    print(f"  compilazione circuito : {t_compile:7.1f} ms")
    print(f"  generazione chiavi    : {t_keygen:7.1f} ms\n")
    print(f"Tempi medi per probe (su {n}):")
    print(f"  cifratura (client)   : {t_cifra / n:7.1f} ms")
    print(f"  match (server)       : {t_match / n:7.1f} ms")
    print(f"  decifra + più vicino : {t_decifra / n:7.1f} ms")
    print(f"  totale per probe     : {(t_cifra + t_match + t_decifra) / n:7.1f} ms")


if __name__ == "__main__":
    main()
