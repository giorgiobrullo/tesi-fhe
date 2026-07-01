"""Gradino 08, demo end-to-end: riconoscimento facciale cifrato con embedding CNN.

L'intera catena, con l'embedding CNN che supera il livello del caso sui volti reali (F14/F16):

  client: volto -> CNN (in chiaro) -> quantizza -> cifra ----->  server
  server: punteggi cifrati  ‖b‖² - 2·a·b  (cifrato×chiaro, no PBS) -->  client
  client: decifra -> distanza² vera -> più vicino + soglia -> "Sei X" / "Nessun match"

Il server non vede mai il volto né l'esito: riceve byte (chiave di valutazione + probe
cifrato), restituisce byte (punteggi cifrati). Solo il client decide. La galleria è in
chiaro sul server (suoi dati). La "soglia open-set" rifiuta gli sconosciuti.

NB (vedi findings): qui l'argmin+soglia li fa il client (versione funzionante e
veloce). Spostarli sul server, sotto FHE, è il passo successivo (privacy piena) ed è
quello che poi ottimizziamo, vedi `ottimizza_argmin.py`.

Esegui:  uv run python experiments/08_cnn/demo.py [mobilefacenet|resnet50|resnet100]
"""

import pathlib
import sys
import time

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from core import dataset, quantize                    # noqa: E402
from core.server import Server                        # noqa: E402
from core.client import Client                        # noqa: E402
import embedding as ec                                # noqa: E402

MODELLO = sys.argv[1] if len(sys.argv) > 1 else "resnet50"
BITS = 6
Q_MAX = 2 ** (BITS - 1) - 1
N_ISCRITTI = 20            # persone in galleria


def _ms(fn):
    t = time.perf_counter(); r = fn(); return r, (time.perf_counter() - t) * 1000


def main():
    print(f"Modello: {MODELLO} | quantizzazione: {BITS} bit | galleria: {N_ISCRITTI} persone\n")
    # Dati: DigiFace (sintetico, già allineato). Metà identità iscritte, metà impostori.
    X, y = dataset.carica_digiface(max_identita=2 * N_ISCRITTI, max_per_identita=6, grigio=False)
    E = ec.embedding(X, MODELLO)                       # embedding CNN (in chiaro)
    ids = np.unique(y)
    iscritte, ignote = set(ids[:N_ISCRITTI].tolist()), set(ids[N_ISCRITTI:].tolist())

    # Iscrizione: 1 foto di riferimento per persona iscritta (la galleria del server)
    gal_idx = [np.where(y == p)[0][0] for p in iscritte]
    Eg, yg = E[gal_idx], y[gal_idx]
    scala = quantize.scala_quant(Eg, Q_MAX)
    galleria_q = quantize.quantizza(Eg, scala, Q_MAX)
    # soglia open-set: a metà tra distanze "stessa persona" e "persone diverse" (in chiaro,
    # all'iscrizione). Qui una stima semplice dalle distanze inter-galleria.
    dgal = [np.min(np.sum((galleria_q - b) ** 2, axis=1)[np.arange(len(galleria_q)) != i])
            for i, b in enumerate(galleria_q)]
    soglia = int(np.percentile(dgal, 20))             # sotto questa = match

    # Server (galleria in chiaro) + Client (chiave segreta, embedding CNN)
    server, t_comp = _ms(lambda: Server(galleria_q))
    emb_fn = lambda img: ec.embedding(img[None], MODELLO)[0]
    client, t_key = _ms(lambda: Client(server.client_specs(), emb_fn, scala, Q_MAX, yg))
    eval_keys = client.eval_keys()
    print(f"Iscrizione (una tantum): compile {t_comp:.0f} ms, keygen {t_key:.0f} ms\n")

    def riconosci(img):
        """volto -> esito ('Sei X' / 'Nessun match') + tempi per fase."""
        probe_cif, t_c = _ms(lambda: client.cifra_volto(img))
        punteggi_cif, t_m = _ms(lambda: server.match(probe_cif, eval_keys))
        # client: decifra i punteggi (= dist² − ‖a‖²), rimette ‖a‖², argmin + soglia
        scores = client.fhe.decrypt(__import__("concrete").fhe.Value.deserialize(punteggi_cif))
        a = quantize.quantizza(emb_fn(img), scala, Q_MAX)
        dist2 = scores + np.sum(a * a)
        j = int(np.argmin(dist2))
        esito = (int(yg[j]) if dist2[j] < soglia else None)
        return esito, t_c + t_m

    # Prova: alcuni iscritti (altre foto) e alcuni impostori
    print("Prove (un volto per riga):")
    print(f"  {'vero':>10} | {'esito':>14} | {'corretto?':>9} | tempo/query")
    print("  " + "-" * 52)
    casi = []
    for p in list(iscritte)[:5]:
        casi.append(("iscritto", p, np.where(y == p)[0][-1]))   # un'altra foto della persona
    for p in list(ignote)[:5]:
        casi.append(("impostore", p, np.where(y == p)[0][0]))
    tempi = []
    for tipo, p, idx in casi:
        esito, t = riconosci(X[idx]); tempi.append(t)
        atteso = (int(p) if tipo == "iscritto" else None)
        nome_esito = f"persona {esito}" if esito is not None else "NESSUN MATCH"
        vero = f"persona {p}" if tipo == "iscritto" else f"sconosciuto ({p})"
        ok = "OK" if esito == atteso else "X"
        print(f"  {vero:>10} | {nome_esito:>14} | {ok:>9} | {t:6.0f} ms")
    print(f"\n  tempo medio per query (cifra + match cifrato): {np.mean(tempi):.0f} ms")
    print("  (il server non ha mai visto il volto né l'esito)")


if __name__ == "__main__":
    main()
