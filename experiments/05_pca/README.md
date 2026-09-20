# Gradino 05 - PCA (eigenfaces)

Prototipo di riconoscimento con embedding PCA in chiaro sul client e calcolo
cifrato della distanza in forma espansa sul server. L'esperimento misura
accuratezza del riconoscimento e costo FHE sullo stesso protocollo.

## Architettura

```
   client                                   server
   - chiave segreta                         - galleria in chiaro (embedding + nomi)
   - base PCA                               - chiave di valutazione
   - elenco dei nomi iscritti               - circuito specifico per la galleria

   volto
     │ PCA (in chiaro) + quantizza
     ▼
   embedding cifrato  ───────────────────►  punteggi = ‖b‖² − 2·a·b
                                            (b e ‖b‖² sono costanti nel circuito)
   identità  ◄───────────────────────────  punteggi cifrati (uno per faccia)
     ▲ decifra + sceglie il più vicino
```

L'unico ingresso cifrato è il probe; `b` e `‖b‖²` sono costanti nel circuito, quindi
il client non ha bisogno di conoscere la galleria. Tutto ciò che attraversa il
confine (frecce) è serializzato in byte.

L'argmin è sul client: decifra tutti gli N punteggi e sceglie il minimo,
quindi accede alle distanze rispetto all'intera galleria. L'[esperimento 06](../06_argmin_soglia/)
sposta questa operazione sotto FHE sul server.

## File

| File | Ruolo | Collocazione |
|---|---|---|
| `embedding.py` | base PCA (eigenfaces): volto -> vettore | locale |
| `demo.py` | pipeline completa; accuratezza float/quant/cifrata + tempi | locale |
| `core/server.py`, `core/client.py` | operazioni FHE (chiavi, run, serializzazione) | condiviso |
| `core/matching.py` | il circuito `‖b‖² − 2·a·b` (fonte unica) | condiviso |
| `core/quantize.py`, `core/dataset.py` | quantizzazione, caricamento dataset | condiviso |

## Esecuzione

```bash
uv run python experiments/05_pca/demo.py [olivetti|lfw]
```

(default: `olivetti`; la prima volta scarica il dataset e lo mette in cache.)

## Note

- Il client sceglie il più vicino dopo la decifratura: il circuito non contiene
  confronti cifrati né bootstrapping.
- Client e server si scambiano solo byte serializzati: la chiave segreta resta
  nel `Client` e non attraversa mai il confine. I due ruoli vivono nello stesso
  processo per l'esecuzione della demo.
- Su Olivetti il percorso cifrato produce le stesse predizioni del chiaro
  quantizzato. Su LFW l'accuratezza della PCA è inferiore; gli esperimenti
  successivi valutano descrittori locali e CNN. Vedi `findings.md`.
