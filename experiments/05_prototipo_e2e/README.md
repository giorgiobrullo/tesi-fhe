# Prototipo end-to-end

Piccolo prototipo con preprocessing in chiaro lato
client (PCA) + matching cifrato lato server (distanza in forma espansa).


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

L'unico ingresso cifrato è il probe; `b` e `‖b‖²` sono costanti nel circuito,
quindi il client non ha bisogno di conoscere la galleria. Tutto ciò che attraversa
il confine (frecce) è **serializzato in byte**.

## File

| file | ruolo |
|---|---|
| `dataset.py` | carica i volti Olivetti/LFW e li divide in galleria e probe |
| `pca.py` | base PCA (eigenfaces) e quantizzazione a interi con segno |
| `server.py` | galleria in chiaro, compila il circuito, esegue il match cifrato |
| `client.py` | chiave segreta, cifra il volto, decifra e sceglie il più vicino |
| `demo.py` | mette tutto insieme; confronta accuratezza float / quantizzata / cifrata |

## Esecuzione

```bash
uv run python experiments/05_prototipo_e2e/demo.py [olivetti|lfw]
```

(default: `olivetti`; la prima volta scarica il dataset e lo mette in cache.)

## Note di implementazione

- Il più vicino lo sceglie il **client** dopo aver decifrato i punteggi → nessun
  confronto cifrato, quindi nessun bootstrapping nemmeno lì.
- Client e server si scambiano **solo byte serializzati** (client specs, chiave di
  valutazione, probe cifrato, punteggi cifrati), come nella deploy guide di Concrete:
  la chiave segreta resta nel `Client` e non attraversa mai il confine. I due
  ruoli vivono comunque nello stesso processo per comodità del demo.
