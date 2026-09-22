# Gradino 05 - PCA (eigenfaces)

Questo gradino costruisce la catena **foto → vettore → punteggi cifrati →
identità scelta dal client**. La PCA, analisi delle componenti principali,
riassume i pixel del volto usando una base ricavata dalle immagini della
galleria. Le direzioni di questa base sono dette *eigenfaces*; i coefficienti
della proiezione formano l'**embedding**, cioè il vettore numerico del volto.
La quantizzazione converte poi i coefficienti in interi per il circuito.

Prima si confrontano i vettori in chiaro; il prototipo mantiene lo stesso
criterio e sposta il calcolo dei punteggi sotto FHE, cioè sui dati cifrati.
Il server riceve il vettore cifrato della foto da verificare, detto **probe**,
e restituisce un punteggio cifrato per ogni voce della galleria in chiaro.
Il client decifra questi valori e sceglie il minimo: la scelta dell'identità
non è ancora parte del circuito cifrato.

Il punteggio `‖b‖² − 2·a·b` non è da solo la distanza quadratica: manca
`‖a‖²`. Per una stessa query questo termine è comune a tutti i candidati,
quindi la sua omissione conserva il vicino più prossimo. L'esperimento
confronta le predizioni con vettori originali, quantizzati e cifrati, per
distinguere l'effetto della quantizzazione da quello del calcolo FHE.

È un prototipo storico basato su Concrete. La
[guida al confronto](../../docs/come-funziona-il-confronto.md) mostra il
percorso successivo, in cui anche minimo e rifiuto restano cifrati; il
[runtime mantenuto](../../runtime/README.md) usa un altro contratto di risposta.

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
