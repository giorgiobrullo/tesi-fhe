# Gradino 05 — PCA (eigenfaces)

Primo gradino di **riconoscimento** della scaletta (tecniche geometriche): prototipo
end-to-end con embedding PCA in chiaro lato client + matching cifrato lato server
(distanza in forma espansa). È il punto di convergenza dei due filoni: accuratezza
del riconoscimento e costo FHE sullo stesso esperimento.

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
confine (frecce) è **serializzato in byte**.

> ⚠️ Limite noto: l'**argmin è ancora sul client**: decifra tutti gli N punteggi e
> prende il minimo, quindi vede le distanze con tutta la galleria. Lo sposta sotto
> FHE il gradino [`06_argmin_soglia`](../06_argmin_soglia/).

## File

| file | ruolo | dove vive |
|---|---|---|
| `embedding.py` | base PCA (eigenfaces): volto -> vettore | **locale** (la tecnica di questo gradino) |
| `demo.py` | wiring end-to-end; accuratezza float/quant/cifrata + tempi | locale |
| `core/server.py`, `core/client.py` | plumbing FHE (chiavi, run, serializzazione) | condiviso |
| `core/matching.py` | il circuito `‖b‖² − 2·a·b` (fonte unica) | condiviso |
| `core/quantize.py`, `core/dataset.py` | quantizzazione, caricamento dataset | condiviso |

## Esecuzione

```bash
uv run python experiments/05_pca/demo.py [olivetti|lfw]
```

(default: `olivetti`; la prima volta scarica il dataset e lo mette in cache.)

## Note

- Il più vicino lo sceglie il **client** dopo aver decifrato i punteggi: in questo
  gradino nessun confronto cifrato, quindi nessun bootstrapping. (Cambia col 06.)
- Client e server si scambiano **solo byte serializzati**: la chiave segreta resta
  nel `Client` e non attraversa mai il confine. I due ruoli vivono nello stesso
  processo per comodità del demo.
- **Esito (vedi `findings.md`):** su Olivetti la PCA regge e il percorso cifrato dà
  le identiche predizioni del chiaro quantizzato; su LFW (volti reali) la PCA crolla,
  motivo per salire di gradino (CNN leggera, gradino 07).
