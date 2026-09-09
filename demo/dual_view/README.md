# Demo locale: client e server

Due pagine sullo stesso motore FHE della demo composita selezionata:

- **Client:** <http://127.0.0.1:8006/> — fotocamera o foto, richiesta di accesso,
  esito consentito/negato. Non espone la gestione della galleria.
- **Server:** <http://127.0.0.1:8005/> — foto degli iscritti, aggiunta, modifica,
  rimozione e registro delle richieste cifrate.

**Dopo il clone la galleria parte vuota.** Per provare il proprio volto,
registrarsi dalla pagina server. Le nuove registrazioni usano per default
la soglia 273 della pipeline esistente, modificabile dal server. La sessione
locale usata per le verifiche aveva invece 127 soggetti sintetici DigiFace
con soglia 4; immagini, template e iscrizioni personali non sono pubblicati.
Questi valori sono quelli della demo, non una nuova validazione
dell'accuratezza biometrica.

Le foto d'iscrizione e i template della galleria sono visibili al server. Le foto
usate per chiedere l'accesso sono elaborate dal client: il gateway riceve il
messaggio cifrato e registra soltanto orario, stato di elaborazione, durata,
dimensioni e impronta del messaggio. La risposta viene decifrata dal client,
che espone soltanto consentito/negato. Il registro non conosce quell'esito.

## Avvio locale

Eseguire i comandi seguenti dalla radice del repository, salvo i comandi
di compilazione dell'esperimento 22, che indicano la propria cartella.
Preparare l'ambiente Python dalle dipendenze di `pyproject.toml` e `uv.lock`:

```sh
uv sync --locked
```

Compilare `varco_demo_composite_v9` seguendo
[le istruzioni dell'esperimento 22](../../experiments/22_demo_composita/README.md#compilazione-locale-successiva).
Il runtime incluso seleziona `public_parallel`, senza G4. Il percorso prodotto
dalla compilazione è quello usato nei comandi qui sotto.

Per fotocamera e immagini servono questi file nella cache
`~/.insightface/models/`: `antelopev2/glintr100.onnx`,
`buffalo_s/det_500m.onnx` e `buffalo_s/w600k_mbf.onnx`. Se i pacchetti mancano,
il modulo di embedding esistente può scaricarli e caricarli con questo comando;
i pesi restano asset esterni al repository:

```sh
.venv/bin/python -B - <<'PY'
import sys
sys.path.insert(0, "experiments/08_cnn")
import embedding
embedding.carica("resnet100")
embedding._app("mobilefacenet")
PY
```

Generare una coppia `client.key`/`server.key` in una **directory nuova**.
Il comando rifiuta di sovrascrivere file di chiave già presenti; ai successivi
avvii riutilizzare la coppia generata, senza ripetere questo passaggio:

```sh
RAYON_NUM_THREADS=16 \
  experiments/22_demo_composita/.local/target-service/release/varco_demo_composite_v9 \
  keygen "$PWD/demo/dual_view/.local/keys"
```

Avviare i tre ruoli. Il launcher richiede binario, modelli e chiavi già pronti:

```sh
.venv/bin/python -B -m demo.dual_view.launch start \
  --binary "$PWD/experiments/22_demo_composita/.local/target-service/release/varco_demo_composite_v9" \
  --keys "$PWD/demo/dual_view/.local/keys"
```

Il launcher rifiuta l'avvio se una delle porte 9005, 8005 o 8006 è occupata.
Avvia i tre ruoli in background, registra i propri processi e lascia le demo
precedenti in esecuzione. Il backend Rust ascolta su 9005; la pagina server
controlla esclusivamente questa nuova galleria.

```sh
.venv/bin/python -B -m demo.dual_view.launch status
.venv/bin/python -B -m demo.dual_view.launch stop
```

`stop` controlla l'identità dei soli processi indicati nella propria ricevuta.
Foto, template, registro e log restano nella cartella ignorata `.local/`.
Non eliminare questa cartella se si vogliono conservare gli iscritti.
La directory di stato può essere scelta con `--state-root` prima del comando.

## Strumenti opzionali con dati locali

`seed_gallery.py` importa i 127 template sintetici soltanto se sono disponibili
le fixture originali sotto `tmp/e2e-camera-fast-mixed-20260906/` e le foto in
`datasets/digiface/estratto/`, esclusi dalla pubblicazione. Accetta anche
`--fixtures` e `--photos`, verifica l'impronta della fixture qualificata e
rifiuta una directory di galleria già esistente. Non è un requisito dell'avvio
da clone.

`check_live.py` verifica una demo già avviata con quella galleria sintetica e
foto DigiFace locali; crea, modifica e rimuove un'iscrizione di prova ed esegue
richieste cifrate. Non è il controllo iniziale di una galleria vuota.

## Ambito

È una demo su loopback, con le due funzioni separate per presentazione e prova.
Non introduce un sistema di login per amministratori né isolamento tra utenti
del computer. La fotocamera richiede l'autorizzazione del browser e viene
attivata dall'utente. Non vengono effettuate richieste di accesso automatiche.

Il core e il protocollo qualificati restano in
[`experiments/22_demo_composita`](../../experiments/22_demo_composita/README.md).
Il wrapper ne riusa cifratura, valutazione e controlli del protocollo. Questa
modifica dell'interfaccia non costituisce una nuova misura di velocità o una
prova formale del limite di fallimento FHE.
