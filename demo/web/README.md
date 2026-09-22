# Demo web

Una pagina per iscrivere i volti, provare il riconoscimento e seguire le
richieste. La galleria parte con 120 [ritratti d'esempio](gallery/README.md),
fra scienza, cinema ed esplorazione spaziale, e può essere modificata nella
propria sessione. Restano otto posti per aggiungere persone.
Le verifiche usano il runtime attuale corretto.

## Avvio locale

Servono uv, Python 3.12, Rust e una catena C/C++ per le dipendenze native.
Su macOS occorrono i Command Line Tools. Dalla radice del repository, creare
un ambiente dedicato in una directory nuova:

```sh
uv venv --python 3.12 .local/venv-web
uv pip install --python .local/venv-web/bin/python -r demo/web/requirements.txt
```

Agli avvii successivi riutilizzare questo ambiente. Se la directory esiste già,
non ricrearla: eseguire soltanto l'installazione dei requisiti se serve un
aggiornamento. Questa procedura usa le dipendenze della sola demo web;
non installa Concrete o TenSEAL e può essere usata anche su Linux ARM.
Il bootstrap completo `uv sync` della demo storica non copre quella piattaforma.

Preparare i tre modelli esterni nella cache `~/.insightface/models/` usando
lo stesso interprete che avvierà la demo:

```sh
.local/venv-web/bin/python -B - <<'PY'
import sys
sys.path.insert(0, "experiments/08_cnn")
import embedding
embedding.carica("resnet100")
embedding._app("mobilefacenet")
PY
```

Il comando può scaricare i pesi mancanti. I file richiesti sono
`antelopev2/glintr100.onnx`, `buffalo_s/det_500m.onnx` e
`buffalo_s/w600k_mbf.onnx`. Modelli, chiavi e build restano fuori dai sorgenti.

Se una cache `antelopev2` preesistente contiene altri file ONNX ma manca
`glintr100.onnx`, l'helper storico non completa automaticamente il pacchetto
e la preparazione può fallire. Completare il pacchetto `antelopev2` nella
cache con il modello di riconoscimento richiesto, poi ripetere la preparazione.

Compilare il [runtime attuale](../../BUILD_AND_RUN.md) con la versione
del compilatore indicata per il progetto:

```sh
rustup toolchain install 1.98.0 --profile minimal
.local/venv-web/bin/python -B runtime/configure.py --check
rustup run 1.98.0 cargo build --release --locked \
  --manifest-path runtime/Cargo.toml --bin varco_demo_composite_v9 \
  --target-dir target-selector-pack4
```

Generare le chiavi in una directory nuova. Se una coppia compatibile è già
pronta, saltare `keygen` e indicare quella directory al launcher:

```sh
RAYON_NUM_THREADS=16 target-selector-pack4/release/varco_demo_composite_v9 \
  keygen "$PWD/demo/web/.local/keys-current"

.local/venv-web/bin/python -B -m demo.web.launch \
  --binary "$PWD/target-selector-pack4/release/varco_demo_composite_v9" \
  --keys "$PWD/demo/web/.local/keys-current"
```

Aprire <http://127.0.0.1:8010/>. Il comando resta in primo piano: interromperlo
arresta anche il motore avviato dalla demo. Non sostituisce servizi già
presenti. Le porte si possono scegliere con `--port` e `--native-port`.

## Sessioni e verifiche

Il server legge al massimo otto corpi JSON contemporaneamente, condivisi fra
iscrizioni, verifiche e modifiche. Gli invii oltre questo limite ricevono 429;
una lettura che supera 60 secondi riceve 408 e libera il posto. Ogni corpo
resta limitato a 17 MiB. Questo limite riguarda la ricezione delle richieste:
l'elaborazione mantiene un solo worker e otto lavori in attesa.
Anche ogni singola scrittura verso una connessione SSE ha un limite di
60 secondi: un lettore bloccato viene disconnesso e libera la sottoscrizione.
Non è un limite alla durata totale del flusso; gli aggiornamenti e i messaggi
di mantenimento possono continuare finché la sessione resta valida.

La capacità predefinita è **512 sessioni**, modificabile con `--max-sessions`
o `VARCO_WEB_MAX_SESSIONS` fra 1 e 4096; il valore passato al comando prevale
sulla variabile. È la capacità delle sessioni conservate, non il numero di
calcoli FHE paralleli. La sola apertura della pagina iniziale non crea una
sessione: la pagina la richiede quando carica lo stato della demo.

Ogni sessione ha galleria, foto e registro separati e scade dopo un'ora
dall'apertura. A capacità piena il server può recuperare una sessione senza
modifiche né richieste, inattiva da almeno cinque minuti. Non recupera per
questo motivo sessioni con dati personali modificati, un registro di prove
o lavori in coda o in esecuzione; resta valida la normale scadenza di un'ora.
La connessione per gli aggiornamenti non prolunga la sessione né la rende
attiva ai fini di questo recupero. Se non ci sono posti recuperabili, un nuovo
ingresso deve attendere. I ritratti iniziali condividono i dati immutabili;
le modifiche di un visitatore restano nella sua sessione.

Un solo lavoro alla volta esegue embedding e verifica, con al massimo otto
lavori in attesa. Ogni richiesta conserva l'ordine
degli iscritti e le soglie presenti al momento dell'invio. La pagina ammette
fino a 128 iscritti. La soglia iniziale 273 è quella della demo e resta
modificabile: abbassarla rende il controllo più severo, alzarla più tollerante.
Non è una percentuale o una garanzia di accuratezza biometrica. La demo sceglie
il primo volto con punteggio minimo e applica la soglia di quella persona;
se la supera, rifiuta l'accesso senza passare al secondo classificato.

Questa versione riunisce sullo stesso host il client fidato e il servizio FHE.
L'operatore può quindi accedere alle foto, ai template e agli esiti. La
separazione fra visitatori è applicativa: il motore usa una coppia interna
di chiavi. Non viene promessa segretezza verso l'operatore.

Ricerca e «Mostra altre» cambiano soltanto le schede visibili: ogni verifica
usa l'intera galleria della sessione. Il registro riporta il numero di persone
al momento dell'invio, oltre ad attesa, preparazione, elaborazione FHE e tempo totale.
Aprendo una richiesta, la cascata colloca le fasi sui loro intervalli reali,
con un asse comune e le sottofasi all'interno del motore. Le barre
aperte avanzano durante il lavoro; i dettagli interni appaiono alla risposta
del motore. La POST restituisce subito 202: la cascata segue il lavoro sul
server, non la durata della connessione HTTP. Per il runtime attuale lo span
del servizio FHE comprende il trasporto locale; il solo calcolo resta indicato
separatamente. Gli intervalli usano lo stesso orologio monotono nei processi.
Il runtime usa il suo client a comandi per cifratura e decifratura. Il totale
include anche la gestione del servizio. I tempi mostrati dalla demo non
sostituiscono le misure pubblicate, le cui gallerie e soglie sono documentate
nelle rispettive campagne.

La pagina riceve stato, galleria e risultati dal server mediante una
connessione SSE. L'esito viene inviato appena disponibile, senza attendere
un controllo periodico del browser. Durante il lavoro il server aggiorna
anche gli intervalli aperti della cascata. Se la connessione si interrompe,
la pagina si ricollega e riceve lo stato corrente della propria sessione.

«Attuale» indica la demo composita corretta con anchor e pack4. Il finale
senza anchor del grafico sperimentale è una variante distinta. Le uscite
native sono controllate rispetto alla stessa regola in chiaro, senza
sostituire un risultato cifrato errato con quello atteso. Questo controllo
di servizio non costituisce una prova formale del circuito.

## Avvio dietro HTTPS

Aggiungere `--public-origin https://demo.example.org` al comando di avvio,
oppure impostare `VARCO_WEB_PUBLIC_ORIGIN`. Usare l'indirizzo effettivo della
demo, senza sottopercorsi. Il servizio accetta soltanto l'host configurato e
le API richiedono la propria origine. L'apertura della pagina da un link su
un altro sito è consentita; questo non autorizza richieste API da quell'altro
sito. Il cookie di sessione richiede HTTPS.

Il proxy deve conservare gli header `Host` e `Origin` e inoltrare alla porta
web su `127.0.0.1`. Il launcher rimane su loopback, con un solo worker;
la porta nativa non va esposta. Prevedere richieste fino a 17 MiB e timeout
compatibili con la coda di elaborazione delle foto. Per `/api/eventi`,
disabilitare il buffering delle risposte e consentire connessioni persistenti;
il server invia un messaggio di mantenimento ogni 15 secondi quando è inattivo.

Su Linux ARM occorrono un ambiente Python locale, i modelli e il binario
compilato sul sistema di destinazione, con Rust almeno 1.91.1. Generare chiavi
dedicate sul server. Avvio, iscrizione e verifiche cifrate sono stati
controllati il 21 settembre anche su Ubuntu 24.04 ARM con la galleria da 120
persone. Questo controllo precede l'aggiornamento delle sessioni del 22 settembre.
Per l'avvio automatico è disponibile una [unit systemd](deploy/README.md).

## Verificare le modifiche alla demo web

Con l'ambiente dedicato, dalla radice:

```sh
.local/venv-web/bin/python -B -m unittest discover -s demo/web -t .
node --test demo/web/test_ui.mjs
```

I test usano motori e immagini simulati e non avviano il motore Rust o una
fotocamera. Le prove FHE e i benchmark rimangono separati.
