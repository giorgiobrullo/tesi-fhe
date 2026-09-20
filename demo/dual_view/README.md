# Demo: accesso dal client e gestione della galleria

Due pagine sul runtime mantenuto della demo composita:

- Client: <http://127.0.0.1:8006/> - fotocamera o foto, richiesta di accesso,
  esito consentito/negato. Non espone la gestione della galleria.
- Server: <http://127.0.0.1:8005/> - foto degli iscritti, aggiunta, modifica,
  rimozione e registro delle richieste cifrate.

Dopo il clone la galleria parte vuota. Per provare il proprio volto,
registrarsi dalla pagina server. Le nuove registrazioni usano per default
la soglia 273 della pipeline esistente, modificabile dal server. È un valore
di partenza della demo: non garantisce la stessa accuratezza biometrica per
ogni fotocamera, ambiente o galleria.

Le foto d'iscrizione e i template della galleria sono visibili al server. Le foto
usate per chiedere l'accesso sono elaborate dal client: il gateway riceve il
messaggio cifrato e registra soltanto orario, stato di elaborazione, durata,
dimensioni e impronta del messaggio. La risposta viene decifrata dal client,
che espone soltanto consentito/negato. Il registro non conosce quell'esito.

## Prerequisiti

Servono Python 3.12, uv, Rust/Cargo 1.98.0 e una
catena di compilazione C/C++ per le dipendenze native. Su macOS occorrono i
Command Line Tools. Modelli, chiavi e file di esecuzione occupano spazio
aggiuntivo rispetto ai sorgenti e vengono preparati nei passaggi seguenti.

Il lock Python installa le dipendenze dell'intero progetto, compresi Concrete
e TenSEAL, anche se il motore della demo è TFHE-rs. Concrete 2.11 nel lock ha
solo wheel CPython 3.12 per macOS 13+ ARM64/x86_64 e Linux x86_64 con glibc
2.28+, senza distribuzione sorgente. Questo bootstrap non copre Linux ARM
né Windows. TenSEAL 0.3.17 ha wheel macOS 14+ ARM64 e Linux x86_64;
su macOS Intel o versioni precedenti richiede una compilazione da sorgente
che questa guida non descrive. La disponibilità delle wheel non costituisce
una verifica della demo su tutte queste piattaforme.

## Avvio locale

Eseguire dalla radice del repository. Per fissare la versione Python prevista
da `uv.lock` e predisporre il compilatore Rust:

```sh
uv sync --locked --python 3.12
rustup toolchain install 1.98.0 --profile minimal
```

Compilare `varco_demo_composite_v9` seguendo
[le istruzioni di compilazione](../../BUILD_AND_RUN.md#compilazione).
Il runtime incluso seleziona `public_parallel`, senza G4. Eseguire la
compilazione dalla radice della consegna, come indicato nella guida. Il percorso prodotto è quello usato qui sotto.

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

Generare una coppia `client.key`/`server.key` in una directory nuova.
Le chiavi sono legate all’identità del runtime: dopo questo aggiornamento
ricompilare il binario e generare una nuova coppia. Il comando rifiuta di sovrascrivere file di chiave già presenti; ai successivi
avvii riutilizzare la coppia generata, senza ripetere questo passaggio:

```sh
RAYON_NUM_THREADS=16 \
  target-selector-pack4/release/varco_demo_composite_v9 \
  keygen "$PWD/demo/dual_view/.local/keys"
```

Avviare i tre ruoli. Il launcher richiede binario, modelli e chiavi già pronti:

```sh
.venv/bin/python -B -m demo.dual_view.launch start \
  --binary "$PWD/target-selector-pack4/release/varco_demo_composite_v9" \
  --keys "$PWD/demo/dual_view/.local/keys"
```

Il launcher richiede libere le porte 9005, 8005 e 8006 e avvia i tre servizi
in background. Aprire la pagina server per iscrivere un volto, poi la pagina
client per richiedere l'accesso. Il backend Rust ascolta su 9005 e accetta i servizi Python locali.
Le richieste dirette del browser a quella porta sono rifiutate.

```sh
.venv/bin/python -B -m demo.dual_view.launch status
.venv/bin/python -B -m demo.dual_view.launch stop
```

`stop` arresta i servizi avviati dal launcher. Foto, template, chiavi,
registro e log restano nella cartella ignorata `.local/`.
Non eliminare questa cartella se si vogliono conservare gli iscritti.
La directory di stato può essere scelta con `--state-root` prima del comando.

## Ambito

È una demo su loopback, con le due funzioni separate per presentazione e prova.
Non introduce un sistema di login per amministratori né isolamento tra utenti
del computer. La fotocamera richiede l'autorizzazione del browser e viene
attivata dall'utente. Non vengono effettuate richieste di accesso automatiche.

Il motore FHE e i risultati sperimentali sono descritti
nel [rapporto della baseline pack4](../../docs/validazione/PACK4_VALIDATION.md).
L'[esperimento 22](../../experiments/22_demo_composita/README.md) descrive
la composizione precedente, con le sue misure storiche.
Le due pagine usano lo stesso protocollo di cifratura e verifica. I tempi
pubblicati riguardano le condizioni del benchmark; non misurano l'interfaccia
a due pagine né dimostrano un limite formale del fallimento FHE.
