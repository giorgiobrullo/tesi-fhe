# 22 — Demo TFHE composita selezionata

Questa cartella rende riutilizzabile il servizio selezionato l'8 settembre:
Head/PFKS, tre cifre ID in base15, soglia inclusiva del vincitore, entrambi i
tagli ID, normalizzatori condivisi, costanti pubbliche e parallelismo dei
confronti e della selezione. La modalità è `public_parallel`, senza G4 e
senza Tetris. Il torneo conserva le barriere fra livelli. Il client include
il rilevamento dei soli landmark prima dell'unico embedding ResNet100.

`runtime/` contiene87 file identici alla demo qualificata, comprese chiusura
Cargo, LUT pubblica, metadati, client e pagina. `COPY_ORIGINS.json` collega
ogni copia all'origine; `PACKAGE_PINS.json` identifica questo pacchetto.
Gli ID incorporati nel runtime e il suo README storico conservano il
significato della qualificazione originale. La nuova copia non è stata
compilata e non ha eseguito crittografia o misure di velocità.

## Risultati conservati

| Confronto nella seconda famiglia nuova | Riduzione geometrica appaiata | Vittorie | Mediane precedente / nuovo |
|---|---:|---:|---:|
| Richiesta al backend,32 coppie |24,710555%|32/32|2,510316 /1,866797 s|
| Richiesta completa con immagine,12 coppie |28,439223%|12/12|2,819970 /2,011201 s|

La prima famiglia resta separata:25,295668% backend e27,406907% immagine.
Complessivamente passano288 uscite cifrate,864 fasi terminali e quattro
controlli senza volto. La cattura della camera è esclusa dai tempi.
Tutte le osservazioni conservano i segnali di carico esterno: il risultato
non promette la stessa latenza su gallerie personali o altri computer.
Le percentuali di interventi precedenti non si sommano a queste misure.
Correttezza empirica, accuratezza biometrica e probabilità formale di errore
sono affermazioni distinte.

I numeri e gli indici originali sono in `RESULTS.json` ed `evidence/`.
L'esito negativo di G4 nella composizione e quello di Tetris motivano la
selezione; gli esperimenti25/26 conservano le successive strade negative.

## Verifiche di questa copia

Passano i18 test esistenti del protocollo client, con rete e crittografia
simulate e senza modelli. Il generatore originale ricrea in una destinazione
temporanea tutti gli87 file identici, compresi gli ID del servizio e circuito.
Il sorgente resta identico dopo entrambi i controlli. Ricevuta:
`evidence/PACKAGE_CHECKS.json`. Non è una nuova qualificazione FHE.

## Compilazione locale successiva

Eseguire questi comandi dalla cartella `experiments/22_demo_composita`.
Servono Cargo/Rust1.93.1 e le dipendenze del lock; `--offline` è possibile
solo dopo averle disponibili localmente. Il profilo qualificato è opt3,
CGU1, nessun LTO/PGO, CPU generica e16 thread con FFT Dif4 fissa. Non aggiungere
flag native o PGO se si vuole preservare questo profilo.

```sh
env -u RUSTFLAGS CARGO_ENCODED_RUSTFLAGS= \
  CARGO_PROFILE_RELEASE_OPT_LEVEL=3 CARGO_PROFILE_RELEASE_LTO=false \
  CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
  cargo +1.93.1 build --release --locked \
  --manifest-path runtime/candidate/Cargo.toml --target-dir .local/target-service
```

Un SDK locale va selezionato dal proprio toolchain; i percorsi assoluti del
vecchio Mac nei documenti di origine non sono dipendenze della compilazione.
Non cambiare i nomi dei crate o spostare i metadati fuori dalla radice runtime.
La LUT `core/artifacts/fused_candidate_zero_body.u64le` è pubblica e serve
anche quando il ramo che la usa non è selezionato.

Per creare una variante sorgente nuova, senza compilare o generare chiavi:

```sh
python3 -B runtime/configure.py --mode public_parallel \
  --destination .local/configured-public-parallel
```

La destinazione deve essere nuova e sotto questa cartella, esterna a
`runtime/`. Non aggiungere target, chiavi o ricevute dentro `runtime/`.

## Avvio esplicito di una nuova istanza

I comandi seguenti sono istruzioni per una futura esecuzione; questo
consolidamento non avvia processi. Scegliere due porte libere. Gli esempi
usano19004/18004 e non sostituiscono le demo già attive su9003/8003 e9004/8004.
In un primo terminale, dalla cartella dell'esperimento:

```sh
RAYON_NUM_THREADS=16 .local/target-service/release/varco_demo_composite_v9 \
  serve 19004 512 4
```

In un secondo terminale, con l'ambiente Python del repository attivo:

```sh
VARCO_SERVER=http://127.0.0.1:19004 \
VARCO_BIN="$PWD/.local/target-service/release/varco_demo_composite_v9" \
VARCO_CHIAVI="$PWD/.local/keys" RAYON_NUM_THREADS=16 \
  python -B -m uvicorn ui.camera_web:app --app-dir runtime \
  --host 127.0.0.1 --port 18004
```

Il client genera una nuova coppia di chiavi se `.local/keys` è vuota e invia
al backend soltanto la chiave di valutazione. Non usare la cartella delle
chiavi o la galleria di una demo esistente. La galleria parte vuota e resta
in memoria fino al riavvio del backend; l'iscrizione si effettua nella pagina.

La pagina dipende dal repository intero: trova `RESEARCH_STATE.md` e importa
`experiments/08_cnn/embedding.py`. Le dipendenze Python sono dichiarate nel
`pyproject.toml`/`uv.lock` della radice; il modulo usa anche imageio,
InsightFace, ONNX Runtime e scikit-image. I pesi sono asset esterni nella cache
InsightFace e possono essere scaricati al primo uso. DigiFace è opzionale
per i campioni sintetici già allineati. Non sono inclusi immagini, pesi,
chiavi o gallerie; il core Rust non richiede questi asset.

Il terminale fidato vede immagine, embedding e risultato decifrato. Il
backend tratta il probe cifrato, ma galleria e soglie sono pubbliche in
questo modello. Il risultato è il primo minimo esatto, ammesso solo se passa
la propria soglia; non si sceglie un candidato più lontano perché accetta.
