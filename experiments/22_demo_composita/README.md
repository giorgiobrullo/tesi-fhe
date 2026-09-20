# 22 - Demo TFHE composita

Un servizio di riconoscimento facciale che riceve un probe cifrato e restituisce
un'identità cifrata oppure un rifiuto. Il risultato è il **primo minimo esatto**:
nei pareggi vince il primo elemento della galleria; l'accesso è consentito solo
se quel vincitore soddisfa la propria soglia inclusiva. Un candidato più lontano
non può sostituirlo perché ha una soglia più permissiva.

Per installare le dipendenze, predisporre i modelli, generare le chiavi e usare
fotocamera o immagini, seguire la [demo client/server](../../demo/dual_view/README.md).
La galleria parte vuota e viene gestita dalla pagina server.

## Metodo

Il servizio usa TFHE-rs 1.7, ingresso Head/PFKS full51/low60 e una risposta
di tre LWE che codificano tre cifre ID in base 15.
La modalità `public_parallel` combina tagli delle cifre ID, normalizzatori
condivisi, specializzazione delle costanti pubbliche e parallelismo dei
confronti e della selezione. Il torneo conserva le barriere fra livelli.
Il client rileva i landmark e calcola l'embedding ResNet100 sul volto allineato.
G4 e Tetris sono esclusi dalla variante selezionata.

Il client fidato vede immagine, embedding e risultato decifrato. Il backend
riceve il probe cifrato e la chiave di valutazione; in questo modello, galleria
e soglie sono pubbliche. Le tre cifre decifrate ricostruiscono
`low + 15 * middle + 225 * high`: zero significa rifiuto, gli altri codici
identificano una delle al massimo 3374 voci ammesse.
Il [contratto del core](runtime/core/README.md) descrive API, domini e semantica.

## Risultati

Il confronto abbinato usa due famiglie nuove di chiavi. Per ciascuna famiglia
sono misurate 32 coppie di richieste al backend e 12 coppie di richieste
complete con immagini, confrontando la versione precedente con la composizione.

| Percorso | Famiglia | Mediana precedente / composita | Riduzione geometrica appaiata | Vittorie |
|---|---|---:|---:|---:|
| Backend HTTP | Prima | 2,406070 / 1,767481 s | 25,295668% | 32/32 |
| Immagini HTTP | Prima | 2,813581 / 2,001651 s | 27,406907% | 12/12 |
| Backend HTTP | Conferma | 2,510316 / 1,866797 s | 24,710555% | 32/32 |
| Immagini HTTP | Conferma | 2,819970 / 2,011201 s | 28,439223% | 12/12 |

Le mediane riassumono separatamente i due programmi; la riduzione è calcolata
sui rapporti entro coppia. I risultati delle due famiglie e dei due percorsi
restano separati e non si sommano. Le verifiche comprendono **288 uscite cifrate,
864 fasi terminali e quattro controlli senza volto**; includono controlli e
richieste di preparazione oltre alle coppie usate per stimare la latenza.

Il backend usa otto scene a N128/129, con soglie uniformi e variamente miste.
Il percorso immagini usa tre frame, galleria N129 e soglia 273; include il
lavoro del client fino alla risposta completa, ma esclude l'acquisizione della
fotocamera. Il [rapporto del servizio](evidence/ORIGINAL_SERVICE_RESULTS.md)
riporta risultati per scena, preparazione delle chiavi e memoria osservata.
I valori numerici sono disponibili in [RESULTS.json](RESULTS.json).
Il [manifest di provenienza](PROVENANCE.json) riporta le impronte dei file
inclusi e distingue i sorgenti invariati dalle copie pubbliche delle evidenze,
redatte per rimuovere percorsi locali e metadati personali. Non rappresenta
una nuova verifica FHE.

Una campagna distinta di 96 triple abbinate ha selezionato la composizione
pubblica/parallela: riduzione del 6,596842% rispetto al proprio controllo.
L'aggiunta di G4 è risultata più lenta della variante selezionata.
Il prototipo Tetris provato, pur superando i controlli di correttezza del
componente, rallenta il produttore di confronto del 66,40% nel pilot di
18 coppie. Il [rapporto delle alternative](evidence/ORIGINAL_RISULTATI.md)
descrive il perimetro di questi confronti.

Tutte le 288 finestre osservate hanno carico esterno alto; 237 hanno contabilità
dei processi parzialmente sconosciuta. Nessuna coppia è stata esclusa per il
carico o per l'effetto misurato. Non è stimato un intervallo di confidenza.
I risultati non garantiscono la stessa latenza su altri computer o gallerie.
Correttezza FHE osservata, accuratezza biometrica e probabilità formale di errore
sono affermazioni distinte.

## Compilazione

Servono Rust/Cargo **1.93.1** tramite rustup e una catena di compilazione
C/C++ disponibile per le dipendenze native. I
[prerequisiti Python e delle piattaforme](../../demo/dual_view/README.md#prerequisiti)
riguardano l'applicazione completa; questa compilazione prepara il motore Rust.
Predisporre il toolchain con `rustup toolchain install 1.93.1 --profile minimal`,
poi eseguire dalla cartella `experiments/22_demo_composita`.
`--offline` è utilizzabile solo quando le dipendenze del lock sono già disponibili.

```sh
env -u RUSTFLAGS CARGO_ENCODED_RUSTFLAGS= \
  CARGO_PROFILE_RELEASE_OPT_LEVEL=3 CARGO_PROFILE_RELEASE_LTO=false \
  CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
  cargo +1.93.1 build --release --locked \
  --manifest-path runtime/candidate/Cargo.toml --target-dir .local/target-service
```

Il profilo del confronto usa ottimizzazione 3, una unità di generazione del
codice, nessun LTO/PGO, CPU generica, 16 thread e FFT Dif4 fissa. Cambiare
queste impostazioni modifica le condizioni rispetto al benchmark.

L'eseguibile prodotto è `.local/target-service/release/varco_demo_composite_v9`.
Il pacchetto Rust comprende sorgenti, lockfile, metadati del circuito e la LUT
pubblica `runtime/core/artifacts/fused_candidate_zero_body.u64le`.
La compilazione del core non richiede modelli, immagini o chiavi.
Per avviare l'applicazione seguire la [guida della demo](../../demo/dual_view/README.md#avvio-locale).

## Varianti sorgente

Il generatore prepara una variante in una directory nuova, sotto questa
cartella e fuori da `runtime/`:

```sh
python3 -B runtime/configure.py --mode public_parallel \
  --destination .local/configured-public-parallel
```

La generazione aggiorna configurazione e identificatori della variante.
Non compila il codice e non genera chiavi. La modalità alternativa
`public_parallel_g4` è disponibile per esperimenti; i suoi risultati vanno
misurati separatamente. Conservare target e chiavi fuori dalla directory
sorgente per poter riusare il generatore.
