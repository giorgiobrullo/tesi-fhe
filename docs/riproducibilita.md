# Eseguire il progetto e leggere i risultati

Il repository offre una demo interattiva, implementazioni sperimentali e
misure delle prestazioni. Questi punti di ingresso permettono di provare
il sistema, studiarne il funzionamento e controllare i risultati.
La qualifica del runtime con il nuovo selettore è separata dalle campagne
storiche e si legge in [PACK4_VALIDATION.md](validazione/PACK4_VALIDATION.md).

## Ambiente e piattaforme

Usare Python 3.12 con uv. Le campagne di settembre usano Rust/Cargo 1.98.0
su macOS ARM64. Per nuove build usare la patch 1.98.1: i comandi sotto
la selezionano con `rustup run 1.98.1`, dopo l'installazione descritta nella
[guida della demo](../demo/dual_view/README.md#avvio-locale).
Le revisioni storiche conservano le proprie versioni del compilatore.
Dalla radice, `uv sync --locked --python 3.12` crea l'ambiente `.venv`.
Il lock include anche Concrete e TenSEAL: le wheel vincolano l'installazione
completa a macOS e Linux x86_64 secondo i
[prerequisiti della demo](../demo/dual_view/README.md#prerequisiti).
Linux ARM e Windows non sono coperti da questo bootstrap. La guida specifica
anche i casi macOS che richiedono compilazione da sorgente; non implica
che ogni piattaforma sia stata verificata.

Dataset biometrici e pesi dei modelli sono asset esterni. I sorgenti e i dati
riepilogativi inclusi permettono di studiare le implementazioni e rigenerare
le figure; alcune campagne storiche richiedono anche cache, binari o manifest
non distribuiti, come indicato nei relativi report.

## Provare la demo

Seguire il [README della demo](../demo/dual_view/README.md) per installare
le dipendenze Python, compilare il motore Rust e preparare modelli e chiavi.
La galleria parte vuota: dalla pagina server si registra una persona;
dalla pagina client si effettua una richiesta di accesso usando una foto
o la fotocamera.

Il client calcola l'embedding del volto e cifra la query. Il server cerca
il primo minimo sui dati cifrati e verifica la soglia di quel vincitore.
Il client decifra la risposta e mostra accesso consentito o negato.
Le fotografie d'iscrizione e la galleria sono visibili al server.

La demo richiede un terminale fidato ed è pensata per l'esecuzione sullo
stesso computer. Il [modello di fiducia](../README.md#modello-di-fiducia)
spiega quali informazioni sono protette e quali ipotesi sono necessarie.

Per la pagina unica con galleria d'esempio e sessioni individuali, seguire
la [guida della demo web](../demo/web/README.md). Questa usa un ambiente
Python dedicato, senza Concrete o TenSEAL, e descrive anche l'avvio Linux ARM
e dietro HTTPS. Nella demo web il client fidato gira sullo stesso host del
motore: l'operatore può accedere alle foto, ai template e agli esiti.

## Studiare le implementazioni

L'[indice degli esperimenti](../experiments/README.md) presenta il percorso
dai primi prototipi all'implementazione usata dalla demo. Ogni esperimento
descrive la domanda, il metodo, i risultati e le condizioni del confronto.

La stessa mappa comprende campagne e tentativi privi di cartella numerata.
Per ciascuno distingue il rapporto, i dati e i programmi inclusi, con le
dipendenze esterne necessarie a una nuova esecuzione. La trattazione dei
[tentativi e risultati negativi](risultati/alternative.md) spiega cosa è
stato provato e quali conclusioni sono sopravvissute alle correzioni.

I [materiali dei tentativi A](../experiments/attempts-a/README.md) includono
i programmi e gli input pubblici verificati. Il ricostruttore
ricrea i percorsi originali in una cartella nuova, senza moltiplicare le
copie identiche nella repository:

```sh
python3 tools/restore_attempt.py --list
python3 tools/restore_attempt.py --id A108 --check
mkdir -p .local
python3 tools/restore_attempt.py --id A108 --output .local/a108-source
```

`--check` verifica i file senza scrivere; `--output` li verifica prima di
copiare e registra la ricostruzione. Il comando non avvia i programmi.
Le versioni di libreria, i prerequisiti di esecuzione e gli eventuali
asset esterni restano quelli della singola prova.

Per le campagne di benchmark, il manifesto unico `PROVENANCE.json`
contiene inventario dei file, origini e mappa dei sorgenti. Il secondo
[strumento di ricostruzione](../tools/README.md#ricostruire-una-campagna-di-benchmark)
verifica e materializza quel layout. Un manifesto di sole dipendenze,
come quello biometrico Georgia Tech, consente la verifica ma non una
ricostruzione completa.

Il [runtime mantenuto](../runtime/README.md) contiene il servizio modulare
e la libreria Rust da cui partire per il riuso. Il
[pacchetto 22](../experiments/22_demo_composita/README.md) conserva la versione
su cui sono stati misurati i risultati storici del servizio. I suoi tempi
e conteggi non descrivono automaticamente il selettore nuovo, che aggiunge
un refresh del controllo e richiede una diversa chiave funzionale PFKS.
I pacchetti precedenti permettono di confrontare le varianti dell'algoritmo;
i sorgenti possono differire intenzionalmente, perché rappresentano
implementazioni diverse. I file `RESULTS.json` riportano i dati delle prove.

I README specificano compilatore, librerie e comandi necessari. I lockfile
fissano le dipendenze Rust; le tabelle LUT incluse sono dati pubblici usati
dal circuito. Le chiavi vanno generate per la propria esecuzione.

L'[esperimento 24](../experiments/24_frontiere_common_mask_bgv/README.md)
include i sorgenti common-mask/BGV, i riferimenti necessari e gli input
pubblici. La chiusura delle dipendenze locali è stata controllata; i comandi
e le librerie esterne sono nel suo README. La verifica dei file non aggiunge
una nuova esecuzione alle campagne riportate.

## Provenienza dei dati inclusi

Le copie pubblicate normalizzano i percorsi personali: `/workspace/research`
indica l'archivio di ricerca, `/workspace/maintained` il checkout mantenuto,
`/opt/cargo` e `/opt/models` le cache di librerie e modelli.
`/opt/tool-cache`, `/workspace/legacy-benchmark` e `/workspace/redacted-home`
sono gli altri segnaposto locali. Questi percorsi non sono installazioni fornite
dalla repository: vanno adattati prima di eseguire i driver archiviati.
Il [registro delle impronte](provenienza-dati.json) documenta le sostituzioni
e distingue i byte precedenti da quelli distribuiti. Risultati numerici,
verdetti e hash delle esecuzioni originali restano invariati; le copie ripulite
non costituiscono nuove esecuzioni né sorgenti byte-identici agli originali.
I controlli dei driver sulle dipendenze distribuite usano le nuove impronte;
il registro elenca i riferimenti aggiornati. Gli hash nelle ricevute storiche
continuano a identificare i byte usati nelle esecuzioni documentate.

Le misure FHE si riferiscono alle revisioni identificate nei rapporti.
L’aggiornamento che elimina la dipendenza dalle note locali cambia il client
Python e le impronte del pacchetto, mantenendo invariati tutti i sorgenti Rust,
i parametri e le operazioni cifrate. I tempi archiviati conservano le identità
originali; l’aggiornamento non costituisce una nuova campagna temporale.

Alcuni report e JSON sono estratti pubblici privi dei metadati personali
o dei percorsi locali degli originali. Il
[registro delle impronte](provenienza-dati.json) distingue lo SHA-256
dell'originale da quello della copia pubblicata: una modifica editoriale
cambia l'impronta del file anche quando conserva le misure riportate.
Il [registro del 20 settembre](publication-provenance-20260920.json) documenta
le ulteriori copie redatte della qualifica pack4 e del confronto CKKS/TFHE.
I riferimenti hash interni e le ricevute dei grafici identificano gli originali
congelati; il registro distingue gli hash delle copie pubbliche.
Il [confronto diretto del costo](selector-direct-cost-20260920.md) include
un proprio registro e il comando per ricalcolare le statistiche.

I manifest `PROVENANCE.json` dei pacchetti 16–26 indicano le impronte dei
file distribuiti e distinguono i sorgenti invariati dalle evidenze redatte.

## Eseguire i test della demo

I comandi di questa sezione verificano la demo a due pagine e il runtime.
Per la pagina unica, seguire i [test della demo web](../demo/web/README.md#verificare-le-modifiche-alla-demo-web),
che usano il suo ambiente dedicato e comprendono anche l'interfaccia JavaScript.

Dalla radice, dopo avere installato l'ambiente Python:

```sh
.venv/bin/python -B -m unittest demo.dual_view.test_client demo.dual_view.test_server
.venv/bin/python -B - <<'PYTHON'
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path('runtime').resolve()))
names = ['client.test_app', 'client.test_protocol',
         'client.test_pack4_ledger', 'runtime.test_configure']
suite = unittest.defaultTestLoader.loadTestsFromNames(names)
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(not result.wasSuccessful())
PYTHON
```

Questi test verificano interfaccia, richieste, risposte, pipeline del client
e binding dei sorgenti usando rete e crittografia simulate. Non richiedono una fotocamera
o un servizio attivo. Le prove con cifrati reali e i benchmark sono descritti
separatamente nei risultati degli esperimenti.

Per le regressioni asincrone del browser, con Node.js (26.8.1 nella verifica
storica del 18 settembre):

```sh
node --test demo/dual_view/test_ui.mjs
```

Non occorrono pacchetti npm. I test controllano risposte della galleria in
ritardo, ritorno alla pagina dalla cache e chiusura della fotocamera durante
l'avvio. Usano un DOM minimo e stream simulati; la prova storica con immagini
e servizi attivi è descritta nella [verifica del 18 settembre](runtime-verification.md).

I test Rust del servizio controllano codec, galleria, CLI e parser HTTP;
quelli ordinari del core controllano domini, LUT, conteggi e pareggi. Dalla
radice, mantenendo gli output di compilazione fuori dai sorgenti:

```sh
rustup run 1.98.1 cargo test --release --locked \
  --manifest-path runtime/candidate/Cargo.toml --target-dir .local/target-service \
  -p composite_camera_service_20260908 -p selector_four_core_20260920 \
  -- --test-threads=1
```

La regressione FHE mirata genera chiavi fresche soltanto in memoria ed esegue
tre query a N2: soglia inclusiva, rifiuto uniforme e rifiuto del primo vincitore
con soglie miste. Usa 16 thread e la politica FFT del servizio. Eseguirla
isolatamente, senza altre build o benchmark:

```sh
rustup run 1.98.1 cargo test --release --locked \
  --manifest-path runtime/candidate/Cargo.toml --target-dir .local/target-service \
  -p selector_four_core_20260920 --lib \
  service_smoke_tests::fresh_key_public_parallel_preserves_exact_ids_without_benchmarking \
  -- --ignored --exact --test-threads=1
```

È una regressione su quei casi, non una misura di velocità o una prova generale
del circuito. Le diagnostiche FHE storiche ignorate restano separate.
I [rapporti sperimentali](validazione/README.md) distinguono la prima
correzione B dalle prove pack4 e specificano sorgenti, chiavi e casi misurati.
Gli esiti valgono per quelle versioni: dopo una modifica al runtime,
ricompilare e ripetere le verifiche pertinenti seguendo la
[procedura di sviluppo](../BUILD_AND_RUN.md#modificare-il-progetto).

## Grafici correnti e rigenerazione storica

### Quale risultato descrive quale versione

| Evidenza | Versione e carico | Cosa misura |
|---|---|---|
| [Pipeline binaria del 4 ottobre](validazione/PIPELINE_BINARIA_20261004.md) | Prototipo Head55 + due PBS, nuova famiglia; common e Mixed N2 | Quattro casi corretti, quinto atteso0/ID2, sesto omesso; proposta respinta, tempi esclusi |
| [Comparatore binario del 4 ottobre](validazione/COMPARATORE_BINARIO_20261004.md) | Helper 1.8.1, una fresca famiglia; due cifre55, output binario59 | Otto casi completati e 24 ternari reference corretti; Head, torneo e tempi esclusi |
| [Comparatore compresso del 4 ottobre](validazione/COMPARATORE_COMPRESSO_20261004.md) | Helper 1.8.1, una nuova famiglia; encoding55 e riferimento59 | Correttezza del solo primitivo: stop al primo errore centrato dopo sei casi; nessuna latenza |
| [Buffer temporaneo del 4 ottobre](validazione/SCRATCH_BR_20261004.md) | Helper separato 1.8.1, M4 Max, 1/16 worker; nessuna chiave o query | Allocazione/azzeramento/rilascio contro riuso su memoria pubblica; non è un tempo FHE |
| [Progressione corretta del 20 settembre](../output/figures/progressione-fhe/selettori-corretti-20260920/LEGGIMI.md) | Dieci stadi, TFHE-rs 1.7, N127/D512/T4 nel tratto completo | Core cifrato; 30 misure per stadio, mediana e quartili |
| [Confronto CKKS/TFHE](../output/figures/ckks-tfhe/selettore-corretto-20260920/LEGGIMI.md) | CKKS balanced-v3 e TFHE CPU corretto 1.7, N128 e soglia generale nell'esempio riassuntivo | Core delle due costruzioni, mediane dei blocchi; uscite e contratti distinti |
| [Demo dopo SSE](validazione/CONTROLLO_GENERALE_20261002.md#risultati-cosa-rimane-valido) | Demo 1.7 con anchor e pack4, galleria N120 | Tre osservazioni click→risultato con foto già caricata; non il solo core |
| [Migrazione 1.8.1](validazione/TFHE_181_MIGRATION.md) | Runtime aggiornato e pilot N120 separato | Gate funzionali e screening temporale breve; non sostituisce i tempi 1.7 |
| [Confronto 1.7/1.8.1 del 4 ottobre](validazione/TEMPI_181_20261004.md) | Stesso Rust 1.98.1, M4 Max/16 thread, N120; tre famiglie per versione | 144 misure del servizio HTTP FHE; preparazione della foto e demo escluse |
| [Demo 1.8.1 del 4 ottobre](validazione/DEMO_SSE_20261004.md) | Applicazione reale, M4 Max/16 thread, N120, una foto per richiesta | Tre osservazioni POST→SSE con elaborazione foto e FHE; cattura e rendering esclusi |
| [Diagnosi del merge del 4 ottobre](validazione/PROFILO_MERGE_20261004.md) | Copia 1.8.1, M4 Max/16 thread, N120; un nodo del primo livello, una nuova famiglia | Tre osservazioni dei passaggi sequenziali del worker dopo un warmup; nessun rapporto con campagne precedenti |
| [Profilazione del 4 ottobre](validazione/PROFILO_RUNTIME_20261004.md) | Copia 1.8.1, M4 Max/16 thread, N120; stesso binario, chiave e query per on/off | 48 misure e 24 warmup; fasi cifrate e livelli del torneo, senza foto o demo |
| [Foto originali](validazione/BIOMETRIA_VGGFACE2_20261002.md) e [preparazione UI](validazione/BIOMETRIA_UI_20261002.md) | Estrattore corrente, N120/T273, iscrizione a tre foto | Qualità della decisione in chiaro e sensibilità appaiata; FHE e timer esclusi |

N, soglia, preparazione e inizio/fine del timer fanno parte del risultato.
Non c'è un unico «finale» che possa ereditare tutte queste misure.

Le due nuove campagne del 20 settembre, CSV e figure sono nel
[percorso corrente](percorso-sperimentale.md). I loro audit
completi richiedono i cifrati e le chiavi conservati localmente, esclusi
dalla consegna. La rigenerazione delle figure usa invece soltanto i dati
pubblici e non richiede quell'archivio.

### Entrambe le figure del 20 settembre

Dalla radice del repository, con uv installato:

```sh
uv run --script --python 3.12 benchmark/figure_current.py --output .local/grafici-20260920
```

Il [comando](../benchmark/figure_current.py) prepara un ambiente dedicato con
Matplotlib 3.10.9 e le sue dipendenze. Non installa Concrete, TenSEAL o i
modelli biometrici, non compila Rust e non esegue FHE. Al primo uso serve
accesso alla rete per le dipendenze mancanti; una volta disponibili Python
e pacchetti nella cache di uv, si può aggiungere `--offline`.

La destinazione deve essere **nuova**: per ripetere il comando scegliere
un altro nome. Le cartelle esistenti e l'area degli originali `output/figures`
sono rifiutate. Vengono prodotti:

- `progressione.{png,svg,pdf}` e `progressione-email.png`;
- `confronto-ckks-tfhe.{png,svg,pdf}` e `confronto-ckks-tfhe-email.png`;
- `statistiche.json`, con i valori ricalcolati;
- `RENDER.json`, con impronte di ingressi, generatori e risultati, e versioni dell'ambiente.

Prima di creare le figure vengono verificate le impronte dei sette file
di ingresso e la concordanza fra CSV e riepiloghi pubblicati. Nella
progressione, mediana e quartili usano solo le 300 misure; i 150 warmup
restano esclusi. Il pannello storico dei prototipi conserva i suoi dati
del 9 settembre e rimane separato. Per CKKS/TFHE si ricalcolano le 18 celle
dai 216 record: mediana CKKS per blocco, media delle mediane TFHE prima/dopo,
poi mediana e min–max dei tre blocchi. Non si usano mediane aggregate delle
singole query come sostituto di questo stimatore.

Il controllo conferma statistiche e consistenza dei record pubblici;
non ridecifra i risultati, non ripete i gate e non certifica gli audit
crittografici indicati nei vecchi manifest. La ricostruzione della
progressione, il TFHE intermedio del confronto e la demo anchor/pack4
rimangono circuiti distinti. Dati e figure originali non vengono modificati.
Le esportazioni sono nuove: la dicitura del carico nella progressione
precisa che l'incertezza riguarda l'attribuzione CPU, non la copertura
temporale. Le impronte dei vecchi PDF non sono quelle delle nuove esportazioni.

Se si dispone già di Python e Matplotlib 3.10.9, si può eseguire direttamente
`python -B benchmark/figure_current.py --output CARTELLA_NUOVA`.
I controlli del generatore, senza rendering o FHE, si eseguono con:

```sh
python -B -m unittest benchmark.test_figure_current benchmark.test_figure_current_progression benchmark.test_figure_current_ckks
```

### Figura storica del 9 settembre

La [campagna del 9 settembre](../output/figures/progressione-fhe/benchmark-comune-matplotlib-20260909/LEGGIMI.md)
include il grafico, le osservazioni in CSV e le statistiche riepilogative.
Per produrre PNG, SVG e PDF dai dati, eseguire dalla radice:

```sh
.venv/bin/python -B benchmark/figure_common_benchmark.py --output .local/grafico
```

La cartella di destinazione deve essere nuova. Il comando verifica le
impronte dei dati e disegna la figura; non esegue nuovi calcoli FHE.
Il grafico conserva le versioni misurate il 9 settembre e non include
misure della riparazione del selettore del 19 settembre.

`osservazioni-exact.csv` e `osservazioni-prototipi.csv` contengono anche il
riscaldamento, identificato nella colonna `phase`. `duration_ns` è espresso
in nanosecondi. Le mediane e i quartili usano soltanto le righe `measured`
nel CSV exact e `measure` nel CSV dei prototipi; le righe `warmup` sono escluse.
Gli accoppiamenti confrontano la stessa scena, famiglia
e ripetizione: un rapporto appaiato non è il rapporto delle due mediane.

## Interpretare correttamente le misure

Il grafico ha due sezioni: primo minimo a N=8 e 64 coordinate; risultato
0/ID a N=127 e 512 coordinate. Lo stacco cambia il compito, quindi non si
calcola una percentuale di miglioramento fra i due lati. I tempi sono
logaritmici e le barre mostrano l'intervallo interquartile, non un intervallo
di confidenza.

Ogni confronto vale per le chiavi, scene, parametri e condizioni indicati.
I tempi del core escludono interfaccia, embedding e rete; le misure del
servizio seguono un protocollo diverso. I guadagni di campagne diverse non
si sommano. Il metodo segnala inoltre il carico concorrente della macchina.

Un risultato esatto sui casi provati non stabilisce la probabilità di errore
dell'intero circuito né l'accuratezza biometrica su nuove persone. La croce
su Head generale conserva il fallimento storico ID75 anziché ID1. La diagnosi
successiva lo localizza nel selettore: indirizzo 341 fuori da 300…340, con
estrazioni Head corrette in quell'istanza. La baseline del 19 settembre passa
il replay separato con ID1 e indirizzo 318 nel nodo interessato. Queste prove
non qualificano da sole il nuovo selettore o la probabilità globale di errore.
I [risultati](../findings.md) e le [questioni aperte](limiti.md)
descrivono queste distinzioni nel dettaglio.
