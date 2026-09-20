# Eseguire il progetto e leggere i risultati

Il repository offre una demo interattiva, implementazioni sperimentali e
misure delle prestazioni. Questi punti di ingresso permettono di provare
il sistema, studiarne il funzionamento e controllare i risultati.
La qualifica del runtime con il nuovo selettore è separata dalle campagne
storiche e si legge in [PACK4_VALIDATION.md](validazione/PACK4_VALIDATION.md).

## Ambiente e piattaforme

Usare Python 3.12 con uv. La campagna del nuovo runtime usa Rust/Cargo 1.98.0
su macOS ARM64; i comandi Rust sotto assumono quella versione nell'ambiente.
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

## Studiare le implementazioni

L'[indice degli esperimenti](../experiments/README.md) presenta il percorso
dai primi prototipi all'implementazione usata dalla demo. Ogni esperimento
descrive la domanda, il metodo, i risultati e le condizioni del confronto.

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
fornisce risultati e sorgenti parziali common-mask/BGV: le dipendenze mancanti
sono elencate nel suo README. Per provare un servizio completo usare il runtime mantenuto.

## Provenienza dei dati inclusi

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
cargo test --release --locked \
  --manifest-path runtime/candidate/Cargo.toml --target-dir .local/target-service \
  -p composite_camera_service_20260908 -p selector_four_core_20260920 \
  -- --test-threads=1
```

La regressione FHE mirata genera chiavi fresche soltanto in memoria ed esegue
tre query a N2: soglia inclusiva, rifiuto uniforme e rifiuto del primo vincitore
con soglie miste. Usa 16 thread e la politica FFT del servizio. Eseguirla
isolatamente, senza altre build o benchmark:

```sh
cargo test --release --locked \
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

Le due nuove campagne del 20 settembre, CSV e figure sono nel
[percorso corrente](percorso-sperimentale-20260920.md). I loro audit
completi richiedono i cifrati e le chiavi conservati localmente, esclusi
dalla consegna. Il comando seguente rigenera soltanto la figura storica.

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
