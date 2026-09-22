# Benchmark e risultati

Questa cartella raccoglie misure biometriche in chiaro, verifiche FHE,
confronti di latenza e generatori di figure. La sintesi delle conclusioni
è in [findings.md](../findings.md); le istruzioni comuni sono nella
[guida alla riproducibilità](../docs/riproducibilita.md).

## Scegliere il percorso

| Obiettivo | Punto di ingresso | Cosa misura |
|---|---|---|
| Confrontare le tecniche biometriche | [verifica.py](verifica.py), [identificazione_1n.py](identificazione_1n.py) | Accuratezza in chiaro, con protocolli distinti |
| Leggere le campagne exact-ID storiche | [Risultati A33](results/fhe_digiface_exact_primary_a33_2026-09-02.md), [A29/A33 appaiato](results/fhe_digiface_exact_paired_a29_a33_2026-09-02.md) | Concordanza FHE/clear e latenza nelle condizioni riportate |
| Studiare il servizio corrente | [Runtime mantenuto](../runtime/README.md) | Motore corretto usato dalle demo attuali |
| Consultare il confronto storico del servizio composito | [Esperimento 22](../experiments/22_demo_composita/README.md) | Backend e richieste complete con immagini nelle campagne precedenti |
| Rigenerare le due figure correnti del 20 settembre | [Comando unico](figure_current.py), [istruzioni](../docs/riproducibilita.md#entrambe-le-figure-del-20-settembre) | Ricalcolo dai CSV pubblici e PNG/SVG/PDF, senza archivio privato o FHE |
| Rigenerare il grafico comune storico del 9 settembre | [Guida del grafico](../output/figures/progressione-fhe/benchmark-comune-matplotlib-20260909/LEGGIMI.md), [generatore](figure_common_benchmark.py) | Figura storica dai dati inclusi, senza nuove esecuzioni FHE |

## Biometria in chiaro

`verifica.py` confronta PCA, LBP, HOG e CNN sui file InsightFace `.bin` in
`datasets/bench/`: LFW, CPLFW, CFP-FP, AgeDB-30 e CALFW. Salta i set assenti.
Il protocollo è verifica **1:1**, con soglia selezionata sui fold di training
e accuratezza sui fold di test. I dati sono esterni; le indicazioni per
procurarli e per i dataset 1:N sono nella [guida ai dataset](../docs/benchmark_dataset.md).

`identificazione_1n.py` usa DigiFace e VGGFace2 con uno split open-set:
galleria, probe noti e probe ignoti. Riporta Rank-1 e DIR alle soglie FPIR
considerate. Il risultato riguarda lo split e la calibrazione usati nello
script; non è una misura della demo live né una verifica crittografica.

Dalla radice, dopo la [preparazione Python](../demo/dual_view/README.md#prerequisiti)
e dei dataset:

```sh
.venv/bin/python -B benchmark/verifica.py
.venv/bin/python -B benchmark/identificazione_1n.py
```

Gli script scrivono in `benchmark/results/`, rispettivamente
`verifica_duri.csv` e `identificazione_1n.csv`, e possono sostituire risultati
omonimi: eseguirli su una copia di lavoro se si vogliono conservare i dati inclusi.

## Campagne FHE

I file `fhe_*.py` conservano i driver delle campagne della demo precedente
(es. [validator DigiFace](fhe_digiface_validation.py)). Possono richiedere
cache biometriche, binari congelati o manifest locali non distribuiti.
I report in [results/](results/) descrivono prerequisiti, prove e limiti di
ciascuna campagna; il solo clone non ricrea automaticamente quelle esecuzioni.
Per compilare e usare il servizio corrente seguire la
[guida di compilazione](../BUILD_AND_RUN.md) e le [guide delle demo](../demo/README.md).
L'esperimento 22 conserva il servizio dei confronti storici, con sorgenti e
identità del circuito diversi dal runtime mantenuto.

Anche `a29_pfail_accounting.py`, `a33_pfail_accounting.py` e
`figure_exact_id_improvements.py` conservano i controlli sugli hash originali:
gli estratti JSON pubblici non sostituiscono gli input completi di quei generatori
storici. Il [registro dei dati](../docs/provenienza-dati.json) distingue le due impronte.

Il [grafico comune del 9 settembre](../output/figures/progressione-fhe/benchmark-comune-matplotlib-20260909/LEGGIMI.md)
confronta i prototipi a N8/D64 e l'exact-ID a N127/D512 in due sezioni separate.
Non si calcola un guadagno attraverso lo stacco. Mantiene l'errore storico
Head generale e le condizioni di carico; i test successivi riusciti non
risolvono quel fallimento.

Per rigenerare PNG, SVG e PDF in una cartella nuova:

```sh
.venv/bin/python -B benchmark/figure_common_benchmark.py --output .local/grafico
```

Correttezza sui cifrati provati, accuratezza biometrica e probabilità formale
di errore del circuito restano risultati diversi.
