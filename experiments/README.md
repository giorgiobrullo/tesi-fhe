# Esperimenti e materiali

<a id="composizione-del-motore-e-alternative"></a>
<a id="dal-selettore-corretto-ai-tentativi-recenti"></a>
<a id="dalle-prime-operazioni-alla-decisione-cifrata"></a>
<a id="esperimenti"></a>

Questa è la mappa di codice, input e risultati. Il
[percorso sperimentale](../docs/percorso-sperimentale.md) racconta
le scelte; i [findings](../findings.md) raccolgono le conclusioni.
I [tentativi e risultati negativi](../docs/risultati/alternative.md)
spiegano i rami scartati, le correzioni e i risultati senza vantaggio di costo.
Per sviluppare o avviare l’applicazione usare il
[runtime mantenuto](../runtime/README.md) e le [guide della demo](../demo/README.md).

Le cartelle numerate identificano campagne, le sigle A tentativi più piccoli
e le F schede di risultati. Il numero non dichiara un’esecuzione riuscita.
Le fonti dei run restano associate alla versione effettivamente misurata;
la copia dei sorgenti non costituisce una nuova build o una replica.

Per trovare una campagna:

- [Primitive e contratto 0/ID, 00–16](#programmi-0016)
- [Composizione e alternative, 17–26](#pacchetti-1726)
- [Singoli tentativi A](#tentativi-a)
- [Selettore, migrazione e grafici](#selettore)
- [Servizio, riduzioni del costo e generalizzazione](#campagne-di-ottobre)

Nelle tabelle delle campagne numerate, il nome apre la guida; le colonne
successive portano direttamente a codice, input e risultati. I nomi dei materiali indicano:

| Percorso o file | Contenuto |
|---|---|
| `results/`, `RESULTS.json`, `samples.csv`, `rows.jsonl` | Dati e riepiloghi della singola campagna; la guida ne distingue campioni e aggregati. |
| `evidence/`, `docs/evidence/` | Rapporti, controlli e ricevute collegati alle prove; in `docs/evidence/` anche gli inventari delle fonti. |
| `docs/risultati/`, `docs/validazione/` | Interpretazione del percorso e rapporti di verifica, con rimandi ai dati. |
| `output/figures/` | Figure esportate e, nelle rispettive cartelle, dati e metodo per rigenerarle. |
| `PROVENANCE.json`, `SOURCE_MAP.json`, `RESULTS_MAP.json` | Identità, origini e posizioni dei file; le mappe dei sorgenti descrivono anche i percorsi da ricostruire. |

<a id="percorso-storico-conservato"></a>
<a id="programmi-iniziali"></a>

<a id="programmi-0016"></a>

## Dalle primitive al contratto 0/ID — 00–16

| Campagna | Codice | Input e prerequisiti | Risultati e metodo |
|---|---|---|---|
| [00–04, operazioni e protocollo](README-00-04.md) | [Cinque programmi e comandi](README-00-04.md) | Esempi numerici nei programmi; Python/Concrete | [Guida delle singole prove](README-00-04.md) |
| [05, PCA](05_pca/README.md) | [Demo e embedding](05_pca/) | Olivetti/LFW e cache descritti nel [README](05_pca/README.md) | [Prototipo](05_pca/README.md), [F4–F5](../docs/risultati/diario/f00-f14.md#f4) |
| [06, argmin e soglia](06_argmin_soglia/README.md) | [Programmi](06_argmin_soglia/) | Inputset e condizioni nel [README](06_argmin_soglia/README.md); utility [core](../core/README.md) | [CSV](06_argmin_soglia/results/), [F6](../docs/risultati/diario/f00-f14.md#f6) |
| [07, descrittori locali](07_descrittori_locali/README.md) | [Programmi](07_descrittori_locali/) | Olivetti/LFW; [comandi](07_descrittori_locali/README.md) | [CSV](07_descrittori_locali/results/), [metodo](07_descrittori_locali/README.md) |
| [08, CNN](08_cnn/README.md) | [Estrattori e prove](08_cnn/) | Modelli e foto esterni: [modelli](../docs/modelli_embedding.md), [dataset](../docs/benchmark_dataset.md) | [Risultati](08_cnn/results/), [metodo](08_cnn/README.md) |
| [09, GPU Concrete](09_gpu/README.md) | [Notebook conservato](09_gpu/colab_argmin_gpu.ipynb) | Ambiente e workload originali descritti nel [rapporto](09_gpu/RISULTATI.md) | [Rapporto GPU](09_gpu/RISULTATI.md) |
| [10, struttura dell’argmin](10_argmin_struttura/README.md) | [Struttura](10_argmin_struttura/bench_struttura.py), [varco](10_argmin_struttura/bench_varco.py) | Configurazioni della campagna nel [README](10_argmin_struttura/README.md) | [Rapporto](10_argmin_struttura/RISULTATI.md), [CSV](10_argmin_struttura/) |
| [11, MegaFace](11_megaface/README.md) | [Schema di valutazione](11_megaface/megaface_1n.py) | Embedding esterni; loader incompleto | [Stato: campagna non eseguita](11_megaface/README.md) |
| [13, confronto Concrete/TFHE-rs](13_tfhe_rs_headtohead/README.md) | [Crate Rust](13_tfhe_rs_headtohead/Cargo.toml) | Versioni, parametri e domini originali nel [README](13_tfhe_rs_headtohead/README.md) | [Rapporto](13_tfhe_rs_headtohead/RISULTATI.md), [dati](13_tfhe_rs_headtohead/results/) |
| [14, pipeline TFHE-rs](14_pipeline_tfhe_rs/README.md) | [Crate](14_pipeline_tfhe_rs/Cargo.toml), [core e driver](14_pipeline_tfhe_rs/src/) | Input e binari variano fra le revisioni; riferimenti nei singoli rapporti | [Registro della fase](14_pipeline_tfhe_rs/RISULTATI.md), [rapporti e dati](14_pipeline_tfhe_rs/results/), [campagne di servizio](../benchmark/results/) |
| [15, CKKS iniziale](15_ckks_confronto/README.md) | [Driver score/soglia](15_ckks_confronto/ckks_varco.py), [packing](15_ckks_confronto/ckks_packing_forte.py) | TenSEAL e configurazioni nel [README](15_ckks_confronto/README.md) | [Report originario](15_ckks_confronto/RISULTATI.md), [rerun e dati](15_ckks_confronto/results/) |
| [16, common-mask](16_common_mask_poc/README.md) | [Crate](16_common_mask_poc/Cargo.toml), [controllo ordinario](16_common_mask_poc/ordinary_baseline/Cargo.toml) | TFHE-rs fissata dai manifest e lockfile; [comandi](16_common_mask_poc/README.md) | [Record delle primitive](16_common_mask_poc/results/), [provenienza](16_common_mask_poc/PROVENANCE.json) |

Non è presente una cartella 12. I dataset e i pesi esterni non sono inclusi
automaticamente con i risultati; la [guida di riproducibilità](../docs/riproducibilita.md)
distingue ricalcolo dei dati e nuova esecuzione.

<a id="implementazioni-e-confronti-del-48-settembre-2026"></a>
<a id="pacchetti-17-26"></a>

<a id="pacchetti-1726"></a>

## Composizione del circuito e alternative — 17–26

Ogni scheda collega programma, dati e provenienza della sua campagna.
`RESULTS.json` è il riepilogo; i report e le ricevute collegati spiegano
protocollo, campioni e limiti. Le chiavi e gli asset privati necessari a
un replay originale non vengono ricreati dalla presenza di quei file.

| Campagna | Codice della revisione | Input, dipendenze e ricostruzione | Risultati |
|---|---|---|---|
| [17, Head/PFKS](17_head_pfks_tfhe17/README.md) | [Sorgenti](17_head_pfks_tfhe17/source/) | [Guida](17_head_pfks_tfhe17/README.md), [provenienza](17_head_pfks_tfhe17/PROVENANCE.json) | [Riepilogo](17_head_pfks_tfhe17/RESULTS.json), [rapporto](../docs/risultati/core-e-scaling.md#f85---headpfks-core-completo-e-primo-servizio) |
| [18, taglie e soglie](18_scaling_soglie_miste/README.md) | [Sorgenti](18_scaling_soglie_miste/source/) | [Guida](18_scaling_soglie_miste/README.md), [provenienza](18_scaling_soglie_miste/PROVENANCE.json) | [Riepilogo](18_scaling_soglie_miste/RESULTS.json), [rapporto](../docs/risultati/core-e-scaling.md#f86---taglie-variabili-e-soglie-generali-o-miste) |
| [19, runtime CPU](19_runtime_cpu/README.md) | [Sorgenti](19_runtime_cpu/source/), [configurazioni](19_runtime_cpu/configs/) | [Guida](19_runtime_cpu/README.md), [provenienza](19_runtime_cpu/PROVENANCE.json) | [Riepilogo](19_runtime_cpu/RESULTS.json), [rapporto](../docs/risultati/core-e-scaling.md#f87---fft-fissa-e-configurazione-cpu) |
| [20, normalizzatori](20_normalizzatori_carry/README.md) | [Sorgenti](20_normalizzatori_carry/sources/) | [Guida](20_normalizzatori_carry/README.md), [provenienza](20_normalizzatori_carry/PROVENANCE.json) | [Riepilogo](20_normalizzatori_carry/RESULTS.json), [rapporti e controlli](20_normalizzatori_carry/evidence/) |
| [21, costanti e parallelismo](21_costanti_pubbliche_parallelismo/README.md) | [Sorgenti](21_costanti_pubbliche_parallelismo/sources/) | [Guida](21_costanti_pubbliche_parallelismo/README.md), [provenienza](21_costanti_pubbliche_parallelismo/PROVENANCE.json) | [Riepilogo](21_costanti_pubbliche_parallelismo/RESULTS.json), [rapporti e controlli](21_costanti_pubbliche_parallelismo/evidence/) |
| [22, servizio composito](22_demo_composita/README.md) | [Runtime della campagna](22_demo_composita/runtime/) | [Guida](22_demo_composita/README.md), [provenienza](22_demo_composita/PROVENANCE.json) | [Riepilogo](22_demo_composita/RESULTS.json), [prove del servizio](22_demo_composita/evidence/) |
| [23, valutatore CKKS](23_ckks_ottimizzazioni/README.md) | [Runtime C++](23_ckks_ottimizzazioni/runtime/) | [Generatore sintetico](23_ckks_ottimizzazioni/generate_synthetic.py), [dipendenze](23_ckks_ottimizzazioni/DEPENDENCIES.json), [guida](23_ckks_ottimizzazioni/README.md) | [Riepilogo](23_ckks_ottimizzazioni/RESULTS.json), [coppie misurate](23_ckks_ottimizzazioni/PUBLIC_TIMING_PAIRS.csv), [rapporti](23_ckks_ottimizzazioni/evidence/) |
| [24, common-mask e BGV](24_frontiere_common_mask_bgv/README.md) | [Sorgenti e dipendenze](24_frontiere_common_mask_bgv/sources/) | [Guida](24_frontiere_common_mask_bgv/README.md), [provenienza](24_frontiere_common_mask_bgv/PROVENANCE.json) | [Riepilogo](24_frontiere_common_mask_bgv/RESULTS.json), [rapporti](24_frontiere_common_mask_bgv/evidence/) |
| [25, Tetris](25_tetris/README.md) | [Runtime](25_tetris/runtime/), [primo tentativo](25_tetris/failed-first/) | [Guida](25_tetris/README.md), [provenienza](25_tetris/PROVENANCE.json) | [Riepilogo](25_tetris/RESULTS.json), [rapporti e controlli](25_tetris/evidence/) |
| [26, torneo DAG](26_torneo_dag/README.md) | [Sorgenti](26_torneo_dag/sources/) | [Guida](26_torneo_dag/README.md), [provenienza](26_torneo_dag/PROVENANCE.json) | [Riepilogo](26_torneo_dag/RESULTS.json), [coppie misurate](26_torneo_dag/timing-pairs.csv), [rapporti](26_torneo_dag/evidence/) |

<a id="tentativi-a"></a>

## Tentativi A

Le sigle A seguono i singoli tentativi all’interno di queste campagne. Il
[catalogo A](../docs/risultati/catalogo-tentativi-a.md) collega ogni sigla
a proposta, esito, successore e materiali. La [guida dei sorgenti e risultati](attempts-a/README.md)
spiega come ricostruire le revisioni riusando i file condivisi; la
[lettura per filoni](../docs/risultati/tentativi-a.md) raccorda i passaggi
che attraversano più campagne.

<a id="confronto-comune-del-9-settembre"></a>
<a id="selettore"></a>

## Selettore, migrazione e grafici

| Campagna | Rapporto | Dati e programma |
|---|---|---|
| Diagnosi e prima correzione del selettore | [Diagnosi](../docs/selector-repair-20260920.md), [verifica](../docs/validazione/SELECTOR_REPAIR_VALIDATION.md) | [Benchmark conservati](../docs/validazione/SELECTOR_REPAIR_BENCHMARKS.json); revisioni identificate nei rapporti |
| Pack 4 e costo della correzione | [Pack 4](../docs/validazione/PACK4_VALIDATION.md), [costo diretto](../docs/selector-direct-cost-20260920.md) | [Dati e ricalcolo del costo](../docs/evidence/selector-direct-cost-20260920/README.md) |
| Progressione corretta e confronto CKKS/TFHE | [Metodo della progressione](../output/figures/progressione-fhe/selettori-corretti-20260920/LEGGIMI.md), [confronto distinto](../output/figures/ckks-tfhe/selettore-corretto-20260920/LEGGIMI.md) | CSV nelle rispettive cartelle; [generatore](../benchmark/figure_current.py), [comando di ricalcolo](../docs/riproducibilita.md#entrambe-le-figure-del-20-settembre) |
| Migrazione TFHE-rs 1.8.1, 22 settembre | [Rapporto](../docs/validazione/TFHE_181_MIGRATION.md) | [Campioni e riepilogo](../benchmark/tfhe-181-20260922/); programma e chiavi identificati nel rapporto |

<a id="ottobre"></a>

<a id="campagne-di-ottobre"></a>

## Servizio, riduzioni del costo e generalizzazione

Queste campagne proseguono dalla correzione del selettore e dalla migrazione
a TFHE-rs 1.8.1. I materiali in `benchmark/` collegano programmi, campioni
e analisi; i protocolli distinguono la riproduzione dei riepiloghi da una
nuova esecuzione con gli input e l’ambiente richiesti.

| Campagna | Rapporto | Materiale incluso |
|---|---|---|
| Biometria e preparazione UI, 2 ottobre | [Nuova galleria](../docs/validazione/BIOMETRIA_VGGFACE2_20261002.md), [UI](../docs/validazione/BIOMETRIA_UI_20261002.md) | Protocolli e risultati nei report; foto e modelli sono asset esterni |
| Confronto 1.7/1.8.1, 4 ottobre | [Metodo](../docs/validazione/TEMPI_181_20261004.md) | [Sorgenti, driver, ricetta degli input e risultati](../benchmark/tfhe-181-20261004/README.md) |
| Demo POST→SSE | [Metodo](../docs/validazione/DEMO_SSE_20261004.md) | [Sorgenti, driver, ricetta degli input e risultati](../benchmark/demo-sse-20261004/README.md) |
| Profilazione delle fasi | [Metodo](../docs/validazione/PROFILO_RUNTIME_20261004.md) | [Sorgenti, driver, ricetta degli input e risultati](../benchmark/core-profile-20261004/README.md) |
| Profilazione di un merge | [Metodo](../docs/validazione/PROFILO_MERGE_20261004.md) | [Sorgenti, driver, ricetta degli input e risultati](../benchmark/merge-profile-20261004/README.md) |
| Torneo DAG sul core corrente | [Risultato: corretto, più lento](../benchmark/tournament-dag-20261004/RESULT.md) | [Sorgenti, primo tentativo invalido e campagna corretta](../benchmark/tournament-dag-20261004/README.md); distinto da 26 |
| FCMA, codice generato | [Analisi del caller compilato](../benchmark/fcma-codegen-20261004/RESULT.md) | [Sorgenti, impostazioni e assembly](../benchmark/fcma-codegen-20261004/README.md) |
| FCMA, aritmetica e tempi | [Gate su operandi sintetici pubblici](../benchmark/fcma-public-gate-20261004/RESULT.md) | [Sorgenti, operandi, controlli e misure](../benchmark/fcma-public-gate-20261004/README.md); microbenchmark, non pipeline FHE |
| Buffer temporaneo | [Metodo](../docs/validazione/SCRATCH_BR_20261004.md) | [Crate, protocollo, record, CSV e review](../benchmark/br-scratch-cost-20261004/) |
| Comparatore compresso | [Risultato negativo](../docs/validazione/COMPARATORE_COMPRESSO_20261004.md) | [Crate, protocollo, record, CSV e review](../benchmark/comparator-encoding-20261004/) |
| Comparatore binario | [Prova del primitivo](../docs/validazione/COMPARATORE_BINARIO_20261004.md) | [Crate, protocollo, record, CSV e review](../benchmark/binary-comparator-20261004/) |
| Pipeline binaria e diagnosi | [Risultato e seguito](../docs/validazione/PIPELINE_BINARIA_20261004.md) | [Protocolli, registrazioni, CSV e analisi](../benchmark/binary-pipeline-20261004/) |
| Produttore in due blocchi da 6 bit | [Risultato negativo](../docs/validazione/ESTRAZIONE_DUE_BLOCCHI_20261004.md) | [Sorgente di componente, protocollo, record, CSV e review](../benchmark/base64-producer-20261004/) |
| raw 9, PFKS-ID, GLWE e CBS, 5 ottobre | [Esiti e decisioni](../docs/risultati/selettore-e-generalizzazione.md) | [raw9](../benchmark/raw9-20261005/README.md), [PFKS-ID](../benchmark/public-id-pfks-20261005/README.md); analisi GLWE/CBS nel rapporto |
| Georgia Tech, 5 ottobre | [Protocollo e risultato](../docs/risultati/selettore-e-generalizzazione.md#georgia-tech) | [Driver, ricetta e risultati aggregati](../benchmark/biometrics-gt-20261005/README.md); prova biometrica in chiaro |

## Dal circuito verificato al budget di errore

La [mappa del rumore](../docs/validazione/RUMORE_COMPOSTO.md) collega i
passaggi della pipeline ai budget ancora da giustificare. I
[rapporti di validazione](../docs/validazione/README.md) documentano i
controlli svolti; non forniscono una probabilità complessiva di errore
della baseline adottata nella demo.
