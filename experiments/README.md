# Esperimenti

I numeri identificano gruppi di lavoro, non un singolo run o una progressione
monotona di velocità. Le cartelle **14, 15 e 16 esistevano già**: vengono
conservate e la riorganizzazione prosegue da 17. Le campagne parallele sono
raggruppate per argomento; il numero non riscrive le date dei singoli test.

## Percorso storico conservato

| Esperimento | Contenuto |
|---|---|
| [00](00_hello_concrete.py)–[04](04_client_server.py) | Concrete, operazioni FHE, distanze, galleria e client/server |
| [05](05_pca/README.md) | PCA |
| [06](06_argmin_soglia/README.md) | Argmin e soglia |
| [07](07_descrittori_locali/README.md) | Descrittori locali |
| [08](08_cnn/README.md) | Embedding CNN e quantizzazione |
| [09](09_gpu) | Prime prove GPU |
| [10](10_argmin_struttura) | Struttura dell'argmin |
| [11](11_megaface) | Valutazione MegaFace |
| [13](13_tfhe_rs_headtohead) | Confronto TFHE-rs |
| [14](14_pipeline_tfhe_rs) | Pipeline exact-ID e ottimizzazioni storiche Axx |
| [15](15_ckks_confronto) | Circuito CKKS di confronto |
| [16](16_common_mask_poc/README.md) | Primo common-mask PoC |

Non è presente un esperimento 12 nell'albero esistente; la numerazione
storica non viene corretta creando un esperimento fittizio.

## Lavoro consolidato del 4–8 settembre 2026

| Esperimento | Domanda / esito | Materiale |
|---|---|---|
| [17 — Head/PFKS su TFHE-rs 1.7](17_head_pfks_tfhe17/README.md) | Primo core riutilizzabile, correzione media e servizio N127 | Sorgenti della baseline e controllo, risultati e provenienza |
| [18 — Scaling e soglie miste](18_scaling_soglie_miste/README.md) | Taglie variabili, tre cifre ID, soglia del vincitore | Quattro estensioni e controlli, risultati separati |
| [19 — Runtime CPU](19_runtime_cpu/README.md) | FFT fissa, 16 thread e CGU1; anche compiler/PGO/copie/cache negativi | Due runtime e configurazioni storiche |
| [20 — Normalizzatori carry](20_normalizzatori_carry/README.md) | Cifre derivate dal riporto, rumore osservato, parallelismo e composizione notturna | Varianti di componente, sweep e query |
| [21 — Costanti pubbliche e parallelismo](21_costanti_pubbliche_parallelismo/README.md) | Selettore/cifre pubbliche/G4; attraversamento PFKS negativo | Quattro prototipi e conferme distinte |
| **[22 — Demo composita selezionata](22_demo_composita/README.md)** | Integrazione migliore misurata, senza G4; confronto del servizio | **Core Rust, servizio, client immagini e UI** |
| [23 — Ottimizzazioni CKKS](23_ckks_ottimizzazioni/README.md) | Riduzioni condivise e preparazione rotazioni; confronto separato da TFHE | C++/OpenFHE, input sintetici e risultati |
| [24 — Common-mask e BGV](24_frontiere_common_mask_bgv/README.md) | Joint4 corretto ma più lento di R3; grafo BGV N8 ammesso | Estratti dei sorgenti storici e risultati; dipendenze da completare per una build autonoma |
| [25 — Tetris](25_tetris/README.md) | Consumatore corretto, produttore conversion-inclusive più lento | Runtime, primo tentativo fallito e riepilogo |
| [26 — Torneo DAG](26_torneo_dag/README.md) | Due screening negativi; tre politiche effettivamente esercitate | Candidati/controlli, coppie di tempi e limiti |

L'implementazione consigliata come punto di partenza per riuso è il
[core del pacchetto 22](22_demo_composita/runtime/core/src/lib.rs).
I sorgenti ripetuti nelle cartelle storiche sono snapshot dei confronti:
sostituirli tutti con l'ultima libreria cambierebbe il programma misurato.
Le utility [Python/Concrete](../core/README.md) restano al loro posto.

Ogni README esplicita se la cartella è una chiusura di sorgenti con dipendenze
risolte oppure un estratto d'archivio. Una copia verificata per hash non è una
nuova compilazione o una nuova misura. Per i dettagli leggere `RESULTS.json`
e il manifest di provenienza nella cartella. I grandi archivi originali
restano locali; i percorsi di origine permettono di ritrovarli e gli hash di
controllarne l'identità. Non è necessario portarli nella consultazione ordinaria.

[Fatti consolidati](../findings.md) e [domande ancora aperte](../OPEN_QUESTIONS.md)
hanno ruoli separati. Il diario precedente e i tentativi intermedi non duplicati
nei pacchetti restano nell'archivio locale. La [guida alla provenienza](../docs/riproducibilita.md)
spiega quali prove sono distribuite e quali riferimenti richiedono gli originali.
Nessun originale è stato spostato o eliminato.

## Campagna comune del 9 settembre

Il [grafico con metodo e dati](../output/figures/progressione-fhe/benchmark-comune-matplotlib-20260909/LEGGIMI.md)
confronta versioni recuperate in due sezioni: primi prototipi argmin N8/D64
e implementazioni 0/ID N127/D512/T4. Le nuove misure non sostituiscono i
confronti originali dei pacchetti e non si confrontano attraverso lo stacco.
Il rapporto conserva il precedente errore irrisolto di Head generale, anche
dopo i risultati corretti della nuova campagna. La figura e le tabelle
pubbliche non contengono l'intero archivio di cifrati, chiavi e replay.
