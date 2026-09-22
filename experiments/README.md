# Esperimenti

Gli esperimenti esplorano il riconoscimento facciale con query cifrata:
embedding, calcolo dei punteggi, selezione del minimo e controllo della
soglia. Le cartelle sono raggruppate per domanda di ricerca.

Per una prima lettura, partire dall'[esempio con due candidati](../docs/come-funziona-il-confronto.md),
poi dal [percorso sperimentale](../docs/percorso-sperimentale-20260920.md):
il primo spiega il calcolo, il secondo collega le scelte ai risultati.
Le cartelle sotto permettono di approfondire ogni passaggio.

| Parte del problema | Dove si interviene | Esperimenti |
|---|---|---|
| Rappresentare il volto | Foto → vettore numerico → interi da cifrare | 05, 07, 08 |
| Decidere l'identità | Punteggi → minimo → soglia → risposta | 06, 13–18 |
| Ridurre il costo del circuito TFHE | Estrazione delle cifre, confronto e selezione dei dati | 17, 19–21 |
| Integrare il servizio | Foto, chiavi, richieste e risultato nell'applicazione | 22 |
| Valutare altre costruzioni | Confronti CKKS, dati con maschera comune, Tetris e pianificazione del torneo | 15–16, 23–26 |

Per eseguire la versione mantenuta seguire [compilazione e avvio](../BUILD_AND_RUN.md)
e il [runtime](../runtime/README.md). Il packing a quattro cifre raggruppa
i dati del vincitore; il refresh rigenera il controllo del selettore.
Il [rapporto pack4](../docs/validazione/PACK4_VALIDATION.md) e la
[prima correzione B](../docs/validazione/SELECTOR_REPAIR_VALIDATION.md)
documentano due passaggi distinti, con verifiche e misure proprie.

La [demo 22](22_demo_composita/README.md) conserva la versione delle campagne
storiche: i suoi tempi e conteggi non qualificano il selettore nuovo.
Ogni risultato va letto con il proprio programma, parametri e casi.
La [sintesi dei risultati](../findings.md) collega le conclusioni alle schede
complete; la [guida pratica](../docs/riproducibilita.md) raccoglie esecuzione
e verifica. I grafici rimisurati sono nel percorso sperimentale indicato sopra.

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

## Implementazioni e confronti del 4–8 settembre 2026

| Esperimento | Domanda / esito | Materiale |
|---|---|---|
| [17 - Head/PFKS su TFHE-rs 1.7](17_head_pfks_tfhe17/README.md) | Primo core riutilizzabile, correzione media e servizio N127 | Sorgenti della baseline e del controllo, risultati |
| [18 - Scaling e soglie miste](18_scaling_soglie_miste/README.md) | Taglie variabili, tre cifre ID, soglia del vincitore | Quattro estensioni e controlli, risultati separati |
| [19 - Runtime CPU](19_runtime_cpu/README.md) | FFT fissa, 16 thread e CGU1; anche compiler/PGO/copie/cache negativi | Due runtime e configurazioni storiche |
| [20 - Normalizzatori carry](20_normalizzatori_carry/README.md) | Cifre derivate dal riporto, rumore osservato, parallelismo e composizione notturna | Varianti di componente, sweep e query |
| [21 - Costanti pubbliche e parallelismo](21_costanti_pubbliche_parallelismo/README.md) | Selettore/cifre pubbliche/G4; attraversamento PFKS negativo | Quattro prototipi e conferme distinte |
| [22 - Demo composita storica](22_demo_composita/README.md) | Composizione selezionata in quel checkpoint, senza G4; confronto del servizio | Core Rust, servizio, client immagini e UI storici |
| [23 - Ottimizzazioni CKKS](23_ckks_ottimizzazioni/README.md) | Riduzioni condivise e preparazione rotazioni; confronto separato da TFHE | C++/OpenFHE, input sintetici e risultati |
| [24 - Common-mask e BGV](24_frontiere_common_mask_bgv/README.md) | Joint4 corretto ma più lento di R3; grafo BGV N8 ammesso | Estratti dei sorgenti storici e risultati; dipendenze da completare per una build autonoma |
| [25 - Tetris](25_tetris/README.md) | Consumatore corretto; produttore più lento, conversioni incluse | Runtime, primo tentativo fallito e riepilogo |
| [26 - Torneo DAG](26_torneo_dag/README.md) | Due screening negativi; tre politiche effettivamente esercitate | Candidati/controlli, coppie di tempi e limiti |

Il [core del pacchetto 22](22_demo_composita/runtime/core/src/lib.rs)
è il riferimento storico dei confronti; il [runtime mantenuto](../runtime/README.md)
contiene pack4, con verifiche proprie.
I sorgenti ripetuti nelle cartelle storiche sono snapshot dei confronti:
sostituirli tutti con l'ultima libreria cambierebbe il programma misurato.
I README annidati in `source/` e nei runtime storici descrivono API,
formati e comandi di quelle copie: leggerli dopo il README dell'esperimento.
I loro nomi e conteggi restano quelli della versione conservata.
Le utility [Python/Concrete](../core/README.md) restano al loro posto.

I README descrivono metodo, risultati, requisiti e comandi disponibili.
I file `RESULTS.json` riportano i dati dei confronti; le tabelle dei tempi
permettono di distinguere misure, riscaldamento e condizioni sperimentali.
L'esperimento 24 comprende sorgenti parziali con dipendenze non risolte;
la demo storica integrata è documentata nel 22; per avviare la versione
corrente seguire [BUILD_AND_RUN.md](../BUILD_AND_RUN.md).

I [risultati](../findings.md) raccolgono le conclusioni dei confronti.
Le [questioni aperte](../docs/limiti.md) descrivono le verifiche e le
possibili estensioni ancora necessarie.

## Confronto comune del 9 settembre

La [figura delle prestazioni](../output/figures/progressione-fhe/benchmark-comune-matplotlib-20260909/LEGGIMI.md)
confronta dodici versioni in due sezioni: primo minimo N8/D64 e 0/ID
N127/D512/T4. Il cambio di compito impedisce confronti di velocità attraverso
lo stacco. La croce su Head generale conserva un errore precedente riprodotto.
La diagnosi del 19 settembre lo attribuisce, in quella istanza, all'indirizzo
341 fuori dalla finestra 300…340 del selettore; le estrazioni Head sono corrette.
Il replay separato della baseline del 19 settembre restituisce ID1 con
indirizzo 318 nel nodo interessato. Il grafico resta una misura delle versioni
storiche e non include la nuova riparazione del selettore.

La progressione corretta e il confronto CKKS/TFHE sono stati rimisurati in
due campagne separate. Il [percorso sperimentale](../docs/percorso-sperimentale-20260920.md)
contiene figure, dati e verifiche del 20 settembre. I punti derivano dalle
nuove misure; non sono ottenuti applicando percentuali ai tempi precedenti.
