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

I numeri sono l'ordine delle prove, non versioni equivalenti dello stesso
programma. All'inizio il server restituiva **tutti gli score cifrati** e il
client sceglieva la persona; in seguito la scelta è entrata nel circuito.
La [narrazione continua](../docs/percorso-sperimentale-20260920.md) spiega
questo passaggio. Qui si può aprire la prova che risponde alla singola domanda.

| Passo | Cosa si è fatto | Perché si è proseguito |
|---|---|---|
| [00](00_hello_concrete.py)–[04](04_client_server.py) | Prime operazioni cifrate, calcolo dei punteggi e scambio client/server con Concrete. | Serviva distinguere la foto in chiaro sul client dai calcoli sulla richiesta cifrata. |
| [05](05_pca/README.md) | Un volto diventa un vettore PCA; il server calcola uno score cifrato per iscritto. | Il client vede tutti gli score; inoltre la PCA riconosce male i volti reali provati. |
| [06](06_argmin_soglia/README.md) | Il server calcola anche minimo e rifiuto sotto FHE. | L'uscita è ancora indice più sì/no; i confronti cifrati con Concrete costano molto. |
| [07](07_descrittori_locali/README.md) | Vettori LBP/HOG al posto della PCA, senza cambiare il calcolo base degli score. | Migliorano LFW, ma i benchmark più difficili chiedono un modello di volto migliore. |
| [08](08_cnn/README.md) | Una rete già addestrata produce il vettore sul client. | La qualità cresce; resta da rendere veloce la decisione cifrata sul server. |
| [09](09_gpu) | Prova GPU del circuito Concrete a riduzione sequenziale. | Sulla T4 e con questo carico la latenza resta elevata: si prova a cambiare struttura. |
| [10](10_argmin_struttura) | Torneo di confronti invece della catena sequenziale. | Le prove migliorano, ma restano nell'ordine delle decine di secondi. |
| [11](11_megaface) | Valutazione della ricerca con gallerie molto più grandi. | La qualità biometrica va misurata anche quando cresce il numero di iscritti. |
| [13](13_tfhe_rs_headtohead) | Primo confronto Concrete/TFHE-rs e scomposizione del tempo. | L'argmin Rust appariva rapido; gli score con l'API intera erano ancora costosi. I rapporti storici non isolano un guadagno appaiato della pipeline. |
| [14](14_pipeline_tfhe_rs) | Punteggi con primitive TFHE a basso livello e sviluppo del torneo exact 0/ID. | Da questa linea nascono le revisioni Axx e la funzione poi portata nel core Head/PFKS. |
| [15](15_ckks_confronto) | Alternativa CKKS per la decisione cifrata. | L'uscita approssimata e i parametri richiedono un confronto separato con TFHE. |
| [16](16_common_mask_poc/README.md) | Microbenchmark che condivide lavoro fra cifrati. | Misura primitive, non una pipeline di identificazione completa. |

Le [schede F0–F83](../docs/risultati/diario/README.md) conservano anche i
tentativi senza miglioramento e le correzioni successive. Una scheda F è
un'annotazione del diario: non coincide sempre con un singolo esperimento
numerato in questa tabella.

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
