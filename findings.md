# Risultati sperimentali

I risultati seguono due filoni: riconoscimento sui dati quantizzati e costo
del confronto cifrato. Il [percorso sperimentale](docs/percorso-sperimentale-20260920.md)
ricostruisce lo sviluppo; le schede F raccolgono le prove e i relativi riferimenti.

## Risultati del 20 settembre

| Esperimento | Risultato | Riferimento |
|---|---|---|
| Progressione dei circuiti, N127/D512 | Mediane da 7,79 s a 1,82 s | [Dieci versioni rimisurate](output/figures/progressione-fhe/selettori-corretti-20260920/LEGGIMI.md) |
| Confronto CKKS/TFHE, N128 e soglia generale | Mediane dei blocchi: 3,41 s / 2,60 s | [Metodo e differenze fra gli output](output/figures/ckks-tfhe/selettore-corretto-20260920/LEGGIMI.md) |
| Selezione in gruppi fino a quattro cifre, rispetto alla prima correzione | −4,74% di tempo sui confronti primari | [Metodo e verifica](docs/validazione/PACK4_VALIDATION.md) |
| Baseline corretta rispetto all'originale del 19 settembre | +6,87%; differenza mediana appaiata 0,121 s | [Confronto diretto](docs/selector-direct-cost-20260920.md) |

Sono tempi del core su Apple M4 Max con 16 thread. I confronti usano versioni
e campioni diversi; il finale del grafico non coincide con il motore della
demo corrente. I rapporti appaiati non derivano dal rapporto delle mediane.
Durante le misure erano attivi anche altri processi sul computer. I tempi
descrivono quelle condizioni; non sappiamo quantificare quanto sarebbero
diversi su una macchina libera. Ogni rapporto documenta questa attività e
i limiti della sua osservazione.

La correzione risolve il meccanismo del guasto osservato nel selettore storico.
L'ultima ottimizzazione trasferisce insieme fino a quattro cifre che codificano
punteggio, ID e soglia, riducendo le operazioni necessarie. Nei sorgenti si
chiama `pack4`; mantiene la rigenerazione del controllo introdotta dal fix.
La [nota tecnica](docs/selector-repair-20260920.md) descrive la causa,
le prove e i tentativi successivi. Resta aperto il limite di probabilità di
fallimento del circuito completo.

## Risultati precedenti

Le schede seguenti riportano le misure delle rispettive versioni, fino al
9 settembre. F93 conserva la campagna precedente alla correzione; per la
progressione corretta usare il grafico sopra. Le lettere A/B sono etichette
locali a ciascun confronto, non nomi di versioni condivisi fra campagne.

| Argomento | Schede complete |
|---|---|
| Contratto, core, scaling e CPU (F84–F87) | [Core e scaling](docs/risultati/core-e-scaling.md) |
| Normalizzatore, componenti e demo (F88–F90) | [Composizione e servizio](docs/risultati/normalizzatore-e-demo.md) |
| Alternative (F91–F92) | [Tetris, DAG e altri filoni](docs/risultati/alternative.md) |
| Confronto comune precedente alla correzione (F93) | [Campagna del 9 settembre](docs/risultati/campagna-comune.md) |
| Prime revisioni (F0–F83) | [Sintesi storica](docs/risultati/storico.md) |

## F84 - Contratto exact 0/ID e implementazione selezionata

La demo del pacchetto 22 restituisce l'identità del primo minimo se il suo punteggio
non supera la soglia associata, altrimenti zero. Usa il core Head/PFKS `public_parallel` del
pacchetto 22, senza G4, e tre cifre LWE in base 15. La capacità rappresentativa
di 3374 ID non è una qualifica FHE a ogni taglia.

[Condizioni, risultati e fonti](docs/risultati/core-e-scaling.md#f84---contratto-exact-0id-e-implementazione-selezionata).

## F85 - Head/PFKS: core completo e primo servizio

Il primo core Head/PFKS M misura mediane M/H/R3 di 3,049/3,071/4,616 secondi
su una nuova famiglia e sei terne misurate. Il servizio N127 supera una prova
separata; formati e scale di questa revisione precedono la demo composita.

[Condizioni, risultati e fonti](docs/risultati/core-e-scaling.md#f85---headpfks-core-completo-e-primo-servizio).

## F86 - Taglie variabili e soglie generali o miste

Il confronto M/A126 su tre chiavi e 15 taglie comuni fino a N128 osserva
riduzioni geometriche appaiate del 25,60–50,97%. Il pilot a tre cifre fino a
N1024 e le prove sulle soglie generali hanno campioni e limiti distinti.

[Condizioni, risultati e fonti](docs/risultati/core-e-scaling.md#f86---taglie-variabili-e-soglie-generali-o-miste).

## F87 - FFT fissa e configurazione CPU

CGU1/16 thread/FFT fissa riduce il tempo del 18,37% rispetto a FFT fissa/8
su due famiglie di conferma. PGO e le altre opzioni non selezionate conservano
i propri esiti negativi; il carico esterno limita la generalizzazione.

[Condizioni, risultati e fonti](docs/risultati/core-e-scaling.md#f87---fft-fissa-e-configurazione-cpu).

## F88 - Normalizzatore condiviso: risparmio e rumore osservato

Carry-v2 verifica 49.152 estrazioni su tutto il dominio, quattro modalità e
tre chiavi. Il primo confronto completo osserva una riduzione del 12,39%:
è già incorporata nella composizione successiva. I limiti di rumore restano
condizionati ai vettori salvati.

[Condizioni, risultati e fonti](docs/risultati/normalizzatore-e-demo.md#f88---normalizzatore-condiviso-risparmio-e-rumore-osservato).

## F89 - Parallelismo, costanti pubbliche e confronti delle combinazioni

I confronti classici paralleli e alcuni componenti successivi migliorano i
rispettivi riferimenti. I guadagni hanno baseline separate; la selezione della
combinazione dipende da F90. L'attraversamento PFKS condiviso non supera lo screening.

[Condizioni, risultati e fonti](docs/risultati/normalizzatore-e-demo.md#f89---parallelismo-costanti-pubbliche-e-confronti-delle-combinazioni).

## F90 - Composizione selezionata e miglioramento della demo

La composizione `public_parallel` misurata in quella campagna riduce il tempo del 6,596842% rispetto
al proprio riferimento su 96 terne di conferma. Il servizio di quella revisione riduce separatamente
i tempi backend del 24,710555% e delle richieste immagini del 28,439223%.
Sono scene sintetiche; la cattura della telecamera è esclusa.

[Condizioni, risultati e fonti](docs/risultati/normalizzatore-e-demo.md#f90---composizione-selezionata-e-miglioramento-della-demo).

## F91 - Tetris e torneo DAG: esiti negativi circoscritti

Il produttore Tetris provato è il 66,401451% più lento includendo le
conversioni. Il primo torneo DAG e le successive politiche D/I/W non superano
i controlli di riferimento. Questi esiti circoscrivono le costruzioni provate.

[Condizioni, risultati e fonti](docs/risultati/alternative.md#f91---tetris-e-torneo-dag-esiti-negativi-circoscritti).

## F92 - CKKS, common-mask, BGV e GPU

CKKS osserva l'8,098% di riduzione nel proprio confronto. Joint4, BGV e GPU
hanno prove e limiti diversi: nessuno di questi risultati misura un ulteriore
guadagno della demo TFHE. La verifica CUDA completa resta aperta.

[Condizioni, risultati e fonti](docs/risultati/alternative.md#f92---ckks-common-mask-bgv-e-gpu).

## F93 - Nuova campagna comune e precedente errore di Head generale

Nel tratto exact N127/D512/T4, le mediane A28/finale sono 7,351781/1,622570
secondi; la riduzione geometrica appaiata è 77,8052%. Il tratto dei prototipi
misura un altro compito e non consente rapporti attraverso lo stacco.
Tutte le finestre misurate riportano segnalazioni di carico esterno.

Il fallimento storico ID75 anziché ID1 è riprodotto e diagnosticato il
19 settembre: indirizzo 341 fuori dalla finestra 300…340 del selettore,
con le 127 estrazioni Head corrette. L'intervento diagnostico su quel solo
controllo, 341→340, riporta il torneo a ID1. La baseline del 19 settembre
passa un replay separato con ID1 e indirizzo 318 nel medesimo nodo.
Questi risultati non stimano una frequenza di fallimento né qualificano
la nuova riparazione; il suo [registro](docs/validazione/SELECTOR_REPAIR_VALIDATION.md)
resta separato dai tempi storici sopra.

[Condizioni, risultati e fonti](docs/risultati/campagna-comune.md#f93---nuova-campagna-comune-e-precedente-errore-di-head-generale).

## F0–F83 - Risultati storici e correzioni consolidate

La tabella storica mantiene le correzioni successive: il comparatore diretto
vicino alla soglia è stato invalidato; le vecchie suite e i formati di risposta
appartengono alle revisioni che li hanno prodotti. Le misure iniziali non
qualificano automaticamente il core attuale.

[Condizioni, risultati e fonti](docs/risultati/storico.md#f0f83---risultati-storici-e-correzioni-consolidate).
