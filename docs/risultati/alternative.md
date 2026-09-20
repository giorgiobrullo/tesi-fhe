# Tetris, torneo DAG e filoni alternativi

[Indice dei risultati](../../findings.md) · [Repository](../../README.md)

Risultati al 9 settembre 2026. Le percentuali si riferiscono ai singoli
confronti e non si sommano. Le prove empiriche non stabiliscono un limite
alla probabilità di fallimento del circuito.

## F91 - Tetris e torneo DAG: esiti negativi circoscritti

Il produttore Tetris ibrido include sei circuit bootstrap freschi ed è
66,401451% più lento in 18 coppie, senza vittorie, su una famiglia e tre
scene. Passano 54 uscite complete del consumatore e 2091 controlli di fase
LWE, oltre ai controlli di componente. La misura comprende le conversioni
del produttore, ma non è una misura della query intera. Questa costruzione
è esclusa dalla demo; l'esito non dimostra l'impossibilità di altri produttori.

Il primo torneo senza attesa globale di livello è 3,060286% più lento
del core qualificato P in 48 terne, con 2/48 vittorie. La successiva diagnosi
prova nuove politiche in una campagna distinta: una nuova famiglia, cinque
scene e 50 gruppi appaiati di cinque versioni.

| Politica della diagnosi successiva | Aumento del tempo rispetto a P | Vittorie |
|---|---:|---:|
| D: accodare il padre pronto | 0,897554% | 17/50 |
| I: proseguire direttamente nel padre pronto | 1,691943% | 19/50 |
| W: limitare il parallelismo interno finché resta lavoro iniziale largo | 2,619876% | 13/50 |

Il nuovo controllo con barriera B è 0,010341% più lento di P. Tutti i
risultati aggregati per scena dei candidati/P sono sfavorevoli. Passano 560 uscite,
1680 fasi e 455 uguaglianze complete. I meccanismi sono effettivamente
esercitati: 1909 partenze anticipate per D/I/W nel gate, 2089 prosecuzioni I
e 103 soppressioni interne W. Tutte le 300 finestre di timing conservano
carico alto; in 220 l’attribuzione ai processi è parzialmente incerta.
Fra le 250 misurate, 177 hanno attribuzione incerta.
La copertura temporale campionata è completa in entrambe le campagne DAG.

Nessun candidato supera il criterio di selezione prefissato, quindi non
vengono generate le famiglie aggiuntive. La differenza fra i risultati delle
due campagne non permette di attribuire un guadagno a una singola modifica. I profili di prontezza e il rapporto CPU/tempo
trascorso non misurano core liberi né un limite al risparmio ottenibile.
Il fallimento iniziale di un controllo sull'ordine fra due orologi diversi,
la correzione verificata e il gate completo successivo sono preservati.

Fonti: [esperimento 25](../../experiments/25_tetris/README.md),
[esperimento 26](../../experiments/26_torneo_dag/README.md),
[riepilogo delle due campagne DAG](../../experiments/26_torneo_dag/RESULTS.json),
[coppie di tempi](../../experiments/26_torneo_dag/timing-pairs.csv) e
[limiti dell'interpretazione](../../experiments/26_torneo_dag/evidence/POST_SCREEN_INTERPRETATION.md).

## F92 - CKKS, common-mask, BGV e GPU

| Filone | Risultato osservato | Limite del confronto |
|---|---|---|
| CKKS: riduzioni condivise e preparazione delle rotazioni | 8,098% di riduzione, 18/18 coppie favorevoli su tre nuove chiavi; 66 risultati e 69 uguaglianze fra checkpoint e uscite | Il riferimento ha già la stessa cache pubblica. La preparazione dipendente dalla query è inclusa; nessuna misura della demo TFHE o incremento da sommarle. |
| Common-mask Joint4, N16 | Core completo corretto sulle quattro scene; 17,77% più veloce del precedente CM e 24,57% più lento del proprio controllo R3 | Pilot separato; nessuna estrapolazione N127 o promozione prestazionale. |
| BGV, anello più grande | Grafo completo N8/8/8/4, 210 stadi e tutti i 32.768 valori terminali corretti; capacità finale 575,184 bit | Una chiave e decifrazione diagnostica delle copie. La chiave serializzata di 3.150.947.064 byte non è RSS; i 20,6 minuti dell'azione non sono latenza di query. |
| GPU custom Head/PFKS | Prototipo con controlli preliminari CPU | Compilazione CUDA, correttezza FHE GPU e velocità comprensiva dei trasferimenti non osservate negli artefatti disponibili. |

Fonti: [esperimento 23](../../experiments/23_ckks_ottimizzazioni/README.md),
[esperimento 24](../../experiments/24_frontiere_common_mask_bgv/README.md),
[rapporto originale CKKS combinato](../../experiments/23_ckks_ottimizzazioni/evidence/ORIGINAL_COMBINED_RESULTS.md),
[riepilogo common-mask e BGV](../../experiments/24_frontiere_common_mask_bgv/RESULTS.json).
