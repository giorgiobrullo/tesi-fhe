# Campagna comune storica del 9 settembre

La curva corrente è la [ricostruzione del 20 settembre](../percorso-sperimentale-20260920.md),
con selettori corretti e nuove misure. I paragrafi seguenti conservano
il risultato storico e non descrivono il nuovo circuito.

[Indice dei risultati](../../findings.md) · [Repository](../../README.md)

Risultati al 9 settembre 2026. Le percentuali si riferiscono ai singoli
confronti e non si sommano. Le prove empiriche non stabiliscono un limite
alla probabilità di fallimento del circuito.

## F93 - Nuova campagna comune e precedente errore di Head generale

La campagna del 9 settembre rimisura i sorgenti recuperati in due sezioni:
Concrete e TFHE iniziale su punteggi/primo argmin N8/D64; dieci versioni
destinate a exact 0/ID su N127/D512 e soglia uniforme inclusiva T4.
Lo stacco cambia contratto e dimensioni: non si calcola un miglioramento
fra i due lati. A28 è il primo sorgente exact recuperato e rimisurato;
i precedenti tempi A23/A25 non sono inseriti nella nuova curva.

I prototipi producono 54 risultati corretti, di cui 36 misurati e 18 warmup;
la sezione exact produce 450 risultati corretti, di cui 300 misurati e 150
warmup. Ogni profilo nativo usa tre nuove famiglie. Le mediane
Concrete/TFHE iniziale sono 264,797785/49,767460 secondi, con riduzione
geometrica appaiata 81,2735% e 18/18 coppie favorevoli. Le mediane A28/finale
sono 7,351781/1,622570 secondi, con riduzione appaiata 77,8052% e 30/30 coppie
favorevoli. I warmup non entrano nelle mediane; questi estimatori non sono
rapporti delle mediane e non si sommano ai risultati precedenti.

Aggiornamento del 19 settembre: la diagnosi della capsula storica localizza
il primo errore nel selettore PFKS, con indirizzo 341 fuori dalla finestra
300…340. Le estrazioni Head risultano corrette in quella capsula. Il replay
della baseline più recente restituisce invece ID1 e indirizzo 318 nello
stesso nodo. La correzione e le sue nuove misure sono trattate nel
[rapporto separato](../../SELECTOR_REPAIR_VALIDATION.md); i dati di questa
campagna restano quelli delle versioni storiche.

Un tentativo precedente aveva prodotto un errore: fra 269 risultati, 268 erano
corretti e Head generale restituiva ID75 invece di ID1 nel caso
`tie_first_last`. Il replay di chiave, input e binario invariati riproduce
gli stessi ciphertext errati; è la ripetizione dello stesso errore, non
un campione indipendente aggiuntivo. La causa non era risolta al momento della campagna. Questi tempi
non entrano nella nuova curva; i nuovi 45/45 risultati corretti di Head
generale non ne spiegano la causa. I confronti che coinvolgono questo
punto restano descrittivi e non qualificano un miglioramento exact.

La figura usa tempo logaritmico e intervalli interquartili Type 7, non
intervalli di confidenza. Tutti i bracci exact hanno 16 thread; il punto
FFT + CGU1 non introduce quel parallelismo e non ripete il confronto 8/16
thread di F87. I profili conservano librerie, scale e parametri nativi:
l'accostamento non isola causalmente una sola modifica né attesta garanzie
crittografiche identiche. Il timer misura il calcolo cifrato completo,
escludendo chiavi, cifratura, decifratura, serializzazione e interfaccia web.

Tutte le 336 finestre misurate segnalano carico esterno alto e 232 anche
contabilità incerta; nessuna osservazione pianificata viene rimossa.
La copertura campionata non dimostra isolamento continuo. I replay
indipendenti degli input e delle fasi exact e le osservazioni native dei
prototipi restano evidenze distinte; nessuna costituisce una probabilità
formale di fallimento dell'intero circuito o una nuova misura biometrica.

Riferimenti: [figura, metodo e tabelle](../../output/figures/progressione-fhe/benchmark-comune-matplotlib-20260909/LEGGIMI.md).
