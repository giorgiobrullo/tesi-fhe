# Percorso sperimentale e risultati correnti

Aggiornamento del 20 settembre 2026. Questa pagina presenta il percorso da
usare nella tesi e nell'email: contratto, sviluppo, confronto comune e
baseline selezionata. Si legge in ordine cronologico; i
[findings](../findings.md) sono invece il catalogo delle evidenze e conservano
gli identificatori F. I dati originali restano nei rispettivi archivi.

## Dal prototipo al servizio 0/ID

Il problema è cercare il primo minimo tra i punteggi cifrati e confrontare
soltanto quel vincitore con la sua soglia inclusiva. Il risultato è l'ID,
oppure zero. La galleria è pubblica al server; la query e la risposta sono
cifrate. La risposta TFHE contiene tre cifre LWE in base 15 e non restituisce
gli score. Le prove funzionali di questo contratto sono distinte dalla
validazione biometrica e dalla prova del rumore composto.

## Cinque tappe per raccontare la tesi

1. **Prototipi e definizione del problema.** Le prime revisioni Concrete/TFHE
   esplorano confronti e selezione cifrati. Le correzioni successive portano
   a fissare primo minimo, pareggi stabili, soglia del solo vincitore e uscita
   0/ID. Le prove iniziali conservano formati e taglie propri: non qualificano
   automaticamente il contratto finale. [F0–F83](risultati/storico.md).
2. **Un circuito exact 0/ID completo.** La successione A28–R3 affronta il costo
   del torneo e dell'uscita cifrata. I risultati dei circuiti completi diventano
   confrontabili quando input, contratto e dimensioni sono fissati. Il tratto
   N127/D512/T4 resta distinto dai prototipi N8/D64. La ricostruzione comune
   del 20 settembre è riportata sotto; non sostituisce le misure originali.
   [F84–F87](risultati/core-e-scaling.md) e [F93](risultati/campagna-comune.md).
3. **Head, CPU e composizione, nelle campagne del 4–9 settembre.** Head/PFKS,
   correzione della media, soglie generali, FFT fissa e configurazione CPU
   riducono il costo delle versioni complete. Normalizzatori condivisi,
   costanti pubbliche e parallelismo confluiscono nel servizio. Ogni guadagno
   mantiene il proprio riferimento; la curva non isola causalmente ogni
   componente. [F85–F87](risultati/core-e-scaling.md) e
   [F88–F90](risultati/normalizzatore-e-demo.md).
4. **Il guasto rende esplicito un obbligo trascurato.** La geometria stretta
   entra nella linea Head/PFKS il 6 settembre; il primo output ID75 invece
   di ID1 rintracciato nella linea con correzione della media è del 9 settembre.
   La diagnosi del 19 settembre localizza il selettore, mentre Head e ternari
   passano. La correzione B rigenera il controllo e allarga il supporto;
   prove finite e costo +13,17% sono documentati separatamente. La baseline
   pre-fix del 19 settembre passa lo stesso replay: non si attribuisce anche
   a essa un errore non osservato. [Diagnosi e correzione](selector-repair-20260920.md).
5. **Recupero di prestazioni e misura del costo residuo, il 20 settembre.**
   Pack4 mantiene il refresh e i margini, riduce i gruppi payload e misura
   −4,7438% rispetto alla correzione B. Segue una verifica in quattro fasi:
   ridondanze, guardia pubblica, un solo candidato di scheduling e confronto
   diretto. Il candidato non è adottato; la misura diretta finale osserva
   +6,8737456% rispetto all'originale. Questi esiti chiudono il piano delimitato,
   lasciando aperto il limite formale del circuito.
   [Costo diretto e limiti](selector-direct-cost-20260920.md).

## Quale versione compare in ciascun risultato

| Risultato | Versione usata | Aggiornamento del 20 settembre |
|---|---|---|
| Grafico della progressione | Dieci stadi storici ricostruiti | Primi sei circuiti invariati; Head M, generale, CPU e finale corretti; pack4 nel finale; tutti rimisurati |
| Grafico CKKS/TFHE | CKKS balanced-v3 e TFHE CPU del confronto originario | TFHE corretto senza anchor/pack4; entrambi gli schemi rimisurati |
| Baseline corrente della demo | Linea anchor del 19 settembre, corretta e con pack4 | Nuovo confronto pack4/B, regressione storica e servizio verificati |
| Costo residuo diretto | Originale pre-fix e baseline anchor/pack4 adottata | Tre famiglie B riusate; +6,8737456% sul core, senza la variante di scheduling |

Questi risultati hanno riferimenti distinti. Il +13,17% storico non viene
applicato ai punti dei grafici, e la mediana del loro finale non viene
presentata come latenza della demo corrente. Anche il costo diretto finale
rimane una misura separata, senza fattori applicati alle altre curve.

## Progressione ricostruita su ingressi comuni

Le dieci versioni 0/ID sono state ricompilate e rimisurate il 20 settembre su
cinque scene comuni N127/D512/T4, Apple M4 Max, 16 thread. I quattro stadi
interessati dalla geometria del selettore usano la correzione; il finale usa
anche pack4. Gli altri sei conservano il proprio circuito. È una ricostruzione
corretta della successione, non una riscrittura delle misure storiche.

| Versione | Mediana del calcolo cifrato (s) | Selettore corretto nella ricostruzione |
|---|---:|---|
| A28 | 7,787 | Non interessato |
| A29 | 7,049 | Non interessato |
| A33 | 5,960 | Non interessato |
| A38 | 5,084 | Non interessato |
| A66 | 4,400 | Non interessato |
| R3 | 3,190 | Non interessato |
| Head con correzione media | 2,373 | Sì |
| Head generale | 2,401 | Sì |
| FFT fissa e CGU1 | 2,406 | Sì |
| Composizione finale con pack4 | 1,821 | Sì |

Passano il gate separato di 50 uscite e tutte le 450 uscite della campagna:
300 misurate e 150 warmup, tre nuove famiglie per profilo. Input GLWE e uscite
LWE sono decifrati da un lettore indipendente. Ogni punto usa 30 misure;
i baffi rappresentano l'intervallo interquartile, non un intervallo di confidenza.
Il timer esclude preparazione delle chiavi, cifratura, decifratura e HTTP.
Carico esterno alto è segnalato in 300/300 misure, con contabilità
incerta in 164/300. Tutte le osservazioni sono mantenute.

I due prototipi N8/D64 rimangono nel pannello storico del 9 settembre, con
contratto e dimensioni diversi. Non si calcola un rapporto tra i pannelli.
La mediana del finale di questa curva (1,821 s) non è la
mediana della baseline anchor più recente: sono circuiti e campagne distinti.

## Baseline selezionata e costo della correzione

La baseline corrente aggiunge il refresh del controllo e conserva i margini
geometrici verificati. Il packing a quattro cifre riunisce score e cifre
ID/soglia non costanti, riducendo le operazioni senza restringere la finestra.
La campagna separata pack4/B misura una riduzione del 4,7438%, rapporto
geometrico appaiato 0,952562, intervallo bootstrap al 95% [0,948049; 0,957387]
condizionato alle tre famiglie. Le mediane aggregate sono 2,123362/2,010978 s.
Tutte le 432 chiamate, il replay storico e tre roundtrip di servizio passano.
Il carico esterno è presente; il rapporto non è una latenza universale.

La prima correzione B del selettore aveva misurato +13,1659% rispetto alla versione del
19 settembre. Questa percentuale e il nuovo -4,7438% hanno riferimenti e
campagne distinti: non si combinano come misura diretta del costo residuo.
Le finestre nominali e i successi osservati non dimostrano da soli una
probabilità globale di fallimento. Il [rapporto pack4](../PACK4_VALIDATION.md)
conserva questi limiti. La lettera B qui indica la correzione del selettore;
le varianti B della composizione storica e del controllo DAG sono distinte.

Il successivo [confronto diretto](selector-direct-cost-20260920.md) misura
**+6,8737456%** per pack4 rispetto all'originale, con intervallo bootstrap
al 95% **[+6,21%; +7,52%]** condizionato alle tre famiglie riusate e ai casi
osservati. La differenza mediana appaiata è **0,1207 s per query**. Sono 60
coppie primarie misurate; entrambe le versioni passano le **216 chiamate
complessive e le 648 LWE finali** verificate indipendentemente. Le mediane
marginali sono 1,701612/1,824226 s e appartengono a questa campagna.
Tutte le 144 chiamate misurate hanno un indicatore di carico esterno, 67 con
contabilità CPU parzialmente incerta; nessun campione è escluso. Il timer
del core esclude chiavi, cifratura, decifratura, serializzazione e HTTP.

I quattro approfondimenti sono conclusi. L'analisi non individua un refresh
duplicato. La guardia pubblica non qualifica nessuno dei 254 controlli
salvati esaminati, neppure assumendo errore precedente nullo: sono due
programmi sulla stessa capsula, non nuove famiglie. È un limite della
condizione sufficiente esaminata, non una prova d'impossibilità. Lo screening
della sovrapposizione refresh/PFKS conserva le uscite su 96 query, ma misura
+0,49% sui cinque scenari primari e non raggiunge il criterio di risparmio.
Usa una sola famiglia riusata, con carico esterno; il candidato non è adottato.
La quarta fase misura direttamente il costo riportato sopra. La baseline
resta pack4; la conclusione del piano non chiude gli obblighi formali.

## Confronto CKKS/TFHE rimisurato

La campagna separata conserva la costruzione CKKS qualificata e corregge
la versione TFHE CPU del confronto originale. Non sostituisce quest'ultima
con la baseline anchor/pack4. Sei scene: N64/N128, soglie allineate, generali
e miste. Passano 216/216 query, inclusi 54 warmup; l'audit indipendente TFHE
verifica tutte le 144 uscite e ricontrolla il gate di 30 query. Il verificatore
ha ricevuto una correzione documentata dopo le misure: rimuove un confronto
non valido tra durata monotona e intervallo UTC. L'audit originario fallito
resta conservato; dati, tempi, controlli crittografici e campioni sono invariati.

A N128 con soglia generale, le mediane dei tre blocchi sono **3,411 s
per CKKS e 2,604 s per TFHE**. Ogni blocco CKKS è la mediana di tre
query; il riferimento TFHE è la media delle mediane prima/dopo. I baffi
sono minimo e massimo dei tre blocchi, non intervalli di confidenza. Le
famiglie TFHE sono due, riusate in ordine 1/2/1; CKKS usa sei contesti nuovi.

CKKS restituisce uno scalare approssimato, arrotondato sul client; TFHE
restituisce tre cifre discrete. I casi corretti non equiparano leakage,
formato d'uscita o privacy. Il confronto non stabilisce un primato SOTA.

## Finding tecnico da conservare

La [nota tecnica sul selettore](selector-repair-20260920.md) conserva la
diagnosi e distingue prova di componente, torneo completo e nuove famiglie.
Il 6 settembre la linea Head/PFKS introduce packing a passo 41 e margine ±20
senza refresh del controllo. Il fallimento storico del 9 settembre è stato
riprodotto: indirizzo 341 fuori dall'intervallo 300...340, con Head e ternari corretti.
L'intervento diagnostico 341→340 ripristina ID1 e localizza la causa, ma non
è la correzione adottata. L'ultima baseline precedente passava la stessa
capsula con indirizzo 318: su quella versione il rischio era potenziale.

La lezione è verificare congiuntamente rumore del controllo, geometria delle
finestre e tutte le cifre trasportate. Una demo corretta non prova il margine
su chiavi future. La correzione generale rigenera il controllo; pack4 ne
conserva la geometria e richiede una nuova verifica FHE per il diverso rumore
dell'accumulatore. Diagnosi, prova geometrica, prove FHE, tempi e servizio
restano evidenze separate. Gli archivi conservano anche le prove fallite.

## Dati e figure

- [Progressione, figure e tabelle](../output/figures/progressione-fhe/selettori-corretti-20260920/LEGGIMI.md).
- [Confronto CKKS/TFHE, figure e metodo](../output/figures/ckks-tfhe/selettore-corretto-20260920/LEGGIMI.md).
