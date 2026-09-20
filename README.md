# Tesi-FHE: baseline pack4 del 20 settembre 2026

<a id="implementazione-selezionata"></a>

Questa consegna locale contiene la baseline **pack4**, adottata dopo verifiche
di correttezza, confronto appaiato, regressione storica e collaudo del servizio.
Il [rapporto pack4](PACK4_VALIDATION.md) raccoglie risultati e limiti;
[BUILD_AND_RUN.md](BUILD_AND_RUN.md) descrive compilazione e avvio.
Il runtime selezionato e congelato è [runtime/](runtime/README.md).

Per seguire la tesi in ordine, partire dal
[percorso sperimentale](docs/percorso-sperimentale-20260920.md): prototipi,
contratto exact 0/ID, ottimizzazioni, diagnosi e correzione del selettore.
I [findings](findings.md) sono il catalogo dei risultati, con gli identificatori
storici F; la [nota tecnica](docs/selector-repair-20260920.md) approfondisce
il guasto e i limiti della correzione.

<a id="modello-di-fiducia"></a>

Il progetto studia identificazione facciale mediante query cifrata. Il
terminale fidato acquisisce, trasforma e cifra il probe; il server conosce
galleria e soglie ed esegue il confronto cifrato. Il contratto intero è:

```text
k = primo argmin_i (||g_i||² - 2 <g_i,q>)
output = k + 1, se score_k <= T_k
         0, altrimenti
```

I pareggi favoriscono il primo indice e conta la soglia del vincitore. La
risposta contiene tre cifre LWE in base 15, senza restituire gli score.
La rappresentazione ammette fino a 3374 identità, coordinate in `[-3,3]`,
norma quadrata del probe al massimo 1024 e un intervallo pubblico degli score
di al massimo 4096 interi. La capacità non è una qualifica FHE a ogni taglia;
il server non prova che un ciphertext arbitrario rispetti i vincoli del terminale.

Pack4 mantiene il refresh 4/12 e la finestra PFKS di raggio 127 della prima
correzione B del selettore, raggruppando fino a quattro cifre dello score
e di ID/soglia.
Conserva anchor, specializzazioni pubbliche e i margini condizionali ±63/±127.
Usa TFHE-rs 1.7.0, 16 thread, FFT fissa e modalità `public_parallel`; G4 è
rifiutato. La PFKS interna B è compatibile, mentre l'envelope del servizio
richiede la nuova identità di circuito. Per le chiavi seguire la
[guida della demo](demo/dual_view/README.md), senza riutilizzare implicitamente
quelle di una precedente consegna.

Tre famiglie nuove, 90 coppie di correttezza, 18 di riscaldamento e 108
misurate danno 432 risposte attese, comprese le scorciatoie pubbliche. L'audit
indipendente verifica 1.296 LWE finali. Tre roundtrip CLI/HTTP danno 1/0/0;
il vecchio envelope W287 viene rifiutato senza modificare lo stato.

Sulle 90 coppie primarie, il rapporto **pack4/B è 0,952561993**, ossia
**−4,7438% di tempo**, con intervallo bootstrap95%
**[0,948049442; 0,957387164]**, condizionato alle tre famiglie osservate.
Le mediane aggregate sono 2,123361813 s per B e 2,010978417 s per pack4;
il rapporto appaiato non è il rapporto delle mediane. Qui B indica la prima
correzione del selettore, non le varianti B di altre campagne. Tutte le durate
restano incluse, con carico esterno osservato e finestre di attribuzione incerta.
Il timer esclude chiavi, cifratura, decifratura, serializzazione e HTTP.

Il [rapporto storico della correzione B](SELECTOR_REPAIR_VALIDATION.md)
documenta il precedente +13,17% rispetto alla versione pre-fix. Sono campagne
distinte: non si combinano le percentuali per ottenere un confronto diretto
pack4/pre-fix.

Il successivo [confronto diretto](docs/selector-direct-cost-20260920.md)
misura **+6,8737456%** per pack4 rispetto all'originale pre-fix, con intervallo
bootstrap al 95% **[+6,21%; +7,52%]**, condizionato alle tre famiglie riusate
e ai casi osservati. La differenza mediana appaiata è **0,1207 s per query**.
Entrambe le versioni passano: **216 chiamate complessive e 648 LWE finali**
verificate indipendentemente. Sono 60 coppie primarie misurate; carico esterno
presente, nessun campione escluso. Il dato riguarda il core, non l'intera demo.

I quattro approfondimenti sul costo sono conclusi. L'analisi delle ridondanze
non ha individuato un refresh duplicato; la guardia pubblica esaminata non
ha qualificato casi in cui ometterlo. La sovrapposizione di refresh e PFKS
ha superato il replay, ma non il criterio temporale, e non è adottata.
La quarta fase è la misura diretta appena riportata. Questi esiti non sono
una prova formale del circuito composto.

I [risultati precedenti](findings.md) e gli
[esperimenti 17–26](experiments/README.md) conservano le rispettive versioni.
Le due rimisurazioni del 20 settembre sono concluse: progressione con
mediane A28/finale 7,787/1,821 s (N127/D512/T4), gate 50/50 e campagna 450/450;
CKKS/TFHE 216/216, con mediane di blocco 3,411/2,604 s a N128/general.
Il finale ricostruito e la baseline anchor/pack4 sono circuiti distinti.
[Percorso, nuove figure e metodo](docs/percorso-sperimentale-20260920.md).

La [cronologia](docs/selector-repair/INTRODUCTION_HISTORY.md) distingue il
guasto storico ID75 dal replay della baseline pre-fix che restituisce ID1.
Le prove finite non forniscono una probabilità generale di fallimento,
circuit privacy o accuratezza biometrica. Le [questioni aperte](OPEN_QUESTIONS.md)
conservano questi obblighi; la [rassegna](letteratura.md) non attribuisce a
questa revisione completezza bibliografica o un primato SOTA.
