# Findings — risultati consolidati

Aggiornamento: 9 settembre 2026. Questo documento raccoglie i risultati con
il loro ambito di validità. Il diario F0–F83 completo è conservato senza
modifiche nell'archivio locale, insieme alla sua provenienza; la sintesi
corretta è riportata in fondo. Le correzioni successive prevalgono sulle
interpretazioni storiche. Le questioni irrisolte sono in
[OPEN_QUESTIONS.md](OPEN_QUESTIONS.md); il riepilogo pubblico è in
[RESEARCH_STATE.md](RESEARCH_STATE.md). La [guida alla provenienza](docs/riproducibilita.md)
distingue i riepiloghi distribuiti dalle verifiche integrali locali.

Un modello statico, un programma compilato, una prova FHE con rumore, un
confronto dei tempi e una verifica del servizio sono evidenze diverse.
I conteggi di operazioni non sono tempi; i campioni corretti non sono una
probabilità globale di fallimento. Le riduzioni di campagne diverse non si
sommano. Le chiavi, i casi, il carico e gli estimatori indicati qui delimitano
ciascun risultato.

## F84 — Contratto exact 0/ID e implementazione selezionata

Per i punteggi interi ammessi, il server sceglie il **primo minimo** in ordine
di identità e verifica la **soglia inclusiva del vincitore**: per il vincitore
`j` (identità numerate da 1 a N) restituisce `j` se `s_j ≤ T_j`, altrimenti `0`. Non cerca un altro candidato
con una soglia più favorevole. La decisione e la selezione
avvengono sui cifrati; galleria e soglie sono pubbliche nel modello attuale.

La sorgente selezionata usa TFHE-rs 1.7, Head con correzione media, PFKS
`direct-window`, tre cifre cifrate in base 15 e gruppi di payload adattati al
modo uniforme/misto e ai tagli pubblici. La demo composita
sceglie `public_parallel`, senza G4: normalizzatore condiviso, confronti
classici e selettore paralleli, trasporto delle sole cifre ID necessarie,
selezione finale del solo ID e specializzazione delle costanti pubbliche.
Eredita FFT Dif4 fissa, 16 thread e build opt3/CGU1 senza native, LTO o PGO.
Il client immagini usa il solo rilevatore necessario all'allineamento,
conservando embedding, fusione e quantizzazione nei casi verificati.

La rappresentazione ammette fino a **3374 identità**, subordinatamente anche
ai controlli sul dominio dei punteggi. Questo limite non è una qualifica FHE
a ogni taglia: l'estensione generale precedente ha casi noisy fino a 1024 e
casi di servizio fino a 225; le prove delle revisioni successive hanno le
proprie taglie. Le suite di versioni precedenti non qualificano automaticamente
la sorgente composita.

Fonti pubblicate: [esperimento 22](experiments/22_demo_composita/README.md),
[riepilogo dell'integrazione](experiments/22_demo_composita/RESULTS.json),
[risultati dell'estensione generale](experiments/18_scaling_soglie_miste/RESULTS.json).

## F85 — Head/PFKS: core completo e primo servizio

Il confronto finale M/H/R3 del 6 settembre usa una nuova famiglia di chiavi,
otto input, due terne di riscaldamento escluse e sei terne misurate con tutti
gli ordini. Le mediane sono **3,048836 / 3,071472 / 4,615544 secondi**.
La mediana delle riduzioni entro coppia per M è **0,7963% rispetto a H** e
**34,0848% rispetto a R3**; tutte le sei coppie favoriscono M. Passano 31
uscite complete e i controlli di uguaglianza e delle fasi. Split, base e
correzione media cambiano insieme: il contributo dei 127 KS eliminati non è
isolato. Mantenere distinto questo estimatore dalle riduzioni geometriche
usate nelle campagne successive.

Il primo servizio riutilizzabile N127 passa separatamente **15 uscite e 39
rifiuti attesi**, con sei nuove cifrature della query sotto una nuova famiglia.
M usa il profilo nativo full51/low60; i controlli full52 richiedono l'adattamento
esplicito documentato. Il confronto M/H/R3 usa per R3 parole full51 moltiplicate
per due: non è un confronto con input nativi full52 del servizio. Questa prima
versione restituisce due cifre base 15 e conserva il percorso precedente alle
altre taglie; l'estensione a tre cifre è successiva.

Fonti pubblicate: [esperimento 17](experiments/17_head_pfks_tfhe17/README.md) e
[riepilogo dei risultati originali](experiments/17_head_pfks_tfhe17/RESULTS.json).
La revisione indipendente completa resta locale in
`docs/research-state/2026-09-06/wrap-up/finalist-result-review.md`;
il riepilogo distribuito non ne sostituisce il replay.

## F86 — Taglie variabili e soglie generali o miste

La campagna a due cifre misura M a 17 taglie da 1 a 224. A 15 taglie condivise
fino a 128, il confronto con A126 invariato su tre nuove chiavi dà riduzioni
geometriche appaiate del **25,60–50,97%**. A N127 le mediane M/A126 sono
3,031/6,115 secondi. La campagna e lo smoke preliminare passano 1272 uscite
complete e 12 uguaglianze seriale/parallelo; R3 è un controllo separato.

Il pilot distinto M3/A126_3 adatta esplicitamente anche il controllo a tre
cifre: una nuova chiave, cinque taglie 224/225/256/512/1024, due warmup esclusi
e quattro coppie misurate per taglia. Passano 60 uscite; **20/20 coppie**
favoriscono M3, con riduzioni del **50,45–52,44%**. A N1024 le mediane sono
23,451/49,062 secondi. Non è disponibile un intervallo fra più chiavi.

La correttezza con soglia uniforme generale, soglia del vincitore diversa
per identità e ID più larghi ha controlli separati su tre chiavi. Alcuni casi
con soglie estreme usano scorciatoie pubbliche e non sono valutazioni noisy
non banali. Il servizio generale passa 18 uscite e 44 rifiuti specifici;
le successive prove fotografiche sono sintetiche. Lo scaling dei tempi non
misura il vantaggio su ogni configurazione di soglie né la latenza web.

Fonti pubblicate: [esperimento 18](experiments/18_scaling_soglie_miste/README.md)
e [riepilogo delle campagne e dei limiti](experiments/18_scaling_soglie_miste/RESULTS.json).
Il resoconto esteso resta locale in `docs/personal/fast-core-scaling-2026-09-06.md`.

## F87 — FFT fissa e configurazione CPU

Su due nuove famiglie di conferma, **CGU1/16 thread/FFT fissa** riduce il tempo
del **18,37%** rispetto al riferimento FFT fissa/8 thread. Passano 450 uscite
complete. L'intervallo al 95% del rapporto dei tempi, costruito sulle due medie
per chiave, è 0,6768–0,9846: le 48 coppie misurate non sono 48 chiavi
indipendenti. Il confronto diretto con il riferimento originario a FFT
adattiva dà 16,63% e comprende anche la diversa politica numerica.

CGU1 preso da solo e native non confermano un beneficio. ThinLTO, FatLTO,
le combinazioni native/LTO, la rimozione di copie PFKS e la cache LUT sono
state provate senza un vantaggio selezionato. PGO, addestrato e verificato
separatamente, è **1,53% più lento** su una chiave nuova e 24 coppie, con
10 vittorie. La configurazione scelta resta senza queste opzioni.

La FFT fissa è installata prima di creare o caricare le chiavi Fourier e
permette i controlli di identità dei cifrati. Le vecchie differenze fra
processi sono compatibili con la scelta adattiva del piano; senza i piani
storici registrati non è una causa dimostrata per ogni differenza. Tutte le
coppie finali conservano segnalazioni di carico esterno e attribuzione del carico parzialmente incerta.
Sedici thread software non dimostrano affinità a specifici core fisici.

Fonti pubblicate: [esperimento 19](experiments/19_runtime_cpu/README.md) e
[riepilogo dei confronti CPU](experiments/19_runtime_cpu/RESULTS.json).
Il resoconto esteso resta locale in `docs/personal/ottimizzazioni-complete-2026-09-07.md`.

## F88 — Normalizzatore condiviso: risparmio e rumore osservato

La variante carry-v2 deriva anche una cifra bassa dalla rotazione che produce
il riporto, trasformando linearmente l'intero ciphertext. Il controllo esteso
copre tutti i **4096 input, quattro modalità e tre chiavi: 49.152 estrazioni**,
oltre a 384 selezioni successive. Sono verificate 592.128 fasi LWE e oltre
100 milioni di coefficienti GLWE. L'errore massimo delle cifre derivate usa
il 23,28% e l'11,74% del margine; i limiti conservativi condizionati ai vettori
salvati arrivano al 67,75% e al 31,74%. Non sono code di probabilità per nuove
chiavi o per il circuito completo.

Il primo confronto completo dà **12,39%** su una famiglia e 24 coppie misurate,
tutte favorevoli. La successiva composizione riusa esattamente questo
normalizzatore: quel guadagno è già incorporato. Le mappe fuse dello stesso
normalizzatore passano 130 uscite e 390 fasi, ma sono circa **0,14% più lente**,
con 9/24 coppie favorevoli; nessun risparmio dimostrato per quella variante.
Il primo controllo troppo restrittivo di una rappresentazione equivalente e
la sua correzione restano conservati.

Fonti pubblicate: [esperimento 20](experiments/20_normalizzatori_carry/README.md),
[riepilogo dei risultati](experiments/20_normalizzatori_carry/RESULTS.json),
[mappe di errore](experiments/20_normalizzatori_carry/evidence/NORMALIZER_ERROR_MAPS.md).

## F89 — Parallelismo, costanti pubbliche e confronti delle combinazioni

La campagna notturna conferma i **confronti classici paralleli: 6,51% su due
nuove chiavi, 56/56 coppie favorevoli**. Nel confronto diretto G4 non aggiunge
un vantaggio al classico in quelle condizioni. La prima combinazione di
normalizzatore, confronto parallelo e soglie pubbliche dà **19,24% nella
seconda famiglia**, 28/28 coppie favorevoli, mediane 2,324/1,820 secondi.
Il primo blocco, distinto dalla conferma, aveva dato 20,82%. Questi riferimenti
sperimentali avevano già entrambi i tagli sulle cifre ID; le percentuali non
misurano l'effetto di quei tagli rispetto alla demo precedente.

La conferma del 19,24% è geometrica. Il diverso estimatore mediano dà 18,37%,
con intervallo di ricampionamento 95% 17,81–19,00%, condizionato ai casi e alle
chiavi provate. Tale intervallo non è un intervallo per il 19,24% geometrico
né per tutte le chiavi future. Fra qualifica e timing le due famiglie della
combinazione passano 672 uscite e 2016 fasi terminali.

La successiva campagna diurna verifica componenti ulteriori contro i propri
riferimenti, già dotati del normalizzatore, parallelismo classico, soglie
pubbliche e tagli ID:

| Variante | Riduzione nelle due famiglie di conferma, screening escluso | Coppie favorevoli |
|---|---:|---:|
| Parallelismo interno del selettore | 3,642326% | 44/56 |
| Propagazione di cifre/costanti pubbliche | 4,087594% | 46/56 |
| Selezione G4 dinamica | 2,323432% | 45/56 |
| Attraversamento condiviso delle chiavi PFKS | Screening 0,991443% più lento; nessuna famiglia aggiuntiva | 11/28 nello screening |

Le quattro prove diurne passano **1716 uscite, 5148 fasi terminali e 796
uguaglianze complete**. Sono controlli correlati, non altrettanti campioni
indipendenti. Le 840 finestre di timing conservano carico alto, 786 anche
attribuzione del carico parzialmente incerta. I guadagni dei tre componenti hanno riferimenti separati;
la selezione finale richiede il confronto della combinazione in F90.

Fonti pubblicate: [esperimento 21](experiments/21_costanti_pubbliche_parallelismo/README.md),
[composizione notturna](experiments/20_normalizzatori_carry/evidence/night-composition.json),
[conferma classica](experiments/20_normalizzatori_carry/evidence/classic-confirmation.json),
[riepilogo della campagna diurna](experiments/21_costanti_pubbliche_parallelismo/RESULTS.json).

## F90 — Composizione qualificata e miglioramento della demo

Il confronto di composizione su **96 terne di conferma e due nuove famiglie**
seleziona B, `public_parallel`: **6,596842%** rispetto al riferimento A della
stessa campagna. Aggiungere G4 rende C **0,699159% più lento di B** e richiede
**296.404.088 byte di chiavi serializzate aggiuntive**. La demo qualificata
usa B senza G4. Questo risultato sostituisce l'antica voce «da integrare»;
non cancella i guadagni G4 osservati contro riferimenti differenti.

Il confronto diretto fra i servizi precedente e nuovo include una prima
famiglia e una distinta conferma, fissate prima della misura iniziale:

| Misura HTTP appaiata | Conferma, riduzione geometrica | Coppie favorevoli | Prima famiglia, separata |
|---|---:|---:|---:|
| Backend, otto scene N128/129 | 24,710555% | 32/32 | 25,295668% |
| Richiesta completa con immagini, due scene N129/T273 | 28,439223% | 12/12 | 27,406907% |

Le mediane delle richieste con immagini nella conferma sono **2,819970 e
2,011201 secondi**; quelle backend 2,5103 e 1,8668 secondi. Passano **288
uscite complete e 864 fasi terminali**, oltre a quattro controlli vuoti.
Le scene sono sintetiche; la cattura della telecamera è esclusa. Tutte le
288 finestre conservano carico alto; in 237 l’attribuzione ai processi è
parzialmente incerta. La copertura campionata è completa e non vi sono rimozioni. Non si inferiscono accuratezza biometrica, latenza di una galleria
personale, isolamento continuo o una probabilità formale di fallimento.
Backend, immagini e componenti sono misure distinte: i relativi vantaggi
non sono incrementi da sommare.

Fonti pubblicate: [esperimento 22](experiments/22_demo_composita/README.md),
[riepilogo della selezione](experiments/22_demo_composita/RESULTS.json) e
[rapporto originale del confronto HTTP](experiments/22_demo_composita/evidence/ORIGINAL_SERVICE_RESULTS.md).

## F91 — Tetris e torneo DAG: esiti negativi circoscritti

Il produttore Tetris ibrido include sei circuit bootstrap freschi ed è
**66,401451% più lento** in 18 coppie, senza vittorie, su una famiglia e tre
scene. Passano 54 uscite complete del consumatore e 2091 controlli di fase
LWE, oltre ai controlli di componente. La misura comprende le conversioni
del produttore, ma non è una misura della query intera. Questa costruzione
è esclusa dalla demo; l'esito non dimostra l'impossibilità di altri produttori.

Il primo torneo senza attesa globale di livello è **3,060286% più lento**
del core qualificato P in 48 terne, con 2/48 vittorie. La successiva diagnosi
prova nuove politiche in una campagna distinta: una nuova famiglia, cinque
scene e 50 gruppi appaiati di cinque versioni.

| Politica della diagnosi successiva | Aumento del tempo rispetto a P | Vittorie |
|---|---:|---:|
| D: accodare il padre pronto | 0,897554% | 17/50 |
| I: proseguire direttamente nel padre pronto | 1,691943% | 19/50 |
| W: limitare il parallelismo interno finché resta lavoro iniziale largo | 2,619876% | 13/50 |

Il nuovo controllo con barriera B è 0,010341% più lento di P. Tutte le
aggregate per scena dei candidati/P sono sfavorevoli. Passano **560 uscite,
1680 fasi e 455 uguaglianze complete**. I meccanismi sono effettivamente
esercitati: 1909 partenze anticipate per D/I/W nel gate, 2089 prosecuzioni I
e 103 soppressioni interne W. Tutte le 300 finestre di timing conservano
carico alto; in 220 l’attribuzione ai processi è parzialmente incerta.
Fra le 250 misurate, 177 hanno attribuzione incerta.
La copertura temporale campionata è completa in entrambe le campagne DAG.

Nessun candidato supera la selezione prefissata; le ulteriori famiglie non
sono generate. Le due campagne non sono sottraibili per attribuire un
guadagno a una modifica. I profili di prontezza e il rapporto CPU/tempo
trascorso non misurano core liberi né un limite al risparmio ottenibile.
Il fallimento iniziale di un controllo sull'ordine fra due orologi diversi,
la correzione verificata e il gate completo successivo sono preservati.

Fonti: [esperimento 25](experiments/25_tetris/README.md),
[esperimento 26](experiments/26_torneo_dag/README.md),
[riepilogo delle due campagne DAG](experiments/26_torneo_dag/RESULTS.json),
[coppie di tempi](experiments/26_torneo_dag/timing-pairs.csv) e
[limiti dell'interpretazione](experiments/26_torneo_dag/evidence/POST_SCREEN_INTERPRETATION.md).

## F92 — CKKS, common-mask, BGV e GPU restano filoni distinti

| Filone | Risultato osservato | Limite del confronto |
|---|---|---|
| CKKS: riduzioni condivise e preparazione delle rotazioni | 8,098% di riduzione, 18/18 coppie favorevoli su tre nuove chiavi; 66 risultati e 69 uguaglianze fra checkpoint e uscite | Il riferimento ha già la stessa cache pubblica. La preparazione dipendente dalla query è inclusa; nessuna misura della demo TFHE o incremento da sommarle. |
| Common-mask Joint4, N16 | Core completo corretto sulle quattro scene; 17,77% più veloce del precedente CM e 24,57% più lento del proprio controllo R3 | Pilot separato; nessuna estrapolazione N127 o promozione prestazionale. |
| BGV, anello più grande | Grafo completo N8/8/8/4, 210 stadi e tutti i 32.768 valori terminali corretti; capacità finale 575,184 bit | Una chiave e decifrazione diagnostica delle copie. La chiave serializzata di 3.150.947.064 byte non è RSS; i 20,6 minuti dell'azione non sono latenza di query. |
| GPU custom Head/PFKS | Notebook consegnato, con controlli locali CPU | Compilazione CUDA, correttezza FHE GPU e velocità comprensiva dei trasferimenti non osservate negli artefatti disponibili. |

Fonti: [esperimento 23](experiments/23_ckks_ottimizzazioni/README.md),
[esperimento 24](experiments/24_frontiere_common_mask_bgv/README.md),
[rapporto originale CKKS combinato](experiments/23_ckks_ottimizzazioni/evidence/ORIGINAL_COMBINED_RESULTS.md),
[riepilogo common-mask e BGV](experiments/24_frontiere_common_mask_bgv/RESULTS.json).
Il resoconto GPU e il notebook preparato restano locali; lo stato citato è
in `docs/personal/ottimizzazioni-complete-2026-09-07.md` e non attesta una
successiva esecuzione CUDA.

## F93 — Nuova campagna comune e precedente errore di Head generale

La campagna del 9 settembre rimisura i sorgenti recuperati in due sezioni:
Concrete e TFHE iniziale su punteggi/primo argmin N8/D64; dieci versioni
destinate a exact 0/ID su N127/D512 e soglia uniforme inclusiva T4.
Lo stacco cambia contratto e dimensioni: non si calcola un miglioramento
fra i due lati. A28 è il primo sorgente exact recuperato e rimisurato;
gli antichi tempi A23/A25 non sono inseriti nella nuova curva.

I prototipi producono 54 risultati corretti, di cui 36 misurati e 18 warmup;
la sezione exact produce 450 risultati corretti, di cui 300 misurati e 150
warmup. Ogni profilo nativo usa tre nuove famiglie. Le mediane
Concrete/TFHE iniziale sono 264,797785/49,767460 secondi, con riduzione
geometrica appaiata 81,2735% e 18/18 coppie favorevoli. Le mediane A28/finale
sono 7,351781/1,622570 secondi, con riduzione appaiata 77,8052% e 30/30 coppie
favorevoli. I warmup non entrano nelle mediane; questi estimatori non sono
rapporti delle mediane e non si sommano ai risultati precedenti.

**Un precedente tentativo resta fallito:** fra 269 risultati, 268 erano
corretti e Head generale restituiva ID75 invece di ID1 nel caso
`tie_first_last`. Il replay di chiave, input e binario invariati riproduce
gli stessi ciphertext errati; è la ripetizione dello stesso errore, non
un campione indipendente aggiuntivo. La causa resta irrisolta. Questi tempi
non entrano nella nuova curva; i nuovi 45/45 risultati corretti di Head
generale non cancellano il fallimento. I confronti che coinvolgono questo
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

Fonti pubblicate: [figura, metodo e tabelle](output/figures/progressione-fhe/benchmark-comune-matplotlib-20260909/LEGGIMI.md).
L'archivio integrale del primo tentativo e del replay resta locale in
`tmp/progress-common-benchmark-20260909/late-exact/audit/main-failure-01/REPORT.json`.

## F0–F83 — Risultati storici e correzioni consolidate

Gli identificatori originari rimangono stabili nell'archivio integrale locale,
`docs/archive/2026-09-08-before-consolidation/findings.md`.
La tabella raggruppa i risultati per facilitarne la lettura; i dettagli,
le condizioni e i tentativi intermedi restano nelle rispettive voci storiche.
Le vecchie parole «corrente», «finale» o «chiuso» indicano il loro checkpoint,
non lo stato della ricerca oggi.

| Identificatori | Risultato che rimane, con le correzioni successive |
|---|---|
| F0–F3 | Concrete è stato eseguito nativamente su macOS arm64. La galleria pubblica consente prodotti cifrato×chiaro e richiede la corretta espansione del punteggio; non elimina da sola i problemi del modello di minaccia. |
| F4–F10 | PCA e descrittori locali hanno prototipi e benchmark conservati. I risultati sui dataset semplici non si trasferiscono ai benchmark difficili o al riconoscimento open-set 1:N. |
| F11–F14 | Argmin+soglia è implementabile; un inputset di compilazione non è un dominio di sicurezza. Gli embedding CNN migliorano le prove biometriche rispetto ai descrittori precedenti; quantizzazione e protocollo vanno valutati separatamente. |
| F15–F19 | Profondità, taglia della galleria e dominio dei volti cambiano l'accuratezza osservata. I primi numeri con un solo seed sono circoscritti e rinviano alle successive verifiche multi-seed; nessun tetto universale di accuratezza è dimostrato. |
| F20–F24 | Sono state confrontate compressione degli embedding, argmin server e strategie a blocchi in Concrete. Funzione restituita, interazione e minaccia determinano se un confronto preserva il contratto. |
| F25–F28 | Il test Concrete su Tesla T4 e i tornei/controlli a soglia hanno risultati propri. Non qualificano il successivo circuito custom GPU né dimostrano limiti generali di GPU o TFHE. La lettura della letteratura F26 è storica e corretta dagli audit successivi. |
| F29–F34 | Scaling DigiFace, divario di dominio, confronto Concrete/TFHE-rs sullo stesso Mac e prodotto scalare leveled sono misurati nelle rispettive prove. Il rapporto di circa 100× riguarda quel microbenchmark; il breakdown end-to-end evita di attribuirlo all'intera applicazione. |
| F35–F39 | I requisiti dell'incontro orientano il protocollo. Gli otto bit sono una verifica in chiaro della quantizzazione; il torneo radix e la prima CKKS hanno benchmark separati. Il comparatore diretto a un PBS di F37 è invalidato vicino alla soglia da F68. |
| F40–F43 | Ridurre l'output riduce l'informazione esposta, ma conserva un oracolo applicativo. Query compatta, prototipo a tre ruoli e scaling storico fino a N1024 non validano il comparatore invalido né il contratto exact-ID corrente. |
| F44–F49 | GhostFaceNet e fusione multi-frame hanno verifiche biometriche specifiche. Parametri, ponti e codifiche hanno prove distinte. Le latenze del servizio pre-fold F49 restano storiche: i suoi casi facili non provano la frontiera riparata successivamente. |
| F50–F55 | Rumore PBS, codifica dell'uscita e rumore composto sono obblighi diversi. La primitiva a galleria GGSW cifrata riesce senza validare la decisione completa; il torneo con circuit bootstrapping provato non è un argmin esatto. Z-norm ha effetti biometrici circoscritti. |
| F56–F61 | Il bound e i controlli della galleria risolvono l'overflow nel dominio verificato, non l'origine biometrica di un probe arbitrario. Cascata, packing e multi-bit hanno esiti propri; l'output minimale non chiude gli attacchi applicativi. |
| F62–F67 | Confronti di sicurezza e prestazioni richiedono parametri e funzioni comparabili. Il contributo locale è implementazione, integrazione e valutazione, senza pretesa di priorità. Le negative di ammortizzazione/scaling sono circoscritte; CKKS deve includere i rifiuti open-set. |
| F68–F70 | L'audit invalida la soglia diretta, ritira il percorso residuale da 14 PBS e conserva il fallback da 9. Periodic-fold ripara empiricamente la frontiera con tre PBS/template; è ancora distinto dal successivo exact-ID e da una prova di probabilità globale. |
| F71–F73 | F71 stabilisce primo minimo+soglia del vincitore+0/ID. A28 elimina 508 KS a N127; A29 riduce il tempo dell'8,876% nel suo confronto appaiato. La singola LWE e la specifica del servizio di allora non sono il formato attuale a tre cifre. |
| F74–F76 | A33 viene integrato e poi promosso con 13,734% nel confronto A29/A33; A38 dà 13,828% nel proprio confronto. Le suite precedenti da 632 casi appartengono alle revisioni indicate nelle fonti, senza trasferimento alle revisioni nuove. |
| F77–F80 | A41 passa 29/29 casi con due LWE p16; A44 passa 120/120 ma conserva il bound raw condizionale. A62 materializza A50+A53 con 3390 BR e 142/142 casi di componente. A64 è un progetto statico checked, non un circuito compilato o misurato. |
| F81 | A73 confronta **A62/A66**, non A23/A66: 22,2018% di miglioramento a 16 thread e 2,2628% di peggioramento a un thread. Il conteggio A23→A66 e le suite 632 sono fatti separati. I successivi Head/PFKS, BGV e common-mask superano le vecchie descrizioni di stato senza rendere valide le vecchie costruzioni fallite. |
| F82 | Domini A124 eseguiti: N64 `[-1019,2317]`, N127/128 `[-1019,2329]`. BR di estrazione/selezione/scan a N128: 1664+1615+136=3415; a N127: 1651+1603+136=3390. Conteggi e tagli sovrapposti non sono risparmi sommabili. Il margine nominale p128 non prova la coda del circuito raw. |
| F83 | A124 termina 21 celle, 294 uscite corrette e 210 misure. L'audit successivo classifica 8 celle valide ai controlli pre/post, 12 con attività post elevata e una senza metadati driver. Il PASS originario non richiedeva quel successivo criterio post. Nessun monitor interno alla cella prova isolamento continuo; thread, carico e rapporti di stadio non identificano causalmente contributi degli E-core, copie, KS o un tetto allo scheduler. |

Fonti locali non distribuite delle correzioni F81–F83:
`docs/research-state/2026-09-04/audit.md` e
`docs/research-state/2026-09-05/a124-final-guard-audit/README.md`.
Le appendici storiche e la borsa delle idee sono conservate nell'archivio;
le prove successive hanno risolto alcune azioni e circoscritto altre negative.
La ricerca locale indefinita rimane aperta, senza regola di arresto a cinque
passaggi o obiettivo di latenza imposto da questo riordino.
