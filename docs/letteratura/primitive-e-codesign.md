# Primitive e integrazione TFHE

[Indice della rassegna](../../letteratura.md) · [Fonti](fonti.md) · [Repository](../../README.md)

Fonti verificate al **19 settembre 2026**; raccordo aggiornato il 22 settembre.
Il riferimento è il [runtime Head/PFKS mantenuto](../../runtime/README.md),
con selettore corretto, anchor e pack4 adottato il 20 settembre. La rassegna
non aggiunge prove crittografiche o misure; le sezioni A28/A29/A33
ricostruiscono passaggi storici con evidenza propria. Per le alternative si veda
anche [CKKS numerico, discreto e scheme switching](ckks-discreto.md).

## 5. Primitive e protocolli complementari

**Segno TFHE ad alta precisione.** Liu, Micciancio e Polyakov,
[Large-Precision Homomorphic Sign Evaluation using FHEW/TFHE Bootstrapping](https://eprint.iacr.org/2021/1337.pdf),
costruiscono il segno ad alta precisione tramite applicazioni iterative di una floor omomorfa e
digit decomposition, con complessità logaritmica nel modulo del plaintext invece che lineare. È
il precedente concettuale più vicino al problema emerso in F68: un singolo PBS di segno ha pochi
bit effettivi di precisione. Analogamente, Chillotti et al.,
[Improved Programmable Bootstrapping with Larger Precision and Efficient Arithmetic Circuits for
TFHE](https://www.iacr.org/archive/asiacrypt2021/130900334/130900334.pdf), introducono WoP-PBS e
l'estrazione di chunk di bit. Sono prior art di contesto per digit/chunk extraction e per i
tentativi storici; il core A28 usa invece PBS classico iterativo e non implementa WoP-PBS.

Il bootstrapping multi-output ha precedenti. Carpov, Izabachène e Mollimard,
[New Techniques for Multi-value Input Homomorphic Evaluation and Applications](https://eprint.iacr.org/2018/622)
(CT-RSA 2019), condividono la prima fase del bootstrapping per valutare più funzioni dello stesso
input. Chillotti et al. formalizzano poi `PBSmanyLUT`: una sola `GenPBS`/blind rotation seguita da
più sample extraction produce più LUT dello stesso ciphertext. Un precedente applicativo
particolarmente vicino è [FRAST](https://eprint.iacr.org/2024/745) (Cho et al., ToSC 2024(3)):
durante una valutazione usa `PBSmanyLUT` per co-estrarre l'MSB e lo sottrae per costruire
`ClearMSB`; in una costruzione separata decompone inoltre una parola in più bit tramite
multi-value PBS. Questi lavori anticipano la condivisione della blind rotation e il riuso di un bit
estratto come correzione. Nel loro testo non è stata identificata la specifica coppia
di copie dello stesso bit alle scale
correction/Boolean né la sua integrazione nell'argmin facciale completo.

Per A33 esiste un precedente ancora più vicino alla meccanica dell'accumulatore. La domanda
[Axell US20240154786A1](https://patents.google.com/patent/US20240154786A1/en), con priorità
dichiarata 24 giugno 2021, descrive coefficienti differenti nelle posizioni pari e dispari del
test vector, rotazioni rese pari, una sola `BlindRotate` e due `SampleExtract` ai gradi 0 e 1 per
ottenere due risultati semanticamente diversi, `sum` e `carry`. La domanda
[US20240121077A1](https://patents.google.com/patent/US20240121077A1/en) estrae invece alle
posizioni 0 e `N/2` dopo la stessa blind rotation e combina i risultati; la domanda
[US20240187210A1](https://patents.google.com/patent/US20240187210A1/en), con priorità
dichiarata 24 novembre 2022, estende il disegno a più estrazioni e combinazioni nel contesto di
confronti e ricerca/autenticazione fuzzy. Interlacciamento, distanza fra estrazioni e output semanticamente diversi hanno quindi
precedenti documentati. L'eventuale contributo di A33 riguarda la combinazione applicativa: residuo sparso,
coppia `(r signed, flag signed)`, pesi posizionali 1/3, canonicalizzazione e continuazione verso
tie-first e singolo codice exact open-set `0`/ID. La combinazione completa non era stata individuata nel corpus mirato della rassegna originaria. Questa
osservazione sul corpus non stabilisce priorità, brevettabilità o freedom-to-operate.

La prima integrazione A33 superò sei casi/sette valutazioni e una frontiera
DigiFace di 80 query a 4.273 PBS/query. Nella stessa giornata del 2 settembre
seguirono la [suite primaria 632/632](../../benchmark/results/fhe_digiface_exact_primary_a33_2026-09-02.md),
il [controllo Docker 6/6](../../benchmark/results/demo_e2e_exact_id_a33_frozen_2026-09-02.md)
e il [confronto A29/A33](../../benchmark/results/fhe_digiface_exact_paired_a29_a33_2026-09-02.md):
120 coppie misurate su sei chiavi, riduzione geometrica del 13,734%, intervallo
del run [11,806%, 15,595%]. A33 fu quindi selezionato per il suo percorso
allineato, mantenendo A29 come fallback in quella revisione. Il carico elevato
limita l'interpretazione dei tempi. La [contabilità del rumore](../../benchmark/results/exact_id_a33_pfail_accounting_2026-09-02.md)
fu completata come analisi condizionale, senza certificato numerico end-to-end.
Queste evidenze appartengono ad A33 e non qualificano automaticamente il runtime
successivo Head/PFKS.

Anche i due accorgimenti implementativi più specifici hanno precedenti più ampi. La domanda di
brevetto, poi ritirata,
[EP4096148A1 di Zama](https://data.epo.org/publication-server/rest/v1.2/publication-dates/20221130/patents/EP4096148NWA1/document.pdf)
descrive coefficienti GLWE con fattori di scala differenti, prodotti polinomiali, estrazione e
riuso dei risultati; [Bergerat et al.](https://eprint.iacr.org/2022/704.pdf) riutilizzano
ciphertext ottenuti durante l'estrazione come selettori. Il packing multi-scala e il riuso delle
correction ciphertext non sono quindi rivendicabili isolatamente. La distinzione del prototipo è
la loro integrazione specifica nel percorso facciale completo/modulo 16, fino alla soglia del
vincitore e al codice `0`/ID.

La selezione dei candidati che condividono i primi `k` bit più significativi con il massimo ha
un precedente diretto in [Lee, Choi e Lee (2023)](https://doi.org/10.3390/electronics12071724),
sebbene sia realizzata con confronti approssimati in CKKS. L'idea del filtraggio MSB-first non è
quindi una nuova primitiva del presente lavoro.

Per il priority encoder TFHE, Yu et al., WAHC 2024,
[DOI 10.1145/3689945.3694803](https://doi.org/10.1145/3689945.3694803), valutano esplicitamente un
priority encoder generico da 818 gate e costo stimato 32.720 nel contesto della sintesi FBS
multi-value. La proposta storica di fusione scan/output A34 andava valutata come specializzazione exact-ID,
misurandone i costi end-to-end. Priority encoder e sintesi multi-value sono già presenti
nel lavoro citato.

Per la selezione categorica esiste un precedente più specifico. Legiest et al.,
[“Leuvenshtein: Efficient FHE-based Edit Distance”](https://eprint.iacr.org/2025/012.pdf), sezione
3.1 e Tabella 2, impacchettano piccole differenze multivalore con una codifica lineare pesata,
calcolano il minimo di tre valori in un solo PBS TFHE e sfruttano le entrate nulle negacicliche per
far corrispondere 18 valori logici a una lookup da 16 valori. Dense encoding, LUT `min-of-three` e uso dei gap negaciclici hanno dunque precedenti.
La proposta A34 della rassegna iniziale riguardava la codifica exact-ID e la
composizione nearest-ID completa. La sua menzione non è uno stato aggiornato
dei lavori: le revisioni implementate e i relativi conteggi sono nella
[ricostruzione storica](../risultati/storico.md).

L'implementazione A28 usa questa combinazione: un canale modulo 16 e il canale completo
condividono lo stesso GLWE senza sovrapposizione dei supporti; `b0..b3` vengono estratti al margine
largo, ricodificati come quattro correzioni alla scala full e sottratti, quindi il residuo fornisce
`b4..b11`. I bit alimentano un argmin per prefisso, la selezione cifrata della soglia pubblica del
vincitore e una sentinella scalare. Questa revisione è implementata e ha evidenza autonoma:
198/198 casi split4 sotto tre chiavi fresche, 632/632 output completi uguali al clear e un E2E
Docker 3/3 identità esatte più 3/3 rifiuti. Sono test empirici, non una prova del `p-fail`.

A29 fonde sperimentalmente alcune estrazioni tramite una blind rotation condivisa, emettendo sia
la copia alla scala di correzione sia quella alla scala booleana. Il core implementato ha superato
198/198 casi boundary in tre processi con chiave fresca e 198/198 query semantiche su
`N=1..8,64,127,128` con 33 coppie di chiavi fresche; il percorso uniforme N=127 ha osservato
4.965 PBS. Un replay diagnostico DigiFace del probe 87 ha restituito il codice exact-ID 88 con zero
mismatch ai checkpoint; la regressione di frontiera ha poi dato 80/80 query concordi col clear,
zero errori operativi e 48 autorizzazioni attese/osservate. La suite primaria successiva ha dato
632/632 output uguali al clear, zero discrepanze/errori, 131/131 autorizzazioni e 632 probe
ciphertext distinti; l'E2E Docker ha dato 3/3 identità esatte e 3/3 rifiuti, zero failure
semantici e 4.965 PBS/query. Il confronto paired successivo sulla stessa chiave/scena e sugli
stessi byte cifrati ha preservato 72/72 output e misurato su 60 coppie una riduzione geometrica
dell'8,876%, intervallo del run [8,092%, 9,728%], con 57/60 vittorie. Il carico alto ne limita la
generalizzazione. Le 60 coppie ripetono cinque probe di frontiera fissati 12 volte ciascuno nei
tre blocchi-chiave per stimare la latenza; non sono 60 casi biometrici indipendenti.
A29 fu selezionato in quel passaggio, prima della successiva qualifica di A33
nella stessa giornata. Queste verifiche non stabiliscono garanzie per l'uso in
produzione. Le fonti sono il [replay diagnostico](../../experiments/14_pipeline_tfhe_rs/results/exact_id_manylut_replay_probe87_2026-09-02.md),
la [frontiera](../../benchmark/results/fhe_digiface_exact_frontier_manylut_2026-09-02.md),
la [suite primaria](../../benchmark/results/fhe_digiface_exact_primary_manylut_2026-09-02.json),
il [controllo E2E](../../benchmark/results/demo_e2e_exact_id_manylut_2026-09-02.json)
e il [confronto A28/A29](../../benchmark/results/fhe_digiface_exact_paired_a28_a29_2026-09-02.md).
Nel corpus accademico/ePrint mirato della rassegna originaria non era stato
identificato un prototipo valutato con la stessa
microarchitettura A28 né la specifica integrazione mixed-scale A29. È una constatazione sul
corpus, non un claim di priorità, brevettabilità o freedom-to-operate.

Il quadro di prior art include anche un processore TFHE a base 16. Trama et al.,
[Designing a General-Purpose 8-bit (T)FHE Processor Abstraction](https://eprint.iacr.org/2024/1201)
(TCHES 2025), rappresentano ogni parola a 8 bit come due cifre in base 16, sistematizzano
functional bootstrapping, MVB/MVLUT e implementano anche `MIN`/`MAX` su valori cifrati. Il loro
MVB valuta più LUT dello stesso input condividendo la blind rotation, poi aggiunge moltiplicazioni
plaintext/ciphertext, sample extraction e public functional key switching. È un ulteriore precedente per la scomposizione in nibble e la fusione multi-output,
pur con un accumulatore diverso da quello di A29. Non è un sistema biometrico open-set e l'algoritmo
pubblicato per il minimo restituisce il solo valore, non una label di galleria o il contratto
soglia-del-vincitore più `0`/ID di A28.

Un'alternativa per LUT a precisione maggiore è descritta nel preprint di Li et al.,
[Leveled Functional Bootstrapping via External Product Tree](https://eprint.iacr.org/2025/022).
Gli autori implementano TFBS e LFBS in OpenFHE. La sezione sperimentale 5.3 riporta 1,12 s e un
fattore 11,7x per la LUT 12-bit-to-12-bit nel confronto indicato con TFBS+PRCA, mentre menziona
anche 180x fra parentesi rispetto a una baseline diversa; per 16 bit riporta 96x. Non esiste quindi
un unico fattore trasferibile. Propongono anche scheme switching BFV/LFBS. L'applicazione a score traslati in un intervallo pubblico di ampiezza al massimo 4096
resta da verificare: cambiano
costruzione, backend, rappresentazione, chiavi, piattaforma e interfaccia; il passaggio BFV/LFBS
è un'opzione aggiuntiva. Prima di considerarla alternativa ad
A28 servono un adattatore score, payload ID stabile, soglia open-set e un benchmark LFBS-vs-TFBS
matched, seguito da un confronto end-to-end.

L'analisi statica successiva A106 ha individuato un limite di questa costruzione. La LUT 12-to-12 è
unaria su tre cifre base 16; un confronto arbitrario fra due score a 12 bit
richiede sei cifre, quindi un dominio da `2^24` valori. Anche concedendo
l'horizontal packing descritto nel paper, la forma richiede almeno 1.048.576
polinomi di test (16 GiB dei soli coefficienti plaintext a `N=2048`) e induce
oltre un milione di nodi external-product nel mapping letterale. Non è quindi
una sostituzione diretta competitiva del torneo exact-ID. Resta da valutare il
caso a piccoli chunk, che richiede un'implementazione conforme al paper e
un meccanismo reale di riuso fra nodi; conversione LWE-to-RGSW, HomoTrace/PRCA
e riuso multi-output continuano invece nella famiglia A92/A99/A102/A104 senza
materializzare la LUT arbitraria esponenziale. Il limite riguarda questo
mapping letterale e non esclude costruzioni specializzate su domini più piccoli.

## Dal percorso storico al runtime Head/PFKS

Il [core selezionato](../../runtime/README.md) usa TFHE-rs 1.7, Head con
correzione media, PFKS direct-window, refresh del controllo e gruppi fino a
quattro payload. Restituisce tre cifre cifrate in base 15. La [qualifica pack4](../validazione/PACK4_VALIDATION.md)
e il [contratto geometrico](../../runtime/REPAIR.md) documentano la revisione
adottata. Questa integrazione ha una genealogia distinta dalla sola
estrazione multi-output di A29. Le fonti seguenti chiariscono quali idee sono riprese
dalla letteratura e quali adattamenti richiedono evidenza locale.

**Head Start.** D'Anvers, Pottier, de Ruijter e Verbauwhede,
[Head Start: Digit Extraction in TFHE from MSB to LSB](https://eprint.iacr.org/2025/2012),
ePrint 2025/2012, ricevuto il 28 ottobre 2025 e ancora classificato preprint
nella pagina consultata, introduce `DirtyMSB` e compensa l'errore nelle
estrazioni successive. È un precedente diretto per l'estrazione da MSB a LSB
e per il riuso degli output nei consumatori. Il [codice degli autori](https://github.com/KULeuven-COSIC/Head_Start)
è una patch per TFHE-rs **1.1.0**, commit
`2cd16ac70af19308e7a4578083b4e2e3730964ca`: il port 1.7 e le scelte di scala
locali richiedono quindi verifiche proprie. L'[esperimento 17](../../experiments/17_head_pfks_tfhe17/README.md)
documenta l'integrazione iniziale. La [diagnosi del caso storico](../selector-repair-20260920.md)
ha localizzato il guasto nel selettore: il controllo raggiungeva 341, oltre
la finestra 300–340, mentre tutte le 127 estrazioni Head erano corrette.
Il refresh e il successivo pack4 hanno prove proprie. Il caso non confuta
la primitiva Head; le garanzie del paper non sostituiscono la prova del
rumore composto del circuito locale.

**Compensazione della media.** de Ruijter, D'Anvers e Verbauwhede,
[Don't be mean: Reducing Approximation Noise in TFHE through Mean Compensation](https://doi.org/10.46586/tches.v2026.i1.82-104),
TCHES 2026(1), pp. 82–104, affrontano componenti medie dell'errore di modulus switching
e gadget decomposition. È il riferimento per questa tecnica, da distinguere
dalle modifiche congiunte di split e rappresentazione nell'esperimento 17.
L'edizione finale è stata controllata il 22 settembre; la
[scheda di lettura](testi-integrali/tfhe.md#compensazione-della-media) distingue
le sue tabelle da quelle del preprint ePrint 2025/809.
Non si attribuisce al runtime un fattore
di accelerazione del paper o una probabilità di fallimento ereditata.

**Packing e conversioni.** Chen, Dai, Kim e Song,
[Efficient Homomorphic Conversion Between (Ring) LWE Ciphertexts](https://eprint.iacr.org/2020/015),
ACNS 2021, ePrint 2020/015, revisione 4 dicembre 2020, trattano conversioni
LWE/RLWE, key switching e packing di più ciphertext. Lee e Yoon,
[Homomorphic Field Trace Revisited: Breaking the Cubic Noise Barrier](https://eprint.iacr.org/2025/1088),
TCHES 2026, ePrint 2025/1088, revisione 16 ottobre 2025, introducono
`RevHomTrace` e `MS-PackLWEs` per ridurre l'amplificazione di fase e l'errore
di packing. Sono riferimenti per le alternative di conversione e il lavoro
sulla traccia; non implicano che il selettore direct-window implementi tutti
questi algoritmi. Una bound di varianza della primitiva non è una bound di
fallimento del torneo composto.

Nel confronto tra fonti conviene scrivere **functional packing key switch
LWE→GLWE/RLWE**, poi indicare se la funzione è pubblica o privata. La sigla
PFKS non ha un'espansione universale: Blind Counting Sort usa *Public
Functional Key Switch*, mentre un'API di libreria può offrire una costruzione
privata. Una LUT cifrata non rende automaticamente privata la funzione del
key switch. Costi di packing, finestre, payload, chiavi e conversioni vanno
contati nel percorso che il consumatore utilizza davvero.

## Common-mask e famiglie di LUT alternative

**Common-mask.** Bergerat, Bonte, Curtis, Orfila, Paillier e Tap,
[Sharing the Mask: TFHE Bootstrapping on Packed Messages](https://eprint.iacr.org/2025/2112),
TCHES 2025(4), 925–971, formalizzano maschera condivisa, molteplici corpi e
segreti matriciali, con LUT distinte e operazioni lineari private. Il modello
non equivale al riuso ingenuo della stessa maschera sotto lo stesso segreto:
in quest'ultimo caso sottrarre due corpi cancella la maschera e lascia la
differenza dei messaggi più rumore. Le [misure di primitiva](../../experiments/16_common_mask_poc/README.md)
e il [successivo pilot Joint4](../../experiments/24_frontiere_common_mask_bgv/README.md)
sono evidenze diverse; nessuna autorizza a trasferire un guadagno all'intera
demo o a N127 senza le conversioni e le prove corrispondenti.

**Tetris.** Wang et al.,
[Tetris: Versatile TFHE LUT and Its Application to FHE Instruction Set Architecture](https://eprint.iacr.org/2025/1623),
ePrint 2025/1623, ricevuto il 9 settembre 2025 e classificato preprint,
propongono LUT GLWE, circuit bootstrap in batch e parametri adattivi.
L'abstract distingue LUT generali univariate a 32 bit da bivariate a 16 bit.
Il testo completo (§6.2, tabella 6) presenta però anche **confronti specializzati
cifrato/cifrato a 32 bit**, ottenuti potando la LUT. La limitazione del dominio
generale non esclude questi circuiti; corregge la precedente lettura troppo
restrittiva dell'abstract. Questo lavoro
è distinto dall'omonimo TETRIS di Izabachène e Bossuat, PoPETs 2025(2), dedicato
all'esplorazione funzionale privata. Nell'[esperimento 25](../../experiments/25_tetris/README.md)
il consumatore locale supera i controlli, ma il produttore comprensivo delle
conversioni è più lento nel pilot. Il risultato esclude quella costruzione
dalla demo, senza chiudere ogni variante della famiglia.

**Full-domain functional bootstrapping.** Kluczniak e Schild,
[FDFB: Full Domain Functional Bootstrapping Towards Practical Fully Homomorphic Encryption](https://eprint.iacr.org/2021/1135),
TCHES 2023, ePrint 2021/1135 rivisto il 3 gennaio 2023, trattano funzioni
sull'intero dominio e conversioni fra rappresentazioni aritmetiche e booleane.
Hwang, Lee, Min e Song,
[Efficient Full Domain Functional Bootstrapping from Recursive LUT Decomposition](https://sacworkshop.org/SAC25/preproceedings/sac2025-2-paper18.pdf),
preproceedings SAC 2025, decompongono la LUT in parti negacicliche e una parte
full-domain ridotta, usando Extended Bootstrapping e TFHE-go. “Full-domain”,
“precisione elevata” e “multi-output” sono proprietà distinte. Il costo di
un FDFB non può essere contato come quello di un PBS negaciclico ordinario.

**RevoLUT.** Azogagh, Birba, Killijian, Larose-Gervais e Gambs,
[RevoLUT: Rust Efficient Versatile Oblivious Look-Up-Tables](https://eprint.iacr.org/2024/1935),
ePrint 2024/1935, revisione 20 aprile 2025, trattano LUT cifrate come array
per accesso, ordinamento e permutazione. Il ruolo è quello di libreria di
strutture dati cifrate, distinto da FDFB e dalla costruzione biometrica completa.

## Portata della verifica delle fonti del 19 settembre

Sono ora disponibili i PDF completi di Head Start, Tetris, compensazione
media, Sharing the Mask, Chen, RevHomTrace, FDFB e RevoLUT. La
[lettura mirata delle otto fonti](testi-integrali/tfhe.md) documenta pagine,
versioni e condizioni. Supera i precedenti limiti d'accesso; non certifica
tutte le prove né replica i benchmark.

Per l'integrazione locale emergono condizioni precise: Head assume
indipendenza fra cifrati bootstrappati e ammette cifre intermedie non canoniche;
Chen richiede un inverso modulare non disponibile nella trasposizione letterale
a modulo 2^64; il miglioramento asintotico di RevHomTrace riguarda la varianza.
I tempi della compensazione media e di FDFB hanno livelli di sicurezza da
esplicitare. Common-mask include conversioni e non accelera ogni batch;
RevoLUT richiede riallineamento per evitare che le scritture successive
compromettano i centri delle LUT.
Questi punti diventano obblighi dell'adattatore, senza cambiare retroattivamente
i risultati degli esperimenti conservati.

Il PDF SAC 2025 già consultato resta una versione preproceedings. Il 22 settembre
sono stati verificati metadati e abstract dell'[edizione pubblicata](https://doi.org/10.1007/978-3-032-10536-3_25)
(LNCS 16207, 2026, pp. 679–699); il capitolo integrale finale non è stato
confrontato. Le verifiche storiche conservano il loro perimetro. Riferimenti
nelle [fonti](fonti.md) e nel [file BibTeX](aggiornamento-20260919.bib).
