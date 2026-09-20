# Primitive e integrazione TFHE

[Indice della rassegna](../../letteratura.md) · [Fonti](fonti.md) · [Repository](../../README.md)

Rassegna al 2 settembre 2026. «Corrente», «promossa» e le prove ancora da
svolgere si riferiscono alle revisioni A28/A29/A33 a quella data. Gli sviluppi
successivi sono descritti nei [risultati del 9 settembre](../../findings.md).

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
tie-first e singolo codice exact open-set `0`/ID. La combinazione completa non è stata individuata nelle fonti esaminate. Questa
osservazione sul corpus non stabilisce priorità, brevettabilità o freedom-to-operate.

Sul piano sperimentale, al 2 settembre A33 è un candidato integrato e congelato: il full-core mirato passa sei casi/sette valutazioni fino a N=127/codice 127 e la
frontiera DigiFace passa 80/80 query, 48/48 autorizzazioni e zero errori/discrepanze a 4.273
PBS/query. Restano suite primaria canonica, Docker, paired A29/A33 e accounting condizionale della
`p-fail`; A29 rimane quindi l'ultimo snapshot promosso e il fallback generale.

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
multi-value. Una futura fusione scan/output A34 andrebbe valutata come specializzazione exact-ID,
misurandone i costi end-to-end. Priority encoder e sintesi multi-value sono già presenti
nel lavoro citato.

Per la selezione categorica esiste un precedente più specifico. Legiest et al.,
[“Leuvenshtein: Efficient FHE-based Edit Distance”](https://eprint.iacr.org/2025/012.pdf), sezione
3.1 e Tabella 2, impacchettano piccole differenze multivalore con una codifica lineare pesata,
calcolano il minimo di tre valori in un solo PBS TFHE e sfruttano le entrate nulle negacicliche per
far corrispondere 18 valori logici a una lookup da 16 valori. Dense encoding, LUT `min-of-three` e uso dei gap negaciclici hanno dunque precedenti.
Un'eventuale costruzione A34 resta da implementare e misurare: il contributo da valutare
riguarderebbe la codifica exact-ID, la composizione nearest-ID completa e il conteggio
effettivo delle operazioni.

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
tre blocchi-chiave per stimare la latenza; non sono 60 casi biometrici indipendenti. A29 è la versione selezionata e congelata al 2 settembre; queste verifiche non
stabiliscono garanzie per l'uso in produzione. I report sono
`experiments/14_pipeline_tfhe_rs/results/exact_id_manylut_replay_probe87_2026-09-02.md` e
`benchmark/results/fhe_digiface_exact_frontier_manylut_2026-09-02.md`, con suite ed E2E in
`benchmark/results/fhe_digiface_exact_primary_manylut_2026-09-02.{csv,json}` e
`benchmark/results/demo_e2e_exact_id_manylut_2026-09-02.{csv,json}` e paired in
`benchmark/results/fhe_digiface_exact_paired_a28_a29_2026-09-02.md`. Nelle pubblicazioni
accademiche/ePrint esaminate non è stato identificato un prototipo valutato con la stessa
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
