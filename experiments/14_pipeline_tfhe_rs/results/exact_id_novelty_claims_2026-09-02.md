# Audit dei claim di contributo e priorita' dell'exact-ID

Data dell'audit: 2026-09-02.

## Risposta breve

Il risultato difendibile non e' «abbiamo inventato l'argmin cifrato». Argmin, min+label,
nearest-ID, soglia globale sul minimo, output cifrato `0`/ID, scomposizione in nibble e
bootstrapping multi-output hanno tutti precedenti pubblicati.

Il contributo prudente e' la **progettazione, implementazione, integrazione e valutazione empirica**
dello specifico co-design A28/A29 e, come candidato pre-promozione, della specializzazione A33.
Erkin, Sadeghi, Kolesnikov, Azogagh, Cong, il POC Zama e la
domanda CEA WO2025027253 anticipano la funzione o sottocombinazioni decisive. Nelle pubblicazioni
accademiche/ePrint esaminate non e' stato trovato un prototipo valutato che riproduca
congiuntamente la microarchitettura A28; questa e' un'osservazione sul corpus, non un primo
assoluto, un giudizio di brevettabilita' o una freedom-to-operate.

La ricerca mirata successiva su A33 restringe ulteriormente il claim. Una blind rotation con
coefficienti interlacciati e piu' sample extraction e' gia' descritta sia da `PBSmanyLUT` sia, in
forma particolarmente vicina, dalla domanda Axell US20240154786A1: coefficienti diversi nelle
posizioni pari/dispari, rotazioni rese pari, una sola blind rotation ed estrazioni separate per
`sum` e `carry`. Anche estrazioni distanti e due o tre uscite combinate hanno precedenti Axell.
Non e' quindi difendibile chiamare A33 una nuova primitiva. Resta valutabile come contributo
applicativo la composizione specifica `residuo sparso -> (r signed, flag signed) -> pesi 1/3 ->
canonicalizzazione -> continuazione exact-ID`; nessuna fonte del corpus mirato e' stata trovata
con l'intera composizione, ma questo non equivale a una prova di novita'.

## Requisito che non puo' essere rimosso

Per una galleria ordinata di score `s_i` e soglie pubbliche `T_i`, il contratto e':

1. `k = min argmin_i s_i`, quindi in caso di parita' vince il primo indice;
2. si seleziona sotto cifratura soltanto `T_k`;
3. il client riceve un unico ciphertext che decifra a `k+1` se `s_k <= T_k`, altrimenti `0`;
4. su un rifiuto non vengono rilasciati nearest-ID, score, vettore di match o count.

Un semplice `OR_i(s_i <= T_i)` non e' equivalente: con soglie diverse puo' aprire per un
template piu' lontano e, in ogni caso, non restituisce l'identita' piu' vicina richiesta.

## Matrice dei claim

| Possibile claim | Esito dell'audit | Precedente decisivo o limite | Formulazione ammessa |
|---|---|---|---|
| Primo face recognition 1:N cifrato | **non difendibile** | Erkin et al. e Sadeghi et al., 2009; SCiFI, 2010 | Il lavoro implementa e valuta una specifica istanza TFHE del problema, non introduce il problema. |
| Primo nearest-ID esatto cifrato | **non difendibile** | Erkin mantiene `(distanza, ID)` nel torneo; Sadeghi usa `CMinimum`; Cong et al. trasportano min+label in TFHE | Descrivere differenze di schema, interazione e precisione, non priorita' sulla funzione. |
| Prima soglia sul vincitore con output `0`/ID | **non difendibile** per soglia globale | Erkin inserisce la soglia come candidato con ID `0`; Sadeghi usa compare+MUX | Descrivere e valutare la selezione concreta `k -> T[k]` dentro l'intero co-design. |
| Prima semantica con soglia per-template | **non difendibile** in assoluto | SCiFI definisce soglie `t_i` e closest-or-reject, ma non pubblica la composizione completa a soglie diverse | SCiFI e' prior art concettuale; la realizzazione TFHE A28 e' piu' specifica. |
| Primo argmin/top-k TFHE | **non difendibile** | Zuber-Sirdey, Ameur et al., Chakraborty-Zuber, Cong et al., Blind Top-k | Confrontare complessita', dominio e contratto di output. |
| Primo tie-break deterministico sul primo minimo | **non difendibile** | Kolesnikov et al. definiscono esplicitamente il minimo piu' a sinistra; Azogagh et al. pubblicano un sort TFHE stabile con label | Descriverlo come semantica implementata e testata, non come novita'. |
| Prima topologia single-server probe cifrata/galleria in chiaro | **non difendibile** | Erkin, Sadeghi, Cong e altri la usano; il POC Zama e' un near miss nello stesso stack Concrete/TFHE; WO2025027253 copre gran parte della composizione high-level | Descrivere il prototipo A28/A29 misurato, non attribuirsi l'architettura astratta. |
| Prima rappresentazione/scomposizione in nibble | **non difendibile** | Trama et al. rappresentano parole a 8 bit come due cifre in base 16 | Il packing split4 di A28 e' una scelta specifica del circuito, non una nuova rappresentazione generale. |
| Primo bootstrapping multi-output / blind rotation condivisa | **non difendibile** | Carpov et al., `PBSmanyLUT` di Chillotti et al., FRAST, Trama et al. | A29 puo' essere un'integrazione mixed-scale specifica, non una nuova primitiva. |
| Primo accumulatore interlacciato con piu' estrazioni | **non difendibile** | Axell US20240154786A1 interlaccia coefficienti pari/dispari e ottiene `sum`/`carry` con una blind rotation e due estrazioni; US20240121077A1 e US20240187210A1 coprono estrazioni distanti e combinazioni ulteriori | A33 adatta una tecnica nota ai suoi otto stati sparsi; non e' un nuovo PBS. |
| Intera composizione A33 verso exact-ID | **non trovata nel corpus tecnico mirato** | I singoli ingredienti hanno prior art; non e' stata trovata la stessa coppia `(r, flag)`, codifica signed 1/3, canonicalizzatore e prosecuzione exact-ID | “Specializzazione implementata nel core completo, con full-core mirato e frontiera valutati; promozione e confronto causale ancora aperti”, mai “prima al mondo”, brevetto o FTO. |
| Prima selezione MSB-first | **non difendibile** | Candidate narrowing sui bit piu' significativi in Lee, Choi e Lee; diversi circuiti digit/chunk | Presentarla come specializzazione esatta del dominio bounded A28. |
| Primo priority encoder TFHE o prima sintesi FBS multi-value | **non difendibile** | Yu et al., WAHC 2024, valutano esplicitamente un priority encoder TFHE generico da 818 gate/costo stimato 32.720 e una sintesi FBS multi-value | Una futura fusione scan/output A34 puo' essere descritta soltanto come co-design exact-ID specifico, non come nuova primitiva o primo priority encoder. |
| Prima codifica densa multivalore, LUT `min-of-three` o tecnica dei gap negaciclici | **non difendibile** | Legiest et al., ePrint 2025/012, codificano linearmente differenze multivalore pesate, calcolano il minimo di tre in un PBS TFHE e mappano 18 valori logici su una lookup da 16 usando entrate nulle negacicliche | La route categorica resta non implementata e non promossa; un possibile contributo e' soltanto la codifica applicativa exact-ID, la composizione nearest-ID completa e il conteggio misurato. |
| Stessa microarchitettura end-to-end di A28 | **non trovata nel corpus accademico/ePrint esaminato** | Nessun prototipo valutato verificato combina doppia vista disgiunta nello stesso GLWE, bounded 12 bit, `T[k]` e singolo `0`/ID | Osservazione scoped sul corpus, mai «prima al mondo», brevetto o FTO. |
| Evidenza empirica A28 | **contributo realizzato** | 198/198 stress split4 su tre chiavi, 632/632 replay completi, E2E Docker 3 ID + 3 rifiuti | Risultato sperimentale riproducibile, non prova formale di correttezza probabilistica. |
| Evidenza empirica A29 | **contributo realizzato; paired positivo** | Boundary 198/198, semantica 198/198, replay senza mismatch, frontiera 80/80, suite primaria 632/632, E2E Docker 6/6 a 4.965 PBS/query e cinque probe di frontiera fissati ripetuti 12 volte ciascuno nei tre blocchi-chiave (60 coppie, non 60 casi biometrici indipendenti) | Evidenza funzionale e d'integrazione; nel run paired riduzione geometrica 8,876% [8,092%, 9,728%], condizionata al carico osservato e senza chiudere la `p-fail`. |

## Che cosa A28 dimostra davvero

- Il percorso eseguibile conserva exact nearest-ID e rifiuto open-set; non sostituisce il
  requisito con membership.
- A `N=127` uniforme usa 5.600 PBS e 4.584 key switch; la suite completa ha dato 632/632 output
  uguali all'oracolo clear e 131/131 autorizzazioni attese/osservate.
- Lo stress mirato split4 ha dato 198/198 casi sotto tre chiavi fresche.
- L'E2E containerizzato `/api/verifica` ha restituito 3/3 identita' esatte e 3/3 rifiuti.
- Patch sorgente, input, hash e report congelano lo snapshot A28 separatamente dal successore A29.

Questi test non forniscono un bound formale del fallimento composto, non validano una distribuzione
webcam e non dimostrano la scalabilita' del **circuito FHE di selezione** a migliaia di iscritti.
Le misure biometriche a gallerie piu' grandi e la suite FHE a `N=127` sono risultati distinti.

## Stato di A29 e delle route successive

A29 implementa nel core sperimentale due copie dello stesso bit a scale diverse da una blind
rotation condivisa. Oltre ai test ordinari e agli smoke iniziali, passa 198/198 casi boundary in
tre processi con chiave fresca: 792 coppie correction/Boolean fused vengono decifrate e la
correlazione di fase viene misurata senza assumere indipendenza. Passa inoltre 198/198 query
semantiche su `N=1..8,64,127,128`, sei scene per dimensione e 33 coppie di chiavi fresche. La
formula uniforme a N=127 e' ora osservata nel core FHE: **4.965 PBS**, con 4.584 KS strutturali. Il
replay diagnostico DigiFace del probe 87 ha restituito il codice exact-ID 88 con zero mismatch ai
checkpoint; la regressione di frontiera ha dato 80/80 codici concordi col clear, zero errori
operativi e 48 autorizzazioni attese/osservate. La suite primaria ha ora dato 632/632 codici uguali
al clear, zero discrepanze/errori, 131/131 autorizzazioni e 632 probe ciphertext distinti; l'E2E
Docker ha dato 3/3 identita' esatte e 3/3 rifiuti con zero failure semantici. Il benchmark paired
A28/A29 sulla stessa chiave/scena e sugli stessi byte cifrati ha poi dato zero discrepanze su 72
coppie, 57/60 vittorie misurate e riduzione geometrica dell'8,876%, con intervallo bootstrap del
run [8,092%, 9,728%]. Le 60 coppie misurate ripetono cinque probe di frontiera fissati 12 volte
ciascuno nei tre blocchi-chiave per stimare la latenza; non sono 60 casi biometrici indipendenti.
Il carico era alto e la stima non e' universale. A29 e' quindi l'ultimo snapshot promosso e
congelato; resta aperto il bound della `p-fail` composta. Il contributo e'
l'integrazione mixed-scale nel co-design, non ManyLUT in se'.

A31 conserva l'identificazione sfruttando il cutoff normalizzato `K=T-L=991`, con `T=4` e
`L=-987`; il modello clear e' positivo, ma manca ancora la validazione FHE. A32 registra
LFBS/OpenFHE come possibile route per
LUT 12-bit-to-12-bit: la sezione sperimentale pubblica 1,12 s e 11,7x nel confronto indicato con
TFBS+PRCA, ma il dato non e' trasferibile senza una replica LFBS-vs-TFBS matched che includa poi
label e soglia open-set.

A33 conserva l'identificazione: il primo output di ogni accumulatore e' il residuo signed `r`, che
continua nei bit `b8..b0`, nello scan tie-first e nel codice finale `0`/ID; il secondo e' soltanto
un indicatore signed. I pesi alternati 1/3 vengono incorporati negli accumulatori e un PBS per
coppia canonicalizza la presenza della classe minima. Il micro-harness sul residuo rumoroso A29
passa 54/54 residui, 216/216 uscite e 192/192 coppie su tre chiavi, inclusi `h'=0..7` e il bordo
`1023/1024`. Il core e il servizio A33 sono ora integrati con fallback A29 fail-closed. Il full-core
mirato congelato passa sei casi/sette valutazioni fino a N=127/codice 127; la frontiera DigiFace
passa 80/80 query, 48/48 autorizzazioni, zero errori/discrepanze e 4.273 PBS/query. Questi risultati
dimostrano un percorso integrato nel perimetro provato, non ancora una revisione promossa: restano
suite primaria canonica, Docker, paired A29/A33 e accounting condizionale della `p-fail`. Il claim
meccanico e' escluso dai precedenti Axell e `PBSmanyLUT`; confronti con due PBS indipendenti, API
`ManyLookupTable` e pesi post-cifratura possono rafforzare l'attribuzione sperimentale del
co-design, ma non rendere nuova la primitiva.

## Formulazione consigliata per la tesi

> Il contributo di questa tesi e' la progettazione, implementazione e validazione sperimentale di
> uno specifico co-design TFHE per identificazione facciale 1:N open-set. Non proponiamo nuove
> primitive di argmin o bootstrapping e non rivendichiamo la priorita' di nearest-ID, tie-break
> stabile, soglia sul vincitore, uscita cifrata identita'/rifiuto, query cifrata contro galleria in
> chiaro o bootstrapping multi-output: tali funzioni o sottocombinazioni hanno precedenti
> espliciti. Nelle pubblicazioni accademiche/ePrint esaminate fino al 2 settembre 2026 non abbiamo
> individuato un prototipo valutato che riproduca congiuntamente tutti i dettagli implementativi di
> A28: doppia vista full/modulo 16 su supporti disgiunti dello stesso GLWE, dominio intero bounded a
> 12 bit, selezione cifrata di `T[k]` e singolo ciphertext `0`/ID. Questa e' una constatazione sul
> corpus consultato, non un claim di priorita', brevettabilita' o freedom-to-operate.

«Esatto» significa esatto rispetto all'oracolo clear intero sul dominio quantizzato e bounded
dichiarato, salvo la probabilita' di fallimento della valutazione/decrittazione FHE; non esatto
rispetto agli embedding continui o alla verita' biometrica.

## Evidenza e fonti di controllo

- A28 split4: `exact_id_split4_boundaries_2026-09-02.md`.
- A28 suite completa: `../../../benchmark/results/fhe_digiface_exact_primary_split4_2026-09-02.md`.
- A28 Docker E2E: `../../../benchmark/results/demo_e2e_exact_id_split4_2026-09-02.md`.
- Snapshot sorgente A28: `../../../benchmark/patches/a28_split4_source_2026-09-02.patch`.
- A29 boundary/correlazione: `exact_id_manylut_boundaries_2026-09-02.md`.
- A29 matrice semantica: `exact_id_manylut_semantics_2026-09-02.md`.
- A29 replay diagnostico probe 87: `exact_id_manylut_replay_probe87_2026-09-02.md`.
- A29 regressione di frontiera: `../../../benchmark/results/fhe_digiface_exact_frontier_manylut_2026-09-02.md`.
- A29 suite primaria: `../../../benchmark/results/fhe_digiface_exact_primary_manylut_2026-09-02.json`.
- A29 Docker E2E: `../../../benchmark/results/demo_e2e_exact_id_manylut_2026-09-02.json`.
- A29 confronto appaiato: `../../../benchmark/results/fhe_digiface_exact_paired_a28_a29_2026-09-02.md`.
- A29 contabilita' `p-fail`: `exact_id_manylut_pfail_accounting_2026-09-02.md`.
- A33 micro-harness sul residuo: `exact_id_a33_sparse_residual_trace_2026-09-02.md`.
- A33 full-core mirato congelato: `exact_id_a33_full_validation_2026-09-02.txt`.
- A33 frontiera pulita: `../../../benchmark/results/fhe_digiface_exact_frontier_a33_2026-09-02.md`.
- A33 patch congelata: `../../../benchmark/patches/a33_aligned_sparse_source_2026-09-02.patch`.
- Rassegna e bibliografia primaria: `../../../letteratura.md`.
- Erkin et al., PETS 2009: <https://doi.org/10.1007/978-3-642-03168-7_14>.
- Sadeghi et al., ICISC 2009: <https://eprint.iacr.org/2009/507>.
- Kolesnikov et al., CANS 2009: <https://eprint.iacr.org/2009/411>.
- SCiFI, IEEE S&P 2010: <https://doi.org/10.1109/SP.2010.39>.
- Azogagh et al., PoPETs 2025: <https://eprint.iacr.org/2024/1894>.
- Cong et al., SAC 2024: <https://eprint.iacr.org/2023/852>.
- Zama FHE Biometrics, commit `3038bc9`:
  <https://github.com/zama-ai/fhe-biometrics/tree/3038bc94e907ae73e67df9087f27191d091874e8>.
- CEA WO2025027253A1: <https://patents.google.com/patent/WO2025027253A1/fr>.
- Carpov et al., CT-RSA 2019: <https://eprint.iacr.org/2018/622>.
- FRAST, ToSC 2024(3): <https://eprint.iacr.org/2024/745>.
- Trama et al., TCHES 2025: <https://eprint.iacr.org/2024/1201>.
- Li et al., LFBS preprint 2025: <https://eprint.iacr.org/2025/022>.
- Chillotti et al., `PBSmanyLUT`, ASIACRYPT 2021: <https://eprint.iacr.org/2021/729>.
- Axell US20240154786A1: <https://patents.google.com/patent/US20240154786A1/en>.
- Axell US20240121077A1: <https://patents.google.com/patent/US20240121077A1/en>.
- Axell US20240187210A1: <https://patents.google.com/patent/US20240187210A1/en>.
- Yu et al., WAHC 2024, priority encoder TFHE e sintesi FBS multi-value:
  <https://doi.org/10.1145/3689945.3694803>.
- Legiest et al., “Leuvenshtein: Efficient FHE-based Edit Distance”, ePrint 2025/012:
  <https://eprint.iacr.org/2025/012.pdf>.

## Limite metodologico

Questa e' una rassegna tecnica mirata, non una ricerca brevettuale completa, una prova di novita'
legale, un giudizio di brevettabilita' o un'analisi di freedom-to-operate. «Non identificato»
descrive soltanto il corpus accademico/ePrint controllato alla data indicata e deve rimanere una
formulazione falsificabile.
