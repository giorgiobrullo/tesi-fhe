# Esperimento 14 - identificazione TFHE 1:N esatta con tfhe-rs

Obiettivo dell'incontro di luglio (findings F35): calcolare sul server la selezione a N=64/128,
restituire l'identita' piu' vicina se sufficientemente vicina oppure un rifiuto, e non restituire
mai la distanza. Misure su Apple M4 Max (12P+4E, 16 thread Rayon), tfhe-rs 0.11.3, `--release`,
`target-cpu=native`, parametri standard
`V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`.

## Stato del contratto al 2 settembre 2026: argmin esatto, poi soglia del vincitore

Il contratto finale implementato da `private_argmin` e `varco_demo` e':

```text
k = primo argmin_i score_i
codice = k+1  se score_k <= T_k
         0    altrimenti
```

L'output e' un solo big-LWE. Un rifiuto non rivela l'indice piu' vicino; nessuna risposta contiene
distanze, score, count o vettori. Il primo indice vince i pareggi e la soglia selezionata
cifratamente e' soltanto quella del vincitore. Una soglia permissiva di un template piu' lontano
non puo' aprire il varco.

Lo stato va distinto dal sorgente vivo: **A33 e' la baseline sperimentale corrente del fast path
uniforme/allineato**; A29 ManyLUT resta lo snapshot generale congelato e il fallback fail-closed,
mentre A28 e' la baseline precedente. Il termine “corrente” nelle sezioni storiche sotto non deve
essere letto come evidenza della revisione piu' recente.

Il client fidato impone coordinate `[-3,3]` e `||q||^2<=1024`. Il server deriva per ogni template
il dominio intero di Cauchy
`norm2(g) +/- 2*ceil_sqrt(norm2(g)*1024)` e rifiuta enrollment che porterebbero la larghezza oltre
4096. Il punteggio traslato usa quindi esattamente 12 bit.

### Costruzione A28, baseline congelata

- un solo GLWE contiene il probe completo a `Delta=2^52` nei coefficienti `0..511` e lo stesso
  probe modulo 16 a `Delta=2^60` nei coefficienti `1024..1535`;
- i due supporti non si sovrappongono e condividono il prodotto di scoring con il template;
- il canale modulo 16 fornisce esattamente `b0..b3` a `Delta=2^60`; quattro correction ciphertext
  li ricodificano alla scala completa e vengono sottratte dal punteggio;
- il residuo, multiplo di 16, fornisce `b4..b11` a `Delta=2^56`; lo split conserva 20 blind
  rotation di estrazione per template ma riduce i key switch di estrazione da `16N` a `12N`;
- la scansione lessicografica MSB-first usa OR a fan-in massimo quattro senza il vecchio selettore
  paired, conserva i candidati al minimo e rinfresca il one-hot del vincitore;
- il comparatore Booleano applica soltanto `T_k`; il codice `0` oppure `k+1` viene rinfrescato per
  nibble, con quello basso gia' a `Delta_bool` e senza il precedente `x16`.

Il percorso crittografico e' definito una sola volta in `src/private_argmin.rs`; il benchmark
`argmin_bucket_bits_periodic.rs` e il servizio `varco_demo.rs` chiamano lo stesso core.

### A29 ManyLUT, snapshot promosso precedente e fallback generale

A29 conserva lo stesso contratto exact-ID, lo split4 e la selezione del solo `T_k`. Per i bit
globali `3..6`, una blind rotation custom produce insieme la correction full e il bit alla scala
Booleana tramite due sample extraction; il bit 7 riusa direttamente la correction gia' alla scala
Booleana. Nel percorso uniforme N=127 il costo osservato scende a **4.965 PBS**, con 4.584 KS
strutturali, contro 5.600/4.584 di A28.

Boundary 198/198, matrice semantica 198/198, replay diagnostico, frontiera 80/80, suite primaria
632/632 ed E2E Docker 6/6 sono tutti concordi con l'oracolo exact-ID. Nel confronto appaiato A28/A29
sugli stessi byte cifrati, A29 preserva 72/72 output e riduce la latenza server geometrica
dell'8,876%, intervallo del run [8,092%, 9,728%], con 57/60 vittorie. Le 60 misure ripetono cinque
probe di frontiera fissati 12 volte ciascuno nei tre blocchi-chiave: stimano la latenza
dell'implementazione e non sono 60 casi biometrici indipendenti. Il carico host era alto e il
bound composto della `p-fail` resta aperto. Evidenza storica:
`../../benchmark/results/fhe_digiface_exact_primary_manylut_2026-09-02.md`,
`../../benchmark/results/demo_e2e_exact_id_manylut_2026-09-02.md` e
`../../benchmark/results/fhe_digiface_exact_paired_a28_a29_2026-09-02.md`.

### A33, baseline sperimentale corrente del fast path

Il fast path a soglia uniforme riallinea pubblicamente il dominio a `T-1023`, conserva il residuo
signed `r` per proseguire esattamente sui bit `b8..b0` e produce in parallelo un flag signed. Due
flag vengono emessi con pesi 1/3 e canonicalizzati con un PBS per coppia; il resto del percorso
rimane tie-first e restituisce il singolo codice `0`/ID. Il progetto completo conta 4.273 PBS e
3.892 KS a N=127, 692 PBS/KS meno di A29. Il punto A31 `K=991` effettivamente derivato nel
documento e' 4.373/3.992, quindi A33 ne risparmia 100; una precedente stima allineata 4.358/3.977
priva di derivazione congelata non viene usata come baseline.

Il planner attiva A33 soltanto con soglia uniforme, allineamento pubblico a `T-1023`, dominio
coperto e larghezza al massimo 4096. Ogni altro input valido usa il corpo generale A29 preservato.
Il micro-harness sul residuo rumoroso A29 passa 54/54 residui, 216/216 uscite e 192/192 coppie su
tre chiavi. Il full-core mirato congelato passa sei casi/sette valutazioni fino a N=127/codice 127,
inclusi `1023/1024`, tail dispari, tie-first con replay dello stesso ciphertext e rifiuto senza
risurrezione. La frontiera DigiFace pulita passa 80/80 query, 48/48 autorizzazioni, zero errori e
zero discrepanze sull'intero exact-ID, sempre a 4.273 PBS.

I gate di promozione successivi sono tutti positivi:

- la suite primaria passa **632/632**, zero errori/discrepanze, 131/131 autorizzazioni e
  ciphertext tutti distinti; la mediana server osservata di 8.458,2 ms appartiene a un run con
  carico estremo e non e' una latenza nominale;
- il paired A29/A33 usa **120 coppie misurate piu' 24 warm-up** su sei blocchi-chiave, conserva
  tutti i codici exact-ID e vede A33 vincere 105/120 volte. La riduzione geometrica e'
  **13,7343377%**, CI 95% **[11,8060731%, 15,5946764%]**, con differenza fra gli ordini di
  0,534606 punti. L'estensione preregistrata e' scattata per la larghezza iniziale del CI; carico
  alto e deriva restano caveat;
- l'E2E Docker provenance-bound passa **3/3 ID esatti e 3/3 rifiuti**, a 4.273 PBS/query;
- l'accounting riproducibile conta 4.273 BR, 3.892 KS e 4.908 marginali. Le union bound
  `2^-59,563966` e `2^-59,364080` sono soltanto condizionali: il decode finale non bootstrappato
  resta non valutato e non esiste ancora un bound end-to-end.

Patch, binario e artifact dei gate A33 sono congelati. A33 e' quindi promosso come baseline
sperimentale **nel perimetro del fast path**; A29 resta necessario come fallback generale.
L'accumulatore e' raw/custom, non l'API stock `ManyLookupTable`. La blind rotation multi-output e
l'interlacciamento hanno prior art diretta in `PBSmanyLUT` e nelle domande Axell
US20240154786A1/US20240121077A1/US20240187210A1: l'eventuale contributo e' soltanto il co-design
applicativo completo, non una nuova primitiva TFHE. Evidenza:
`results/exact_id_a33_sparse_residual_trace_2026-09-02.md`,
`results/exact_id_a33_full_validation_2026-09-02.txt`,
`../../benchmark/results/fhe_digiface_exact_frontier_a33_2026-09-02.md`,
`../../benchmark/results/fhe_digiface_exact_primary_a33_2026-09-02.md`,
`../../benchmark/results/fhe_digiface_exact_paired_a29_a33_2026-09-02.md`,
`../../benchmark/results/demo_e2e_exact_id_a33_frozen_2026-09-02.md`,
`../../benchmark/results/exact_id_a33_pfail_accounting_2026-09-02.md`,
`../../benchmark/patches/a33_aligned_sparse_source_2026-09-02.patch` e
`results/exact_id_uniform_threshold_fastpath_design_2026-09-02.md`.

### A34/A36, prossimo candidato non promosso

I prototipi isolati FHE di A34-top, scan/output a due nibble e selettore A36 sono positivi. Il
modello clear di componibilita' separa i conteggi per stadio e proietta, a N=127, **3.655 blind
rotation / 3.274 KS / 4.206 marginali** per A34 + A36 + radix-5, 618 BR meno di A33. Il numero e'
soltanto statico: non e' stato osservato in un singolo core Rust e mancano ancora fixture FHE
integrate, suite primaria, Docker, paired e accounting. Questa linea resta il prossimo candidato
da falsificare, non una baseline. Evidenza:
`results/exact_id_a34_a36_component_fhe_2026-09-02.md` e
`results/exact_id_a34_a36_composability_2026-09-02.md`.

### Conteggi della baseline precedente A28 e misure storiche del core condiviso

La formula deterministica dello snapshot bounded A28 conta, con soglia uniforme T=4,
2.814/5.600/5.640 PBS a N=64/127/128; gli upper bound per soglie arbitrarie sono
3.087/6.159/6.199. La suite cifrata completa N=127 ha concluso **632/632** output exact-ID uguali al
clear, zero discrepanze/errori, 632 probe e result ciphertext distinti e 131/131 autorizzazioni.
Tutte le query usano 5.600 PBS; i key switch uniformi sono 2.302/4.584/4.616. Il server ha mediana
7,45175 s e p95 8,0367 s in un run non isolato. A25, anch'esso a 5.600 PBS ma con 5.092 KS a
N=127, aveva mediana 7,51215 s in una finestra diversa: la differenza non e' una misura causale.
Report A28: `../../benchmark/results/fhe_digiface_exact_primary_split4_2026-09-02.md`. Il report
A25 e' preservato in `../../benchmark/results/fhe_digiface_exact_primary_optimized_2026-09-02.md`.
Lo stress mirato split4 passa 198/198 casi sotto tre chiavi fresche; resta evidenza empirica, non
un bound del `p-fail`: `results/exact_id_split4_boundaries_2026-09-02.md`.

I run pre-hardening preservati avevano invece misurato:

| N | caso | PBS storici | tempo core storico |
|---:|---|---:|---:|
| 64 | tre casi accept/reject e soglie per-template | 2.483 | **4,460-4,594 s** |
| 127 | pareggio tie-first, coda dispari | 4.919 | **8,010 s** |
| 128 | run avversari/reali precedenti | 4.949 | **9,488-11,223 s** |

In quei run tutti gli output provati coincidevano con l'oracolo clear. La forchetta storica N=128
dipendeva da carico, ordine e versione del percorso di estrazione: dimostrava fattibilita', ma non
autorizzava un bound worst-case inferiore a 10 secondi e non va attribuita agli snapshot A28/A29
o alla baseline A33. I
dettagli sono in
`results/private_argmin_core_2026-09-01.md`,
`results/argmin_bucket_bits_exact_norm12_2026-09-01.md` e
`results/argmin_bucket_bits_exact_split_2026-09-01.md`.

Il bridge storico modulo 16, incluso il layout duale nello stesso GLWE, e' stato provato con tre
chiavi, valori avversari e probe reali: 20.025 bit raw e 16.506 bit ricodificati senza errori
osservati. Vedi `results/score_mod16_lowbits_2026-09-01.md`. Questi smoke descrivono il circuito
allora misurato: sono evidenza empirica storica, non una misura del bridge bounded A28/A29 ne' una
prova formale della probabilita' di fallimento dell'intera composizione.

### E2E della baseline A33, N=127

Il gate Docker dedicato ricostruisce lo snapshot A33 congelato, vincola sorgenti, immagini,
PID 1, modello e dataset, poi attraversa embedding, cifratura, preload, endpoint, core e
decifratura:

| campione | esito |
|---|---:|
| 3 positivi | 3/3 apertura e identita' esatta |
| 3 negativi held-out | 3/3 rifiuto, nessun ID |
| contratto / PBS | `exact-open-set-id-v2` / 4.273/query |
| preload | 127 template in 92,3 s |
| server | mediana 13.030,5 ms |
| endpoint HTTP | mediana 14.779,938 ms |
| probe / pacchetto output | 32.840 / 16.464 byte |

Il report e' `../../benchmark/results/demo_e2e_exact_id_a33_frozen_2026-09-02.md`. Il carico host
era alto e le latenze Docker sono soltanto descrittive; il confronto relativo autorevole del run
resta il paired A29/A33 sugli stessi ciphertext. Il gate non pilota webcam/browser e non verifica
il rendering della UI.

### E2E dello snapshot generale A29, N=127

Le immagini Linux Docker sono state ricostruite e `benchmark/demo_e2e.py` ha attraversato
embedding, cifratura, preload, endpoint, core condiviso e decifratura:

| campione | esito |
|---|---:|
| 3 positivi | 3/3 apertura e identita' esatta |
| 3 negativi held-out | 3/3 rifiuto, nessun ID |
| contratto / PBS | `exact-open-set-id-v2` / 4.965/query |
| preload | 127 template in 39,7 s |
| server | 7,5621-9,1837 s; mediana 7,6868 s |
| endpoint HTTP | 7,994941-10,150079 s; mediana 8,195264 s |
| probe / pacchetto output | 32.840 / 16.464 byte |

Il report dello snapshot A29 e'
`../../benchmark/results/demo_e2e_exact_id_manylut_2026-09-02.md`. Il carico host era
estremamente alto e non isolato, quindi i tempi non sono una baseline. Lo script vincola il runtime
Docker ma non pilota webcam/browser e non verifica il rendering della UI.

Il run A28 precedente, anch'esso 6/6 ma a 5.600 PBS, resta nello storico:
`../../benchmark/results/demo_e2e_exact_id_split4_2026-09-02.md`. Il run A25, su immagini
diverse, resta a sua volta nello storico:
`../../benchmark/results/demo_e2e_exact_id_optimized_2026-09-02.md`.

### E2E storico pre-hardening del servizio exact-id, N=127

Il benchmark host `benchmark/demo_e2e.py`, con binario release/PID vincolati e cache di
calibrazione richiesta, ha attraversato embedding, cifratura, endpoint, core condiviso e
decifratura prima degli hardening successivi:

| campione | esito |
|---|---:|
| 3 genuine | 3/3 apertura e identita' esatta |
| 3 impostori held-out | 3/3 rifiuto, nessun ID |
| PBS | 4.919/query |
| server | 7,7557-8,6953 s; mediana 8,46805 s |
| endpoint HTTP | mediana 8,671392 s |
| probe / output | 32.840 / 16.464 byte |

L'output rimane un solo LWE. Il pacchetto Docker e' stato ricostruito e verificato anche nel
browser: identita' esatta sul positivo e `Negato / identita' non rilasciata` sul negativo. Gli
screenshot sono `demo/screenshots/exact-id-docker-2026-09-01.png` e
`demo/screenshots/exact-reject-docker-2026-09-01.png`.

Artefatto di sintesi: `benchmark/results/exact_id_end_to_end_2026-09-01.md`. Sei query sono una
prova funzionale storica del contratto operativo, non una misura degli snapshot bounded o della
baseline A33 ne' una stima
statistica di DIR/FPIR, errore biometrico o `p-fail`. I tempi Docker, influenzati dalla
virtualizzazione, non sono mescolati con quelli host.

Il validator `benchmark/fhe_digiface_validation.py` ora verifica `0/null` oppure l'indice exact-ID
contro l'oracolo clear. Lo smoke di frontiera pre-hardening comprendeva cinque impostori di tuning
e concordava **5/5** col clear: tre false accept biometrici a score 2/3/4, con lo stesso
indice/codice FHE e clear, e due rifiuti a score 5/7; il costo storico era 4.919 PBS/query. Non erano
tre identificazioni biometriche corrette. Le suite bounded A29 e A33 da **632 query** sono
concluse:
632/632 output FHE coincidono col clear, con 127/127 genuine identificate, 1/500 impostori primari
accettato e 3/5 frontiera accettati. Gli ultimi quattro sono false accept biometrici, non errori
FHE. A29 conta 4.965 PBS e A33 4.273 PBS sul fast path uniforme/allineato. Le figure
`benchmark/results/architettura.{png,svg}` e
`percorso.{png,svg}` rappresentano l'exact-ID e incorporano il punto E2E bounded A28 congelato,
non la baseline A33; in
`percorso` le curve precedenti restano storico esplicito.

### Limite di integrita' del protocollo

Il raw LWE e l'HTTP corrente non sono autenticati: il ciphertext e' malleabile e una risposta puo'
essere forgiata o riprodotta come codice accettato. Header, range, epoch e revisione sono controlli
di consistenza, non una MAC/firma. L'esperimento sostiene quindi il modello honest-but-curious con
trasporto fidato. Un deployment richiede TLS/mTLS, nonce per query e MAC/firma della risposta e
dello stato galleria; contro un server malevolo servono verificabilita' o attestation.

Il server registra lo SHA-256 della evaluation key, lo espone in `/stato` e rifiuta una chiave
diversa fino al riavvio. Questo pinning runtime server-side mitiga la sostituzione nello stesso
processo. Anche un confronto client con l'impronta locale prova soltanto l'uguaglianza dei byte,
non la relazione con la secret key. Non e' binding crittografico, autenticazione del protocollo o
prova dell'esecuzione corretta.

### Baseline A16/A19 scartata

Il periodic-fold a 3 PBS/template seguito da OR calcolava soltanto
`any_match = OR_i[score_i<=T_i]`. I suoi 400 PBS a N=127, replay 80/80 e run applicativo 20+20
restano artefatti storici validi per quella funzione. Non restituisce pero' l'identita' piu'
vicina e, con soglie per-template, non equivale a confrontare il vincitore con `T_k`: non e' il
percorso finale e i suoi tempi sub-secondo non vanno attribuiti all'argmin esatto.

La variante a 9 PBS/template, il candidato WoP-PBS a 14 PBS/template e il comparatore diretto a
un PBS restano route storiche/fallback, non il percorso exact-ID promosso.

## Registro storico precedente al contratto esatto

Le sezioni seguenti conservano la cronologia sperimentale e i relativi artefatti. Quando riportano
un PBS/template, 146/400 PBS nel servizio, un output `any_match`, una banda approssimata o una
latenza sub-secondo, descrivono il comparatore diretto o il successivo periodic-fold, entrambi
ritirati dal percorso finale. Non sono prestazioni o garanzie dell'identificazione esatta.

## 0. In chiaro prima: quanti bit del punteggio servono (`precisione_punteggio.py`, F36)

Embedding ResNet100 su VGGFace2, 4 bit, punteggio ⌊(s+C)/2^t⌋ troncato ai k bit alti, 20 scene.
La DIR@FPIR=1% non si muove fino a 4 bit; è la FPIR effettiva a degradare per i pareggi alla
soglia (8 bit: 1,1%; 5 bit: 2,4%; 4 bit: 8-54%). **Punto operativo: 8 bit** → `FheUint8`.

## 1. La selezione radix (`selezione.rs`, F38)

Punteggi casuali già in forma radix, argmin + soglia sul vincitore, 16 thread:

| param | N | seq-F32 (lt+min+select) | seq (lt+2 select) | **torneo** (livelli paralleli) | +soglia |
|---|---|---|---|---|---|
| def/u8 | 8 | 0,82 s | 0,61 s | **0,36 s** | 0,029 s |
| def/u8 | 64 | 7,36 s | 5,50 s | **2,32 s** | 0,028 s |
| def/u8 | 128 | 14,57 s | 10,81 s | **4,69 s** | 0,029 s |
| def/u16 | 8 | 1,12 s | 0,82 s | 0,57 s | 0,029 s |
| def/u16 | 64 | 10,23 s | 7,65 s | 4,55 s | 0,028 s |
| def/u16 | 128 | 20,78 s | 14,98 s | 9,07 s | 0,029 s |
| mb3/u8 | 128 | 8,27 s | 6,59 s | 4,84 s | 0,012 s |
| mb3/u16 | 128 | 14,88 s | 11,56 s | 9,86 s | 0,013 s |

(tabella completa in `results/selezione_16thread.txt`). Single-thread (`selezione_1thread.txt`):

| param | N | seq-F32 | seq | torneo | +soglia |
|---|---|---|---|---|---|
| def/u8 | 8 | 2,86 s | 2,43 s | 2,36 s | 0,041 s |
| def/u8 | 128 | 55,70 s | 48,20 s | 46,74 s | 0,040 s |
| def/u16 | 128 | 112,56 s | 94,18 s | 90,45 s | 0,070 s |
| mb3/u8 | 128 | 24,49 s | 21,09 s | 20,71 s | 0,018 s |
| mb3/u16 | 128 | 48,11 s | 40,04 s | 38,53 s | 0,030 s |

Su un thread il torneo non guadagna nulla (stesso lavoro, N−1 confronti) e il multi-bit vale
2,3× da solo; è la combinazione 16 thread + torneo a portare i 48 s della catena a 4,7 s (~10×).
Tutti gli esiti verificati contro il chiaro. Il torneo `FheUint8` sta nel target del prof (2,3 s
a N=64, 4,7 s a N=128), **ma presuppone i punteggi in forma radix**, cioè il ponte dal punteggio
leveled che coi parametri standard non c'è (F34).

## 2. Il varco senza ponte, storico pre-fold (`varco_leveled.rs`, F37)

Prodotto scalare leveled su LWE grezzi (0 PBS) + **un PBS di segno per iscritto** contro la
soglia, tutti in parallelo (profondità 1). Uscita: N bit (one-hot), oppure compatta: conteggio +
indice in binario (log N somme leveled). Scena reale (`esporta_dati.py`: ResNet100, VGGFace2,
4 bit, 128 iscritti, 64 probe genuini + 64 impostori, T al quantile 1% di 2000 impostori).

| N | dot (leveled) | KS+PBS ×N (16 thread) | **totale/query** | per PBS per thread |
|---|---|---|---|---|
| 8 | 0,001 s | 0,016 s | **0,017 s** | 32 ms |
| 16 | 0,002 s | 0,027 s | **0,029 s** | 27 ms |
| 32 | 0,002 s | 0,047 s | **0,049 s** | 23 ms |
| 64 | 0,005 s | 0,089 s | **0,094 s** | 22 ms |
| 128 | 0,007 s | 0,170 s | **0,177 s** | 21 ms |

Esattezza: **0 discrepanze su 31.744 confronti** cifrato/chiaro; esito per probe identico al
chiaro (58/64 genuini riconosciuti = 90,6%, 0/64 impostori accettati); uscita compatta corretta
128/128 a ogni N (0,2 ms).

Questa e le altre osservazioni di esattezza della sezione sono empiriche sui campioni storici,
quasi tutti lontani dalla soglia. L'audit successivo ha invalidato il comparatore diretto come
implementazione esatta del predicato inclusivo; i numeri restano misure pre-fold.

Single-thread (`RAYON_NUM_THREADS=1`): il PBS costa 13,5-13,9 ms l'uno (meno che a 16 thread, dove
i thread si contendono cache e E-core), e il totale scala lineare in N:

| N | 8 | 16 | 32 | 64 | 128 |
|---|---|---|---|---|---|
| totale/query, 1 thread | 0,114 s | 0,225 s | 0,446 s | 0,887 s | **1,764 s** |
| totale/query, 16 thread | 0,017 s | 0,029 s | 0,049 s | 0,094 s | **0,177 s** |

Il parallelismo dei confronti indipendenti vale ~10× (12 P-core + 4 E-core).

Scala (`scena_reale_1024.txt`, `varco_leveled_16thread_1024.txt`, F43): N=256 0,34 s, 512 0,70 s,
**1024 1,41 s**, 0 discrepanze su 131.072 confronti, esito per probe come in chiaro (96,9%).
Uscita compatta **a blocchi di 64** (conteggio + indice locale): 128/128 a ogni N; con le somme su
tutti gli N sbagliava 8/128 a N=1024 (rumore ~√N). PBS multi-bit (`--multibit`, `--mb-threads K`):
0,198 s (7 thread interni) e 0,210 s (1) contro 0,177 s del classico: nessun guadagno
(`varco_leveled_16thread_multibit.txt`).

### La banda di sfocatura (`banda_soglia.rs`, `effetto_banda.py`)

Il PBS di segno decide dopo il modulus switch a 2N, che aggiunge un errore ~√(n/24)·q/2N =
2^54,6. Misurato a cavallo di T (400 prove per d = s−T ∈ [−48, 48]): P(match | d) è una sigmoide
con σ ≈ 12 unità di punteggio a Δ_s = 2^51 (quella della scena reale; 6,5 a 2^52, 25 a 2^50),
esattamente 2^54,6 / 2^51. Sui dati reali non scatta: nelle 20 scene le coppie (probe, iscritto)
entro ±24 unità da T sono lo 0,003-0,006%, e simulando la sfocatura su tutte le decisioni la DIR
resta identica (92,9 / 92,9 / 92,3% a N = 64 / 128 / 1000) con FPIR 0,97-0,99% contro 1,00%.

## 3. La CLI a tre ruoli (`varco.rs`, F41)

`varco keygen <dir>` · `varco encrypt <dir> probe.txt probe.ct` · `varco server <dir> galleria.txt
probe.ct esito.ct` · `varco decrypt <dir> esito.ct`. Probe come un solo GLWE (encoding
polinomiale): **32.800 byte** invece di 8,4 MB; esito 229 KB (a blocchi di 64); chiavi 23 KB (client) e 130 MB
(server). Server 0,18 s a N=128 (16 thread). Esempio in `results/e2e/` (galleria.txt = scena
reale con LOG_DELTA=50, cioè |s−T| < 2^13 dichiarato): genuino → `{"conteggio": 1, "indice": 104}`,
impostore → `{"conteggio": 0}`.

## 4. Cosa rivela il bit (`attacco_oracolo.py`, F40)

Oracolo di appartenenza simulato in chiaro: con la distanza l'embedding esce esatto in 513 query;
col solo bit servono ~30.000 query per coseno 0,999 (1.000 per un vettore accettato), e solo
partendo da un probe già accettato (una foto dell'iscritto); da impostori o vettori casuali
20.000 query non producono un'accettazione. Mettere ‖v‖² nel punteggio (palla invece di
semispazio) non aiuta: coseno 0,995 in 10.000 query, perché l'attaccante conosce la norma del
proprio vettore e il punteggio resta lineare nelle incognite. Contromisura: rate limiting.

## 4b. Spremere i parametri, storico pre-fold (`--params`, F46)

Il PBS di segno vuole solo 1 bit di LUT: i set piccoli catalogati da tfhe-rs nel gruppo
`p_fail_2_minus_64` hanno polinomi piu' corti e un PBS piu' economico. Il target e' nominale per le
primitive supportate, non un bound del varco low-level composto. **MESSAGE_1_CARRY_1** (N=512):
N=128 **0,100 s**, N=1024 **0,72 s** (~2× sul default), con 0 errori osservati su 131.072 confronti
a N=1024; nella simulazione di `effetto_banda.py` la DIR resta invariata con σ≈50, anche a σ=100.
`2_1` sta in mezzo (0,134 s a N=128, σ≈30). `2_0`/`1_0` (N≤512, GLWE rumoroso) crollano: banda
~1900, metà confronti errati - il varco vive del budget di rumore leveled. Il numero finale del
sistema: **0,10 s a N=128, 0,72 s a N=1024**. `results/varco_leveled_16thread_params.txt`,
`banda_soglia_{1_1,2_1}.txt`. Non spremuto: GPU con tfhe-rs (lotto di N PBS indipendenti; serve NVIDIA).

## 4c. Il fondo locale, storico pre-fold: 3 bit e il muro spiegato (`esporta_dati.py N 3`, F47)

3-bit quant dimezza il range -> Delta da 2^51 a 2^53. Set 1_1 a 3 bit: N=1024 0,83 s, **0 discrepanze**,
banda dimezzata (sigma ~11 a Delta=2^53, vedi F50) a costo zero, accuratezza in chiaro identica. 2_0/1_0 restano rotti:
non per Delta ma per la **box size del PBS** = N/message_modulus, la ridondanza contro il rumore del
modulus switch. Nel campione storico 1_1 (N=512, box 256) e' il piu' piccolo set con zero
discrepanze osservate; sotto la scatola scende a 128 e crolla. Punto operativo dichiarato allora:
**3 bit, set 1_1, 0,10 s a N=128, ~0,8 s a N=1024, banda sigma~4, zero discrepanze osservate**.
Leva ancora aperta ovunque: GPU (lotto di N PBS, serve NVIDIA). Questo era il punto
operativo dichiarato prima dell'audit della frontiera e non e' il comparatore corrente.

## 4d. Il bilancio del rumore (`rumore.rs`, F50)

Misurato tappa per tappa (400 campioni, Delta=2^52): GLWE fresco 2^15,7 -> dopo il prodotto scalare
leveled 2^22,2 (x92,7, atteso ||p||=90,5) -> dopo il keyswitch 2^56 -> col modulus switch 2^56,5.
**L'accumulo leveled contribuisce 2^-34 della varianza**: la banda viene tutta da keyswitch e
modulus switch, cioe' dalle tappe che qualunque PBS fa comunque. Regola in forma chiusa:
**banda ~ range/90** (set 1_1) e ~range/360 (set 2_2), quindi banda ∝ 1/N - il rapporto 22,5/4,9
misurato coincide con 2048/512. Probabilita' d'errore a distanza d dalla soglia: 1,3e-2 a d=50,
4e-6 a d=100, 3e-19 a d=200; sui dati reali le distanze sono 300-3600.

## 4e. Galleria CIFRATA a costo leveled (`galleria_cifrata.rs`, F51)

GGSW(template) (x) GLWE(probe) = prodotto scalare su galleria **cifrata**, leveled. GGSW polinomiale
costruita a mano sulla formula di tfhe-rs (la libreria cifra solo costanti) e verificata decifrando.
Varco completo sulla scena reale: **0,094 s a N=128** (contro 0,10-0,12 s con galleria in chiaro),
**2048/2048 decisioni corrette**, banda aggiunta ~0 col gadget 2^10x3 (0,10 unita' col 2^12x2, 200 KB).
Il prodotto scalare passa da 11 ms a 1,1 ms (FFT invece di Karatsuba). Prezzo: 200-300 KB per
iscritto (37 MB a N=128) invece di 4 KB. Mondo 2 senza cambiare schema e senza cifrato x cifrato.

## 4f. Torneo con circuit bootstrapping, storico noisy (`argmin_torneo.rs`, F52)

`circuit_bootstrap_boolean` (LWE -> GGSW) rende possibile il CMUX, quindi il torneo: N-1 confronti
invece di N^2/2. Candidato = un GLWE con il punteggio al coeff dim-1 e l'indice al coeff N-1 (dove il
prodotto e' zero). Serve un PBS di segno PRIMA del circuit bootstrap. Parametri LEGACY_WOPBS.
**1,32 s a N=128** (contro 14,4 s della matrice, F45), 0,75 s a N=64. Il run storico dava 69/80
indici e 31/31 nei casi con minimo sotto soglia, ma gli stress domain-safe successivi hanno dato
soltanto 12/32-20/32 decisioni finali corrette. La parola «esatto» e' quindi ritirata per questo
torneo. Con `--cifrata` la misura storica era **1,21 s a N=128**; non dimostra un'identificazione
open-set affidabile.

## 4g. Correzione storica pre-fold (F55): il "muro" di 4b/4c non esiste

Una revisione critica ha mostrato che l'inferenza di F47 era un artefatto (1878/344 = 5,459 = il
rapporto fra i RANGE delle due scene, non una banda) e che la box size non c'entra (l'accumulatore e'
costante: `message_modulus` non entra nel circuito). La causa vera dei ~20% di errori dei set 2_0/1_0
e' il rumore in USCITA del PBS (~2^54) contro il margine 2^55 imposto da `LOG_DO = 56`. Alzando il
margine (`--log-do 60 --blocco 8`) quei set diventano esatti E sono i piu' veloci:

| set | N=128 | N=1024 | N=4096 | errori |
|---|---|---|---|---|
| 1_1 (il preteso muro) | 0,089 s | 0,72 s | 3,07 s | 0 / 3 a N=4096 |
| **1_0 (N=256)** | **0,064 s** | **0,505 s** | **2,073 s** | **0 / 524.288** |

Il PBS scende da 12 a 7,6 ms. Vincolo: 1_0 ha N=256 < dim 512, quindi il probe polinomiale compatto
(F41) va spezzato in due GLWE; con un solo GLWE serve 1_1.

## 5. La strada del ponte (`pbs_largo.rs`, `argmin_delta.rs`, F45)

PBS largo (unità di costo del ponte), un thread: 4 bit / N=2048 **13,9 ms**; 8 bit / N=32768
**548 ms** (chiave 2,2 GB); 13-14 bit senza set validati (Concrete: 1,5-4 s). Ponte a N=128 stimato
60-70 s. Argmin esatto senza ponte (matrice dei confronti a coppie, `argmin_delta_16thread.txt`):
0,09 s (N=8), 0,97 s (32), **3,66 s (64)**, **14,4 s (128)**, 10.816 PBS a 128; match sempre
giusto, vincitore esatto quando il minimo dista dal secondo più della banda (σ≈25 a Δ=2^50).

## Riprodurre

```
cargo test --lib                           # dominio, LUT, tie-first, soglie per-template, PBS count
cargo test --bin argmin_bucket_bits_periodic
cargo test --release --bin varco_demo      # wire e servizio exact-id
RAYON_NUM_THREADS=16 cargo run --release --bin argmin_bucket_bits_periodic -- \
  --run --keys 1 --sizes 64 --cases all --real-probes 1
RAYON_NUM_THREADS=16 cargo run --release --bin argmin_bucket_bits_periodic -- \
  --run --keys 1 --sizes 127 --cases tie --real-probes 1
cargo test --bin score_mod16_lowbits
cargo run --release --bin score_mod16_lowbits -- --run --keys 3 --n 128 --probes 4

# Da qui in poi: riproduzioni storiche, non il contratto exact-id corrente.
cargo test --release --bin exact_comparator_scratch
uv run python precisione_punteggio.py      # F36, ~30 s
uv run python esporta_dati.py              # scena reale per i binari Rust
cargo run --release --bin selezione        # F38, ~4 min a 16 thread
cargo run --release --bin varco_leveled    # F37, ~1 min  (args: [scena] [N_min] [--multibit] [--mb-threads K])
uv run python esporta_dati.py 1024 && cargo run --release --bin varco_leveled -- results/scena_reale_1024.txt 256   # F43, ~6 min
cargo run --release --bin varco_leveled -- results/scena_reale_q3.txt 128 --params 1_0 --log-do 60 --blocco 8   # F55, il piu' veloce
cargo run --release --bin banda_soglia     # banda, ~3 min
uv run python effetto_banda.py             # effetto della banda, ~1 min
RAYON_NUM_THREADS=1 cargo run --release --bin <bin>   # versione seriale
uv run python attacco_oracolo.py                # F40, ~40 s
cargo run --release --bin argmin_delta -- results/scena_reale.txt 8 16   # F45, ~5 min
cargo run --release --bin pbs_largo             # F45, ~6 min
cargo run --release --bin rumore -- --params 1_1 --log-delta 52   # F50, bilancio del rumore, ~1 min
cargo run --release --bin galleria_cifrata                        # F51, galleria cifrata, ~2 min
cargo run --release --bin argmin_torneo -- --probe 16 [--cifrata]  # F52, argmin esatto a torneo, ~5 min
cargo run --release --bin varco_leveled -- results/scena_reale.txt 8 --params 1_1   # F46, varco 2x
cargo run --release --bin banda_soglia -- --params 1_1 --d 200                      # F46, banda del set 1_1
cargo run --release --bin varco -- keygen results/e2e/chiavi   # poi encrypt/server/decrypt (F41)
```

Su macOS, se Concrete cerca un SDK inesistente, usare il
[wrapper del linker](../../tools/README.md).
