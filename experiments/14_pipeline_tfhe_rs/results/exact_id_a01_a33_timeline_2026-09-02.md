# Da A01 ad A33: timeline auditata dell'identificazione cifrata

Data dell'audit: 2026-09-02.

## Risposta breve

Le sigle A01--A33 non indicano trentatre release successive. A01--A22 sono in gran parte audit di
sicurezza, controesempi, baseline che restituiscono soltanto un bit e route alternative rimaste
incomplete o troppo lente. **A23 e' il primo checkpoint che soddisfa il requisito applicativo
completo**:

```text
server: primo argmin esatto sotto cifratura
       -> soglia inclusiva applicata soltanto al vincitore
client: un solo ciphertext che decodifica 0 oppure indice+1
```

Quindi l'identita' piu' vicina viene restituita quando il vincitore e' autorizzato; un rifiuto
restituisce soltanto `0` e non espone il nearest ID. A25, A28, A29 e A33 mantengono questa stessa
semantica e intervengono sul costo o sulla robustezza. A33 porta il fast path uniforme/allineato da
7.804 a 4.273 blind rotation/PBS rispetto ad A23 (`-45,246%`), mentre A29 resta il fallback
generale fail-closed.

## Regole di lettura dell'evidenza

- **Esatto** significa concordanza osservata col primo argmin intero e la soglia del suo solo
  vincitore; non significa accuratezza biometrica perfetta. Un falso accept gia' prodotto
  dall'oracolo biometrico resta un falso accept anche se FHE lo riproduce esattamente.
- **Privato al confine applicativo** significa che probe e risposta attraversano il confine
  client/server cifrati e che la risposta contiene solo `0`/ID. Non prova circuit privacy, non
  cifra la galleria rispetto al server e non dimostra che un probe arbitrario sia un volto.
- I conteggi PBS/BR e KS sono strutturali. I tempi di run separati sono osservazioni locali sotto
  carichi diversi; solo i benchmark appaiati A28/A29 e A29/A33 sostengono un confronto relativo.
- Un test empirico senza errori non e' un bound della probabilita' di failure crittografica
  composta.

## A01--A15: chiusura delle assunzioni sbagliate e route esplorative

| ID | Che cosa cambia | Semantica e privacy | Evidenza / decisione |
|---|---|---|---|
| A01 | La scala `Delta` non puo' essere scelta dal solo range osservato. | Un probe ammesso puo' attraversare il semitoro e invertire il segno. | **Invalidata**; i vecchi tempi restano soltanto honest-client. |
| A02 | Il guard di enrollment deve includere anche `norm2(g)`, non solo massimo e norma L1. | Il vecchio guard accettava template il cui bound superava il raggio cifrabile. | **Invalidata e corretta**; controesempio con bound 5.423 contro raggio 4.095. |
| A03 | La scala dell'argmin deve coprire `score_i-score_j`, non soltanto `score_i-T_i`. | Il vecchio bound 3.646 non copriva l'inviluppo a coppie 4.262. | **Invalidata**; il vecchio `Delta=2^51` non copriva il dominio promesso. |
| A04 | Si prova un torneo con circuit bootstrap e scala pairwise-safe. | Cerca l'indice, ma il cammino CMUX rumoroso non conserva decisione e indice insieme. | **Negativa per quella costruzione**: a `N=128`, un run fa 32/32 indici ma 20/32 decisioni; un altro 30/32 e 12/32. Il cap L1=110 fa 31/32 indici ma 16/32 decisioni. Tempi contaminati. |
| A05 | Si considera di restituire tutti gli `N` bit di appartenenza. | E' un oracolo piu' ricco del risultato del varco: rivela posizioni e molteplicità. | **Invalidata come protocollo di produzione**; ammessa solo in diagnostica esplicita. |
| A06 | Si prova il singolo bit `count == 1`. | Non equivale a `min(score)<=T`: rifiuta anche due template entrambi validi. | **Invalidata semanticamente**; resta solo una diagnostica. |
| A07 | Si tenta una soglia unica tra DigiFace e iscrizioni reali/webcam. | Trasferisce un operating point tra domini non validati. | **Invalidata**: `T=4` DigiFace e mediana `T=273` sui sette split VGGFace2 non sono intercambiabili. |
| A08 | Prima baseline CKKS con segno polinomiale. | Route approssimata, non exact-ID end-to-end. | **Provvisoria**: a `N=128`, circa 0,9969 s score + 0,048 s soglia, 0/512 discrepanze sui quattro probe provati; range e campione non bastano. |
| A09 | Packing CKKS ibrido per ridurre le rotazioni dello score. | Misura soltanto lo scoring, senza decisione discreta o protocollo `0`/ID. | **Provvisoria**: 10 rotazioni/0,966 s contro 39/3,583 s su un probe; picco processo 6,178 GiB durante i keygen. |
| A10 | Si tenta di salvare il comparatore diretto ritarando `Delta`. | Una guard band cambierebbe la semantica e richiederebbe nuova calibrazione. | **Negativa come drop-in**: il primo punto campionato senza errori e' `log2 Delta=58`, ma ammette raggio 31 contro bound 3.690. |
| A11 | Si tenta di ridurre la dimensione dell'embedding per ridurre il tempo. | Non modifica necessariamente la precisione richiesta dalla selezione; puo' perdere accuratezza. | **Provvisoriamente negativa**: un solo campione per dimensione e riga 64-D errata impediscono una conclusione generale. |
| A12 | Si considera BatchBoot prima dei PBS individuali. | Richiede un bridge da LWE indipendenti a RLWE packed con segreto sparso. | **Aperta**, non un circuito exact-ID implementato e non un confronto matched. |
| A13 | Si prova CKKS packed -> scheme switching FHEW. | La decisione discreta arriva dopo score CKKS approssimati, quindi non e' exact-ID intero end-to-end. | **Provvisoriamente negativa su CPU**: a 16 slot, compare 32,1 s keygen + 44,4 s eval; min/indice 31,8 + 69,2 s; circa 8,4--8,7 GB RSS. |
| A14 | Si prova la route CKKS BSGS-Diagonal di FastHE-Search. | Cambia backend e workload; l'open-set negativo deve essere corretto prima del confronto. | **Provvisoria di sessione**: i positivi CPU sono trovati, ma i negativi `N=128/1.024` danno `membership=true` e indice vuoto; GPU NVIDIA non disponibile e artefatti grezzi insufficienti per attribuire la causa. |
| A15 | Si separa il bound numerico dalla provenienza del probe. | `q` bounded evita overflow, ma non prova che `q` derivi dalla telecamera/modello autorizzati. | **Aperta**: servono terminale fidato, attestazione o prova del preprocessing per client arbitrari. |

## A16--A22: il gate veloce funziona, ma non restituisce l'identita'

| ID | Che cosa cambia | Semantica e privacy | Evidenza / decisione |
|---|---|---|---|
| A16 | Il server restituisce un solo bit cifrato `count>0`. | Riduce il leakage, ma non identifica il nearest template; con soglie per-template non equivale neppure a sogliare solo il vincitore. | **Ritirata come finale**, conservata come baseline membership. |
| A17 | Comparatore diretto TFHE a un PBS/template, `Npoly=2048`, `Delta=2^51`. | Il gate e' veloce ma il segno vicino a `T` e' quasi casuale. | **Invalidata e ritirata**: sui minimi 2/3/4/5/7 ottiene 15/25, 10/25, 13/25, 13/25, 9/25 accept; 146 PBS a `N=127` appartengono solo a questo percorso pre-fold. |
| A18 | Comparatore multi-cifra con sette low bit WoP-PBS e segno del residuo. | Rende affidabile il predicato provato, ma resta un comparatore/gate e non il contratto exact-ID. | **Ritirata**: 200/200 ciphertext freschi e 1.016/1.016 output a `N=127`; circa 14 PBS/template, 3,743--4,872 s per 127 soglie e 195.510.272 byte di chiavi aggiuntive. |
| A19 | Due fold periodici (`P=32,512`) e segno finale. | Il predicato finito `score<=T` e' corretto nei test, ma l'uscita resta soltanto membership. | **Baseline ritirata dal finale**: 400 PBS a `N=127`; regressione 80/80; E2E 20/20 aperture + 20/20 rifiuti; mediana server 647,55 ms. Non e' confrontabile con exact-ID. |
| A20 | Comparatore alternativo a 9 PBS/template. | Ancora solo threshold per-template; non sceglie l'identita'. | **Ritirata/fallback storica**, non integrata nel finale. |
| A21 | Scheme switching CKKS diretto con solo output globale. | Produce il bit discreto sui due vettori, ma non include scoring né exact-ID. | **Negativa**: 30,4695 s senza match e 35,2800 s con match, 35,794 s di evaluation-key generation, 6,603 GB RSS. |
| A22 | CKKS aggregate-first prima di un unico switch. | Esegue soltanto il prefisso numerico; mancano scoring e switch/segno finale. | **Provvisoria**: 3,574--3,864 s e 4,55 GB RSS; non e' una pipeline 1:N completa. |

La conseguenza e' importante: i circa 0,65 s di A19 non erano una soluzione piu' veloce dello
stesso problema. Erano il tempo di una funzione piu' debole, `qualcuno passa la soglia?`, che il
requisito di identificazione ha poi escluso.

## A23--A33: nascita e ottimizzazione del vero exact-ID

| ID | Modifica | Contratto / correttezza | Costo e misura | Stato |
|---|---|---|---|---|
| A23 | Argmin bucket-bit esatto a 12 bit; vista full + modulo 16; first-min; selezione del solo `T_k`; codice unico. | **Primo checkpoint completo** `0`/`k+1`, tie-first e nearest ID soltanto sugli accept. Suite `632/632`, 131/131 autorizzazioni, zero errori/discrepanze; Docker 3/3 ID + 3/3 reject. | `3.934/7.804/7.852` PBS a `N=64/127/128`; mediana primaria `15.882,65 ms`, run non isolato. | Promosso storicamente, poi superato. |
| A24 | Si tenta di ricostruire i low bit riusando correzioni/centrature approssimate. | Produce errori nascosti sui low bit; non conserva exact-ID. | Nessuna misura promossa. | **Negativa**; resta il canale modulo 16 indipendente di A23. |
| A25 | Stato candidato alternato `-1/0/+1`, scan in gruppi di tre, output radix-8. | Stesso exact-ID; suite `632/632`, 131/131, zero errori/discrepanze; Docker 6/6. | `5.600` PBS e `5.092` KS a `N=127`; mediana `7.512,15 ms`. Il confronto con A23 e' fra run separati, quindi non causale. | Snapshot funzionalmente promosso, poi superato. |
| A26 | Correzione della LUT per lo stato torus `-Delta`: `f(15)=-1`, non `f(15)=+1`. | La prima variante rifiutava deterministicamente gli accept su cinque chiavi; la correzione ripristina il Booleano `+1`. | Bug semantico riprodotto e corretto, non ottimizzazione temporale autonoma. | **Invalidazione interna e fix** della costruzione A25. |
| A27 | Batch PBS, upgrade tfhe-rs e POC common-mask. | Nessuno implementa ancora riduzioni cross-slot + exact-ID completo. | Batch seriale circa 10x peggiore del parallelismo esterno; upgrade 0.11.3->1.7 circa 4% nel microbenchmark; il primo POC common-mask non decifra/consuma abbastanza da provare speedup end-to-end. | **Aperta**, non promossa. |
| A28 | Split4 robusto: low modulo 16, quattro correzioni full, poi high bits. | Stesso exact-ID; boundary `198/198` su tre chiavi, primaria `632/632`, Docker 6/6. | PBS invariati a `5.600`; KS `5.092 -> 4.584` (`-508`). Mediana `7.451,75 ms`, non paired con A25. | Baseline precedente congelata. |
| A29 | Una blind rotation con due sample extraction fonde correction full e bit Booleano per `b3..b6`. | Stesso exact-ID generale; boundary `198/198`, matrice semantica `198/198`, primaria `632/632`, Docker 6/6. | `4.965` PBS / `4.584` KS. Paired A28/A29: 60 misure + 12 warm-up, 0 mismatch, `-8,876%` latenza geometrica, CI95 `[8,092%,9,728%]`, 57/60 vittorie. Primaria separata: mediana `6.851,8 ms`. | **Fallback generale corrente**. |
| A30 | Torneo pubblicato/prior art a tre limb da 4 bit, con label stabile. | Conferma che argmin TFHE generico e tie-first non sono claim di novita'; mancano bridge, soglia del vincitore e protocollo locale. | Proiezione `1.387 PBS + 1.002 PFKS` a `N=127`, escluso score->limb; nessun core locale validato. | **Aperta** come fallback/prior art. |
| A31 | Fast path per soglia uniforme: normalizzazione `K=991`, poi variante allineata `K'=1023`. | Il modello clear conserva first-min, soglia del vincitore e `0`/ID; fallback obbligatorio se soglie/dominio non rispettano i vincoli. | Clear: 4.096/4.096 valori e 100.000/100.000 gallerie; proiezione documentata `4.373 PBS / 3.992 KS` a `N=127` per `K=991`. Nessun timing FHE. | Design clear; variante allineata assorbita da A33. |
| A32 | Route LFBS/OpenFHE per LUT esatta 12->12 bit. | Il dato pubblicato non include scoring, minimum+label, soglia del vincitore o `0`/ID. | `1,12 s` e fattori pubblicati non sono trasferibili; nessun benchmark locale matched. | **Aperta**, non implementata. |
| A33 | Fast path allineato con accumulatore sparso raw/custom `p=8`, due uscite correlate e canonicalizzazione per coppia. | Stesso exact-ID completo. Il planner lo usa solo con soglia uniforme, offset checked e dominio coperto `<=4096`; altrimenti dispatch fail-closed ad A29. Primaria `632/632`, 131/131; Docker 6/6. | `4.273` BR/PBS, `3.892` KS, `4.908` marginali conservative. Paired A29/A33: 120 misure + 24 warm-up, zero mismatch, `-13,734%`, CI95 `[11,806%,15,595%]`, 105/120 vittorie. Primaria separata `8.458,2 ms` sotto carico eccezionale. | **Baseline sperimentale corrente del fast path**; A29 resta fallback generale. |

## Progressione quantitativa del solo percorso exact-ID

Tutti i punti sotto hanno la stessa semantica applicativa a `N=127`; il confronto strutturale e'
quindi legittimo. Le mediane assolute restano run separati.

| snapshot | PBS/BR | KS strutturali | primaria FHE=clear | mediana server osservata | cambiamento strutturale principale |
|---|---:|---:|---:|---:|---|
| A23 | 7.804 | non congelate qui | 632/632 | 15,883 s | primo exact-ID completo |
| A25 | 5.600 | 5.092 | 632/632 | 7,512 s | `-2.204 PBS` (`-28,242%`) vs A23 |
| A28 | 5.600 | 4.584 | 632/632 | 7,452 s | PBS uguali; `-508 KS` (`-9,976%`) vs A25 |
| A29 | 4.965 | 4.584 | 632/632 | 6,852 s | `-635 PBS` (`-11,339%`) vs A28 |
| A33 | 4.273 | 3.892 | 632/632 | 8,458 s | `-692 PBS` (`-13,938%`) e `-692 KS` vs A29 |

Da A23 ad A33 il circuito uniforme/allineato rimuove **3.531 PBS/BR su 7.804**, cioe'
**45,246%**, senza cambiare `0`/ID, first-min o soglia del vincitore. La mediana A33 piu' alta di
A29 nel run primario non smentisce il miglioramento: quel run A33 era sotto carico eccezionale. Il
confronto appaiato sugli stessi byte cifrati misura invece A33 piu' veloce del 13,734% geometrico
nel campione e mostra una differenza di appena 0,203 punti rispetto alla riduzione strutturale dei
blind rotation.

## Che cosa e' davvero privato, e che cosa resta aperto

| proprieta' | A16/A19 | A23--A29 | A33 |
|---|---|---|---|
| server calcola senza ricevere il probe in chiaro | si | si | si |
| identita' nearest corretta su un accept | **no**, solo bit | si | si |
| nearest ID nascosto su un reject | si, perche' non esiste nell'output | si, output `0` | si, output `0` |
| soglia applicata soltanto al winner | no con soglie per-template | si | si |
| fallback per soglie arbitrarie valide | n/a | A29 | A29 fail-closed |
| galleria nascosta al server | no | no | no |
| provenienza biometrica di un probe remoto provata | no | no | no |
| circuit privacy / `p-fail` end-to-end certificata | no | no | no |

Per A33 il conteggio condizionale ricostruisce 4.273 blind rotation, 3.892 KS e 4.908 marginali.
Applicare meccanicamente il `p_fail` nominale darebbe `log2 <= -59,563966` sui BR oppure
`-59,364080` sulle marginali, ma **non e' un certificato end-to-end**: il decode lineare finale a
`Delta=2^56` non e' valutato e le primitive raw/custom richiedono ancora un argomento sul rumore
raggiungibile e sulle uscite correlate.

## Fonti verificate e digest correnti

Il registro `attempts.md` e' stato usato come indice, poi i passaggi quantitativi sono stati
controllati sui report e sui JSON congelati. I digest seguenti identificano i byte letti durante
questo audit:

| fonte | SHA-256 | uso |
|---|---|---|
| `attempts.md` | `315af08b7bc7ab148a344dc23e8baab615060ed732ea429a273130e18e1ce87c` | mappa A01--A33 e stati |
| `experiments/14_pipeline_tfhe_rs/results/argmin_pairwise_safe_2026-09-01.txt` | `8d31ae6aabf34e64a66070a625298abbede2e280a2516666c7620663fe5aa8f4` | A04, primo run pairwise-safe |
| `experiments/14_pipeline_tfhe_rs/results/argmin_torneo_q3_pairwise_safe_2026-09-01.txt` | `1ab2d293fb660e255e5ed386492a0a01bb7477232d0b113cf12b7759d3b5f25a` | A04, replica q3 |
| `experiments/14_pipeline_tfhe_rs/results/argmin_torneo_qm3_cap110_pairwise_safe_2026-09-01.txt` | `0c3b7ae27e01765578005b59b60549e642b28af7c635bad592f30aca321c6b14` | A04, cap L1=110 |
| `experiments/15_ckks_confronto/results/ckks_rerun_2026-09-01.md` | `b388b35b059e2e663c25de8702699ba6c50e2c5a16ac1c269ed65c88627a3d54` | A08, A09 |
| `benchmark/results/protocol_boundary_audit_2026-09-01.md` | `bb46efbbff570d2ec6aacc8e5ab0212060675885cba68f0a8e1b5b5ac1c78084` | A10, A17, A19 |
| `benchmark/results/exact_comparator_scratch_2026-09-01.md` | `696b7161149abf8dd41132df24e6f82f958b7d9715061ffd62825fba844a3cc9` | A18--A20 |
| `benchmark/results/external_routes_2026-09-01.md` | `f33689fe3c106da0a71e8b6b7aa062f540e23eea29e2d1338ba23e103a9a02bc` | A13, A14, A21, A22 |
| `experiments/16_common_mask_poc/results/2026-09-02_common_mask_primitives.txt` | `e577eef5c5b0873291149938e9ab3343bd26b50555bd0c53a1d12f7d2c292797` | A27 common-mask |
| `benchmark/results/fhe_digiface_exact_primary_noise_bounded_2026-09-01.json` | `b6e54b92bef8f53c0ce057f1e68e9b473487fdd423776962579661669d4fa512` | A23 primaria |
| `benchmark/results/fhe_digiface_exact_primary_optimized_2026-09-02.json` | `a322ee946b6f5f7a031d1f59f6e9a5ae26cc42b642333295526aa7b9a6e7a009` | A25 primaria |
| `benchmark/results/fhe_digiface_exact_primary_split4_2026-09-02.json` | `683fdf98ccc5dc45222c0b51b4b3ce678e3b5bd1aa9d9fbc10ed67fcb5108465` | A28 primaria |
| `benchmark/results/fhe_digiface_exact_primary_manylut_2026-09-02.json` | `328964c860919cfce2ae09ec3ac1e2ab1f3efcc7d25c1a9781ee1ee7dafa0b34` | A29 primaria |
| `benchmark/results/fhe_digiface_exact_paired_a28_a29_2026-09-02.json` | `590a6256bbd895780fa643a6497ca8bf8f2f710231ec2cded2cc56fb2aaf6f44` | speedup paired A29 |
| `experiments/14_pipeline_tfhe_rs/results/exact_id_uniform_threshold_fastpath_design_2026-09-02.md` | `3fbf444425f86bc5fe2a0b599914ba47588b9fd5a750dda772768d2072417a90` | A31 e costruzione A33 |
| `benchmark/results/fhe_digiface_exact_primary_a33_2026-09-02.json` | `e3ef7b5ae74c85e883d8ed3b2670fb6efbd20291775752fefe1ec56c0f1a9467` | A33 primaria |
| `benchmark/results/fhe_digiface_exact_paired_a29_a33_2026-09-02.json` | `659a996f5094112b3ea34ee3306a65bf03c8b308cd0d212c597890fc6fd71b8d` | speedup paired A33 |
| `benchmark/results/demo_e2e_exact_id_a33_frozen_2026-09-02.json` | `b94020132f369d10d60bf6201ef42337f29a84f525feaae94694166b97072d81` | integrazione Docker A33 |
| `benchmark/results/exact_id_a33_pfail_accounting_2026-09-02.json` | `0cfd431534d093d1ba7aeea79a5be0e4a611d2b2380e76e8fbecc8e8237bf54f` | limiti formali A33 |

## Conclusione auditata

La storia difendibile non e' “A01 era lenta e A33 e' veloce”. E' questa:

1. A01--A15 hanno mostrato che range osservati, guard incompleti, output troppo ricchi e backend
   non matched non bastano.
2. A16--A22 hanno prodotto un gate membership rapido e comparatori interessanti, ma la funzione
   era quella sbagliata per il requisito: mancava l'identita' piu' vicina.
3. A23 ha chiuso per la prima volta la semantica exact-ID privata `0`/ID.
4. A25/A28/A29 hanno ridotto costo e fragilita' senza cambiare quella semantica.
5. A33 specializza in sicurezza il caso uniforme/allineato, misura un ulteriore vantaggio paired e
   mantiene A29 per tutto cio' che non soddisfa i suoi vincoli pubblici.

Quindi A33 e' un avanzamento reale e misurato del prototipo exact-ID, non una scorciatoia che torna
al solo bit. Restano aperti il certificato `p-fail` end-to-end, circuit privacy, integrita' del
probe arbitrario, privacy della galleria rispetto al server e un claim di novita' piu' ampio del
co-design applicativo specifico.
