# Audit statico upgrade TFHE-rs 0.11.3 -> 1.7.0 per exact open-set ID (A38/A41)

Data: 2026-09-02. Snapshot analizzato alle `2026-09-02T14:17:58Z`.

## Esito in breve

L'audit non giustifica la sostituzione del runtime A38. TFHE-rs 1.7.0 non
offre un `argmin` exact pronto. Le API CPU `min_parallelized` e `first_index_of_parallelized`
utili a comporlo esistevano gia' in 0.11.3, e la release 1.7 non dichiara un'accelerazione del PBS
classico CPU.

L'audit propone un port e un benchmark isolati, per fasi e con pin esatti, per valutare:

1. i parametri moderni p16/p128 con centered-mean noise reduction (CMNR), che migliorano di circa
   58 bit il termine nominale del union bound rispetto al parametro p16/p64 corrente;
2. il backend CPU stabile `KeySwitch32` (KS32), assente in 0.11.3, che mantiene il PBS a output
   `u64` ma esegue KS e ingresso PBS in `u32`; il payload teorico delle chiavi valutative scende da
   123.69 MiB a 86.09 MiB (`-30.39%`) rispetto al parametro corrente;
3. il simulatore di rumore core-crypto, utile come controllo analitico del circuito, ma non come
   certificato end-to-end per i riusi correlati di A38;
4. due primitive sperimentali, common-mask LWE ed extended PBS, da provare soltanto dietro gate
   separati. Nessuna delle due implementa la selezione cross-slot/first-winner richiesta.

La priorita' consigliata e': **port same-parameter -> p128 Standard/CMNR -> p128 KS32 -> solo dopo
common-mask o extended PBS**. In questo modo non si confondono effetto della versione, effetto dei
parametri e cambiamento di algoritmo.

## Legenda epistemica

- **Evidenza**: osservata nei sorgenti locali, negli artefatti del repository o nella release
  ufficiale.
- **Inferenza**: conseguenza diretta dell'API, delle dimensioni o della struttura del circuito, ma
  non ancora misurata sull'exact-ID completo.
- **Ipotesi**: possibile vantaggio che richiede compilazione, chiavi effimere e benchmark futuro.

L'analisi e' statica: non comprende nuove compilazioni, esecuzioni FHE, generazioni di chiavi
o prove Docker.

## Contratto della baseline

A38 implementa il protocollo completo di identificazione:

- `0 = reject`;
- `i+1 = identita' iscritta esattamente piu' vicina`;
- a parita' vince la prima identita';
- la soglia viene applicata al punteggio vincente;
- il server non decifra intermedi.

A `N=127`, il grafo A38 eseguito conta 3,655 blind rotation, 3,274 key switch e 4,206 output
marginali conservativi. Il componente ha passato 29/29 fixture FHE; i tempi diagnostici non
triviali erano circa 6.71--8.46 s, ma non sono un benchmark paired o primario. A38 non era ancora
promosso rispetto ad A33 nel report congelato.

Il percorso formale successivo A41 propone due output terminali p16 `(low, high)` a
`Delta=2^59`. La variante terminal-only conserva i conteggi A38; la schedule prudente raw-L1,
ancora solo modellata, porta `N=127` a 3,909 BR, 3,528 KS e 4,460 marginali.

## Versioni e compatibilita' toolchain

| elemento | evidenza statica |
|---|---|
| progetto | `Cargo.toml` richiede `tfhe = "0.11"`; il lock risolve esattamente `0.11.3` |
| candidato analizzato | sorgenti del crate `tfhe-1.7.0` |
| upstream | la pagina release ufficiale marcava 1.7.0 come `Latest`, tag firmato `4267a92`, al momento dell'audit |
| MSRV 0.11.3 | Rust 1.83 |
| MSRV 1.7.0 | Rust 1.91.1 |
| host | `rustc 1.97.1`, quindi il solo MSRV non blocca il port |

Fonte upstream: [release TFHE-rs 1.7.0](https://github.com/zama-ai/tfhe-rs/releases/tag/tfhe-rs-1.7.0)
e [repository ufficiale](https://github.com/zama-ai/tfhe-rs).

## Matrice delle primitive

| capacita' | 0.11.3 | 1.7.0 | valore reale per A38 | giudizio |
|---|---|---|---|---|
| `unchecked_min`/`min_parallelized` fra due radix ciphertext | si' | si' | mattone per una riduzione a torneo | non motiva l'upgrade |
| `first_index_of_parallelized` e varianti clear | si' | si' | trova la prima uguaglianza con un valore gia' noto | non e' argmin; non motiva l'upgrade |
| `argmin`/`first accepted nearest` pronto | no | no | requisito finale della tesi | assente |
| ManyLUT shortint | si' | si' | un BR, piu' sample extraction dallo stesso input | gia' sfruttato manualmente da A38 |
| batch PBS FFT64 | si' | si' | carica il BSK una volta, ma il loop non sostituisce il parallelismo esterno | gia' provato sfavorevole |
| Rayon/parallelismo CPU integer | si' | si' | utile, ma A38 lo usa gia' sulle PBS indipendenti | nessun nuovo meccanismo per questo circuito |
| `pbs-stats` | si' | si' | conta PBS delle API instrumentate | contatore, non bound di correttezza |
| `NoiseLevel`/`MaxNoiseLevel` | si' | si' | contratto shortint se non si scende in core-crypto raw | A38 raw lo aggira |
| noise simulation core-crypto | non trovata | si' | modello di varianza per KS/PBS/modulus switch | utile come cross-check, non prova |
| parametri p16/p128 + CMNR | non nel catalogo corrente 0.11 | si' | termine nominale del union bound ridotto | motivo per valutare nuovi parametri |
| CPU KS32 | non trovato | si', atomic pattern stabile | meno payload e potenzialmente meno memory bandwidth | candidato benchmark prioritario |
| common-mask LWE | no | si', `experimental` | quattro corpi possono condividere una mask | manca la riduzione cross-slot |
| extended PBS | no | si', `experimental` | LUT effettivamente piu' larga con parallelismo interno | un solo output, oversubscription probabile |
| GPU vector-find/comparison improvements | no | si' | la release li elenca sotto GPU | non applicabili alla CPU Apple M4 |

### 1. `first_index` non e' la novita' cercata

**Evidenza.** In entrambe le versioni, allo stesso percorso
`integer/server_key/radix_parallel/vector_find.rs`, esistono:

- `first_index_in_clears_parallelized`;
- `index_of_parallelized`;
- `first_index_of_clear_parallelized`;
- `first_index_of_parallelized`.

Le firme pubbliche compaiono alle stesse linee 611, 697, 897 e 1008 nei due sorgenti locali. Il
diff 0.11.3 -> 1.7.0 contiene soprattutto il refactor della aggregazione/unpacking one-hot; non
appare alcun simbolo `argmin`. Le operazioni pairwise `unchecked_min` e `min_parallelized`
esistono anch'esse in entrambe le versioni.

**Inferenza.** Un baseline generic-radix exact puo' essere composto cosi':

1. riduzione a torneo dei punteggi con `min_parallelized`;
2. `first_index_of_parallelized(scores, minimum)` per la tie-first semantics;
3. confronto cifrato `minimum <= threshold`;
4. output `accept ? index+1 : 0`.

La semantica coincide con il requisito open-set, ma non la complessita'. Per score a 12 bit si
pagano confronti radix multi-blocco sia nella riduzione sia nella ricerca dell'indice. Senza un
conto statico o un microbenchmark non c'e' evidenza che batta il circuito specializzato A38;
poiche' gli stessi mattoni erano gia' in 0.11.3, un eventuale risultato positivo sarebbe una nuova
baseline algoritmica, non un vantaggio intrinseco dell'upgrade.

### 2. ManyLUT non diventa SIMD sulla galleria

**Evidenza.** `generate_many_lookup_table` e `apply_many_lookup_table` erano gia' pubbliche in
0.11.3. Entrambe le versioni costruiscono un solo accumulatore, fanno una blind rotation e
restituiscono piu' sample extraction. La formula implementata impone:

```text
number_of_functions <= (message_modulus * carry_modulus) / 2
max_input_degree = message_modulus * carry_modulus / number_of_functions - 1
```

Con p16 sono quindi possibili al massimo otto funzioni; con due funzioni, l'ingresso valido e'
`0..7`. A38 usa gia' manualmente la stessa idea core-crypto per layout misti e scale custom.

**Inferenza.** L'API ufficiale puo' essere utile per le due radici p16 di A41, quando il dominio
rispetta davvero il suo `input_max_degree`, ma non impacchetta gli `N` score indipendenti e non
esegue una OR/prefix/first-one fra identita'. Non risolve lo scaling 1:N da sola.

### 3. Batch e parallelismo

**Evidenza locale storica, debole.** A27 registra che il batch PBS seriale 0.11.3 era circa 10x
peggiore del parallelismo esterno a `N=128`; registra anche un miglioramento di circa 4% nel
microbenchmark scalar-PBS 0.11.3 -> 1.7. Il transcript matched di quel 4% non e' conservato, quindi
non va promosso come risultato.

**Evidenza upstream.** Le note CPU 1.7 elencano common-mask ed extended PBS sperimentali, ma non
dichiarano un'accelerazione del PBS classico CPU. Gli incrementi di throughput PBS, comparison
p2/2 e vector-find sono elencati nella sezione GPU. Il nostro caso e' latenza di una singola query
su Apple M4; una promessa GPU di throughput non si trasferisce a questo host.

**Esito.** Conservare il parallelismo esterno Rayon come controllo. Qualunque nuovo scheduler deve
essere confrontato a parita' di thread totali, non sommando thread interni e outer Rayon.

## Cosa cambia davvero nel port low-level

Il port non e' un semplice cambio di numero nel manifest.

### Struttura delle chiavi

In 0.11.3 `shortint::ServerKey` espone direttamente `key_switching_key`, `bootstrapping_key` e
`pbs_order`. In 1.7 `ServerKey` e' un `GenericServerKey<AtomicPatternServerKey>`; l'atomic pattern
puo' essere `Standard`, `KeySwitch32` o `Dynamic`.

Anche la variante BSK cambia:

```text
0.11: ShortintBootstrappingKey::Classic(key)
1.7:  ShortintBootstrappingKey::Classic {
          bsk,
          modulus_switch_noise_reduction_key,
      }
```

A38 fa pattern-match sulla vecchia variante e accede ai campi flat in piu' punti. Serve quindi un
adapter esplicito, preferibilmente confinato nel prototipo isolato.

### CMNR e blind rotation manuale

**Evidenza.** In 1.7 `blind_rotate_assign` riceve un oggetto che implementa
`ModulusSwitchedLweCiphertext`, non direttamente un LWE. Il percorso shortint ufficiale chiama
`modulus_switch_noise_reduction_key.lwe_ciphertext_modulus_switch(...)` prima della blind
rotation. Il wrapper core `FourierLweBootstrapKey::bootstrap`, invece, applica direttamente il
modulus switch standard.

**Conseguenza critica.** Se si seleziona il parametro p128/CMNR ma si porta meccanicamente la
pipeline raw chiamando il wrapper core standard, non si e' dimostrato di usare l'algoritmo a cui il
catalogo associa `log2_p_fail=-129.581`. Il port deve:

1. estrarre la `ModulusSwitchConfiguration` dal BSK;
2. applicarne esplicitamente `lwe_ciphertext_modulus_switch` con il log modulus corretto;
3. passare il risultato alla blind rotation;
4. mantenere invariati estrazione, scale e LUT e rifare il proof ledger nodo per nodo.

Per KS32 il bridge e' ancora piu' specifico: il codice ufficiale esegue
`keyswitch_lwe_ciphertext_with_scalar_change` da big-LWE `u64` a small-LWE `u32`, poi PBS con
input `u32` e output `u64`. E' compatibile concettualmente con il flusso KS->PBS di A38, ma non e'
drop-in per gli helper tipizzati `u64` correnti.

### Serializzazione e wire compatibility

**Evidenza.** Il demo corrente usa `bincode::serialize`/`deserialize` direttamente per
`ClientKey` e `ServerKey`. In 1.7 la rappresentazione serde di `ServerKey` inizia dall'atomic
pattern ed e' diversa dalla struttura flat 0.11. Le due versioni dispongono invece di safe
serialization versionata. Il codice di backward compatibility 1.7 dichiara supporto a partire da
TFHE-rs v0.10 e converte un `GenericServerKeyV1` flat nell'atomic pattern Standard.

**Inferenza prudente.** Questo supporto non rende automaticamente versionati i byte raw-bincode
gia' scritti dal demo. Fino a una prova su chiavi usa-e-getta, bisogna considerarli incompatibili.
Inoltre una chiave p64 deserializzata rimane p64: non puo' diventare p128 o KS32.

Piano di migrazione sicuro da verificare separatamente:

1. utility isolata 0.11: legge una chiave raw-bincode usa-e-getta e la riscrive con
   `safe_serialize`;
2. utility isolata 1.7: `safe_deserialize` + conformance check + un round-trip cifrato;
3. mai sovrascrivere chiavi esistenti; aggiungere una versione esplicita al protocollo;
4. per p128/KS32 generare comunque nuove chiavi e considerare il wire format distinto.

Questa procedura e' un'ipotesi di migrazione da validare, non un risultato di questo audit.

## Parametri, p-fail e tracker

### Confronto dei tre bracci utili

| campo | old p64 Standard | 1.7 p128 Standard | 1.7 p128 KS32 |
|---|---:|---:|---:|
| costante | `V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64` | `V1_7_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128` | `V1_7_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128` |
| LWE dimension | 879 | 918 | 918 |
| GLWE dimension | 1 | 1 | 1 |
| polynomial size | 2048 | 2048 | 2048 |
| LWE TUniform | 46 bit, u64 | 45 bit, u64 | 13 bit, post-KS u32 |
| GLWE TUniform | 17 | 17 | 17 |
| PBS decomposition | 23 x 1 | 23 x 1 | 23 x 1 |
| KS decomposition | 3 x 5 | 4 x 4 | 4 x 4 |
| p16 max noise | 5 | 5 | 5 |
| modulus switch | Standard | CMNR | CMNR |
| `log2_p_fail` nominale | -71.625 | -129.581 | -129.581 |

La copia archivistica del parametro v0.11 dentro TFHE-rs 1.7 conserva gli stessi valori e aggiunge
esplicitamente `ModulusSwitchType::Standard`. Questo rende possibile un controllo U0/U1 a
parametro identico prima di cambiare il regime di errore.

### Union arithmetic: utile ma solo condizionale

Se, e soltanto se, ogni marginale contata soddisfa il contratto nominale del parameter set, il
bound meccanico `M * p` darebbe:

| eventi M | old `log2(Mp)` | p128 `log2(Mp)` |
|---:|---:|---:|
| 2 radici terminali A41 | -70.625 | -128.581 |
| 3,655 BR A38 | -59.789 | -117.745 |
| 4,206 marginali A38 | -59.587 | -117.543 |
| 4,460 marginali schedule prudente | -59.502 | -117.458 |

Questi numeri **non sono** un certificato end-to-end. Restano gli epsilon di
extraction/corrections e A34-top; alcune uscite raw sono correlate e riusate; le scale custom non
ereditano il contratto shortint solo perche' provengono da una PBS. Il passaggio p128 migliora il
termine nominale di 57.956 bit, ma non dimostra le premesse.

### Tracker e simulatore

- `NoiseLevel`, `MaxNoiseLevel` e `pbs-stats` esistevano gia' in 0.11.3.
- A38 usa LWE core-crypto raw: i metadata shortint non accompagnano quelle operazioni.
- 1.7 aggiunge `NoiseSimulationLwe`, modelli per Fourier BSK, KS, packing KS e modulus switch.
- Le trait di somma/sottrazione si chiamano esplicitamente `LweUncorrelatedAdd/Sub`: sommare le
  varianze dei cammini correlati A38 senza un lemma aggiuntivo sarebbe un'ipotesi non valida.
- `MetaParametersFinder` sceglie un parameter set catalogato in base a feature/backend/p-fail; non
  analizza o certifica il nostro circuito custom.

**Uso raccomandato.** Creare un mirror statico del DAG A41 nel simulatore e confrontarlo con il
ledger manuale. Trattarlo come allarme/regression test, non come prova matematica finale.

## Payload teorico delle chiavi valutative

Calcolo statico sui container, non misura di file serializzato o RSS:

```text
Fourier BSK bytes = lwe_dim * (glwe_dim+1)^2 * (N/2) * pbs_levels * sizeof(c64)
KSK bytes         = big_lwe_dim * ks_levels * (small_lwe_dim+1) * sizeof(scalar)
```

| braccio | Fourier BSK | KSK | totale | delta vs old |
|---|---:|---:|---:|---:|
| old p64 Standard | 57,606,144 B | 72,089,600 B | 129,695,744 B = 123.69 MiB | baseline |
| p128 Standard | 60,162,048 B | 60,227,584 B | 120,389,632 B = 114.81 MiB | -7.18% |
| p128 KS32 | 60,162,048 B | 30,113,792 B | 90,275,840 B = 86.09 MiB | -30.39% |

**Evidenza:** le dimensioni e i tipi scalar vengono dalle costanti e dalle struct 1.7.
**Ipotesi:** meno KSK/memory traffic potrebbe accelerare i 3,274--3,528 KS per query. Le release
notes non dichiarano uno speedup CPU KS32 e il PBS domina verosimilmente il wall time; serve un
benchmark. Anche RSS, cache misses e byte serializzati vanno misurati, non dedotti da questa
tabella.

## Primitive sperimentali 1.7

### Common-mask LWE

La release 1.7 la marca sperimentale. Il POC locale p2/width4 ha misurato:

- 128 slot logici = 32 gruppi x 4 corpi;
- chiavi trattenute: 435.73 MiB;
- CMKS+PBS outer-parallel median: 39.688 ms;
- baseline ordinary p2/Rayon: 118.279 ms;
- stima con una packing pass separata: 58.851 ms, circa 2.01x.

Ma i loop timed non dimostravano ancora una pipeline completa: output non tutti
decifrati/consumati, identita'/input riusati e somma di mediane separate. Il profilo p4/width4
usava 736.25 MiB di chiavi e il rapporto incluso packing era 1.003x, cioe' nessun margine.

Inoltre l'helper 1.7 replica la stessa LUT sui corpi e contiene un TODO per una funzione distinta
per slot. Non c'e' un'API pronta per OR/prefix/first-one cross-slot. Quindi il vero gate resta POC
B: riduzione di quattro slot senza estrazione/repacking a ogni livello, output decifrati e vantaggio
misurato end-to-end.

L'integrazione in A38 richiede prima il completamento del POC isolato gia' specificato.

### Extended PBS

Il modulo 1.7 `lwe_extended_programmable_bootstrapping` cita il paper
[Accelerating TFHE with Sorted Bootstrapping Techniques](https://eprint.iacr.org/2025/2214). Il
paper riporta 1.75x--8.28x rispetto al bootstrap tradizionale e 1.26x--2.14x rispetto a LY23 nei
propri regimi; questi numeri non sono trasferibili automaticamente ad A38.

**Evidenza nel codice 1.7:** la funzione sperimentale:

- usa una LUT effettiva `N' = extension_factor * N`;
- richiede `extension_factor` potenza di due e maggiore di uno;
- richiede un buffer per thread e crea esattamente `extension_factor` thread scoped;
- sincronizza una barriera per ogni coefficiente della mask LWE;
- estrae alla fine **un solo LWE**, non piu' score o un indice;
- usa il modulus switch core standard nel wrapper mostrato, non il percorso CMNR shortint.

L'unico test-parametro p16 incluso nel modulo usa LWE 884, GLWE dimension 4, base `N=512` ed
extension factor 16, quindi LUT effettiva 8192 e output big-LWE dimension 2048. E' un test
Gaussian p128 circa, non un parameter set shortint produttivo gia' collegato ad A41.

**Inferenza.** A38 ha migliaia di PBS indipendenti e usa gia' fino a 16 worker esterni. Usare EF=16
internamente per ogni PBS rischia oversubscription; per battere 16 PBS ordinary concorrenti sul
throughput, una singola PBS dovrebbe compensare l'intero consumo dei thread. Il paper non prova
questo confronto. La primitiva potrebbe invece aiutare una coda stretta del DAG o sostituire un
sottografo che necessita davvero di LUT piu' larga.

L'integrazione nell'intero A38 non e' giustificata. Resta da valutare un microbenchmark su uno
strato stretto, a budget totale di thread fissato e dopo Standard/KS32.

## Piano benchmark isolato e falsificabile

I confronti seguenti sono proposti e non sono stati eseguiti nell'analisi. Richiedono misure
senza benchmark concorrenti sulla stessa CPU.

### Isolamento

1. Preparare copie separate degli input A38/A41, verificate tramite SHA-256, conservando
   manifest, lockfile e sorgenti della baseline per ogni braccio.
2. Usare manifest con pin esatti (`=0.11.3`, `=1.7.0`) e `Cargo.lock` separati.
3. Usare `CARGO_TARGET_DIR` separati per evitare artefatti condivisi e invalidazioni concorrenti.
4. Generare chiavi effimere fresche e separate dal materiale della demo.
5. Congelare host, governor/energia, numero di thread e commit/input hash nel report.

### Bracci da non confondere

| ID | crate | parametro/backend | grafo | domanda isolata |
|---|---|---|---|---|
| U0 | 0.11.3 | old p64 Standard | A38 frozen | controllo attuale |
| U1 | 1.7.0 | stesso old p64 Standard archiviato | A38 port identico | effetto della sola versione/API |
| U1P | 1.7.0 | old p64 Standard | A41 prudent, quando materializzato | controllo per il cambio di grafo |
| U2 | 1.7.0 | p128 Standard + CMNR | stesso A41 prudent | costo/beneficio dei parametri p128 |
| U3 | 1.7.0 | p128 KS32 + CMNR | stesso A41 prudent | effetto specifico KS32 |
| U4 | 1.7.0 | p128 Standard | generic radix min + first-index | baseline algoritmica, non upgrade claim |

Common-mask ed extended PBS devono restare in binari/workspace separati (`X1`, `X2`), non essere
aggiunti a U2/U3 prima che i rispettivi component gate passino.

### Ordine di implementazione

1. **Port U1 same-parameter.** Adattare key access, BSK variant e modulus-switched blind rotation,
   senza cambiare LUT, scale, conteggi o scheduling.
2. **Gate semantico U0/U1.** Prima le 29 fixture componente A38, poi il corpus primario 632-case,
   edge threshold, reject, ID 1/127/128 e tie 64/127 e 127/128.
3. **Materializzare A41 prudent.** Due radici p16 e refresh raw-L1 previsti dal report formale;
   nessun altro refactor.
4. **U2 p128 Standard.** Verificare nel trace che ogni blind rotation usi realmente la
   `ModulusSwitchConfiguration` CMNR.
5. **U3 KS32.** Cambiare soltanto atomic pattern/scalar bridge; stesso DAG, LUT e corpus U2.
6. **Solo dopo** valutare U4, common-mask POC B ed extended PBS tail-layer.

### Disegno della misura

- Compilazione e keygen fuori dalla regione temporizzata.
- Warm-up dichiarato; output sempre consumati e poi decifrati/verificati.
- Stesse fixture clear nello stesso ordine; ABBA/randomizzazione dell'ordine dei processi.
- Almeno tre chiavi effimere fresche per braccio.
- Microstadi: almeno 31 round per processo x 3 processi; full query `N=127`: almeno 31 coppie per
  confronto che si vuole chiamare performance result.
- Thread sweep minimo `1` e `16`; il confronto principale usa lo stesso budget totale di 16 core,
  incluso qualunque parallelismo interno.
- Riportare median, p10/p90, MAD e bootstrap CI paired sulla differenza quando esiste pairing.
- Per U0/U1 provare prima la safe-serialization su materiale usa-e-getta. Solo se passa si puo'
  usare la stessa chiave/ciphertext e parlare di vero paired cryptographic input; altrimenti il
  pairing e' soltanto per fixture clear e va dichiarato.
- Per U2/U3 i parametri/chiavi differiscono: usare blocchi matched per fixture e chiave index, senza
  fingere che i ciphertext siano gli stessi.

Metriche obbligatorie:

- mismatch semantici e decoded code;
- BR, KS e marginali per stage;
- tempo totale e tempi score/extraction, classifier, selection, terminal encode;
- tempo separato KS e blind rotation su microfixture;
- byte BSK/KSK serializzati, RSS peak e memoria dopo key load;
- per KS32, conversioni u64->u32 e loro tempo;
- versione crate, parametro completo, MSRV/toolchain, thread count e input SHA.

### Gate pre-registrati

| candidato | GO | NO-GO/stop |
|---|---|---|
| U1 port | zero mismatch su component + primary, stessi conteggi; protocol/serialization versionati | qualsiasi divergenza o raw key compatibility assunta senza test |
| U1 performance | CI paired non mostra regressione >5%, oppure regressione motivata da un beneficio separato | nessun claim di speedup dal solo storico 4% |
| U2 p128 | zero mismatch, CMNR verificato nel percorso raw, ledger p-fail aggiornato; latenza dentro il budget esplicito della tesi | catalog p-fail citato mentre il codice usa modulus switch standard o precondizioni raw non chiuse |
| U3 KS32 | zero mismatch; riduzione memoria misurata; per claim di velocita', guadagno E2E >5% con CI lower bound >0 | stessa/lenta latenza: conservarlo al massimo come opzione memory-only |
| U4 generic radix | correttezza exact e costo competitivo misurato gia' su N=16/32 | stop anticipato se l'estrapolazione e' chiaramente peggiore di A38; non aspettare N=127 |
| X1 common-mask | decrypt di tutti gli stati, niente per-slot extraction, bridge+stage >=1.5x e OR/prefix a 4 slot resta packed | extraction/repack a ogni livello o vantaggio eliminato dal bridge |
| X2 extended PBS | stesso layer exact, stessi thread totali, speedup layer >=1.25x con CI lower >1.10, p-fail del parametro giustificato | oversubscription, throughput <=1.10x o solo una LUT identity favorevole |

## Criteri per la migrazione

1. **Conservare la baseline versionata.** A38/A41 e il benchmark primario devono rimanere
   riproducibili con i propri pin e input identificati.
2. **Aprire un port isolato 1.7 same-parameter.** E' il prerequisito per attribuire qualsiasi
   differenza alla versione.
3. **Portare prima A41 prudent a p128 Standard/CMNR.** Consente di valutare il termine nominale
   del union bound con i nuovi parametri; non garantisce una latenza inferiore.
4. **Confrontare subito dopo p128 Standard vs p128 KS32.** La variazione del payload teorico
   delle chiavi e' -30.39% rispetto al parametro precedente; lo speedup resta da dimostrare.
5. **Usare il noise simulator come controllo aggiuntivo.** Non sostituisce i lemma sui cammini correlati.
6. **Tenere first-index/min come baseline di controllo.** Non presentarlo come novita' 1.7.
7. **Valutare separatamente common-mask ed extended PBS.** Nelle implementazioni esaminate non
   soddisfano il requisito exact first-winner 1:N end-to-end.

L'upgrade rende disponibili p128 e KS32 per ulteriori prove sul circuito exact-ID.
Il confronto isolato U0/U1/U2/U3, a parita' di semantica, deve stabilire l'effetto della versione,
dei parametri e del backend sulla latenza e sul rumore.

## Fonti e provenienza

### Artefatti repository letti

| artefatto | SHA-256 allo snapshot |
|---|---|
| `experiments/14_pipeline_tfhe_rs/Cargo.toml` | `290b97cfd9af85685db419b5782d0e9ab073179b6ffe2c97ef9c8a33c4fddfb6` |
| `experiments/14_pipeline_tfhe_rs/Cargo.lock` | `1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a` |
| `experiments/14_pipeline_tfhe_rs/src/private_argmin.rs` | `5230f3863a5cad726aefe51a3c6a786899e4f1cdd47aeb0ff8f7141fcc3917ae` |
| A38 component report | `184f4b08a03b8d71f999466df8127bfb0afd7baa10c4f732934cdd59f01b0229` |
| formal p-fail path | `4a2a29bed963e67ef848b5386d9016edf267dea78374fdf02c163dbed0202e86` |
| A41 static report | `fa65c5e21ccd4687e29c13801f28870355835abea2260fd271d6c75a189ae55c` |
| A01--A33 timeline | `8d44abdb3001ac0e199796190e7f8331fcd7c91b868807a9089c4addffd64bca` |
| `attempts.md` | `315af08b7bc7ab148a344dc23e8baab615060ed732ea429a273130e18e1ce87c` |
| common-mask README | `00f8911065ce14bb10beb2bd7a1f2fe945ce72110971dfb5c72adc6e1a260a06` |
| common-mask retained results | `e577eef5c5b0873291149938e9ab3343bd26b50555bd0c53a1d12f7d2c292797` |

### Sorgenti crate locali letti

- `tfhe-0.11.3` Cargo manifest SHA-256:
  `5a540a90dede666592aa727fa0af3147c8def98e42372bf8bf5ecb2a7a9118e8`.
- `tfhe-1.7.0` Cargo manifest SHA-256:
  `82e042e34a0f6d027c1f7168b40e58c242402b873d85e77088c94b35077caa60`.
- first-index:
  `src/integer/server_key/radix_parallel/vector_find.rs` nelle due versioni.
- ManyLUT:
  `src/shortint/engine/mod.rs` e `src/shortint/server_key/mod.rs`.
- parametri old archiviati:
  `src/shortint/parameters/v0_11/classic/tuniform/p_fail_2_minus_64/ks_pbs.rs`.
- parametri p128 Standard:
  `src/shortint/parameters/v1_7/classic/tuniform/p_fail_2_minus_128/ks_pbs.rs` e alias v1.4.
- parametri p128 KS32:
  `src/shortint/parameters/v1_7/ks32/tuniform/p_fail_2_minus_128/ks_pbs.rs`.
- atomic patterns:
  `src/shortint/atomic_pattern/{mod.rs,standard.rs,ks32.rs}`.
- CMNR e BSK:
  `src/shortint/server_key/{mod.rs,modulus_switch_noise_reduction.rs}`.
- backward compatibility:
  `src/shortint/backward_compatibility/server_key/mod.rs`.
- noise simulation:
  `src/core_crypto/commons/noise_formulas/noise_simulation/`.
- extended PBS:
  `src/core_crypto/experimental/algorithms/lwe_extended_programmable_bootstrapping.rs` e relativo
  test.

### Fonti upstream

- [TFHE-rs 1.7.0 release notes](https://github.com/zama-ai/tfhe-rs/releases/tag/tfhe-rs-1.7.0)
- [TFHE-rs repository/README](https://github.com/zama-ai/tfhe-rs)
- [Bergerat et al., Accelerating TFHE with Sorted Bootstrapping Techniques](https://eprint.iacr.org/2025/2214)
