# A44: retuning statico dei parametri p16 per il blocco `p-fail`

Data: 2026-09-02. Perimetro: TFHE-rs 0.11.3 bloccato dal `Cargo.lock`, sorgenti ufficiali
Zama e calcoli statici. In questo audit non sono stati eseguiti Cargo, FHE, keygen o Docker; non
sono state lette o prodotte chiavi e non sono stati modificati core, servizio, input vivi o manifest.

## Esito

Il retuning e' **fattibile** e c'e' un candidato minimo gia' distribuito dalla stessa versione
TFHE-rs usata dal progetto:

```text
V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64
```

Mantiene il plaintext totale `p=2*8=16`, `N=2048`, `k=1`, `Delta=2^59` e le stesse
decomposizioni classic KS/PBS. Porta pero' `max_noise_level` da 5 a **15**, quindi copre
nativamente, senza dividere il rumore per un margine allargato:

- il classificatore del residuo A34 con raw `L1<=8`, con headroom 7;
- il cammino A36 corrente con raw `L1<=10`, con headroom 5;
- qualunque variante A40/A45 la cui ledger finale dimostri raw `L1<=15` prima di ogni PBS p16.

Questa scelta rimuove il **blocco locale** max-5. Non produce ancora un bound end-to-end: gli
stadi custom di estrazione, le LUT raw/ManyLUT correlate e, nel formato A38 a un solo LWE, il
decode terminale a `Delta=2^56`, non ereditano automaticamente il numero del preset.

Il target di query che si puo' preparare con il preset p64 e' quindi:

```text
P(wrong query) <= 4206 * 2^-64.088 = 2^-52.0497668653
               = 2.14515612749e-16
```

ma soltanto **condizionalmente** alla futura equivalenza di tutte le 4.206 marginali con il
contratto per-evento. Se si vuole dichiarare `P(query failure)<=2^-64`, serve un per-evento almeno
`2^-76.0382331347`; il preset p64 non basta per quel target globale. La variante p128 descritta
piu' avanti darebbe condizionalmente `2^-116.064766865` sulla stessa ledger.

## Parametri esatti

| campo | corrente | candidato minimo A44 |
|---|---:|---:|
| preset | `M2C2 TUniform 2M64` | `M1C3 Gaussian 2M64` |
| TFHE-rs | 0.11.3 | 0.11.3 |
| message x carry | `4 x 4` | `2 x 8` |
| plaintext totale | 16 | 16 |
| `max_noise_level` | 5 | **15** |
| `log2_p_fail` dichiarato | -71.625 | **-64.088** |
| LWE dimension | 879 | 859 |
| GLWE dimension / `N` | 1 / 2048 | 1 / 2048 |
| rumore LWE | TUniform(46) | Gaussian `std=2.3088161607134664e-6` |
| rumore GLWE | TUniform(17) | Gaussian `std=2.845267479601915e-15` |
| PBS | `base_log=23`, `level=1` | uguale |
| KS | `base_log=3`, `level=5` | uguale |
| modulus / key choice | native / Big | uguale |
| costo algoritmico annotato | non annotato | circa 109 |

La sorgente del candidato lo annota esplicitamente come `p-fail=2^-64.088`, costo circa 109 e
`2-norm=15`. Non dichiara nella stessa riga un numero di bit di sicurezza; questo audit non ne
inventa uno e non ha rieseguito lo stimatore. Il parametro corrente e' invece annotato nel file
TUniform come sicurezza 132 bit e `p-fail=2^-71.625`.

Il p-fail nominale per evento diventa circa 185,72 volte piu' alto del corrente. Il confronto non
e' pero' un peggioramento di un bound valido: il numero corrente non copriva proprio gli ingressi
raw 8 e 10 che ci interessano.

### Perche' il limite diventa 15

`MaxNoiseLevel::from_msg_carry_modulus` in 0.11.3 calcola

\[
L_{max}=\frac{m c-1}{m-1}.
\]

Per `m=4,c=4` si ottiene 5; per `m=2,c=8` si ottiene 15. La stessa sorgente descrive
`MaxNoiseLevel` come il massimo rumore che garantisce il target p-error alla PBS. Somme e
moltiplicazioni clear propagano il tracker in modo lineare. Usare raw `L1=8` o `L1=10` come
ledger conservativa riproduce quindi il criterio esposto dall'API, senza il precedente argomento
"il plateau e' doppio, dunque divido L1 per due".

Questa e' una lettura del **contratto nominale della libreria**, non una dimostrazione autonoma
delle FFT o di una LUT core-crypto arbitraria. La stessa implementazione contiene un TODO:
l'attuale limite norm2 e il vincolo che mantiene pulito il padding bit sono ancora accoppiati.

## Geometria: cosa resta uguale e cosa no

Per l'encoding shortint standard:

\[
\Delta=\frac{2^{63}}{m c}.
\]

Poiche' entrambi i preset hanno `m*c=16`, in entrambi i casi `Delta=2^59`. Con `N=2048`, una LUT
raw p16 conserva `N/16=128` coefficienti per casella, cioe' 64 passi di blind rotation come mezzo
margine standard. Restano uguali:

- layout p16, centri, box e accumulatori raw che dipendono dal prodotto 16;
- forma del probe GLWE (`k=1,N=2048`);
- dimensione del large LWE di risposta (`kN=2048`);
- decomposizione PBS `23x1`, KS `3x5` e modulus nativo.

Cambiano invece la dimensione small-LWE (`879 -> 859`), la distribuzione del rumore e i metadati
message/carry. Conseguenze operative:

- servono client key, server key, probe e ciphertext nuovi; nulla va riusato o cross-decifrato;
- il numero di word del probe e del large-LWE di risposta resta uguale, ma non la compatibilita'
  crittografica;
- il servizio deve autenticare un nuovo `params_id`, non soltanto la lunghezza dei blob;
- qualsiasi uso high-level che assume message modulus 4 va riesaminato; il core exact-ID corrente
  usa quasi interamente costanti raw (`PBS_MESSAGE_MODULUS=16`), ma questo va provato con una
  scansione sorgente nel prototipo congelato.

## Caso A40/A45 multilane a `Delta=2^60`

La futura decomposizione proposta porta ciascun nibble intero `c=0..15` in un LWE a
`Delta=2^60`, poi materializza i bit iterativamente. Il top residual somma al massimo due radici
fresche.

Sul solo rumore lineare il risultato e' netto:

| quantita' | valore |
|---|---:|
| radici fresche sommate | 2 |
| raw L1 conservativo | 2 |
| limite candidato | 15 |
| headroom nativo | 13 |
| margin-rescaling usato | **no** |

La spaziatura a `Delta=2^60` ha mezzo passo `2^59`, doppio del mezzo passo p16 standard `2^58`.
Questo margine extra **non viene accreditato** per abbassare artificialmente L1: il tracker resta
2 e viene confrontato direttamente con 15.

Resta pero' un vincolo semantico essenziale. I 16 centri a `Delta=2^60` occupano il toro completo;
`c+8` e' l'antipodo negaciclico di `c`. Ogni accumulatore deve dunque soddisfare, sui valori
raggiungibili,

\[
Y(c+8)=-Y(c).
\]

Una LUT nibble arbitraria non lo soddisfa. In particolare non si puo' assumere gratuitamente una
fusione `nibble -> tutte le correzioni`: servono correzioni bitwise, oppure una ricodifica/offset
con prova esaustiva. Il preset max-15 copre il raw L1 del top residual, ma il suo p-fail nominale
si puo' trasferire alla LUT custom soltanto dopo aver dimostrato:

1. output corretto a tutti i 16 centri e relazione negaciclica per ogni coppia antipodale;
2. distanza aperta di ogni centro raggiungibile dal confine almeno pari ai 64 passi della p16
   standard, includendo il rounding del modulus switch;
3. stessa sequenza KS/PBS e stesse decomposizioni del preset;
4. provenance condivisa delle due radici, senza chiamarle indipendenti.

Quindi il verdetto multilane e': **si' per il budget raw L1=2; condizionale per il p-fail della
custom LUT; no a una LUT nibble arbitraria o a un vantaggio ottenuto riscalando il margine.**

## Tre livelli diversi di affermazione sul `p-fail`

### 1. Aritmetica dimostrata qui

Se `P(F_i | nessun errore precedente)<=p` per ciascun evento contato, allora

\[
P(\cup_i F_i)\le\sum_i P(F_i)\le Np.
\]

E' la disuguaglianza di Boole e non richiede indipendenza. Per A38/A41 a `N=127` si usa la ledger
conservativa delle **4.206 marginali**, non le sole 3.655 blind rotation, finche' non esiste un
bound congiunto per gli output ManyLUT.

| preset | per evento | query condizionale, 4.206 eventi |
|---|---:|---:|
| corrente TUniform max-5 | `2^-71.625` | `2^-59.5867668653` (ma L1 8/10 fuori contratto) |
| candidato A44 max-15 | `2^-64.088` | **`2^-52.0497668653`** |
| migrazione p128 max-15 | `2^-128.103` | `2^-116.064766865` |

### 2. Modello nominale Zama/optimizer

Il README ufficiale di Concrete optimizer 2.11 definisce `norm2` come somma dei quadrati dei pesi
fra table lookup e specifica che gli input devono essere indipendenti rispetto al rumore per
descrivere un atomic pattern con la sola precisione/norm2. Il codice:

- costruisce la varianza sicura invertendo una coda Gaussiana tramite `erfc`;
- moltiplica il rumore della blind rotation per il quadrato del noise factor;
- somma i contributi BR, KS e modulus switch e ricava `p_error` dalla varianza;
- per ripetere un errore usa `1-(1-p)^N`, formula da eventi indipendenti.

Nel nostro accounting globale si usa invece `Np`, perche' ManyLUT campiona piu' LWE dalla stessa
blind rotation e i residui riusano correzioni comuni. Il valore del preset e' quindi una base
ufficiale per evento, ma non autorizza ne' `1-(1-p)^N` ne' la somma di sole varianze marginali nel
nostro grafo correlato.

### 3. Prova matematica end-to-end

Non e' ancora disponibile. Per ottenerla bisogna mappare topologicamente ogni input raw alla
precondizione del preset o assegnargli un epsilon separato. In particolare restano aperti:

- split4/multilane e correzioni a scale non standard;
- classificatore A34 alimentato da residui correlati, anche se il suo raw L1 ora rientra in 15;
- equivalenza delle ManyLUT custom all'API ufficiale;
- terminale A38 a un solo `Delta=2^56` (A41 a due LWE p16 lo elimina, condizionalmente);
- conteggio esatto degli eventi dopo la variante finale A40/A41/A45.

Per questo lo script A44 lascia intenzionalmente `end_to_end_numeric_upper = null`.

## Cambio TUniform -> Gaussian: regressione formale da non nascondere

Il bound sul supporto del rumore iniziale del probe usato nell'audit A38 sfrutta TUniform(17), che
ha supporto deterministico finito. Passare al preset Gaussian invalida quella specifica prova a
supporto zero-failure; va sostituita da un termine probabilistico.

Come sola sensibilita', con `||g||_2^2<=1022`, coefficiente `-2` e la std GLWE del candidato:

```text
sigma(score iniziale) = 1.81919202561e-13
mezzo passo Delta_full=2^52 = 1.220703125e-4 sul toro normalizzato
rapporto = 6.71013893977e8 sigma
```

Una coda Gaussiana ideale sarebbe astronomicamente piccola; il bound Chernoff bilaterale del
modello ha `log2` circa `-3.25e17`. Non lo si contabilizza come prova del circuito: il numero non
copre estrazione/correzioni, implementazione FFT, modulus switch e dipendenze successive. Serve
solo a mostrare che il cambio di distribuzione non pare un rischio pratico sullo score iniziale,
pur perdendo la precedente conclusione deterministica.

## Prestazioni e alternative

### Classic M1C3, prima scelta

Il candidato conserva `N=2048`, `k=1`, PBS `23x1` e KS `3x5`; cambia small-LWE da 879 a 859. La
geometria suggerisce un costo della stessa classe, ma non consente di dichiarare uno speedup. Il
preset Gaussian M2C2 della stessa tabella ha costo algoritmico 106 contro 109 del candidato
(+2,83% nel modello). Non e' un confronto diretto con il baseline TUniform, che non ha la medesima
annotazione; cache, parallelismo e distribuzione vanno misurati.

### Multi-bit, esperimento separato

La stessa 0.11.3 offre M1C3 max-15 multi-bit:

| variante | `log2_p_fail` | costo annotato |
|---|---:|---:|
| group 2 | -64.089 | 89 |
| group 3 | -64.242 | 86 |

Il core vivo rifiuta ogni `ShortintBootstrappingKey` non `Classic`; le API raw di blind rotation e
ManyLUT andrebbero riscritte e `deterministic_execution=false` cambia anche la riproducibilita' del
ciphertext. Non e' il primo benchmark A44.

### Preset p128, target query forte

Le sorgenti locali TFHE-rs 1.7.0 includono il preset storico v1.4
`V1_4_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M128`: p16, max-15, `N=2048`, LWE 904,
PBS `23x1`, KS `3x6`, `log2_p_fail=-128.103`, costo circa 119 e centered-mean modulus-switch noise
reduction. Soddisfa condizionalmente un target query `2^-64`, ma richiede migrazione di versione,
API e semantica del modulus switch. Va provato dopo il candidato classic pinned, non mescolato con
esso.

Generare parametri custom con Concrete optimizer per un per-evento `<=2^-76.0383` e' una terza
strada. Sarebbe pero' un parameter set non gia' distribuito: richiede riesecuzione dello stimatore,
audit di sicurezza, congelamento dei parametri e validazione indipendente. Cambiare soltanto il
campo `max_noise_level` del preset corrente non e' mai valido.

## Piano benchmark esatto, da eseguire soltanto dopo il primary attivo

### Fase 0 - freeze e separazione

1. Attendere la fine del primary corrente e congelarne risultato, hash sorgente, dataset, ordine
   casi, toolchain e carico macchina.
2. Scegliere un solo grafo per il confronto parametri: preferibilmente A41 two-LWE dopo la sua
   validazione, cosi' il terminale `Delta=2^56` non confonde l'audit upstream.
3. Copiare il grafo in `tmp/a44-p16-retune-prototype`; nessuna modifica al live core.

### Fase 1 - materializzazione e guardrail

Il prototipo deve cambiare esclusivamente il simbolo PARAMS e gli import corrispondenti. Prima del
keygen deve stampare e serializzare un fingerprint con tutti i campi della tabella sopra. Client e
server devono rifiutare un `params_id` diverso. Non deve accettare chiavi/ciphertext del preset
corrente anche se alcune lunghezze coincidono.

Comandi statici preliminari:

```bash
python3 -m unittest tests.test_a44_p16_parameter_retune -v
python3 benchmark/a44_p16_parameter_retune.py --json
```

### Fase 2 - certificato di geometria e ledger, prima dell'FHE

Un harness clear dedicato deve:

1. enumerare ogni centro raggiungibile di ogni LUT p16 e gli errori di rotazione `-63..63`;
2. fallire esplicitamente ai confini `-64/+64`, salvo plateau custom provato piu' largo;
3. emettere per ogni PBS: ID nodo, predecessori/provenance, raw L1, scala, margine minimo, ID blind
   rotation condivisa e ragione `official`/`raw-equivalent`/`open`;
4. imporre `raw_l1<=15` senza divisioni per fattori di margine;
5. per la multilane `Delta=2^60`, enumerare `c=0..15`, coppie `c/c+8`, margini `-127..127` e
   confini `-128/+128`, verificando la relazione negaciclica sul valore torus effettivo;
6. produrre il conteggio eventi dalla ledger, senza hardcodare 4.206 se A40/A45 lo cambia.

### Fase 3 - build e component FHE con chiavi nuove

Solo dopo le fasi 0-2:

```bash
cd tmp/a44-p16-retune-prototype
cargo fmt --all -- --check
cargo test --locked --release --features diagnostic-trace --lib
cargo run --locked --release --features diagnostic-trace \
  --bin a44_param_retune_prototype -- --run --small-only --keys 3
cargo run --locked --release --features diagnostic-trace \
  --bin a44_param_retune_prototype -- --run --keys 3
```

Il CLI `--keys 3` e la stampa della ledger sono requisiti del futuro harness, non funzionalita'
gia' esistenti. Ogni key block genera entrambe le chiavi da zero e non le persiste.

La matrice component deve includere:

- A34 su ingressi che raggiungono davvero raw L1 8 e tutti i confini delle 16 categorie;
- A36 su tracce che raggiungono raw L1 10, soprattutto i due fine-chunk e radix-5;
- tutte le lane multilane `0..15` e ogni coppia antipodale, se quella variante viene adottata;
- `N=1,8,64,127,128`, all-reject, threshold 1023/1024, primo/ultimo vincitore, tie interno e
  tail-tie, ID 127 e ID 128;
- terminale A41 low/high separato per tutti i codici `0..128`.

Acceptance component: zero mismatch, zero panic, zero nodo `raw_l1>15`, zero LUT senza stato di
equivalenza, identici conteggi strutturali attesi.

### Fase 4 - primary e Docker

Eseguire la stessa suite primaria da 632 casi con scene/oracolo clear congelati. Acceptance:
`632/632`, nessun worker error/timeout, exact ID e tie-first invariati, threshold invariata,
ciphertext freschi e fingerprint parametro registrato. Poi eseguire il gate Docker client-server
con chiavi nuove e mismatch di parametro fail-closed.

### Fase 5 - paired prestazionale per scena, non per ciphertext

Ciphertext e chiavi non possono essere identici fra i due preset. Il pairing valido e' sulla
stessa scena clear:

- 3 coppie indipendenti di key block;
- gallery `N=8,16,32,64,127`;
- 1 warmup escluso e 5 query misurate per scena/key block;
- ordine AB/BA bilanciato e pseudocasuale, macchina idle e thread count congelato;
- keygen, serializzazione, eval server e decode misurati separatamente;
- RSS peak, dimensioni key/probe/response, BR/KS/marginali e hash binario registrati.

Il futuro comando previsto e':

```bash
python3 benchmark/fhe_exact_id_paired_a41_params.py \
  --baseline v0_11_m2c2_tuniform \
  --candidate v0_11_m1c3_gaussian \
  --gallery-sizes 8,16,32,64,127 \
  --key-blocks 3 --warmups 1 --runs-per-cell 5 --balanced-order
```

Il report deve dare mediane per cella, rapporto paired per scena, intervallo bootstrap e geomean;
non deve chiamarlo "stesso ciphertext". Soglia operativa preliminare: se median eval a N=127 o
RSS peggiorano oltre il 10%, mantenere il candidato come soluzione di correttezza e aprire
un'ablation separata; non tornare silenziosamente al parametro max-5.

### Fase 6 - significato dell'evidenza empirica

Neppure migliaia di run possono osservare o certificare un evento da `2^-52`. Ripetizioni con
chiavi fresche e fixture ai confini servono a trovare regressioni. Noise injection e Monte Carlo
amplificato possono controllare la pendenza del modello, non sostituire il bound. La promozione del
numero globale richiede la ledger per-evento con una giustificazione official/equivalent/proved.

### Regole finali di promozione

- **Retuning implementabile:** si', dopo primary, con il classic pinned M1C3.
- **A34/A36 native max-noise blocker:** chiuso se la ledger runtime conferma massimi 8 e 10.
- **Multilane top residual a due radici:** coperto a raw L1 2; LUT custom ancora da provare.
- **Query nominale p64:** dichiarabile al massimo come `<=2^-52.0498`, condizionale a tutte le
  4.206 premesse.
- **Query formale `<=2^-64`:** no col solo preset p64; valutare p128 o parametro custom auditato.
- **End-to-end oggi:** aperto; nessun numero unconditional.

## Artefatti statici e verifica eseguita

- `benchmark/a44_p16_parameter_retune.py`
- `tests/test_a44_p16_parameter_retune.py`
- questo report

Verifica realmente eseguita in A44:

```text
python3 -m py_compile ...                         PASS
python3 -m unittest tests.test_a44_p16_parameter_retune -v
Ran 9 tests ... OK
```

## Fonti primarie

- Preset classic Gaussian TFHE-rs 0.11.3, righe 72-94:
  <https://raw.githubusercontent.com/zama-ai/tfhe-rs/tfhe-rs-0.11.3/tfhe/src/shortint/parameters/classic/gaussian/p_fail_2_minus_64/ks_pbs.rs>
- Preset corrente TUniform TFHE-rs 0.11.3, righe 8-25:
  <https://raw.githubusercontent.com/zama-ai/tfhe-rs/tfhe-rs-0.11.3/tfhe/src/shortint/parameters/classic/tuniform/p_fail_2_minus_64/ks_pbs.rs>
- `MaxNoiseLevel` e tracker lineare TFHE-rs 0.11.3:
  <https://raw.githubusercontent.com/zama-ai/tfhe-rs/tfhe-rs-0.11.3/tfhe/src/shortint/ciphertext/common.rs>
- Concrete optimizer 2.11, definizione norm2/per-table-lookup e requisito di indipendenza:
  <https://raw.githubusercontent.com/zama-ai/concrete/v2.11.0/compilers/concrete-optimizer/v0-parameters/README.md>
- Conversione varianza/coda Gaussiana tramite `erfc`:
  <https://raw.githubusercontent.com/zama-ai/concrete/v2.11.0/compilers/concrete-optimizer/concrete-optimizer/src/noise_estimator/error.rs>
- Atomic pattern, quadrato del noise factor e somma dei rumori BR/KS/modulus switch:
  <https://raw.githubusercontent.com/zama-ai/concrete/v2.11.0/compilers/concrete-optimizer/concrete-optimizer/src/optimization/atomic_pattern.rs>
- Ripetizione `1-(1-p)^N` nell'optimizer:
  <https://raw.githubusercontent.com/zama-ai/concrete/v2.11.0/compilers/concrete-optimizer/concrete-optimizer/src/noise_estimator/p_error.rs>

Fonti locali aggiuntive usate per congelare la versione e la compatibilita' del core:

- `experiments/14_pipeline_tfhe_rs/Cargo.lock:463-466` (`tfhe=0.11.3`);
- `experiments/14_pipeline_tfhe_rs/src/bin/varco_demo.rs:554-578` (conformance del parametro);
- `experiments/14_pipeline_tfhe_rs/src/private_argmin.rs:773-786,2159-2166` (solo BSK classic e
  layout auditato per `N=2048`);
- cargo registry 0.11.3 `shortint/ciphertext/standard.rs:228,244` (formula di `Delta`).
