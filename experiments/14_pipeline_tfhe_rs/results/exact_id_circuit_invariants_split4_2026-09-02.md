# Invarianti del circuito exact-ID TFHE A28 split4

**Data:** 2026-09-02

**Oggetto:** audit statico del core `private_argmin` A28 e collegamento alle evidenze FHE

**Revisione:** split4, `CODE_DELTA_LOG=56`, 5.600 PBS e 4.584 KS nel caso `N=127`
con soglia uniforme

Questo documento e' il report degli invarianti della revisione A28. Il precedente
[`exact_id_circuit_invariants_2026-09-02.md`](exact_id_circuit_invariants_2026-09-02.md) resta uno
snapshot storico A25 e non viene reinterpretato come evidenza per il nuovo estrattore.

La nota ricostruisce il contratto e gli invarianti logici del circuito, quindi li collega a due
run FHE gia' concluse. Non propone claim di novita', non e' una prova formale dell'implementazione
Rust e non trasforma il `log2_p_fail` nominale di TFHE-rs in un bound end-to-end della composizione
low-level.

## 1. Contratto exact-ID

Il server riceve:

- un probe cifrato in un solo GLWE, presente in due layout coerenti: precisione completa a
  `Delta=2^52` e residuo modulo 16 a `Delta=2^60`;
- una galleria in chiaro di `N` template, con `1 <= N <= 128`;
- norma quadrata e soglia pubblica associate a ogni template;
- la chiave di valutazione, ma non la chiave segreta.

Il circuito restituisce un solo LWE:

- `0` se il primo template a distanza minima supera la propria soglia (`score_i > T_i`);
- `i+1` se il primo template a distanza minima ha indice zero-based `i` e non supera la propria
  soglia (`score_i <= T_i`).

La distanza non fa parte dell'output. Contratto, API pubblica e oracolo clear dello snapshot A28
sono congelati nella
[patch sorgente A28](../../../benchmark/patches/a28_split4_source_2026-09-02.patch); il modulo
[private_argmin.rs](../src/private_argmin.rs) e' la linea di sviluppo leggibile e puo' avanzare
oltre quello snapshot. L'oracolo clear ordina le coppie `(score, indice)`, applica soltanto la
soglia del vincitore e codifica `0` oppure `indice+1`.

In forma compatta:

```text
k = first argmin_i score_i
code = (score_k <= threshold_k) ? (k + 1) : 0
```

Questa e' identificazione open-set esatta: non e' il solo bit di membership e non restituisce un
indice non accettato nel caso di rifiuto.

## 2. Assunzioni di correttezza

### 2.1 Probe honest e ben formato

L'argomento vale se il client cifra un probe che rispetta il contratto:

1. le coordinate appartengono a `[-3,3]`;
2. la norma quadrata e' al massimo `1024`;
3. i layout full e modulo 16 rappresentano lo stesso probe;
4. formato, chiave e parametri crittografici sono quelli attesi.

Il server verifica forma e modulo del ciphertext, ma non puo' verificare in chiaro le proprieta'
semantiche del probe cifrato. Questo confine e' esplicito nell'API
([sorgente, L850-L857](../src/private_argmin.rs#L850-L857)). Il circuito non include quindi una
prova di conoscenza o di well-formedness contro un client malevolo.

### 2.2 Galleria e dominio a 12 bit

Per ogni template il server verifica dimensione, coordinate e norma dichiarata
([sorgente, L448-L492](../src/private_argmin.rs#L448-L492)). Il dominio deve essere ordinato,
avere larghezza al massimo `4096` e coprire il bound conservativo di ogni template
([sorgente, L495-L535](../src/private_argmin.rs#L495-L535)).

Per il template `t_i`, il punteggio cifrato e'

```text
s_i = ||t_i||^2 - 2 <q,t_i>.
```

Rispetto alla distanza euclidea manca soltanto `||q||^2`, costante per tutti gli indici. Quindi
`argmin_i s_i` coincide con `argmin_i ||q-t_i||^2`. Il prodotto GLWE per il template pubblico e
l'aggiunta del termine costante sono in
[sorgente, L1124-L1160](../src/private_argmin.rs#L1124-L1160).

Da Cauchy-Schwarz e `||q||^2 <= 1024`:

```text
||t_i||^2 - 2 sqrt(||t_i||^2 * 1024)
    <= s_i <=
||t_i||^2 + 2 sqrt(||t_i||^2 * 1024).
```

Il codice usa il ceil intero della radice per ottenere un intervallo conservativo
([sorgente, L247-L288](../src/private_argmin.rs#L247-L288)). Dopo la traslazione per
`domain.lower`, ogni punteggio valido appartiene a `[0,4095]` ed e' rappresentabile con 12 bit.

## 3. Invariante dell'estrazione split4

Sia `x = s_i - domain.lower`, quindi `0 <= x <= 4095`. Il GLWE contiene due viste coerenti:

```text
full = x * 2^52
low  = (x mod 16) * 2^60.
```

Le costanti che fissano le due scale, i quattro bit low, gli otto bit high e la scala d'uscita
sono in [sorgente, L17-L35](../src/private_argmin.rs#L17-L35).

### 3.1 Quattro bit low e quattro correzioni globali

L'estrattore low recupera i bit `0..3` dalla vista modulo 16. Produce quattro LWE piccoli e tre
correzioni interne necessarie alla decomposizione iterativa
([sorgente, L729-L780](../src/private_argmin.rs#L729-L780)). A28 applica poi un PBS dedicato a
ciascuno dei quattro LWE piccoli per ottenere quattro correction ciphertext alla scala full:

```text
correction_j = bit_j(x) * 2^(52+j),  j=0..3.
```

Gli accumulatori sono costruiti in [sorgente, L933-L938](../src/private_argmin.rs#L933-L938) e
le quattro correzioni in [sorgente, L1167-L1201](../src/private_argmin.rs#L1167-L1201).

### 3.2 Residuo high e ricomposizione dei 12 bit

Sottraendo le quattro correzioni al punteggio full si ottiene, nel modello aritmetico esatto,

```text
residual = (x - (x mod 16)) * 2^52
         = (x >> 4) * 2^56.
```

Il codice costruisce questo residuo e poi estrae soltanto otto bit a `Delta=2^56`, che
corrispondono ai bit globali `4..11`
([sorgente, L1202-L1230](../src/private_argmin.rs#L1202-L1230)). La rappresentazione globale
ricuce i quattro bit low con gli otto high e conserva undici correzioni globali
([sorgente, L1231-L1268](../src/private_argmin.rs#L1231-L1268)).

In particolare, non si assume che la vista modulo 16 contenga informazione sui bit alti: essa
serve a cancellare esattamente il nibble basso dalla vista full; l'estrattore high opera sul
quoziente risultante. Il trace diagnostico conserva esplicitamente il checkpoint `high_residual`
([sorgente, L91-L121](../src/private_argmin.rs#L91-L121)), cosi' la correttezza del codice finale
non e' l'unico osservabile del test mirato.

### 3.3 Costo dell'estrazione

Per ciascun template, lo stadio usa:

- `4` KS per estrarre i quattro bit low;
- `8` KS per estrarre gli otto bit high;
- `3 + 4 + 7 = 14` PBS di correzione;
- `6` PBS per ricodificare alla scala booleana i bit `3..7` e `11`
  ([sorgente, L659-L685](../src/private_argmin.rs#L659-L685)).

Quindi A28 conserva `20N` PBS di estrazione, ma usa **`12N` KS** nello stadio invece dei `16N`
dello snapshot A25. I PBS di correzione e ricodifica ricevono gia' un LWE piccolo e producono un
LWE grande; non richiedono l'ulteriore KS di `apply_pbs`. Questa distinzione e' necessaria per non
confondere il conteggio dei blind rotation con quello dei key switch.

## 4. Invariante di selezione bit per bit

I bit ricomposti sono visitati dal piu' significativo al meno significativo
([sorgente, L914-L917](../src/private_argmin.rs#L914-L917)). Siano:

- `C_l` l'insieme dei candidati attivi prima del livello `l`;
- `b_i,l` il bit del punteggio dell'indice `i` al livello `l`;
- `z_i,l = c_i,l AND NOT b_i,l`;
- `a_l = OR_i z_i,l`.

Il circuito conserva il candidato `i` se e solo se

```text
c_i,l+1 = c_i,l AND (b_i,l != a_l).
```

La realizzazione e' in [sorgente, L1299-L1399](../src/private_argmin.rs#L1299-L1399).

**Invariante.** Dopo ciascun livello restano esattamente gli indici il cui prefisso gia'
esaminato e' minimo.

La dimostrazione e' per induzione. Prima del MSB tutti gli indici sono attivi. Se almeno un
candidato attivo ha bit zero, `a_l=1` e sopravvivono esattamente quelli con bit zero. Se nessuno
ha bit zero, `a_l=0`, tutti hanno bit uno e sopravvivono tutti. Dopo 12 livelli restano tutti e
soli gli indici che realizzano il minimo globale; inoltre `minimum_bit_l = NOT a_l`.

## 5. Stato alternato e margine locale

Per evitare un PBS di normalizzazione dopo ogni bit, i livelli pari producono uno stato torus
codificato e quelli dispari tornano a un Booleano fresco.

Dato un candidato Booleano `c`, il suo indicatore zero `z` e `a=OR z`, il livello pari costruisce
linearmente

```text
e = -c - z + a.
```

Sugli stati raggiungibili, `e=-1` identifica esattamente i candidati sopravvissuti; gli inattivi
sono `0` o `+1` ([sorgente, L1364-L1377](../src/private_argmin.rs#L1364-L1377)). Al livello
dispari, `e + w*b` ha codice modulo 16 uguale a 15 soltanto per `(attivo, bit=0)`. Poiche'
l'ingresso fisico e' il valore torus negativo `-1`, la LUT usa `u64::MAX` nella casella 15 per
ottenere il Booleano positivo ([sorgente, L578-L587](../src/private_argmin.rs#L578-L587)). La
normalizzazione successiva applica una LUT a `-e+z-a` e ripristina un candidato Booleano fresco
([sorgente, L1378-L1393](../src/private_argmin.rs#L1378-L1393)).

Assumendo una unita' nominale per ogni uscita PBS fresca, i massimi locali prima di un PBS sono:

| Operazione | Contributi freschi | Bound locale |
|---|---:|---:|
| OR radix-4 | fino a 4 Booleani | 4 |
| stato pari `-c-z+a` | candidato, zero, OR | 3 |
| test zero dispari `e+w*b` | stato codificato, bit | 4 |
| normalizzazione dispari `-e+z-a` | stato, zero, OR | **5** |
| winner scan | candidato, prefisso, max 2 locali | 4 |
| confronto ternario | stato e 2 Booleani | 3 |
| gruppo di output | tag e max 3 digit | 4 |

Il massimo locale cinque e' dichiarato anche nel punto critico del core
([sorgente, L1378-L1381](../src/private_argmin.rs#L1378-L1381)). E' un audit del fan-in
algebrico, non un bound statistico dell'errore.

## 6. Primo minimo, soglia del vincitore e tie-break

Dopo i 12 livelli possono restare piu' candidati soltanto in caso di parita' esatta. Lo scan:

1. forma gruppi di tre candidati;
2. calcola un prefisso esclusivo radix-4 sui flag dei gruppi;
3. combina per ogni indice quel prefisso e al massimo due predecessori locali.

La costruzione del prefisso e' in [sorgente, L793-L839](../src/private_argmin.rs#L793-L839) e lo
scan completo in [sorgente, L1401-L1439](../src/private_argmin.rs#L1401-L1439). La LUT finale
emette uno se e solo se il candidato e' attivo e nessun indice precedente e' attivo. Esiste
quindi un solo winner e, a parita' di punteggio, vince il primo indice della galleria.

Ogni bit pubblico delle soglie definisce poi una maschera sugli indici. Il circuito OR-riduce
soltanto i winner abilitati dalla maschera; poiche' il winner e' one-hot, il risultato e' il bit
della soglia associata a quell'unico vincitore. Maschere vuote o piene diventano costanti e non
richiedono PBS ([sorgente, L1441-L1486](../src/private_argmin.rs#L1441-L1486)).

Una macchina a tre stati `less/equal/greater`, codificata come `0/2/4`, confronta il minimo con la
soglia selezionata. L'accettazione e' inclusiva, `minimum <= threshold`; una soglia sotto
`domain.lower` forza il rifiuto, mentre una soglia sopra `domain.upper` puo' essere clampata
([sorgente, L1491-L1517](../src/private_argmin.rs#L1491-L1517)).

Conseguenza: una seconda identita' a pari punteggio o una identita' piu' lontana con soglia piu'
permissiva non puo' autorizzare la query al posto del primo minimo. Il test clear esercita
esplicitamente tie e soglie per-template
([sorgente, L1661-L1682](../src/private_argmin.rs#L1661-L1682)); il confronto a 12 bit e'
enumerato su tutte le coppie del dominio
([sorgente, L1720-L1741](../src/private_argmin.rs#L1720-L1741)).

## 7. Uscita e sicurezza della scala `CODE_DELTA_LOG=56`

Per ciascuna posizione binaria usata dai codici `1..N`, il circuito OR-riduce i winner il cui
`indice+1` possiede quel bit. L'ultimo PBS emette un digit locale fresco `1`, `2` o `4`. Tre digit
e il tag di accettazione `8` formano un codice locale in `[0,15]`; la LUT di gruppo emette zero
senza tag e il payload spostato con il tag. Il payload viene mascherato alla lunghezza reale del
gruppo, quindi gli stati non raggiungibili dell'ultimo gruppo non possono produrre bit oltre il
codice supportato ([sorgente, L598-L606](../src/private_argmin.rs#L598-L606)). La somma di al
massimo tre gruppi ricostruisce il codice finale
([sorgente, L1519-L1564](../src/private_argmin.rs#L1519-L1564)).

Con `N<=128`, i plaintext leciti sono `0..128`. Alla scala `Delta_code=2^56`, il massimo valore
nominale e' `128*2^56 = 2^63`, quindi non provoca overflow aritmetico `u64` e non collide con lo
zero nel modello noiseless. Il test percorre ogni dimensione di galleria supportata, maschera i
gruppi alla loro lunghezza reale e verifica che ogni uscita LUT moltiplicata per la scala sia
rappresentabile ([sorgente, L1883-L1896](../src/private_argmin.rs#L1883-L1896)).

Questo argomento stabilisce sicurezza del range e della codifica, non la probabilita' di corretta
decodifica in presenza di rumore. L'unico plaintext previsto resta

```text
code = accept * (first_argmin_index + 1).
```

## 8. Conteggi esatti di PBS e KS

Sia `R(k)` il numero di PBS di un OR radix-4 su `k` ciphertext:

```text
R(0)=R(1)=0
R(k)=ceil(k/4) + R(ceil(k/4)),  k>1.
```

La funzione corrispondente e' in [sorgente, L319-L325](../src/private_argmin.rs#L319-L325).

Per `N` template:

- estrazione: `14N` PBS di correzione + `6N` ricodifiche = `20N`;
- selezione: `11N` test zero + `6N` normalizzazioni dispari + `12R(N)` OR, cioe'
  `17N + 12R(N)`;
- scan: `scan(N)` secondo [sorgente, L328-L357](../src/private_argmin.rs#L328-L357);
- confronto finale: 12 aggiornamenti e un tag = 13 PBS;
- codifica: `output(N)` secondo [sorgente, L360-L385](../src/private_argmin.rs#L360-L385).

Per tredici maschere di soglia pubbliche, dodici bit piu' la sentinella `threshold<lower`, sia
`M_j=0` per una maschera vuota o piena e `M_j=R(k_j)` per una maschera parziale con `k_j` indici
abilitati. Allora:

```text
PBS(N, thresholds)
  = 37N + 12R(N) + scan(N) + output(N) + 13 + sum_j M_j

PBS_max(N)
  = 37N + 25R(N) + scan(N) + output(N) + 13.
```

Le formule sono implementate in [sorgente, L388-L445](../src/private_argmin.rs#L388-L445).

### Caso `N=127`

Per `R(127)=43`:

| Stadio | PBS, soglia uniforme |
|---|---:|
| estrazione | `20*127 = 2540` |
| selezione | `17*127 + 12*43 = 2675` |
| scan del primo minimo | `222` |
| confronto finale | `13` |
| output | `150` |
| **totale** | **`5600`** |

Con soglie arbitrarie, `sum_j M_j <= 13R(127)=559`, quindi il limite indipendente dai valori e'
**6.159 PBS**. I due valori sono fissati nei test
([sorgente, L1898-L1920](../src/private_argmin.rs#L1898-L1920)).

Nel caso uniforme, i `5600-20N=3060` PBS esterni all'estrazione passano per `apply_pbs` e includono
un KS ([sorgente, L1041-L1053](../src/private_argmin.rs#L1041-L1053)). A questi si aggiungono i
`12N=1524` KS espliciti dell'estrazione split4:

```text
KS_uniform(127) = 3060 + 12*127 = 4584.
```

Lo snapshot A25 richiedeva 5.092 KS nello stesso circuito uniforme. A28 ne risparmia quindi 508,
cioe' `4N`, senza cambiare i 5.600 PBS. Il risparmio e' un conteggio deterministico derivato
staticamente dalla struttura; non va trasformato automaticamente in uno speed-up temporale.

## 9. Evidenza FHE collegata agli invarianti

### 9.1 Confini split4: 198/198 su tre chiavi

Il report mirato
[`exact_id_split4_boundaries_2026-09-02.md`](exact_id_split4_boundaries_2026-09-02.md) conserva
tre processi con chiavi fresche, 66 casi ciascuno e **198/198 esiti corretti senza mismatch**. La
griglia include `0..15`, le terne `2^j-1,2^j,2^j+1` per `j=4..11`, `4095` e 78 esecuzioni noisy
complessive. Per ogni caso sono stati verificati score full/modulo 16, bit, correzioni,
`high_residual`, codice e conteggio di 53 PBS a `N=1`.

Il checkpoint high ha sempre decodificato `x>>4` a `Delta=2^56`. Il massimo errore di fase
annotato e' stato `0,260839 Delta`, sotto il confine di decodifica `0,5 Delta`; e' un massimo
campionario, non un bound. Questa run isola bene l'estrazione, ma da sola non valida selezione,
tie-break, soglie per-template o codici diversi da uno a `N>1`.

### 9.2 Suite primaria: 632/632 a `N=127`

Il report host
[`fhe_digiface_exact_primary_split4_2026-09-02.md`](../../../benchmark/results/fhe_digiface_exact_primary_split4_2026-09-02.md)
e il relativo
[`JSON`](../../../benchmark/results/fhe_digiface_exact_primary_split4_2026-09-02.json) registrano:

- **632/632** codici exact-ID uguali all'oracolo clear;
- zero discrepanze e zero errori operativi;
- 131 autorizzazioni attese e 131 osservate;
- 632 probe ciphertext distinti e 632 result ciphertext distinti;
- 5.600 PBS in ogni query;
- `code_delta_log=56` e input hash invariati durante il run.

La suite comprende 5 casi storici di frontiera, 127 genuine e 500 impostori. Estende quindi la
verifica alla composizione completa a `N=127`, inclusi primo argmin, rifiuti e diversi ID. Usa pero'
una sola coppia di chiavi, una galleria DigiFace sintetica, una soglia uniforme e un insieme finito
di query: e' evidenza empirica FHE-clear, non una prova universale.

## 10. Provenienza e limiti

Gli hash vincolano questo audit agli input e agli artefatti effettivamente eseguiti:

| artefatto | SHA-256 |
|---|---|
| `src/private_argmin.rs` | `7ad812724bf43742d9d03ec9db204e93d6a2c0db3e6ea9dbc650054633fa3596` |
| report confini split4 | `eafa0c0bf32388089a9de868d53beab80ddda4bf483cf1ad46fbc6a8effc4a18` |
| JSON host 632 query | `14ab4e07807744f547d4e042fc768202962e110322c4562cd21ae84d4b8b764d` |
| CSV host 632 query | `8ab4ff23b7f81fa48eb629c9d1b64c93e051d2c8456728f6815f3ba19b79704a` |
| patch sorgenti/config A28 | `58182d45efbfd8d6f87c5f5c842b83952e36a408f4639fb0e2ba019ed259115b` |

Il parameter set del servizio e'
`V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`
([servizio, L38-L41](../src/bin/varco_demo.rs#L38-L41)). Restano separati almeno questi limiti:

1. **Punteggio.** Il prodotto polinomiale pubblico per `-2t_i` combina e amplifica il rumore del
   GLWE prima dell'estrazione.
2. **Estrattore custom.** La sequenza shift, KS, PBS e sottrazione delle correzioni richiede una
   propria analisi quantitativa; i 198 casi ne danno evidenza mirata, non un bound.
3. **Composizione.** I 5.600 PBS e le somme lineari del circuito non ereditano automaticamente il
   `log2_p_fail` nominale del singolo parameter set.
4. **Output.** La somma finale di fino a tre ciphertext a `Delta=2^56` richiede un'analisi della
   decodifica distinta dalla sola sicurezza del range.
5. **Modello di minaccia.** Il server non dimostra la coerenza semantica delle due viste del probe
   cifrato e la galleria resta in chiaro.

Anche il servizio distingue esplicitamente la compatibilita' geometrica della chiave da una
garanzia di failure probability del circuito composto
([servizio, L489-L491](../src/bin/varco_demo.rs#L489-L491)).

Sotto il contratto honest-input e nel
dominio a 12 bit, A28 preserva esattamente primo argmin, tie-break al primo indice, soglia del solo
vincitore e unica uscita cifrata `0`/ID; riduce staticamente l'estrazione da `16N` a `12N` KS senza
cambiare i conteggi PBS; e coincide empiricamente con l'oracolo clear nei 198 casi mirati e nelle
632 query complete documentate. Non segue da questi risultati un bound end-to-end del `p-fail`,
un claim di novita' o una validazione automatica di revisioni successive.

Gli hash dei JSON si riferiscono agli estratti pubblicati; la
[corrispondenza con gli originali](../../../docs/provenienza-dati.json) conserva entrambe le impronte.
