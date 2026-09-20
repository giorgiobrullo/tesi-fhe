# A29: fusione ManyLUT della correzione e del bit Booleano

Data dell'audit: 2026-09-02.

## Stato e limite del documento

Questo documento congela un **design con prova algebrica statica** per ridurre il costo del core
exact-ID dopo lo split4 di A28. Al momento dello snapshot:

- la fusione A29 **non e' implementata** nel core;
- non e' stato eseguito alcun benchmark FHE della fusione;
- non esiste ancora evidenza su latenza, varianza/covarianza reale o correttezza end-to-end;
- i conteggi sotto sono conteggi progettuali di blind rotation/PBS equivalenti, non misure;
- la primitiva ManyLUT e' gia' presente in TFHE-rs e **non costituisce da sola un claim di
  novita'**. L'eventuale contributo riguarda soltanto il co-design e la validazione nel circuito
  exact-ID open-set completo.

### Aggiornamento post-snapshot del 2 settembre 2026

A29 e' stato poi implementato senza riscrivere il corpo storico di questo documento. La revisione
ha superato 198/198 casi boundary, 198/198 casi semantici, il replay senza mismatch, 80/80 query di
frontiera, 632/632 query della suite primaria e 6/6 query E2E Docker. I gate di implementazione,
correttezza funzionale, replay, conteggio, test statici, suite primaria e Docker sono quindi chiusi
dagli artefatti successori. Anche il confronto appaiato A28/A29 e' ora positivo: 60 coppie misurate
sulla stessa chiave/scena e sugli stessi byte cifrati danno una riduzione geometrica dell'8,876%,
intervallo bootstrap del run [8,092%, 9,728%], 57/60 vittorie e zero discrepanze su 72 coppie
incluse le warm-up. Le 60 coppie misurate ripetono cinque probe di frontiera fissati 12 volte
ciascuno nei tre blocchi-chiave per stimare la latenza; non sono 60 casi biometrici indipendenti.
Il carico alto limita la generalizzazione delle latenze. A29 e' quindi l'ultimo snapshot promosso
e congelato; resta separatamente aperto un bound composito applicabile
della `p-fail`. Le frasi `non implementata` e `non misurata` sotto descrivono esclusivamente lo
stato al momento dello snapshot statico.

Il risultato statico e' positivo: nel modello ideale, con il parameter set corrente una singola
blind rotation puo' produrre, dallo stesso small LWE estratto, sia la correzione alla scala del
punteggio sia il bit alla scala Booleana. Se i gate FHE confermeranno il design, questo
consentirebbe di eliminare cinque blind rotation per template mantenendo la stessa funzione e lo
stesso protocollo exact-ID.

## Non e' il `MultiBit` BSK di TFHE-rs

Nel codice TFHE-rs esistono due concetti distinti:

1. `ShortintBootstrappingKey::MultiBit`, che raggruppa bit della chiave durante il bootstrap;
2. `ManyLookupTable`, che ruota una sola GLWE e ne estrae piu' campioni LWE, cioe' piu' funzioni
   dello **stesso** input.

A29 usa il secondo concetto con il bootstrap key **Classic** corrente. Non cambia schema,
parametri o chiavi. Il core A29 congelato rifiuta esplicitamente un BSK non Classic sia nella
validazione sia nel percorso di calcolo; il sorgente e' identificato dall'hash e dalla patch
riportati sotto, perche' le righe del
[`private_argmin.rs` vivo](../src/private_argmin.rs) possono spostarsi con gli esperimenti
successivi. L'enum distinto e' definito in
`tfhe-0.11.3/src/shortint/server_key/mod.rs:139-145`.

Una blind rotation non puo' fondere gli small LWE distinti dei bit 3, 4, 5 e 6. La fusione viene
eseguita **una volta per bit**: ciascuna delle quattro blind rotation emette due LWE, correzione e
Booleano.

## Scale correnti

Si usa il torus nativo $q=2^{64}$. Le costanti del core sono:

\[
\Delta_{\mathrm{full}}=2^{52},
\qquad
\Delta_{\mathrm{bool}}=2^{59},
\qquad
N_p=2048.
\]

L'estrazione di un bit produce uno small LWE con plaintext ideale:

\[
B=b\frac q2,
\qquad b\in\{0,1\}.
\]

Per un bit globale $j$, la correzione che deve essere sottratta dal residuo full e':

\[
C_j=b2^{52+j}.
\]

Il codice corrente ottiene prima una uscita grezza a segno con ampiezza

\[
\alpha_j=2^{52+j-1}
\]

e poi aggiunge in chiaro $\alpha_j$, trasformando

\[
-\alpha_j,+\alpha_j
\quad\longrightarrow\quad
0,2\alpha_j=C_j.
\]

La ricodifica Booleana separata usa analogamente

\[
\beta=2^{58}=\frac{\Delta_{\mathrm{bool}}}{2}
\]

e trasforma $-\beta,+\beta$ in $0,2^{59}$.

## Accumulatore a due uscite

Per ogni $j\in\{3,4,5,6\}$, si aggiunge $q/8=2^{61}$ allo small LWE e si costruisce una GLWE
triviale con maschera nulla e body polinomiale:

\[
P[k]=
\begin{cases}
-\alpha_j & 0\le k < N_p/2,\\
-\beta & N_p/2\le k < N_p.
\end{cases}
\]

E' necessario verificare a setup che $N_p\bmod 4=0$. Con $N_p=2048$, i due plaintext ideali
dopo il centering vengono convertiti dal modulus switch nelle rotazioni:

\[
r_0=N_p/4,
\qquad
r_1=N_p+N_p/4.
\]

La seconda rotazione differisce dalla prima di un intero giro negaciclico e cambia quindi il segno
di tutto il polinomio. Dopo la sola blind rotation si estraggono due coefficienti:

| sample extraction | bit 0, prima dello shift | bit 1, prima dello shift | shift pubblico | uscita |
|---|---:|---:|---:|---:|
| grado `0` | $-\alpha_j$ | $+\alpha_j$ | $+\alpha_j$ | $b2^{52+j}$ |
| grado `N_p/2` | $-\beta$ | $+\beta$ | $+\beta$ | $b2^{59}$ |

In forma operativa:

```rust
let mut centered = small_bit.clone();
lwe_ciphertext_plaintext_add_assign(&mut centered, Plaintext(1u64 << 61));

let mut rotated = accumulator.clone();
blind_rotate_assign(&centered, &mut rotated, fourier_bootstrap_key);

extract_lwe_sample_from_glwe_ciphertext(
    &rotated,
    &mut correction,
    MonomialDegree(0),
);
extract_lwe_sample_from_glwe_ciphertext(
    &rotated,
    &mut boolean,
    MonomialDegree(polynomial_size.0 / 2),
);

lwe_ciphertext_plaintext_add_assign(&mut correction, Plaintext(alpha));
lwe_ciphertext_plaintext_add_assign(&mut boolean, Plaintext(bool_delta >> 1));
```

Il contatore deve aumentare di **una** blind rotation, non due. Le due sample extraction non usano
un altro BSK e non richiedono key switch.

### Prova del margine discreto

Per il bit zero, la divisione negaciclica per $X^{N_p/4}$ porta:

- il coefficiente `0` al centro della prima meta' di $P$;
- il coefficiente `N_p/2` al centro della seconda meta'.

Per il bit uno, il giro aggiuntivo cambia entrambi i segni. Ogni campione resta nella propria meta'
per tutti gli errori interi di rotazione:

\[
|\varepsilon|<N_p/4.
\]

Il margine geometrico ideale nel torus e' $q/8$. Tenendo conto dell'arrotondamento del modulus
switch al bin di rotazione piu' vicino, una condizione simmetrica conservativa sul rumore torus e'

\[
|e_{\mathrm{torus}}| < q\left(\frac18-\frac{1}{4N_p}\right)
=0{,}1248779296875q\quad\text{per }N_p=2048.
\]

La disuguaglianza e' stretta: al confine positivo di mezzo bin il round-to-nearest entra nel bin
non sicuro.

Durante l'audit e' stata verificata aritmeticamente l'identita' per:

- $j=3,4,5,6$;
- $b=0,1$;
- ogni $\varepsilon\in[-511,511]$;
- aritmetica `u64` wrapping e segni negaciclici.

Tutte le combinazioni hanno prodotto le due uscite ideali. Questa e' una verifica del layout
polinomiale, non un test FHE: non include BSK, FFT, modulus switch dei coefficienti della maschera o
rumore.

## Dove si applica nel circuito

Le fusioni sono:

- bit globale 3: la ricodifica low-to-full di `low.small_lsb_first[3]` emette anche il Booleano;
- bit globali 4, 5 e 6: le prime tre correzioni dell'estrattore high emettono anche il Booleano;
- bit globale 7: nessuna fusione necessaria, perche' la correzione high locale 3 e' gia' a
  $2^{56+3}=2^{59}=\Delta_{\mathrm{bool}}$ e puo' essere clonata;
- bit globale 11: resta una ricodifica dedicata, perche' l'ultimo small LWE non possiede una
  correction ciphertext.

Il percorso split diventa quindi:

\[
3\ \text{PBS low}
+4\ \text{PBS low-to-full}
+7\ \text{PBS high}
+1\ \text{PBS bit 11}
=15\ \text{PBS/template}.
\]

I key switch dell'estrazione non cambiano rispetto ad A28:

\[
4\ \text{KS low}+8\ \text{KS high}=12\ \text{KS/template}.
\]

## Conteggi progettuali

Rispetto ad A28 vengono eliminate:

- quattro ricodifiche Booleane separate per i bit 3..6;
- una ricodifica separata per il bit 7.

Il risparmio e' esattamente $5N$ blind rotation. Nella formula dell'upper bound il coefficiente
lineare passa quindi da `37*N` a `32*N`; i termini di riduzione OR, scan, output e selezione della
soglia restano invariati.

| galleria $N$ | PBS uniformi A28 | PBS uniformi A29 | upper bound A28 | upper bound A29 | risparmio |
|---:|---:|---:|---:|---:|---:|
| 64 | 2.814 | **2.494** | 3.087 | **2.767** | 320 |
| 127 | 5.600 | **4.965** | 6.159 | **5.524** | 635 |
| 128 | 5.640 | **5.000** | 6.199 | **5.559** | 640 |

A $N=127$, il risparmio progettuale e' l'11,34% del totale uniforme e il 25% dello stadio
extract, che passa da $20N=2540$ a $15N=1905$ blind rotation. Non ne segue automaticamente lo
stesso risparmio di latenza.

Ogni PBS fuori dallo stadio extract usa `apply_pbs`, quindi un big-to-small KS. Le 15 blind
rotation extract ricevono gia' small LWE, mentre l'estrazione dei bit esegue 12 KS/template. Il
conteggio totale dei KS e' percio':

\[
K(N)=P(N)-15N+12N=P(N)-3N.
\]

| galleria $N$ | KS totali, soglia uniforme | KS totali, upper bound |
|---:|---:|---:|
| 64 | **2.302** | **2.575** |
| 127 | **4.584** | **5.143** |
| 128 | **4.616** | **5.175** |

Per evitare ambiguita' nella tesi, `4.965 PBS` va descritto come numero di **blind rotation/PBS
equivalenti**: quattro di esse per template emettono due LWE invece di uno.

## Supporto concreto in TFHE-rs 0.11.3

`Cargo.lock` fissa `tfhe 0.11.3`, checksum crates.io
`ebacd6973a20d4967a64bac147ad6890182fd8ce910ce841ecbb3cae47bdf5ff`.

I riferimenti seguenti sono alla directory `src/` del crate TFHE-rs `0.11.3`:

- `core_crypto/algorithms/lwe_programmable_bootstrapping/fft64.rs:180-219` espone
  `blind_rotate_assign`, che modifica una GLWE in place senza imporre una singola sample extraction;
- `core_crypto/algorithms/glwe_sample_extraction.rs:89-165` estrae un LWE da un grado monomiale
  arbitrario e verifica dimensione equivalente e modulo;
- `shortint/server_key/mod.rs:447-461` definisce `ManyLookupTable` con accumulator, stride e gradi
  delle diverse funzioni;
- `shortint/server_key/mod.rs:1285-1335` mostra la sequenza di produzione: un KS, una sola
  `apply_blind_rotate`, poi un loop di sample extraction a gradi diversi;
- `shortint/engine/mod.rs:190-267` costruisce il layout multi-funzione e lo stride fra le sub-LUT;
- `core_crypto/fft_impl/fft64/crypto/bootstrap.rs:301-351` implementa la divisione iniziale per il
  monomio del body e i CMUX della blind rotation;
- `core_crypto/fft_impl/common.rs:10-24` mostra il modulus switch verso il modulo di rotazione;
- `shortint/parameters/classic/tuniform/p_fail_2_minus_64/ks_pbs.rs:8-25` fissa $N_p=2048$,
  dimensione LWE 879, GLWE 1 e `log2_p_fail=-71.625` per il parameter set corrente.

La `generate_many_lookup_table` shortint pubblica non va usata direttamente qui. Essa assume il
dominio e il delta shortint ordinari; il core exact-ID usa raw LWE e deve produrre contemporaneamente
ampiezze $\alpha_j=2^{54},2^{55},2^{56},2^{57}$ e $\beta=2^{58}$. Serve quindi l'accumulatore
raw custom sopra, costruito come GLWE trivialmente cifrata.

## Rischi implementativi

1. **Peso del bit 7.** La funzione corrente `extracted_bit_weight` restituirebbe peso 2 per una
   correction con log 59. I bit fused 3..6 e il bit diretto 7 devono essere dichiarati
   esplicitamente Booleani canonici di peso 1.
2. **Origine del bit 3.** Deve essere `low.small_lsb_first[3]`; l'estrattore high inizia dal bit
   globale 4.
3. **Un input per blind rotation.** Non si devono sommare gli small LWE dei quattro bit tentando una
   sola LUT globale: la prova vale per correzione e Booleano dello stesso bit.
4. **Mutabilita' dell'accumulatore.** `blind_rotate_assign` modifica la GLWE. Ogni iterazione Rayon
   deve ruotare una clone locale, lasciando immutabile la LUT condivisa.
5. **Contatore.** Una rotazione con due sample extraction incrementa `pbs_count` una sola volta.
6. **Scale globali.** `alpha` deve usare l'indice globale. Rinumerare i bit high da zero senza
   incorporare `HIGH_DELTA_LOG=56` rompe le scale.
7. **Rappresentazione del trace.** Il trace deve distinguere correction, Booleano fused e riuso del
   bit 7; il bridge finale da solo non basta per un audit A/B del rumore.
8. **Nessun protocollo nuovo.** Le due uscite restano interne al server; la risposta continua a
   essere soltanto `0` oppure `indice+1`.
9. **Storico separato.** I report A25/A28 e i loro conteggi non vanno riscritti retroattivamente come
   evidenza di A29.

## Rumore, dipendenza e p-fail

Le due sample extraction provengono dalla stessa GLWE ruotata. Sono LWE validi sotto la stessa
chiave equivalente, come dimostra l'implementazione ManyLUT di TFHE-rs, ma i loro errori non sono
indipendenti.

La correction fused viene sottratta dal residuo e influenza i bit successivi; il Booleano della
stessa rotazione entra nel torneo. Il bit 7 riusato ha la stessa dipendenza: la sua correction
influenza il residuo high e viene anche consumata come bit. Non e' quindi lecito:

- moltiplicare probabilita' assumendo indipendenza;
- applicare meccanicamente `4965 * 2^-71.625` come bound dimostrato della query;
- assumere che un accumulatore a due plateau abbia la stessa distribuzione d'errore osservata di un
  accumulatore costante;
- promuovere il design sulla sola base del conteggio.

Il margine geometrico ideale del lookup fused e' $q/8$; per il calcolo discreto conservativo si
usa invece $q(1/8-1/(4N_p))$. La correction separata corrente usa idealmente $q/4$, mentre la
ricodifica Booleana che A29 elimina usa gia' idealmente $q/8$: il margine geometrico di decisione
all'ingresso del lookup Booleano non viene ristretto, ma i due eventuali errori diventano
condivisi e il comportamento FHE end-to-end resta da misurare.

Usando soltanto come sensibilita' il modello di A28 documentato in
[`exact_id_extraction_noise_audit_2026-09-02.md`](exact_id_extraction_noise_audit_2026-09-02.md), il
peggior ingresso fused e' il bit globale 4:

| modello | sigma input | z al margine conservativo | log2 coda modellata | log2 union 127 score |
|---|---:|---:|---:|---:|
| base | 0,008638276 | 14,456 | -154,938 | -147,949 |
| con varianza MS separata | 0,008764006 | 14,249 | -150,623 | -143,634 |

Sono code Gaussiane bilaterali modellate, non bound formali. La sensibilita' pessimistica che somma gli RMS
per disuguaglianza triangolare usa sigma 0,0178295 e produce circa `log2 p=-38,548` per score e
`-31,559` dopo l'union aritmetica su 127 score. Anche questa non e' una probabilita' dimostrata, ma
mostra perche' la covarianza va misurata e dichiarata.

## Checklist originaria prima della promozione

Al momento dello snapshot statico era stata preregistrata la seguente checklist. Lo stato
successore sotto documenta esplicitamente una sostituzione motivata del punto 2, invece di fingere
che la lista originaria sia stata eseguita alla lettera.

1. **Test puro dell'accumulatore:** entrambi i bit, $j=3..6$, tutti gli offset interi
   $|\varepsilon|<N_p/4$, verifica delle transizioni esattamente ai bordi e assert
   `polynomial_size % 4 == 0`.
2. **Micro-harness FHE A/B su almeno tre chiavi fresche:** per gli stessi small LWE confrontare il
   percorso precedente a due PBS e quello fused; decifrare entrambe le uscite e richiedere zero
   mismatch semantici.
3. **Misura appaiata del rumore:** per bit e chiave registrare errore torus signed di correction e
   Booleano, media, RMS/deviazione, massimo assoluto, covarianza e correlazione. Ripetere su
   ciphertext freschi o score diversi: reiterare lo stesso PBS deterministico non crea campioni.
4. **Bit 7 diretto:** dimostrare che correction e bridge sono lo stesso ciphertext canonico a
   $2^{59}$, con zero errori di decodifica e rumore compatibile con il fan-in successivo.
5. **Frontiere split4:** tutti i residui 0..15, estremi 0/4095 e $2^j-1,2^j,2^j+1$ per i bit
   globali, su piu' chiavi.
6. **Semantica exact-ID completa:** N=1..8 e N=64/127/128, pareggi con primo argmin, soglia stretta,
   accept/reject, soglie uniformi e arbitrarie, ID massimo 128.
7. **Replay diagnostico:** zero mismatch nei checkpoint score, correction, Booleani fused, torneo,
   soglia del vincitore e codice finale.
8. **Conteggi:** assert esatti a 2.494/4.965/5.000 PBS uniformi e
   2.767/5.524/5.559 upper bound; 4.584 KS a N=127 uniforme.
9. **Test statici:** `cargo fmt`, test release, Clippy `-D warnings`, test Python e validator della
   formula aggiornato.
10. **Benchmark appaiato e interleaved:** stessa chiave e stessi byte di input A28/A29, ordine
    bilanciato e diagnostica del carico; riportare latenza e distribuzione, senza inferire la
    velocita' dal solo -11,34% di rotazioni.
11. **Suite primaria e Docker soltanto dopo il freeze:** congelare hash di core/binario, eseguire le
    632 query e poi l'E2E provenance-bound. Gli artefatti precedenti restano storici.

Nello stato successore descritto nel banner, i gate 1 e 3-11 hanno evidenza positiva. Il gate 2,
letto letteralmente, non e' stato eseguito: lo stress boundary confronta le uscite fused con
l'oracolo su tre chiavi, ma non calcola in parallelo il vecchio percorso a due PBS sullo stesso
small LWE. Questa A/B ridondante e' stata sostituita dall'insieme di boundary, semantica, replay,
suite primaria e confronto completo A28/A29, e la differenza resta registrata invece di chiamare
chiuso ogni punto della checklist originaria. Il gate 10 e' positivo nel disegno appaiato, ma non
va reinterpretato come benchmark su macchina idle: il carico era alto, le query entro blocco erano
seriali e i tre blocchi-chiave non provano una distribuzione universale. Il lavoro sulla `p-fail`
resta inoltre un obbligo separato che i test empirici non possono chiudere. Evidenza:
[`fhe_digiface_exact_paired_a28_a29_2026-09-02.md`](../../../benchmark/results/fhe_digiface_exact_paired_a28_a29_2026-09-02.md)
e [`exact_id_manylut_pfail_accounting_2026-09-02.md`](exact_id_manylut_pfail_accounting_2026-09-02.md).

## Provenienza dello snapshot statico

Gli hash sono stati calcolati in sola lettura il 2026-09-02:

| artefatto | SHA-256 |
|---|---|
| `src/private_argmin.rs` | `7ad812724bf43742d9d03ec9db204e93d6a2c0db3e6ea9dbc650054633fa3596` |
| `Cargo.lock` | `1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a` |
| `core_crypto/algorithms/lwe_programmable_bootstrapping/fft64.rs` | `174c74c30625316491a408b34f5a7bd135ead4652df63d102b8791b13e957e52` |
| `core_crypto/algorithms/glwe_sample_extraction.rs` | `981d3839cd83cb8c24b02fe48d945d61e23c9c0f2e714b554d9296eed304ec43` |
| `shortint/server_key/mod.rs` | `36002891d536e90caa3719a130e066342018234ba7527d858e2448ed606c8f73` |
| `shortint/engine/mod.rs` | `23e46b3e53bab7d8832438de5bd2f87bd806c86ccef0d54d2c2389817eeec7b1` |
| `core_crypto/fft_impl/fft64/crypto/bootstrap.rs` | `7b39fd3c98c7958bea756109cdf8354677790071a3d17acec6d963d15efaeebe` |
| `core_crypto/fft_impl/common.rs` | `64768c9574e1d932610c3859dfab0a6736f023d0982457b00d6c422b92c33ac5` |
| parameter set `ks_pbs.rs` | `14a3c8cae508fec1f96e76ed74e186efbd005c0c84292975333dc202a6987bb6` |

Questi hash identificano il codice letto per il design; non sono hash di una implementazione A29.
