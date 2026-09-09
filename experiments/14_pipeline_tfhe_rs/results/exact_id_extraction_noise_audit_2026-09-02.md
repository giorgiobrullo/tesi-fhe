# Audit analitico del rumore nell'estrazione dei bit exact-ID

Data dell'audit: 2026-09-02.

## Stato e perimetro

Questo documento verifica il percorso di estrazione dei bit usato dal circuito exact-ID TFHE-rs:

- vista completa del punteggio con scala \(\Delta_{\mathrm{full}}=2^{52}\) e 12 bit;
- vista modulo 16 con scala \(\Delta_{\mathrm{low}}=2^{60}\) e 4 bit;
- correzione iterativa del residuo tramite PBS;
- possibilità di usare i bit robusti della vista modulo 16 per eliminare i primi bit anche dal residuo completo.

L'audit è analitico. Al momento della sua redazione, la suite primaria A25 da 632 query era ancora in esecuzione. Gli esiti parziali della suite non sono stati usati per stimare probabilità di fallimento. Anche una futura esecuzione completa senza discrepanze sarebbe evidenza di correttezza funzionale sui casi provati, non evidenza sperimentale di una coda di probabilità dell'ordine di \(2^{-41}\) o inferiore.

Il runtime del progetto resta TFHE-rs 0.11.3. Le formule TUniform di TFHE-rs 1.7.0 sono usate soltanto come modello analitico locale perché la 0.11.3 espone il codice dell'estrattore e i parametri TUniform, ma nella cartella delle formule di rumore espone soltanto le varianti Gaussian.

## Esito in breve

La propagazione pericolosa esiste nel modello generico ufficiale:

1. ogni PBS di correzione produce un nuovo errore nel ciphertext sottratto dal residuo;
2. il bit successivo effettua uno shift del residuo;
3. nella vista completa, l'errore della prima correzione viene moltiplicato per \(2^{10}\) prima di estrarre il bit 1;
4. con le formule TUniform ufficiali e un'approssimazione Gaussiana, il bit 1 ha una coda modellata di circa \(2^{-41.14}\) per punteggio, molto peggiore del valore nominale per un normale PBS.

Questo non prova che il tasso reale sia \(2^{-41.14}\): la varianza PBS generica può essere conservativa per questi accumulatori costanti, gli errori possono essere correlati e la trasformazione della varianza in una coda Gaussiana non è un teorema sul circuito.

La correzione consigliata è uno split a quattro bit:

- estrarre i bit 0..3 dalla vista modulo 16;
- ricodificarli in quattro correzioni alla scala completa;
- sottrarli dal residuo completo;
- iniziare l'estrazione completa dal bit globale 4.

Questa variante mantiene 14 PBS di estrazione/correzione per template, mantiene il totale corrente di 5.600 PBS a \(N=127\), elimina quattro key switch per template e sposta il primo punto sensibile al bit 4. La sua coda Gaussiana modellata diventa circa \(2^{-609.37}\) per punteggio, oppure \(2^{-592.14}\) includendo separatamente la sensibilità al modulus switch.

## Corrispondenza con l'estrattore ufficiale

Il core locale implementa la stessa sequenza dell'algoritmo WoP-PBS di TFHE-rs 0.11.3:

1. copia del residuo;
2. shift a sinistra;
3. key switch dalla chiave LWE grande a quella piccola;
4. conservazione del piccolo LWE del bit;
5. aggiunta di \(q/4\);
6. PBS con accumulatore costante negativo;
7. aggiunta di \(\alpha\);
8. sottrazione della correzione dal residuo.

Fonti locali del progetto:

- costanti e dimensioni: /Users/giorgiobrullo/Documents/Tesi-FHE/experiments/14_pipeline_tfhe_rs/src/private_argmin.rs:17-31;
- estrattore strumentato: /Users/giorgiobrullo/Documents/Tesi-FHE/experiments/14_pipeline_tfhe_rs/src/private_argmin.rs:701-755;
- accumulatori di correzione: /Users/giorgiobrullo/Documents/Tesi-FHE/experiments/14_pipeline_tfhe_rs/src/private_argmin.rs:895-909;
- punteggi duali ed estrazioni: /Users/giorgiobrullo/Documents/Tesi-FHE/experiments/14_pipeline_tfhe_rs/src/private_argmin.rs:1095-1183;
- contratto della vista duale: /Users/giorgiobrullo/Documents/Tesi-FHE/experiments/14_pipeline_tfhe_rs/src/private_argmin.rs:822-831;
- codifica client delle due viste nello stesso GLWE: /Users/giorgiobrullo/Documents/Tesi-FHE/experiments/14_pipeline_tfhe_rs/src/bin/varco_demo.rs:540-570.

Fonti ufficiali TFHE-rs 0.11.3:

- specifica e implementazione di extract_bits: /Users/giorgiobrullo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-0.11.3/src/core_crypto/fft_impl/fft64/crypto/wop_pbs/mod.rs:57-70 e 153-221;
- centratura a \(q/4\), accumulatore \(-\alpha\), aggiunta di \(\alpha\) e sottrazione: stesso file, righe 189-220;
- API high-level marcata Experimental: /Users/giorgiobrullo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-0.11.3/src/shortint/wopbs/mod.rs:626-657;
- test ufficiale di estrazione basato su parametri toy insicuri: /Users/giorgiobrullo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-0.11.3/src/core_crypto/fft_impl/fft64/crypto/wop_pbs/tests.rs:92-130 e 209-235.

La corrispondenza algoritmica non trasferisce automaticamente una garanzia sui parametri. L'API WoP-PBS usa un proprio server key e parametri dedicati. Il set legacy 2+2 usa PBS \(2^{15}\times2\), non il PBS ordinario \(2^{23}\times1\) del progetto:

- /Users/giorgiobrullo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-0.11.3/src/shortint/parameters/parameters_wopbs_message_carry.rs:403-428.

## Parametri effettivi

Il progetto usa V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64:

\[
n=879,\qquad k=1,\qquad N=2048,
\]

\[
B_{\mathrm{PBS}}=2^{23},\quad L_{\mathrm{PBS}}=1,
\]

\[
B_{\mathrm{KS}}=2^3,\quad L_{\mathrm{KS}}=5.
\]

Le distribuzioni sono TUniform(46) per LWE e TUniform(17) per GLWE; il limite shortint dichiarato è max_noise_level \(=5\), con log2_p_fail nominale \(-71.625\).

Fonti:

- runtime 0.11.3: /Users/giorgiobrullo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-0.11.3/src/shortint/parameters/classic/tuniform/p_fail_2_minus_64/ks_pbs.rs:8-25;
- copia mantenuta nella 1.7.0, incluso ModulusSwitchType::Standard: /Users/giorgiobrullo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0/src/shortint/parameters/v0_11/classic/tuniform/p_fail_2_minus_64/ks_pbs.rs:7-25.

## Rumore iniziale del punteggio

Sia \(g\) un template e siano \(e_i\) gli errori indipendenti dei coefficienti del GLWE del probe. Il prodotto con i coefficienti \(-2g_i\) dà:

\[
E_0=\sum_i -2g_i e_i,
\]

\[
V_0=4\lVert g\rVert_2^2 V_{\mathrm{TU}(17)}.
\]

La varianza esatta della TUniform con bound logaritmico \(b\), normalizzata rispetto a un modulo \(q\), è:

\[
V_{\mathrm{TU}(b)}
=
\frac{2^{2b+1}+1}{6q^2}.
\]

Fonte:

- /Users/giorgiobrullo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0/src/core_crypto/commons/math/random/t_uniform.rs:75-79.

Con \(b=17\), \(q=2^{64}\) e il bound progettuale \(\lVert g\rVert_2^2=1024\):

\[
V_{\mathrm{TU}(17)}=1.68290326452047\cdot10^{-29},
\]

\[
V_0=6.893171771476\cdot10^{-26},
\qquad
\sigma_0=2.625485054514\cdot10^{-13}.
\]

Il rumore iniziale è trascurabile rispetto a KS e PBS. Esiste anche un bound deterministico dovuto al supporto limitato della TUniform:

\[
|E_0|
\le
\frac{2\lVert g\rVert_1 2^{17}}{2^{64}}.
\]

Il bound grezzo dato dal solo vincolo per coordinata sarebbe
\(\lVert g\rVert_1\le1536\). Il core impone pero' anche una larghezza massima 4096 al dominio
Cauchy: una singola entry con \(\lVert g\rVert_2^2=1023\) richiederebbe gia' 4097 valori, quindi
\(\lVert g\rVert_2^2\le1022\). Risolvendo il problema intero con 512 coordinate in
\(\{-3,\ldots,3\}\), il massimo esatto e' \(\lVert g\rVert_1=682\), raggiunto da 342 valori
assoluti unitari e 170 valori assoluti pari a due. Quindi:

\[
|E_0|\le9.691802915768\cdot10^{-12}.
\]

Anche dopo lo shift massimo \(2^{11}\):

\[
2^{11}|E_0|\le1.984881237149\cdot10^{-8}.
\]

Questo bound riguarda soltanto il rumore della cifratura iniziale. Poiche' e' oltre
\(2^{23.586}\) volte piu' piccolo del raggio della vista completa a \(2^{52}\), chiude quel tratto
con probabilita' di attraversamento del confine pari a zero per un GLWE validamente generato. Non
fornisce un bound analogo per KS, PBS o aritmetica FFT. La derivazione riproducibile e' in
`benchmark/a38_initial_score_bound.py` e
`results/exact_id_a38_initial_score_support_2026-09-02.md`.

## Ricorrenza dell'estrazione

Si lavora in unità torus normalizzate, quindi \(q=1\). Sia \(E_j\) l'errore del residuo prima dell'estrazione del bit \(j\). Per la vista completa:

\[
\delta=52,
\qquad
s_j=64-\delta-j-1=11-j.
\]

Lo small LWE che entra nel PBS di correzione ha errore:

\[
I_j=2^{s_j}E_j+K_j,
\]

dove \(K_j\) è il rumore additivo del key switch.

Se la selezione del ramo del PBS è corretta, la correzione contiene il bit alla scala attesa e un nuovo errore \(P_j\). Dopo la sottrazione:

\[
E_{j+1}=E_j-P_j.
\]

Usando la convenzione di varianze non correlate del simulatore TFHE-rs:

\[
V_j=V_0+jV_{\mathrm{PBS}},
\]

\[
W_j
=
2^{2s_j}V_j+V_{\mathrm{KS}}.
\]

Il \(q/4\) aggiunto prima del PBS porta i due plaintext ideali a \(q/4\) e \(3q/4\). La distanza da entrambi i confini della LUT negaciclica è:

\[
d=\frac14.
\]

Trasformando il secondo momento in una coda Gaussiana bilaterale:

\[
p_j
\approx
\operatorname{erfc}
\left(
\frac{1}{4\sqrt{2W_j}}
\right).
\]

Questa è un'approssimazione modellistica, non un bound formale.

## Costanti ottenute dalle formule ufficiali

Le formule TUniform della 1.7.0, valutate con il parameter set v0.11 effettivo, danno:

\[
V_{\mathrm{PBS}}
=
1.133226667479\cdot10^{-9},
\]

\[
\sigma_{\mathrm{PBS}}
=
3.366343219992\cdot10^{-5},
\]

\[
V_{\mathrm{KS}}
=
3.526608149211\cdot10^{-7},
\]

\[
\sigma_{\mathrm{KS}}
=
5.938525195038\cdot10^{-4}.
\]

Il valore PBS usa correttamente una mantissa FFT64 di 53 bit. Eliminare per errore questo termine produce il valore più piccolo \(8.8879\cdot10^{-10}\), che non è quello applicabile.

Fonti:

- formula PBS TUniform: /Users/giorgiobrullo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0/src/core_crypto/commons/noise_formulas/lwe_programmable_bootstrap.rs:83-152;
- formula KS TUniform: /Users/giorgiobrullo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0/src/core_crypto/commons/noise_formulas/lwe_keyswitch.rs:59-107;
- mantissa FFT64 pari a 53: /Users/giorgiobrullo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0/src/core_crypto/commons/noise_formulas/noise_simulation/mod.rs:25-30;
- condizioni di validità delle formule PBS: /Users/giorgiobrullo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0/src/core_crypto/commons/noise_formulas/lwe_programmable_bootstrap.rs:79-106;
- il simulatore KS somma input e varianza additiva: /Users/giorgiobrullo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0/src/core_crypto/commons/noise_formulas/noise_simulation/lwe_keyswitch.rs:92-129;
- il simulatore PBS sostituisce il rumore d'ingresso con varianza accumulatore più varianza PBS: /Users/giorgiobrullo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0/src/core_crypto/commons/noise_formulas/noise_simulation/lwe_programmable_bootstrap.rs:115-164.

## Sensibilità separata al modulus switch

Il blind rotation classico arrotonda corpo e maschera LWE al modulo di rotazione \(2N=4096\):

- chiamate a pbs_modulus_switch su corpo e maschera: /Users/giorgiobrullo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-0.11.3/src/core_crypto/fft_impl/fft64/crypto/bootstrap.rs:284-324;
- implementazione dell'arrotondamento: /Users/giorgiobrullo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-0.11.3/src/core_crypto/fft_impl/common.rs:10-24;
- modulo \(2N\) dovuto alla negaciclicità: /Users/giorgiobrullo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-0.11.3/src/core_crypto/commons/parameters.rs:156-160.

La formula standard di modulus switch è:

\[
V_{\mathrm{MS}}
=
n\left(
\frac{1}{48q^2}
+
\frac{1}{24(2N)^2}
\right)
-
\frac{1}{12q^2}
+
\frac{1}{12(2N)^2}.
\]

Fonte:

- /Users/giorgiobrullo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0/src/core_crypto/commons/noise_formulas/modulus_switch.rs:9-31.

Per \(n=879\), \(q=2^{64}\), \(2N=4096\):

\[
V_{\mathrm{MS}}
=
2.187987168630\cdot10^{-6},
\]

\[
\sigma_{\mathrm{MS}}
=
1.479184629663\cdot10^{-3}.
\]

Il simulatore tratta il modulus switch come operazione separata che aggiunge varianza:

- /Users/giorgiobrullo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0/src/core_crypto/commons/noise_formulas/noise_simulation/modulus_switch.rs:31-61.

Per evitare di presentare come ufficiale una composizione che la formula PBS monolitica non espone, il risultato principale usa \(W_j\) senza \(V_{\mathrm{MS}}\). Una seconda colonna di sensibilità usa:

\[
W_j^{+\mathrm{MS}}
=
2^{2s_j}V_j+V_{\mathrm{KS}}+V_{\mathrm{MS}}.
\]

Il rumore di modulus switch non viene accumulato nel residuo: se la selezione è corretta, il PBS produce una nuova correzione con il proprio errore; se la selezione attraversa un confine, l'estrazione è già fallita.

## Vista completa corrente

La tabella usa il bound progettuale \(\lVert g\rVert_2^2=1024\). La colonna \(z\) è il margine \(d/\sigma(I_j)\). Le due colonne di probabilità sono code Gaussiane modellate, non limiti dimostrati.

| bit \(j\) | shift \(s_j\) | correzioni precedenti | \(\sigma(I_j)\) | \(z\) | \(\log_2 p_j\) | \(\log_2 p_j\), con MS separato |
|---:|---:|---:|---:|---:|---:|---:|
| 0 | 11 | 0 | 0.000593853 | 420.980 | -127849.218 | -17752.785 |
| 1 | 10 | 1 | 0.034476469 | 7.251 | **-41.140** | **-41.069** |
| 2 | 9 | 2 | 0.024382162 | 10.253 | -79.534 | -79.253 |
| 3 | 8 | 3 | 0.014938343 | 16.735 | -206.427 | -204.459 |
| 4 | 7 | 4 | 0.008638276 | 28.941 | -609.368 | -592.136 |
| 5 | 6 | 5 | 0.004853982 | 51.504 | -1919.512 | -1756.852 |
| 6 | 5 | 6 | 0.002704664 | 92.433 | -6169.939 | -4750.781 |
| 7 | 4 | 7 | 0.001543827 | 161.935 | -18923.568 | -9869.451 |
| 8 | 3 | 8 | 0.000965853 | 258.838 | -48336.706 | -14453.559 |
| 9 | 2 | 9 | 0.000718224 | 348.081 | -87407.465 | -16681.765 |
| 10 | 1 | 10 | 0.000630864 | 396.282 | -113288.771 | -17441.721 |
| 11 | 0 | 11 | 0.000604257 | 413.731 | -123484.701 | -17666.141 |

Il bit 1 domina: l'errore del primo PBS di correzione viene moltiplicato per \(2^{10}\).

La somma aritmetica delle code modellate è:

\[
p_{\mathrm{score,current}}
\approx
2^{-41.140}.
\]

Applicando un union bound aritmetico ai 127 score:

\[
p_{\mathrm{query,current}}
\lesssim
127p_{\mathrm{score,current}}
\approx
2^{-34.151}.
\]

Includendo separatamente \(V_{\mathrm{MS}}\):

\[
p_{\mathrm{query,current}}^{+\mathrm{MS}}
\approx
2^{-34.080}.
\]

Su 632 query tutte a \(N=127\), lo stesso modello dà:

\[
632\cdot127\cdot p_{\mathrm{score,current}}
\approx
2^{-24.847}
\approx
3.31\cdot10^{-8}.
\]

Zero errori su 632 query sarebbero quindi il risultato atteso anche se questo modello della coda fosse corretto.

Un'applicazione meccanica del valore nominale ai 5.600 PBS darebbe invece:

\[
5600\cdot2^{-71.625}
\approx
2^{-59.174}.
\]

Poiché gli input del bit 1 non seguono il normale budget shortint dopo l'amplificazione della correzione precedente, questa seconda espressione non può essere presentata come bound dimostrato dell'intera query.

## Vista modulo 16 corrente

Per \(\delta=60\):

\[
s_j=64-60-j-1=3-j.
\]

| bit \(j\) | shift \(s_j\) | \(\sigma(I_j)\) | \(\log_2 p_j\) | \(\log_2 p_j\), con MS separato |
|---:|---:|---:|---:|---:|
| 0 | 3 | 0.000593853 | -127849.218 | -17752.785 |
| 1 | 2 | 0.000608927 | -121597.840 | -17627.037 |
| 2 | 1 | 0.000601437 | -124645.191 | -17689.687 |
| 3 | 0 | 0.000596708 | -126628.588 | -17729.071 |

La vista modulo 16 non amplifica significativamente gli errori PBS precedenti. È quindi la sorgente naturale per eliminare i primi quattro bit anche dal residuo completo.

## Split consigliato: quattro bit bassi

LOW_EXTRACTED_BITS è già pari a 4. L'estrattore low esegue tre correzioni e conserva anche small_lsb_first[3] come ultimo bit, senza una quarta correzione.

La variante proposta è:

1. eseguire l'estrazione low corrente dei bit 0..3;
2. per ogni \(j\in\{0,1,2,3\}\), applicare un PBS direttamente al piccolo LWE low del bit;
3. usare un accumulatore costante \(-\alpha_j\), con:

\[
\alpha_j=2^{52+j-1};
\]

4. aggiungere \(\alpha_j\) dopo il PBS, ottenendo:

\[
C_j=b_j2^{52+j}+P_j;
\]

5. sottrarre \(C_0,C_1,C_2,C_3\) dal ciphertext del punteggio completo;
6. iniziare l'estrazione completa dal bit globale \(j=4\);
7. produrre correzioni soltanto per i bit 4..10; il bit 11 resta l'ultimo small LWE.

Il residuo prima del bit 4 contiene quattro errori PBS, come il residuo corrente allo stesso bit. La differenza è che non vengono più eseguite le selezioni pericolose dei bit completi 1, 2 e 3.

### Conteggio

PBS di estrazione/correzione per template:

\[
3\ \text{low}
+
4\ \text{ricodifiche low-to-full}
+
7\ \text{high}
=14.
\]

Il circuito corrente usa:

\[
3\ \text{low}
+
11\ \text{full}
=14.
\]

Conservando le sei ricodifiche Booleane già usate per i bit 3..7 e 11:

\[
14+6=20\ \text{PBS per template}.
\]

A \(N=127\):

\[
20N=2540\ \text{PBS nello stadio di estrazione},
\]

e il totale uniforme dell'intera query resta 5.600 PBS.

### Key switch e profondità

Il percorso corrente esegue:

\[
12\ \text{KS full}+4\ \text{KS low}=16\ \text{KS/template}.
\]

Lo split esegue:

\[
8\ \text{KS high}+4\ \text{KS low}=12\ \text{KS/template}.
\]

Le quattro ricodifiche low-to-full ricevono già piccoli LWE e non richiedono un altro KS. Il risparmio è quindi di quattro KS per template, 508 KS a \(N=127\).

Le quattro ricodifiche low-to-full sono indipendenti nel grafo delle dipendenze dopo l'estrazione low e possono essere eseguite nello stesso livello parallelo. Questo non implica indipendenza statistica dei loro errori. La profondità delle correzioni è:

\[
3+1+7=11,
\]

uguale alla catena full corrente di 11 PBS e non peggiore del percorso critico esistente.

### Margine modellato

Il primo punto high diventa il bit 4:

\[
\sigma(I_4)=0.008638276,
\]

\[
\log_2p_4\approx-609.368.
\]

Con \(V_{\mathrm{MS}}\) separato:

\[
\log_2p_4^{+\mathrm{MS}}\approx-592.136.
\]

Le somme modellate per 127 score sono:

\[
\log_2p_{\mathrm{query,split4}}
\approx
-602.380,
\]

\[
\log_2p_{\mathrm{query,split4}}^{+\mathrm{MS}}
\approx
-585.148.
\]

Questi numeri non diventano una garanzia end-to-end: indicano soltanto che, dentro lo stesso modello, lo split rimuove l'estrazione come collo di bottiglia probabilistico. Gli altri PBS e gli altri percorsi raw-LWE restano da giustificare.

## Sensibilità alle correlazioni

La ricorrenza principale somma le varianze come se gli errori PBS fossero non correlati. Tutti i PBS usano la stessa evaluation key e non è stata dimostrata indipendenza.

Una sensibilità più pessimistica usa la disuguaglianza triangolare sugli RMS:

\[
\sigma(E_j)
\le
\sigma_0+j\sigma_{\mathrm{PBS}},
\]

\[
\sigma(I_j)
\le
2^{s_j}
\left(
\sigma_0+j\sigma_{\mathrm{PBS}}
\right)
+
\sigma_{\mathrm{KS}}.
\]

Per il circuito corrente al bit 1:

\[
\sigma(I_1)\le0.0350652.
\]

Inserendo comunque questo RMS in una coda Gaussiana:

\[
\log_2p_1\approx-39.853.
\]

Per lo split a quattro bit, al bit 4:

\[
\sigma(I_4)\le0.0178295,
\]

\[
\log_2p_4\approx-145.965.
\]

Anche questa non è una probabilità dimostrata: sostituire un RMS più grande dentro una formula Gaussiana resta una sensibilità. Se si applicasse soltanto Chebyshev al secondo momento condizionale, si otterrebbero limiti troppo deboli:

- corrente, bit 1: circa \(1.97\cdot10^{-2}\), cioè \(2^{-5.67}\);
- split4, bit 4: circa \(5.09\cdot10^{-3}\), cioè \(2^{-7.62}\).

Le formule ufficiali di varianza non sono dichiarate come upper bound formali dell'errore FFT; non è quindi corretto trasformare neppure Chebyshev in una garanzia crittografica del circuito.

## Rischi implementativi dello split

1. La ricodifica deve partire da low.small_lsb_first[j], che è già sotto la chiave LWE piccola. Usare la correction low grande introdurrebbe scala e rumore non necessari.
2. Shift e \(\alpha\) devono usare l'indice globale \(j\). Rinumerare il primo bit high come zero produrrebbe scale errate.
3. Le strutture correnti indicizzano full.small_lsb_first e full.corrections_lsb_first con il numero globale del bit. Un vettore high di lunghezza 8 richiede un accessor esplicito globale o slot opzionali; un semplice offset implicito è fragile.
4. Il bit 3 Booleano deve provenire da low.small_lsb_first[3], perché il nuovo estrattore high non produce il bit completo 3.
5. Trace diagnostica e replay assumono attualmente vettori full completi. Il formato dei checkpoint deve distinguere low, low-to-full e high.
6. La correttezza richiede che la vista full e la vista low cifrate rappresentino lo stesso probe. Il server non può verificare questa proprietà sotto cifratura: resta un'assunzione di client onesto già presente nel protocollo duale.
7. Le correzioni low-to-full sono prodotte con la stessa evaluation key e possono avere covarianza. Servono misure mirate su chiavi fresche.
8. La formula PBS generica non dipende dalla LUT. Un accumulatore triviale e costante può avere una varianza reale diversa, verosimilmente minore, ma questo va misurato e non assunto.

## Ottimizzazione opzionale del bit 3

La nuova correzione full del bit 3 codifica:

\[
b_3 2^{55}.
\]

Moltiplicandola per 16:

\[
16b_3 2^{55}
=
b_3 2^{59},
\]

si ottiene la scala Booleana corrente. Questo potrebbe evitare la ricodifica Booleana dedicata del bit 3 e risparmiare un PBS per template:

\[
5600-127=5473\ \text{PBS a }N=127.
\]

Il rumore viene però moltiplicato per 16:

\[
\sigma_{\mathrm{bit3,scaled}}
=
16\sigma_{\mathrm{PBS}}
=
5.386149151988\cdot10^{-4},
\]

\[
V_{\mathrm{bit3,scaled}}
=
256V_{\mathrm{PBS}}
=
2.901060268746\cdot10^{-7}.
\]

Questo valore sembra ancora piccolo rispetto alla distanza fra i codici Booleani, ma entra nei fan-in dello stadio di selezione. Prima di adottarlo servono:

- propagazione del rumore fino al primo PBS successivo;
- verifica del massimo fan-in locale;
- test su tutte le classi residue;
- test su più chiavi fresche;
- conferma del conteggio ridotto a 5.473;
- replay dei checkpoint.

La prima implementazione consigliata conserva la ricodifica Booleana dedicata e il totale di 5.600 PBS.

## Piano di validazione dopo l'implementazione

La validazione minima dello split4 dovrebbe includere:

1. test esaustivo dei 16 residui low e di tutti i pattern dei bit 0..3;
2. punteggi alle frontiere di ogni bit della parola a 12 bit;
3. casi con pareggi, primo argmin, soglie strette e rifiuto;
4. replay cifrato di ogni correzione low-to-full e di ogni bit high;
5. più chiavi fresche;
6. conferma di 5.600 PBS e 2.540 PBS nello stadio extract;
7. confronto di latenza e numero di KS;
8. misura empirica di varianza e covarianza degli errori delle quattro correzioni;
9. esecuzione della suite primaria completa soltanto dopo aver congelato gli hash del nuovo core;
10. mantenimento separato dell'evidenza A25 corrente, che descrive il circuito precedente e non deve essere reinterpretata come evidenza dello split.

## Limiti delle conclusioni

Questo audit stabilisce:

- la ricorrenza esatta con cui il rumore delle correzioni entra nel residuo;
- il motivo per cui il bit completo 1 è il punto peggiore nel modello generico;
- i valori corretti delle formule TUniform per i parametri effettivi;
- la separazione fra rumore fresco PBS e sensibilità al modulus switch;
- la fattibilità dello split a quattro bit senza aumento dei PBS;
- il risparmio di quattro KS per template;
- il forte miglioramento del margine modellato.

Non stabilisce:

- che il tasso reale del circuito corrente sia \(2^{-41.14}\) per score;
- che gli errori PBS siano Gaussiani o indipendenti;
- una varianza specifica per gli accumulatori costanti usati;
- un bound formale sugli errori FFT;
- un bound end-to-end della query;
- che log2_p_fail \(-71.625\) possa essere moltiplicato direttamente per 5.600 nel percorso raw-LWE;
- che una suite funzionale di 632 query possa osservare o escludere una coda così piccola.

La formulazione difendibile è quindi:

> Il circuito corrente è funzionalmente validato sui casi eseguiti, ma il suo bound di fallimento end-to-end non è dimostrato. Un audit basato sulle formule di varianza ufficiali individua nell'estrazione full del bit 1 un margine modellato peggiore di quello nominale dei normali PBS. Uno split che usa i quattro bit robusti della vista modulo 16 elimina questo punto senza aumentare il numero di PBS e costituisce il prossimo hardening da implementare e validare.
