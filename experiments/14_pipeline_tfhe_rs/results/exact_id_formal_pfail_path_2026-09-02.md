# Percorso verso un bound `p-fail` difendibile per A33 e A34/A36

Data dell'audit: 2026-09-02. Perimetro: sorgenti locali TFHE-rs 0.11.3, core A33 congelato,
modelli A34/A36 e prototipo integrato A38. Non sono stati eseguiti Cargo, FHE, keygen o Docker e
non sono state lette chiavi segrete.

## Esito

Non esiste ancora un bound numerico end-to-end dimostrato. Esiste pero' un percorso molto piu'
stretto e verificabile per arrivarci:

1. **Scartare il PBS finale `p=256` come chiusura.** Una LUT centrata puo' renderne corretta la
   semantica negaciclica, ma il massimo margine che vede all'ingresso e' soltanto `2^55`, cioe'
   esattamente il raggio di decode non dimostrato del codice corrente. Il bootstrap sposta quindi
   l'obbligo, non lo elimina. Il `p-fail` nominale del parametro p16 non si applica a questa LUT.
2. **Restituire davvero due digit p16** `(low, high)` a `Delta=2^59`, senza pesare `high`, senza
   sommare i ciphertext e senza ricodificarli a `Delta=2^56`. Se ciascuna radice e' una PBS p16
   ufficiale o provata equivalente, con ingresso `NoiseLevel<=5`, il termine terminale e' chiuso
   dal contratto nominale: `P(F_low union F_high) <= 2p = 2^-70.625`, senza indipendenza.
3. **Non usare la normalizzazione A36 `L1/2` come se fosse gia' un teorema.** La via piu' corta che
   resta entro il tracker esistente fa emettere direttamente lo stato fresco `0/2` da A34 e
   rinfresca dopo `b6`, `b4`, `b2`, `b0`. Tutti gli ingressi raw restano cosi' a `L1<=5`; costa
   254 BR/KS/marginali in piu' a `N=127` rispetto alla proiezione 3.655 BR.
4. **Isolare il vero blocco restante:** l'ingresso GLWE e la convoluzione dello score sono ora
   chiusi da un bound deterministico di supporto (`|E_0|<=178782208`, oltre `2^23.586` di slack
   sulla vista completa). Restano estrazione/correzioni e classificatore A34-top. Questi cammini
   raw contengono output correlati riusati nel residuo; le sole varianze ufficiali piu' un'ipotesi
   Gaussiana danno una sensibilita' utile, non un teorema.

Con la variante prudente, il bound che possiamo gia' scrivere senza barare e' simbolico:

\[
P(\mathrm{wrong})
\le
\varepsilon_{\mathrm{extract/corrections}}
+\varepsilon_{\mathrm{A34\ top\ classifier}}
+4460\,2^{-71.625}.
\]

L'ultimo termine vale `1.22478940055e-18 = 2^-59.5021720`, ma e' valido soltanto dopo aver
verificato, nodo per nodo, le precondizioni del contratto shortint. I due epsilon non sono ancora
valorizzati da un upper bound formale.

## Che cosa significa qui "formale"

Si ordinino topologicamente le operazioni non lineari. Sia `C_i` l'evento che tutti i primi `i`
nodi abbiano seguito il ramo ideale e sia `F_i` il primo errore al nodo `i`. Per ogni ingresso si
scrive la fase come

\[
\phi_i=\mu_i+Z_i,
\]

dove `mu_i` e' uno dei centri raggiungibili sul cammino ideale e `Z_i` contiene tutto il rumore
ereditato, il KS e l'errore rilevante al modulus switch. Se `m_i(mu_i)` e' la distanza dal piu'
vicino confine della LUT, un certificato deve fornire

\[
P\left(|Z_i|\ge m_i(\mu_i)\mid C_{i-1}\right)\le\epsilon_i.
\]

Per ogni output terminale `o`, con errore `E_o` e raggio di rounding `d_o`, serve analogamente
`P(|E_o|>=d_o | C_last)<=epsilon_o`. Allora, per decomposizione sul primo errore e disuguaglianza
di Boole,

\[
P(\mathrm{wrong})\le\sum_i\epsilon_i+\sum_o\epsilon_o.
\]

Questa somma **non richiede indipendenza**. Diventa pero' un numero soltanto quando ogni
`epsilon_i` e' davvero dimostrato; moltiplicare meccanicamente il numero di marginali per il
`p-fail` del parameter set non dimostra le premesse.

I key switch non vengono aggiunti una seconda volta come eventi Bernoulli autonomi: il loro
rumore appartiene a `Z_i` della PBS successiva. Un KS terminale non seguito da PBS richiederebbe
invece un proprio termine di decode. Per ManyLUT si puo' contare conservativamente una marginale
per sample estratto oppure usare un unico evento congiunto per blind rotation, ma soltanto se si
dispone di un bound congiunto; non si possono alternare i due conteggi scegliendo il piu' piccolo.

## Cosa offre davvero TFHE-rs 0.11.3

Il parameter set usato dal progetto dichiara:

- LWE dimension 879, GLWE dimension 1 e `N=2048`;
- TUniform(46) lato LWE e TUniform(17) lato GLWE;
- PBS `base_log=23, level=1`, KS `base_log=3, level=5`;
- plaintext totale p16, `max_noise_level=5` e `log2_p_fail=-71.625`.

Fonte: TFHE-rs `0.11.3`,
`src/shortint/parameters/classic/tuniform/p_fail_2_minus_64/ks_pbs.rs:8-25`.

La documentazione di `MaxNoiseLevel` dice esplicitamente che traccia il massimo rumore che
garantisce il target p-error quando si esegue una PBS; il codice corrente lega questo limite al
norm2 che mantiene pulito il padding bit. Fonte:
TFHE-rs `0.11.3`, `src/shortint/ciphertext/common.rs:22-49`. Le somme aggiungono i `NoiseLevel` e le
moltiplicazioni clear li moltiplicano: `src/shortint/server_key/add.rs:518-528` e
`src/shortint/server_key/bivariate_pbs.rs:22-42`.

Questa e' una base difendibile come **contratto nominale della libreria**, non una dimostrazione
matematica autocontenuta dell'implementazione FFT. Nel sorgente locale non c'e' un teorema che
trasferisca quel singolo valore a una LUT core-crypto arbitraria, a una scala piu' stretta o a una
combinazione con `NoiseLevel>5` compensata da un plateau piu' largo.

### Output che possono ereditare il contratto nominale

| famiglia | stato del `p-fail` nominale | motivo/condizione |
|---|---|---|
| `ServerKey::apply_lookup_table`, input p16 con tracker valido | si', contrattualmente | esegue KS+PBS e imposta l'output a `NoiseLevel::NOMINAL`; `server_key/mod.rs:796-848` |
| `ServerKey::apply_many_lookup_table` ufficiale | si' per ciascuna marginale | un KS, una blind rotation, piu' sample extraction; ogni output e' marcato `NOMINAL`; `server_key/mod.rs:913-921,1285-1334` |
| clone, somma e moltiplicazione clear | nessun nuovo evento | devono propagare il livello/provenienza fino alla PBS successiva |
| ciphertext triviale e offset plaintext | rumore zero/nessun nuovo rumore | cambiano i centri raggiungibili, non aggiungono una variabile casuale |
| implementazione raw byte-equivalente a una LUT p16 ufficiale | solo dopo un lemma/test di equivalenza e le stesse precondizioni | `core_crypto` non trasporta automaticamente metadata shortint |

### Output che non lo ereditano automaticamente

| famiglia | obbligo |
|---|---|
| score estratto dal prodotto GLWE per template | propagare il rumore dei coefficienti del probe attraverso la combinazione lineare |
| correzioni a scale variabili dell'estrattore | propagare il loro errore quando vengono sottratte e poi shiftate |
| classificatore sparse/A34 alimentato dal residuo | dimostrare il rumore ereditato e il margine su tutti i centri raggiungibili |
| output a `Delta=2^56`, anche se appena prodotto da PBS | il raggio e' otto volte piu' piccolo di quello p16; "fresh" non implica `p=2^-71.625` per quel decode |
| somma LWE non seguita da PBS | varianza/coda esplicita del decode o un successivo ingresso PBS con margine provato |
| LUT con `L1=10` giustificata dividendo per un margine doppio | serve un teorema di scaling della coda; il tracker espone soltanto il limite 5 |
| custom `p=256` | plaintext grid, margine e output sono fuori dal contratto del parametro p16 |

## Correlazione e ManyLUT

L'API ManyLUT ufficiale riusa **una sola blind rotation** e campiona piu' coefficienti del medesimo
GLWE ruotato. La sorgente imposta ogni marginale a `NoiseLevel::NOMINAL`, ma non dichiara le
marginali indipendenti. La correlazione non invalida la union bound:

\[
P(F_1\cup F_2)\le P(F_1)+P(F_2),
\]

ma vieta di usare formule come `Var(E1+E2)=Var(E1)+Var(E2)` senza il termine di covarianza.

Per una combinazione lineare

\[
E=\sum_j a_jE_j,
\qquad
\mathrm{Var}(E)=a^T\Sigma a.
\]

La somma delle sole varianze e' valida soltanto con covarianze nulle. Sempre valida in L2 e' la
forma di Minkowski

\[
\sqrt{\mathbb E[E^2]}
\le
\sum_j |a_j|\sqrt{\mathbb E[E_j^2]},
\]

ma un secondo momento produce con Chebyshev una coda troppo debole per arrivare a `10^-18`.
Una coda esponenziale richiederebbe, per esempio, un bound sub-Gaussiano con matrice congiunta
`K`, non la sola varianza marginale:

\[
\mathbb E e^{t^T\xi}\le e^{t^TKt/2}
\Longrightarrow
P(|a^T\xi|\ge m)\le2e^{-m^2/(2a^TKa)}.
\]

Nel core A33 la correlazione non e' teorica: la correzione e il Booleano sono estratti ai gradi 0
e `N/2` dallo stesso GLWE ruotato (`private_argmin.rs:904-921`); il classificatore sparse estrae
due LWE dalla stessa rotazione (`:2063-2077`); le correzioni vengono poi sottratte dal residuo e
riusate (`:938-980,2197-2251`). Questi cammini richiedono provenance/covarianza congiunta, non
etichette di freschezza indipendenti.

L'A34 selector low/high e', invece, un buon candidato per l'API ManyLUT ufficiale. Con due funzioni
e p16, `fill_many_lut_accumulator` ammette input degree `0..7`, assegna due sotto-LUT da 1024
coefficienti e campiona ai gradi `0` e `N/2`; sono esattamente la griglia e lo stride del selector.
Fonte: TFHE-rs `0.11.3`, `src/shortint/engine/mod.rs:190-266`. Va comunque conservato lo stesso
`blind_rotation_id` nella provenance dei due output.

### Ricorrenza concreta che il certificato upstream deve coprire

Sia `e` il vettore degli errori dei coefficienti GLWE del probe e sia `A_g` la matrice pubblica
della convoluzione col template `-2g`. I due score estratti dallo stesso prodotto hanno errori

\[
S_{g,full}=a_{g,full}^Te,
\qquad
S_{g,low}=a_{g,low}^Te.
\]

Se i coefficienti iniziali sono indipendenti TUniform, la loro covarianza iniziale e' calcolabile
esattamente:

\[
\operatorname{Cov}(S_{g,d},S_{g',d'})
=V_{TU(17)}a_{g,d}^Ta_{g',d'}.
\]

Il core costruisce davvero una sola convoluzione GLWE e ne estrae i due gradi
(`private_argmin.rs:2123-2155`), quindi trattare le due lane come indipendenti sarebbe errato.

Per una lane dell'estrattore, indicando con `R_j` l'errore del residuo, con `K_j` il contributo KS
e con `P_j` l'errore della correzione PBS sul ramo corretto:

\[
X_j=2^{s_j}R_j+K_j,
\qquad
R_{j+1}=R_j-P_j.
\]

La seconda equazione deriva direttamente dalla sottrazione nel core
(`private_argmin.rs:955-979`). La propagazione corretta e'

\[
\operatorname{Var}(R_{j+1})
=\operatorname{Var}(R_j)+\operatorname{Var}(P_j)
-2\operatorname{Cov}(R_j,P_j),
\]

non `V_0+jV_PBS` a meno di dimostrare le covarianze nulle. Dopo lo split low/full, l'ingresso high
ha inoltre la forma

\[
R_{high,0}=S_{g,full}-\sum_{r=0}^{3}P_{bridge,r},
\]

e il residuo del classificatore A34 sottrae ancora le correzioni successive. Le correzioni bridge
nascono da bit della lane low e vengono applicate alla lane full (`private_argmin.rs:2167-2207`):
anche qui il termine congiunto e' strutturale, non opzionale.

Un checker sufficiente deve quindi conservare almeno una forma lineare simbolica per tutti i
contributi prima di ogni PBS e una primitiva congiunta per ogni output di PBS/ManyLUT. Se si adotta
un bound MGF/sub-Gaussiano, la matrice `K` deve includere questi identificatori condivisi; se si
adotta un bound deterministico, ogni primitiva deve avere un supporto certificato. Registrare solo
`sigma` per ciphertext non basta.

## Opzione A: PBS conclusivo `p=256`

Si consideri il codice `c in 0..128` a `Delta=2^56`. Il blind rotation usa il modulo `2N=4096`,
quindi i centri ideali sono

\[
r(c)=\frac{2N\,c\,2^{56}}{2^{64}}=16c.
\]

Una chiamata al helper core con `message_modulus=256` ha box

\[
B=N/256=8.
\]

Il helper non modificato offre soltanto `B/2=4` passi di margine attorno a ogni slot p256. Poiche'
i codici raggiungibili colpiscono gli slot pari `0,2,...,254`, si puo' costruire un corpo custom
traslato/coalescente che pone il confine negli slot dispari. Il massimo teorico diventa otto passi:

\[
m_{max}=8/4096=1/512=2^{-9}=2^{55}/2^{64}.
\]

Non puo' essere maggiore: i centri di due codici distinti consecutivi distano 16 passi. E' quindi
lo stesso margine della decodifica `Delta=2^56` che si voleva eliminare.

### Vincolo negaciclico

Il codice 128 ruota di 2048 passi ed e' l'antipode del codice zero. Una LUT PBS deve soddisfare
`Y(x+N)=-Y(x)`. L'identita' grezza richiederebbe `Y(0)=0` e `Y(N)=2^63`, ma la negaciclicita'
impone `Y(N)=-Y(0)=0`: e' impossibile.

E' possibile una ricodifica centrata:

\[
Y(c)=(c-64)2^{56}.
\]

Infatti `Y(0)=-2^62` e `Y(128)=+2^62=-Y(0)`. Il client deve fare un decode signed e aggiungere
64; in alternativa il server puo' aggiungere pubblicamente `64*2^56` dopo la PBS e conservare il
decoder legacy. L'offset non aggiunge rumore. Questa correzione risolve la **semantica della LUT**,
non il rumore.

### Sensibilita' del rumore

Per A33 l'ingresso conclusivo somma fino a tre radici code-scale fresche; A38 ne somma due. Usando
le varianze gia' estratte dalle formule TFHE 1.7 per i parametri v0.11,

\[
V_{PBS}=1.133226667479\cdot10^{-9},\quad
V_{KS}=3.526608149211\cdot10^{-7},\quad
V_{MS}=2.187987168630\cdot10^{-6},
\]

e **assumendo per sensibilita'** sorgenti Gaussiane/non correlate, si ottiene:

| radici sommate | modello ingresso | sigma | coda bilaterale a `1/512` | `log2` |
|---:|---|---:|---:|---:|
| 3, A33 | `3 V_PBS + V_KS` | 5.967080e-4 | 1.063497e-3 | -9.87697 |
| 3, A33 | `3 V_PBS + V_KS + V_MS` | 1.595007e-3 | 2.207545e-1 | -2.17949 |
| 2, A38 | `2 V_PBS + V_KS` | 5.957577e-4 | 1.044018e-3 | -9.90364 |
| 2, A38 | `2 V_PBS + V_KS + V_MS` | 1.594652e-3 | 2.206517e-1 | -2.18016 |

Queste cifre **non sono upper bound**: ignorano o idealizzano covarianze, trasformano il secondo
momento in una coda Gaussiana e trattano il modulus switch col modello separato. Mostrano pero'
che non e' plausibile trasferire silenziosamente il valore `2^-71.625`. Anche ignorando il
modulus switch, la sensibilita' e' circa `10^-3` per il solo ingresso.

L'output fresco della PBS avrebbe, nel medesimo modello Gaussiano, una coda estremamente piccola
alla scala `2^56` (`log2` circa -2434). Neppure questo e' un bound; soprattutto non ripara la
selezione errata avvenuta all'ingresso.

**Verdetto A:** il PBS `p=256` e' semanticamente costruibile soltanto in forma centrata, fuori dal
contratto shortint p16. Non chiude il decode: sposta lo stesso margine stretto all'ingresso della
PBS e aggiunge una nuova uscita stretta da giustificare.

## Opzione B: due LWE low/high p16

La risposta proposta cifra separatamente

\[
low=c\bmod16,\qquad high=\lfloor c/16\rfloor
\]

e il client ricostruisce `c=low+16*high`. Per `c in 0..128` la mappa e' biunivoca e conserva
esattamente il requisito di identificazione: zero rifiuta, `i+1` identifica la persona `i`.

Ogni digit usa `Delta=2^59`, quindi il raggio e'

\[
d=2^{58}/2^{64}=1/64,
\]

otto volte quello code-scale. A `N=127`, ciascun albero finale somma al massimo cinque marginali
fresche one-hot e applica una identity PBS p16. Se il wrapper dimostra `NoiseLevel<=5` e la PBS e'
quella ufficiale o equivalente, ogni output eredita contrattualmente `p=2^-71.625`. Anche se i due
cammini condividono input, BSK e KSK,

\[
P(F_{low}\cup F_{high})\le2p=5.49232915046\cdot10^{-22}=2^{-70.625}.
\]

Le due uscite sono gia' comprese nel totale delle marginali e non vanno ricontate.

### Distinzione necessaria dal prototipo A38 corrente

Il prototipo A38 corrente produce due radici **a `Delta=2^56`**, pesa gia' la radice high per 16 e
poi le somma in un solo LWE (`src/private_argmin.rs` dello snapshot A38, righe 2297-2357
e 2811-2829; si veda il [report componente A38](exact_id_a38_combined_component_fhe_2026-09-02.md)). La sola freschezza di quelle radici non trasferisce il `p-fail` p16. Restituirle tali
e quali separatamente lascerebbe due decode stretti e non sarebbe l'opzione qui certificata.

La modifica richiesta e' precisa:

- la radice low deve contenere `low` a `Delta=2^59`;
- la radice high deve contenere `high`, non `16*high`, alla stessa scala;
- il server deve restituire entrambe senza aritmetica successiva;
- il decoder deve arrotondarle separatamente e combinare in chiaro.

Per `N<=3`, dove i due digit potrebbero uscire direttamente dallo stesso selector ManyLUT, la
union bound tra le due marginali resta valida; se si vuole che entrambe siano anche terminali
fresh separate in senso stretto, si possono forzare due identity PBS aggiuntive. Questo dettaglio
non cambia il caso target `N=127`.

**Verdetto B:** chiude realmente il termine terminale sotto il contratto nominale, ma non trasforma
automaticamente il circuito intero in un teorema. Restano gli obblighi upstream.

## A36: perche' il modello corrente non basta e la correzione minima

Il modello A36 corrente parte da un candidato fresco moltiplicato per due e lascia crescere il
livello raw fino a 10. Lo dichiara equivalente a cinque dividendo per il doppio margine della LUT:
`benchmark/a36_chunked_candidate_model.py:479-521`. Questa e' una ragionevole euristica geometrica,
ma il sorgente TFHE-rs non dice che raddoppiare il margine autorizzi a raddoppiare
`MaxNoiseLevel`. Un valore p-fail noto in un solo punto non determina la forma della coda.

La correzione senza nuova teoria e': far produrre ad A34-top direttamente `0/2` con rumore
nominale 1, poi rinfrescare dopo due livelli:

| bit | L1 ingresso zero-test | L1 stato dopo update | refresh |
|---:|---:|---:|---|
| b7 | 3 | 3 | no |
| b6 | 5 | 5 | si' -> 1 |
| b5 | 3 | 3 | no |
| b4 | 5 | 5 | si' -> 1 |
| b3 | 3 | 3 | no |
| b2 | 4 | 5 | si' -> 1 |
| b1 | 2 | 3 | no |
| b0 | 4 | 5 | si' -> 1 |

Rispetto ai refresh correnti dopo `b4` e `b0`, si aggiungono quelli dopo `b6` e `b2`: `2N=254`
nodi a `N=127`. La proiezione composta diventa:

| variante | BR | KS | marginali | union aritmetica condizionale |
|---|---:|---:|---:|---:|
| A34/A36 corrente | 3.655 | 3.274 | 4.206 | `4206p = 2^-59.5867669` |
| schedule raw-L1 prudente | 3.909 | 3.528 | 4.460 | `4460p = 2^-59.5021720` |

I 254 nodi non chiudono score/extraction/classifier; eliminano pero' una premessa non dimostrata
dal tratto A36 e rendono ogni PBS downstream compatibile col limite nominale senza riscalare il
tracker.

## Certificato implementabile minimo

Il candidato dovrebbe introdurre un wrapper auditabile, separato dal contatore di latenza, per
ogni LWE:

```text
AuditedLwe {
    encoding / delta,
    reachable_centers,
    noise_level,
    linear_provenance,
    blind_rotation_id,
    sample_degree,
}
```

Regole obbligatorie:

1. somma e moltiplicazione clear aggiornano esattamente coefficienti di provenance e L1;
2. una PBS p16 e' ammessa soltanto se tutti i centri raggiungibili distano almeno il margine
   shortint standard e il livello raw e' `<=5`;
3. la PBS resetta il livello a 1, ma gli output ManyLUT conservano lo stesso `blind_rotation_id`;
4. ogni custom accumulator ha una tabella machine-readable di centri, confini, output, offset
   pubblico e gradi di sample extraction;
5. una scala `Delta=2^56`, un residuo dell'estrattore o un output custom non riceve mai
   automaticamente l'etichetta nominale.

Il checker deve esportare, per ogni nodo, `mu`, margine minimo, L1/provenance e motivazione del
bound. Il conto finale deve essere derivato da questo DAG, non da un numero PBS globale scritto a
mano.

## Test e misure necessari

### Statici, senza chiavi

- enumerare tutti i centri raggiungibili e ogni residuo di modulus switch entro il mezzo bin;
- verificare per coefficiente i corpi delle LUT, inclusa la continuazione negaciclica;
- per selector low/high, confrontare corpo, stride e output degree con
  `generate_many_lookup_table` ufficiale;
- iniettare errori sintetici `m-1`, `m` e `m+1` in un simulatore esatto della rotazione per ogni
  centro e sample degree;
- eseguire semantica clear esaustiva per `N=1..128`, reject, ogni winner e tie-first;
- rendere fallente il build statico se un nodo supera L1=5, cambia scala o perde provenance.

### Con chiavi, soltanto in una fase autorizzata successiva

- misurare l'errore signed di fase per ogni famiglia di nodo su molte chiavi fresche;
- registrare matrici di covarianza per output dello stesso ManyLUT e per cammini che riusano le
  correzioni;
- provare i confini LUT con rumore iniettato e fixture avversariali;
- ripetere le suite FHE, primary, Docker e paired del candidato finale.

Queste misure possono falsificare il modello e stimare margini reali, ma non provano una coda
`10^-22` per evento. Con zero errori, un upper confidence bound del 95% e' circa `3/n`: servirebbero
dell'ordine di `2.5e18` prove indipendenti solo per osservare statisticamente un limite query di
circa `1.2e-18`.

### Per un vero teorema crittografico

Serve una fonte o derivazione verificabile che dia una coda, non soltanto una varianza, per:

- rumore TUniform iniziale dopo il prodotto GLWE;
- key switch con la KSK condivisa;
- PBS FFT64 e suoi errori numerici;
- modulus switch;
- vettore congiunto dei sample ManyLUT;
- condizionamento sul prefisso corretto del circuito adattivo.

In alternativa si puo' dichiarare esplicitamente il valore Zama come assioma/contratto nominale
e limitare il claim della tesi a un **bound ingegneristico condizionale, verificato dal tracker**.
Questo e' difendibile; chiamarlo prova matematica end-to-end non lo sarebbe.

## Stato delle due chiusure richieste

| proposta | semantica esatta ID | chiude il decode terminale | chiude tutto il circuito |
|---|---|---|---|
| PBS `p=256` centrata dopo somma code56 | si', con decode signed +64 | **no**: stesso margine `2^55` spostato all'ingresso | no |
| due LWE p16 low/high fresche a `Delta=2^59` | si', ricombinazione biunivoca client | **si', sotto contratto nominale e L1<=5** | no: extraction/classifier ancora aperti |
| due radici A38 correnti a `Delta=2^56` restituite separate | si' | no | no |

## Artefatti riproducibili

- `benchmark/exact_id_pfail_certificate.py`
- `benchmark/a38_initial_score_bound.py`
- `tests/test_exact_id_pfail_certificate.py`
- `tests/test_a38_initial_score_bound.py`

Il JSON del certificato incorpora ora il sottocertificato
`initial_score_support.initial_score_decode_failure_probability_upper = 0.0`; la prima voce di
`blocking_obligations` parte esplicitamente **dopo** quel tratto chiuso e continua a vietare un
numero end-to-end finche' estrattore/correzioni e classificatore non hanno un bound.

Verifica statica eseguita:

```text
python3 -m unittest tests.test_a38_initial_score_bound tests.test_exact_id_pfail_certificate
.............
Ran 13 tests
OK
```

Il modello emette deliberatamente `end_to_end_numeric_upper: null` finche' gli obblighi upstream
non sono valorizzati.
