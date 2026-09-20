# A31 storico e A33: fast path exact-ID per la soglia uniforme DigiFace

Data dell'audit: 2026-09-02.

## Stato e limite del documento

La prima parte di questo documento conserva il design storico A31, verificato soltanto in chiaro,
per il punto operativo DigiFace originario:

\[
L=-987,\qquad T=4,\qquad K=T-L=991.
\]

Stato aggiornato:

- A31 resta **storico e non implementato**. I suoi `5.008 PBS / 3.992 KS` su A28 e
  `4.373 PBS / 3.992 KS` su A29 a \(N=127\) sono proiezioni, non misure;
- A29 resta il percorso generale promosso e congelato. I suoi stress boundary e semantici sono in
  [`exact_id_manylut_boundaries_2026-09-02.md`](exact_id_manylut_boundaries_2026-09-02.md) e
  [`exact_id_manylut_semantics_2026-09-02.md`](exact_id_manylut_semantics_2026-09-02.md);
- A33 e' ora implementato nel core come candidato specializzato per la soglia uniforme riallineata
  a `K'=1023`. Un solo accumulatore raw/custom e una sola blind rotation per template emettono due
  sample LWE correlati: il codice signed `r` e un indicatore signed di peso alternato `1/3`;
- il test FHE del core completo su chiave fresca copre inclusione `1023`, esclusione `1024`, rifiuto
  totale, anti-risurrezione, primo tie, tail dispari `N=127` e ID massimo `128`. Il micro-harness
  separato passa inoltre 54/54 residui, 216/216 uscite e 192/192 coppie su tre chiavi, per tutti gli
  stati `h'=0..7`; report:
  [`exact_id_a33_sparse_residual_trace_2026-09-02.md`](exact_id_a33_sparse_residual_trace_2026-09-02.md);
- il conteggio implementato A33 a `N=127` e' **4.273 PBS / 3.892 KS**. E' un conteggio strutturale,
  confermato dai run FHE ma non una percentuale di latenza. La frontiera ha mediana server 8.272,6
  ms sotto forte carico e non costituisce un confronto causale;
- A33 non viene ancora promosso sopra A29 finche' non sono congelati suite primaria, Docker,
  confronto appaiato A29/A33 e accounting condizionale della `p-fail`. Patch, binario, transcript
  full-core e frontiera sono gia' congelati;
- la costruzione e' descritta come co-design specifico di questo sistema. Non viene rivendicata
  come nuova primitiva, come primo assoluto, come prova di brevettabilita' o come analisi FTO. Le
  LUT, il PBS negaciclico e l'estrazione multi-output sono tecniche note;
- i test empirici non certificano il `p-fail` end-to-end. Le uscite della stessa blind rotation
  sono correlate e gli accumulatori `core_crypto` custom non ereditano automaticamente una prova
  compositiva dal parametro nominale.

Il fast path non degrada il requisito applicativo a un solo bit di membership. Quando accetta,
restituisce ancora l'identita' esatta `indice+1`; quando rifiuta, restituisce solo `0`. Soglie
diverse o un diverso valore normalizzato devono usare il percorso generale della revisione scelta:
A29 e' il percorso generale promosso corrente; A28 resta la baseline precedente congelata.

Le sezioni seguenti fino a **Verifica in chiaro eseguita** documentano A31 e vanno lette come
storia del percorso progettuale. La sezione **A33 implementato** descrive invece il core corrente.

## Snapshot storico A31: `K=991` (non corrente)

Le sottosezioni di questo blocco descrivono la proposta `K=991`; formule, LUT e verifiche qui non
descrivono l'architettura A33 corrente.

### Contratto e guardie di attivazione

Per ogni score intero \(s_i\) si usa la traslazione gia' presente nel core:

\[
x_i=s_i-L,\qquad 0\le x_i\le 4095.
\]

Poiche' la soglia e' uniforme,

\[
s_i\le T \iff x_i\le K=991.
\]

Il dispatch puo' entrare nel fast path soltanto se sono vere **tutte** le condizioni seguenti:

1. tutte le soglie pubbliche dei template sono uguali;
2. la sottrazione checked `threshold - domain.lower` produce esattamente `991`;
3. il dominio e' valido e la sua larghezza e' al massimo `4096`;
4. restano soddisfatte tutte le guardie del core generale: \(1\le N\le128\), dimensione 512,
   coordinate template in `[-3,3]`, norme dichiarate corrette, bound Cauchy coperto, probe GLWE
   della forma attesa, modulo nativo e bootstrap key Classic.

Nel deployment corrente le prime tre condizioni corrispondono a `L=-987`, `T=4`. Il controllo
determinante e' pero' \(K=991\): non bisogna selezionare il percorso dal solo nome della scena o da
un flag di configurazione. Se una guardia fallisce, il server deve ripiegare sul core generale,
senza errore permissivo e senza cambiare la semantica.

### Preparazione: soltanto i bit necessari

Per decidere ammissibilita' e minimo non servono piu' tutti i bit `b11..b0` come nel percorso
generale. Il fast path prepara `b0..b8` e il residuo

\[
h=\left\lfloor\frac{x}{2^7}\right\rfloor=x\mathbin{\texttt{>>}}7
\in[0,31].
\]

Il percorso split4 A28 viene troncato in questo modo:

1. il ramo modulo 16 estrae `b0..b3` con quattro KS e tre correzioni;
2. gli stessi quattro small-LWE producono le correzioni `b0..b3` alla scala full;
3. il ramo high estrae `b4..b8` con cinque KS e quattro correzioni, per `b4..b7`;
4. subito dopo avere sottratto le correzioni `b0..b6`, il residuo full vale idealmente

   \[
   x\Delta_{\rm full}-\sum_{j=0}^{6}b_j2^j\Delta_{\rm full}
   =h\,2^7\Delta_{\rm full}=h\,2^{59};
   \]

5. `b8` viene ricodificato separatamente come Booleano canonico; `b0..b2` possono conservare i
   pesi 2/4/8 gia' usati dal selettore A28.

Con A28 servono ricodifiche separate per `b3..b8`. Con A29 implementato, le correzioni di `b3..b6`
emettono anche il Booleano, mentre la correzione di `b7` e' gia' alla scala
\(2^{59}=\Delta_{\rm bool}\). Rimane separata soltanto la ricodifica di `b8`.

| preparazione per template | blind rotation A28 | blind rotation dopo A29 | KS |
|---|---:|---:|---:|
| correzioni low modulo 16 | 3 | 3 | 4 |
| correzioni low-to-full | 4 | 4, una anche multi-output (`b3`) | 0 aggiuntivi |
| correzioni high `b4..b7` | 4 | 4, tre anche multi-output (`b4..b6`); `b7` riusata | 5 |
| ricodifiche Booleane separate | 6 (`b3..b8`) | 1 (`b8`) | 0 |
| classificatori `h -> c` e `c+b6+b5 -> r` | 2 | 2 | 2 |
| **totale** | **19** | **14** | **11** |

Le quattro rotazioni A29 a due uscite contano come quattro blind rotation/PBS equivalenti, non
otto. I dettagli e le cautele sulla dipendenza fra le due uscite sono nel report
[`exact_id_manylut_design_2026-09-02.md`](exact_id_manylut_design_2026-09-02.md).

### Classificatore specializzato `h`, con `p=16`

Tutti i codici di questa sezione usano \(\Delta_{\rm bool}=2^{59}=q/32\). Un accumulatore con
message modulus `p=16` definisce liberamente i valori base `0..15`; per negaciclicita', sul secondo
semigiro vale idealmente

\[
F(z+16)=-F(z)\pmod q.
\]

#### Prima LUT: `h -> c`

La LUT base e':

| valore base di `h` | codice `c` |
|---:|---:|
| `0..3` | 2 |
| `4..6` | 5 |
| `7` | 6 |
| `8..15` | 8 |

Per `h=16..31`, il PBS non puo' scegliere altri sedici valori indipendenti: produce il negativo
del codice alla posizione `h-16`. Questa limitazione viene sfruttata esplicitamente, non ignorata.

#### Seconda LUT: `v=c+b6+b5 -> r`

Si calcola linearmente

\[
v=c+b_6+b_5
\]

e si applica la LUT base

\[
R(v)=
\begin{cases}
3 & 2\le v\le4,\\
4 & 5\le v\le7,\\
0 & \text{altrimenti.}
\end{cases}
\]

Il risultato ha la seguente semantica:

\[
r=
\begin{cases}
3 & x\le991\ \land\ b_9=0,\\
4 & x\le991\ \land\ b_9=1,\\
0 & x>991.
\end{cases}
\]

#### Prova ideale, inclusa la meta' negaciclica

- Per `h=0..3`, `c=2` e `v=2..4`: il template e' ammissibile e ha `b9=0`, quindi `r=3`.
- Per `h=4..6`, `c=5` e `v=5..7`: il template e' ammissibile e ha `b9=1`, quindi `r=4`.
- Per `h=7`, `c=6`. I prefissi `(b6,b5)=00,01,10` danno `v=6,7,7` e descrivono precisamente
  il suffisso `0..95`; `(b6,b5)=11` da' `v=8` e descrive `96..127`. Quindi `x=991=7*128+95`
  e' incluso, mentre `x=992` e' escluso.
- Per `h=8..15`, `v=8..10`, sempre escluso.
- Per `h=16..19`, il primo output e' `-2`, quindi dopo l'addizione si osservano i codici torus
  `30,31,0`; per `h=20..22` si osserva `27..29`; per `h=23`, `26..28`; per `h=24..31`,
  `24..26`. Il secondo accumulatore vede dunque soltanto `0` o `24..31`. Questi ultimi sono i
  negativi delle caselle base `8..15`, dove `R` vale zero, quindi anche tutto il semigiro alto
  viene escluso.

La prova riguarda plaintext ideali e la funzione negaciclica. Non dimostra che il residuo FHE
rumoroso venga sempre modulus-switched nella casella corretta.

### Selezione di `b9` in gruppi di tre

I codici `r` appartengono a `{0,3,4}`. In un gruppo di al massimo tre template, le somme possibili
si separano in due insiemi disgiunti:

| contenuto del gruppo | somme raggiungibili |
|---|---|
| nessun codice 3 | `{0,4,8,12}` |
| almeno un codice 3 | `{3,6,7,9,10,11}` |

Una LUT per gruppo produce quindi il Booleano `1` esattamente se nel gruppo esiste un template
ammissibile con `b9=0`. Con

\[
g=\left\lceil\frac N3\right\rceil,
\]

un OR radix-4 dei \(g\) flag produce il Booleano globale `a`. Il costo di questa parte e'

\[
C(N)=g+R(g),
\]

dove \(R(m)\) e' il numero di PBS dell'OR radix-4. Per `N=127`, `g=43`, `R(43)=15` e
`C(127)=58`.

Si forma poi, senza PBS,

\[
q_i=r_i+a.
\]

Sugli stati raggiungibili, `q_i=4` identifica esattamente gli ammissibili nella classe minima di
`b9`:

- se non esiste alcun `r=3`, `a=0` e sopravvivono gli `r=4`;
- se esiste un `r=3`, `a=1`, gli `r=3` diventano 4 e gli `r=4` diventano 5;
- gli inammissibili diventano 0 oppure 1.

Non viene speso un PBS per normalizzare subito `q_i`: il livello `b8` assorbe questa operazione.

### Livello speciale `b8`

Dal codice `q_i` si ricava con una LUT

\[
z_i=[q_i+b_{8,i}=4].
\]

Poiche' i codici raggiungibili di `q` sono `0,1,4,5`, `z_i=1` significa precisamente
`q_i=4` e `b8=0`. Sia

\[
A_8=\bigvee_i z_i.
\]

Una seconda LUT per template calcola

\[
c_i=[q_i-z_i+A_8=4].
\]

La relazione e' esatta sugli stati raggiungibili:

- un candidato `q=4,b8=0` ha `z=1` e implica `A8=1`, quindi il codice resta 4;
- un candidato `q=4,b8=1` ha `z=0` e resta 4 soltanto se `A8=0`;
- `q=0,1,5` produce rispettivamente codici in `{0,1}`, `{1,2}`, `{5,6}`, mai 4.

Il livello `b8` costa quindi `2N + R(N)` PBS e termina con candidati Booleani canonici.

### Livelli `b7..b0`, primo pareggio e rifiuto

Gli otto bit restanti usano la transizione exact-min gia' presente in A28. A ogni livello si
calcola, fra i candidati attivi, se esiste un bit zero; sopravvivono gli zero se esistono,
altrimenti gli uno. L'encoding alternato A28 passa da candidato canonico a codice `15` e ritorno,
cosi' una coppia di livelli richiede tre PBS per template invece di quattro.

Per otto livelli il costo e':

\[
12N+8R(N).
\]

Il termine e' `12N`, non `11N`: dopo il livello speciale `b8` i candidati sono Booleani freschi,
ma non sono piu' tutti uguali a uno. Al primo livello `b7` bisogna quindi calcolare sotto cifratura
`candidate AND NOT(b7)` con un PBS per template. La scorciatoia `level == 0` del core generale,
che costruisce linearmente `NOT(bit)` assumendo candidati iniziali tutti uno, qui farebbe
**risorgere template gia' esclusi** e non deve essere riusata.

Insieme al livello speciale `b8`, la selezione dopo la preparazione costa

\[
14N+9R(N)+C(N).
\]

Dopo `b0`, tutti gli indici con lo stesso minimo restano candidati. Lo scan `first-one` esistente
seleziona il piu' piccolo indice, quindi conserva la regola del primo argmin. L'output bitwise
ricostruisce `indice+1`.

Non serve il comparatore a dodici PBS ne' il tag di accettazione separato: l'ammissibilita' e'
stata incorporata nel set iniziale. Non sono inclusi, ne' necessari, tre PBS aggiuntivi per una
presunta maschera canonica. Nel nuovo output-group la LUT mappa direttamente i digit del winner;
se non esiste alcun ammissibile, non esiste alcun winner, tutti i digit restano zero e l'unico
output e' `0`.

Questo richiede una LUT di output **distinta** da quella del core generale. La LUT corrente riceve
anche il tag di accettazione con peso 8 e restituisce zero per ogni codice minore di 8: limitarsi a
rimuovere `accept_tag` senza sostituire quella LUT trasformerebbe quindi anche tutti i match validi
in `0`. La variante A31 deve mappare direttamente i soli digit raggiungibili `0..7`, mantenendo lo
stesso unico ciphertext finale alla scala del codice.

### Prova della semantica exact-ID

Sia

\[
E=\{i:x_i\le991\}.
\]

Il classificatore produce `r!=0` se e solo se \(i\in E\).

- Se \(E\) e' vuoto, ogni score e' sopra soglia. Nessun livello puo' creare un candidato, lo scan
  non crea un winner e il codice finale e' `0`.
- Se \(E\) non e' vuoto, il minimo globale appartiene a \(E\). Per ogni elemento di \(E\),
  `x<=991<1024`, quindi `b11=b10=0` per tutti: confrontare esattamente `b9..b0` equivale a
  confrontare l'intero `x`.
- La selezione di `b9`, poi quella lessicografica di `b8..b0`, lascia precisamente tutti e soli gli
  indici che realizzano il minimo globale.
- Lo scan first-one sceglie il minimo indice fra gli eventuali pari merito.
- L'output e' dunque `i+1` se il minimo soddisfa la soglia inclusiva, altrimenti `0`.

La trasformazione usa soltanto dati pubblici della configurazione e operazioni cifrate sul probe;
non aggiunge un output intermedio e non rivela il nearest ID in caso di rifiuto.

### Conteggi progettuali

Definiamo:

- \(R(N)\): costo dell'OR radix-4 di \(N\) Booleani;
- \(C(N)=\lceil N/3\rceil+R(\lceil N/3\rceil)\): classificazione raggruppata di `b9`;
- \(S(N)\): costo dello scan first-one corrente;
- \(O(N)\): costo dell'output bitwise corrente, con una LUT per ogni gruppo di tre digit.

I totali sono:

\[
P_{\rm A28-fast}(N)=33N+9R(N)+C(N)+S(N)+O(N),
\]

\[
P_{\rm A29-fast}(N)=28N+9R(N)+C(N)+S(N)+O(N).
\]

La preparazione esegue `11N` KS in entrambe le versioni. Ogni PBS successivo usa il percorso
big-to-small `apply_pbs`, quindi

\[
KS_{\rm fast}(N)=25N+9R(N)+C(N)+S(N)+O(N).
\]

| N | `R(N)` | `C(N)` | `S(N)` | `O(N)` | PBS A28-fast | PBS A29-fast | KS |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 64 | 21 | 31 | 111 | 70 | 2.513 | 2.193 | 2.001 |
| 127 | 43 | 58 | 222 | 150 | **5.008** | **4.373** | **3.992** |
| 128 | 43 | 58 | 224 | 151 | 5.044 | 4.404 | 4.020 |

Per `N=127`, il conto esplicito post-A29 e':

\[
28\cdot127+9\cdot43+58+222+150=4.373.
\]

La versione A28 aggiunge le cinque ricodifiche eliminate da A29:

\[
4.373+5\cdot127=5.008.
\]

I `3.992` KS sono invece

\[
11\cdot127+(14\cdot127+9\cdot43+58+222+150)=3.992.
\]

Il core A28 validato resta a `5.600 PBS / 4.584 KS` per la stessa galleria uniforme. Il fast path
A28 progetta quindi un risparmio di 592 PBS e 592 KS; A29 progetta altri 635 blind rotation, ma
nessun altro KS. Queste differenze di conteggio non sono percentuali di latenza misurate.

### Verifica in chiaro eseguita

Un modello Python in memoria, separato dal core FHE, ha verificato:

- `4.096/4.096` valori `x=0..4095` contro la specifica
  `(x<=991, b9)`, inclusi `991` e `992`;
- tutte le `39/39` tuple `{0,3,4}` di lunghezza 1, 2 o 3 contro la LUT delle somme di gruppo;
- tutti gli stati globalmente raggiungibili della transizione speciale `b8`;
- `1.086/1.086` gallerie deterministiche, con `N` ciclico da 1 a 128, seed `0xA31`, casi casuali,
  estremi, frontiere, pari merito, minimo a `991`, minimo a `992` e gallerie tutte rifiutate,
  confrontando il codice con `argmin((x_i,i))` seguito dalla soglia inclusiva.

Un secondo audit indipendente e in sola lettura ha inoltre rieseguito l'intera tabella del
classificatore su `4.096/4.096` valori e confrontato **100.000/100.000** gallerie pseudocasuali,
con `N` campionato in `1..128` e seed `0xA31A31`, contro lo stesso oracolo clear con tie-break
`(score, indice)`. Lo stesso audit ha verificato separatamente anche il classificatore e 100.000
gallerie della variante allineata `K'=1023` descritta sotto. Sono controlli plaintext in memoria:
non sono test del core TFHE e non costituiscono evidenza sul rumore o sulla `p-fail`.

Questi controlli sono una sanity check del design. Lo script era ad hoc e non e' un artefatto FHE
versionato; la prova algebrica sopra, i futuri test Rust e i futuri transcript cifrati devono essere
la base riproducibile della promozione.

## A33 implementato: riallineamento pubblico a `K'=1023`

A33 implementa la normalizzazione pubblica allineata. Il `domain.lower` non deve coincidere col
bound Cauchy piu' stretto: deve coprire tutti gli score possibili, conservare una larghezza al
massimo 4096 e venire usato in modo coerente dal server, dallo stato pubblico e dagli harness.

Per i bound sintetici correnti `[-987,2329]` e la soglia uniforme `T=4` si puo' scegliere

\[
L'=T-1023=-1019,
\qquad D'=[-1019,2329],
\qquad |D'|=3349\le4096.
\]

La nuova coordinata e' soltanto una traslazione pubblica comune:

\[
x'=s-L'=x+32.
\]

Non cambia quindi ne' l'ordine degli score ne' i pareggi. Inoltre 32 e' multiplo di 16, quindi la
vista low modulo 16 non cambia. La soglia diventa invece un confine binario allineato:

\[
s\le4 \iff x'\le1023=2^{10}-1.
\]

Il planner implementato calcola `L'=T-1023` con sottrazione checked e attiva A33 soltanto se tutte
le soglie sono uguali, `L'` non supera il lower bound Cauchy e `upper-L'+1` appartiene a
`1..=4096`. Overflow, soglie miste, mancata copertura o dominio troppo largo producono il piano
generale A29. Il core rivalida comunque gli input e ricontrolla autonomamente soglia uniforme e
offset esatto prima del dispatch: la selezione non dipende dal nome del dataset o da un flag.

### Preparazione e classificatore signed-code fuso

Dopo avere sottratto le correzioni `b0..b8`, il residuo ideale e'

\[
h'=x'\mathbin{\texttt{>>}}9,
\qquad h'\,2^{61},
\]

con `h'=0..7`. La preparazione implementata per ogni template e':

| famiglia | blind rotation | KS |
|---|---:|---:|
| estrazione low modulo 16 | 3 | 4 |
| bridge low-to-full | 4 | 0 aggiuntivi |
| estrazione high `b4..b8` | 4 | 5 |
| correzione terminale `b8` | 1 | 0 aggiuntivi |
| classificatore sparso fuso | 1 | 1 |
| **totale** | **13** | **10** |

La correzione terminale usa lo small-LWE di `b8` gia' estratto; la sua uscita alla scala
`2^60=2*Delta_bool` viene riusata come bit `b8` di peso 2.

Il classificatore non e' una catena di due LUT. Un accumulatore raw/custom con `p=8` contiene negli
slot `0..7`:

| slot | `0` | `1` | `2` | `3` | `4` | `5` | `6` | `7` |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| valore | `2` | `w` | `3` | `0` | `4` | `0` | `4` | `0` |

Il residuo a scala `2^61` visita gli slot pari. Dalla stessa GLWE ruotata vengono estratti:

- al grado zero, il codice signed `r`;
- al grado `Npoly/8`, l'indicatore signed di peso `w`, con `w=1` per il template sinistro della
  coppia e `w=3` per quello destro.

La singola blind rotation produce quindi due LWE correlati e conta come **una** rotazione, non come
due PBS indipendenti. Per negaciclicita' si ottiene:

| `h'` | codice `r` | indicatore signed |
|---:|---:|---:|
| `0` | `2` | `+w` |
| `1` | `3` | `0` |
| `2,3` | `4` | `0` |
| `4` | `30=-2 mod 32` | `-w` |
| `5` | `29=-3 mod 32` | `0` |
| `6,7` | `28=-4 mod 32` | `0` |

I valori negativi del semigiro alto non sono valori indipendenti programmati nella LUT: sono i
negativi negaciclici di `2,3,4,4` e, per il flag, di `w,0,0,0`.

### Canonicalizzazione per coppie e livello `b8`

Per ogni coppia adiacente si sommano i due indicatori signed e l'offset pubblico 4. Grazie ai pesi
1 e 3, gli stati con almeno un `h'=0` sono esattamente `{2,5,6,7,8}`; quelli senza `h'=0` sono
`{0,1,3,4}`. Una LUT `p=16` per coppia, incluso l'eventuale singleton finale, produce un Booleano
canonico. Definendo

\[
P(N)=\left\lceil\frac N2\right\rceil,
\]

questa fase costa `P(N)` PBS/KS; l'OR dei flag di coppia costa altri `R(P(N))` PBS/KS e restituisce

\[
a=[\exists i:h'_i=0].
\]

Si forma linearmente `q_i=r_i+a`. Sugli stati raggiungibili, `q_i=3` identifica esattamente la
classe ammissibile col minimo `b9`: se esiste `h'=0`, seleziona quella classe; altrimenti seleziona
`h'=1`; se tutti gli `h'` sono almeno 2, nessun codice raggiunge 3 e la query resta rifiutata.

Il livello `b8` riusa direttamente il peso 2:

\[
z_i=[q_i+2b_{8,i}=3],
\qquad A_8=\bigvee_i z_i,
\qquad c_i=[q_i-z_i+A_8=3].
\]

Questa fase costa `2N+R(N)` PBS/KS. I `c_i` sono Booleani canonici: se esiste un candidato con
`b8=0` sopravvivono quei candidati, altrimenti sopravvivono quelli con `b8=1`. Nessun codice
rifiutato raggiunge 3 attraverso il wrap negaciclico.

Gli otto livelli `b7..b0` costano `12N+8R(N)` PBS/KS. L'encoding alternato impedisce la
risurrezione dei candidati gia' esclusi; lo scan first-one conserva il primo indice nei pareggi.
Non serve un comparatore di soglia o un `accept_tag` separato. Se tutti sono rifiutati non esiste
alcun winner e la LUT finale, specifica di A33, mappa direttamente i digit `0..7` nel solo output
`0/ID`.

### Conteggi del core A33 implementato

Definiamo:

- `R(N)`: PBS dell'OR radix-4 di `N` Booleani;
- `P(N)=ceil(N/2)`: numero di canonicalizzatori di coppia;
- `S(N)`: PBS dello scan first-one;
- `O(N)`: PBS della codifica finale dell'ID.

Gli stadi implementati sono:

\[
PBS_{\rm extract}(N)=13N,
\qquad KS_{\rm extract}(N)=10N,
\]

\[
PBS_{\rm select}(N)=KS_{\rm select}(N)
=14N+9R(N)+P(N)+R(P(N)),
\]

con gli stadi `score` e `threshold` a 0 PBS/KS, `scan=S(N)` e `output=O(N)`. I totali sono quindi

\[
PBS_{\rm A33}(N)=27N+9R(N)+P(N)+R(P(N))+S(N)+O(N),
\]

\[
KS_{\rm A33}(N)=24N+9R(N)+P(N)+R(P(N))+S(N)+O(N)
=PBS_{\rm A33}(N)-3N.
\]

| N | `R(N)` | `P(N)` | `R(P)` | extract PBS/KS | select PBS/KS | `S(N)` | `O(N)` | PBS totali | KS totali |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0 | 1 | 0 | 13 / 10 | 15 / 15 | 1 | 2 | **31** | **28** |
| 3 | 1 | 2 | 1 | 39 / 30 | 54 / 54 | 4 | 3 | **100** | **91** |
| 64 | 21 | 32 | 11 | 832 / 640 | 1.128 / 1.128 | 111 | 70 | **2.141** | **1.949** |
| 127 | 43 | 64 | 21 | 1.651 / 1.270 | 2.250 / 2.250 | 222 | 150 | **4.273** | **3.892** |
| 128 | 43 | 64 | 21 | 1.664 / 1.280 | 2.264 / 2.264 | 224 | 151 | **4.303** | **3.919** |

Per `N=127` il conto esplicito e':

\[
27\cdot127+9\cdot43+64+21+222+150=\mathbf{4.273\ PBS},
\]

\[
24\cdot127+9\cdot43+64+21+222+150=\mathbf{3.892\ KS}.
\]

Rispetto al percorso generale A29 uniforme (`4.965 PBS / 4.584 KS`), il risparmio strutturale e'
di 692 PBS e 692 KS. Non e' una percentuale di latenza: il rapporto effettivo dipende da scheduler,
cache, parallelismo e carico, e deve essere misurato con un benchmark appaiato.

Il solo punto A31 derivato in questo documento e' `4.373 PBS / 3.992 KS` per `K=991`: rispetto a
quel riferimento documentato A33 risparmia 100 PBS e 100 KS. Una precedente stima della variante
allineata a due LUT (`4.358/3.977`) non ha qui una derivazione congelata e non viene usata come
baseline.

Questa costruzione non coincide col percorso diretto modulo 1024 respinto sotto: mantiene il canale
full a `Delta=2^52`, il canale low a `Delta=2^60` e deriva `h'` soltanto dopo split e correzioni. Non
assume una LUT diretta a dieci bit con `Delta=2^54`.

### Evidenza corrente e limite della promozione

Il modello deterministico copre `x'=0..4095`, i 64 stati ordinati delle coppie, il primo tie, il
rifiuto e l'ID massimo. Il test FHE completo con chiave fresca esercita i confini `1023/1024`, la
non-risurrezione, gallerie `N=1/2/127/128` e osserva i conteggi della tabella. Il micro-harness del
classificatore usa tre ulteriori chiavi e copre tutti gli `h'=0..7`.

Queste prove rendono A33 un candidato implementato e congelato, non ancora il nuovo baseline
sperimentale. Il full-core mirato passa sei casi/sette valutazioni fino a N=127/codice 127 e la
frontiera DigiFace pulita passa 80/80 query, 48/48 autorizzazioni, zero errori e zero discrepanze.
Restano la suite primaria canonica, Docker, un confronto appaiato A29/A33 con input e carico
controllati e l'accounting condizionale della `p-fail`. La costruzione non viene rivendicata come
nuova primitiva o come primo assoluto; un eventuale contributo va formulato limitatamente al
co-design e supportato da confronto con la letteratura pertinente.

## Rumore e limiti non risolti

1. **Residuo e classificatore raw.** I test osservano margini ampi su piu' chiavi, ma non sono una
   prova analitica che ogni residuo venga sempre modulus-switched nella casella corretta.
2. **Uscite correlate.** Il classificatore estrae `r` e flag dalla stessa GLWE ruotata. Anche le
   fusioni A29 di correction e Booleano producono uscite correlate: non sono trial indipendenti.
3. **Accounting del `p-fail`.** Il `log2_p_fail=-71.625` nominale del parameter set non certifica
   automaticamente accumulatori `core_crypto` custom, scale torus non standard o l'intera
   composizione. Una union bound e' lecita soltanto dopo avere giustificato il bound marginale di
   ogni famiglia di uscite.
4. **Somma finale.** I gruppi di digit finali vengono sommati linearmente senza un ultimo refresh.
   La correttezza delle singole LUT non sostituisce una prova separata del margine di decode della
   somma, soprattutto quando i gruppi sono tre.
5. **Vincolo sul probe.** Come nel core A29, la norma del probe cifrato e' validata dal client e non
   puo' essere ricontrollata in chiaro dal server. La prova del dominio e' condizionata a quel
   contratto.
6. **Prestazioni.** I conteggi prevedono meno lavoro strutturale ma non provano una latenza minore.
   Servono misure appaiate, distribuzioni e controllo esplicito del carico macchina.

## Percorso diretto modulo 1024 respinto

E' stata considerata anche una variante piu' aggressiva: classificare direttamente un valore a
dieci bit con una LUT modulo 1024/ManyLUT. Il suo conto ideale arrivava a `3.723` blind rotation a
`N=127`, ma **non e' una candidata implementativa corrente**.

La rappresentazione richiesta ricadeva sul regime `Delta=2^54`. L'evidenza gia' presente in
[`bucket_bit_bridge_audit_2026-09-01.md`](bucket_bit_bridge_audit_2026-09-01.md) e' negativa: il
tentativo di estrarre direttamente dieci bit a quella scala ha sbagliato 24/71 valori senza bias e
40/71 con bias 3,5, inclusi i lati alti dei bin. Ignorare i bit frazionari cambia `floor` in un
arrotondamento dipendente dalla frontiera.

Per rendere difendibile la LUT diretta servirebbe inoltre un modulus switch esplicitamente
`theta`-aware, con allineamento dimostrato fra fase, offset e caselle del lookup. Il percorso stock
TFHE-rs usato dal core non espone ne' valida tale correzione. Il numero `3.723` resta quindi il costo
di un'idea scartata, non un risultato, e non deve apparire come confronto prestazionale promosso.

## Gate di promozione A33

Completati sul candidato corrente:

1. **Modello deterministico:** tutti i `4.096` valori normalizzati, tutti i 64 stati ordinati delle
   coppie, casi di rifiuto, pareggio e ID massimo, piu' gallerie pseudocasuali fino a `N=128`.
2. **Guardie e fallback:** soglie miste, offset non allineato, mancata copertura, larghezza 4096 e
   4097, overflow e input pubblici non validi.
3. **Micro-harness FHE del classificatore:** tre chiavi fresche, 54/54 residui, 216/216 uscite e
   192/192 coppie, inclusi tutti gli stati `h'=0..7` e i confini `1023/1024`.
4. **Core FHE completo mirato e congelato:** chiave effimera, sei casi/sette valutazioni, confini
   `1023/1024`, rifiuto totale, anti-risurrezione, tie-first con replay dello stesso ciphertext,
   tail dispari e `N=127 -> codice 127`. Il transcript non contiene un caso N=128.
5. **Conteggi e regressione locale:** fixture `N=1,3,64,127,128`, assert runtime dei PBS, corpo A29
   invariato, `fmt`, `check`, `clippy` e suite della libreria positivi.
6. **Frontiera DigiFace:** 80/80 query, 48/48 autorizzazioni, zero errori/discrepanze exact-ID,
   percorso sempre `a33_aligned_sparse` e 4.273 PBS/query. La mediana server 8.272,6 ms sotto forte
   carico e' descrittiva, non causale.
7. **Freeze riproducibile:** patch, binario di produzione, binario diagnostico, transcript e
   artefatti finali della frontiera legati da SHA-256.

Ancora necessari prima di sostituire A29 come baseline sperimentale:

1. suite primaria completa delle 632 query contro l'oracolo clear, con artefatti canonici;
2. E2E Docker provenance-bound sul binario A33 congelato;
3. benchmark A29/A33 appaiato, con stessi ciphertext per coppia, ordine alternato e carico
   controllato;
4. accounting condizionale del `p-fail`, inventario delle uscite multi-output e termine separato
   per il decode della somma finale;

Fino a questi gate, A29 resta la revisione generale promossa. A31 resta uno snapshot progettuale
storico; A33 e' il fast path exact-ID implementato ma non ancora promosso.

## Provenienza

Gli hash storici A31, conservati per distinguere il design originario dall'implementazione
successiva, sono:

| artefatto storico | SHA-256 |
|---|---|
| `src/private_argmin.rs` A28 letto per formule e stadi | `7ad812724bf43742d9d03ec9db204e93d6a2c0db3e6ea9dbc650054633fa3596` |
| `results/exact_id_manylut_design_2026-09-02.md` | `e28dbb6a860c72fc363bb0e53d61844e469fdfdd77e2cb1c85ab6a14f6889f27` |

Lo snapshot A33 implementato e auditato in questo aggiornamento e':

| artefatto corrente | SHA-256 |
|---|---|
| `src/private_argmin.rs` | `1d50a2b0e6f98069e0ab2de0eb228133543b5792cf0b34016031593de1e0850d` |
| `src/lib.rs` | `c6fbdd61636f6335e6547ed17aa73cdea7c69c2a7c26f74980bb99c52a2e6f53` |
| `src/bin/varco_demo.rs` | `ae23024c8cbcb3269db14d816da44fb035f72b8ba00d83b5a5c2cb1aaca4c5ca` |
| patch A33 congelata | `6d07077efc52e721399740ef7d443ca87ee0a6c575cd19b7a453d5109224f7f5` |
| binario `varco_demo` congelato | `13a1593be85d8e585bdf48d7d4e8a09a57a82902f6e8da7299a5b02415a3ea59` |
| binario `a33_full_validation` congelato | `596792a8e306d6ba2811ade51054d0f6c9aff09ab339f65db6311e7f32e42a7d` |
| transcript full-core congelato | `2c3fd446b4f0a2f382a2ec5c939facd427680b0d1e88315c57a474e55a279595` |
| frontiera finale CSV | `e72dd64db5751ee49ca2016908698f583e1f7d16c33c44d77beb3d9a7e68e98d` |
| frontiera finale JSON | `7e528e254313c4a602968354f96d80d497034da61024b7eb94c8423393d4ca8a` |
| patch A29 congelata usata per il confronto | `7858a3e51c50ddbd94ea76dbcc50410ffa37b10b99cad1eebb8609851b66cb54` |
| `results/exact_id_a33_sparse_residual_trace_2026-09-02.md` | `a596b824cb214bc2ebee3fe9c9d026fa78a224a9664873e23845c52572baf5a4` |
| `Cargo.lock` (`tfhe 0.11.3`) | `1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a` |

Questi hash identificano il freeze riproducibile del candidato A33, non una revisione gia' promossa.
Un eventuale aggiornamento successivo del core o del servizio richiede nuovi hash e la ripetizione
dei gate residui.

Gli hash dei JSON si riferiscono agli estratti pubblicati; la
[corrispondenza con gli originali](../../../docs/provenienza-dati.json) conserva entrambe le impronte.
