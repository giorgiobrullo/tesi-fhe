# A37: raggruppamento gerarchico dei flag signed A33 - modello statico, 2026-09-02

## Esito

Il raggruppamento diretto di tre flag signed in **un solo bit Booleano con un PBS `p=16` e'
impossibile** nel modello A33 corrente. Non e' pero' necessario tornare alle coppie: una rete a
due stadi, sempre a `Delta=2^59`, comprime fino a **15 template** in un Booleano canonico:

1. un PBS per tripla, con pesi `(1,3,9)`, produce il codice intermedio `31`, `0` oppure `1`;
2. un PBS somma fino a cinque codici intermedi e ne calcola l'OR.

Il modello clear passa tutti i controlli. A `N=127`, la sottorete A33
`pair canonicalizer -> compact OR` scende da **85 a 56 BR/KS/marginali**, cioe' risparmia
**29 BR, 29 KS e 29 output marginali**. La proiezione dell'intero A33 passa quindi da
`4.273/3.892/4.908` a **`4.244/3.863/4.879`** BR/KS/marginali.

Questo e' un risultato clear e strutturale. Non e' stato compilato o eseguito codice FHE e non e'
una promozione del core.

## 1. Semantica di ingresso

Per ogni template, il classificatore A33 emette un ciphertext fresco alla scala Booleana
`Delta=2^59=q/32`:

```text
h=0 -> +w
h=4 -> -w
altro -> 0
```

Il bit cercato e' `1` se almeno un ingresso appartiene alla classe `h=0`. La classe `h=4` non deve
essere confusa con `h=0`: il suo segno negativo e' precisamente il motivo per cui una somma non
pesata non basta.

## 2. Perche' un solo PBS `p=16` non basta per tre flag

La ricerca finita considera tutti i pesi non nulli di `Z_32`, con ripetizione. L'ordine puo' essere
quotientato per permutazione, perche' il predicato "esiste un positivo" e' simmetrico. Sono quindi

```text
C(31+3-1, 3) = 5.456
```

triple di pesi. Per ciascuna vengono enumerati:

- tutti i `3^3=27` vettori in `{-1,0,+1}^3`;
- tutti i 32 offset pubblici;
- la relazione negaciclica del PBS `p=16`, `F(x+16)=-F(x)`.

Il numero di soluzioni e' **zero**. Il peso zero non e' omesso in modo favorevole: renderebbe
indistinguibili `h=0` e `h=4` nella relativa posizione, quindi fallirebbe immediatamente.

Il caso naturale `(1,3,9)` e' iniettivo sulle 27 configurazioni balanced-ternary, ma non risolve il
vincolo negaciclico. Esistono fasi antipodali occupate per cui le etichette sono `(1,0)` oppure
`(1,1)`; un unico output Booleano canonico richiederebbe simultaneamente valori incompatibili
nello stesso coefficiente indipendente dell'accumulatore.

L'offset non puo' correggere questa collisione perche' trasla entrambi i membri della coppia
antipodale. Cambiare ordine o grado di sample extraction non cambia la fase scalare osservata dal
gate. Piu' sample extraction dalla stessa rotazione potrebbero restituire un codice vettoriale, ma
non produrre un unico Booleano canonico senza un successivo stadio non lineare; una combinazione
lineare delle uscite conserva l'anti-periodicita'.

## 3. Limite piu' forte a quattro ingressi

La ricerca enumera anche le

```text
C(31+4-1, 4) = 46.376
```

quadruple di pesi e tutti gli `81` vettori ternari. Per **nessuna** quadrupla l'etichetta e' nemmeno
una funzione della fase sommata modulo 32: esiste sempre almeno una collisione tra un caso senza
positivi e uno con almeno un positivo.

Questo blocca qualunque LUT o insieme di sample extraction che riceva soltanto quella somma
scalare. Blocca anche gruppi piu' grandi: restringendo quattro posizioni e fissando tutte le altre a
zero si otterrebbe altrimenti una quadrupla separabile, che la ricerca esclude.

## 4. Codice intermedio per gruppi di tre

Per una tripla si usano i pesi balanced-ternary `(1,3,9)`. La LUT `p=16` ha i seguenti 16 valori
indipendenti; la seconda meta' e' fissata dalla negaciclicita':

```text
[31, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 31, 1]
```

L'enumerazione esaustiva delle `8^3=512` triple reali `h in 0..7`, oltre alle code da uno e due
template, dimostra l'alfabeto:

```text
nessun h=0       -> {31}     # -1 signed
almeno un h=0    -> {0, 1}
```

Il codice intermedio non e' ancora un Booleano: `0` puo' significare una tripla positiva. Le due
classi sono pero' disgiunte e pronte per il secondo stadio.

La disposizione e' compatibile strutturalmente col classificatore A33. Servirebbe un terzo
accumulatore di peso `9`, oltre agli attuali pesi `1` e `3`; il codice numerico `r` resta nel grado
zero e il flag usa ancora il grado `N/8=256`. Il coefficiente `9*Delta` resta nella meta'
indipendente `0..15`, mentre il semigiro alto produce automaticamente `-9`. Non serve cambiare
scala ne' aggiungere blind rotation per template.

## 5. Cinque triple in un solo secondo stadio

Siano `k<=5` codici intermedi. Si sommano i `k` ciphertext e si aggiunge l'offset pubblico `+k`.
Se nessuna tripla e' positiva, ogni codice vale `-1`, quindi:

```text
sum(-1) + k = 0.
```

Se `j>=1` triple sono positive e `t` delle loro uscite valgono `1`, il codice e':

```text
j + t, con 1 <= j+t <= 2k <= 10.
```

Un'unica LUT comune restituisce quindi zero sulla fase `0` e uno sulle fasi `1..10`. Tutte queste
fasi stanno nella meta' indipendente del `p=16`. Le code vengono trattate con il loro `k` pubblico;
equivale a completare il blocco con triple negative di codice `-1`.

L'audit esaustivo prova tutti i `3^1+...+3^5=363` vettori raggiungibili del secondo stadio.

## 6. Dominio e rumore locale

La scala rimane quella A33:

| ingresso PBS | scala | L1 lineare | margine geometrico standard |
|---|---:|---:|---:|
| tripla `(1,3,9)` | `2^59` | 3 | `2^58` |
| fino a cinque riassunti freschi | `2^59` | **5** | `2^58` |
| riduzione OR finale radix-4 | `2^59` | 4 | `2^58` |

Il massimo e' 5, uguale al `max_noise_level=5` del parameter set congelato
`V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`. Il controllo e' lo stesso bound locale a
contributi freschi usato per gli invarianti A33; non trasferisce automaticamente il
`log2_p_fail=-71.625` nominale all'intero circuito raw-LWE.

I pesi `1,3,9` sono valori della LUT del classificatore, non moltiplicazioni omomorfe del
ciphertext dopo il PBS: ogni flag resta un solo contributo fresco nel conto L1.

## 7. Conteggi

Con `R4(m)` numero di nodi della riduzione OR radix-4:

```text
A33: P=ceil(N/2)
     C33(N) = P + R4(P)

A37: T=ceil(N/3)
     B=ceil(T/5)=ceil(N/15)
     C37(N) = T + B + R4(B)
```

A `N=127`:

| rete | primo stadio | secondo stadio | riduzione | totale |
|---|---:|---:|---:|---:|
| A33 coppie | 64 | 0 | 21 | 85 |
| A37 `3 x 5` | 43 | 9 | 4 | **56** |

Ogni nodo nuovo e' un PBS ordinario con una KS e un output marginale. Le blind rotation
multi-output del classificatore A33 non cambiano. Di conseguenza il risparmio `29` vale in egual
misura per BR, KS e marginali:

| proiezione statica N=127 | BR | KS | marginali |
|---|---:|---:|---:|
| A33 congelato | 4.273 | 3.892 | 4.908 |
| A37 sopra A33 | **4.244** | **3.863** | **4.879** |

Per `N=1,2` i due stadi costerebbero un nodo in piu' del pairing A33; una futura integrazione deve
mantenere il percorso A33 per queste taglie. A `N=4` i conteggi sono pari, mentre dal caso utile
`N=127` il vantaggio e' netto.

## 8. Perche' non usare `p=32`

Cambiare soltanto la LUT di gruppo a `p=32` non cambia la griglia dei flag: un flag a `q/32`
occupa gli slot pari, quindi `(1,3,9)` diventa `(2,6,18)` in `Z_64`. La ricerca negaciclica trova
ancora **zero** offset validi.

Ricodificare invece i flag a `q/64` renderebbe `(1,3,9)` direttamente separabile con un PBS
`p=32`, ma:

- porta l'uscita del classificatore da `Delta=2^59` a `2^58`;
- dimezza ancora il mezzo-slot, da `2^58` a `2^57`;
- esce dalla griglia nominale message/carry `4x4` del parametro corrente;
- non autorizza il riuso del suo `p-fail` nominale.

Inoltre non conviene neppure nel conto corrente: a `N=127`, triple dirette `p=32` piu' riduzione
radix-4 costano `43+15=58` nodi, contro i **56** della rete A37 interamente `p=16`. La via `p=32`
resta quindi scartata.

## 9. Compatibilita' con gli altri candidati

- **A33:** A37 sostituisce soltanto `pair_flags -> compact_or` e restituisce lo stesso
  `any_b9_zero` Booleano canonico. Il resto dell'argmin exact-ID e il fallback A29 restano
  invariati.
- **A34 two-nibble scan/output:** e' a valle della selezione e risulta strutturalmente componibile.
  La sola aritmetica dei conteggi darebbe `4.082/3.701/4.760`.
- **A36 chunked candidate:** consuma i candidati dopo l'ammissione e risulta strutturalmente
  componibile. La sola aritmetica darebbe `3.990/3.609/4.625`; con anche A34 two-nibble,
  `3.828/3.447/4.506`.
- **A34 top-category:** e' un'alternativa alla stessa rete alta A33 che A37 modifica; i risparmi
  non sono sommabili.

Le cifre combinate sono proiezioni clear, non circuiti implementati o validati FHE.

## 10. Evidenza riproducibile e prossimi gate

Modello:

```text
benchmark/a37_sparse_grouping_model.py
```

Test:

```bash
uv run --python 3.12 python -m unittest tests.test_a37_sparse_grouping_model
uv run --python 3.12 python benchmark/a37_sparse_grouping_model.py --compact
```

La validazione completa comprende 24 casi di flag, 584 gruppi del primo stadio, 363 combinazioni
del secondo, 8.190 gallerie esaustive fino a `N=12`, 4.096 gallerie pseudocasuali fino a `N=128`,
5.456 triple di pesi e 46.376 quadruple di pesi.

Per validare un circuito integrato servono ancora:

1. un micro-harness FHE isolato per il nuovo accumulatore di peso 9 e le due LUT `p=16`;
2. casi su piu' chiavi, tutte le fasi e le code `N mod 15`;
3. integrazione fail-closed con A33 per `N=1,2`;
4. full-core exact-ID, replay, frontiera, suite primaria e Docker;
5. confronto appaiato contro il binario A33 congelato.

Finche' questi gate non passano, A37 resta un candidato statico e non una nuova baseline.
