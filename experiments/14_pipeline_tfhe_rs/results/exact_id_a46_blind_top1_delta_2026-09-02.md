# A46: Blind Counting Sort rispetto al contratto exact-ID

Data: 2026-09-02. Perimetro: audit statico del paper PoPETs 2025 di Azogagh,
Killijian e Larose-Gervais e dei sorgenti fissati di `knn`/RevoLUT. Non sono
stati eseguiti Cargo, FHE, key generation o benchmark.

## Esito

Il lavoro e' prior art molto vicino e impedisce di descrivere il nostro
percorso come il primo top-k o k-NN in TFHE. Non e' pero' un sostituto diretto
di A38:

- il k-NN pubblicato ordina una distanza ridotta a `Z_16`, non il punteggio
  bounded esatto a 12 bit;
- ritorna `k` class labels cifrate e lascia la majority vote al client;
- non applica una soglia open-set al solo vincitore e non restituisce il
  contratto `0/ID`;
- il singolo BCS e' stabile, ma il top-k parallelo concatena i blocchi tramite
  [`par_bridge`](https://docs.rs/rayon/latest/rayon/iter/trait.ParallelBridge.html),
  che non garantisce l'ordine originario. Il first-tie globale
  non e' quindi un contratto dimostrato del sorgente fissato.

Verdetto: **NO-GO come drop-in di A38**. Rimane una pista condizionale per un
radix top-1 a tre nibble, ma prima servono tre stati digit esatti e ordinabili,
ordine dei blocchi deterministico, LUT/noise proof e gestione esplicita della
soglia.

Fonti fissate:

- [Paper PoPETs 2025](https://petsymposium.org/popets/2025/popets-2025-0093.pdf),
  DOI `10.56553/popets-2025-0093`.
- [Sorgente knn, revisione 4fd244e](https://github.com/sofianeazogagh/knn/tree/4fd244e5a52cfe218a202e3040f8540ef8879251),
  in particolare `src/server.rs` e `src/main.rs`.
- [Sorgente RevoLUT, revisione e934754](https://github.com/sofianeazogagh/revoLUT/tree/e93475470c126c4a0fa121f8fae0c6194988b74e),
  in particolare `src/blind_topk.rs`, `src/blind_sort.rs` e `src/lib.rs`.

## Cosa calcola davvero il k-NN pubblicato

Il client manda un RLWE del feature vector e un LWE della sua norma. Per ogni
model point in chiaro il server calcola il prodotto polinomiale, sample-extract
del prodotto scalare e quindi la distanza quadratica. Se `p_dist > p`,
`server.rs` chiama `lower_precision` una volta per distanza; il riferimento
clear divide la distanza intera per `p_dist/p` prima del sort.

Con `p_dist=4096` e `p=16`, quindi, il valore ordinato e'
`floor(distance/256)`. La trasformazione e' monotona ma non conserva l'argmin
esatto. Per esempio:

```text
score esatti             = [255, 1]
score ridotti a p16      = [0, 0]
first argmin esatto      = indice 1
first argmin dopo reduce = indice 0
```

Questo non e' solo un problema di accuratezza media: viola direttamente il
nostro contratto deterministico su input validi. La selezione pubblicata
restituisce inoltre i class labels (nel codice breast-cancer/MNIST, non gli
indici della galleria); `main.rs` li decifra e calcola `majority` sul client.
Non c'e' una soglia open-set.

## Conteggi statici: sorgente fissato, `k=1, d=127, p=16`

Il sorgente fa due round:

```text
round 0: [16,16,16,16,16,16,16,15]
round 1: [8]
BCS calls = 9, elementi elaborati cumulativi = 135
```

Per un blocco di `s` elementi e `m` lane, il controllo effettivamente eseguito
da `many_blind_counting_sort_k` contiene:

```text
BR/PBS             = (m+3)*s + 15
packing-key calls  = m*s [input] + (m+2)*s + 15 [BCS]
```

Qui `packing-key calls` conta letteralmente ogni chiamata a
`keyswitch_lwe_ciphertext_into_glwe_ciphertext` fatta da `LUT::from_lwe`.
Il paper la tratta come lavoro PFKS; il sorgente usa il campo `packing_ksk`,
non il campo `pfpksk`. Il conteggio include anche gli operandi triviali e i 15
blind rotate indicizzati pubblicamente, perche' il codice non ha uno
short-cut per evitarli.

Con due lane (distanza e label):

| caso | BR/PBS | packing-key calls |
|---|---:|---:|
| top-1 soltanto | 810 | 945 |
| piu' reduce `p4096 -> p16` su 127 distanze | 937 | 945 |

Il prodotto polinomiale e il sample extraction iniziale non aggiungono BR o
PFKS. Il secondo caso aggiunge esattamente 127 bootstrap di precision
reduction.

### Perche' i numeri del paper sono diversi

Applicando letteralmente la convenzione di Equazione 3 e Tabella 5, lo stesso
caso non pubblicato `k=1,d=127` produce 570 BR e 390 PFKS per il top-1, oppure
697 BR quando serve anche la precision reduction. Questa convenzione:

- attribuisce `kappa=16` ai bucket pieni e `min(k,tau)` all'ultimo bucket;
- aggiunge due PFKS astratte prima di ogni KV-BCS;
- omette i BR su indici triviali e non conta una packing-key call per ogni LWE
  come fa materialmente `LUT::from_vec_of_lwe`.

Il modello riproduce tutte le dieci coppie BR/PFKS della colonna "Ours" in
Tabella 5 (incluso `k=3,d=40`: 190/148). I due ledger descrivono quindi
convenzioni diverse; non vanno mescolati. In particolare, il sorgente passa
`chunk.len()` a KV-BCS, non `min(k, remainder)`.

## Stabilita' e first-tie

Dentro una chiamata BCS, il rebuild scorre gli input al contrario, decrementa
la cumulative count e scrive il tuple completo nella stessa posizione. E' il
classico counting sort stabile: chiavi uguali mantengono l'ordine. Il test
key-value incluso nel progetto conserva infatti le label degli elementi uguali
nell'ordine originale.

Questo non basta per il first-tie globale. `blind_topk_many_lut_par` crea i
chunk in ordine ma li attraversa con `par_bridge()` e raccoglie i risultati in
un `Vec`; l'API di Rayon non promette di conservare l'ordine seriale. Se due
minimi uguali arrivano da chunk diversi, il round successivo puo' quindi vedere
prima il chunk successivo. Il clear reference usa invece un sort stabile, ma
il programma non asserisce l'uguaglianza delle coppie `(distance,label)` FHE e
clear: le stampa e confronta soltanto la majority/accuracy.

Un riuso per exact-ID deve allegare l'indice pubblico del chunk e riordinare i
risultati prima della concatenazione, oppure usare un iteratore parallelo
indicizzato con ordine dimostrato. Senza questa modifica non si puo' asserire
`min(score,index)`.

## Ibrido condizionale: LSD radix su tre nibble

La pista piu' conservativa e': per ogni elemento rappresentare

```text
(score_low, score_mid, score_high, id_low, id_high)
```

con cinque LWE p16; in ogni blocco di massimo 16 elementi fare tre KV-BCS
stabili nell'ordine low, mid, high, tenere un solo vincitore e ripetere il
torneo. I LUT prodotti da un pass possono essere riusati nel pass successivo,
quindi il packing degli input serve una sola volta per blocco.

Nei blocchi non terminali tutte e tre le nibble di score devono sopravvivere:
il vincitore deve portare il valore completo al round seguente. Soltanto
l'ultimo blocco globale, se la soglia e' gia' incorporata, puo' scartare low
dopo il primo pass e mid dopo il secondo; i numeri di lane diventano `5,4,3`.

Conteggi condizionali del solo selector, includendo il packing letterale:

| input | round | BR/PBS | packing-key calls |
|---|---|---:|---:|
| 127 gallery | non terminale | 3.408 | 3.662 |
| 127 gallery | terminale | 213 | 229 |
| **127 totale** | | **3.621** | **3.891** |
| 127 gallery + sentinel = 128 | non terminale | 3.432 | 3.688 |
| 127 gallery + sentinel = 128 | terminale | 213 | 229 |
| **128 totale** | | **3.645** | **3.917** |

Questi sono conteggi strutturali condizionali, non una previsione di latenza.
Partono da tre stati digit p16 esatti gia' disponibili; la loro costruzione non
e' inclusa. La PBS `lower_precision` pubblicata produce un solo quoziente p16,
perdendo gli altri otto bit, e quindi non puo' fornirli.

### Interfaccia A45 e ordine pubblico dei bucket

Il modello statico A45 restringe il problema ma non consegna direttamente i
cinque LWE richiesti sopra. I suoi intermedi low e mid sono

```text
u(d) = 2*(d & 7) + floor(d/8), a Delta=2^59
```

La mappa e' biiettiva ma **non** preserva l'ordine numerico. L'ordine pubblico
dei bucket che corrisponde a `d=0..15` e':

```text
[0,2,4,6,8,10,12,14,1,3,5,7,9,11,13,15]
```

Usare il BCS esistente, che fa la prefix sum in ordine naturale `0..15`,
ordinerebbe per `u`, non per `d`, e sarebbe scorretto gia' per i digit `8` e
`7`: `u(8)=1` precederebbe `u(7)=14`.

Non e' pero' necessario invertire `u` con una PBS. Una variante BCS puo'
percorrere i 15 archi della prefix sum nell'ordine pubblico qui sopra:

1. estrarre `count[u(d-1)]` anziche' `count[i-1]`;
2. sommarlo in `count[u(d)]` anziche' `count[i]`;
3. lasciare invariati decrement, lookup cifrato e rebuild inverso.

La cumulative count associata a ogni `u(d)` diventa cosi' la posizione finale
secondo `d`; il rebuild inverso resta stabile. Il modello clear lo verifica su
tre pass LSD e sulle parita'. La modifica non cambia il numero di iterazioni,
BR o packing-key calls, ma **non esiste ancora nei sorgenti RevoLUT fissati**.
Serve una nuova API con una permutazione pubblica validata; l'identita' deve
restare il default per non cambiare BCS.

Se invece si mantiene l'ordine naturale, e si assume condizionalmente di avere
tutti e tre gli stati folded, servono tre inverse-map PBS per gallery item:

| opzione condizionale | input selector | inverse PBS | BR/PBS subtotal | packing-key calls |
|---|---:|---:|---:|---:|
| bucket pubblici permutati | 127 | 0 | 3.621 | 3.891 |
| inverse PBS, ordine naturale | 127 | 381 | 4.002 | 3.891 |
| bucket pubblici + sentinel | 128 | 0 | 3.645 | 3.917 |
| inverse PBS + sentinel | 128 | 381 | 4.026 | 3.917 |

Il sentinel e' pubblico e non richiede inverse PBS. Queste righe escludono
comunque la costruzione degli stati folded. A45 produce `u_low` e `u_mid`, ma
per high lascia soltanto `h` numerico a `Delta=2^60` per il classificatore
categorico A34: non emette ne' un digit high numerico standard `Delta=2^59` ne'
`u_high`. Questa e' ancora un'obbligazione separata, con costo ignoto. I numeri
proiettati A40+A45 (`3551/3424/4229`) descrivono il diverso grafo A38
categorico e non si possono sommare al selector radix.

### Sentinel uniforme

Per una soglia pubblica uniforme `0 <= T < 4095`, si puo' premettere il tuple
pubblico `(T+1, label=0)` alla galleria. Con sort esatto e stabile:

- se il minimo gallery e' `<= T`, precede il sentinel e vince il primo ID
  gallery a parita';
- se tutti gli score sono `>= T+1`, il sentinel vince, anche sulle parita' a
  `T+1`, e produce `0`.

Questo integra semanticamente reject e first-ID, ma dipende proprio dalla
stabilita' globale oggi non garantita da `par_bridge`. Non copre soglie diverse
per identita', `T<0`, o il bordo `T=4095` senza special case. Due nibble label
restituiscono semanticamente `0/ID`; se il wire contract pretende un solo LWE,
la loro fusione e il relativo costo restano da progettare.

## Blocchi prima di una prova FHE

1. Materializzare il digit high folded o numerico a `Delta=2^59`; A45 non lo
   emette.
2. Dimostrare encoding LUT negaciclico e margini di rumore per ogni digit; il
   paper stesso segnala la difficolta' oltre 8 bit.
3. Implementare e validare il bucket order pubblico, oppure pagare le PBS di
   inversione per ogni digit e item.
4. Rendere deterministico l'ordine dei chunk e testare ties cross-chunk.
5. Fissare il requisito: sola soglia pubblica uniforme o soglia per-template.
6. Decidere il wire a due nibble oppure pagare/provare una fusione cifrata.
7. Instrumentare un prototipo prima di trasformare i conteggi in performance.

Il paper riporta, sul proprio Intel i9-11900KF, microbenchmark p16 di 18 ms per
BR e 3 ms per PFKS. Non riporta `k=1,d=127`. Quei tempi non vengono applicati
ai conteggi sopra e non autorizzano confronti di latenza con A38 su un'altra
macchina, versione TFHE o set di parametri.

## Artefatti e verifica

- [benchmark/a46_blind_top1_delta.py](../../../benchmark/a46_blind_top1_delta.py)
- [tests/test_a46_blind_top1_delta.py](../../../tests/test_a46_blind_top1_delta.py)

Comandi statici previsti:

```sh
python3 -m unittest -v tests.test_a46_blind_top1_delta
python3 benchmark/a46_blind_top1_delta.py --compact
```

Risultato: 20 test passati; il modello include tutti i confini adiacenti del
dominio a 12 bit, stability intra-blocco, tie cross-chunk, sentinel, entrambi i
ledger dei conteggi e tutte le righe pubblicate di Tabella 5.
