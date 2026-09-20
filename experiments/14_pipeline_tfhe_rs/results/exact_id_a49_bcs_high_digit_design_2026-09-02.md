# A49: digit high esatto per BCS e ordine deterministico dei chunk

Data: 2026-09-02. Perimetro: modello statico su centri torus, modulus switch
`u64`, controllo del sorgente RevoLUT fissato e conteggi strutturali. Non sono
stati eseguiti Cargo, FHE, key generation o benchmark.

## Esito

Il maggiore buco aritmetico lasciato da A46 si puo' chiudere staticamente con
una sola PBS per template: la quarta lane gia' provata geometricamente da A45
porta lo score bounded `x` a `Delta=2^51`; un offset pubblico seguito dalla LUT
identita' p16 restituisce direttamente il digit numerico fresco
`h=floor(x/256)` a `Delta=2^59`.

Il costo incrementale e': **1 BR / 1 KS classico / 1 marginale per template**,
quindi `127/127/127` a `N=127`. E' minimo nel percorso corrente
`large-LWE -> KS -> PBS`: la funzione e' non lineare e richiede almeno un
refresh, mentre la costruzione ne usa esattamente uno. Questo e' un minimo
rispetto a tale architettura, non un lower bound crittografico generale.

Anche il difetto first-tie di `par_bridge` ha una correzione deterministica
senza BR/PFKS aggiuntive: associare a ogni risultato l'indice pubblico del
chunk, ordinare i risultati completati per tale indice e soltanto dopo
concatenarli. La valutazione dei chunk resta parallela.

Il sentinel `(T+1,0)` e' esatto soltanto per una **soglia pubblica uniforme**.
Non implementa il contratto finale della repository, che usa `T_k` del
vincitore. A49 e' pertanto **GO per una materializzazione Rust isolata**, ma
resta **NO-GO come percorso finale o come risultato FHE** finche' non vengono
implementati e provati digit, BCS modificato, soglia per-template e bound di
errore composto.

## Una quarta lane canonica

A45 ha gia' enumerato quattro blocchi disgiunti da 512 coefficienti nello
stesso GLWE `Npoly=2048`. Il quarto blocco, finora libero, e' agli indici
`1536..2047`; la convoluzione col template seleziona il suo prodotto scalare al
grado `2047`, senza contributi cross-lane o wrapped su quel sample.

A49 assegna a questa lane:

```text
x * 2^51,      0 <= x <= 4095.
```

E' la codifica padded canonica dell'intero dominio a 12 bit: a differenza della
lane A45 `x*2^52`, non percorre tutto il torus. Il ciphertext GLWE e la
moltiplicazione polinomiale restano gli stessi; si aggiungono coefficienti nel
blocco finora inutilizzato, un sample-extract lineare per template e l'add del
termine pubblico di norma alla stessa scala. Sample-extract e add non sono
BR/KS. Il server deve comunque validare il nuovo layout e il client fidato deve
codificare viste coerenti dello stesso probe.

## Quoziente high in una PBS

Prima della PBS il server aggiunge l'offset pubblico

```text
O = -257 * 2^50.
```

Per `Npoly=2048`, il modulus switch nativo di tfhe-rs arrotonda il torus a
`2N=4096` rotazioni aggiungendo `2^51` e scartando 52 bit. Scrivendo
`x=256h+r`, `0<=r<=255`, la rotazione ideale e':

```text
t = floor((x*2^51 - 257*2^50 + 2^51) / 2^52)
  = 128*h + floor((2*r - 255) / 4)
  in [128*h - 64, 128*h + 63].
```

La LUT identita' standard p16 generata da tfhe-rs assegna proprio queste 128
rotazioni al messaggio `h`. Per `h=0`, gli indici negativi cadono nella coda
negaciclica il cui valore e' `-0=0`. Ne segue, su ogni centro:

```text
PBS(x*2^51 + O) = floor(x/256) * 2^59.
```

Il modello riproduce letteralmente sia `pbs_modulus_switch` sia la costruzione
dell'accumulatore p16 di tfhe-rs 0.11.3 ed esaurisce tutti i 4.096 score. Ogni
blocco high occupa esattamente le rotazioni sopra e il risultato e' numerico,
standard-p16 e fresco.

La distanza minima da una transizione, includendo l'arrotondamento del modulus
switch, e' aperta e vale `2^50` torus units, cioe' un quarto di rotazione. Il
modello verifica esaustivamente correttezza con errore uniforme `+(2^50-1)` e
`-(2^50-1)` e trova il primo errore a `+2^50`. Il bound deterministico iniziale
TUniform gia' derivato da A45, `178.782.208`, e' circa `2^22,586` volte sotto
questo margine. Questo controllo non include KS/PBS noise e non diventa da solo
un `p-fail` end-to-end.

## Perche' il vecchio residuo high costa due PBS

A45 lascia `R(h)=h*2^60`, `h in 0..15`. Un singolo sample PBS, anche dopo un
offset pubblico `A`, deve soddisfare

```text
Y(h+8) + Y(h) = 2A.
```

Per l'output numerico desiderato `Y(h)=h*2^59`, la somma e'
`(2h+8)*2^59` e assume otto valori diversi. Una PBS diretta dal vecchio residuo
non puo' quindi produrre il digit numerico. Questo e' un no-go per un singolo
sample negaciclico, non per ogni possibile circuito.

La fallback esatta e' invece:

```text
b = floor(h/8)
C = 15*b*2^59                         # prima PBS, correzione encodabile
u*2^59 = h*2^60 - C
u = 2*(h&7) + b
h = floor(u/2) + 8*(u&1)              # seconda PBS, LUT inversa p16
```

Costa `2 BR / 2 KS / 2 marginali`. Gli ingressi hanno raw `L1=2` e `L1=3`,
quindi rientrano localmente sia nel max-5 corrente sia nel max-15 A44. La lane
canonica A49 e' migliore: una sola PBS e raw `L1=0` da marginali precedenti;
il rumore del sample iniziale e' contabilizzato separatamente.

## Costi rispetto al selector A46

Le due famiglie di key switch restano separate:

- `KS classico`: large-LWE verso small-LWE prima della PBS A49;
- `packing-key call`: `LUT::from_lwe` nel sorgente RevoLUT, contato come in
  A46 e non sommato aritmeticamente al KS classico.

Sommando **soltanto** il digit high A49 ai subtotal A46:

| caso N=127 | selector BR | high BR | BR subtotal | packing-key calls | KS classici high |
|---|---:|---:|---:|---:|---:|
| senza sentinel | 3.621 | 127 | **3.748** | 3.891 | 127 |
| con sentinel uniforme pubblico | 3.645 | 127 | **3.772** | 3.917 | 127 |

Questi non sono ancora totali del circuito: nella tabella la costruzione dei
digit low/mid rimane esclusa.

Una proiezione BCS-only puo' eliminare le estrazioni bitwise A36 di A45. Con le
lane low/mid A45 e la lane high A49 bastano, per template:

1. una PBS di fold low;
2. una PBS `low -> correzione` per isolare mid;
3. una PBS di fold mid;
4. la PBS high A49.

Il risultato e' `(u_low,u_mid,h)`, tutto a `Delta=2^59`, con low/mid folded e
high numerico fresco. Il costo condizionale e' `4 BR / 4 KS / 4 marginali` per
template. Gli ingressi PBS hanno raw `L1=[0,1,1,0]`; il massimo stato consegnato
al selector ha raw `L1=2`. Localmente rientra nel max-5 e nel max-15, ma non
prova le LUT custom o il rumore RevoLUT.

| proiezione completa dei tre digit, N=127 | BR selector | BR digit | BR subtotal | packing-key calls | KS classici digit |
|---|---:|---:|---:|---:|---:|
| senza sentinel | 3.621 | 508 | **4.129** | 3.891 | 508 |
| con sentinel uniforme pubblico | 3.645 | 508 | **4.153** | 3.917 | 508 |

Se invece si conserva tutto l'upstream A45 non potato, A49 sostituisce il
classificatore A34-top `1/1/1` con un altro `1/1/1`: il ledger upstream resta
`12/11/17` per template. In quel grafo, pero', il picco raw `L1=8` delle
estrazioni bitwise resta incompatibile col max-5 corrente; rientra soltanto nel
max-15 A44. La compatibilita' locale del nuovo high non deve essere confusa con
quella dell'intero A45 non potato.

## Riparazione deterministica di `par_bridge`

Nel sorgente fissato i chunk vengono creati in ordine e poi passati a
`par_bridge`, che dichiara esplicitamente di non preservare quell'ordine. Non e'
necessario serializzare il lavoro FHE. Una modifica robusta, indipendente dalle
garanzie di `collect`, e':

```text
enumerate chunk pubblici
  -> valuta ogni (chunk_index, chunk) in parallelo
  -> raccogli (chunk_index, risultato) in qualunque ordine
  -> sort_by_key(chunk_index) in chiaro
  -> concatena i risultati
```

L'indice del chunk e' pubblico; sort e concatenazione non toccano ciphertext e
aggiungono zero BR/PFKS. C'e' un piccolo lavoro clear `O(c log c)`, con al piu'
otto chunk al primo round per `N=127`, e nessuna nuova barriera crittografica:
il round ricorsivo poteva gia' iniziare soltanto dopo avere raccolto i vincitori
del precedente.

La prova first-tie e' induttiva. Il BCS stabile sceglie il primo minimo dentro
ciascun chunk. Riordinando i vincitori per indice del chunk, la sequenza del
round successivo conserva il loro ordine originario. Ripetendo l'argomento,
l'ultimo vincitore e' il primo minimo globale. Il modello prova tutte le 24
permutazioni di completamento di quattro chunk e un torneo `N=127` con minimi
uguali in chunk diversi.

Un'alternativa pulita e' usare un `IndexedParallelIterator` su un range di
indici dei chunk e una collect ordinata. La coppia indice pubblico + sort resta
la variante piu' esplicita da verificare e non dipende da una sottigliezza
dell'adapter Rayon scelto.

## Sentinel: esatto in uniforme, insufficiente per il contratto finale

Per una sola soglia pubblica uniforme `0<=T<4095`, si premette alla galleria
`S=(T+1,label=0)`. Con sort esatto, stabile e ordine globale riparato:

- se `M=min_i score_i <= T`, allora `M<T+1`: vince il primo template con score
  `M`;
- se `M>=T+1`, il sentinel non e' maggiore del minimo gallery e, nel pareggio
  a `T+1`, viene prima: vince `label=0`.

Quindi accetta esattamente il bordo inclusivo `M<=T` e conserva il primo tie
gallery. Il modello verifica esaustivamente coppie di score su un dominio
ridotto e include i bordi `T=0`, `T=4094`, tie a `T+1` e tie gallery.

Il contratto finale, pero', e':

```text
k = first argmin_i score_i
accept iff score_k <= T_k.
```

Una soglia uniforme non puo' rappresentarlo. Con `T=[4,6]`, i vettori
`[5,7]` e `[7,5]` hanno entrambi minimo 5, ma il primo deve essere rifiutato e
il secondo deve accettare l'ID 2. Qualunque sentinel uniforme vede soltanto lo
stesso minimo e prende la stessa decisione.

Il riuso piu' diretto di BCS deve portare con ogni candidato anche i tre nibble
di `T_i`: `score3 + label2 + threshold3 = 8` lane. I tre digit score non
possono essere scartati nel blocco terminale, perche' servono ancora nel
confronto col threshold selezionato. Applicando letteralmente il ledger sorgente
A46 a otto lane per tutti e tre i passaggi si ottiene a `N=127`:

```text
4.860 BR / 5.535 packing-key calls
```

Questo e' soltanto il selector: esclude costruzione digit, confronto finale
12-bit, gate `0/ID` e formato wire. Un lookup cifrato del threshold a partire
dall'ID potrebbe essere un'altra architettura, ma non e' contato ne' provato.

## Confini del risultato

A49 non dimostra ancora:

- accumulatori Rust e comportamento FHE rumoroso della nuova lane;
- validita' delle LUT fold/aggregate e del bucket order permutato RevoLUT;
- compatibilita' statistica fra rumore di lane, PFKS e PBS;
- soglie per-template e singolo output `0/ID`;
- latenza sullo stesso hardware di A38;
- un bound `p-fail` end-to-end;
- novita' rispetto all'intera letteratura o priorita' di una primitiva.

## Modello, test e fonti

- [Modello A49](../../../benchmark/a49_bcs_high_digit_design.py).
- [Test A49](../../../tests/test_a49_bcs_high_digit_design.py).
- [Modello A46](../../../benchmark/a46_blind_top1_delta.py) e
  [confronto BCS/exact-ID](exact_id_a46_blind_top1_delta_2026-09-02.md), che identifica
  la revisione RevoLUT ispezionata.
- TFHE-rs 0.11.3: implementazione del modulus switch e helper dell'accumulatore.
- Rayon: implementazione `par_bridge`.

Il prototipo multilane A45, da cui deriva la quarta lane, non e' incluso
in questa distribuzione. La geometria impiegata da A49 e' descritta sopra.

Verifica statica eseguita:

```sh
python3 -m unittest -v tests.test_a49_bcs_high_digit_design
python3 benchmark/a49_bcs_high_digit_design.py --compact
uv run ruff check benchmark/a49_bcs_high_digit_design.py tests/test_a49_bcs_high_digit_design.py
python3 -m py_compile benchmark/a49_bcs_high_digit_design.py tests/test_a49_bcs_high_digit_design.py
```

Risultato: **13 test passati**, JSON valido, ruff e py_compile senza errori.
