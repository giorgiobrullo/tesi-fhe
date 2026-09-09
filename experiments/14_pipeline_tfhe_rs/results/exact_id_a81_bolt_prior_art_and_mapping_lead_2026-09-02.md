# A81: chiusura prior art BOLT e lead di mapping exact-ID

Data: 2026-09-02. Stato: **BOLT DOCUMENT-ACCESS GAP CLOSED; NEW LEAD NOT YET IMPLEMENTED**.

## Domanda

BOLT 2026 contiene gia' la costruzione A53, oppure indica una strada nuova che possiamo applicare
al selettore exact `0/ID`?

Risposta corta: il PDF **non descrive ne' valuta la costruzione interna A53**, pur includendo il
priority encoder EPFL come benchmark booleano. BOLT ottimizza netlist booleane TFHE usando una
libreria finita di gate booleani e una mappa di riscritture a uno bootstrap. Il paper non presenta
il nostro accumulatore raw multi-valore, il selettore affine di primo elemento, la coppia di sample
correlati base 15 o la ricostruzione esatta dell'ID. Pero' rende concreta una strada ulteriore:
fare mapping del nostro DAG con un costo consapevole di profondita', parallelismo e runtime, invece
di scegliere ogni ottimizzazione soltanto dal conteggio totale dei PBS.

## Fonte hash-pinned

- Chaturvedi, Chatterjee, Chattopadhyay, Mukhopadhyay, *BOLT: Bootstrapping-Aware Logic
  Resynthesis and Technology Mapping for Efficient TFHE Circuits*, ePrint 2026/153,
  [pagina ufficiale](https://eprint.iacr.org/2026/153), PDF di 14 pagine;
- PDF ufficiale SHA-256:
  `dbc4ae321f47a7e6f93155fa660b0195c8f2738be1503e18888b41a6a19ad2e5`;
- estrazione testuale locale SHA-256:
  `3c3b1b1b3114bb13a20ced635052efbb3aa76b62a3b4d7ca87b5332f18365f9f`.

Il PDF e' stato ispezionato integralmente. I numeri di pagina sotto sono quelli stampati nel PDF.

## Cosa fa davvero BOLT

1. La libreria di tecnologia, in Tabella I a p. 2, contiene gate booleani bootstrapped:
   AND/OR/NAND/NOR fino a fan-in 4, XOR/XNOR fino a fan-in 3 e gate compositi del tipo
   AND-XOR, OR-XNOR e varianti.
2. La risintesi, pp. 5-6, usa inserimento/propagazione di inverter e riscrittura booleana per
   trasformare catene di gate in un elemento della libreria che richiede un solo bootstrap.
   La Tabella III e' una mappa finita di coppie di gate, non una ricerca di coefficienti su stati
   plaintext multi-valore.
   Il preprocessing affine generico dei ciphertext con costanti e scaling interi e' gia' presente
   nella descrizione TFHE a p. 3 e nelle Equazioni 1-2 a p. 5; BOLT non cerca pero' i coefficienti
   sui nove stati dipendenti multi-valore di A53.
3. Il technology mapping, pp. 7-10, rappresenta la netlist come DAG e bilancia profondita' di
   bootstrapping, conteggio e duplicazione/fan-out con la metrica DRDM e uno scheduler simulated
   annealing. Il runtime viene misurato dopo: BOLT non usa un modello calibrato di costi eterogenei
   per primitiva.
4. Il confronto con gli approcci LUT/FBS, pp. 10-11, e' esplicito: BOLT resta gate-based. Nella
   conclusione a p. 13, gli autori lasciano come lavoro futuro l'adattamento di metodi di
   ottimizzazione LUT del CAD tradizionale ai flow FHE LUT-based; non presentano quel mapper.

Quindi il paper rafforza il prior art su riscrittura, priority encoder e mapping TFHE, ma non
anticipa la relazione A53

```text
f + 4*c0 + 2*c1 + c2
local - 4*prefix
```

ne' il layout con nove stati raggiungibili, due sample correlati, cifre base 15 e correzioni
pubbliche dipendenti dal gruppo.

## Il dato sul priority encoder

BOLT include il priority encoder EPFL, quindi non possiamo presentare come nuova l'idea generale di
un priority encoder cifrato o della sua ottimizzazione circuitale.

| metrica | Yu et al. LUT/FBS | Singh et al. gate | BOLT |
|---|---:|---:|---:|
| gate/nodi della netlist finale, Tabella V p. 11 | 818 | 681 | 686 |
| runtime riportato, Tabella VI p. 11 | 32.720 ms | 7.342 ms | 4.221 ms |

La baseline iniziale della stessa riga e' 974 gate; AutoHoG/Guan et al. ne riporta 833. BOLT non
vince il conteggio contro Singh su questa istanza, ma riporta uno speedup di 1,74x, equivalente a
un runtime inferiore del 42,5% (`4.221` contro `7.342` ms). Questi
numeri **non sono direttamente trasferibili** ad A53: usano un priority encoder booleano generico,
un'altra libreria/runtime, altri parametri e altro hardware. Sono prova che profondita' e forma del
DAG possono contare piu' del solo numero totale di gate.

## Confine di novita' aggiornato

Claim ancora difendibile, limitato al corpus ispezionato:

- A53 e' una costruzione exact-ID specifica non trovata in BOLT;
- il contributo potenziale e' la combinazione esatta fra selettore signed group-4, layout
  dual-sample base-15 e ricostruzione tie-first `0/ID`;
- il no-go group-5 resta interessante solo dentro la classe formale dichiarata.

Claim non difendibili:

- nuovo priority encoder TFHE;
- nuova idea di fondere piu' gate in un bootstrap;
- nuovo mapping consapevole della profondita' di bootstrapping;
- superiorita' runtime rispetto a BOLT senza una baseline implementata sullo stesso task e sulla
  stessa macchina.

## Lead A81 derivato: mapper eterogeneo per il nostro DAG

La trasposizione utile non e' passare A53 dentro BOLT come netlist booleana: perderemmo proprio la
struttura raw multi-valore che ci fa risparmiare PBS. Il lead e' costruire un piccolo mapper per il
nostro alfabeto eterogeneo:

```text
linear LWE
  -> KS / PFKS
  -> blind rotation / many-extract
  -> CM-GGSW external product / lane permutation
  -> checked PBS
```

Ogni riscrittura candidata deve portare un certificato di equivalenza sull'intero dominio
raggiungibile e mantenere soglia, tie-left ed esito esatto `0/ID`. Il costo non deve essere il solo
conteggio dei PBS, ma almeno:

- wall time misurato per tipo di primitiva e dimensione chiave;
- profondita' critica e parallelismo disponibile;
- BR, KS, PFKS, external product e sample marginali separati;
- traffico/reuse delle evaluation key;
- obblighi di rumore A79 e memoria di picco.

Questa estensione a PFKS, many-extract, external product, obblighi di rumore e costi calibrati per
primitiva e' nostra ed esige un audit di prior art separato; non e' ancora un claim di novita'.

Il primo test controllato e' piccolo: esprimere A62, A66, A30-D2 e A53 come quattro DAG congelati,
verificare che il mapper recuperi le forme note, poi vedere se trova una composizione non dominata.
Qualunque candidato viene promosso solo dopo replay Rust, correttezza esaustiva sulle fixture e
benchmark paired con chiavi fresche. Fino ad allora A81 e' un **lead motivato**, non un guadagno.

## Decisione

- chiudere il gap documentale BOLT nell'audit A50/A53;
- conservare A53 come segnale costruttivo stretto, senza claim di primitive nuove;
- aggiungere il mapper bootstrapping-aware alla frontiera, dopo i gate runtime gia' in corso;
- non sostituire A30/A78/A79 con A81: il mapper deve confrontare e combinare quelle route.
