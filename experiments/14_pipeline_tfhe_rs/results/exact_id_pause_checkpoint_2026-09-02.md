# Checkpoint di pausa — identificazione cifrata exact-ID

Data: 2 settembre 2026.

Stato operativo: **seconda pausa esplicita richiesta dall'utente**. I tre worker A73/A74/A75
sono stati congelati; nessun processo Cargo, compilazione, servizio o valutazione FHE e' lasciato
in esecuzione. Nessun candidato nuovo e' promosso.

## Requisito che non cambia

Il server deve calcolare sotto cifratura il primo argmin e restituire:

```text
0     se il volto piu' vicino non supera la soglia
i + 1 se l'identita' i e' il volto piu' vicino ammesso
```

Non basta quindi il solo bit accept/reject. Un rifiuto non deve rivelare l'identita' piu' vicina.

## Stato congelato

| linea | cosa sappiamo davvero | cosa manca | stato |
|---|---|---|---|
| A29 | exact-ID generale e fallback fail-closed validato | bound `p-fail` composto | fallback corrente |
| A33 | fast path exact-ID; paired A29/A33 positivo | bound `p-fail` composto | baseline sperimentale promossa |
| A38 | 3.655 BR/PBS; primaria 632/632; paired A33/A38 `-13,828%`; Docker 6/6 | failure budget raw | candidato, non promosso |
| A62 | A50+A53 realmente integrati; 3.390 BR, 3.009 KS, 3.930 marginali a N=127; 142/142 valutazioni FHE | servizio, paired, primary e bound raw | componente FHE valido |
| A66 | stesso circuito/wire A62; accumulatori A53 costruiti 136 -> 35; compilato; 46/46 valutazioni FHE aggiuntive | paired A62/A66 e RSS | candidato latency-ready |
| A67 | servizio A62 wire v4, due LWE p16 base-15 e binding del circuito; compilazione isolata, lib 23 pass/3 ignored e bin 12/12 | gate runtime locale, negativi cross-format, FHE e Docker | servizio compilato, non eseguito |
| A68 | circuito checked-only D=512/N<=128; ledger `M(N)=24029+18984N`; compilazione isolata riuscita; il primo N=1 e' stato avviato e poi interrotto alla pausa | completare da zero il primo run FHE N=1 e trasferire davvero il bound | baseline formale compilata, ancora senza risultato FHE |

## Numeri da non confondere

- La mediana primaria A38 osservata resta **8,328 s/query**, ma non e' una promessa idle.
- Il percorso exact-ID e' passato da 7.804 BR/PBS in A23 a 3.390 in A62: **-56,56%**
  strutturale.
- Il miglioramento temporale paired misurato lungo A28 -> A29 -> A33 -> A38 e' circa
  **-32,26% composto**; non e' un singolo paired A28/A38.
- Le prove A66 grandi hanno prodotto tempi grezzi circa 5,82--13,37 s sotto carico variabile.
  Non autorizzano uno speedup: il confronto causale A62/A66 non e' ancora stato eseguito.
- I circa 0,65 s storici di A19 appartengono al solo membership bit e non soddisfano exact-ID.

## Punto esatto di ripresa

1. Materializzare da zero `tmp/a73-a62-a66-paired` con la stessa chiave, galleria e ciphertext,
   ordine AB/BA, target Cargo isolato, strati 1-thread e produzione, piu' RSS. Nessun file A73
   era ancora stato creato al momento della pausa.
2. Materializzare il runner A74 e riprendere A67 dal gate locale: reject dei wire/base-16 legacy
   e due query exact-ID FHE N=16; soltanto dopo valutare Docker. Nessuna chiave o directory
   temporanea A74 era ancora stata creata.
3. Riprendere A68 dal solo N=1 FHE (43.013 call checked nominali) con un nuovo log `run02`; il
   `run01` parziale resta immutato e non vale come evidenza. Non autorizzare N maggiori prima di
   un PASS N=1 con tempo e RSS.
4. Aggiornare la figura soltanto con risultati paired/runtime, non con proiezioni.

Il paired A62/A66 non e' stato ancora materializzato. A74 non ha lanciato il servizio A67. A75 ha
interrotto il processo A68 con SIGINT: la chiave effimera esisteva soltanto in memoria ed e'
scomparsa col processo. Il log parziale contiene soltanto caso scelto e warning, senza PASS,
tempo o RSS; non autorizza alcuna claim FHE. Le istruzioni restano recuperabili e i percorsi A62,
A66, A67 e A68 sono preservati.

## Provenienza minima della pausa

| artefatto | SHA-256 |
|---|---|
| figura corrente PNG | `de3b536838161306f92d170432ae671f50daf64541f267412ddb66851440c686` |
| A66 `private_argmin.rs` | `92289e44e9c26c3190ac61c16c50e0e338bc9399d19fbf9231dacd50a6c3102b` |
| A66 adapter `a53_scan/fhe.rs` | `ad70a676fbce8e1f58b5d40a151d1ce186b0b90527c8cc50c3b9f9873cb85a99` |
| audit indipendente A66 | `89b7f5c2781445b497e15a6c9f0e4307d2cd02576b1cd9067dbfe118108d47f3` |
| report compile A67 | `e3812d9eb6788881dcf5aab277b68b72fad9f0547bd5c9507fd8a64e033438be` |
| report compile A68 | `a1e3353ab28762a5ef73390282ddad04f5549922dd3ebe99affbe7d1605731ef` |
| dry-plan A68 A75 | `9fb28981c12f9d89e44ef5883f6aba9fae6c2484a5ec220bbfeed766ef765f48` |
| log parziale A68 N=1 A75 | `6d4640f5e0716de6cb72bfbd3ec59b7b7e0a8047f6ec59092ab74365718b6fe8` |
| binario isolato A67/A71 | `35dd29890573790158d1174f391b83c607693183f663e79fbdfc69f658819021` |
| binario isolato A68/A72 | `df4825cdc5784e81e5ddbf31dd376c249db063154f8ef74592332596d6e9663a` |

Tre artefatti preesistenti esplicitamente protetti risultano ancora byte-identici al checkpoint
precedente: README congelato A38 `156a35f...`, `ritaratura_soglia.txt` `e490b743...` e trascrizione
ultimo meeting `01e08d54...`.
