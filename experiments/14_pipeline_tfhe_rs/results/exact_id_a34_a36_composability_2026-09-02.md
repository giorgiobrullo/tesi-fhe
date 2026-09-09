# Componibilita' statica: A34-top + due nibble + radix-5 + A36

Data: 2026-09-02. Questo documento riguarda soltanto modello clear, contratti di scala/LUT e
conteggi strutturali. Non e' stato modificato o compilato il core Rust, non sono state generate
chiavi e non e' stato eseguito alcun workload FHE.

## Esito

Le quattro proposte sono **componibili a livello semantico e strutturale**, ma non sono ancora una
revisione integrata o promossa. La proiezione condizionale a `N=127` e':

| circuito | blind rotation | key switch | marginali di output |
|---|---:|---:|---:|
| A33 corrente, radix-4 | 4.273 | 3.892 | 4.908 |
| A34-top + two-nibble + A36, ancora radix-4 | 3.728 | 3.347 | 4.279 |
| composizione completa con radix-5 selettivo | **3.655** | **3.274** | **4.206** |
| risparmio strutturale contro A33 | **618** | **618** | **702** |

`3.655/3.274` non e' una misura di latenza, non e' stato osservato da un binario e non deve essere
attribuito al core A33/A34/A36 vivo. E' il risultato di una decomposizione per stadi disgiunti che
passa i controlli statici descritti sotto.

## Ledger disgiunto, non somma di percentuali

Il conto A33 viene prima separato in quattro regioni. La colonna `backbone` contiene scoring,
estrazione e ogni nodo che non appartiene alle altre tre regioni; nella composizione A34 perde
soltanto il key switch del sample terminale `b8`, mentre conserva i ciphertext esatti `b7..b0`.

Ogni cella riporta `BR / KS / marginali`.

| variante | backbone | top/admission | selezione bassa | scan/output | totale |
|---|---:|---:|---:|---:|---:|
| A33 radix-4 | 1.397 / 1.143 / 1.905 | 636 / 509 / 763 | 1.868 / 1.868 / 1.868 | 372 / 372 / 372 | 4.273 / 3.892 / 4.908 |
| composta radix-4 | 1.397 / 1.016 / 1.905 | 507 / 507 / 507 | 1.614 / 1.614 / 1.614 | 210 / 210 / 253 | 3.728 / 3.347 / 4.279 |
| composta radix-5 | 1.397 / 1.016 / 1.905 | 507 / 507 / 507 | 1.550 / 1.550 / 1.550 | 201 / 201 / 244 | 3.655 / 3.274 / 4.206 |

La rete top A34 usa un riduttore categoriale **binario** da 126 nodi, non un OR Booleano: il
radix-5 non le viene applicato. La selezione A36 conserva invece otto OR di galleria, mentre la
nuova scan conserva il prefisso di gruppo e le due riduzioni one-hot dei nibble.

## Ablation sequenziale a N=127

| passo | totale BR / KS / marginali | risparmio incrementale | risparmio cumulativo |
|---|---:|---:|---:|
| A33 radix-4 | 4.273 / 3.892 / 4.908 | 0 / 0 / 0 | 0 / 0 / 0 |
| + A34 top-category e trim del sample `b8` | 4.144 / 3.763 / 4.652 | 129 / 129 / 256 | 129 / 129 / 256 |
| + A34 scan/output a due nibble | 3.982 / 3.601 / 4.533 | 162 / 162 / 119 | 291 / 291 / 375 |
| + A36 chunk da quattro | 3.728 / 3.347 / 4.279 | 254 / 254 / 254 | 545 / 545 / 629 |
| + radix-5 soltanto sulle riduzioni rimaste | **3.655 / 3.274 / 4.206** | **73 / 73 / 73** | **618 / 618 / 702** |

Le ablation singole, ciascuna applicata da sola ad A33, sono invece:

| componente isolato | totale BR / KS / marginali | saving isolato |
|---|---:|---:|
| A34 top-category | 4.144 / 3.763 / 4.652 | 129 / 129 / 256 |
| two-nibble scan/output | 4.111 / 3.730 / 4.789 | 162 / 162 / 119 |
| A36 chunked selector | 4.019 / 3.638 / 4.654 | 254 / 254 / 254 |
| radix-5 sul solo A33 | 4.166 / 3.785 / 4.801 | 107 / 107 / 107 |

Questi quattro saving **non si possono sommare**. La somma ingenua darebbe `652/652/736`, cioe'
34 nodi/marginali di troppo rispetto a `618/618/702`:

- 12 dei 107 nodi radix-5 isolati appartengono alle riduzioni A33 top `R(N)` e `R(ceil(N/2))`,
  eliminate del tutto da A34-top;
- la vecchia scan/output A33 guadagnava 31 nodi col radix-5, ma la nuova two-nibble ne guadagna
  soltanto 9: altri 22 non sopravvivono alla sostituzione;
- nel circuito composto restano 64 nodi risparmiati negli otto OR A36 e 9 nella nuova scan, quindi
  il contributo radix-5 realmente componibile e' `64+9=73`.

## Contratto fra gli stadi

| confine | uscita | adattamento | ingresso successivo |
|---|---|---|---|
| A34-top -> A36 | candidato fresco `0/1` a `2^59` | moltiplicazione clear per 2, nessun PBS | stato A36 `0/2` a `2^59` |
| bit extractor -> A36 | ciphertext A33/A34 di `b7..b0` con pesi `[1,1,1,1,1,8,4,2]` | moltiplicatori `[-2,-2,-2,-2,-2,1,-1,-1]` | pesi A36 `[-2,-2,-2,-2,-2,8,-4,-2]` |
| A36 -> scan | finalizzatore separato `0/1` a `2^59` | nessuno | candidati Booleani ordinari |
| selector -> riduzione nibble | due marginali freschi low/high a `2^59` | riduzioni one-hot p16 | due radici a `2^56`, pesi 1 e 16 |
| radici -> wire | due LWE alla stessa scala codice | somma LWE lineare | **un solo LWE** `0`/ID |

A34-top sottrae le correzioni `b0..b7` per classificare `h`, ma conserva prima gli stessi output
esatti usati da A36. Il loro fan-out non richiede nuove blind rotation, KS o sample extraction.
Esiste pero' dipendenza statistica fra questi cammini; il ledger non la interpreta come
indipendenza della `p-fail`.

## LUT che devono restare distinte

Il passaggio a radix-5 non equivale a cambiare una costante globale:

1. il minimo categoriale A34 resta una LUT binaria sulla codifica `{1,3,7,0}`;
2. gli OR Booleani della scan usano la costruzione signed `0/1 -> 0/1` con fan-in massimo cinque;
3. l'OR A36 usa lo stato step-two e richiede un nuovo corpo raw `p=16`: output `2` nel plateau
   `[N/16,11N/16)`, cioe' codici somma `2,4,6,8,10`, e zero attorno al codice 0;
4. le riduzioni dei nibble sono LUT identita' p16 su plaintext one-hot `0..15`, non OR.

Per l'OR A36 radix-5 sono stati controllati tutti i centri raggiungibili
`{0,2,4,6,8,10}` e ogni errore intero con `|e|<N/16`. Il target antipodale 18 resta
irraggiungibile; il fan-in cinque ha `L1=5` ma, grazie al plateau nominale doppio, normalizza a
2,5. Il corpo A36 radix-4 corrente `[N/16,9N/16)` **non** puo' essere riusato senza estensione.

## Rumore: nessun conflitto statico, ma due punti senza slack

| blocco | bound locale auditato | limite usato |
|---|---:|---:|
| LUT immediate A34-top | 2 | 5 |
| zero-test/refresh A36, normalizzato sul margine nominale doppio | **5** | 5 |
| OR A36 radix-5, stessa normalizzazione | 2,5 | 5 |
| OR/prefix/selector/digit reduction radix-5 della scan | **5** | 5 |

Quindi non emerge una collisione di scala o un superamento L1 locale, ma A36 al confine `b4` e le
LUT radix-5 della scan arrivano esattamente al limite, senza guard band. Inoltre questo controllo:

- tratta il margine full-slot A36 sulla griglia intera della blind rotation e non incorpora nel
  numero L1 il mezzo bin di arrotondamento del modulus switch;
- non chiude il rumore ereditato dal residuo che alimenta il classificatore A34-top;
- non dimostra la probabilita' di decode delle due radici fresche a scala codice `2^56`;
- non rende indipendenti le due estrazioni dello stesso selector two-nibble, ne' gli errori dei
  cammini che condividono i ciphertext dei bit;
- usa `core_crypto`, dove il tracker shortint `NoiseLevel` non viene applicato automaticamente.

La composizione e' dunque ammessa come **candidato statico da implementare e falsificare**, non come
prova crittografica o bound end-to-end.

## Cosa manca per materializzare la composizione

I prototipi dei componenti restano separati. Un futuro candidato Rust combinato deve ancora:

- integrare A34-top lasciando disponibili gli stessi ciphertext pesati `b7..b0` e verificare che il
  trim del solo sample `b8` valga davvero `0 BR / 127 KS / 0 marginali`;
- collegare direttamente i candidati A34 `0/1` all'adattatore clear `x2` di A36, senza checkpoint
  decifrati o re-encryption;
- estendere l'OR raw A36 dal plateau radix-4 `[N/16,9N/16)` al plateau radix-5
  `[N/16,11N/16)` e cambiare la topologia delle sue otto riduzioni;
- portare a radix-5 soltanto prefisso e riduzioni digit della scan two-nibble, mantenendo separati
  local-first, selector multi-output e minimo categoriale binario;
- misurare nel medesimo binario BR, KS e marginali per stadio, verificando il totale
  `3.655/3.274/4.206` invece di assumerlo dal modello.

Finche' questi collegamenti non esistono nello stesso circuito, il numero finale resta una
proiezione statica condizionale.

## Validazione clear

Il modello `benchmark/a34_a36_composability_model.py` compone realmente i tre trasformatori clear:
top-category, A36 sui byte bassi e scan/output a due nibble. La variante radix-5 ricostruisce il
prefisso e le riduzioni dei digit, quindi viene confrontata sia con la scan radix-4 sia con
l'oracolo `min(score,index)` seguito dalla soglia 1023.

La suite separata controlla:

- decomposizione/count invariant per tutte le gallerie `N=1..128`;
- tutti i 4.096 score singoli;
- 9.216 coppie ottenute da tutte le 16 categorie alte e sei suffissi di confine;
- all-reject e tie per tutte le 128 dimensioni;
- ogni posizione vincente, 8.256 casi;
- confini 1023/1024, cambio categoria 767/768, tie-first, tail N=127/codice 127 e codice massimo
  128.

Con la matrice deterministica senza casi random aggiuntivi sono **21.833 casi semantici**, tutti
coincidenti. Il run completo separato aggiunge 256 gallerie pseudocasuali deterministiche e passa
**22.089/22.089** casi; anche i 9 test del file dedicato passano. Questi test restano clear e non
sostituiscono il necessario prototipo Rust integrato, le fixture FHE, la suite primaria, Docker, il
paired o l'accounting `p-fail`.

## File

- `benchmark/a34_a36_composability_model.py`
- `tests/test_a34_a36_composability_model.py`
- `experiments/14_pipeline_tfhe_rs/results/exact_id_a34_a36_composability_2026-09-02.md`
