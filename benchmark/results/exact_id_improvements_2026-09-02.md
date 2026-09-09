# Percorso di ottimizzazione exact-ID: guida alla figura

Data di congelamento: 2 settembre 2026.

![Percorso di ottimizzazione exact-ID](exact_id_improvements_2026-09-02.png)

La figura riassume quanto e' stato guadagnato mantenendo il requisito forte del sistema: il
server deve restituire **l'identita' esatta piu' vicina**, oppure `0` quando il minimo supera la
soglia. Non rappresenta quindi tecniche che calcolano soltanto il bit accept/reject.

La serie quantitativa parte da A23 perche' e' il primo circuito completo confrontabile con questo
contratto. A1--A22 erano esplorazioni, primitive o protocolli parziali: inserirne i secondi nella
stessa curva farebbe sembrare uno speedup il semplice fatto che calcolavano meno cose.

## Come leggere i quattro pannelli

1. **Costo strutturale.** A23--A38 sono pipeline osservate nelle suite FHE primarie; A41, A44 e
   A62 sono validazioni FHE di componente, mentre A40, A50 e A51 sono alternative statiche
   disegnate vuote. Da A23 ad A38 le blind rotation/PBS scendono da 7.804 a 3.655:
   **-53,165%**. A41 sostituisce l'uscita larga con due cifrati p16; A44 porta il limite nominale
   di rumore a 15; A62 materializza insieme A50+A53 e arriva a 3.390 BR/PBS, **-7,250%** rispetto
   ad A44. Questi sono conti di operazioni, non misure di secondi.
2. **Mediane dei run primari.** Ogni punto viene da una suite primaria separata. Serve a dare
   l'ordine di grandezza, ma i punti non sono collegati perche' furono eseguiti con carico host e
   condizioni diversi. In particolare, il fatto che A33 e A38 mostrino rispettivamente 8,458 s e
   8,328 s non misura correttamente il vantaggio causale di A38.
3. **Benchmark appaiati.** Qui le due revisioni ricevono gli stessi byte cifrati nello stesso
   blocco-chiave, con ordine bilanciato. Questi sono i confronti temporali utilizzabili:

   | passaggio | riduzione geometrica della latenza | CI 95% del run | coppie |
   |---|---:|---:|---:|
   | A28 -> A29 | 8,876% | [8,092%, 9,728%] | 60 |
   | A29 -> A33 | 13,734% | [11,806%, 15,595%] | 120 |
   | A33 -> A38 | 13,828% | [11,729%, 15,806%] | 120 |

   Il prodotto descrittivo delle tre stime corrisponde a circa **-32,261%**, cioe' **1,476x**,
   da A28 ad A38. Non e' pero' un singolo benchmark appaiato A28/A38 e non va presentato come un
   suo intervallo di confidenza.
4. **Ablation A33 -> A38.** La riduzione strutturale di 618 PBS e' composta da selezione top
   A34 (-129), scansione su due nibble (-162), chunk A36 (-254) e radix selettivo a cinque stati
   (-73). La cascata spiega da dove proviene il guadagno, senza attribuire a ogni singolo blocco
   una latenza misurata isolatamente.

## Stato che la figura autorizza a dichiarare

- A38 ha preservato il codice exact-ID in tutte le 632 query della suite primaria e in tutte le
  144 coppie totali del paired, incluse 24 coppie di warm-up escluse dalle statistiche temporali.
- Nel paired misurato, A38 ha battuto A33 in 107/120 coppie e ha ridotto la latenza geometrica del
  13,828%.
- Il CI finale A33/A38 e' ancora largo 4,076 punti percentuali, oltre l'obiettivo preregistrato di
  2 punti. L'effetto e' chiaro nel campione, ma la precisione fra blocchi resta limitata.
- Il carico assoluto durante A33/A38 era alto e non stazionario. Per questo la figura non unisce
  le mediane dei run primari e non converte automaticamente i 3.655 PBS in una promessa di
  latenza idle.
- A38 e' ancora un **candidato**: il gate end-to-end Docker passa 3/3 ID esatti e 3/3 rifiuti, ma
  l'audit A56 ha lasciato aperto il failure budget crittografico. In particolare, A36 raggiunge
  raw L1=10 contro il massimo nominale 5 e il decode finale a `Delta=2^56` non ha ancora una coda
  provata. A40/A50/A51 non sono risultati runtime; A53 e' stato materializzato soltanto nel
  componente A62.
- A41 ha superato 25/25 fixture nel gate fail-closed e poi 29/29 nella suite FHE completa con una
  terza chiave effimera. Ricostruisce esattamente `code=low+16*high`, inclusi ID 127/128, rifiuto e
  pareggi. Ripara l'uscita terminale ma non il failure budget upstream, non riduce i gate e porta
  la risposta proiettata da 16.464 a 32.856 byte.
- A44 conserva exact-ID e i contatori A41, ma usa il preset Gaussian p16 max-15. Ha superato
  120/120 valutazioni complessive, incluse 87/87 nella suite completa ripetuta su tre chiavi.
  Questo contiene numericamente raw L1=10 senza rescaling, ma l'audit A60 mostra che l'API raw non
  eredita automaticamente il contratto `p-fail` shortint: il bound incondizionato resta `<=1`.
- A62 integra davvero sia la selezione A50 sia la scan/output A53. Ha superato 96/96 valutazioni
  nella suite completa su tre chiavi e 142/142 complessive su otto key-block dichiarati effimeri.
  A N=127 osserva 3.390 BR, 3.009 KS e 3.930 marginali e ricostruisce
  `code=low+15*high`, inclusi ID 60/64/127/128, rifiuto e pareggi. Resta una validazione di
  componente: servizio, primary, paired e bound `p-fail` raw non sono ancora chiusi.
- Questi dati supportano un miglioramento ingegneristico riproducibile nel perimetro testato; da
  soli non dimostrano novita' scientifica rispetto alla letteratura.

Le alternative vuote hanno inoltre precondizioni diverse:

| candidato statico, N=127 | BR/PBS | KS | limite principale |
|---|---:|---:|---|
| A40 | 3.551 | 3.170 | sorgente Rust non eseguito; raw L1 oltre il max5 corrente |
| A50 | 3.455 | 3.074 | richiede il parametro A44 max15 e LUT custom ancora da provare |
| A51 | 3.432 | 3.051 | estende radix 15, sempre condizionato ad A44 |

A53 elimina una collisione reale incontrata nella codifica base 16. Il suo conto e' ora osservato
nel binario A62, ma il `-7,250%` rispetto ad A44 resta un delta **strutturale**, non temporale.
Il cambio di parameter set e l'adapter A53 possono cambiare il costo di ogni nodo: non si puo'
applicare quella percentuale agli 8,328 s del run primario A38.

## Dati sorgente congelati

| serie | artifact JSON | SHA-256 |
|---|---|---|
| primary A23 | `fhe_digiface_exact_primary_noise_bounded_2026-09-01.json` | `b6e54b92bef8f53c0ce057f1e68e9b473487fdd423776962579661669d4fa512` |
| primary A25 | `fhe_digiface_exact_primary_optimized_2026-09-02.json` | `a322ee946b6f5f7a031d1f59f6e9a5ae26cc42b642333295526aa7b9a6e7a009` |
| primary A28 | `fhe_digiface_exact_primary_split4_2026-09-02.json` | `683fdf98ccc5dc45222c0b51b4b3ce678e3b5bd1aa9d9fbc10ed67fcb5108465` |
| primary A29 | `fhe_digiface_exact_primary_manylut_2026-09-02.json` | `328964c860919cfce2ae09ec3ac1e2ab1f3efcc7d25c1a9781ee1ee7dafa0b34` |
| primary A33 | `fhe_digiface_exact_primary_a33_2026-09-02.json` | `e3ef7b5ae74c85e883d8ed3b2670fb6efbd20291775752fefe1ec56c0f1a9467` |
| primary A38 | `fhe_digiface_exact_primary_a38_2026-09-02.json` | `21b6a7db9e6eaa026cf3ea1fcc0264d942c56d6ead4d3f95a9fd4d76b9bc96e0` |
| paired A28/A29 | `fhe_digiface_exact_paired_a28_a29_2026-09-02.json` | `590a6256bbd895780fa643a6497ca8bf8f2f710231ec2cded2cc56fb2aaf6f44` |
| paired A29/A33 | `fhe_digiface_exact_paired_a29_a33_2026-09-02.json` | `659a996f5094112b3ea34ee3306a65bf03c8b308cd0d212c597890fc6fd71b8d` |
| paired A33/A38 | `fhe_digiface_exact_paired_a33_a38_2026-09-02.json` | `003ae3ec413c5788a689f63c79d97b1141f641752846f09e131a2eba1a0cb808` |

La proiezione A53 proviene da
`tmp/a53-radix15-group4-scan-model/a53_radix15_group4_scan_model.py`, SHA-256
`a03c8753298e0959133b0c915b911172795bafba353d86b75c7cdfb38d31eb9f`; i suoi nove test hanno
SHA-256 `c64026b21134d6df1b0e2d2dfdf4358137a98dc6b832f5cfde2e43b50d9166ae`.

Il punto A41 e' ancorato al gate
`exact_id_a41_component_gate_2026-09-02_gate01.json`, SHA-256
`fea5cc41867744edf708145574009a13274b12d06ebdaa8bee01b5ab4abe4224`, e alla suite completa
`exact_id_a41_component_full_2026-09-02_run01.log`, SHA-256
`a603f5e6b646cac2d51b3466c1587dcbdf8fd2f0434b608d88bf8d57bc57b2ba`. Il report interpretativo
ha SHA-256 `f733c8476a3dcce756124f0decd28bc0d52407385d7e708c5b8931ed11b5f3ac`.

Il punto A44 e' ancorato al gate canonico richiesto-full
`exact_id_a44_component_gate_2026-09-02.json`, SHA-256
`fadc3ddd7562fc4192c89f4c759630888472a35dc1a1b441175b3bd1f6796c83`, e al log completo
87/87, SHA-256 `921fea38c0fd6ca00af5fbe79812a04a677d5b002317ab744e3126f8de70fbec`.
Il report interpretativo e' `exact_id_a44_component_fhe_2026-09-02.md`.

Il punto A62 e' ancorato al gate canonico
`exact_id_a62_component_gate_2026-09-02.json`, SHA-256
`c72c22b4560093f437cce0029bef098556e27d6f1a4b520cc3180f221be5ce3a`, e al log full
96/96, SHA-256 `13b9e9e20b4f03d6931b963f0f3220ba091ce2d8c90e016f4803e0a09767688e`.
Il report interpretativo e' `exact_id_a62_component_fhe_2026-09-02.md`.

Il generatore [`../figure_exact_id_improvements.py`](../figure_exact_id_improvements.py) verifica
prima di disegnare che ciascun run sia riuscito, che il numero di PBS coincida con quello atteso,
che le discrepanze clear/FHE siano zero e che ogni stima paired cada nel proprio intervallo.

| output | SHA-256 |
|---|---|
| generatore Python | `9ee7bf7fbdaad19796986b1e7116e675ac5a37fddd62e4cf579282555fb82c32` |
| PNG 300 dpi | `de3b536838161306f92d170432ae671f50daf64541f267412ddb66851440c686` |
| SVG | `94f5afbb68deaea85d78be80a9e792ddfcdfb160ab5cebc8514b7b583e5fcbb8` |

Rigenerazione:

```bash
env MPLCONFIGDIR=/tmp/tesi-fhe-mpl-exact-id \
  uv run python benchmark/figure_exact_id_improvements.py
```
