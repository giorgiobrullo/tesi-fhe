# A29 ManyLUT: frontiere split4 e uscite correlate

Data: 2026-09-02. Ambiente: Apple arm64, macOS 27.0 build 26A5421a, 16 thread Rayon,
tfhe-rs 0.11.3, parametro `V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`.

## Esito

**PASS: 198/198** casi del core A29 sotto tre chiavi fresche, zero mismatch. Ogni caso ha
prodotto il codice exact-ID atteso, tutte le correzioni, quattro uscite Booleane fuse per i bit
globali 3..6 e il bit 7 riusato; il conteggio e' sempre 48 PBS a N=1.

In totale sono state decifrate e confrontate **792 coppie** correction/Boolean provenienti dalla
stessa blind rotation. Per il bit 7 il ciphertext riusato e' risultato byte-per-byte identico alla
correzione in tutti i 198 casi, come richiesto dall'implementazione senza PBS aggiuntivo.

La matrice per chiave contiene 66 casi in cinque scene:

- 40 target unici: `0..15`, terne attorno alle potenze di due da `2^4` a `2^11` e `4095`;
- 40 esecuzioni a score nullo/triviale per isolare la logica discreta;
- 26 esecuzioni con rumore reale del calcolo score, quindi 78 noisy case sulle tre chiavi;
- verifica di `score_full`, `score mod 16`, `high_residual=x>>4`, bit piccoli, correzioni,
  Booleani fusi, riuso bit 7 e codice finale.

Un primo pilot indipendente ha dato altri 66/66 casi corretti; i tre run sotto sono quelli usati
come matrice ufficiale perche' conservano anche le massime aggregate con lo stesso filtro.

## Risultati per chiave

Gli errori sono distanze di fase firmate normalizzate al `Delta` dell'uscita corrispondente.
`Pearson` descrive le coppie fuse aggregate; non e' un test di indipendenza e non entra nel
criterio di pass.

| chiave | casi | coppie fuse | mean abs correction | mean abs Boolean | Pearson globale | max correction, ogni bit | max Boolean fuso | max gap coppia | max bit 7 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 66/66 | 264 | 0,002446 | 0,000279 | 0,237106 | 0,368956 | 0,001982 | 0,044290 | 0,002505 |
| 2 | 66/66 | 264 | 0,002152 | 0,000379 | 0,049801 | 0,240313 | 0,003158 | 0,030679 | 0,001609 |
| 3 | 66/66 | 264 | 0,002603 | 0,000342 | 0,106655 | 0,185491 | 0,002288 | 0,031919 | 0,002166 |

Le correlazioni per bit osservate sono:

| chiave | bit 3 | bit 4 | bit 5 | bit 6 |
|---:|---:|---:|---:|---:|
| 1 | 0,078156 | 0,584227 | 0,400917 | -0,088347 |
| 2 | -0,141800 | 0,024508 | 0,276623 | 0,632248 |
| 3 | 0,094065 | 0,234021 | 0,203246 | 0,509405 |

La variabilita' e il campione con molti casi triviali rendono questi coefficienti soltanto
descrittivi. Le uscite condividono per costruzione una GLWE ruotata e non vanno trattate come
indipendenti in un eventuale calcolo della `p-fail`.

## Comando

Il binario release e' stato costruito con:

```bash
cargo build --release \
  --manifest-path experiments/14_pipeline_tfhe_rs/Cargo.toml \
  --features diagnostic-trace --bin split4_boundary_trace
```

Ogni chiave ufficiale usa una nuova invocazione di:

```bash
RAYON_NUM_THREADS=16 \
  experiments/14_pipeline_tfhe_rs/target/release/split4_boundary_trace
```

Il processo termina con errore se un checkpoint diverge, se manca una delle quattro coppie fuse,
se il bit 7 non e' lo stesso ciphertext della correction o se il conteggio non e' 48.

## Provenienza

SHA-256:

- core `src/private_argmin.rs`:
  `06b62cb44f372fbf44e33b9a541a3609e49657f1201f4e319cdab3b0da1e37e4`;
- harness `src/bin/split4_boundary_trace.rs`:
  `4af54565d58978b604518663d83355e21774a3e2d38c32ac7c1f336d3ad72efc`;
- binario release:
  `91798ff9c0d63159934906daadc18dac93c5c98818e99deca12351104040ffad`.

Le chiavi sono rimaste in memoria e non sono state persistite. I tempi di validazione delle tre
invocazioni sono 13,605303 s, 13,578986 s e 13,541008 s; non sono benchmark di latenza applicativa.

## Interpretazione e limite

Questo gate supera il rischio immediato che sample extraction a gradi diversi o il riuso del bit
7 cambino il messaggio. Non deriva una distribuzione teorica congiunta, non fornisce un bound
composto e non sostituisce gallerie grandi, suite primaria 632 o Docker E2E. A29 resta candidato
finche' quei gate non sono completati.
