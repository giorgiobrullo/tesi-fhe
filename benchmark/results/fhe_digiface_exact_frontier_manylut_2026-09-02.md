# A29 ManyLUT: regressione cifrata di frontiera DigiFace

Data run: 2026-09-02T05:16:14Z--05:25:29Z. Durata wall totale: 555,144 s.

## Esito

**PASS: 80/80 query**, zero errori operativi e zero discrepanze fra oracolo clear e codice
exact-ID cifrato.

La regressione ripete 16 volte cinque probe ai punteggi minimi `2, 3, 4, 5, 7`, con soglia
uniforme `T=4`:

| score minimo | argmin zero-based | codice atteso/osservato | esito | ripetizioni |
|---:|---:|---:|---|---:|
| 2 | 17 | 18 | accetta identita' 17 | 16/16 |
| 3 | 45 | 46 | accetta identita' 45 | 16/16 |
| 4 | 92 | 93 | accetta all'uguaglianza | 16/16 |
| 5 | 87 | 0 | rifiuta | 16/16 |
| 7 | 87 | 0 | rifiuta | 16/16 |

Totale: 48 autorizzazioni attese e 48 osservate. Il controllo include l'indice dell'argmin e il
codice `indice+1`, quindi non puo' essere soddisfatto da un circuito membership-only.

## Cifrature, costo e contratto

- 80/80 probe ciphertext distinti, 32.840 byte ciascuno;
- 80/80 result ciphertext distinti, 16.464 byte ciascuno;
- **4.965 PBS in ogni query**;
- contratto `exact-open-set-id-v2` in ogni risposta;
- chiave client/server fresca in directory temporanea, rimossa a fine run;
- server terminato con SIGTERM (`exit_code=-15`) e porta rilasciata.

## Tempi osservati, non confronto prestazionale

| misura server | valore |
|---|---:|
| minimo | 6.614,7 ms |
| mediana | 6.800,15 ms |
| media | 6.910,631 ms |
| p95 | 7.673,3 ms |
| massimo | 8.675,4 ms |

Il carico host era alto e variabile (`load average` 1m 14,368 prima e 45,317 dopo). Questi tempi
servono a caratterizzare il run, non a stimare causalmente il guadagno su A28. Quel confronto deve
usare la stessa chiave e gli stessi ciphertext in coppie A28/A29 sul sistema inattivo.

## Provenienza verificata

- base Git `6611c185adc9a658a075519b4316386f0bb48656`, worktree esplicitamente sporco;
- core A29 `src/private_argmin.rs`:
  `06b62cb44f372fbf44e33b9a541a3609e49657f1201f4e319cdab3b0da1e37e4`;
- validator `benchmark/fhe_digiface_validation.py`:
  `eabb803d3c8e85f4c38ac395a8907b7b0579fede89f9c23362006da675523398`;
- binario A29 congelato:
  `cb0d0c1736713ae7b7a36450456a6ea45cab5bd8ac63d0c08c78220b4aaba102`;
- CSV:
  `de609a07ffb4ba21f9228c96662aedd1ed3fb22af898fb663c470adfea7c4a5f`;
- JSON:
  `7a41459ce8eed969996365f6c3da41e135a989a925046e501368ec18e60d800c`.

Il JSON attesta gli stessi hash prima e dopo, il path eseguibile osservato e il PID. Il CSV e'
vincolato dall'hash registrato nel JSON. L'unicita' dei ciphertext di risultato e' stata
ricontrollata direttamente dalle 80 righe CSV.

Artifact grezzi:

- [CSV](fhe_digiface_exact_frontier_manylut_2026-09-02.csv)
- [JSON](fhe_digiface_exact_frontier_manylut_2026-09-02.json)

## Limiti

Il gate usa soltanto cinque probe scelti per la frontiera. Non sostituisce la suite primaria da
632 query, l'E2E HTTP/Docker su immagini, il confronto paired A28/A29 o un bound composto della
`p-fail`. A29 resta candidato non promosso finche' quei gate non sono chiusi.
