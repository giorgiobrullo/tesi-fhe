# A29 ManyLUT: semantica exact-ID N=1..8/64/127/128

Data: 2026-09-02. Core A29 condiviso, tfhe-rs 0.11.3,
`V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`, Apple arm64, 16 thread Rayon.

## Esito

**PASS: 198/198 query cifrate**, zero differenze rispetto all'oracolo clear e zero differenze fra
conteggio PBS osservato e formula A29.

La matrice copre `N=1..8,64,127,128`, tre chiavi fresche per dimensione e sei casi per chiave:

1. soglia uniforme della scena;
2. soglia strict del vincitore e permissiva per i template piu' lontani;
3. vincitore permissivo;
4. vero vincitore spostato all'ultimo indice;
5. per `N >= 2`, pareggio al primo indice con il duplicato successivo permissivo;
6. tutte le soglie sotto il dominio.

Il summary del binario e' positivo in entrambi gli stadi, N=1..8 e N=64/127/128:

```text
SUMMARY,all_correct=true,all_under_10s=true,time_gate_enforced=false,same_core=true,no_distance_output=true
```

Sono state generate 33 coppie di chiavi: il binario crea una nuova chiave per ogni coppia
`(key_run, N)`, non riusa tre chiavi globali su tutte le dimensioni. Ogni caso cifra nuovamente il
probe GLWE dual-layout.

## Conteggi e codici osservati

| N | query | PBS osservati | codice vincitore, casi non permutati | ultimo codice provato | esito |
|---:|---:|---:|---:|---:|---:|
| 1 | 18 | 48 | 1 | 1 | 18/18 |
| 2 | 18 | 95 | 1 | 2 | 18/18 |
| 3 | 18 | 128--129 | 3 | 3 | 18/18 |
| 4 | 18 | 162--165 | 4 | 4 | 18/18 |
| 5 | 18 | 220--223 | 4 | 5 | 18/18 |
| 6 | 18 | 253--262 | 4 | 6 | 18/18 |
| 7 | 18 | 287--296 | 4 | 7 | 18/18 |
| 8 | 18 | 323--332 | 4 | 8 | 18/18 |
| 64 | 18 | 2.494--2.578 | 39 | 64 | 18/18 |
| 127 | 18 | **4.965--5.094** | 39 | 127 | 18/18 |
| 128 | 18 | **5.000--5.129** | 39 | **128** | 18/18 |

I valori bassi delle ultime tre righe sono il percorso a soglia uniforme o pubblicamente
costante. I valori alti osservati appartengono ai pattern per-template strict/tie di questa
matrice; non sono l'upper bound teorico su ogni possibile maschera, pari a
2.767/5.524/5.559 PBS a N=64/127/128.

La formula uniforme A29 a N=127 e' quindi ora sia derivata dal codice sia **osservata in un core
FHE completo**: 4.965 PBS. Le KS non sono telemetria runtime; il conteggio strutturale resta
`PBS - 3N`, quindi 4.584 KS nel caso uniforme N=127.

Il caso `last_winner_permissive` ha restituito il codice massimo N sotto tutte le chiavi,
incluso `128`. Per `N >= 2`, il caso `first_tie_strict_later_permissive` ha restituito sempre `0`:
il circuito mantiene il primo minimo e usa la soglia del solo vincitore, senza degradare a
membership. A `N=1` lo stesso nome identifica soltanto il caso degenere con soglia strict, poiche'
non esiste un secondo template da duplicare.

## Tempi osservati, non benchmark

| N | intervallo `total_s` nei 18 casi |
|---:|---:|
| 64 | 3,689138--4,370192 s |
| 127 | 6,684349--7,596960 s |
| 128 | 6,712880--8,627936 s |

Il gate `<10 s` era disabilitato con `--allow-slow`; `all_under_10s=true` e gli intervalli sono
osservazioni non isolate, non una garanzia di latenza. Le soglie per-template aggiungono PBS e il
carico dell'host non era controllato.

## Comandi

Stadio piccolo:

```bash
RAYON_NUM_THREADS=16 \
  experiments/14_pipeline_tfhe_rs/target/release/argmin_bucket_bits_periodic \
  --run --keys 3 --cases all --real-probes 1 \
  --sizes 1,2,3,4,5,6,7,8 --allow-slow
```

Stadio grande:

```bash
RAYON_NUM_THREADS=16 \
  experiments/14_pipeline_tfhe_rs/target/release/argmin_bucket_bits_periodic \
  --run --keys 3 --cases all --real-probes 1 \
  --sizes 64,127,128 --allow-slow
```

## Provenienza

SHA-256 al build/run:

- core `src/private_argmin.rs`:
  `06b62cb44f372fbf44e33b9a541a3609e49657f1201f4e319cdab3b0da1e37e4`;
- harness `src/bin/argmin_bucket_bits_periodic.rs`:
  `6f081eee994f0c6629e66a50bb58ae080ea80d2f141aab143b381a59ff671963`;
- binario release:
  `57fd91c22c2e4792fc3bd2cbde20457b56cb6ff48f601fa38485639644170ed4`.

## Limiti e prossimo gate

La matrice usa il core condiviso ma una sola scena/probe per dimensione. Non sostituisce la suite
DigiFace primaria da 632 query, l'E2E HTTP/Docker, un confronto A28/A29 paired o un bound della
`p-fail` composta. A29 resta candidato finche' tali gate non sono completati.
