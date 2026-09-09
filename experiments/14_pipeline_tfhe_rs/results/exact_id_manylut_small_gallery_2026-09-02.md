# A29 ManyLUT: matrice cifrata N=1..8 su tre chiavi

Data run: 2026-09-02T04:54Z circa, conclusione 2026-09-02T04:56:14Z.

Questo e' il primo stadio, poi superseduto dalla
[matrice semantica N=1..8/64/127/128](exact_id_manylut_semantics_2026-09-02.md).

## Esito

**PASS: 144/144** esecuzioni del core condiviso hanno restituito lo stesso codice exact-ID
dell'oracolo clear e lo stesso conteggio PBS della formula A29.

La matrice contiene:

- gallerie `N=1..8`;
- tre coppie di chiavi fresche per ogni dimensione (`24` keygen indipendenti);
- sei semantiche per coppia chiave/dimensione: soglia della scena, vincitore strict con template
  piu' lontani permissivi, vincitore permissivo, vincitore spostato all'ultimo indice, per `N >= 2`
  pareggio al primo indice con il secondo permissivo e tutte le soglie sotto dominio;
- una nuova cifratura GLWE dual-layout del probe per ogni esecuzione.

Il summary del processo e':

```text
SUMMARY,all_correct=true,all_under_10s=true,time_gate_enforced=false,same_core=true,no_distance_output=true
```

`all_under_10s` e' soltanto un'osservazione del run: il gate temporale era disabilitato con
`--allow-slow` e questa non e' una misura isolata di performance.

## Comando

```bash
RAYON_NUM_THREADS=16 cargo run --release \
  --manifest-path experiments/14_pipeline_tfhe_rs/Cargo.toml \
  --bin argmin_bucket_bits_periodic -- \
  --run --keys 3 --cases all --real-probes 1 \
  --sizes 1,2,3,4,5,6,7,8 --allow-slow
```

## Conteggi osservati

Ogni riga `RESULT` controlla `actual_code == expected_code` e
`pbs_count == expected_pbs`. I casi a soglia pubblica costante o interamente fuori dominio
saltano LUT di soglia che diventano pubblicamente costanti; i casi strict/tie possono quindi
avere un conteggio maggiore senza cambiare circuito privato.

| N | righe | PBS osservati nei sei casi | tutti i codici corretti | tutti i conteggi esatti |
|---:|---:|---:|---:|---:|
| 1 | 18 | 48 | 18/18 | 18/18 |
| 2 | 18 | 95 | 18/18 | 18/18 |
| 3 | 18 | 128--129 | 18/18 | 18/18 |
| 4 | 18 | 162--165 | 18/18 | 18/18 |
| 5 | 18 | 220--223 | 18/18 | 18/18 |
| 6 | 18 | 253--262 | 18/18 | 18/18 |
| 7 | 18 | 287--296 | 18/18 | 18/18 |
| 8 | 18 | 323--332 | 18/18 | 18/18 |

Sono stati osservati esplicitamente sia codice `0`, sia identificazioni intermedie, sia il codice
massimo `N` nei casi `last_winner_permissive`. Il caso
Per `N >= 2`, `first_tie_strict_later_permissive` ha sempre restituito `0`: conferma che il primo
minimo e la sua soglia governano l'esito, senza aprire per il duplicato piu' permissivo. A `N=1`
lo stesso nome indica soltanto il caso degenere con soglia strict, senza un duplicato.

## Provenienza

Ambiente osservato dopo il run: Apple arm64, macOS 27.0 build 26A5421a, 16 CPU logiche,
`rustc 1.97.1`, `cargo 1.97.1`, tfhe-rs 0.11.3 e parametro
`V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`.

SHA-256:

- core `src/private_argmin.rs`:
  `06b62cb44f372fbf44e33b9a541a3609e49657f1201f4e319cdab3b0da1e37e4`;
- harness `src/bin/argmin_bucket_bits_periodic.rs`:
  `6f081eee994f0c6629e66a50bb58ae080ea80d2f141aab143b381a59ff671963`;
- binario release eseguito:
  `57fd91c22c2e4792fc3bd2cbde20457b56cb6ff48f601fa38485639644170ed4`.

## Limiti e gate successivo

Questo primo stadio copre il vero core cifrato ma non misura direttamente le due fasi correlate
dell'uscita ManyLUT e non sale oltre N=8. I gate N=64/127/128 e split4/mixed-scale sono documentati
negli artifact successivi; restano separati la suite primaria 632, l'E2E Docker e un bound formale
del `p-fail`.
