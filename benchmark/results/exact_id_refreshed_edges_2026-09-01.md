# Regressione degli estremi exact-ID dopo il doppio refresh

> **Storico: hardening 2/3, non circuito corrente.** Questo run includeva la ricostruzione bitwise
> dell'ID e la masked OR reduction della soglia, ma usava ancora il comparatore ternario pesato.
> Il terzo run ampio ha poi osservato due falsi rifiuti lontani dalla soglia. I quattro casi restano
> evidenza della revisione intermedia a 5.128/5.158 PBS. Lo stato canonico e' in `../../README.md`
> e `../../status.md`; la cronologia tecnica e' in
> `exact_id_noise_hardening_2026-09-01.md`.

Data: 1 settembre 2026. Host: Apple M4 Max, 16 thread Rayon. Libreria: tfhe-rs 0.11.3,
parameter set `V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`.

## Circuito provato

Il circuito intermedio qui provato applicava due hardening senza cambiare il contratto applicativo:

1. ricostruisce `indice+1` bit per bit, evitando la vecchia somma di N output PBS;
2. seleziona i 12 bit della soglia del vincitore e i due sentinel mediante masked OR reduction
   con refresh, evitando le somme lineari di indicatori cifrati.

Il server continua a restituire un solo LWE: `0=rifiuto`, `i+1=identita' accettata`.

Comando:

```sh
RAYON_NUM_THREADS=16 target/release/argmin_bucket_bits_periodic \
  --run --keys 1 --sizes 127,128 --cases edges --real-probes 1 --allow-slow
```

`--allow-slow` disabilita soltanto il gate prestazionale storico sotto 10 secondi; non modifica il
circuito, l'oracolo o il gate di correttezza.

## Risultati

| N | caso | codice atteso | codice osservato | PBS attesi/osservati | tempo core |
|---:|---|---:|---:|---:|---:|
| 127 | soglia strict del vincitore, altri permissivi | 0 | 0 | 5.128 / 5.128 | 10,843056 s |
| 127 | vincitore spostato nell'ultimo template | 127 | 127 | 5.128 / 5.128 | 11,972580 s |
| 128 | soglia strict del vincitore, altri permissivi | 0 | 0 | 5.158 / 5.158 | 11,106249 s |
| 128 | vincitore spostato nell'ultimo template | 128 | 128 | 5.158 / 5.158 | 9,812619 s |

Tutti i quattro risultati coincidono con l'oracolo clear. I tempi sono riportati per trasparenza,
ma il run e' una regressione funzionale eseguita durante altre attivita' e non un benchmark
prestazionale controllato.

## Binding del sorgente eseguito

| artefatto | SHA-256 |
|---|---|
| `src/private_argmin.rs` | `f27f9fcb41aa464186624caf3dd81665ac076a79b131122edaab9b89945ab494` |
| `src/bin/argmin_bucket_bits_periodic.rs` | `6013701391a3a98109e253cc911f82b9079df57b9cadc5f4683c053b782583f8` |
| binario release | `d5d1a2972e232ca6898913c402874fc21b6e31587b6226f3249505f766c51ca1` |
| `Cargo.toml` | `bdd7e63b67fbcd7a6326248bed09daf33e30f95a7873b44fff37b591261a634a` |
| `Cargo.lock` | `1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a` |

Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)` e Cargo 1.97.1.

## Limite

Il run dimostra l'aritmetica dell'encoding, i sentinel di soglia e la correttezza cifrata nei
quattro casi eseguiti. Non deriva la probabilita' di fallimento composta: i fan-in custom, i
riscalamenti e la somma finale a `Delta=2^55` non sono certificati dal `log2_p_fail` nominale della
primitiva standard.
