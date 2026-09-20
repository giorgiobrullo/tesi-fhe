# Regressione intermedia degli estremi dell'output exact-ID bitwise (superata)

> **Storico: hardening 1/3, non circuito corrente.** Questo run seguiva il refresh dell'encoding
> dell'ID ma precedeva sia il refresh della selezione cifrata della soglia sia il comparatore
> Booleano finale. Le suite ampie successive hanno trovato rifiuti spuri in entrambi quegli stadi.
> I quattro casi qui sotto restano una diagnosi valida della sola ricostruzione dell'ID. Lo stato
> canonico e' in `../../README.md` e `../../status.md`; la cronologia tecnica e' in
> `exact_id_noise_hardening_2026-09-01.md`.

Data: 1 settembre 2026. Host: Apple M4 Max, 16 thread Rayon. Libreria: tfhe-rs 0.11.3,
parameter set `V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`.

## Scopo

Il circuito post-fix ricostruisce il codice `1..=N` bit per bit e restituisce ancora un solo LWE;
`0` rimane il rifiuto. Questa regressione esercita:

- il codice `127`, che richiede tutti i sette bit usati a `N=127`;
- il codice `128`, che richiede l'ottavo bit e la capacita' massima del core;
- l'uscita tutta zero a entrambe le dimensioni;
- la formula PBS aggiornata dopo la sostituzione della somma di `N` ciphertext con al massimo otto
  componenti fresche.

`--allow-slow` disabilita soltanto il gate prestazionale storico sotto 10 secondi; non modifica il
circuito, l'oracolo o il gate di correttezza.

## Risultati

| N | caso | codice atteso | codice osservato | PBS attesi/osservati | tempo core |
|---:|---|---:|---:|---:|---:|
| 127 | soglia strict del vincitore, altri permissivi | 0 | 0 | 4.862 / 4.862 | 11,838339 s |
| 127 | vincitore spostato nell'ultimo template | 127 | 127 | 4.862 / 4.862 | 10,721774 s |
| 128 | soglia strict del vincitore, altri permissivi | 0 | 0 | 4.892 / 4.892 | 10,612958 s |
| 128 | vincitore spostato nell'ultimo template | 128 | 128 | 4.892 / 4.892 | 11,054975 s |

Tutti i quattro risultati coincidono con l'oracolo clear. I tempi sono riportati per trasparenza,
ma il run e' una regressione funzionale eseguita durante altre attivita' e non un benchmark
prestazionale controllato.

## Binding del sorgente eseguito

| artefatto | SHA-256 |
|---|---|
| `src/private_argmin.rs` | `676e274829c5d3ec99076d1922faf7c8ca8dd1b27f96fbdd9c28f06f7ec68687` |
| `src/bin/argmin_bucket_bits_periodic.rs` | `6013701391a3a98109e253cc911f82b9079df57b9cadc5f4683c053b782583f8` |
| binario release | `a0c32d5e89c754181b611dbb2a6eaba09ef80cc5bddd560a1b90877b9b0860ea` |
| `Cargo.toml` | `bdd7e63b67fbcd7a6326248bed09daf33e30f95a7873b44fff37b591261a634a` |
| `Cargo.lock` | `1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a` |

Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)` e Cargo 1.97.1.

## Limite

Il run dimostra l'aritmetica dell'encoding e la correttezza cifrata nei quattro casi eseguiti. Non
deriva la probabilita' di fallimento composta: la riduzione OR, i PBS custom e la somma finale a
`Delta=2^55` restano fuori dal bound nominale della primitiva standard.

I risultati si riferiscono alla revisione e agli input identificati in questo report.
Il clone non include il binario e tutti gli input del run storico; eseguire gli
script sul codice corrente non replica automaticamente queste misure.
