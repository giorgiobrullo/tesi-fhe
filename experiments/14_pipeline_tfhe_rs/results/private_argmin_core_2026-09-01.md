# Core `private_argmin`: verifica riuso, soglie per-template e N dispari

> **Storico: baseline precedente ai tre hardening del rumore.** API, dominio esatto, tie-first e
> semantica delle soglie per-template restano riferimenti utili, ma smoke, conteggi PBS e tempi qui
> sotto appartengono al primo circuito integrato. Non vanno presentati come evidenza del core
> corrente. Lo stato canonico e' in `../../../README.md` e `../../../status.md`; la cronologia
> tecnica degli hardening e' in
> `../../../benchmark/results/exact_id_noise_hardening_2026-09-01.md`.

Data: 2026-09-01  
Macchina: Apple M4 Max (`Mac16,9`, arm64)  
Thread Rayon: 16  
Parametri: `V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`  
Baseline Git: `6611c18`; sorgenti sperimentali non ancora committati.

## Contratto verificato

Il percorso TFHE esatto e' definito una sola volta in `src/private_argmin.rs`. Il binario
`src/bin/argmin_bucket_bits_periodic.rs` e' un harness sottile che cifra il probe, chiama quel core
e decifra esclusivamente il codice finale.

API:

```rust
pub fn private_argmin(
    server_key: &ServerKey,
    packed_probe: &GlweCiphertextOwned<u64>,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<PrivateArgminOutput, PrivateArgminError>
```

Output: un solo big-LWE, `0` per rifiuto oppure `indice+1` per match; nessuna distanza. La soglia
`T_i` viene selezionata cifratamente soltanto dopo il primo argmin, quindi la soglia permissiva di
un'identita' piu' lontana non puo' accettare il vincitore. Il primo indice vince i pareggi.

Il dominio esatto usa il bound di Cauchy calcolato con sola aritmetica intera checked. Il contratto
richiede che il client validi prima della cifratura coordinate del probe in `[-3,3]` e
`||q||^2 <= 1024`: il server non puo' verificare in chiaro questa proprieta' del probe cifrato.

## Verifiche statiche

```text
cargo fmt -- src/lib.rs src/private_argmin.rs src/bin/argmin_bucket_bits_periodic.rs
cargo test --lib
test result: ok. 7 passed; 0 failed

cargo test --bin argmin_bucket_bits_periodic
test result: ok. 0 passed; 0 failed

cargo clippy --lib --bin argmin_bucket_bits_periodic -- -D warnings
Finished `dev` profile; nessun warning
```

I sette test coprono: ceil-sqrt intera, derivazione/overflow del dominio, coordinate e norme
template, tie-first e soglie per-template, tutte le righe delle LUT threshold, tutte le LUT
booleane pesate e conteggi PBS deterministici inclusi N=1 e coda dispari.

## Smoke cifrati sullo stesso core

Comandi:

```text
RAYON_NUM_THREADS=16 cargo run --release --bin argmin_bucket_bits_periodic -- \
  --run --keys 1 --sizes 1,3 --cases all --real-probes 1

RAYON_NUM_THREADS=16 target/release/argmin_bucket_bits_periodic \
  --run --keys 1 --sizes 64 --cases all --real-probes 1

RAYON_NUM_THREADS=16 cargo run --release --bin argmin_bucket_bits_periodic -- \
  --run --keys 1 --sizes 3 --cases tie --real-probes 1

RAYON_NUM_THREADS=16 target/release/argmin_bucket_bits_periodic \
  --run --keys 1 --sizes 127 --cases tie --real-probes 1
```

| N | caso | atteso | ottenuto | PBS attesi/ottenuti | tempo core |
|---:|---|---:|---:|---:|---:|
| 1 | soglia scena | 0 | 0 | 53 / 53 | 0.743 s |
| 1 | winner strict, altri permissivi | 0 | 0 | 53 / 53 | 0.750 s |
| 1 | winner permissivo | 1 | 1 | 53 / 53 | 0.739 s |
| 3 | soglia scena | 0 | 0 | 143 / 143 | 0.987 s |
| 3 | winner strict, altri permissivi | 0 | 0 | 143 / 143 | 1.053 s |
| 3 | winner permissivo | 3 | 3 | 143 / 143 | 0.990 s |
| 3 | due minimi uguali: primo strict, secondo permissivo | 0 | 0 | 143 / 143 | 1.008 s |
| 64 | soglia scena | 0 | 0 | 2,483 / 2,483 | 4.594 s |
| 64 | winner strict, altri permissivi | 0 | 0 | 2,483 / 2,483 | 4.497 s |
| 64 | winner permissivo | 39 | 39 | 2,483 / 2,483 | 4.460 s |
| 127 | due minimi uguali: primo strict, secondo permissivo | 0 | 0 | 4,919 / 4,919 | 8.010 s |

Tutti gli output e i conteggi PBS coincidono con l'oracolo clear. Ogni query e' sotto 10 s,
inclusa N=127 che esercita la coda dispari a scala piena. Il setup delle LUT e' ora esposto
separatamente nelle metriche (0.1--0.7 ms in questi run) ed e' incluso nel tempo totale.

Questi sono smoke di integrazione con chiavi fresche per dimensione, non una stima statistica del
tasso di fallimento crittografico. Lo stress precedente della rappresentazione esatta e dei bit e'
documentato in `argmin_bucket_bits_exact_norm12_2026-09-01.md` e
`score_mod16_lowbits_2026-09-01.md`.
