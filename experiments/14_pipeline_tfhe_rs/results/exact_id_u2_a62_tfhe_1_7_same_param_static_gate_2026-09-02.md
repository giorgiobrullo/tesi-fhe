# U2 static gate: A62 su TFHE-rs 1.7, stesso parametro

Data: 2026-09-02.

## Esito

`PASS_STATIC_TFHE_1_7_PORT_NOT_COMPILED_NOT_FHE_VALIDATED`.

U2 porta l'attuale circuito A62 da TFHE-rs 0.11.3 a 1.7.0 mantenendo il preset
`V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64`, il contratto exact open-set
`0/first-ID`, i due output p16 e il ledger N=127 `3390/3009/3930`. Questo gate non autorizza
claim di correttezza FHE o performance: il crate non e' ancora stato type-checked o compilato.

## Controlli passati

- TFHE-rs pin esatto 1.7.0 e `dyn-stack` 0.13.2 nel lockfile offline;
- target Cargo isolato `target-u2-tfhe-1_7`;
- adapter `AtomicPatternServerKey::Standard` e BSK `Classic` 1.7;
- modulus switch `Standard` applicato esplicitamente prima dei blind rotate manuali;
- protocol ID/fingerprint 1.7 fail-closed e distinto da 0.11.3;
- 18/18 input di provenienza congelati;
- 512 fixture clear per N=1..128, inclusi reject, ultimo ID e tie-first;
- conteggi strutturali A62 identici per N=1..128;
- 9/9 test Python, Ruff e rustfmt passati;
- nessun target compilato, chiave o ciphertext nella directory U2.

La generazione del lockfile e' stata eseguita offline; non e' una compilazione. Il prossimo gate,
da eseguire senza benchmark FHE concorrenti, e' `cargo check --locked --offline`, seguito da
micro-fixture con chiavi fresche prima di qualunque benchmark.

## Hash dello snapshot statico

```text
53677c9a8331dcc064a5604037703433f7e20742b80bce9535d8c652cf3b49eb  README.md
a3e951c5883261dc25227776e490f6f9ae621f6f40af32b43a2cc7b37077c39e  Cargo.toml
14394c6aacc61f5c867feb8757857d10e67c5ced1d8523e7a670137c502a4c2f  Cargo.lock
2292ed6b11204cb9aec6f00b292b0d7f33cc989337e9bb8a0ed439f9fe1d638b  .cargo/config.toml
c47935904fb51bb1f6a928937e6fda79a3f7c5a9c602372dc18cc5fc720f8721  a62_static_audit.py
4709af9c9f675410404f085659cf7726a0c683af2739a9b65416dd974dcef62d  tests/test_a62_static.py
4561a4d3a134ba603cef0b458a686e33cc251435c8c2e33b75e0410f8687010c  src/private_argmin.rs
24afeac53d99abeaba9ef3ff245d6f97f74114e76a35f3a438ced8960a2fbf3d  src/a53_scan.rs
a4dfbc7cd15bdc65ee699847b46147a0614bceccbdeb5317226103f7ffa68f9e  src/a53_scan/fhe.rs
a86db24d3d15806bf263cbe99a7ed5d56949bd517515f6a43dc89afde466dac3  src/bin/a62_a53_a44_integrated_prototype.rs
```

Percorsi relativi a `tmp/u2-a62-tfhe-1_7-same-param-port/`.
