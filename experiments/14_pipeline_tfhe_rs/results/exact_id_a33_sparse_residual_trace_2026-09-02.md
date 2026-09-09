# A33: accumulatore sparso multi-output sul residuo rumoroso A29 — 2026-09-02

## Esito

**PASS** nel perimetro del micro-harness: zero mismatch su tre keypair freschi.

| controllo | corretti | totali |
|---|---:|---:|
| residuo `h'=x'>>9` dopo le correzioni `b0..b8` | 54 | 54 |
| simboli `r` e flag signed dei due accumulatori custom | 216 | 216 |
| canonicalizzatore `p=16`, coppie ordinate `h'_L,h'_R in 0..7` | 192 | 192 |

Il test attraversa per ogni chiave i 18 valori
`256, 511, 512, 1022, 1023, 1024, 1025, 1535, 1536, 2047, 2048, 2559, 2560,
3071, 3072, 3348, 3584, 3839`. Copre quindi tutti gli stati del dominio a 12 bit
`h'=0..7`, entrambi i lati delle transizioni e, esplicitamente, la frontiera di accettazione
allineata `1023/1024`.

## Percorso realmente esercitato

Per ogni caso viene cifrato un nuovo probe GLWE con plaintext nullo. La galleria ha un template
non nullo con sedici coordinate uguali a uno (`norm2=16`), quindi il prodotto cifrato-per-chiaro
propaga il rumore reale del canale score; il punteggio clear e' `16`. Il dominio pubblico di
larghezza 4096 viene traslato per fare assumere allo score la coordinata `x'` voluta. Tutti i
domini coprono il bound Cauchy del template: l'intervallo necessario e' `[-240,272]`, mentre gli
estremi testati producono rispettivamente `[-240,3855]` e `[-3823,272]`.

Il harness chiama `private_argmin_with_trace` del core A29 e ricostruisce direttamente

```text
residual = trace.score_full[0]
           - sum(trace.full_corrections_lsb_first[0][0..=8])
```

La decifratura diagnostica del residuo avviene client-side per misurarne l'errore, ma non modifica
ne' sostituisce il ciphertext: il classificatore riceve lo stesso oggetto cifrato, senza un
percorso decrypt->reencrypt o refresh client. Ogni residuo alimenta due varianti di un accumulatore
raw/custom `p=8`; una blind rotation per variante viene campionata ai gradi `0` e `256` per
ottenere rispettivamente `r` e il flag signed di peso `1` o `3`. Non viene chiamata l'API stock
`ManyLookupTable` di TFHE-rs. Per ciascuna chiave viene poi scelto un ciphertext rappresentante per
ogni stato `h'=0..7` e vengono provate tutte le 64 coppie ordinate col canonicalizzatore `p=16`.

Le chiavi segrete sono esistite soltanto in memoria nel processo locale. Il test non ha scritto
chiavi o ciphertext su disco.

## Rumore osservato

Gli errori sono distanze signed dal plaintext atteso, espresse in unita' della scala dello stadio.

| misura aggregata sulle tre chiavi | massimo assoluto | margine minimo al mezzo passo |
|---|---:|---:|
| residuo, scala `2^61=q/8` | 0.001802 | 0.498198 |
| uscita `r`, scala `2^59=q/32` | 0.002971 | n/a |
| flag signed, scala `2^59=q/32` | 0.002724 | n/a |
| input sommato del canonicalizzatore, scala `2^59=q/32` | 0.004240 | 0.495760 |
| uscita Booleana del canonicalizzatore, scala `2^59=q/32` | 0.002705 | n/a |

Il mezzo passo e' il confine di rounding pertinente: `0.5*2^61` per le caselle `p=8` del residuo
e `0.5*2^59` per gli input `p=16`. Questi margini sono osservazioni sui campioni eseguiti, non
bound analitici.

## Tempi del run

| stadio | secondi aggregati |
|---|---:|
| generazione delle tre coppie di chiavi | 0.979796 |
| 54 esecuzioni complete del core A29 a `N=1` | 27.593636 |
| 108 blind rotation del classificatore | 1.486696 |
| 192 PBS del canonicalizzatore di coppia | 2.625710 |
| processo completo | 32.701762 |

Per chiave, i tempi del core/classificatore/canonicalizzatore sono stati rispettivamente
`9.172250/0.494923/0.875157`, `9.189247/0.494199/0.878219` e
`9.232139/0.497575/0.872334` secondi. Sono misure di un micro-harness locale, non un benchmark
isolato di latenza del servizio.

## Riproducibilita'

Comando del run:

```bash
cargo run --release --features diagnostic-trace --bin a33_sparse_residual_trace
```

Verifiche successive alla sola formattazione del sorgente:

```bash
cargo check --release --features diagnostic-trace --bin a33_sparse_residual_trace
cargo clippy --release --features diagnostic-trace --bin a33_sparse_residual_trace -- -D warnings
cargo test --release --features diagnostic-trace --bin a33_sparse_residual_trace
```

Tutte PASS. Il target non contiene unit test separati (`0` test); l'evidenza FHE e' l'esecuzione
assertiva sopra, che termina con `total_mismatches=0`.

Provenienza:

- Rust `1.97.1`, Cargo `1.97.1`;
- parameter set `V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`;
- `src/bin/a33_sparse_residual_trace.rs` SHA-256
  `1b03d510ae8c560bb4f9df58f13ac31b8a71e35e55775132cb4c0bdcd4efc281`;
- binario eseguito `target/release/a33_sparse_residual_trace` SHA-256
  `a2e49f21f367c3797eb7d4bdf61e005b06a119a40a42718c396fe6309c3d0af7`;
- `src/private_argmin.rs` SHA-256
  `06b62cb44f372fbf44e33b9a541a3609e49657f1201f4e319cdab3b0da1e37e4`;
- `Cargo.lock` SHA-256
  `1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a`;
- transcript stdout SHA-256
  `4d0663a5289609ad5bc5bcd3e376a7e1cc5409ec4beac29c9d2ca6dbbb952980`.

Il transcript stdout completo del run e' preservato in
[`exact_id_a33_sparse_residual_trace_2026-09-02.txt`](exact_id_a33_sparse_residual_trace_2026-09-02.txt)
e ne registra configurazione, tutti i 54 casi, i riepiloghi per chiave e il riepilogo globale.

## Limiti

- Tre chiavi, 54 ciphertext e un'unica forma template/probe non provano una probabilita' di
  fallimento ne' coprono la distribuzione biometrica.
- Le 64 coppie per chiave sono esaustive sugli stati plaintext `h'=0..7`, ma usano
  un solo ciphertext rappresentante per stato: non sono il prodotto cartesiano di tutti i 18
  campioni rumorosi.
- Le due sample extraction della stessa GLWE ruotata sono correlate. Il test non assume
  indipendenza tra `r` e flag e non autorizza a moltiplicare probabilita' marginali.
- Il trace e la decifratura degli intermedi sono esclusivamente diagnostici e client-side. Il
  percorso di produzione continua a non esporre il residuo o i flag.
- Questa evidenza valida il micro-percorso `residuo -> classificatore -> canonicalizzatore`; non
  implementa il fast path A31/A33 completo, non ne verifica candidati, tie-break, output ID o
  latenza end-to-end e non costituisce ancora una promozione del design.
