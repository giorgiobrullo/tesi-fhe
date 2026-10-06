# SOURCE_READY_SOURCE_ONLY — controllo pubblico FCMA

La sorgente è pronta per la review e il build del root; l'autore non ha compilato o eseguito il programma. Questa copia usa solo operandi sintetici pubblici. Non contiene FFT, chiavi, FHE, letture di payload o modifiche al runtime mantenuto.

## Confine aritmetico conservato

`probe/src/main.rs:15–100` conserva il corpo `Update`, il controllo delle dimensioni e i due wrapper di Z: output e lhs hanno 2.048 complessi, suddivisi in due blocchi da 1.024; la stessa rhs di 1.024 complessi si applica a entrambi. Ogni wrapper riceve un token della factory checked, resta `no_mangle`/`inline(never)` e usa il booleano First per scegliere `mul_c64s` oppure `mul_add_c64s`. Non c'è tail SIMD: entrambe le specializzazioni hanno una lane complessa e le lunghezze sono esatte.

Il confine riproduce TFHE-rs1.8.1 `src/core_crypto/fft_impl/fft64/crypto/ggsw.rs:647–674`. Pulp0.22.3 `src/aarch64.rs:1099–1114` usa per il First NEON un prodotto e una FMA per componente; `1024–1039` usa due FMA ordinate per il MAC. FCMA `2069–2073` applica le rotazioni 0 poi90 e `2102–2103` costruisce il First dal MAC con accumulatore zero. L'ordine differente è intenzionale: uguaglianza bit per bit tra i backend non è il criterio di correttezza.

## Ingresso, ambiente e dump

Solo `--validate` e `--bench` sono accettati. Le factory checked vengono chiamate prima dell'aritmetica. `main.rs:108–124` legge FPCR con `mrs`, senza modificarlo; rifiuta RMode22/23, FZ24, FIZ0 e AH1. I controlli successivi richiedono anche lo stesso valore intero completo. Questa ammissione è per i calcoli FP64 del helper, non un'attestazione dell'immagine del servizio.

La validazione (`181–209`) genera quattro casi deterministici, sempre con due lhs2048 e due rhs1024:

1. `case=0`: piccoli dyadici esatti, inclusi gli zeri;
2. `case=1`: mantisse/signi da xorshift pubblico con esponenti biased1015…1031, tutti normali e limitati;
3. `case=2`: stessi rhs nei due termini e secondo lhs uguale al negativo del primo, per cancellazione;
4. `case=3`: lhs subnormali, inclusi valori prossimi al minimo, con rhs normali scelti tra ±0,5/±1/±2.

Gli ingressi e tutte le uscite sono verificati finiti. Per ciascun backend, il First viene copiato solo per il dump; il MAC modifica il suo stesso output reale, senza sostituire o ricostruire il prefisso. Sono emesse esattamente 8.192 righe con `case` intero0…3 e `index` intero0…2047. Rhs è riportata all'indice `index % 1024`.

NDJSON:

- header: `kind="header"`, `schema="fcma_public_validate_v1"`, `fpcr` intero, `pulp_source_sha256`, factory flags `neon_available`/`fcma_available`, casi4/elementi2048;
- sample: `kind="sample"`, `case`, `index` e gli otto campi `a0`, `a1`, `b0`, `b1`, `neon_first`, `neon_final`, `fcma_first`, `fcma_final`, ciascuno `[real_hex16,imag_hex16]`, stringhe esadecimali minuscole da `f64::to_bits()`;
- complete: `kind="complete"`, `status="VALIDATION_DUMP_COMPLETE"`, `cases=4`, `rows=8192`, `fpcr` finale intero.

La completion indica un dump completo, non un PASS numerico. L'oracolo indipendente controlla ogni stadio rispetto al grafo del backend usando l'ACTUAL First. L'equivalenza del segno degli zeri è una qualifica dell'oracolo. Errore I/O, factory indisponibile, ambiente non ammesso/cambiato o nonfinito termina senza completion valida e senza retry.

## Timing separato

`main.rs:222–261` usa gli stessi operandi normali pubblici del caso1 e buffer separati preallocati per backend. Prima dei timer esegue 64 coppie First+MAC per ciascun backend. Seguono otto blocchi di quattro batch: N,F,F,N nei blocchi pari e F,N,N,F in quelli dispari. Ogni batch contiene esattamente 1.000 coppie First+MAC, con gli stessi wrapper e confini di slice.

La scelta del backend, le factory, gli ingressi, le allocazioni e il warmup sono fuori dai timer. Le due branche hanno gli stessi `black_box` su output, ingressi e booleani; non c'è dispatch per iterazione. Ogni coppia ricomincia con First. Finito il timer, un checksum visita tutti i bit dei 2.048 output complessi e rifiuta output nonfiniti; lettura FPCR e scrittura JSON sono anch'esse fuori dal timer.

Header `schema="fcma_public_bench_v1"`, `cases=1`, `dataset_case=1`, `warmup_pairs=64`; ciascuna delle32 righe ha `kind="batch"`, `block`, `position`, `backend="neon"|"fcma"`, `repetitions=1000`, `elapsed_ns` intero e `checksum` hex16. Il header di validazione mantiene `cases=4` e `dataset_case=null`. Completion: `status="BENCH_COMPLETE"`, `batches=32`, FPCR finale. La policy «bench solo dopo oraclePASS» è applicata dal launcher del root; il helper non può attestare un receipt esterno. Il risultato sarà specifico di host e hot buffer, senza implicazione automatica per FHE o latenza della demo.

## Identità direttamente lette

- `probe/src/main.rs`: SHA256 `7ef97bf24cae04b14407cb56f89a43cf770b2a28105a5caadc8f1458c0970f65`, 298 righe; sorgente pronta, build/codegen ancora da verificare.
- `probe/Cargo.toml`: SHA256 `3010be99def04ec4257692c353bc82505179cf1b390064089820683208bfb075`; package invariato `current-fcma-codegen-probe`, pulp=0.22.3/std, releaseopt3/cgu1/LTOoff.
- `probe/Cargo.lock`: SHA256 `d091029dccf1939dbb573d3a658f273bacd53b88ea0c95d83f296c5bd13dd729`; non modificato dall'autore.
- `/opt/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/pulp-0.22.3/src/aarch64.rs`: SHA256 `428f60728d89512826a40714a4d63bf299d848430e5e1579a49d69f0fb505f29`; letti narrow ranges162–172,1024–1039,1099–1114,2069–2073,2102–2103.
- `/opt/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-1.8.1/src/core_crypto/fft_impl/fft64/crypto/ggsw.rs`: SHA256 `d2cf985c055b55627ce1e9714e404862a71e6aec7c8b459293c9bcbb67a1d956`; letto647–677 per il solo confine pointwise.

Non è una prova completa dell'errore floating point, del rumore, della storia delle chiavi o del contratto0/ID. Queste obbligazioni restano aperte e la baseline rimane invariata.
