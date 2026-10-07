# Microcosto pubblico del buffer BR

Questo helper misura la gestione di memoria pubblica, senza chiavi,
ciphertext o valutazione FHE. Il [rapporto](../../docs/validazione/SCRATCH_BR_20261004.md)
spiega i risultati e la decisione di priorità.

- TFHE-rs 1.8.1, Rayon 1.12.0; Rust 1.98.1/Homebrew, aarch64-apple-darwin.
- M4 Max; pool separati da 1 e 16 worker, carico desktop non controllato.
- `blind_rotate_assign_mem_optimized_requirement::<u64>`: GLWE size 2,
  polynomial size 2048, FFT Dif4/base1024 installato prima di creare Fft.
- 163.967 byte non allineati richiesti dall'API. Riuso privato per worker,
  preallocazione e first touch fuori da tutti i timer.
- 256 cicli warmup per worker/ramo, senza tempi; quattro blocchi misurati
  da 8.192 cicli per worker/ramo, ordini AB/BA/AB/BA. Nessun campione escluso.
- Fresh costruisce, dimensiona/azzera e distrugge un buffer per ciclo.
  Reuse fa il resize alla stessa lunghezza. Stessa osservazione della slice
  e due letture agli estremi; nessun calcolo BR o scrittura equivalente.
- Worker wall dopo la barriera; batch wall prima del dispatch e dopo il join.
  Mediana dei quattro blocchi delle mediane worker. Batch/total-cycle è
  inverso del throughput aggregato, non latenza individuale.

`raw.jsonl` contiene 1 metadata + 4 warmup + 16 misure, con tutti i tempi
dei worker. `samples.csv` riassume i 20 blocchi e mantiene vuoti i tempi
warmup. `SUMMARY.json` conserva statistiche, compilatore effettivo, hash
dei sorgenti, binario e record originali. I conteggi di costruzione/drop
sono logici; non misurano tutte le allocazioni del processo.

Il [sorgente](src/main.rs), [manifest](Cargo.toml) e [lock](Cargo.lock)
sono inclusi. La build originale ha usato `cargo build --release --locked
--offline`, con l'identità di `rustc -Vv` nella variabile di compilazione
`SCRATCH_BUILD_RUSTC`. Il binario viene poi eseguito senza argomenti.
Una nuova build richiede le dipendenze disponibili; non riproduce per
questo i tempi del desktop originale.

Nessun rapporto di speedup FHE, limite di risparmio, prova di rumore o
moltiplicazione per il numero di BR segue da questa esecuzione.
