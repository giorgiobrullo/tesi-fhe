# Verifica indipendente del microcosto scratch

PASS della verifica aritmetica e del protocollo sui soli record pubblici. Nessuna nuova esecuzione, compilazione o lettura di chiavi/ciphertext.

`raw.jsonl` contiene 21 record: una metadata, quattro warmup senza tempi e 16 misure. Per ciascuna configurazione (1/16 worker): warmup fresh/reuse di 256 cicli per worker, poi quattro blocchi AB/BA/AB/BA di 8192 cicli per arm/worker. Totali: 8704 cicli warmup e 1114112 misurati. Ogni batch contiene esattamente gli indici privati 0..workers−1; tutti i checksum endpoint sono zero. Durate misurate positive; batch ≥ massimo dei loop worker, con margine minimo 7833 ns. Tutti i quozienti registrati corrispondono ai tempi interi divisi per i rispettivi conteggi.

La colonna worker usa la mediana dei worker in ciascun blocco, poi la mediana dei quattro blocchi. La colonna batch divide il wall del batch per tutti i cicli, poi prende la mediana dei quattro blocchi: è throughput, non latenza individuale. Nessuna somma dei tempi worker.

| Worker | Arm | Worker ns/ciclo | Range dei quattro blocchi | Batch ns/ciclo totale |
|---:|---|---:|---:|---:|
| 1 | fresh | 913,373 | 831,675–1198,980 | 915,103 |
| 1 | reuse | 1,933 | 1,740–2,630 | 3,530 |
| 16 | fresh | 20713,890 | 20350,006–20994,731 | 1308,344 |
| 16 | reuse | 2,098 | 1,981–2,373 | 2,291 |

La richiesta scratch effettiva è 163967 byte non allineati, dato pubblico della configurazione u64/GLWE2/N2048/Dif4 di TFHE-rs 1.8.1. I conteggi logici costruzione/drop sono tutti i cicli in fresh e zero in reuse; resize compare in entrambi, con stessa dimensione e quindi no-op in reuse. Non sono una traccia delle chiamate dell'allocatore.

Identità verificate direttamente: raw SHA256 `1c56e591c7277c1ab4a5451b59f5a15ca6e50353b52e562d812a44c0bb62c1d7`; binario `9bfd6edbd4ed73f006f2248ed56a9f0a587951697720cff15f4e4582f0cc5b38`, coerente fra build/RUN e file; SOURCE_BUILD e quattro sorgenti congelate coerenti con i digest. Metadata e ricevute concordano su Rust 1.98.1, release opt3/CGU1/LTO off. Build e run exit0; zero chiavi e query FHE dichiarate.

Quattro blocchi della stessa esecuzione non stabiliscono generalità o risparmio FHE. Questi tempi non sono un upper bound BR né una previsione del tempo della query; non vanno moltiplicati per il numero di BR.
