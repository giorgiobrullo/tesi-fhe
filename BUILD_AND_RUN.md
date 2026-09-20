# Compilare il motore Rust

La demo usa Python 3.12 e Rust/Cargo 1.98.0. Per l'ambiente Python, i modelli
e l'avvio delle interfacce, seguire la [guida della demo](demo/dual_view/README.md).
La piattaforma delle misure è macOS ARM64 su Apple M4 Max.

## Compilazione

Dalla radice del repository, dopo aver preparato l'ambiente:

```sh
.venv/bin/python -B runtime/configure.py --check
cargo build --release --locked \
  --manifest-path runtime/Cargo.toml --bin varco_demo_composite_v9 \
  --target-dir target-selector-pack4
```

Il binario è `target-selector-pack4/release/varco_demo_composite_v9`.
Il profilo release usa opt3/CGU1. Aggiungere `--offline` se tutte le dipendenze
Rust sono già in cache.

## Chiavi e avvio

La [guida della demo](demo/dual_view/README.md#avvio-locale) usa questo binario
per generare le chiavi e avviare il servizio. Occorre una coppia generata per
l’identità del runtime attuale. Dopo questo aggiornamento ricompilare il
binario e generare una nuova coppia: le chiavi del pacchetto precedente
non sono compatibili. Generarla in una directory nuova e riutilizzarla agli
avvii successivi.

Per i test e il dettaglio delle misure vedere la
[guida alla riproducibilità](docs/riproducibilita.md) e i
[rapporti sperimentali](docs/validazione/README.md).
