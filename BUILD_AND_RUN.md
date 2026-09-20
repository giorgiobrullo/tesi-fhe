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

## Modificare il progetto

Il circuito e i suoi test sono in `runtime/core/`; il servizio Rust è in
`runtime/candidate/`, il client Python in `runtime/client/` e le interfacce
in `demo/dual_view/`. Le cartelle `experiments/` conservano le versioni usate
nei confronti storici: per sviluppare la demo corrente partire dal runtime.

Dopo una modifica sotto `runtime/`, dalla radice:

```sh
.venv/bin/python -B runtime/configure.py --refresh
.venv/bin/python -B runtime/configure.py --check
cargo build --release --locked \
  --manifest-path runtime/Cargo.toml --bin varco_demo_composite_v9 \
  --target-dir target-selector-pack4
```

Il manifesto include anche test, commenti e README del runtime. Cambiare
questi file cambia l'identità accettata da client e servizio e richiede
nuove chiavi in una directory distinta. I file di configurazione generati
vanno aggiornati con `--refresh`. Le modifiche esterne a `runtime/` non
richiedono questa rigenerazione.

Tenere build, chiavi e risultati fuori da `runtime/`, per esempio in
`target-selector-pack4/` e `.local/`. Eseguire i
[test pertinenti](docs/riproducibilita.md#eseguire-i-test-della-demo) alla
modifica; se cambia il circuito, verificarlo anche con cifrati reali prima
di confrontarne le prestazioni.

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
