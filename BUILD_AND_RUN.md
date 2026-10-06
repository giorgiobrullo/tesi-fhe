# Compilare il motore Rust

Le due demo usano Python 3.12 e Rust/Cargo 1.98.1. Per l'ambiente Python,
i modelli e l'avvio, scegliere la guida della [pagina unica](demo/web/README.md)
o delle [due pagine client/server](demo/dual_view/README.md).
La piattaforma delle misure è macOS ARM64 su Apple M4 Max.

I comandi correnti usano la patch 1.98.1, che corregge un
[difetto nella generazione delle vtable](https://blog.rust-lang.org/2026/09/03/Rust-1.98.1/).
Le misure archiviate conservano il compilatore 1.98.0 indicato nei rapporti.
Il controllo del 2 ottobre ha ricompilato il runtime con 1.98.1 e verificato
i test e casi FHE; non ha misurato un cambiamento di velocità.

## Compilazione

Eseguire i comandi dalla radice del repository, dopo aver preparato l'ambiente
e installato il toolchain con `rustup toolchain install 1.98.1 --profile minimal`.

Gli esempi usano `.venv/bin/python`, l'ambiente completo del progetto
descritto nella guida delle due pagine. Se si usa l'ambiente dedicato della
demo web, sostituirlo con `.local/venv-web/bin/python` nei comandi Python
di questa pagina. I comandi Rust sono gli stessi per entrambe le demo.

```sh
.venv/bin/python -B runtime/configure.py --check
rustup run 1.98.1 cargo build --release --locked \
  --manifest-path runtime/Cargo.toml --bin varco_demo_composite_v9 \
  --target-dir target-selector-pack4
```

Il binario è `target-selector-pack4/release/varco_demo_composite_v9`.
Il profilo release usa opt3/CGU1. Aggiungere `--offline` se tutte le dipendenze
Rust sono già in cache.
`rustup run` seleziona esplicitamente la versione 1.98.1 senza cambiare
il compilatore predefinito del computer.

## Modificare il progetto

Il circuito e i suoi test sono in `runtime/core/`; il servizio Rust è in
`runtime/candidate/`, il client Python in `runtime/client/` e le interfacce
in `demo/web/` e `demo/dual_view/`. Le cartelle `experiments/` conservano le
versioni usate nei confronti storici: per sviluppare la demo corrente partire
dal runtime.

Dopo una modifica sotto `runtime/`, dalla radice:

```sh
.venv/bin/python -B runtime/configure.py --refresh
.venv/bin/python -B runtime/configure.py --check
rustup run 1.98.1 cargo build --release --locked \
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

Le guide della [pagina unica](demo/web/README.md#avvio-locale) e delle
[due pagine](demo/dual_view/README.md#avvio-locale) usano questo binario
per generare le chiavi e avviare il servizio. Occorre una coppia generata per
l’identità del runtime usato. Se questa identità cambia, ricompilare il
binario e generare una nuova coppia in una directory distinta. Agli avvii
successivi con lo stesso runtime riutilizzare le chiavi già preparate.

Per i test e il dettaglio delle misure vedere la
[guida alla riproducibilità](docs/riproducibilita.md) e i
[rapporti sperimentali](docs/validazione/README.md).
