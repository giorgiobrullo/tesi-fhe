# Compilare e avviare la baseline pack4

La baseline locale del 20 settembre conserva il selettore corretto e usa
packing fino a quattro cifre. Il [rapporto pack4](PACK4_VALIDATION.md) distingue
correttezza osservata, tempi, servizio e limiti. La cartella `runtime/` è
congelata: documentazione e ricevute successive stanno fuori dai suoi sorgenti.

## Compilazione

Ambiente delle prove: macOS ARM64, Apple M4 Max, Rust/Cargo 1.98.0,
TFHE-rs 1.7.0 e Python 3.12. Il profilo release è opt3/CGU1, senza LTO,
PGO o feature opzionali. Dalla radice di questa consegna `Tesi-FHE`:

```sh
.venv/bin/python -B runtime/configure.py --check
cargo build --release --locked --offline \
  --manifest-path runtime/Cargo.toml --bin varco_demo_composite_v9 \
  --target-dir target-selector-pack4
```

Il comando offline richiede le dipendenze Rust già in cache. L'ambiente Python
e i modelli si preparano secondo la [guida della demo](demo/dual_view/README.md).
La ricompilazione deve conservare compilatore, lock e opzioni se si vogliono
confrontare i tempi. I benchmark locali non qualificano altre piattaforme.

## Chiavi e demo

Usare il binario `target-selector-pack4/release/varco_demo_composite_v9`
nei comandi keygen e del launcher descritti nella guida della demo.
Le chiavi wire hanno una nuova identità di circuito. Generarle in una directory
nuova: non sovrascrivere né convertire implicitamente chiavi delle revisioni
precedenti. La funzione PFKS interna è la stessa della prima correzione B;
questo non rende compatibili i vecchi envelope del servizio. La PFKS W287
precedente alla correzione resta incompatibile.

Il server gestisce galleria e soglie; il client cifra la query e decifra
soltanto l'esito. Il contratto resta primo minimo, primo ID in caso di parità,
soglia inclusiva del vincitore e risposta cifrata 0/ID.

## Prove attestate

83 test del core, 36 del servizio e 32 controlli Python passano nella revisione
selezionata; quattro test FHE storici sono ignorati dalla suite ordinaria.
La campagna separata verifica 432 chiamate e la prova del servizio tre
roundtrip CLI/HTTP con risultati 1/0/0. Un vecchio envelope viene rifiutato
senza modificare lo stato. Non sono nuove prove della fotocamera o di
accuratezza biometrica. La guida alle altre verifiche è in
[docs/riproducibilita.md](docs/riproducibilita.md).
