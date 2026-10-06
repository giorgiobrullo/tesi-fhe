# Strumenti della repository

## Ricostruire un tentativo A

[restore_attempt.py](restore_attempt.py) ricostruisce l'albero dei sorgenti
di un tentativo dai file inclusi, verificandone prima le impronte e riusando
le copie condivise. Non compila né esegue l'esperimento.
La [guida dei materiali A](../experiments/attempts-a/README.md) descrive
selezione, input e risultati disponibili.

```sh
python3 tools/restore_attempt.py --list
python3 tools/restore_attempt.py --id A108 --check
mkdir -p .local
python3 tools/restore_attempt.py --id A108 --output .local/a108-source
```

La cartella genitore deve esistere, la destinazione deve essere nuova.
Per i soli test del ricostruttore, con fixture temporanee:

```sh
python3 -B -m unittest discover -s tools -p 'test_restore_attempt.py'
```

## Ricostruire una campagna di benchmark

[materialize_sources.py](materialize_sources.py) verifica la mappa dei
sorgenti contenuta nel `PROVENANCE.json` della campagna e ricrea il suo
albero in una directory nuova esterna alla repository. I file condivisi vengono copiati dalla
posizione canonica verificata, senza duplicarli nei pacchetti distribuiti.

```sh
python3 tools/materialize_sources.py --map benchmark/raw9-20261005/PROVENANCE.json --dry-run
python3 tools/materialize_sources.py --map benchmark/raw9-20261005/PROVENANCE.json --output ../raw9-source
```

La verifica non compila né esegue la campagna. Il manifesto conserva anche
origini, trasformazioni e impronte dei risultati; la ricostruzione riguarda
i percorsi descritti in `source_layout`. Toolchain, input esterni e comandi
di esecuzione sono specificati nel README della campagna.

Il pacchetto biometrico Georgia Tech registra le dipendenze del programma,
senza un layout completo di ricostruzione. Accetta `--dry-run` per verificare
quelle dipendenze e rifiuta `--output`.
I test del materializzatore usano esclusivamente fixture temporanee:

```sh
python3 -B -m unittest discover -s tools -p 'test_materialize_sources.py'
```

## Wrapper del linker per Concrete su macOS

Se Concrete-python termina con `ld: library 'System' not found`, controllare
se il percorso SDK passato al linker esiste. Il wrapper `tools/ldfix/ld`
sostituisce il riferimento a
`/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib` con il percorso
restituito da `xcrun --show-sdk-path`, poi richiama il linker di sistema.

Per usarlo, eseguire dalla radice del repository:

```sh
PATH="$PWD/tools/ldfix:$PATH" uv run python benchmark/breakdown_query.py
```

La modifica al PATH vale soltanto per quel comando. Il wrapper è specifico
a questo errore di individuazione dell'SDK; non è necessario per la normale
compilazione Rust quando il toolchain trova già le librerie di sistema.
