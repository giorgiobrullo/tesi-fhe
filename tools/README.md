# Wrapper del linker per Concrete su macOS

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
