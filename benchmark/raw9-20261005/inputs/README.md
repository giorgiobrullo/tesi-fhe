# Input e ambiente della campagna

Il driver `raw_threshold_fullquery.rs` legge a compilazione quattro JSON in `core/fixtures/`: `gallery.json`, `einstein.json`, `curie.json` e `turing.json`. Contengono i vettori della galleria N120/D512 e delle tre query, con soglia 273. Non sono copiati in questo pacchetto. [INPUT_PINS.json](INPUT_PINS.json) conserva dimensioni, SHA-256 e percorsi originali dal manifest congelato, senza leggere o ripubblicare i vettori.

Per ricostruire la stessa prova servono quei quattro input autorizzati con hash identici, collocati nei percorsi indicati dopo aver materializzato i sorgenti. La galleria e le query originarie appartengono a `tmp/m4-thread-scaling-20260921/fixtures` nell'archivio locale. In assenza di quei byte, la ricetta descrive la campagna ma non ne consente una replica identica.

Il driver costruisce altri tre controlli senza modificare le fixture originali: query dalla voce 83; query zero; query Einstein contro una copia della galleria con la voce 65 uguale alla prima. [DERIVED_CASES.json](DERIVED_CASES.json) conserva la trasformazione e gli esiti scalari preregistrati. Il driver ricomputa l'oracolo e l'ammissione del dominio prima della generazione delle chiavi.

Ambiente osservato: Rust 1.98.1, TFHE-rs 1.8.1 fissato da Cargo.lock, release opt-level 3, LTO disabilitato, una codegen unit; feature `opt-owned-pfks,opt-lut-cache`, RUSTFLAGS vuoto, `VARCO_PROFILE_PHASES` assente. Il driver fissa 16 thread e piano FFT Dif4 prima delle chiavi. La [ricevuta di build](../provenance/BUILD_CAPTURE.json) conserva comando, ambiente e fine della compilazione originaria; i percorsi assoluti si riferiscono a quell'ambiente e vanno ricollocati per una nuova prova. Le dipendenze Cargo devono essere disponibili localmente per il comando offline.

Le chiavi fresche e i cinque input cifrati erano generati in memoria. Non sono archiviati nel pacchetto. `analysis/ANALYZE.original.py` conserva il programma originario per le statistiche pubbliche, con percorsi locali originali: non è un comando portabile già adattato.
