# Primo controllo del comparatore a due cifre

La proposta viene scartata dopo sei casi: il ramo con correzione restituisce
un pareggio per 255 contro 0. Il riferimento sulle singole cifre passa.
Il [rapporto](../../docs/validazione/COMPARATORE_COMPRESSO_20261004.md)
spiega il passaggio modificato e i limiti del risultato.

- `samples.csv`: sei casi eseguiti, senza tempi.
- `rows.jsonl`: otto record originali, incluse metadata e conclusione.
- `SUMMARY.json`: esito, impronte, configurazione e casi non eseguiti.
- `PROTOCOL.md`, `Cargo.toml`, `Cargo.lock`, `src/main.rs`: protocollo e helper usato.
- `RESULT_REVIEW.md`: verifica indipendente dei record e delle identità.
- `GEOMETRY.md`, `INGRESS.md`, `MS_REDUCTION.md`: analisi su carta e della sorgente;
  non sono prove di correttezza cifrata né proposte già integrate.

Le chiavi e i cifrati del primo fallimento restano nell'archivio locale:
qui sono incluse soltanto le loro impronte e dimensioni.
`SOURCE_BUILD.json` conserva i nomi originali `probe/...`; gli stessi file
sono distribuiti qui senza quel prefisso. Il `PROTOCOL.md` alla radice
locale era il piano di preparazione, distinto da quello dell'helper.

## Ricostruzione autonoma

Dalla radice del repository, con Rust 1.98.1 e le dipendenze disponibili:

```sh
SCRATCH_BUILD_RUSTC="$(rustup run 1.98.1 rustc -Vv)" \
  rustup run 1.98.1 cargo build --release --locked \
  --manifest-path benchmark/comparator-encoding-20261004/Cargo.toml \
  --target-dir .local/comparator-encoding-target
RAYON_NUM_THREADS=16 .local/comparator-encoding-target/release/current_comparator_encoding_20261004 \
  .local/comparator-encoding-new-run
```

Il genitore `.local` deve esistere; la directory di risultato deve essere
nuova. Eseguire isolatamente. Il programma genera una nuova famiglia senza
sceglierla in base al risultato: una nuova esecuzione può fallire in un
caso diverso o completare il massimo previsto. Non ripetere per selezionare
un esito favorevole. Exit 2 è il rifiuto scientifico previsto del candidato;
exit 1 segnala un errore del riferimento. Nessun codice di uscita stabilisce
una probabilità di fallimento o qualifica la pipeline completa.
