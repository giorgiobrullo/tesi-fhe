# Prima prova della LUT binaria

Otto casi corretti, inclusi entrambi i pareggi. È il solo primitivo basso
con cifre fresche: non qualifica il confronto completo o la demo.
Il [rapporto](../../docs/validazione/COMPARATORE_BINARIO_20261004.md)
spiega il passaggio modificato e i limiti.

- `samples.csv`: gli otto casi, senza tempi.
- `rows.jsonl`: dieci record originali, incluse metadata e conclusione.
- `SUMMARY.json`: configurazione, esito e impronte.
- `PROTOCOL.md`, `Cargo.toml`, `Cargo.lock`, `src/main.rs`: helper e protocollo usati.
- `RESULT_REVIEW.md`: verifica indipendente dell'esito.
- `GEOMETRY.md`, `CONTRACT.md`, `HEAD55_PLAN.md`: logica e audit delle interfacce.
  Il piano Head55 non è stato implementato o eseguito.
- `HEAD_PLAN_REVIEW.md`: revisione del piano precedente; la versione corrente
  esplicita i due callback/LUT e la correzione mean-only richiesta.

Chiavi soltanto nell'archivio locale, trattate come file opachi per il digest.
La famiglia è nuova e diversa da quella del ternario respinto: nessun
confronto appaiato fra i due esiti. `SOURCE_BUILD.json` conserva i nomi
originali `probe/...`; gli stessi file sono qui senza quel prefisso.
Il protocollo alla radice locale era il piano di preparazione, distinto
da quello dell'helper.

## Ricostruzione autonoma

Dalla radice del repository, con Rust1.98.1 e dipendenze disponibili:

```sh
SCRATCH_BUILD_RUSTC="$(rustup run 1.98.1 rustc -Vv)" \
  rustup run 1.98.1 cargo build --release --locked \
  --manifest-path benchmark/binary-comparator-20261004/Cargo.toml \
  --target-dir .local/binary-comparator-target
RAYON_NUM_THREADS=16 .local/binary-comparator-target/release/current_binary_comparator_20261004 \
  .local/binary-comparator-new-run
```

Il genitore `.local` deve esistere e la directory del risultato deve essere
nuova. Eseguire isolatamente. Il helper genera una sola famiglia ordinaria:
nuove esecuzioni possono dare risultati diversi; non ripetere per scegliere
una chiave favorevole. Exit0 significa otto casi superati, exit2 il primo
errore della candidata, exit1 un errore del riferimento. Nessuno qualifica
la probabilità di errore, la pipeline completa o un guadagno di tempo.
