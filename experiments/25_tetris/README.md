# 25 - Tetris: consumatore corretto, produttore più lento

Il prototipo studia un'accelerazione Tetris includendo il costo necessario
per produrre il controllo cifrato consumato dalla primitiva. Il produttore
ibrido esegue sei circuit bootstrap freschi.

## Risultati e limiti

Il componente e il consumatore superano i controlli con rumore: **54 uscite
complete e 2091 verifiche LWE** nel percorso accelerato. Il produttore è però
**66,401451% più lento** nel pilot, con zero vittorie su 18 coppie,
una famiglia di chiavi e tre scene. Le medie geometriche sono
**23,688078 contro 14,235500 ms**.

La misura comprende la conversione del produttore; non è la latenza della
query completa. Il risultato negativo riguarda questa costruzione e non
ogni possibile variante Tetris. Il prototipo è escluso dalla demo selezionata.
[Dati del produttore](evidence/producer-timing.json) e [riepilogo](RESULTS.json).

Un [primo controllo aritmetico fallito](failed-first/RESULT.json), con
[sorgente](failed-first/tetris.rs), rileva al nibble 5/prefix bit 3 un valore
3 invece di −1. Quel tentativo non esegue FHE e resta distinto dalle prove
successive del consumatore e dai tempi del produttore.

## Codice e compilazione

Il [runtime](runtime/Cargo.toml) include il core, il piano di timing e
l'accelerazione split-FFT con [licenza RevHomTrace](runtime/LICENSE-RevHomTrace).
Servono Rust e le dipendenze TFHE-rs 1.7.0 del lockfile. Da questa cartella:

```sh
cargo build --release --locked --manifest-path runtime/Cargo.toml \
  --target-dir .local/target-tetris
```

La [demo 22](../22_demo_composita/README.md) usa la variante selezionata senza Tetris.

## Provenienza

[Provenienza e impronte dei file](PROVENANCE.json) distingue i byte pubblicati
dai documenti storici e dalle copie redatte. I digest degli esperimenti
identificano le esecuzioni originali; questa pubblicazione non aggiunge
una nuova compilazione nativa o una nuova prova FHE.
