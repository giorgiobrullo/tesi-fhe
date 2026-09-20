# 21 - Selettore parallelo, cifre pubbliche, G4 e attraversamento PFKS

Quattro interventi vengono confrontati separatamente con riferimenti già
dotati di normalizzatore condiviso, confronto classico parallelo, soglie
pubbliche e tagli ID. Le percentuali misurano gli interventi aggiuntivi su
quei riferimenti.

## Risultati

| Prototipo | Esito | Coppie favorevoli |
|---|---:|---:|
| Selettore parallelo | 3,642326% di riduzione, due famiglie di conferma | 44/56 |
| Propagazione delle cifre pubbliche | 4,087594% di riduzione, due famiglie di conferma | 46/56 |
| G4 composto | 2,323432% di riduzione, due famiglie di conferma | 45/56 |
| Attraversamento PFKS condiviso | 0,991443% più lento nello screening | 11/28 |

Gli screening iniziali sono esclusi dalle conferme dei primi tre interventi.
Il risultato negativo PFKS non attiva ulteriori famiglie di conferma.
Le perdite per scena e gli indicatori di carico restano parte del risultato.
**Gli effetti non si sommano:** nella successiva combinazione G4 è più lento
della migliore variante pubblica/parallela ed è escluso dalla [demo 22](../22_demo_composita/README.md).
Questo non invalida il risultato contro il precedente riferimento diverso.

[Dati riepilogativi](RESULTS.json) e risultati dei quattro confronti:
[selettore](evidence/selector-confirmation.json),
[cifre pubbliche](evidence/public-digits-confirmation.json),
[G4](evidence/g4-confirmation.json), [PFKS](evidence/pfks-negative.json).
Correttezza dei casi provati, velocità e probabilità formale di errore
restano affermazioni distinte.

## Sorgenti e compilazione

I workspace sono [selector-parallel](sources/selector-parallel/Cargo.toml),
[public-digits](sources/public-digits/Cargo.toml),
[g4-composite](sources/g4-composite/Cargo.toml) e
[pfks-stream](sources/pfks-stream/Cargo.toml). Ogni directory comprende il core,
i file incorporati e il lockfile, con dipendenza TFHE-rs 1.7.0.
Da questa cartella, per esempio:

```sh
cargo build --release --locked \
  --manifest-path sources/selector-parallel/Cargo.toml \
  --target-dir .local/target-selector
```

Per confrontare le varianti usare compilazioni separate e lo stesso piano
di input e misure; per l'applicazione integrata partire dal pacchetto 22.

## Provenienza

[Provenienza e impronte dei file](PROVENANCE.json) distingue i byte pubblicati
dai documenti storici e dalle copie redatte. I digest degli esperimenti
identificano le esecuzioni originali; questa pubblicazione non aggiunge
una nuova compilazione nativa o una nuova prova FHE.
