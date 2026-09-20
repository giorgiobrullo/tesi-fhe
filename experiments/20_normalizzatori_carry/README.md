# 20 - Normalizzatori derivati dal riporto e composizione classica

Una rotazione che produce il riporto può fornire anche la cifra bassa tramite
una trasformazione lineare dell'intero ciphertext. Questo esperimento valuta
il componente, il rumore osservato e la sua integrazione nella query completa.

## Metodo e risultati

Il confronto isolato del carry misura **12,39% di riduzione**, 24/24 coppie
favorevoli su una chiave. Lo sweep copre 4096 valori, quattro modalità e tre
chiavi: **49.152 estrazioni e 384 selezioni**. I limiti derivati dai vettori
di errore osservati sono condizionali, non probabilità globali di fallimento.

La conferma dei comparatori classici paralleli dà **6,51%**, 56/56 coppie su
due nuove chiavi. La composizione di carry, confronto parallelo e soglie
pubbliche dà **19,24% nella seconda famiglia**, 28/28 coppie; lo screening
precedente distinto dà 20,82%. Entrambi i riferimenti avevano già i tagli ID.
Il carry è incorporato nella composizione: i guadagni non si sommano.

Le mappe fuse sono circa **0,14% più lente** e il batch classico del selettore
circa **0,34% più lento** nei rispettivi screening. Un primo controllo della
LUT è risultato troppo restrittivo per una rappresentazione equivalente;
la sua correzione è distinta dalle modifiche al circuito.

| Dati | Contenuto |
|---|---|
| [Risultati](RESULTS.json) | Confronti e limiti |
| [Tempi del normalizzatore](evidence/normalizer-timing.json) | Confronto isolato |
| [Sweep su tre chiavi](evidence/THREE_FAMILY_RESULT.json) | Correttezza e rumore osservato |
| [Conferma classica](evidence/classic-confirmation.json) | Confronto del parallelismo |
| [Composizione](evidence/night-composition.json) | Risultato della combinazione |
| [Mappe di errore](evidence/NORMALIZER_ERROR_MAPS.md) | Trasformazioni lineari e limiti condizionali |

Le misure conservano carico esterno e un numero limitato di chiavi. Una
mappa esatta dei coefficienti non dimostra indipendenza degli errori né
una probabilità di fallimento per il circuito composto.

## Sorgenti e compilazione

| Workspace | Funzione |
|---|---|
| [carry-packed](sources/carry-packed/Cargo.toml) | Circuito completo e confronto dei tempi |
| [carry-sweep](sources/carry-sweep/Cargo.toml) | Sweep esteso |
| [carry-gate](sources/carry-gate/Cargo.toml) | Controllo della LUT effettiva |
| [composite-classic](sources/composite-classic/Cargo.toml) | Composizione del normalizzatore e del parallelismo |

Servono Rust e le dipendenze del lockfile, fra cui TFHE-rs 1.7.0.
Da questa cartella, per compilare il circuito completo:

```sh
cargo build --release --locked --manifest-path sources/carry-packed/Cargo.toml \
  --target-dir .local/target-carry
```

La [demo 22](../22_demo_composita/README.md) integra questa linea di lavoro
con le successive ottimizzazioni.

## Provenienza

[Provenienza e impronte dei file](PROVENANCE.json) distingue i byte pubblicati
dai documenti storici e dalle copie redatte. I digest degli esperimenti
identificano le esecuzioni originali; questa pubblicazione non aggiunge
una nuova compilazione nativa o una nuova prova FHE.
