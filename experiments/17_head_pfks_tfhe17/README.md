# 17 - Head/PFKS exact 0/ID su TFHE-rs 1.7

Questo esperimento combina Head, correzione media pubblica e selezione PFKS
per calcolare il primo minimo e applicare la soglia inclusiva del vincitore.
La variante M usa cinque payload, split 3+2 e PFKS 22 × 1. A N127 restituisce
l'identità del primo minimo se accettato, altrimenti 0, in due cifre cifrate
base 15. I pareggi favoriscono il primo ID.

## Metodo e risultati

Il confronto M/H/R3 usa una famiglia di chiavi nuova, due terne di
riscaldamento escluse e sei terne misurate con tutti gli ordini possibili.
Le mediane M/H/R3 sono **3,048836 / 3,071472 / 4,615544 secondi**.
La mediana della riduzione entro coppia per M è **0,7963% rispetto a H**
e **34,0848% rispetto a R3**, con 6/6 coppie favorevoli in entrambi i casi.

La verifica aritmetica distinta copre tre chiavi. Il servizio N127 supera
separatamente 15 uscite cifrate e 39 controlli negativi, con sei nuove
cifrature della query sotto una nuova famiglia. Il [riepilogo numerico](RESULTS.json)
separa questi controlli dal confronto dei tempi.

Split, base e correzione media cambiano insieme: il contributo dei singoli
interventi non è isolato. Le riduzioni entro coppia non sono rapporti delle
mediane e non si sommano agli esperimenti successivi. Il confronto usa input
full51 adattati per R3; non equivale al suo servizio con input nativi full52.
Le prove non stabiliscono la probabilità globale di fallimento del circuito.

## Codice e compilazione

La [libreria Rust](source/wrapup-head-service-20260906/core/src/lib.rs) espone
il core; il [servizio](source/wrapup-head-service-20260906/candidate/Cargo.toml)
lo integra. Il controllo A126 è in una cartella sorella richiesta dai path
Cargo. Il core M richiede input nativi full51/low60; le codifiche non si
cambiano rinominando o dimezzando ciphertext già prodotti.

Con Rust e le dipendenze TFHE-rs 1.7.0 del lockfile, da questa cartella:

```sh
cargo build --release --locked \
  --manifest-path source/wrapup-head-service-20260906/candidate/Cargo.toml \
  --target-dir .local/target-service
```

La generalizzazione a taglie e soglie diverse è nell'[esperimento 18](../18_scaling_soglie_miste/README.md).
Per l'applicazione client/server usare la [demo 22](../22_demo_composita/README.md).

## Provenienza

[Provenienza e impronte dei file](PROVENANCE.json) distingue i byte pubblicati
dai documenti storici e dalle copie redatte. I digest degli esperimenti
identificano le esecuzioni originali; questa pubblicazione non aggiunge
una nuova compilazione nativa o una nuova prova FHE.
