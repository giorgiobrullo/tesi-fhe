# 18 - Scaling, tre cifre ID e soglie miste

Questo esperimento estende Head/PFKS a taglie diverse, tre cifre ID e soglie
associate ai singoli template. Il contratto sceglie prima il primo minimo,
poi verifica soltanto la sua soglia inclusiva: se non passa restituisce 0.
Un candidato più lontano o un pari successivo non lo sostituisce perché
ha una soglia più permissiva.

## Varianti

| Variante | Dominio e API |
|---|---|
| [Scaling](source/fast-core-scaling-20260906/core/README.md) | N1..224, due cifre ID, soglia uniforme con dominio allineato |
| [Soglie uniformi generali](source/fast-core-uniform-20260906/core/README.md) | N1..224, soglia uniforme e rami pubblici di accettazione/rifiuto |
| [Tre cifre ID](source/fast-core-wide-id-20260906/core/README.md) | Capacità rappresentativa N1..3374, soglie uniformi |
| [Soglie miste](source/fast-core-mixed-20260906/core/README.md) | Tre cifre ID e soglia del solo vincitore |

Il [controllo A126 a tre cifre](source/fast-core-wide-id-20260906/older-control/README.md)
è un adattamento esplicito, distinto dall'A126 invariato fino a N128.
Le varianti M usano input nativi full51/low60; A126 e R3 usano full52/low60.
Le risposte a tre cifre si ricostruiscono come `low + 15*middle + 225*high`.

## Risultati e limiti

La campagna di scaling usa tre chiavi e 17 taglie fino a N224. Alle 15 taglie
condivise fino a N128, M riduce il tempo del **25,60–50,97%** rispetto ad A126
invariato. A N127 le mediane M/A126 sono **3,031/6,115 secondi**.
Campagna e controllo preliminare producono 1272 uscite corrette e 12
uguaglianze seriale/parallelo; R3 è un controllo separato.

Il pilot più largo confronta M3 con A126_3 a N224/225/256/512/1024 su una
nuova chiave: due coppie di riscaldamento escluse e quattro misurate per
taglia. Tutte le **20/20 coppie** favoriscono M3, con riduzioni geometriche
appaiate del **50,45–52,44%**. A N1024 le mediane sono **23,451/49,062 secondi**;
passano 60 uscite complete. Non c'è un intervallo tra chiavi per questo pilot.

I controlli di correttezza per soglie generali, ID larghi e soglie miste
sono separati e usano tre chiavi. Le soglie estreme includono scorciatoie
pubbliche. Capacità 3374, casi FHE del core fino a 1024 e controlli HTTP
fino a 225 sono evidenze diverse. I tempi conservano carico esterno e non
misurano ogni configurazione di soglie, la latenza web o una probabilità
formale di errore. [Dati e risultati](RESULTS.json).

## Compilazione

Ogni variante ha un runner in `candidate/Cargo.toml` e una libreria in `core/`.
Servono Rust e le dipendenze del lockfile, fra cui TFHE-rs 1.7.0. Per la
variante a soglie miste, da questa cartella:

```sh
cargo build --release --locked \
  --manifest-path source/fast-core-mixed-20260906/candidate/Cargo.toml \
  --target-dir .local/target-mixed
```

Le API e i test mirati sono descritti nei documenti delle varianti.
Per il servizio integrato partire dalla [demo 22](../22_demo_composita/README.md).

## Provenienza

[Provenienza e impronte dei file](PROVENANCE.json) distingue i byte pubblicati
dai documenti storici e dalle copie redatte. I digest degli esperimenti
identificano le esecuzioni originali; questa pubblicazione non aggiunge
una nuova compilazione nativa o una nuova prova FHE.
