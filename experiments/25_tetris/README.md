# 25 - Tetris: consumatore corretto, produttore più lento

Il prototipo prova Tetris nel confronto fra due candidati del torneo.
Riceve le tre cifre cifrate di ciascuno score e produce il controllo cifrato
che indica quale candidato conservare. Il selettore successivo usa quel
controllo per trasferire i dati del vincitore. L'[esempio del confronto](../../docs/come-funziona-il-confronto.md)
mostra la distinzione fra decidere il vincitore e conservarne i dati.

## Passaggio modificato

Cifre dei due score → **produzione del controllo di confronto** →
selezione dei dati del vincitore → prosecuzione del torneo.

Qui il *produttore* è il circuito che costruisce il controllo; il
*consumatore* è il selettore che lo usa. La domanda è se il percorso Tetris
riduca il costo del produttore includendo tutte le conversioni richieste.

## Prima e dopo

| Operazione | Prima: confronto classico parallelo | Prototipo Tetris |
|---|---|---|
| Confrontare le tre coppie di cifre | Tre PBS, valutazioni di funzioni su dati cifrati, producono gli esiti minore/uguale/maggiore. | Ogni cifra viene convertita in prefissi binari cifrati nel formato Tetris, poi si ricavano gli stessi esiti di confronto. |
| Costruire il controllo | Gli esiti delle tre cifre sono combinati secondo la loro significatività. | La stessa combinazione produce il controllo atteso dal selettore. |
| Selezionare il vincitore | Il selettore PFKS usa il controllo per trasferire score e ID. | Si verifica che il selettore funzioni anche con il controllo prodotto da Tetris. |

Il produttore ibrido esegue sei circuit bootstrap freschi, uno per ciascuna
cifra dei due score. Il *circuit bootstrap* realizza la conversione al
formato cifrato richiesto da Tetris; il suo costo non può essere omesso.
Il [produttore temporizzato](runtime/src/main.rs) include conversioni,
allocazioni e parallelismo; la misura esclude il selettore PFKS successivo.

I controlli del componente e del selettore passano, ma il produttore
completo di conversioni è più lento del riferimento. Per questo la
costruzione viene esclusa dalla demo; l'esito non esclude altre integrazioni
possibili di Tetris.

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
