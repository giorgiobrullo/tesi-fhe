# 21 - Selettore parallelo, cifre pubbliche, G4 e attraversamento PFKS

Qui si evita di selezionare cifre già note e si eseguono in parallelo
operazioni indipendenti del selettore. L'[esempio con due candidati](../../docs/come-funziona-il-confronto.md)
mostra perché bisogna trasferire insieme score, ID e soglia del vincitore.

Quattro interventi vengono confrontati separatamente con riferimenti già
dotati di normalizzatore condiviso, confronto classico parallelo, soglie
pubbliche e tagli ID, cioè l'omissione delle cifre alte sicuramente nulle.
Le percentuali misurano gli interventi aggiuntivi su quei riferimenti.

## Passaggio modificato

Score cifrati → estrazione delle cifre → torneo (**confronto → selezione
dei dati del vincitore**) → controllo della soglia → esito cifrato 0/ID.

Si interviene sul selettore che, dopo ogni confronto, porta avanti score,
ID e soglia del vincitore. Il riferimento aveva già normalizzatori condivisi,
confronti paralleli, tagli delle cifre ID e scorciatoie per soglie pubbliche.
La PFKS (*private functional key switching*) prepara ciascuna cifra in un
formato cifrato raggruppabile. Una rotazione controllata dalla decisione
cifrata seleziona poi i dati di ogni gruppo. I thread permettono di eseguire
più preparazioni o rotazioni indipendenti contemporaneamente.

## Prima e dopo

| Intervento | Prima | Dopo |
|---|---|---|
| Cifre pubbliche | I tagli già presenti riducono la larghezza degli ID. Le cifre residue vengono selezionate anche quando sono uguali per tutti i possibili vincitori di un ramo. | Un piano segue le costanti ramo per ramo, conserva direttamente le cifre note e prepara solo quelle ancora dipendenti dalla scelta. |
| Selettore parallelo | Torneo e comparatori sono già paralleli; dentro un singolo selettore, preparazioni PFKS e rotazioni dei gruppi vengono eseguite in sequenza. | Quando restano da una a quattro coppie, anche le preparazioni e le rotazioni indipendenti del selettore usano il pool di thread esistente. |

Il primo intervento riduce il lavoro necessario; il secondo distribuisce
lo stesso lavoro su più thread. Il livello successivo del torneo aspetta
comunque il completamento del precedente. Il confronto per ciascun
intervento è distinto: le percentuali non si sommano.

### Esempio delle cifre pubbliche

Con una galleria di 128 persone, consideriamo gli ID 1 e 2 con la stessa
soglia. Gli ID sono `[1, 0, 0]` e `[2, 0, 0]` in base 15, dalla cifra bassa
alla più alta. La terza cifra
era già eliminata dal taglio ID precedente. Anche lo zero intermedio
è comune ai due possibili vincitori: il nuovo piano riconosce questa
costante durante il torneo.

| Selezione di quel nodo | Prima | Dopo |
|---|---|---|
| Cifre preparate con PFKS | Tre di score e due di ID: cinque. | Tre di score e una di ID: quattro. |
| Gruppi da selezionare | Un gruppo score e uno ID. | Ancora due gruppi: score e cifra ID variabile. |

In questo esempio si risparmia una PFKS, non una rotazione di gruppo.
Il raggruppamento successivo a quattro cifre è un [intervento distinto](../../docs/validazione/PACK4_VALIDATION.md).
Il vincitore resta cifrato: la costante viene riconosciuta dai dati pubblici
prima di sapere quale candidato vincerà. Lo stesso principio vale per
cifre comuni di soglie diverse; le soglie interamente comuni erano già
trattate dal riferimento.

La composizione adottata è `public_parallel`. G4 resta un esperimento
separato, escluso dalla composizione finale; l'attraversamento PFKS condiviso
ha esito negativo nello screening. Le misure sotto riguardano i riferimenti
storici TFHE-rs 1.7.0. Il [README del runtime](../../runtime/README.md)
riporta invece la configurazione mantenuta.

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
