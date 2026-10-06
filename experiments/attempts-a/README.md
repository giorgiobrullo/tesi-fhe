# Materiali dei tentativi A

[Mappa degli esperimenti](../README.md) · [Catalogo con esiti e seguito](../../docs/risultati/catalogo-tentativi-a.md)

Questa cartella conserva i programmi e i risultati dei tentativi censiti nel
catalogo. Comprende anche esiti negativi, prime versioni corrette in seguito
e proposte mai eseguite. La storia e l'interpretazione restano nel catalogo;
qui si trovano i materiali per controllarle.

| Materiale | Copertura | Provenienza |
|---|---|---|
| Programmi e manifest di compilazione | 1.080 percorsi, 149 sigle A | [SOURCE_MAP.json](SOURCE_MAP.json) |
| Supporti, licenze e input pubblici | 20 supporti e 42 input | Stessa mappa dei sorgenti |
| Risultati salvati | 631 riferimenti, 111 sigle A: JSON, CSV e riepiloghi terminali | [RESULTS_MAP.json](RESULTS_MAP.json) |
| Rapporti e proposte | Tutte le 187 sigle del censimento | [Catalogo](../../docs/risultati/catalogo-tentativi-a.md) e [fonti puntuali](../../docs/evidence/repo-coverage-20261005/tentativi-a-inventory.json) |

Le mappe verificano i byte delle copie distribuite. I percorsi personali
sono normalizzati come descritto nella [guida alla provenienza](../../docs/riproducibilita.md#provenienza-dei-dati-inclusi);
le impronte degli originali sono conservate separatamente. I due test Python
con guardie per input privati non distribuiti sono identificati come versioni
mantenute, con confronto esplicito agli originali dell’archivio. I file identici
sono memorizzati una sola volta quando il layout lo consente: 1.142 riferimenti usano 870
copie e riutilizzano quelle già presenti. Una cartella `aNN` può quindi
dipendere da file conservati sotto un'altra sigla o campagna. `canonical`
indica il file incluso nella repo; `archive_relative` la posizione originale.
Per ricostruire il programma usare la mappa, senza copiare soltanto `aNN`.

## Verificare e ricostruire i sorgenti

Dalla radice della repo, con Python 3.9 o successivo:

```sh
python3 tools/restore_attempt.py --list
python3 tools/restore_attempt.py --id A108 --check
mkdir -p .local
python3 tools/restore_attempt.py --id A108 --output .local/a108-source
```

Il [ricostruttore](../../tools/restore_attempt.py) verifica dimensioni e
SHA-256 prima di scrivere e segue le dipendenze letterali mappate anche
fra sigle diverse, compresi gli import Python letterali mappati.
La destinazione deve essere nuova e il genitore esistere.
La ricevuta `RESTORE_ATTEMPT.json` elenca ciò che è stato ricostruito.
Il comando non installa dipendenze, compila o esegue gli esperimenti.

La verifica è passata per tutte le 149 sigle con programmi. Non equivale
a una nuova build: toolchain, librerie esterne, percorsi runtime e input
restano quelli indicati nei rapporti. Otto target ausiliari dichiarati nei
manifest congelati A33/A34/A38 non erano inclusi nei rispettivi snapshot;
i programmi effettivamente usati sono conservati. Quattro riferimenti A130
appartengono a un frammento di proposta: la versione applicata e le sue
dipendenze sono presenti. La mappa distingue questi casi.

I programmi e test Python si ricostruiscono dagli stessi percorsi canonici,
insieme alle dipendenze locali mappate. A35 raccoglie tre varianti distinte e
i log dei loro unit test del 2 ottobre: i risultati dei modelli restano distinti
dalla successiva integrazione FHE in A38.

## Leggere i risultati

`RESULTS_MAP.json` collega ogni risultato alla sigla, al percorso originale,
all'impronta originale e alla copia inclusa. `transformations` dichiara le
selezioni e redazioni campo per campo. Le copie strutturate mantengono
conteggi, verdetti e misure pubbliche; le 14 tabelle conservano tutte le
1.835 righe nelle colonne selezionate. Le tracce complete possono contenere
fasi, coefficienti o dati biometrici e non sono sostituite da un riepilogo.

I risultati intermedi conservano il loro stato datato: una prima verifica
positiva può essere seguita da un audit negativo. Per l'interpretazione
aggiornata seguire il catalogo, che collega le correzioni. La
[campagna A108 del 5 ottobre](../14_pipeline_tfhe_rs/results/a108_rerun_2026-10-05/README.md)
è una nuova esecuzione con chiavi e log propri, distinta dalla prova originaria.

Le 38 sigle senza programma autonomo individuato comprendono analisi,
proposte e campagne aggregate; quelle senza risultati strutturati possono
avere soltanto un rapporto testuale. Il catalogo distingue analisi, proposte
ed esecuzioni: la presenza di un file non attesta da sola una prova eseguita.
Foto, embedding, chiavi, ciphertext, directory di build e cache non fanno
parte di questo pacchetto.
