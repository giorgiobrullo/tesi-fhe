# Test del progetto

I test distinguono il runtime mantenuto dai circuiti storici. Le
[istruzioni della demo](../docs/riproducibilita.md#eseguire-i-test-della-demo)
coprono client, servizio corrente e la regressione FHE su chiavi fresche.
I test Python della demo usano rete e crittografia simulate; quelli FHE
vanno eseguiti isolatamente.

La [demo web ha una suite separata](../demo/web/README.md#verificare-le-modifiche-alla-demo-web),
con l'ambiente Python dedicato e i test dell'interfaccia in Node.js.
Non è inclusa nei comandi per la demo a due pagine né nella discovery di `tests/`.

I test dei generatori delle figure sono in `benchmark/test_figure_current*.py`,
fuori dalla discovery di `tests/`. Il loro [comando dedicato](../docs/riproducibilita.md#entrambe-le-figure-del-20-settembre)
verifica il ricalcolo dei dati e i vincoli sugli output senza eseguire FHE.

I [test degli strumenti di ricostruzione](../tools/README.md) verificano
mappe, impronte e copie con fixture temporanee; non avviano gli esperimenti.

<a id="modelli-e-controlli-storici-in-python"></a>

## Modelli aritmetici e controlli sui formati

Dalla radice, con l'ambiente preparato:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -B -m unittest discover -s tests
```

I modelli aritmetici e i controlli sui formati non richiedono chiavi. Alcuni
test di A33/A38 richiedono invece i transcript, le cache biometriche, i
binari e gli snapshot originali conservati localmente. In assenza di questi
input sono indicati come `skipped`; le copie JSON pubbliche redatte non
sostituiscono gli originali. Quando gli input sono presenti, gli stessi
controlli sugli hash restano obbligatori. Un test saltato non è una prova
di correttezza della campagna storica.

## Servizio FHE precedente

`test_varco_demo_service.py` contiene anche una suite sul vecchio servizio
dell'esperimento 14, con risposta a una sola LWE. L'esecuzione normale la
salta. Per eseguirla esplicitamente, usando il binario di quella revisione:

```sh
RUN_HISTORICAL_FHE_TESTS=1 VARCO_DEMO_BIN=/percorso/varco_demo \
  .venv/bin/python -B -m unittest tests.test_varco_demo_service.VarcoDemoServiceTest
```

Senza `VARCO_DEMO_BIN`, la suite compila il vecchio crate; genera chiavi
temporanee e avvia un proprio servizio. Non va eseguita insieme a benchmark.
I suoi esiti non qualificano il runtime corrente a tre LWE.
