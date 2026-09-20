# 23 - Ottimizzazioni del valutatore CKKS

Il confronto diretto `combined-v3` misura una riduzione geometrica appaiata
dell'**8,098463%**, con18 vittorie su18 coppie e tre famiglie di chiavi nuove.
Le mediane sono3,211634 s per il riferimento e2,948412 s per la combinazione.
Il confronto misura il calcolo cifrato completo, con verifiche di output
e uguaglianza dei ciphertext separate dai timer.

`runtime/` contiene il valutatore C++, i tre header e CMake.
La modalità `combined-powers` condivide le riduzioni dell'input e di x²
nei polinomi e prepara una volta la decomposizione per le rotazioni del
punteggio. La cache dei plaintext pubblici è identica nei due bracci.
Quindi l'8,10% si aggiunge operativamente a una cache già presente nel
riferimento, ma non va sommato o moltiplicato con percentuali di altre prove.
Il nome storico `combined` indica la versione precedente; usare
`combined-powers` per questa combinazione.

## Evidenza e limiti

| Famiglia temporale | Riduzione geometrica | Vittorie |
|---|---:|---:|
|0|7,657%|6/6|
|1|8,034%|6/6|
|2|8,602%|6/6|

Le tre qualificazioni producono18 uscite e45 uguaglianze complete dei
ciphertext/input nei cinque stadi. Le misure aggiungono48 uscite e24
uguaglianze complete finali:66 uscite e69 uguaglianze complessive.
Ogni famiglia temporale esclude due coppie di riscaldamento e misura sei
coppie con ordine alternato. Preparazioni dipendenti dalla query e riduzioni
restano dentro i tempi; cifratura iniziale, decifratura, copie per il controllo
e confronti completi dei cifrati sono esterni al tempo della query.

Tutte le famiglie conservano carico esterno alto e in parte indeterminato.
Non è una latenza della demo HTTP, una prova di accuratezza biometrica o
un limite formale alla probabilità di errore. CKKS produce un valore
approssimato che il client arrotonda, diverso dalle tre cifre TFHE esatte.
I controlli osservati impongono risultato atteso ed errori inferiori a0,5.

[RESULTS.json](RESULTS.json) contiene tutte le 18 coppie e i tempi per stadio;
[PUBLIC_TIMING_PAIRS.csv](PUBLIC_TIMING_PAIRS.csv) permette di analizzarli.
Il [metodo](evidence/ORIGINAL_COMBINED_DESIGN.md) descrive il confronto e il
[rapporto dei risultati](evidence/ORIGINAL_COMBINED_RESULTS.md) ne riassume gli effetti.
Le colonne di carico nel CSV riportano il riepilogo della cella temporale
che contiene la coppia, non una nuova misura del carico di quella sola query.

La successiva prova separata8/12/16 thread è conclusa:12 quasi alla pari
(+0,2011% di tempo),8 più lento (+8,9820%), con16 mantenuto come riferimento.
Quel sorgente rende coerente la definizione `PARALLEL` in tutte le unità;
il suo confronto non misura separatamente l'effetto di tale cambiamento
rispetto a `combined-v3`. Il [rapporto sui thread](evidence/ORIGINAL_THREAD_RESULTS.md)
riporta metodo, tabella e limiti di questa prova separata.

## Input sintetici

Il generatore `generate_synthetic.py` usa solo la libreria standard Python.
Ricostruisce dalla formula pubblica gli otto input delle scene N128 e N4
e ne verifica le impronte di riferimento. Tutti i probe hanno512 coordinate uguali a1, norma quadrata512;
galleria e probe rispettano coordinate intere in[-3,3]. L'oracolo calcola
prima il primo minimo e poi verifica la soglia inclusiva di quel vincitore,
anche quando un candidato più lontano o un pari successivo accetterebbe.

Una nona scena `synthetic_n64_r4096_all_tie` usa64 gallerie distinte costruite
con100 coordinate uguali a3, ruotate; il primo ID passa alla soglia300.
Il limite pubblico del parser produce intervallo4096. Questa scena è stata
verificata solo in aritmetica intera e non riproduce il caso DigiFace della
qualifica FHE R4096. La correttezza in chiaro della scena generata non le
trasferisce quella verifica FHE.

Dalla cartella `experiments/23_ckks_ottimizzazioni`:

```sh
python3 -B generate_synthetic.py --check
python3 -B generate_synthetic.py --output .local/fixtures
```

Il primo comando controlla le nove scene in memoria e le otto impronte di
riferimento; il secondo scrive gli input in una cartella nuova. Questi
controlli sono aritmetici e non eseguono FHE.

## Compilazione ed esecuzione

Dipendenza esterna: OpenFHE1.5.1, revisione
`1306d14f8c26bb6150d3e6ad54f28dfe1007689e`, con i submodule indicati in
`DEPENDENCIES.json`, C++17, CMake e OpenMP. Il codice usa `getrusage` ed è
destinato a sistemi POSIX. Installare OpenFHE in una cartella locale e
impostare `OpenFHE_DIR` sulla sua cartella `lib/OpenFHE`.
Non serve openfhe-statistics per compilare questi cinque sorgenti.

```sh
cmake -S runtime -B .local/build -DCMAKE_BUILD_TYPE=Release \
  -DOpenFHE_DIR="$OpenFHE_DIR"
cmake --build .local/build -j 4
```

Ogni invocazione del programma genera una famiglia di chiavi nuova in
memoria. I comandi seguenti mostrano prima un controllo di correttezza,
poi un confronto dei tempi. Per misurare il runtime, evitare altri benchmark
concorrenti e registrare il carico esterno.

Primo controllo N4 con soglia inclusiva, copie complete fuori dal timer:

```sh
OMP_NUM_THREADS=16 OMP_MAX_ACTIVE_LEVELS=1 OPENBLAS_NUM_THREADS=1 \
  .local/build/ckks_identify --input .local/fixtures/adv_n4_last_t.txt \
  --poly balanced --dg 6 --df 2 --scale-bits 33 --first-bits 60 \
  --large-digits 4 --threads 16 --cache-public --paired-runtime \
  --depth 35 --runtime combined-powers --runtime-reference baseline \
  --warmups 0 --repeats 1 --diagnostics
```

Per qualificare N128 passare insieme i tre file N128 con tre opzioni
`--input`, mantenendo i flag e impostando `--depth 38`. Per N4 passare
tutti i cinque file N4 e `--depth 35`. Il controllo sintetico R4096 usa
il solo file N64 e `--depth 37`. Richiedere il record finale `pass:true`,
zero fallimenti e uguaglianze complete ai checkpoint; una sola uscita
decifrata corretta non sostituisce questi controlli.

Dopo i controlli, una famiglia temporale sullo stesso input pubblico
della campagna si ottiene così:

```sh
OMP_NUM_THREADS=16 OMP_MAX_ACTIVE_LEVELS=1 OPENBLAS_NUM_THREADS=1 \
  .local/build/ckks_identify --input .local/fixtures/matched_n128_general.txt \
  --poly balanced --dg 6 --df 2 --scale-bits 33 --first-bits 60 \
  --large-digits 4 --threads 16 --cache-public --paired-runtime \
  --depth 38 --runtime combined-powers --runtime-reference baseline \
  --warmups 2 --repeats 6
```

Tre invocazioni separate generano tre famiglie. Registrare output, ambiente,
versioni di sorgenti/librerie/binario e carico del sistema. Analizzare tutte
le coppie pianificate, comprese quelle lente, e riportare separatamente i
fallimenti. Le medie geometriche dei rapporti appaiati e le mediane dei tempi
sono estimatori diversi.

## Provenienza

[Provenienza e impronte dei file](PROVENANCE.json) distingue i byte pubblicati
dai documenti storici e dalle copie redatte. I digest degli esperimenti
identificano le esecuzioni originali; questa pubblicazione non aggiunge
una nuova compilazione nativa o una nuova prova FHE.
