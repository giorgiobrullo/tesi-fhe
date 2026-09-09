# 23 — Ottimizzazioni del valutatore CKKS

Il confronto diretto `combined-v3` misura una riduzione geometrica appaiata
dell'**8,098463%**, con18 vittorie su18 coppie e tre famiglie di chiavi nuove.
Le mediane sono3,211634 s per il riferimento e2,948412 s per la combinazione.
Questi sono i risultati della campagna conclusa, non nuove misure della copia.

`runtime/` conserva identici il valutatore C++, i tre header e CMake.
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

`RESULTS.json` contiene una proiezione dei risultati originali, incluse tutte
le18 coppie e i tempi per stadio; `PUBLIC_TIMING_PAIRS.csv` li rende comodi da
analizzare. Gli hash delle fonti e delle copie sono in `COPY_ORIGINS.json` e
`PACKAGE_PINS.json`. Non sono inclusi chiavi, immagini, fixture vecchie,
ciphertext, librerie compilate o inventari di altri processi.
Le colonne di carico nel CSV riportano il riepilogo della cella temporale
che contiene la coppia, non una nuova misura del carico di quella sola query.

La successiva prova separata8/12/16 thread è conclusa:12 quasi alla pari
(+0,2011% di tempo),8 più lento (+8,9820%), con16 mantenuto come riferimento.
Quel sorgente rende coerente la definizione `PARALLEL` in tutte le unità;
il suo confronto non misura separatamente l'effetto di tale cambiamento
rispetto a `combined-v3`. La frase «ancora da eseguire» nel report originale
copiato è storica ed è superata da `evidence/ORIGINAL_THREAD_RESULTS.md`.

## Ricostruzione senza vecchi dati

Il generatore `generate_synthetic.py` usa solo la libreria standard Python.
Ricostruisce dalla formula pubblica gli otto file originali necessari per
le scene N128 e N4 e ne verifica gli hash originali. Nessun dato in `tmp`
viene letto. Tutti i probe hanno512 coordinate uguali a1, norma quadrata512;
galleria e probe rispettano coordinate intere in[-3,3]. L'oracolo calcola
prima il primo minimo e poi verifica la soglia inclusiva di quel vincitore,
anche quando un candidato più lontano o un pari successivo accetterebbe.

Una nona scena `synthetic_n64_r4096_all_tie` usa64 gallerie distinte costruite
con100 coordinate uguali a3, ruotate; il primo ID passa alla soglia300.
Il limite pubblico del parser produce intervallo4096. È un controllo nuovo
validato solo in aritmetica intera: non replica la vecchia immagine DigiFace
né eredita la sua verifica FHE. L'esatta qualificazione storica R4096 richiede
gli asset originali, esclusi da questo pacchetto.

Dalla cartella `experiments/23_ckks_ottimizzazioni`:

```sh
python3 -B generate_synthetic.py --check
python3 -B generate_synthetic.py --output .local/fixtures
```

Il primo comando non scrive fixture; il secondo richiede una cartella nuova.
Il controllo in memoria è stato eseguito durante il consolidamento: tutte
le nove scene passano e gli otto hash storici coincidono. Non sono state
eseguite compilazioni, generazioni di chiavi o query cifrate.

## Compilazione ed esecuzione successive

Dipendenza esterna: OpenFHE1.5.1, revisione
`1306d14f8c26bb6150d3e6ad54f28dfe1007689e`, con i submodule indicati in
`DEPENDENCIES.json`, C++17, CMake e OpenMP. Il codice usa `getrusage` ed è
destinato a sistemi POSIX. Installare OpenFHE in una cartella locale e
impostare `OpenFHE_DIR` sulla sua cartella `lib/OpenFHE`; non riutilizzare
i percorsi assoluti del vecchio Mac. Non serve openfhe-statistics per
compilare questi cinque sorgenti.

```sh
cmake -S runtime -B .local/build -DCMAKE_BUILD_TYPE=Release \
  -DOpenFHE_DIR="$OpenFHE_DIR"
cmake --build .local/build -j 4
```

Ogni invocazione del programma genera una famiglia di chiavi nuova in
memoria. I comandi seguenti sono un punto di partenza riproducibile, da
eseguire solo in una finestra libera da benchmark concorrenti. Non sono
stati lanciati da questo consolidamento.

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

Tre invocazioni separate danno tre famiglie; salvare separatamente stdout,
stderr, ambiente, identità di sorgenti/librerie/binario e carico del sistema.
Conservare fallimenti e coppie lente. Questo comando riproduce il nucleo del
confronto, non l'intera catena di audit storica: i vecchi launcher dipendono
dai log, monitor e file congelati e restano nei loro percorsi originali.
