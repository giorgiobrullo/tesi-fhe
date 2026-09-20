# FastHE e scheme switching: risultati preliminari - 1 settembre 2026

Questo rapporto descrive risultati e condizioni dei confronti preliminari. Non e' un benchmark
matched contro il prototipo TFHE: dataset, funzione, hardware pubblicato e metriche non sono
allineati. I checkout temporanei e i file di input non fanno parte del repository, quindi i run
vanno trattati come **riproduzioni preliminari limitate alla sessione, con hash**, non come
artefatti autosufficienti. Per FastHE non sono conservati nel repository il comando di build,
gli input numerici grezzi, il CSV o i log grezzi: gli hash non permettono da soli di ricrearli.

## FastHE-Search / HyDia

Fonti:

- release ufficiale
  [FastHE-Search V1.0.0](https://github.com/FastHE-Search/FastHE-Search/releases/tag/V1.0.0);
- sorgente al commit 4d5a41e13e6467373bf9f40117db39bffd85cf0e, checkout pulito;
- OpenFHE 1.2.3 al commit 7b8346f4eac27121543e36c17237b919e03ec058, come richiesto
  dall'artefatto;
- build Release arm64, OpenMP attivo; ImageMatching approach 8,
  BSGS-Precomp-Opt (CPU).

**Stato dell'evidenza:** riproduzione preliminare limitata alla sessione descritta. La
configurazione di build è annotata, ma il comando di build effettivamente usato non è stato
preservato.

È stata usata l'approach 8 di `ImageMatching`, con `--keep-serial`.

L'opzione `--keep-serial` conserva o riusa artefatti serializzati. Non è stata preservata una
prova di isolamento della cache per ogni input/caso; non si può quindi escludere riuso di stato
fra run né attribuire con certezza un esito al solo input indicato dall'hash.

Gli input erano vettori numerici sintetici nel formato della release. Hash SHA-256:

| caso | hash |
|---|---|
| N=128, otto match piantati | 1b4d757aafd54ad77c39e0bff40e0a727f94405156885735ae4a4c8d17e0f1e1 |
| N=1.024, sedici match piantati | 68009798bd31570b35a227f6daf35c7ec6a42d778ba6be39b7e2112ef80a4396 |
| N=128, zero match | 1aa402c186b3450aed4e3a41c0601de39064e496a570be34211d4408fd5911ba |
| N=1.024, zero match | 8c2035dcccae38bbf05772312e2daf460f036e3249057f569772934d5c2dafc1 |

### Positivi e costo CPU

| caso | enrollment | query | membership | index | risultato |
|---|---:|---:|---:|---:|---|
| N=128 | 1,071 s | 13 ms | 2,277 s | 2,255 s | 8/8 indici piantati |
| N=1.024, primo run | 1,016 s | 14 ms | 2,255 s | 2,191 s | 16/16 |
| N=1.024, tre warm run | - | 13 ms | 2,194 s media, sd 0,049 | 2,145 s media, sd 0,075 | 16/16 in ogni run |

Il tempo wall complessivo era 7,59 s a N=128, 6,73 s al primo N=1.024 e 5,34 s in media nei tre
warm run. Il picco RSS era circa 4,50 GiB. Il footprint serializzato del run N=1.024 era
5.052.156.850 byte (4,705 GiB):

| oggetto | byte |
|---|---:|
| database diagonale | 2.685.714.944 |
| rotation keys | 1.167.224.775 |
| sum keys | 1.167.224.775 |
| multiplication key | 22.025.023 |
| public key | 7.342.901 |
| private key | 2.623.463 |
| context | 969 |

La private key viene serializzata dall'harness di benchmark: non e' una necessita' del ruolo
compute-server e non va contata come dato da consegnare al server.

### Negativi open-set

La release falliva entrambi i casi senza match:

| N | massimo coseno chiaro | membership | indice |
|---:|---:|---|---|
| 128 | 0,0884, sotto la soglia 0,44 | true | lista vuota |
| 1.024 | 0,117, sotto la soglia 0,44 | true | lista vuota |

Nel solo caso N=128 la somma decifrata dell'indicatore approssimato era 5,50882. Per quel caso il
codice somma fino al batch CKKS da 16.384 slot, includendo 16.256 slot di padding. Una modifica
diagnostica `EvalSum(..., numVectors)` ha corretto N=128 mantenendo gli otto positivi, ma non e'
la release e non e' stata validata su un protocollo DIR@FPIR. Per N=1.024 non sono stati
preservati un aggregato decifrato equivalente o la stessa diagnosi causale. Inoltre, la mancata
isolazione di `--keep-serial` e l'assenza degli input/log grezzi nel repository impediscono di
attribuire entrambi i fallimenti al solo padding. Il generatore ufficiale rifiuta K=0, quindi
l'harness standard non copre il negativo.

Il CSV grezzo della sessione aveva SHA-256
49c8f32feb8ad4fae59f6272914b5833eb541214972543f1aa11556d5528e933.
La GPU non era disponibile: la release CUDA richiede hardware NVIDIA e non puo' usare la GPU
Apple. Nessun numero GPU pubblicato viene quindi presentato come misura locale.

## OpenFHE CKKS -> FHEW scheme switching

Fonte: OpenFHE 1.5.1, commit
1306d14f8c26bb6150d3e6ad54f28dfe1007689e. Build Release CPU arm64, esempi ed extras attivi,
OpenMP disattivato.

La configurazione includeva BUILD_EXAMPLES=ON, BUILD_EXTRAS=ON e WITH_OPENMP=OFF. Per isolare i
casi, il main degli esempi e' stato ridotto a una sola chiamata. Non sono stati cambiati gli
algoritmi. La variante range ha sostituito i 16 input con valori di frontiera entro il dominio q=7
e impostato scaleSignFHEW=4.0.

| prova sicura | slot | key generation | valutazione | wall | max RSS | esito |
|---|---:|---:|---:|---:|---:|---|
| compare | 16 | 32,107 s | 44,394 s | 77,51 s | 8.564.129.792 B | 16/16 segni |
| min + indice | 16 | 31,758 s | 69,155 s | 101,85 s | 8.384.544.768 B | minimo/indice corretti |
| compare, range ±19.574 e scale 4 | 16 | 30,728 s | 55,185 s | 87,27 s | 8.684.617.728 B | 16/16 frontiere |

Hash SHA-256 dei log:

- compare: 11df9090ed2598ac6dfb0a71f18cc0a5d579197c981d6c9b25c02b9f6f36ab1f;
- min: 593ddb8096fe25f407dccbea3b68fdffb4ca74a21f6290c5e7e8e0009e51d8b6;
- range: e1a3a0b7be44213f911521b02dfe8651af28ff721897f17cb4373921472978db.

Gli esempi ufficiali possono essere eseguiti anche con configurazioni TOY o HEStd_NotSet; quelle
prove non sono usate qui. Questi tre run mostrano che compare e min scheme-switched funzionano con
i corpi secure dell'esempio, ma non costituiscono il pipeline biometrico: mancano lo scoring packed
sugli stessi embedding, il riordino degli slot sparsi, negativi DIR@FPIR, cifratura/trasferimento e
una misura matched.

### Switch diretto di 128 slot e OR booleano

Per falsificare l'ipotesi che il costo precedente dipendesse soprattutto dall'esempio generico,
un harness OpenFHE 1.5.1 dedicato ha cifrato 128 differenze di score CKKS gia' calcolate, eseguito
CKKS->FHEW per slot, il segno FHEW, la normalizzazione booleana e un OR cifrato. Parametri secure
dell'esempio, ring dimension CKKS 16.384, `lwe_n=1305`, `lwe_q=4096`, `p_lwe=16384`, 16 thread:

| caso | switch | 128 segni | normalizzazione | OR | online totale | errori di segno | bit globale |
|---|---:|---:|---:|---:|---:|---:|---:|
| nessun match | 0,1089 s | 24,3029 s | 2,7287 s | 3,3290 s | **30,4695 s** | 0/128 | 0 |
| un match | 0,0689 s | 22,2045 s | 5,1748 s | 7,8318 s | **35,2800 s** | 0/128 | 1 |

Setup 0,055 s, keygen CKKS 0,004 s, evaluation-key generation **35,794 s**, precompute 0,139 s;
picco RSS 6.603.000.000 byte. I due vettori includono la frontiera a mezzi interi e gli estremi
`+/-3705,5`, ma sono soltanto due ciphertext. L'intervallo online inizia dopo la cifratura CKKS
di score sintetici precomputati: **esclude scoring del probe e cifratura della query**. Produce
un bit globale cifrato. I 30,4695–35,2800 s risultano circa 47–54 volte la mediana del
checkpoint TFHE periodic-fold `any_match` allora confrontato a N=127, prima di aggiungere gli
stadi esclusi. Il confronto riguarda quel vecchio predicato, non il servizio exact-ID attuale.

- sorgente del test dedicato, non incluso nel clone, SHA-256
  `01c502d9586fb8f4a92a0c99b8614cd23580b4671791d651a926806918157b3c`;
- binario del test dedicato, non incluso nel clone, SHA-256
  `b634662cc80fed79589c8e342a53bc050f49f2e89d11a0338f0563e77cb4fc2f`;
- trascrizione originale delle due misure, non inclusa nel clone, SHA-256
  `e48b624b4e537308fa470a488636c8bf281e1d9f77b7cd9e4f785ebb1e824c87`.

### CKKS aggregate-first: solo prefisso numerico

Resta una variante algoritmicamente migliore: approssimare il segno packed in CKKS, convertire
ogni slot in un indicatore morbido, sommare cifrato i 128 slot, poi fare **un solo** switch FHEW e
un solo segno sull'aggregato. Il prefisso TenSEAL/SEAL TC128, `poly=32768`, 24 primi interni e
sette rotation key selettive ha misurato 3,573979-3,863595 s (tre run) e 4.548.509.696 byte RSS;
le somme finali separavano i due casi sintetici (`~0,044` contro `~0,616`).

Questa non e' ancora una route completa: l'input era la cifratura di differenze normalizzate
precalcolate, mancavano lo scoring CKKS e soprattutto lo switch/segno FHEW finale. TenSEAL/SEAL
non espone il ponte OpenFHE, quindi il risultato e' soltanto un test numerico del prefisso. Non va
tracciato come latenza di pipeline ne' descritto come decisione esatta.

## Interpretazione

Il test FastHE indica che BSGS-Diagonal e CKKS meritano un confronto matched, specialmente su
GPU, ma non dimostra da sola né la riproducibilità del risultato né che il padding sia l'unica
causa dei negativi errati. La release V1.0.0 non puo' essere usata come baseline open-set senza
un harness negativo riproducibile, cache isolate e validazione DIR@FPIR.
OpenFHE scheme switching offre una decisione discreta dopo uno score CKKS approssimato, ma sia gli
esempi generici sia il percorso diretto a 128 slot sono troppo lenti e pesanti per competere su
questa CPU a N=128. L'aggregazione CKKS prima dello switch costituisce un'ipotesi alternativa,
ma non è stata integrata in queste prove. Il confronto finale richiede gli stessi embedding, split held-out,
soglia inclusiva, output e hardware.
