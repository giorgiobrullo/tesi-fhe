# FCMA pubblico: review prima del build

4 ottobre 2026. **PREBUILD_PASS**, limitato alla nuova validazione pubblica e al successivo timing accoppiato soltanto dopo oraclePASS. Letti integralmente main, Cargo/lock, SOURCE_SCOPE, EXACT_ORACLE, ORACLE_SPEC, protocollo e launcher. Nessun programma, oracolo o modello eseguito/importato dal reviewer; nessuna build, chiave, FHE o payload. Questa nota resta immutabile dopo il gate.

## Sorgente e ammissione

I corpi Update/wrapper sono byte invariati rispetto al helper Z. Un confronto iniziale più ampio includeva le nuove importazioni I/O/Instant e restituiva false; il confronto circoscritto ai corpi conferma l'identità. Le due slice2048 hanno due chunk1024, rhs1024 si riusa su entrambi; First e MAC mantengono il medesimo boundary. Token checked e geometria/lane1 restano corretti, senza tail. Il gate legge FPCR senza modificarlo e rifiuta RMode[23:22], FZ[24], AH[1], FIZ[0]; verifica anche il valore completo invariato a ogni caso/batch e alla completion. I range primari Arm43873–43917/44126–44171 confermano i campi. Altri fattori possono causare flush: il registro è un controllo delle premesse, non una garanzia universale della piattaforma.

Quattro casi pubblici deterministici coprono dyadici, mantisse normali, cancellazione e subnormali. Input e output sono finiti; First è copiato soltanto per il dump e MAC modifica lo stesso output actual. La forma è header+8192 sample ordinati+footer, con otto coppie hex16 per sample. La prima versione osservata dichiarava cases4 anche nel bench: prima del gate è stata corretta a cases1/dataset_case1, lasciando validate cases4/dataset_case null. Non è una modifica aritmetica.

## Oracolo esatto indipendente

L'oracolo nuovo usa solo Fraction/integer, senza float Python. Decodifica esattamente normali e subnormali; il round nearest-even segue quoziente/resto, carry del significand e quantum2^-1074 sotto il minimo normale. Il passaggio subnormal→minimo normale è corretto; overflow/nonfinite respinge il gate. I due grafi sono distinti: Neon immaginario poi reale, FCMA reale poi immaginario. First è verificato da a0/b0; final usa a1/b1 e **il First registrato di quel backend**, anche dopo un mismatch First.

Il parser respinge campi duplicati, shape/ordine/copertura mancanti, fonte primaria diversa e ambiente errato; verifica tutti i131072 valori finiti e65536 confronti componenti. Gli zeri +0/-0 sono equivalenti soltanto numericamente e contati; ogni nonzero deve coincidere nei bit del proprio grafo. Il PASS riguarda questi operandi e stadi pubblici, non un teorema uniforme, NaN/infinity, FFT, BR o0/ID.

## Confini della misura

Bench usa Inputs1 identico al caso normale validato, preallocazione e64 coppie di warmup per ciascun backend. Gli otto blocchi alternano N,F,F,N / F,N,N,F; tutte le32 righe restano nel risultato. Ciascun timer include1000 coppie First+MAC. Branch/factory/allocazione sono fuori; wrapper e black_box di output, input e booleani sono simmetrici. Le barriere dentro ogni ripetizione e i wrapper inline-never impediscono di assumere che siano eliminabili le coppie che ripartono da First. Checksum completo, verifica finitezza, FPCR e I/O sono successivi al timer. Va comunque controllato il codegen effettivo prima di interpretare il risultato.

Il launcher blocca rilanci da receipt esistente, lega ogni native al binario e agli hash SOURCE_BUILD, ricontrolla il perimetro di processi senza controllarne alcuno. Bench richiede validation terminale0 e oraclePASS sullo SHA esatto del dump. I controlli fresh liveness/preservazione immediati e il singolo build/run sono compiti del root. Il risultato potrà essere solo host/hot-buffer specifico: nessuna stima di beneficio per il servizio, rumore o pipeline cifrata.

## Input attivi verificati

- main.rs11518B `7ef97bf24cae04b14407cb56f89a43cf770b2a28105a5caadc8f1458c0970f65`; SOURCE_SCOPE5999B `9030a83d10424482eaeef885020a5726bf0933b6276c917e7eeaf4b047f92692`.
- EXACT_ORACLE.py9324B `3e1c8bce11070ff5dca76000789d14ccdc72af8ffe507f46bb177ade8f28d1e0`; ORACLE_SPEC3806B `3e9e9578b619475ad9fed8a22b33687e18daa4512b8cdf73bcb64ebba3459133`.
- PROTOCOL2583B `1c7da903db5fffd649523d65f32a211f3c8da0abf7063177c44c0d33fef1e579`; DRIVER4348B `fdb506e9e03795d25a1fd2458130317287a3eb4fd1c789241c2c7b9fb9b74968`.
- Cargo.toml228B `3010be99def04ec4257692c353bc82505179cf1b390064089820683208bfb075`; Cargo.lock2966B `d091029dccf1939dbb573d3a658f273bacd53b88ea0c95d83f296c5bd13dd729`, pinnedpulp0.22.3/std, opt3/CGU1/LTOoff.
- FPCR_PRIMARY1123B `037e690b6ad2b4b40cba312e8e2dd0d819700105534d06b9e00f1556d1d3d5ab`; Arm PDF8935128B `a6eca120622b9bbce6ba7b8991ed6f5dbb4c1a4af600f832420e352ef83b0570`, solo i range testuali citati consumati.

Nessun blocker residuo nella sorgente attiva; nessun PASS numerico o prestazionale ancora ottenuto.
