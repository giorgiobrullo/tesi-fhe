# GT v4: review indipendente dei risultati

**PASS dei conteggi e dell'oracolo intero sui dati salvati.** Review iniziata 2026-10-05 **11:15:24 UTC**; ricalcolo completo alle **11:18:14 UTC**, chiusura documentale al timestamp sotto. Letti gli otto artefatti sotto, STATE top e record della validazione. Un ricalcolo nuovo in Python stdlib, senza importare il runner, ricostruisce tutti i punteggi e i conteggi. Nessun pixel, peso, modello neurale, inferenza, processo esistente, vecchio modello/checker o dato crittografico letto/eseguito. La ricevuta di terminale è gestita da root; il summary riporta COMPLETE alle 11:14:28.953264 UTC.

## Risultati confermati

Manifest: 100 preset + 20 iscritti GT + 30 sconosciuti GT; 150 etichette distinte, 360 foto con path/ruoli disgiunti e SHA dichiarati tutti distinti, 260 input destinati al frontend. Galleria di 120 voci nell'esatto ordine del manifest, tutte con soglia 273, nessun errore di setup. I 100 preset seguono la preparazione server; le nuove foto GT seguono il codec preregistrato. Non sono 120 persone nuove rispetto allo sviluppo.

Sono presenti **220 tentativi e 220 vettori interi**, tutti estratti: 120 enrollment, 50 primary, 50 secondary. Tutti i 360 frame tentati risultano rilevati; nessun frame parziale, decoder/no-face/shape/nonfinite/domain failure registrato. Le 100 query sono ammissibili, una per ciascuna delle 50 persone in ogni condizione. Verificati shape 512, componenti intere fra −3 e 3, norme registrate e querynorm≤1024, coerenza vettore enrollment/galleria e attempt/search.

| Condizione | Iscritti corretti e accettati | ID errati/rifiuti degli iscritti | Sconosciuti accettati | Sconosciuti rifiutati |
|---|---:|---:|---:|---:|
| Primary, 1 foto |20/20|0/0|1/30|29/30|
| Secondary, 3 altre foto |20/20|0/0|1/30|29/30|

Per ciascuna query, calcolati con interi Python `sum(g²)−2*sum(g*q)`, mantenendo il primo indice con score minimo; restituito ID solo se quel minimo è ≤273. **Tutti i 100** output, vincitori, minimi e categorie coincidono con GT_SEARCHES e GT_SUMMARY, comprese due query con più minimi pari. Nessuna valutazione del detector o verifica indipendente della quantizzazione float è implicata da questo ricalcolo.

Il falso accesso riguarda **la stessa persona in entrambi i bracci**: `gt:s41` viene accettata come `gt:s37`, voce/ID 120. Score primary 219; secondary 273, esattamente sulla soglia inclusiva. Non è un errore del confronto: l'oracolo ammette correttamente entrambi. Nessuno sconosciuto accettato verso i 100 preset. Non cambiare T per eliminare questi esiti osservati.

## Interpretazione statistica

FPIR osservata e false-access/tentativi coincidono qui: **1/30 = 3,33% per condizione**, perché non vi sono tentativi falliti. L'upper Clopper–Pearson unilaterale al 95% è stato verificato indipendentemente risolvendo `P(Binomiale(30,p)≤1)=0,05` per bisezione stdlib: **0,14859606865911318**, coerente col summary entro 1e−12.

Il risultato **non sostiene una FPIR≤1%**, ma non dimostra neppure che la FPIR di popolazione superi l'1%. Le stesse 30 persone condividono galleria e condizioni: niente pooling in 60 sconosciuti e nessun confronto causale del solo numero di foto. Intervallo condizionato all'ipotesi binomiale per identità/galleria fissa; sovrapposizione semantica GT/preset e pretraining non verificata, sessioni dei ruoli non attestate. TPIR 20/20 resta un conteggio del piccolo campione, non garanzia generale. Nessuna conclusione FHE/p_fail/HTTP/latency.

## Binding esatto

Il manifest lega byte-identicamente driver e protocollo letti. Nessun file sorgente o risultato precedente modificato. SHA256 e byte degli artefatti effettivamente letti:

| Artefatto, in questa cartella | Byte | SHA256 |
|---|---:|---|
| GT_MANIFEST.json |267327|`7e7f8fa066ac5fd1a6912de668ba1d70f54bf2543d4db66e1495c96c3ca70fef`|
| GT_SUMMARY.json |1228|`ac632fcc4da87b3aaf062e7b02eb6fe0380d6760939238f61eb1746b89843737`|
| GT_SEARCHES.json |41779|`d06207648830f28248b4793c316c94ed2e574b7f45b3f6934bcab865ab34504e`|
| GT_ATTEMPTS.jsonl |45142|`e35a6a3c4eba9f2c61a968a7adfc3c9f40f2bb53ee831f2822c22ff15cdb2bfa`|
| GT_GALLERY.json |707415|`5c87242258c62b6b1f128fe7600269908c90c326bee109f2d23f3d84ca029bf8`|
| GT_VECTORS.json |833007|`a19de85f3b185908094691e0ba05b8764c0dfe619e328695e11388a744b156da`|
| run_gt.py |14224|`10610073ef0168b3f199e68d40431be06cd3870966bad1aabc5d13c35dabd20f`|
| GT_PROTOCOL.md |4808|`f79306e05dd0d5045b48d98060614c7992df2e3ca64df123d9e8551fd06868c9`|

Source cuts: run_gt.py:20–96 (preparazione/binding),99–271 (estrazione, setup, oracolo, metriche). L'intero file è hashato, non importato. I digest delle foto/pesi nel manifest sono metadati, non nuove letture dei loro byte. Scope della review: accounting e decisione sui nuovi vettori in chiaro, non conferma visuale delle identità o indipendenza di popolazione.

Chiusura della review/documento: 2026-10-05 11:22:27 UTC.
