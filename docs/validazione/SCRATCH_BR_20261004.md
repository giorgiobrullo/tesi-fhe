# Costo del buffer temporaneo — 4 ottobre 2026

La blind rotation è l'operazione che ruota un polinomio usando un controllo
cifrato. Nel runtime, TFHE-rs 1.8.1 crea e azzera un buffer temporaneo a
ogni chiamata; il piano FFT è invece già in cache. Abbiamo misurato soltanto
la gestione di questo buffer, per decidere se approfondirne il riuso.

**Il riuso del buffer resta una pista a bassa priorità.** Il costo osservato
è in microsecondi, mentre confronto, refresh e rotazione nella
[diagnosi del nodo](PROFILO_MERGE_20261004.md) richiedono millisecondi.
Il diverso contesto delle due misure impedisce di trasformare questa
osservazione in una previsione di risparmio della query.

| Worker | Nuovo buffer: costruzione, azzeramento e rilascio | Buffer già dimensionato: resize e osservazione |
|---:|---:|---:|
| 1 | 0,913 µs/ciclo | 1,933 ns/ciclo |
| 16 | 20,714 µs/ciclo | 2,098 ns/ciclo |

Ogni valore è la mediana di quattro blocchi; in ciascun blocco si prende
prima la mediana dei tempi per ciclo dei worker. Con 16 worker il loop
produce allocazioni continue e simultanee. La query reale alterna invece
allocazioni e calcolo crittografico: questi numeri non descrivono il suo
tempo per blind rotation. Il rapporto fra le due colonne non è uno speedup FHE.

## Cosa è stato misurato

Helper separato dal runtime, M4 Max, Rust 1.98.1 e TFHE-rs 1.8.1;
release opt3, un codegen unit, LTO disattivato. La richiesta pubblica di
memoria è **163.967 byte**, inclusa la tolleranza per l'allineamento, con
`u64`, GLWE size 2, polynomial size 2048 e piano FFT Dif4/base1024.

Per ciascun pool di 1 o 16 worker: 256 cicli di warmup per ramo, poi
quattro blocchi da 8.192 cicli per ramo e worker. L'ordine alterna
nuovo/riuso e riuso/nuovo. Il buffer riusato è privato al worker e viene
dimensionato prima dei timer. Entrambi i rami rendono osservabile la
stessa slice con `black_box` e leggono due estremi; non percorrono tutti
i byte e non eseguono il lavoro della blind rotation.

Il timer del worker misura il loop dopo una barriera. Il timer del blocco
comprende anche dispatch, accesso al buffer locale, barriera e attesa degli
altri worker. Dividere quest'ultimo per tutti i cicli misura il throughput
aggregato, non la latenza di una chiamata. I dati conservano entrambe le
quantità; non si sommano i tempi dei worker.

Una sola esecuzione, quattro warmup e sedici blocchi misurati, senza
esclusioni. Il carico desktop non è controllato. La revisione indipendente
conferma conteggi, tempi e identità della build. I conteggi di oggetti nel
CSV derivano dal programma, non da una traccia dell'allocatore. Non è stata
verificata l'intera sequenza di istruzioni generata dal compilatore.

**Nessuna chiave generata, nessuna query FHE e nessuna modifica al runtime.**
Non si moltiplicano questi tempi per il numero di rotazioni; non costituiscono
un limite superiore del costo reale, una garanzia di correttezza o un motivo
per aggiornare i grafici della pipeline. La precedente prova A77 con un
thread e TFHE-rs 0.11.3 non aveva osservato un beneficio materiale: questa
misura pubblica riguarda un'altra versione e un altro carico, senza ripeterla.

[Campioni](../../benchmark/br-scratch-cost-20261004/samples.csv),
[record originali](../../benchmark/br-scratch-cost-20261004/raw.jsonl),
[riepilogo e hash](../../benchmark/br-scratch-cost-20261004/SUMMARY.json),
[protocollo e sorgente](../../benchmark/br-scratch-cost-20261004/PROTOCOL.md),
[verifica indipendente](../../benchmark/br-scratch-cost-20261004/INDEPENDENT_REVIEW.md).
