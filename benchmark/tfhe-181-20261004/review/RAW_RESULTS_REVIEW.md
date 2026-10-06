# Verifica indipendente dei risultati correnti

4 ottobre 2026. Solo lettura dei nuovi dati e aritmetica ordinaria inline: nessuna nuova richiesta FHE, decifratura, compilazione, esecuzione del driver o test, modello precedente o controllo di processi. Questa nota è l'unico nuovo file del revisore.

## Copertura e binding

Le 216 righe coprono esattamente tre coppie di famiglie, quattro blocchi, due versioni, tre scene, un warmup e due misure per scena. Non ci sono identità duplicate o mancanti: 72 warmup e 144 misure. Tutte riportano `correct=true` e ID uguale all'oracolo salvato: Einstein 1, Curie 2, Turing 3. Il revisore ha controllato questi record e i byte delle risposte; non ha ripetuto la decifratura né ricostruito l'oracolo dai template.

Tutti i 216 header e trace HTTP coincidono con righe e binding di PREPARED: timer, input/output hash, dimensione risposta, circuito, parametri, variante e profilo. Conteggi identici: BR 1111, PFKS 509, KS 1080, marginals 1709, campioni iniziali 120. I due hash dei binari corrispondono ai receipt, con Rust 1.98.1 e impostazioni release identiche. PREPARED pinna lo spec.v2 corrente e il driver dichiarato in LAUNCH. LAUNCH conserva invece l'hash dello spec del primo tentativo: è un record precedente, non il pin dello spec.v2.

Gli eventi documentano 24 start, 24 stop e 24 blocchi validati, nell'ordine AB/BA/AB/BA di ogni famiglia. Ogni start è seguito dal proprio stop e dalla validazione di nove risposte; 24 PID distinti, nessuna uscita inattesa, stop -15. Non è stato effettuato un nuovo controllo dei processi del sistema.

## Risultati ricalcolati

Per ogni scena/famiglia/blocco: mediana delle due misure di ciascuna versione, rapporto candidate/baseline; poi mediana dei quattro rapporti di blocco e mediana delle tre famiglie. Tutti i rapporti e le mediane HTTP salvati in COMPLETE coincidono esattamente con il ricalcolo.

| Scena | Rapporto gerarchico 1.8.1 / 1.7.0 | Variazione | Mediana marginale server 1.7.0 / 1.8.1 (ms) | Mediana marginale HTTP 1.7.0 / 1.8.1 (ms) |
| --- | ---: | ---: | ---: | ---: |
| Einstein | 1.0208549624855106 | +2.0855% | 1855.85 / 1899.20 | 1856.396 / 1899.723 |
| Curie | 1.0139893483674687 | +1.3989% | 1857.20 / 1884.30 | 1857.748 / 1884.845 |
| Turing | 1.008825644962947 | +0.8826% | 1852.90 / 1877.80 | 1853.502 / 1878.376 |

Le mediane marginali aggregano le 24 misure per scena/versione e sono descrittive: il loro rapporto non sostituisce l'estimando gerarchico. La mediana delle differenze HTTP meno server, per scena/versione, è 0.532–0.591 ms; ogni differenza osservata è positiva, minimo 0.386 ms. Il timer server resta quello di `evaluation::varco`; quello HTTP va dall'invio alla lettura completa. Avvio, iscrizione, cifratura, decifratura e scrittura/hash sono esclusi secondo il driver già revisionato. Non è il tempo dal clic della demo.

COMPLETE riporta passed=true e nessun fault; i suoi hash di samples/events sono corretti. Le tre scene, i blocchi e le ripetizioni non sono famiglie indipendenti. Il carico desktop in LAUNCH e il possibile primo overlap di controlli leggeri restano limiti dichiarati; nessun campione è stato rimosso. Questi risultati non isolano una regressione generale, non danno intervalli di confidenza o limiti sugli errori rari e non sostituiscono una garanzia formale 0/ID.

## Identità dei record consultati

Percorsi relativi a `tmp/current-build-timing-20261004/`; SHA256 e byte al momento della lettura.

| Record | Byte | SHA256 |
| --- | ---: | --- |
| results-run02/samples.jsonl | 235728 | 756a706c3cf55d80a838763f6a6f9de1be2d02be8ca914fcf4b8b036336d3dee |
| results-run02/events.jsonl | 10764 | f7719ebf65df8a2cd0e4f0586acbd82302c66a9688f07645bec8b70d7459bff1 |
| results-run02/COMPLETE.json | 989602 | 2956cb2e7ac0e64bc3333c0e8cf17ea62476eadaa2abab9c754eb88196cf5189 |
| results-run02/PREPARED.json | 146769 | d38ae6f106bfd37d4084a770a8b1c129e94ba5d930d8ff01a2147ce0a54b1901 |
| spec.v2.json | 3313 | 82571f93255d092f98896839c3c16e96a05a63867b9447fa6a262aca24ceb66d |
| root/LAUNCH.json | 5405 | 200ebafe59f7805eb3847bb2358eb881e80e72c397002e95f29b30f3b4b0a516 |
| logs/build-baseline.json | 860 | 5003dac185feda90a8f88099dd4c6c1c1d9afbe31a9ea6512d7b94f347130632 |
| logs/build-candidate.json | 862 | 66c121e41b89f22de510b8655c57adf8718fa98bba4fcb8b7ece52ad37fbc249 |
