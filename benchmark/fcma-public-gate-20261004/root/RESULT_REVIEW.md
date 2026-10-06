# FCMA pubblico: verifica indipendente del risultato

4 ottobre 2026. **PASS_PUBLIC_NUMERIC_AND_PAIRED_RECORDS**. Review dei nuovi sorgenti congelati, receipts, dati pubblici e codice compilato; nessuna build, esecuzione del target/oracolo, chiave/FHE o modello precedente effettuata dal reviewer. PREBUILD_REVIEW resta invariata.

## Integrità e controllo numerico

I nove file SOURCE_BUILD corrispondono direttamente a byte/hash attuali, inclusi helper/oracolo già revisionati e la review prebuild. Binario476000B, SHA256 `0ef735eec45191d0236c2f51978a3fe7572f95d995d40ead71ce82525f0dd485`, uguale al BUILD terminale0. Receipts mostrano un build, una validate, un nuovo oracle e una bench terminali0, nell'ordine previsto; stderr validate/oracle/bench vuoti. Nessun retry è presente nei record.

Dump:8194 record, header+8192 sample ordinati case/index+completion. Riconteggio indipendente:131072 parole binary64 finite, FPCR iniziale/finale0,189 output con bit di zero negativo. ORACLE PASS è legato allo SHA esatto del dump e riporta65536 confronti, zero errori e189 equivalenze di segno zero. Il grafo esatto e il prefisso First actual sono stati revisionati prima del build; l'oracolo non è stato rieseguito qui. Il PASS numerico riguarda questi quattro casi e i grafi propri di ciascun backend, con ±0 equivalenti numericamente.

## Dati e ricalcolo accoppiato

Raw bench34 record: header del solo dataset1,32 batch e completion, FPCR0 invariato e64 warmup/backend dichiarati. Tutti gli otto blocchi rispettano N,F,F,N / F,N,N,F, posizione/repetition1000 e elapsed positivo. Ricalcolati separatamente i checksum dai2048 output finali del caso1: Neon `47fb0c237021b183`, FCMA `da349b47ff3666ea`. Ogni batch coincide con il checksum del proprio backend.

Da ciascun blocco, rapporto delle medie geometriche dei due batch per backend; poi media geometrica degli otto rapporti. Risultato indipendente coincidente con ANALYSIS:

- FCMA/Neon **0.7180258802791004**, tempo relativo **−28.1974119721%**;
- FCMA più rapido in8/8 blocchi; range rapporti0.6964793448–0.7280543269;
- mediane marginali per coppia First+MAC: Neon1495.5625ns, FCMA1073.646ns.

Le mediane marginali non sono l'estimand accoppiato. Somma dei32 elapsed:40.714083ms, coerente con42.531ms fra i timestamp di processo. Host/cache/frequenza/carico non controllati statisticamente; nessun intervallo di confidenza o replica di campagna è inventato.

## Il lavoro misurato è conservato

Ispezione readonly del solo simbolo bench univoco a0x100000888: FCMA carica il contatore1000 a0x100000c20, chiama fcma_update a c64/c90 con First1/0 e torna a c28 dopo decremento/branch c94/c98. Neon carica1000 a d64, chiama neon_update a da8/dd4 e torna a d6c tramite dd8/ddc. Instant::elapsed è successivo ai loop a ca0/de4; checksum segue quel confine. Non è stata eliminata la sequenza di1000 coppie. Restano barriere/passing di slice e wrapper nel tempo misurato, simmetrici nel sorgente.

Ispezione indipendente dei wrapper nel medesimo binario conferma i corpi First14/MAC15 Neon contro9/9 FCMA, con due operazioni FP seriali e zero First FCMA. Lo scope è singolo thread/hot buffer pubblico su questa macchina: il risultato rende concreta la pista pointwise, senza quantificare beneficio di servizio/demo, FFT, rumore o contratto0/ID. Nessuna modifica della baseline è stata validata o eseguita.

## Identità essenziali

- validate.stdout3534936B `db1592b552a2ff65b1285e4a6c120ed749d1e76fa7bc7dfd480764b7f25297cf`; bench.stdout4470B `0e6347bd31341c42c4dec338e624d77952a7cd3136967ce397f92b881f9e138e`.
- SOURCE_BUILD1319B `f7a7cc63e018a0a29ae6b76d4d01d0333247a708a237751442815103ecfbd2b5`; PREBUILD_REVIEW4844B `931f87b947aaea4dc4ceb3c53e8167d2b7da99daa6f24baab12716e67f105bd1`.
- ORACLE733B `4d46c9ba4f9731037be2dffd0cc2a45c37501d652d746759c2f1523005bb9714`; ANALYSIS2228B `ce182da93e04f206481ec62871b8e46013ecdcda4fe94517680f42a4cbbffbc2`; ANALYZE3174B `b1f2136dbf1045f2f26364b33456c4ad2116cf1e5cc99b6a4c63025a1562e85b`, letto ma non eseguito.

Una lookup iniziale di root/ANALYSIS.json era inesistente; recuperata dal path reale logs/ANALYSIS.json. Nessuna modifica a dati/sorgenti/receipt o vecchie evidenze.
