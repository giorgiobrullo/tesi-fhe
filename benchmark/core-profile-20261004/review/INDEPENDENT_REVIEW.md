# Verifica indipendente della profilazione corrente

4 ottobre 2026. Ricalcolo aritmetico dai record originali, senza importare il driver, modelli precedenti o eseguire codice nativo. `COMPLETE.json` dichiara PASS e nessun fault; il ricalcolo conferma i riepiloghi con tolleranza relativa 10⁻¹² per la rappresentazione floating point.

**Copertura verificata:** 72 identità di campione distinte, 24 warmup e 48 misure; quattro blocchi off/on alternati, due misure per scena/arm/blocco. Tutti i record riportano risultato corretto, ID uguale all'oracolo registrato e tre cifre coerenti. Non è una nuova decifratura indipendente.

Gli eventi riportano otto avvii, otto stop e otto blocchi validati da nove query. Gli otto PID coincidono fra avvii e stop, tutti con `unexpected_prior_exit=false` e uscita −15 dopo cleanup. È una verifica dei log, non una nuova osservazione OS di liveness.

Binario, circuito, chiave server e conteggi sono identici nei 72 record; ciascuna scena conserva un solo hash del ciphertext di input fra off/on e blocchi. I 72 trace HTTP confermano status, timer, hash richiesta/risposta e header salvati. I profili coincidono esattamente fra header JSON e campione: 36 on, di cui 24 misurati; nessun header off. Ogni profilo ha tutti i sette livelli 120/60/30/15/8/4/2, ledger dei merge coerente, timer positivi, mode `both`, narrow-ID attivo e parallelismo richiesto. Le somme dei livelli stanno nel torneo, le quattro fasi nell'evaluate, senza dover utilizzare la tolleranza concessa.

## Profiling on/off

Ricalcolo prespecificato: mediana delle due richieste per arm/blocco, rapporto on/off nello stesso blocco, mediana dei quattro rapporti. I tempi `X-Tempo-Ms` sono trattati come decimali esatti durante il ricalcolo.

| Scena | Rapporti nei quattro blocchi | Mediana | Variazione |
| --- | --- | ---: | ---: |
| Einstein | 1,039221 / 0,992804 / 1,033429 / 0,999921 | 1,016675 | +1,67% |
| Curie | 0,988931 / 1,002420 / 0,986425 / 1,127058 | 0,995676 | −0,43% |
| Turing | 1,047146 / 1,034303 / 0,983391 / 1,093357 | 1,040724 | +4,07% |

Queste oscillazioni non permettono di stimare con precisione un overhead generale. Il confronto riguarda il flag nella stessa copia, non l'intera patch rispetto al runtime mantenuto. Una sola famiglia e tre scene fisse; nessun campione è stato eliminato.

## Fasi e livelli

Mediane dei 24 profili misurati on. La frazione è calcolata **per query**, rispetto al suo evaluate, e poi riassunta con una mediana: non è il rapporto fra due mediane.

| Fase | Mediana ms | Mediana frazione per query |
| --- | ---: | ---: |
| Score | 6,346708 | 0,322638% |
| Head/estrazione | 805,403938 | 41,439807% |
| Torneo | 1087,256000 | 55,899874% |
| Finale | 44,294250 | 2,281485% |

Evaluate mediano: **1928,047334 ms**. Gap calcolato per query: mediana **0,486647 ms**, ossia **0,024639%**. Le mediane di colonne diverse non sono additive. Head e torneo sono le fasi dominanti; non segue alcun risparmio già dimostrato.

I sette livelli sono presenti in tutti i 24 profili misurati. Mediane ms, nell'ordine 120/60/30/15/8/4/2: **464,654438 / 250,615459 / 131,413521 / 95,884167 / 53,261188 / 45,289979 / 44,310167**. Sono già inclusi nel torneo, quindi non vanno sommati nuovamente alle quattro fasi.

Fonti dirette: `samples.jsonl` SHA256 `9d7c33e5c5349a580b297f6e70fde08b213e0d69e4f2b0191af3f57c9b1dfb1f`; `events.jsonl` `1cd29be4c7662d2819a520e60d2c1ec23569c6e0287b1e884397cbb4dd91ed2e`; `COMPLETE.json` `915aced854983582525c7714e90ce88b317526e04e15bdbc1dcc0fdc33d5498b`. Hash dei 72 trace HTTP e dei due JSONL confrontati con quelli registrati nel receipt. Nessuna lettura di payload chiave/ciphertext, nuova prova del rumore o garanzia su errori rari/biometria.
