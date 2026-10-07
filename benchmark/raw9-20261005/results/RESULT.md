# Variante raw9 nella pipeline completa: esiti corretti, vantaggio totale piccolo

Risultato osservato il 2026-10-05T05:21:23.439800+00:00. Un solo build offline (exit0) e una sola esecuzione locale completa (exit0), una famiglia di chiavi nuova, 16 thread/Dif4. Ogni versione ricalcola punteggi, Head e tutti i livelli precedenti; condivide soltanto chiavi e input cifrati, come previsto.

Tutti i sei casi hanno superato il controllo iniziale per entrambe le versioni: Einstein1, Curie2, Turing3, vincitore nel ramo destro83, query zero rifiutata0, pareggio tra ID1/65 risolto con ID1. Il driver verifica 54 esiti: 12 iniziali, 6 di warmup, 36 temporizzati. I log mostrano singolarmente 48 ID; i 6 warmup sono verificati nel driver e conteggiati nel record finale.

| Input | Intera valutazione: baseline → raw9 (ms, mediane) | Variazione appaiata mediana | Ultimo stadio: baseline → raw9 (ms, mediane) | Variazione appaiata mediana |
|---|---:|---:|---:|---:|
| einstein | 1666.39 → 1649.71 | -0.8135% | 84.08 → 71.41 | -14.9037% |
| curie | 1658.78 → 1652.49 | -0.2297% | 85.71 → 72.57 | -15.7933% |
| turing | 1663.55 → 1653.86 | -0.0069% | 85.88 → 72.05 | -15.9158% |

Ogni input ha sei coppie con ordini bilanciati. Raw9 riduce il tempo dell’ultimo stadio in 18/18 coppie; sull’intera valutazione è più veloce in 5/6, 4/6 e 3/6 coppie. Le variazioni appaiate complessive cambiano segno e restano sotto l’1% nelle mediane per input. Il 15–16% osservato riguarda quindi soltanto lo stadio terminale. Le due mediane marginali non vanno usate per ricostruire la variazione appaiata o sommate ad altre mediane.

I log verificano entrambi i ledger completi e le route effettive. Baseline: 1111 BR/1080 KS/509 PFKS/1709 estrazioni più120 campioni iniziali; raw9:1113/1083/507/1710 più120. Tutti i15 campi del lavoro terminale concordano:11/10/7/15 →13/13/5/16 per BR/KS/PFKS/estrazioni, con9 callback effettivi contro6 e tre confronti Parallel3 contro due. Nessun reset durante il torneo.

Conclusione: la variante ha superato questi controlli cifrati con gli intermedi prodotti dalla pipeline completa. Resta un esperimento locale; questo piccolo vantaggio totale, non uniforme, non giustifica sostituire la baseline o aggiornare i grafici. Non ripetere il benchmark terminale già chiuso.

Il tempo è quello della valutazione diagnostica: include validazione/strumentazione/report; esclude factory reset, generazione chiavi, cifratura, decodifica e stampa. Lo stadio terminale parte dopo snapshot/setup. Non è un tempo HTTP/browser o e2e, né una rimisurazione comparabile al precedente grafico. Una famiglia e questi casi finiti non dimostrano un limite di fallimento, sicurezza o errore biometrico1%.

Evidenze: root/NATIVE_CAPTURE.json e NATIVE_SESSION.json (PID38556, observer38555, session28594, terminale2026-10-05T05:17:27.711602UTC); root/RESULT_SUMMARY.json e ANALYZE.py; root/NATIVE.stdout.log (29 righe pubbliche), stderr vuoto. Binary2227184B/SHA2565f0e8bcabef1342dfaba8374a604a3300d624e9fc3746c2e1cfa3319e0f25efc; source86 aed7ea6b7192fe9f638201afaf6802e9aabe04376c17c0882c59b58349bef32d; seal103 a51851d469c9d47f2931273f577cfafe2ef17274ac0e7f154fa388c62303d278. FINAL_POSTCHECK conferma W134/protected4 e nessun processo progetto/build corrispondente; nessun controllo di processi o modifica remota. Review indipendente del risultato in chiusura.
