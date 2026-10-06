# Verifica indipendente del merge designato

4 ottobre2026. Sola aritmetica sui record e confronto degli header; nessuna importazione del driver, esecuzione nativa, decifratura o modello precedente. `COMPLETE.json` riporta PASS, senza fault, e il riepilogo coincide con i dati grezzi.

Sequenza esatta: warmup Einstein, poi una misura Einstein/Curie/Turing. Quattro record corretti con ID registrati **1/1/2/3**, uguali all'oracolo e alla ricostruzione delle tre cifre. Un solo avvio PID93408, stop dello stesso PID con −15 e `unexpected_prior_exit=false`, evento di validazione4. È controllo dei log, non nuova osservazione OS.

I quattro header JSON coincidono con i profili nei campioni; timer HTTP/server e hash richiesta/risposta corrispondono. Verificati anche gli hash effettivi dei quattro file di risposta cifrata e dei trace HTTP. Binario, circuito, chiave e fingerprint dei parametri sono identici nei quattro record; Einstein riusa lo stesso input nel warmup e nella misura.

Tutti i nodi: schema v1, N120, ready60, livello0/indice0, **4 payload/1 gruppo**, completed=true, internal_parallel=false. I cinque tempi sono positivi; la loro somma è minore del node wall e il gap coincide esattamente con la differenza. Ogni nodo sta nel proprio primo livello, senza usare tolleranze. Gap delle tre misure: **9,333 / 8,793 / 9,209 µs**.

Quote calcolate sul node wall **di ciascuna query**, poi riassunte; le mediane non sono additive.

| Intervallo | Mediana ms | Range ms | Mediana quota nodo | Range quota nodo |
| --- | ---: | ---: | ---: | ---: |
| Confronto | 43,161416 | 42,851125–51,488792 | 50,8817% | 44,6691–55,8285% |
| Prepare control | 16,715584 | 16,565042–30,285875 | 21,5817% | 16,5185–31,3438% |
| PFKS | 4,650666 | 4,329167–5,783416 | 5,6402% | 4,8131–5,7152% |
| Packing + rotazione | 18,508709 | 12,991625–27,186666 | 19,1552% | 16,9261–26,8661% |
| Estrazione + addback | 0,009000 | 0,008666–0,009958 | 0,00984% | 0,00931–0,01129% |

Node wall misurati: **76,754958 / 101,193209 / 96,624875 ms**. Sono intervalli wall dello stesso worker, con eventuali attese di scheduling. Packing+rotation include BR; non isola il costo delle allocazioni. Non moltiplicare il nodo per60 o sommarlo ai livelli/torneo.

Tempi servizio **1617,0 / 1645,9 / 1700,1 ms**: campagna, famiglia, copia compilata e condizioni di carico diverse dal confronto precedente. **Non sono uno speedup appaiato né una nuova baseline equivalente.** Campione di tre nodi misurati, non garanzia statistica o sugli errori rari.

Fonti SHA256: samples `271ecc35bd5b984d432bf11467525bb14d707070036054c88bde2f1470f8bf95`; events `3b2ad74e14636b5bb77c976d9a0b16e1e9d1e607dd0337abbc14adf41df3043e`; COMPLETE `6db90f6415d16512fb221f01270e87ee0dca0481956b26d365c2bc1a65efe363`. Nessun dato originale o sorgente modificato.
