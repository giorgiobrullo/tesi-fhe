# 15 — Primo confronto del calcolo di soglia con CKKS

L'[esperimento 14](../14_pipeline_tfhe_rs/README.md) usa TFHE per una
decisione esatta. Qui si prova CKKS, che consente di lavorare su molti
valori nello stesso cifrato ma produce risultati **approssimati**. La
domanda di questa prima prova era quanto costasse calcolare gli score e
verificare **per ogni candidato** se `score_i ≤ soglia`.

Il programma [`ckks_varco.py`](ckks_varco.py) riceve una query cifrata e una
galleria pubblica di vettori da 512 dimensioni. Dispone più candidati negli
slot CKKS, calcola gli score e usa un polinomio per approssimare il segno
del confronto con la soglia. Il [primo report F39](RISULTATI.md) conserva
quattro configurazioni e i loro tempi storici, ma **non è la baseline
corretta**: l'intervallo degli score usato per costruire il confronto era
ricavato dalle stesse query poi valutate. Così la zona vicina alla soglia
appariva più stretta di quanto consentisse il dominio dichiarato.

Il [rerun corretto](results/ckks_rerun_2026-09-01.md) usa un limite ricavato
da galleria e coordinate ammesse della query. Nella configurazione minima,
a N=128 misura **0,9969 s per gli score + 0,048 s per la soglia** su quattro
query. I 512 confronti verificati concordano con il calcolo in chiaro, ma
la fascia in cui il polinomio non distingue affidabilmente i lati della
soglia si allarga a **[−1381, 1382]** unità. Quattro query non stimano la
qualità biometrica del rifiuto.

Questo **non è** un confronto dell'identificazione 0/ID completa. L'uscita
del programma è un insieme di decisioni di soglia, una per iscritto; manca
la scelta del primo minimo e della **sola** soglia del vincitore. Zero
discrepanze finite non dimostrano neppure esattezza CKKS per tutti gli input.
Il [valutatore CKKS successivo](../23_ckks_ottimizzazioni/README.md) studia
la pipeline 0/ID approssimata; il
[confronto CKKS/TFHE rimisurato](../../output/figures/ckks-tfhe/selettore-corretto-20260920/LEGGIMI.md)
è un'altra campagna, con contratti e condizioni dichiarati lì.

Il [report originale](RISULTATI.md), lo [script](ckks_varco.py) e la
[variante di packing](ckks_packing_forte.py) conservano i dettagli di questa
prova storica. La variante di packing misura **solo gli score**. I tempi
non includono la demo foto → risposta.
