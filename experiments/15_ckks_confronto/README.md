# 15 — Primo confronto del calcolo di soglia con CKKS

L'[esperimento 14](../14_pipeline_tfhe_rs/README.md) usa TFHE per una
decisione esatta. Qui si prova CKKS, che consente di lavorare su molti
valori nello stesso cifrato ma produce risultati **approssimati**. La
domanda di questa prima prova era quanto costasse calcolare gli score e
verificare **per ogni candidato** se `score_i ≤ soglia`.

Il programma [`ckks_varco.py`](ckks_varco.py) riceve una query cifrata e una
galleria pubblica di vettori da 512 dimensioni. Dispone più candidati negli
slot CKKS, calcola gli score e usa un polinomio per approssimare il segno
del confronto con la soglia. A N=128, le quattro configurazioni del
[report F39](RISULTATI.md) richiedono circa **1,01–4,44 s**, a seconda del
polinomio. In 4096 confronti per candidato sulle scene provate non furono
osservate discrepanze e l'errore numerico degli score fu ≤0,03.

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
prova storica. I tempi non includono la demo foto → risposta.
