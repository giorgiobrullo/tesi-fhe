# Lettura delle fonti sui sistemi biometrici e sull'argmax

Verifica del 19 settembre 2026. Le pagine indicate sono quelle del PDF consultato, oppure del manoscritto autore quando specificato. Sono state lette le sezioni pertinenti a protocollo, assunzioni e valutazione; questo lavoro non costituisce una verifica integrale delle dimostrazioni né una riproduzione degli esperimenti. Le conclusioni per la tesi sono inferenze dell'audit.

## HEFT, Sperling et al., IJCB 2022

**Accesso:** [PDF autore, 10 pagine](https://hal.cse.msu.edu/assets/pdfs/papers/2022-ijcb-heft-encrypted-biometric-template-fusion.pdf) e [supplemento, 2 pagine](https://hal.cse.msu.edu/assets/pdfs/papers/2022-ijcb-heft-encrypted-biometric-template-fusion-supp.pdf) recuperati. Identificazione bibliografica: [arXiv 2208.07241](https://arxiv.org/abs/2208.07241). Tabella 3 verificata anche visivamente.

Il server concatena i template cifrati, applica una proiezione pubblica appresa, approssima la normalizzazione e calcola gli score CKKS. Il client riceve e decifra gli score per l'elaborazione successiva: è esplicito in Figura 1, p. 2, e §3.2, p. 4. Il training della proiezione avviene in chiaro; §3.4, pp. 6–7, adatta la loss alla normalizzazione approssimata.

L'esperimento unisce artificialmente identità face/voice, separando le classi tra training, validazione e test (§4.1, p. 7). Il supplemento, §2, p. 2, limita l'approssimazione a [0,05; 3,00] e scarta durante l'epoca di training i campioni fuori intervallo: non fornisce una garanzia universale sugli ingressi futuri.

I tempi richiedono cautela: abstract e conclusione indicano 884 ms con gallery 1024; Tabella 3, p. 8, riporta 1127,85 ms di fusione e 4,87 ms per score nella configurazione di grado 2; §4.1 indica 1028 campioni di test. La discrepanza non è risolta qui.

**Inferenza per la tesi:** è un riferimento per fusione, packing e apprendimento compatibile con FHE. Non documenta un output limitato a `0/ID`; il suo tempo riassuntivo non va impiegato per rivendicare uno speedup.

## Akbari et al., TBIOM 2025

**Accesso completo:** consultato il PDF editoriale di 15 pagine,
IEEE TBIOM 7(4), pp. 573–587, [DOI 10.1109/TBIOM.2025.3595438](https://doi.org/10.1109/TBIOM.2025.3595438).
La nuova [lettura dell'edizione pubblicata](akbari-edizione-pubblicata.md)
sostituisce il precedente limite al manoscritto indicizzato e riporta le
pagine editoriali esatte. Client onesti con chiavi comuni e restituzione
degli score al client restano confermati.

Il controllo visivo conferma la discrepanza temporale: la Tabella III misura
1127,85 ms di fusione e 4,87 ms **per match**. Il prodotto 4,87×1028
ricostruisce i 5006 ms di matching citati nell'introduzione; non spiega
l'affermazione conclusiva di 1150 ms per fusione e intera galleria.
La ricostruzione aritmetica non è un nuovo benchmark.

La Tabella II usa TMR a FMR 1%; le ablation nelle Figure 11–12 usano invece
AUROC. La precedente distinzione rispetto al lavoro 2022 non deve diventare
un'affermazione che AUROC sia assente dal journal. Rimangono da conservare
il disturbo aggiunto alle feature face/fingerprint e la natura delle bande
0,3 sigma. Non ne deriva un nearest-ID cifrato con sola uscita 0/ID.

## HEArgmax, Nguyen et al., Computer Standards & Interfaces 2026

**Accesso completo:** PDF editoriale di 11 pagine, incluse le sezioni A.1–A.3
alle pp. 10–11. [DOI 10.1016/j.csi.2025.104071](https://doi.org/10.1016/j.csi.2025.104071).
Il preprint SSRN di 34 pagine non è necessario per considerare completo
questo documento pubblicato.

La [lettura dei protocolli e dell'appendice](heargmax-edizione-pubblicata.md)
conferma il confronto interattivo con decifrazione e ricifratura da parte
del client. Fa però emergere problemi nella giustificazione di privacy:
il mascheramento reale moltiplicativo non è dimostrato come one-time pad,
e le permutazioni conservano informazioni sui ranghi oltre l'argmax.
La scheda contiene controesempi aritmetici ideali e ne delimita la portata;
non dichiara un attacco eseguito sul codice CKKS.

Pareggi, margini numerici, packing e contabilità delle comunicazioni
richiedono chiarimenti. I tempi sommano il calcolo di client e server
escludendo il ritardo di rete. Il lavoro resta prior art dell'approccio
interattivo, ma non va citato come garanzia già validata di esattezza e
privacy generale o come confronto numerico omogeneo con la tesi.

## SCiFI, Osadchy et al., IEEE S&P 2010

**Accesso:** [PDF dal sito di Benny Pinkas, 16 pagine](https://www.pinkas.net/PAPERS/scifi.pdf), recuperato. Pagine PDF 8 e 16 verificate anche visivamente; nessuna ri-esecuzione della crittografia.

§IV.B–C, pp. 7–8, distingue `Fthreshold`, che restituisce tutti gli indici entro soglie individuali, da `Fmin+t`, che seleziona il vicino minimo e lo sottopone a soglia. Il testo dichiara di aver implementato soltanto `Fthreshold`. I protocolli combinano cifratura omomorfa, decrittazione di distanze mascherate e oblivious transfer; la sicurezza assume parti semi-honest (§IV.C, p. 9). §IV.G, p. 11, distingue espressamente le ulteriori esigenze contro partecipanti malevoli.

L'appendice, p. 16, descrive un torneo per il minimo, permutazione degli ingressi e successivo controllo della soglia; rinvia i dettagli delle soglie individuali a una versione estesa. Inoltre menziona l'uscita di distanza minima e indice, mentre la definizione di p. 8 indica l'indice: non basta per attribuirle automaticamente il nostro contratto preciso.

§VI.B, pp. 13–14, misura `Fthreshold` con risultato al server: circa 31 secondi online per 100 template, oltre al preprocessing, usando Paillier con modulo di 1024 bit.

**Inferenza per la tesi:** minimo con soglia ha un precedente esplicito; la sua formulazione non è una novità nostra. Restano distinti implementazione misurata, funzionalità proposta, interazione, output rivelato e parametri storici.

## Accesso risolto e questioni scientifiche residue

Tutti e quattro i lavori di questa scheda sono ora disponibili in PDF,
con supplemento HEFT e appendice SCiFI. Non occorrono altri file per
completare questo gruppo di letture mirate.

Restano questioni scientifiche distinte dall'accesso: spiegare i tempi
riassuntivi HEFT/Akbari; chiarire o correggere specifica, analisi e parametri
HEArgmax; ricostruire la variante SCiFI con soglie individuali soltanto se
necessaria al confronto. Le versioni estese eventualmente utili non sono
implicitamente comprese nella verifica delle edizioni qui identificate.
