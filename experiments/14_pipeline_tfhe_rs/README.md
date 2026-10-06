# 14 — Costruire la risposta cifrata 0/ID in TFHE-rs

Nel [passo 13](../13_tfhe_rs_headtohead/README.md) l'argmin era veloce ma
il calcolo degli score con l'API intera dominava il tempo. Qui si sviluppa
una pipeline più completa: query cifrata, galleria pubblica, score calcolati
con primitive a basso livello, scelta del **primo minimo**, verifica della
**soglia del vincitore** e una sola risposta cifrata: `0` per il rifiuto,
altrimenti il suo ID. Il client decifra soltanto quel codice.

Per esempio, con score `21` per ID 1 e `26` per ID 2, il vincitore è ID 1.
Se la sua soglia è `20`, il risultato è `0` anche se ID 2 avrebbe superato
una soglia più permissiva. Il [confronto illustrato](../../docs/come-funziona-il-confronto.md)
segue l'intero passaggio fino al risultato.

Il [registro dei risultati](RISULTATI.md) copre **più prototipi nel tempo**.
Il ramo si sviluppa in questi passaggi:

| Passaggio | Che cosa cambiava | Stato nel registro |
|---|---|---|
| A23 | Primo argmin, soglia del vincitore e risposta 0/ID. | [Costruzione e prove](../../docs/risultati/catalogo-tentativi-a.md#a23). |
| A28 | Estrazione split4 del contratto 0/ID, con score, torneo e soglia del vincitore. | Implementazione congelata e prove proprie. |
| A29 | Estrazione con più uscite dalla stessa tabella cifrata; percorso generale di riserva. | Controlli e confronto appaiato con A28. |
| A33 | Percorso più rapido quando la soglia è comune e il dominio degli score è allineato. | Promosso **solo** per quelle condizioni; A29 resta per gli altri ingressi validi. |
| A34/A36 → A38 | Nuova codifica dell'uscita e successiva integrazione. | Prima componenti isolate, poi [pipeline A38 verificata](../../docs/risultati/catalogo-tentativi-a.md#a38). |
| A41/A44 → A62/A66 | Riduzioni dello stato e della scansione, poi parallelismo. | [Esiti delle versioni](../../docs/risultati/catalogo-tentativi-a.md#a41), inclusi i confronti appaiati. |
| PFKS e Head → servizio | Nuove rappresentazioni e composizione completa, con correzioni dei primi negativi. | [Sequenza dei componenti](../../docs/risultati/tentativi-a.md#pfks) e [pacchetto 17](../17_head_pfks_tfhe17/README.md). |

Lo stesso registro contiene tentativi antecedenti al contratto 0/ID,
microbenchmark, prove sul rumore e analisi del protocollo. Le sezioni
storiche che chiamano A33 «corrente» descrivono **quel checkpoint**; non la
baseline oggi mantenuta. In questa prova la risposta era un singolo big-LWE;
il [core successivo](../17_head_pfks_tfhe17/README.md) impiega una diversa
estrazione e trasporta cifre ID cifrate. Non si devono mescolare tempi o
conteggi di queste due versioni.

Per orientarsi nei sorgenti: [`private_argmin.rs`](src/private_argmin.rs)
contiene il percorso crittografico condiviso dai benchmark e dal servizio
storico [`varco_demo.rs`](src/bin/varco_demo.rs); il
[registro](RISULTATI.md) indica per ogni prova il binario e l'evidenza.
Per la versione mantenuta partire dal [runtime](../../runtime/README.md).
Le altre revisioni A, comprese quelle scartate, sono recuperabili dal
[pacchetto dei sorgenti A](../attempts-a/README.md). Il ricostruttore conserva
gli alberi delle versioni originali e riusa i file identici, evitando una
nuova copia del medesimo sorgente per ogni tentativo.
