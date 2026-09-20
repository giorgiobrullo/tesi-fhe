# Demo di riconoscimento facciale cifrato

La [demo client/server](dual_view/README.md) è il punto di ingresso per
provare il progetto. La pagina server gestisce la galleria; la pagina client
acquisisce una foto o usa la fotocamera e mostra accesso consentito o negato.
La galleria parte vuota.

Il motore cerca il primo minimo esatto e applica la soglia del vincitore.
La risposta cifrata rappresenta `0` per un rifiuto oppure l'ID accettato.
La pagina client decifra il risultato; fotografie d'iscrizione, template
e soglie della galleria restano visibili al server.

## Da dove iniziare

| Obiettivo | Guida |
|---|---|
| Installare e avviare le due pagine | [Demo client/server](dual_view/README.md) |
| Compilare e modificare il servizio | [Runtime mantenuto](../runtime/README.md) |
| Capire algoritmo e risultati misurati | [Esperimento 22](../experiments/22_demo_composita/README.md) |
| Consultare API e limiti del circuito | [Contratto del core](../runtime/core/README.md) |
| Eseguire i test o rigenerare i grafici | [Riproducibilità](../docs/riproducibilita.md) |
| Leggere il percorso precedente A28/A29/A33 | [Guida storica del 1–2 settembre](README-storico.md) |

## Versione della demo

La demo attuale usa il runtime derivato dal pacchetto 22, TFHE-rs 1.7 e la modalità
`public_parallel`: ingresso full51/low60 e risposta di tre LWE, con ID
in base 15. Il dominio ammette fino a 3374 voci; i risultati pubblicati
riguardano le dimensioni delle rispettive campagne, non l'intera capienza.

I file `config.json`, `client/` e `docker-compose.yml` in questa cartella
appartengono alla demo precedente dell'esperimento 14, full52 e una LWE.
La guida storica ne conserva configurazione, prove e limiti.
Per l'avvio corrente seguire `dual_view/`, che usa il proprio client e il
runtime mantenuto in `runtime/`. I tempi pubblicati restano associati ai
sorgenti congelati dell'esperimento 22.

La demo è destinata all'esecuzione locale con un terminale fidato.
Il [modello di fiducia](../README.md#modello-di-fiducia) descrive le ipotesi
necessarie e le informazioni protette.
