# Demo di riconoscimento facciale cifrato

Le demo mostrano un percorso completo: da una foto a una richiesta cifrata,
fino all'identità riconosciuta o al rifiuto. **FHE** significa cifratura
omomorfa: il motore esegue il confronto sulla richiesta ancora cifrata.

La [demo web](web/README.md) offre una pagina unica con 120 ritratti iniziali,
sessioni individuali e registro delle verifiche. La
[demo client/server](dual_view/README.md) separa invece la gestione della
galleria e la richiesta d'accesso in due pagine, partendo da una galleria vuota.

La foto viene trasformata in un vettore di numeri, detto **template** quando
è conservato nella galleria. Il motore confronta la richiesta con gli iscritti
e cerca il minimo esatto: vince il punteggio più basso e, a parità, la prima
voce della galleria.
Applica poi la soglia del solo vincitore: un punteggio entro quella soglia
consente l'accesso, altrimenti lo rifiuta.
La risposta cifrata rappresenta `0` per un rifiuto oppure l'ID accettato.
Il componente client decifra il risultato; fotografie d'iscrizione, template
e soglie della galleria restano visibili al server. Nella demo web ospitata
il client gira anch'esso sul server: l'operatore può quindi leggere anche
le foto delle prove e gli esiti. Le sessioni separano i dati dei visitatori
a livello applicativo.

## Da dove iniziare

| Obiettivo | Guida |
|---|---|
| Usare una pagina unica con galleria iniziale e registro delle richieste | [Demo web con sessioni individuali](web/README.md) |
| Installare e avviare le due pagine | [Demo client/server](dual_view/README.md) |
| Seguire un confronto dall'ingresso al risultato, con un esempio numerico | [Guida illustrata al confronto](../docs/come-funziona-il-confronto.md) |
| Compilare e modificare il servizio | [Runtime mantenuto](../runtime/README.md) |
| Leggere la composizione del motore e i risultati misurati | [Esperimento 22](../experiments/22_demo_composita/README.md) |
| Consultare API e limiti del circuito | [Contratto del core](../runtime/core/README.md) |
| Eseguire i test o rigenerare i grafici | [Riproducibilità](../docs/riproducibilita.md) |
| Leggere il percorso precedente A28/A29/A33 | [Guida storica del 1–2 settembre](README-storico.md) |

## Versione della demo

I sorgenti della demo attuale usano il runtime derivato dal pacchetto 22,
TFHE-rs 1.7 e la modalità
`public_parallel`: ingresso full51/low60 e risposta di tre LWE, con ID
in base 15. Full51/low60 indica le codifiche numeriche dell'ingresso; le LWE
sono i valori cifrati che trasportano il risultato. Il dominio ammette fino a
3374 voci; i risultati pubblicati riguardano le dimensioni delle rispettive
campagne, non l'intera capienza.
Il limite dell'interfaccia web è descritto nella sua guida. La versione
installata di un servizio ospitato dipende dal suo ultimo aggiornamento.

I file `config.json`, `client/` e `docker-compose.yml` in questa cartella
appartengono alla demo precedente dell'esperimento 14, full52 e una LWE.
La guida storica ne conserva configurazione, prove e limiti.
Per l'avvio corrente seguire una delle due guide sopra, entrambe basate sul
runtime mantenuto in `runtime/`. I tempi storici del servizio restano
associati ai sorgenti congelati dell'esperimento 22.

La variante client/server è destinata all'esecuzione locale con un terminale fidato.
Il [modello di fiducia](../README.md#modello-di-fiducia) descrive le ipotesi
necessarie e le informazioni protette.
