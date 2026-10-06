# TFHE-rs 1.7.0 / 1.8.1 — 4 ottobre 2026

Tutte le **216 query** restituiscono l'ID atteso. Nelle tre scene, il rapporto gerarchico dei tempi 1.8.1/1.7.0 indica **0,88–2,09% di tempo in più** per 1.8.1. Il risultato riguarda questo servizio e queste condizioni; non dimostra una regressione generale della libreria.

[216 campioni](samples.csv), [riepilogo](SUMMARY.json), [protocollo](PROTOCOL.md) e [review dei risultati](review/RAW_RESULTS_REVIEW.md). Sono 72 warmup e 144 misure in tre coppie di famiglie, con quattro blocchi AB/BA per coppia. Il timer principale misura il servizio; non include acquisizione e embedding della demo. Le tre scene e le ripetizioni non sono famiglie indipendenti; le chiavi sono generate separatamente per versione e non sono identiche fra i bracci. Non viene stimato un intervallo di confidenza. Il carico desktop è incontrollato; tutti i campioni sono inclusi, anche nei blocchi iniziali sovrapposti a controlli preparatori leggeri.

Il [driver eseguito](driver/paired_http.py), i [controlli originali](driver/test_paired_http.py) e il [template](driver/spec.template.json) accompagnano i sorgenti completi identificati dal [manifest congelato](receipts/SOURCE_SNAPSHOTS.json): 134 file per ciascun braccio. La mappa materializza i workspace in `runtimes/baseline` e `runtimes/candidate`, riutilizzando tutti i file identici. Le ricevute [baseline](receipts/build-baseline.json) e [candidate](receipts/build-candidate.json) conservano le impostazioni Rust 1.98.1 uguali e i due binari.

Il [primo lancio fallito](receipts/FIRST_LAUNCH_FAILURE.md) usava Python 3.9 senza `hashlib.file_digest`; fallì prima delle query. Sono preservati [spec iniziale](driver/spec.first.original.json) e [spec valido](driver/spec.valid.original.json), che cambia soltanto la directory di output. Per la replica usare Python 3.12. La nota conserva anche il mancato blocco del primo lancio dopo un errore della suite preparatoria, senza eliminare campioni o presentarlo come errore numerico.

## Sorgenti e riproduzione

La [mappa dei sorgenti](PROVENANCE.json) ricostruisce il workspace usando i file specifici in `source/` e quelli condivisi nella repo, identificati con SHA-256. I documenti del workspace con suffisso `.md.txt` conservano i byte originali. Lo stesso manifesto conserva provenienza e impronte dei file distribuiti.

Dal repository si può verificare la mappa senza eseguire l'esperimento:

```sh
python3 tools/materialize_sources.py --map benchmark/tfhe-181-20261004/PROVENANCE.json --dry-run
```

Con `--output /percorso/nuovo/fuori-repo` al posto di `--dry-run`, il comando ricostruisce i file senza installare dipendenze o eseguire i driver. La [ricetta degli input](../inputs/web-query-n120-d512.json) specifica ambiente e fixture vettoriali da fornire; foto, pesi, chiavi e cifrati non sono distribuiti. Per eseguire una replica occorre adattare i percorsi assoluti dei driver, compilare con le impostazioni registrate e generare chiavi proprie. Usare una nuova directory per ricevute e risultati.
