# Profilo di un merge designato — 4 ottobre 2026

Nel nodo osservato il confronto occupa **44,67–55,83%** del tempo, mentre le PFKS occupano **4,81–5,72%**. Sono intervalli osservati su tre query, utili a localizzare il costo dentro un merge. Il primo livello esegue 60 merge in parallelo: questi tempi del singolo worker includono ritardi di scheduling e non vanno moltiplicati per 60 o sommati fra worker.

[Quattro campioni](samples.csv), [riepilogo](SUMMARY.json), [protocollo](PROTOCOL.md) e [review dei risultati](review/INDEPENDENT_REVIEW.md). La sequenza è un warmup e tre misure. I cinque intervalli appartengono a un solo nodo del primo livello; il nodo è già incluso nel tempo del livello e del torneo. Il risultato non è un confronto appaiato con le altre campagne.

Sono inclusi [driver](driver/merge_http.py), [controlli originali](driver/test_merge_http.py), [spec effettivo](driver/spec.json), [template](driver/spec.template.json), [costruzione](driver/build_profile.py) e [preparazione chiavi](driver/keygen_profile.py). La mappa comprende i 134 file del workspace e i due helper del driver. [Manifest congelato](receipts/SOURCE_AFTER_BINDINGS.json), [build](receipts/build.json), [strumentazione](review/IMPLEMENTATION.md) e [review del sorgente](review/SOURCE_REVIEW.md) legano il profilo alla copia precisa.

Il [primo errore preparatorio](receipts/PREPARATION_FAILURE.json) riguardava un'asserzione testuale del controllo, prima delle query; è conservato. Per ricollocare il driver vanno aggiornati `HELPER_PATH` e il `BASE_PATH` del [profilatore](../core-profile-20261004/driver/profile_http.py), che a sua volta importa il [driver HTTP](../tfhe-181-20261004/driver/paired_http.py). Se si cambia il primo helper, il suo SHA nel consumer va aggiornato e registrato come nuova preparazione.

## Sorgenti e riproduzione

La [mappa dei sorgenti](PROVENANCE.json) ricostruisce il workspace usando i file specifici in `source/` e quelli condivisi nella repo, identificati con SHA-256. I documenti del workspace con suffisso `.md.txt` conservano i byte originali. Lo stesso manifesto conserva provenienza e impronte dei file distribuiti.

Dal repository si può verificare la mappa senza eseguire l'esperimento:

```sh
python3 tools/materialize_sources.py --map benchmark/merge-profile-20261004/PROVENANCE.json --dry-run
```

Con `--output /percorso/nuovo/fuori-repo` al posto di `--dry-run`, il comando ricostruisce i file senza installare dipendenze o eseguire i driver. La [ricetta degli input](../inputs/web-query-n120-d512.json) specifica ambiente e fixture vettoriali da fornire; foto, pesi, chiavi e cifrati non sono distribuiti. Per eseguire una replica occorre adattare i percorsi assoluti dei driver, compilare con le impostazioni registrate e generare chiavi proprie. Usare una nuova directory per ricevute e risultati.
