# Profilo delle fasi del motore — 4 ottobre 2026

Il torneo e l'estrazione assorbono la maggior parte del tempo del core: le mediane delle quote per query sono **55,90%** e **41,44%** nelle 24 richieste misurate con profilo attivo. Le quote sono calcolate per richiesta; non sono rapporti tra mediane marginali. Il confronto on/off valuta l'effetto del flag di profilazione nella stessa copia strumentata.

[72 campioni](samples.csv), [riepilogo](SUMMARY.json), [protocollo](PROTOCOL.md) e [review dei risultati](review/INDEPENDENT_REVIEW.md). Sono 24 warmup e 48 misure: quattro blocchi off/on alternati, tre scene, una famiglia di chiavi. Non misura il costo dell'intera patch rispetto alla demo, né fornisce repliche fra famiglie o una distribuzione della latenza. Il carico desktop resta incontrollato e nessun campione è escluso.

Il [driver eseguito](driver/profile_http.py), i [controlli offline originali](driver/test_profile_http.py), lo [spec effettivo](driver/spec.json) e il [template](driver/spec.template.json) sono conservati. La mappa comprende tutti i 134 file del workspace nel [manifest congelato](receipts/SOURCE_AFTER_BINDINGS.json), i quattro file del driver e il suo helper. La [ricevuta build](receipts/build.json) fissa compilatore e opzioni. La [correzione preparatoria](receipts/PREPARATION_CORRECTION.json) conserva l'adeguamento delle fixture dei test al metadata configurato.

Il driver dipende dal [driver HTTP appaiato](../tfhe-181-20261004/driver/paired_http.py), pinnato nel sorgente: in una replica ricollocare `BASE_PATH` mantenendo il relativo SHA. Python 3.12 e lo spec compilato restano necessari; il protocollo descrive ordine, controlli e limiti. I tempi dei livelli sono già inclusi nel torneo.

## Sorgenti e riproduzione

La [mappa dei sorgenti](PROVENANCE.json) ricostruisce il workspace usando i file specifici in `source/` e quelli condivisi nella repo, identificati con SHA-256. I documenti del workspace con suffisso `.md.txt` conservano i byte originali. Lo stesso manifesto conserva provenienza e impronte dei file distribuiti.

Dal repository si può verificare la mappa senza eseguire l'esperimento:

```sh
python3 tools/materialize_sources.py --map benchmark/core-profile-20261004/PROVENANCE.json --dry-run
```

Con `--output /percorso/nuovo/fuori-repo` al posto di `--dry-run`, il comando ricostruisce i file senza installare dipendenze o eseguire i driver. La [ricetta degli input](../inputs/web-query-n120-d512.json) specifica ambiente e fixture vettoriali da fornire; foto, pesi, chiavi e cifrati non sono distribuiti. Per eseguire una replica occorre adattare i percorsi assoluti dei driver, compilare con le impostazioni registrate e generare chiavi proprie. Usare una nuova directory per ricevute e risultati.
