# Tempo POST → SSE della demo — 4 ottobre 2026

Le tre richieste misurate si completano in **2,103 / 2,104 / 2,238 secondi** dal POST all'evento SSE, con quattro esiti corretti contando il warmup. Il timer include upload, preparazione della foto, inferenza, cifratura, servizio FHE e consegna dell'esito.

[I campioni](samples.csv) e il [riepilogo](SUMMARY.json) descrivono un warmup e tre fotografie misurate nella stessa sessione. L'intervallo parte prima dell'invio POST e termina al primo evento SSE completo della richiesta corrispondente. Non include avvio, acquisizione webcam o tempo del browser; non è una stima di accuratezza biometrica o della distribuzione di latenza. Il carico desktop è incontrollato e questa campagna non misura una differenza fra versioni TFHE.

Il [driver effettivo](driver/driver.py) e il [driver preparatorio](driver/driver-first.py.txt) conservano la logica archiviata, con i percorsi personali normalizzati nelle copie pubbliche. Le impronte precedenti e pubblicate sono nel [registro](../../docs/provenienza-dati.json). La differenza tra i due driver è il controllo dell'ordine ACK/SSE: entrambi devono seguire l'invio, ma il ricevimento dell'ACK non deve precedere necessariamente l'evento terminale. Il driver effettivo registra anche questo ordine osservato.

La [preparazione originale](receipts/PREPARED.json) fissa 14 file del servizio/demo, interprete e pacchetti Python, identità del binario e receipt della famiglia di chiavi. La mappa conserva gli stessi byte: l'helper di iscrizione e i requisiti Python sono in `source/demo/`, mentre gli altri 12 file sono condivisi con il repository. Il binario è il candidate della [campagna TFHE-rs](../tfhe-181-20261004/README.md); quella mappa rende disponibili i relativi 134 file nativi. I 14 pin Python non attestano l'intera chiusura delle importazioni: occorrono anche i moduli della demo già nella repo e le dipendenze dell'ambiente registrato.

Per una nuova replica ricollocare `ROOT`, `WORK`, `BUILD`, `HERE` e i percorsi della preparazione in una copia nuova; preparare una nuova famiglia del candidate, iscrivere la galleria e conservare nuove ricevute. I ritratti e i modelli sono identificati nei metadata e non sono distribuiti nel pacchetto. Non si pubblicano risposte SSE complete, cookie o payload delle richieste.

## Sorgenti e riproduzione

La [mappa dei sorgenti](PROVENANCE.json) ricostruisce il workspace usando i file specifici in `source/` e quelli condivisi nella repo, identificati con SHA-256. I documenti del workspace con suffisso `.md.txt` conservano i byte originali. Lo stesso manifesto conserva provenienza e impronte dei file distribuiti.

Dal repository si può verificare la mappa senza eseguire l'esperimento:

```sh
python3 tools/materialize_sources.py --map benchmark/demo-sse-20261004/PROVENANCE.json --dry-run
```

Con `--output /percorso/nuovo/fuori-repo` al posto di `--dry-run`, il comando ricostruisce i file senza installare dipendenze o avviare la demo. La [ricetta degli input](inputs/RECIPE.json) specifica versioni, ritratti e modelli esterni richiesti. Chiavi, cifrati e payload restano esclusi; ricevute e risultati della replica devono essere scritti in una directory nuova.
