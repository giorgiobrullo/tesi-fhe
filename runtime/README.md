# Motore TFHE della demo

Il servizio cerca il primo minimo fra gli score cifrati e applica la soglia
del vincitore. Restituisce zero oppure l'ID, codificato in tre LWE in base 15.
I pareggi favoriscono il primo indice della galleria.

Il core usa Head/PFKS, refresh del controllo del selettore e gruppi fino a
quattro cifre. La configurazione è `public_parallel`, con 16 thread e FFT
Dif4/base1024. Il formato ammette da 1 a 3374 ID, subordinatamente ai vincoli
pubblici sugli input. I [risultati](../docs/validazione/PACK4_VALIDATION.md)
riportano le taglie e i casi effettivamente verificati.

## Struttura

- `core/`: circuito cifrato e test aritmetici.
- `candidate/`: binario Rust, protocollo e servizio HTTP.
- `client/`: configurazione, embedding, cifratura e decifratura sul client fidato.
- `ui/`: interfaccia storica della fotocamera; la demo attuale è in `demo/dual_view/`.

Le [istruzioni di compilazione](../BUILD_AND_RUN.md) e la
[guida della demo](../demo/dual_view/README.md) descrivono l'avvio.
Il client trova gli asset tramite `pyproject.toml` e il modulo di embedding;
non richiede note di ricerca locali.

## Configurazione e chiavi

`configure.py --check` verifica le impronte dei sorgenti e la corrispondenza
fra configurazione del client e contratto del servizio. Dopo modifiche ai
sorgenti, rigenerare i binding e ricompilare il binario. Il servizio accetta
soltanto chiavi legate alla stessa identità di circuito: anche un aggiornamento
del client incluso nel manifesto cambia questa identità.

La PFKS precedente alla correzione, W287, resta incompatibile. Il
[contratto geometrico](REPAIR.md) documenta i margini del selettore;
il limite di probabilità di fallimento del circuito completo resta aperto.
