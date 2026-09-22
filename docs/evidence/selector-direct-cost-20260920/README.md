# Evidenze pubbliche del costo diretto

Confronto del 20 settembre 2026 fra originale pre-fix e baseline corretta pack4.
[Rapporto e limiti](../../selector-direct-cost-20260920.md).

La domanda è quanto costa la versione corretta rispetto all'originale,
misurando direttamente entrambe. Una coppia contiene le due esecuzioni sullo
stesso caso e nella stessa famiglia di chiavi; il rapporto dei tempi misura
il costo relativo. Il packing raggruppa fino a quattro cifre del vincitore,
come nell'[esempio del selettore](../../come-funziona-il-confronto.md).

Per leggere il risultato partire dal rapporto, poi da `TIMING_RESULT.json`.
Per ricalcolarlo usare il comando sotto; gli altri file documentano il
calendario e i controlli sui dati.

- [TIMING_RESULT.json](TIMING_RESULT.json): tutte le 72 coppie misurate, 60 primarie
  e 12 secondarie, statistiche e indicatori aggregati del carico per query.
- [PROTOCOL.json](PROTOCOL.json): calendario, vincoli e impronte delle tre famiglie riusate.
- `GATE_AUDIT_0..2.json` e `MEASURE_AUDIT_0..2.json`: sei riepiloghi indipendenti,
  216 query e 648 payload verificati includendo warmup e gate.
- [SUMMARY_BINDING_AUDIT.json](SUMMARY_BINDING_AUDIT.json): esito del controllo
  audit/journal/riepilogo; [FINAL.json](FINAL.json): ricevuta originale di chiusura.
- [PROVENANCE.json](PROVENANCE.json): impronte separate degli originali e delle copie.

L'estimatore è copiato senza modifiche dal codice congelato. Dalla radice:

```sh
python3 -B docs/evidence/selector-direct-cost-20260920/verify.py
```

Il comando verifica gli hash pubblici e ricalcola i rapporti, le statistiche per
scena/famiglia e i due intervalli bootstrap con la sola libreria standard.
Non esegue FHE né ricostruisce le prove di decifratura. Gli hash interni dei
report restano quelli degli originali; usare PROVENANCE.json per le copie.
Le stringhe `local-archive:` identificano materiale locale non distribuito.
Chiavi, cifrati e inventari dei processi sono esclusi; nessuna coppia misurata
è stata esclusa. Il rapporto principale è 1,068737456, costo +6,8737456%,
condizionato ai casi e alle tre famiglie osservate.
