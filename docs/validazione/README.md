# Rapporti sperimentali

Il runtime corrente è la [baseline anchor/pack4](PACK4_VALIDATION.md), con
selettore corretto e gruppi fino a quattro cifre. La prima correzione B usava
gruppi fino a tre; il suo rapporto e quello della baseline precedente
conservano le consegne storiche. In quei testi, «runtime incluso», «questa
versione» e i rispettivi conteggi si riferiscono alla consegna di allora.
Anche il rinvio alla prima correzione nel banner di `BASELINE_VALIDATION.md`
appartiene a quel passaggio: per la qualifica del runtime oggi incluso usare
il rapporto pack4.

| Versione | Rapporto | Dati |
|---|---|---|
| Baseline storica del 19 settembre, precedente alla correzione | [Validazione](BASELINE_VALIDATION.md) | [Benchmark](BASELINE_BENCHMARKS.json) |
| Prima correzione B del selettore, precedente a pack4 | [Metodo e risultati](SELECTOR_REPAIR_VALIDATION.md) | [Benchmark](SELECTOR_REPAIR_BENCHMARKS.json) |
| Baseline corrente: packing a quattro cifre | [Metodo e risultati](PACK4_VALIDATION.md) | [Audit](PACK4_FINAL_AUDIT.json), [tempi](PACK4_TIMING_DECISION.json), [carico](PACK4_LOAD_SUMMARY.json) |
| Regressione storica e servizio | [Replay](PACK4_HISTORICAL_AUDIT.json) | [Servizio](PACK4_SERVICE_VALIDATION.json) |
| Costo diretto della correzione | [Metodo e risultati](../selector-direct-cost-20260920.md) | [Dati e ricalcolo](../evidence/selector-direct-cost-20260920/README.md) |

I rapporti conservano le versioni e le condizioni delle singole prove.
Il [percorso sperimentale](../percorso-sperimentale-20260920.md) le mette in relazione.
