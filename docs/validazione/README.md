# Rapporti sperimentali

Il [percorso sperimentale](../percorso-sperimentale.md) racconta le
scelte in ordine; la [mappa degli esperimenti](../../experiments/README.md)
collega ogni fase a esito e materiali disponibili. Questa pagina raccoglie
i rapporti di verifica, compresi quelli con esito negativo.

Le [schede su selettore e generalizzazione](../risultati/selettore-e-generalizzazione.md) trattano
la specializzazione della soglia finale, il profilo PFKS, le analisi di
riuso GLWE/CBS e la prova biometrica Georgia Tech. I rispettivi livelli
di evidenza rimangono distinti. I test e le analisi dei singoli passaggi
non forniscono ancora una garanzia numerica dell'intera pipeline mantenuta.

Il [controllo generale del 2 ottobre](CONTROLLO_GENERALE_20261002.md)
ricontrolla codice, dati e letteratura. Il [protocollo biometrico](PROTOCOLLO_BIOMETRICO.md)
definisce la valutazione. La [prima prova su nuova galleria](BIOMETRIA_VGGFACE2_20261002.md)
riporta risultati in chiaro, fallimenti e limiti. Il [confronto della preparazione UI](BIOMETRIA_UI_20261002.md)
misura separatamente la sensibilità sugli stessi input; la [mappa del rumore](RUMORE_COMPOSTO.md)
precisa gli obblighi della probabilità di fallimento composta.

I rapporti distinguono la qualità biometrica dal circuito che sceglie
un'identità dai punteggi cifrati. Per capire il calcolo, partire
dall'[esempio con due candidati](../come-funziona-il-confronto.md).
Per leggere una misura, controllare quale versione viene confrontata, quali
casi sono inclusi e dove inizia e finisce il timer. I test verificano i casi
eseguiti; la probabilità formale di errore richiede un'analisi distinta.

Il runtime corrente conserva il selettore corretto e il packing fino a
quattro cifre della [qualifica pack4 su TFHE-rs 1.7](PACK4_VALIDATION.md),
con l’[aggiornamento e il pilot 1.8.1](TFHE_181_MIGRATION.md) verificati
separatamente. La prima correzione B usava gruppi fino a tre. I rapporti
precedenti conservano le consegne storiche: «runtime incluso», «questa
versione» e i rispettivi conteggi si riferiscono alla consegna di allora.

| Versione | Rapporto | Dati |
|---|---|---|
| Estrazione in due blocchi da 6 bit, proposta respinta | [Primo controllo cifrato](ESTRAZIONE_DUE_BLOCCHI_20261004.md) | [Casi](../../benchmark/base64-producer-20261004/samples.csv), [riepilogo](../../benchmark/base64-producer-20261004/SUMMARY.json) |
| Pipeline Head55/binaria 1.8.1 del 4 ottobre, proposta respinta | [Fallimento sul pareggio](PIPELINE_BINARIA_20261004.md) | [Casi](../../benchmark/binary-pipeline-20261004/samples.csv), [riepilogo](../../benchmark/binary-pipeline-20261004/SUMMARY.json) |
| Comparatore binario 1.8.1 del 4 ottobre, solo primitivo | [Otto casi e limiti](COMPARATORE_BINARIO_20261004.md) | [Casi](../../benchmark/binary-comparator-20261004/samples.csv), [riepilogo](../../benchmark/binary-comparator-20261004/SUMMARY.json) |
| Comparatore compresso 1.8.1 del 4 ottobre, proposta scartata | [Primo controllo cifrato](COMPARATORE_COMPRESSO_20261004.md) | [Casi](../../benchmark/comparator-encoding-20261004/samples.csv), [riepilogo](../../benchmark/comparator-encoding-20261004/SUMMARY.json) |
| Buffer temporaneo 1.8.1 del 4 ottobre, senza FHE | [Costo e limiti](SCRATCH_BR_20261004.md) | [Campioni](../../benchmark/br-scratch-cost-20261004/samples.csv), [riepilogo](../../benchmark/br-scratch-cost-20261004/SUMMARY.json) |
| Diagnosi di un merge 1.8.1 del 4 ottobre | [Passaggi del nodo e limiti](PROFILO_MERGE_20261004.md) | [Campioni](../../benchmark/merge-profile-20261004/samples.csv), [riepilogo](../../benchmark/merge-profile-20261004/SUMMARY.json) |
| Profilazione delle fasi 1.8.1 del 4 ottobre | [Fasi, livelli e limiti](PROFILO_RUNTIME_20261004.md) | [Campioni](../../benchmark/core-profile-20261004/samples.csv), [riepilogo](../../benchmark/core-profile-20261004/SUMMARY.json) |
| Demo 1.8.1 locale, POST→SSE del 4 ottobre | [Metodo e risultati](DEMO_SSE_20261004.md) | [Campioni](../../benchmark/demo-sse-20261004/samples.csv), [riepilogo](../../benchmark/demo-sse-20261004/SUMMARY.json) |
| Confronto 1.7/1.8.1 del 4 ottobre | [Metodo e risultati](TEMPI_181_20261004.md) | [Campioni](../../benchmark/tfhe-181-20261004/samples.csv), [riepilogo](../../benchmark/tfhe-181-20261004/SUMMARY.json) |
| Aggiornamento TFHE-rs 1.8.1 e pilot locale | [Metodo e controlli](TFHE_181_MIGRATION.md) | [Campioni](../../benchmark/tfhe-181-20260922/samples.csv), [riepilogo](../../benchmark/tfhe-181-20260922/SUMMARY.json) |
| Baseline storica del 19 settembre, precedente alla correzione | [Validazione](BASELINE_VALIDATION.md) | [Benchmark](BASELINE_BENCHMARKS.json) |
| Prima correzione B del selettore, precedente a pack4 | [Metodo e risultati](SELECTOR_REPAIR_VALIDATION.md) | [Benchmark](SELECTOR_REPAIR_BENCHMARKS.json) |
| Qualifica pack4 su TFHE-rs 1.7 | [Metodo e risultati](PACK4_VALIDATION.md) | [Audit](PACK4_FINAL_AUDIT.json), [tempi](PACK4_TIMING_DECISION.json), [carico](PACK4_LOAD_SUMMARY.json) |
| Regressione storica e servizio | [Replay](PACK4_HISTORICAL_AUDIT.json) | [Servizio](PACK4_SERVICE_VALIDATION.json) |
| Costo diretto della correzione | [Metodo e risultati](../selector-direct-cost-20260920.md) | [Dati e ricalcolo](../evidence/selector-direct-cost-20260920/README.md) |

I rapporti conservano le versioni e le condizioni delle singole prove.
Il [percorso sperimentale](../percorso-sperimentale.md) le mette in relazione.
Le colonne «Dati» portano ai risultati numerici e alle ricevute di controllo;
i rapporti «Metodo e risultati» spiegano come interpretarli prima del ricalcolo.

Le campagne storiche sul selettore usano scene sintetiche. I due confronti
1.7/1.8.1 usano query già calcolate da foto di iscrizione. La cattura della
telecamera e l’elaborazione della foto sono escluse dai loro tempi.
I rapporti biometrici sopra usano foto del dataset e oracoli in chiaro,
con un diverso perimetro di verifica.
