# PFKS degli ID pubblici: profilo prima della cache

Le 12 query restituiscono l'ID atteso. Le PFKS degli ID hanno già un costo ridotto rispetto a quelle dello score: la loro quota è lo 0,1471–0,1556% della somma dei tempi dei worker del primo livello. **La cache è stata de-prioritizzata; non è stata implementata né misurata una variante ottimizzata.**

| Materiale | Dove si trova |
|---|---|
| Domanda, strumentazione e denominatori | [Protocollo originale](PROTOCOL.md) |
| Driver, modulo e tre hook modificati | [Sorgenti specifici](source/core/src/), [mappa completa](PROVENANCE.json) |
| Input, versioni e ricostruzione | [Ricetta](inputs/README.md) |
| 16 righe pubbliche, incluse 2.196 chiamate profilate | [Campioni JSONL](results/rows.jsonl) |
| Risultato, statistiche e chiusura successiva | [Risultato](results/RESULT.md), [riepilogo](results/SUMMARY.json), [chiusura](results/CLOSURE_NOTE.md) |
| Verifiche indipendenti | [Sorgente](review/SOURCE_REVIEW.md), [risultati](results/RESULT_REVIEW.md) |
| Copie, build ed esecuzione originaria | [Provenienza](PROVENANCE.json), [ricevute](provenance/) |

La campagna comprende tre controlli con profilo spento, tre warmup profilati e sei misure. Ogni query profilata osserva 244 chiamate effettive: 180 score, 60 ID basso e quattro ID intermedio. Le sei misure contengono 1.464 record; le mediane per chiamata sono 1468,354 µs, 6,583 µs e 6,459 µs. La maschera è nulla per gli ingressi ID e non nulla per gli score osservati.

I tempi dei worker si sovrappongono. La quota percentuale non è una frazione della latenza della richiesta e non stima uno speedup. La verifica della maschera e la scrittura del record restano fuori dal timer della singola PFKS.

La mappa lega 84 file di sorgente/configurazione/LUT: cinque copie specifiche e 79 file riusati dalla repo o dal [pacchetto raw9](../raw9-20261005/README.md). Dalla radice della repo, verifica senza build o esecuzione:

```sh
python3 tools/materialize_sources.py --map benchmark/public-id-pfks-20261005/PROVENANCE.json --dry-run
```

`--output /percorso/nuovo/fuori-repo` ricostruisce i soli sorgenti al posto della verifica. Restano da fornire le quattro fixture escluse e l'ambiente descritto nella ricetta. I comandi sopra non compilano o eseguono la profilazione.

[Interpretazione nel percorso](../../docs/risultati/selettore-e-generalizzazione.md#pfks-id) · [Mappa esperimenti](../../experiments/README.md)
