# Raw9: ultimo stadio e query completa

La variante raw9 supera i 54 controlli finali della campagna e riduce il tempo dello stadio terminale di circa il 15–16%. Il vantaggio sull'intera valutazione è piccolo, cambia segno fra le coppie e rimane inconclusivo. **Variante non adottata.**

| Materiale | Dove si trova |
|---|---|
| Domanda, confronto e timer fissati prima della prova | [Protocollo originale](PROTOCOL.md) |
| Driver e modifiche al core | [Sorgenti specifici](source/core/src/), [mappa completa](PROVENANCE.json) |
| Input, ricostruzione dei tre casi aggiuntivi e dipendenze | [Ricetta](inputs/README.md) |
| 29 righe pubbliche originali: piani, controlli, 18 coppie e chiusura | [Campioni JSONL](results/rows.jsonl) |
| Risultato e statistiche salvate | [Risultato](results/RESULT.md), [riepilogo](results/SUMMARY.json) |
| Verifiche indipendenti | [Sorgente](review/SOURCE_REVIEW.md), [risultati](results/RESULT_REVIEW.md) |
| Identità delle copie, build ed esecuzione osservate | [Provenienza](PROVENANCE.json), [ricevute](provenance/) |

Le 18 coppie usano una famiglia di chiavi, tre input, due ordini bilanciati, 16 thread e FFT Dif4. I log espongono 48 ID individuali; i sei warmup sono verificati dal driver e attestati dal conteggio conclusivo. Il timer della valutazione include la diagnostica, esclude chiavi, cifratura, decodifica e HTTP. Le mediane appaiate non si ricavano dal rapporto delle due mediane marginali.

`PROVENANCE.json` lega tutti gli 82 file di sorgente, configurazione e LUT pubblica ai byte della campagna: 12 copie specifiche e 70 file già presenti nel repository. Ogni `canonical` è relativo alla radice della repo; `workspace_path` indica dove ricostruirlo. La mappa evita di mantenere una seconda copia del core comune.

Il comando seguente verifica i file senza compilare o eseguire la prova, dalla radice della repo:

```sh
python3 tools/materialize_sources.py --map benchmark/raw9-20261005/PROVENANCE.json --dry-run
```

Per ricostruire i soli sorgenti si può aggiungere `--output /percorso/nuovo/fuori-repo` al posto di `--dry-run`. Le quattro fixture vettoriali sono escluse: leggere la ricetta prima di preparare un futuro ambiente di esecuzione. La ricostruzione dei file non esegue il driver: una replica richiede l'ambiente, gli input e nuove chiavi descritti nella ricetta.

[Interpretazione nel percorso](../../docs/risultati/selettore-e-generalizzazione.md#raw9) · [Mappa esperimenti](../../experiments/README.md)
