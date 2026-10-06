# Georgia Tech: trasferimento biometrico con soglia fissa

Con la soglia 273 già fissata, ciascuna delle due condizioni riconosce correttamente 20/20 iscritti e accetta 1/30 sconosciuti. Il falso accesso riguarda la stessa persona in entrambe le condizioni. **Il campione non certifica una garanzia dell'1%.** È una prova biometrica in chiaro, non una misura FHE, HTTP o webcam.

| Materiale | Dove si trova |
|---|---|
| Coorte, foto disgiunte, denominatori e limiti fissati | [Protocollo originale](PROTOCOL.md) |
| Runner e codec effettivamente eseguiti, versione 4 | [run_gt.py](source/run_gt.py), [encode_gt.mjs](source/encode_gt.mjs) |
| Dipendenze condivise e rispettivi hash | [Mappa sorgenti](PROVENANCE.json) |
| Ricetta dei dati, versioni e modelli | [Input](inputs/README.md), [metadati estratti](inputs/RECIPE.json) |
| Conteggi già salvati e interpretazione | [Riepilogo aggregato](results/SUMMARY.json), [risultato](results/RESULT.md) |
| Verifica prima dell'esecuzione e ricalcolo indipendente | [Sorgente](review/SOURCE_REVIEW.md), [risultati](results/RESULT_REVIEW.md) |
| Copie e ricevute della sola campagna eseguita | [Provenienza](PROVENANCE.json), [ricevute](provenance/) |

La galleria ha 120 voci: 100 preset e 20 nuovi iscritti Georgia Tech; altre 30 persone sono sconosciute. Le 100 ricerche appartengono a due condizioni sulle stesse 50 persone, con una foto oppure tre altre foto fuse. Non sono 100 persone indipendenti e non isolano causalmente l'effetto del numero di foto. Tutte le decisioni coincidono con l'oracolo intero. Nessun errore di elaborazione e nessuna ritaratura sul test.

La FPIR osservata è 3,33% per condizione; il limite superiore unilaterale al 95% è 14,86%, sotto l'ipotesi binomiale per persona e a galleria fissata. Il protocollo conserva le ulteriori cautele su pretraining e possibile sovrapposizione semantica con i preset.

Il pacchetto include i programmi e i risultati aggregati, senza fotografie, embedding, pesi del modello, galleria vettoriale, record individuali o profilo Chrome. Nei programmi i percorsi personali sono sostituiti con i [segnaposto documentati](../../docs/riproducibilita.md#provenienza-dei-dati-inclusi); la logica resta invariata e non sono stati rieseguiti. La ricetta specifica i dati esterni e l'ambiente necessari alla replica. Le versioni 1–3 furono corrette prima dell'esecuzione; non sono tre campagne fallite.

[Interpretazione nel percorso](../../docs/risultati/selettore-e-generalizzazione.md#georgia-tech) · [Mappa esperimenti](../../experiments/README.md)
