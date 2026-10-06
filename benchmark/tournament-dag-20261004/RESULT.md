# Torneo per dipendenze: candidato non adottato

Il prototipo conserva lo stesso torneo, ma avvia ciascun confronto quando sono pronti i suoi due figli, senza attendere che finisca tutto il livello. Il parallelismo interno conserva la politica basata sulla larghezza del livello originale.

**Le verifiche passano; il tempo aumenta del 9,16% nelle otto coppie misurate. Il candidato resta fuori dalla baseline.**

| Caso | Coppie misurate | Variazione del tempo |
|---|---:|---:|
| Soglia comune (Uniform) | 4 | +6,65% |
| Soglia per candidato (Mixed) | 4 | +11,73% |
| Insieme | 8 | +9,16% |

La variazione complessiva è la media geometrica dei rapporti DAG/riferimento. Ogni coppia alterna l'ordine dei due programmi; nessuna misura è stata esclusa. Tutte le otto coppie favoriscono il riferimento. Il criterio fissato prima della prova richiedeva almeno il 3% di riduzione complessiva e nessun caso oltre +1%: non è soddisfatto.

I due test strutturali dello scheduler passano. La campagna valida restituisce tutti i 30 esiti attesi: 28 valutazioni del circuito e due scorciatoie pubbliche AllReject. Sono controllati primo minimo, parità, soglia inclusiva e rifiuto del vincitore anche quando un altro candidato passerebbe la propria soglia. I contatori delle operazioni coincidono fra i due programmi. Le ripetizioni usano una sola famiglia di chiavi e lo stesso input cifrato: non sono una stima della probabilità di errore.

Il primo tentativo era stato fermato dall'ammissione di un template sintetico con coordinata 4, mentre il contratto ammette al massimo 3. Aveva generato una famiglia di chiavi ma non eseguito alcuna valutazione. Sorgente, binario, log e ricevute di quel tentativo restano separati e conservati. La campagna valida corregge soltanto la generazione del template e verifica tutti i casi prima di creare le chiavi. Non si tratta di un errore FHE né di una ricerca di chiavi favorevoli.

Misura locale su M4 Max, 16 thread, N=120 e D=512, TFHE-rs 1.8.1. Il tempo comprende la valutazione del servizio, esclude generazione delle chiavi, cifratura e interfaccia web. Non sostituisce i tempi della demo o dei grafici storici. Non dimostra che ogni scheduler per dipendenze sia più lento e non identifica la causa del rallentamento.

Evidenza: [misure e riepilogo](root/SUMMARY.json), [ricalcolo indipendente](math/RUNTIME_CHECK.md), [review finale](root/NATIVE_REVIEW.md), [protocollo](PROTOCOL.md), [correzione della fixture](root/CORRECTION_PROTOCOL.md). Binari conservati in bin/. Baseline originale, registro delle dipendenze e grafici invariati.

Il tentativo è chiuso senza integrazione o ripetizioni. Il prossimo screen, prima di qualunque nuovo benchmark, deve proporre un contratto concreto per ammettere il parallelismo interno quando si sovrappongono livelli diversi; la sola ipotesi di contesa non giustifica una nuova misura.
